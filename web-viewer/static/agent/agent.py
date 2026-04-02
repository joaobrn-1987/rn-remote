#!/usr/bin/env python3
"""
RemoteLink - Agente Linux
Roda na máquina remota e conecta ao relay para acesso via terminal no browser.

Uso:
    python3 agent.py --relay wss://rnremote.joaoneto.tec.br/ws --id 123456789 --password suasenha
    python3 agent.py --config /etc/rnremote/agent.json
"""
from __future__ import annotations

import asyncio
import configparser
import json
import os
import pty
import time
import logging
import signal
import stat
import subprocess
import sys
import fcntl
import termios
import struct
import socket
import platform
import hashlib
import argparse
import select
import base64
import shutil
import urllib.request

AGENT_VERSION = "1.3.9"

import websockets

PROTOCOL_VERSION = "1.0.0"
HEARTBEAT_INTERVAL = 15

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("agent")


# ─── Helpers ───────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def compute_binding_token(binding_secret: str, agent_id: str) -> str:
    """Token que prova que esta máquina é a dona do agent_id."""
    return hashlib.sha256(f"{binding_secret}{agent_id}".encode()).hexdigest()


def get_system_info() -> dict:
    uname = platform.uname()
    return {
        "hostname": socket.gethostname(),
        "os_type": "Linux",
        "os_version": f"{uname.system} {uname.release}",
        "username": os.environ.get("USER", os.environ.get("LOGNAME", "unknown")),
        "screen_width": 0,
        "screen_height": 0,
    }


# ─── Samba / Active Directory ─────────────────────────────────────────────────

# Paths do Samba — preenchidos dinamicamente por _detect_samba()
SAMBA_BIN     = ""
SAMBA_SBIN    = ""
SAMBA_PRIVATE = ""
SAMBA_ETC     = ""
SYSVOL_PATH   = ""

# Candidatos por distro (ordem de preferência)
_SAMBA_CANDIDATES = [
    # CentOS / RHEL / AlmaLinux — Samba compilado do fonte
    {
        "bin":     "/usr/local/samba/bin",
        "sbin":    "/usr/local/samba/sbin",
        "private": "/usr/local/samba/private",
        "etc":     "/usr/local/samba/etc",
        "sysvol":  "/usr/local/samba/var/locks/sysvol",
    },
    # Ubuntu / Debian — pacote do sistema
    {
        "bin":     "/usr/bin",
        "sbin":    "/usr/sbin",
        "private": "/var/lib/samba/private",
        "etc":     "/etc/samba",
        "sysvol":  "/var/lib/samba/sysvol",
    },
]


def _detect_samba() -> bool:
    """Detecta instalação do Samba AD DC e configura paths globais. Retorna True se encontrado."""
    global SAMBA_BIN, SAMBA_SBIN, SAMBA_PRIVATE, SAMBA_ETC, SYSVOL_PATH
    for paths in _SAMBA_CANDIDATES:
        tool = os.path.join(paths["bin"], "samba-tool")
        ldb  = os.path.join(paths["private"], "sam.ldb")
        if os.path.isfile(tool) and os.path.isfile(ldb):
            SAMBA_BIN     = paths["bin"]
            SAMBA_SBIN    = paths["sbin"]
            SAMBA_PRIVATE = paths["private"]
            SAMBA_ETC     = paths["etc"]
            SYSVOL_PATH   = paths["sysvol"]
            logger.info(f"Samba encontrado em {paths['bin']}")
            return True
    return False


# Padrões de warnings conhecidos do Samba que não são erros reais
_SAMBA_WARN_PATTERNS = [
    "option 'server role' in section 'global' already exists",
    "lpcfg_do_global_parameter: WARNING:",
    "WARNING: The \"enable privileges\" option is deprecated",
    "rlimit_max: increasing rlimit_max",
]

def _strip_samba_warnings(text: str) -> str:
    """Remove linhas de warning conhecidas do Samba do output."""
    lines = [l for l in text.splitlines()
             if not any(w in l for w in _SAMBA_WARN_PATTERNS)]
    return "\n".join(lines).strip()


def _ad_run_cmd(cmd_list):
    env = os.environ.copy()
    path = env.get("PATH", "")
    extra = f"{SAMBA_BIN}:{SAMBA_SBIN}"
    if extra not in path:
        env["PATH"] = f"{extra}:{path}"
    try:
        # Redireciona stderr para /dev/null para suprimir warnings do smb.conf
        # que aparecem mesmo em comandos bem-sucedidos
        proc = subprocess.run(
            cmd_list, capture_output=True, text=True, env=env, timeout=30
        )
        stdout = _strip_samba_warnings(proc.stdout)
        stderr = _strip_samba_warnings(proc.stderr)
        # Se o retorno foi não-zero mas stderr ficou vazio após filtrar warnings,
        # o único "erro" eram warnings — trata como sucesso
        rc = proc.returncode
        if rc != 0 and not stderr:
            rc = 0
        return {"stdout": stdout, "stderr": stderr, "returncode": rc}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout ao executar comando", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def _samba_tool(*args):
    return _ad_run_cmd([os.path.join(SAMBA_BIN, "samba-tool")] + list(args))


def _ldbsearch(base, scope="sub", attrs=None, expression=None):
    cmd = [os.path.join(SAMBA_BIN, "ldbsearch"), "-H", os.path.join(SAMBA_PRIVATE, "sam.ldb")]
    if base:
        cmd += ["-b", base]
    if scope:
        cmd += ["-s", scope]
    if expression:
        cmd.append(expression)
    if attrs:
        cmd.extend(attrs if isinstance(attrs, list) else attrs.split())
    return _ad_run_cmd(cmd)


def _ldbmodify(ldif_string):
    cmd = [os.path.join(SAMBA_BIN, "ldbmodify"), "-H", os.path.join(SAMBA_PRIVATE, "sam.ldb")]
    try:
        proc = subprocess.run(cmd, input=ldif_string, capture_output=True, text=True, timeout=30)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def _ldbadd(ldif_string):
    cmd = [os.path.join(SAMBA_BIN, "ldbadd"), "-H", os.path.join(SAMBA_PRIVATE, "sam.ldb")]
    try:
        proc = subprocess.run(cmd, input=ldif_string, capture_output=True, text=True, timeout=30)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def _ldbdel(dn):
    return _ad_run_cmd([os.path.join(SAMBA_BIN, "ldbdel"), "-H",
                        os.path.join(SAMBA_PRIVATE, "sam.ldb"), dn])


def _parse_ldb_output(stdout):
    """Parseia saída LDIF do ldbsearch (RFC 2849).

    Trata corretamente:
    - Line folding: linhas longas quebradas em 76 chars com continuação
      iniciada por espaço (ex: DNs longos, displayName, etc.)
    - Valores Base64 (attr:: <b64>): usados para caracteres não-ASCII
      como acentos em nomes brasileiros (ã, ç, ê, etc.)
    """
    def _b64(s):
        try:
            return base64.b64decode(s.strip()).decode("utf-8", errors="replace")
        except Exception:
            return s.strip()

    # ── Passo 1: desfazer line folding (RFC 2849 §2.3) ──────────────────
    # Linhas de continuação começam com um espaço; o espaço é removido e
    # o conteúdo é emendado à linha anterior.
    raw_lines = stdout.splitlines()
    lines = []
    for raw in raw_lines:
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]   # emenda sem o espaço inicial
        else:
            lines.append(raw)

    # ── Passo 2: parsear as linhas já desdobradas ────────────────────────
    entries = []
    current = {}
    for line in lines:
        if line.startswith("#"):
            continue
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        # dn: <valor> — inicia nova entrada
        if line.startswith("dn: "):
            if current:
                entries.append(current)
            current = {"dn": line[4:].strip()}
        # dn:: <base64> — dn com caracteres não-ASCII
        elif line.startswith("dn:: "):
            if current:
                entries.append(current)
            current = {"dn": _b64(line[5:])}
        # attr:: <base64> — valor não-ASCII
        elif ":: " in line:
            key, _, b64 = line.partition(":: ")
            key = key.strip()
            value = _b64(b64)
            if key in current:
                existing = current[key]
                current[key] = existing + [value] if isinstance(existing, list) else [existing, value]
            else:
                current[key] = value
        # attr: <valor> — valor ASCII normal
        elif ": " in line:
            key, _, value = line.partition(": ")
            key = key.strip(); value = value.strip()
            if key in current:
                existing = current[key]
                current[key] = existing + [value] if isinstance(existing, list) else [existing, value]
            else:
                current[key] = value
    if current:
        entries.append(current)
    return [e for e in entries if e.get("dn") and not e["dn"].startswith("ref:")]


# ─── Cache SID→Nome ────────────────────────────────────────────────────────────

_SID_NAME_CACHE: dict = {}
_SID_NAME_CACHE_LOADED = False


def _decode_sid_from_b64(b64_str: str):
    """Decodifica SID binário (base64 do ldbsearch) para formato S-1-5-..."""
    import struct as _struct
    try:
        data = base64.b64decode(b64_str.strip())
        if len(data) < 8:
            return None
        revision  = data[0]
        sub_count = data[1]
        authority = int.from_bytes(data[2:8], "big")
        subs = []
        for i in range(sub_count):
            off = 8 + i * 4
            if off + 4 > len(data):
                break
            subs.append(str(_struct.unpack_from("<I", data, off)[0]))
        return "S-" + "-".join([str(revision), str(authority)] + subs)
    except Exception:
        return None


def _load_sid_cache():
    """Carrega cache SID→sAMAccountName a partir do sam.ldb (fallback quando wbinfo falha)."""
    global _SID_NAME_CACHE, _SID_NAME_CACHE_LOADED
    if _SID_NAME_CACHE_LOADED:
        return
    _SID_NAME_CACHE_LOADED = True
    base = _ad_get_domain_dn()
    if not base:
        return
    r = _ad_run_cmd([
        os.path.join(SAMBA_BIN, "ldbsearch"), "-H",
        os.path.join(SAMBA_PRIVATE, "sam.ldb"),
        "-b", base, "-s", "sub",
        "(|(objectClass=user)(objectClass=group))",
        "sAMAccountName", "objectSid",
    ])
    if r["returncode"] != 0 or not r["stdout"]:
        return
    # Parseia manualmente para manter objectSid como base64 (binário)
    raw_lines = r["stdout"].splitlines()
    lines: list = []
    for raw in raw_lines:
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    current_sam: str | None = None
    current_sid_b64: str | None = None
    def _flush():
        if current_sam and current_sid_b64:
            sid = _decode_sid_from_b64(current_sid_b64)
            if sid:
                _SID_NAME_CACHE[sid.upper()] = current_sam
    for line in lines:
        if not line.strip():
            _flush()
            current_sam = current_sid_b64 = None
            continue
        if line.startswith("sAMAccountName: "):
            current_sam = line[len("sAMAccountName: "):].strip()
        elif line.startswith("sAMAccountName:: "):
            try:
                current_sam = base64.b64decode(line[len("sAMAccountName:: "):].strip()).decode("utf-8", errors="replace")
            except Exception:
                pass
        elif line.startswith("objectSid:: "):
            current_sid_b64 = line[len("objectSid:: "):].strip()
    _flush()


def _ad_get_realm():
    cfg = configparser.ConfigParser(strict=False)
    cfg.read(os.path.join(SAMBA_ETC, "smb.conf"))
    return cfg.get("global", "realm", fallback="").strip()


def _ad_get_domain_name():
    cfg = configparser.ConfigParser(strict=False)
    cfg.read(os.path.join(SAMBA_ETC, "smb.conf"))
    return cfg.get("global", "workgroup", fallback="").strip()


def _ad_get_domain_dn():
    realm = _ad_get_realm()
    if not realm:
        return ""
    return ",".join(f"DC={p}" for p in realm.lower().split("."))


class _UserManager:

    _USER_ATTRS = [
        "sAMAccountName", "cn", "givenName", "sn", "displayName", "mail",
        "description", "distinguishedName", "memberOf", "userAccountControl",
        "whenCreated", "whenChanged", "lastLogon", "pwdLastSet", "accountExpires",
        "telephoneNumber", "title", "department", "company",
        "physicalDeliveryOfficeName", "homeDirectory", "homeDrive",
        "scriptPath", "profilePath", "uidNumber", "gidNumber",
        "loginShell", "unixHomeDirectory", "userPrincipalName"
    ]

    def _decode_uac(self, entry):
        uac = 0
        try:
            uac = int(entry.get("userAccountControl", "0") or "0")
        except (ValueError, TypeError):
            pass
        entry["_disabled"]        = bool(uac & 0x0002)
        entry["_locked"]          = bool(uac & 0x0010)
        entry["_pwdNeverExpires"] = bool(uac & 0x10000)
        entry["_pwdNotRequired"]  = bool(uac & 0x0020)
        return entry

    def list_users(self, ou=None):
        base = ou or _ad_get_domain_dn()
        r = _ldbsearch(base, "sub", self._USER_ATTRS, "(&(objectClass=user)(objectCategory=person))")
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        users = []
        for entry in _parse_ldb_output(r["stdout"]):
            sam = entry.get("sAMAccountName", "")
            if isinstance(sam, list): sam = sam[0]
            if sam.endswith("$") or sam.lower() == "krbtgt":
                continue
            users.append(self._decode_uac(entry))
        return {"users": users}

    def get_user(self, username):
        r = _ldbsearch(_ad_get_domain_dn(), "sub", self._USER_ATTRS,
                       f"(sAMAccountName={username})")
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        entries = _parse_ldb_output(r["stdout"])
        if not entries:
            return {"error": "Usuário não encontrado"}
        return {"user": self._decode_uac(entries[0])}

    def create_user(self, username, password, given_name="", surname="",
                    mail="", ou="", must_change_password=False, unix_attrs=None):
        args = ["user", "create", username, password]
        if given_name: args += ["--given-name", given_name]
        if surname:    args += ["--surname", surname]
        if mail:       args += ["--mail-address", mail]
        if ou:
            # samba-tool --userou expects only OU= components, without DC= parts.
            # Strip DC= components in case a full DN was passed (e.g. from the UI).
            ou_parts = [p for p in ou.split(",") if not p.strip().upper().startswith("DC=")]
            ou_stripped = ",".join(ou_parts).strip(",")
            if ou_stripped:
                args += ["--userou", ou_stripped]
        if must_change_password: args.append("--must-change-at-next-login")
        if unix_attrs:
            if unix_attrs.get("uid_number"):   args += ["--uid-number",   str(unix_attrs["uid_number"])]
            if unix_attrs.get("gid_number"):   args += ["--gid-number",   str(unix_attrs["gid_number"])]
            if unix_attrs.get("login_shell"):  args += ["--login-shell",  unix_attrs["login_shell"]]
            if unix_attrs.get("unix_home"):    args += ["--unix-home",    unix_attrs["unix_home"]]
        r = _samba_tool(*args)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def modify_user(self, username, attrs_dict):
        user_data = self.get_user(username)
        if "error" in user_data: return user_data
        dn = user_data["user"]["distinguishedName"]
        if isinstance(dn, list): dn = dn[0]
        lines = [f"dn: {dn}", "changetype: modify"]
        for attr, value in attrs_dict.items():
            if value is None or value == "":
                lines += [f"delete: {attr}", "-"]
            else:
                lines += [f"replace: {attr}", f"{attr}: {value}", "-"]
        r = _ldbmodify("\n".join(lines) + "\n")
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def delete_user(self, username):
        r = _samba_tool("user", "delete", username)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def enable_user(self, username):
        r = _samba_tool("user", "enable", username)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def disable_user(self, username):
        r = _samba_tool("user", "disable", username)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def reset_password(self, username, new_password, must_change=False):
        args = ["user", "setpassword", username, f"--newpassword={new_password}"]
        if must_change: args.append("--must-change-at-next-login")
        r = _samba_tool(*args)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def unlock_user(self, username):
        user_data = self.get_user(username)
        if "error" in user_data: return user_data
        dn = user_data["user"]["distinguishedName"]
        if isinstance(dn, list): dn = dn[0]
        r = _ldbmodify(f"dn: {dn}\nchangetype: modify\nreplace: lockoutTime\nlockoutTime: 0\n")
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def move_user(self, username, target_ou):
        r = _samba_tool("user", "move", username, target_ou)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def get_user_groups(self, username):
        r = _samba_tool("user", "getgroups", username)
        if r["returncode"] != 0: return {"error": r["stderr"]}
        return {"groups": [g.strip() for g in r["stdout"].splitlines() if g.strip()]}


class _GroupManager:

    def list_groups(self, ou=None):
        base = ou or _ad_get_domain_dn()
        attrs = ["cn", "sAMAccountName", "description", "distinguishedName",
                 "member", "groupType", "whenCreated", "gidNumber", "managedBy"]
        r = _ldbsearch(base, "sub", attrs, "(objectClass=group)")
        if r["returncode"] != 0: return {"error": r["stderr"]}
        groups = []
        for entry in _parse_ldb_output(r["stdout"]):
            gt_raw = entry.get("groupType", "0") or "0"
            try:
                gt = int(gt_raw)
                if gt < 0: gt = gt + 2**32
            except (ValueError, TypeError):
                gt = 0
            entry["_scope"] = ("global" if gt & 0x2 else "domainlocal" if gt & 0x4
                               else "universal" if gt & 0x8 else "unknown")
            entry["_type"] = "security" if gt & 0x80000000 else "distribution"
            groups.append(entry)
        return {"groups": groups}

    def get_group(self, groupname):
        attrs = ["cn","sAMAccountName","description","distinguishedName",
                 "member","groupType","whenCreated","gidNumber","managedBy"]
        r = _ldbsearch(_ad_get_domain_dn(), "sub", attrs, f"(sAMAccountName={groupname})")
        if r["returncode"] != 0: return {"error": r["stderr"]}
        entries = _parse_ldb_output(r["stdout"])
        if not entries: return {"error": "Grupo não encontrado"}
        return {"group": entries[0]}

    def create_group(self, groupname, description="", group_type="Security",
                     group_scope="Global", ou="", gid_number=None):
        args = ["group", "create", groupname]
        if group_type.lower() == "distribution": args.append("--group-type=Distribution")
        if group_scope.lower() == "domainlocal":  args.append("--group-scope=DomainLocal")
        elif group_scope.lower() == "universal":  args.append("--group-scope=Universal")
        if description: args += ["--description", description]
        if ou:
            # samba-tool --groupou expects only OU= components, without DC= parts.
            # Strip DC= components in case a full DN was passed (e.g. from the UI).
            ou_parts = [p for p in ou.split(",") if not p.strip().upper().startswith("DC=")]
            ou_stripped = ",".join(ou_parts).strip(",")
            if ou_stripped:
                args += ["--groupou", ou_stripped]
        if gid_number:  args += ["--gid-number", str(gid_number)]
        r = _samba_tool(*args)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def delete_group(self, groupname):
        r = _samba_tool("group", "delete", groupname)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def add_member(self, groupname, member):
        r = _samba_tool("group", "addmembers", groupname, member)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def remove_member(self, groupname, member):
        r = _samba_tool("group", "removemembers", groupname, member)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def list_members(self, groupname):
        r = _samba_tool("group", "listmembers", groupname)
        if r["returncode"] != 0: return {"error": r["stderr"]}
        return {"members": [m.strip() for m in r["stdout"].splitlines() if m.strip()]}

    def move_group(self, groupname, target_ou):
        r = _samba_tool("group", "move", groupname, target_ou)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}


class _OUManager:

    def list_ous(self):
        r = _ldbsearch(_ad_get_domain_dn(), "sub",
                       ["ou","description","distinguishedName","whenCreated"],
                       "(objectClass=organizationalUnit)")
        if r["returncode"] != 0: return {"error": r["stderr"]}
        return {"ous": _parse_ldb_output(r["stdout"])}

    def create_ou(self, ou_name, parent_dn="", description=""):
        if not parent_dn: parent_dn = _ad_get_domain_dn()
        full_dn = f"OU={ou_name},{parent_dn}"
        r = _samba_tool("ou", "create", full_dn)
        if r["returncode"] != 0:
            ldif = f"dn: {full_dn}\nobjectClass: organizationalUnit\nou: {ou_name}\n"
            if description: ldif += f"description: {description}\n"
            r2 = _ldbadd(ldif)
            return {"ok": r2["returncode"] == 0, "output": r2["stdout"] + r2["stderr"]}
        if description:
            _ldbmodify(f"dn: {full_dn}\nchangetype: modify\nreplace: description\ndescription: {description}\n")
        return {"ok": True, "output": r["stdout"]}

    def delete_ou(self, ou_dn, recursive=False):
        if recursive:
            r = _ldbsearch(ou_dn, "one", ["distinguishedName", "objectClass"], None)
            for entry in _parse_ldb_output(r["stdout"]):
                _ldbdel(entry["dn"])
        r = _samba_tool("ou", "delete", ou_dn)
        if r["returncode"] != 0:
            r = _ldbdel(ou_dn)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def rename_ou(self, ou_dn, new_name):
        parent = ",".join(ou_dn.split(",")[1:])
        new_dn = f"OU={new_name},{parent}"
        r = _ad_run_cmd([os.path.join(SAMBA_BIN, "ldbrename"), "-H",
                         os.path.join(SAMBA_PRIVATE, "sam.ldb"), ou_dn, new_dn])
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def move_ou(self, ou_dn, target_parent_dn):
        rdn    = ou_dn.split(",")[0]          # e.g. "OU=TestOU"
        new_dn = f"{rdn},{target_parent_dn}"
        r = _ad_run_cmd([os.path.join(SAMBA_BIN, "ldbrename"), "-H",
                         os.path.join(SAMBA_PRIVATE, "sam.ldb"), ou_dn, new_dn])
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def get_ou_tree(self):
        base = _ad_get_domain_dn()
        r = _ldbsearch(base, "sub",
                       ["distinguishedName","ou","cn","objectClass","name"],
                       "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))")
        if r["returncode"] != 0: return {"error": r["stderr"]}
        entries = _parse_ldb_output(r["stdout"])

        def get_type(entry):
            oc = entry.get("objectClass", "")
            oc_list = oc if isinstance(oc, list) else [oc]
            if "organizationalUnit" in oc_list: return "ou"
            if "builtinDomain" in oc_list: return "builtin"
            return "container"

        nodes = {}
        for e in entries:
            dn = e.get("dn", "")
            name = e.get("ou") or e.get("cn") or e.get("name") or dn.split(",")[0].split("=")[-1]
            if isinstance(name, list): name = name[0]
            nodes[dn.lower()] = {"dn": dn, "name": name, "type": get_type(e), "children": []}

        domain_node = {"dn": base, "name": _ad_get_realm() or base.split(",")[0].split("=")[-1],
                       "type": "domain", "children": []}

        def build_children(parent_dn):
            children = []
            for node in nodes.values():
                dn = node["dn"]
                if ",".join(dn.split(",")[1:]).lower() == parent_dn.lower():
                    node["children"] = build_children(dn)
                    children.append(node)
            return sorted(children, key=lambda x: x["name"])

        domain_node["children"] = build_children(base)
        return {"tree": domain_node}

    def get_ou_objects(self, ou_dn):
        r = _ldbsearch(ou_dn, "one",
                       ["distinguishedName","objectClass","cn","sAMAccountName",
                        "displayName","description","name","userAccountControl","groupType"], None)
        if r["returncode"] != 0: return {"error": r["stderr"]}
        objects = []
        for entry in _parse_ldb_output(r["stdout"]):
            oc = entry.get("objectClass", "")
            oc_list = oc if isinstance(oc, list) else [oc]
            if "computer" in oc_list:               entry["_type"] = "computer"
            elif "user" in oc_list and "person" in oc_list: entry["_type"] = "user"
            elif "group" in oc_list:                entry["_type"] = "group"
            elif "organizationalUnit" in oc_list:   entry["_type"] = "ou"
            elif "container" in oc_list:            entry["_type"] = "container"
            else:                                   entry["_type"] = "object"
            objects.append(entry)
        return {"objects": objects}


class _GPOManager:

    def list_gpos(self):
        r = _samba_tool("gpo", "listall")
        if r["returncode"] != 0: return {"error": r["stderr"]}
        gpos, current = [], {}
        for line in r["stdout"].splitlines():
            line = line.strip()
            if not line:
                if current: gpos.append(current)
                current = {}
            elif ":" in line:
                key, _, value = line.partition(":")
                current[key.strip()] = value.strip()
        if current: gpos.append(current)
        # Normaliza chaves para o formato esperado pelo frontend
        normalized = []
        for g in gpos:
            normalized.append({
                "Display name": g.get("display name") or g.get("Display name", ""),
                "GPO":          g.get("GPO", ""),
                "Path":         g.get("path", ""),
                "dn":           g.get("dn", ""),
                "version":      g.get("version", ""),
            })
        return {"gpos": [n for n in normalized if n["GPO"] or n["Display name"]]}

    def get_gpo(self, gpo_guid):
        r = _samba_tool("gpo", "show", gpo_guid)
        info = {"guid": gpo_guid, "output": r["stdout"]}
        realm = _ad_get_realm().lower()
        tmpl_path = os.path.join(SYSVOL_PATH, realm, "Policies", gpo_guid,
                                 "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")
        if os.path.exists(tmpl_path):
            try:
                with open(tmpl_path, "r", encoding="utf-8", errors="replace") as f:
                    info["gpt_tmpl"] = f.read()
            except Exception:
                pass
        return {"gpo": info}

    def create_gpo(self, display_name):
        r = _samba_tool("gpo", "create", display_name)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def delete_gpo(self, gpo_guid):
        r = _samba_tool("gpo", "del", gpo_guid)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def link_gpo(self, gpo_guid, container_dn):
        r = _samba_tool("gpo", "setlink", container_dn, gpo_guid)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def unlink_gpo(self, gpo_guid, container_dn):
        r = _samba_tool("gpo", "dellink", container_dn, gpo_guid)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def get_linked_gpos(self, container_dn):
        r = _samba_tool("gpo", "getlink", container_dn)
        if r["returncode"] != 0: return {"error": r["stderr"]}
        return {"output": r["stdout"]}

    def _sysvol_base(self, gpo_guid):
        return os.path.join(SYSVOL_PATH, _ad_get_realm().lower(), "Policies", gpo_guid)

    def _bump_version(self, gpo_guid):
        gpt_path = os.path.join(self._sysvol_base(gpo_guid), "GPT.INI")
        ini = configparser.ConfigParser(strict=False)
        if os.path.exists(gpt_path): ini.read(gpt_path)
        ver_str = ini.get("General", "Version", fallback="0") if ini.has_section("General") else "0"
        ver = int(ver_str) if ver_str.isdigit() else 0
        if not ini.has_section("General"): ini.add_section("General")
        ini.set("General", "Version", str(ver + 1))
        with open(gpt_path, "w") as f: ini.write(f)

    def set_security_setting(self, gpo_guid, section, key, value):
        tmpl_path = os.path.join(self._sysvol_base(gpo_guid),
                                 "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")
        try:
            cfg = configparser.ConfigParser(strict=False)
            if os.path.exists(tmpl_path): cfg.read(tmpl_path, encoding="utf-8")
            if not cfg.has_section(section): cfg.add_section(section)
            cfg.set(section, key, str(value))
            os.makedirs(os.path.dirname(tmpl_path), exist_ok=True)
            with open(tmpl_path, "w", encoding="utf-8") as f:
                cfg.write(f)
            self._bump_version(gpo_guid)
            return {"ok": True}
        except Exception as e:
            return {"error": str(e)}

    def read_file(self, gpo_guid, rel_path):
        full = os.path.normpath(os.path.join(self._sysvol_base(gpo_guid), rel_path))
        base = self._sysvol_base(gpo_guid)
        if not full.startswith(base):
            return {"error": "Caminho inválido"}
        if not os.path.exists(full):
            return {"content": "", "exists": False}
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                return {"content": f.read(), "exists": True}
        except Exception as e:
            return {"error": str(e)}

    def write_file(self, gpo_guid, rel_path, content):
        full = os.path.normpath(os.path.join(self._sysvol_base(gpo_guid), rel_path))
        base = self._sysvol_base(gpo_guid)
        if not full.startswith(base):
            return {"error": "Caminho inválido"}
        try:
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as f:
                f.write(content)
            self._bump_version(gpo_guid)
            return {"ok": True}
        except Exception as e:
            return {"error": str(e)}

    def list_files(self, gpo_guid):
        base = self._sysvol_base(gpo_guid)
        if not os.path.isdir(base):
            return {"files": []}
        files = []
        for root, dirs, filenames in os.walk(base):
            for fn in filenames:
                rel = os.path.relpath(os.path.join(root, fn), base).replace(os.sep, "/")
                files.append(rel)
        return {"files": sorted(files)}

    def rename(self, gpo_guid, new_name):
        domain_dn = _ad_get_domain_dn()
        dn = f"CN={gpo_guid},CN=Policies,CN=System,{domain_dn}"
        ldif = f"dn: {dn}\nchangetype: modify\nreplace: displayName\ndisplayName: {new_name}\n"
        r = _ldbmodify(ldif)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def get_links(self, gpo_guid):
        """Return list of OUs that link to this GPO (searches gpLink attribute)."""
        domain_dn = _ad_get_domain_dn()
        r = _ldbsearch(domain_dn, "sub", ["dn", "gpLink", "distinguishedName"],
                        f"(gpLink=*{gpo_guid}*)")
        if r["returncode"] != 0:
            return {"links": []}
        entries = _parse_ldb_output(r["stdout"])
        links = []
        for e in entries:
            links.append({"dn": e.get("dn", ""), "name": e.get("dn", "").split(",")[0].split("=")[-1]})
        return {"links": links}

    # ── Status ────────────────────────────────────────────────────────────────

    def get_gpo_full(self, gpo_guid):
        """Detalhes completos: metadata AD + configs SYSVOL."""
        domain_dn = _ad_get_domain_dn()
        dn = f"CN={gpo_guid},CN=Policies,CN=System,{domain_dn}"
        r  = _ldbsearch(dn, "base",
                        ["displayName", "versionNumber", "flags",
                         "gPCFileSysPath", "whenCreated", "whenChanged"])
        entries = _parse_ldb_output(r["stdout"])
        meta    = entries[0] if entries else {}
        gpt_path = os.path.join(self._sysvol_base(gpo_guid), "GPT.INI")
        gpt_ini  = {}
        if os.path.exists(gpt_path):
            ini = configparser.ConfigParser(strict=False)
            ini.read(gpt_path)
            if ini.has_section("General"):
                gpt_ini = dict(ini.items("General"))
        files = self.list_files(gpo_guid)
        return {
            "guid":        gpo_guid,
            "displayName": meta.get("displayName", ""),
            "flags":       int(meta.get("flags", "0") or "0"),
            "fileSysPath": meta.get("gPCFileSysPath", ""),
            "whenCreated": meta.get("whenCreated", ""),
            "whenChanged": meta.get("whenChanged", ""),
            "gpt_ini":     gpt_ini,
            "files":       files.get("files", []),
        }

    def get_status(self, gpo_guid):
        """Retorna computer_enabled e user_enabled baseado nos flags do objeto GPO no AD."""
        domain_dn = _ad_get_domain_dn()
        dn = f"CN={gpo_guid},CN=Policies,CN=System,{domain_dn}"
        r  = _ldbsearch(dn, "base", ["flags"])
        entries = _parse_ldb_output(r["stdout"])
        flags   = int(entries[0].get("flags", "0") or "0") if entries else 0
        return {"computer_enabled": not bool(flags & 2), "user_enabled": not bool(flags & 1)}

    def set_status(self, gpo_guid, computer_enabled, user_enabled):
        """Define flags: 0=ambos on, 1=user off, 2=machine off, 3=ambos off."""
        flags = 0
        if not user_enabled:     flags |= 1
        if not computer_enabled: flags |= 2
        domain_dn = _ad_get_domain_dn()
        dn   = f"CN={gpo_guid},CN=Policies,CN=System,{domain_dn}"
        ldif = f"dn: {dn}\nchangetype: modify\nreplace: flags\nflags: {flags}\n"
        r    = _ldbmodify(ldif)
        return {"ok": r["returncode"] == 0}

    # ── Helpers gPLink ────────────────────────────────────────────────────────

    def _parse_gplink(self, gplink_str):
        """Parse gPLink attribute: [LDAP://dn;flags][LDAP://dn;flags]..."""
        import re
        links = []
        for m in re.finditer(r'\[LDAP://([^;]+);(\d+)\]', gplink_str, re.IGNORECASE):
            dn    = m.group(1)
            flags = int(m.group(2))
            links.append({
                "dn":       dn,
                "flags":    flags,
                "enabled":  not bool(flags & 1),
                "enforced": bool(flags & 2),
            })
        return links

    def _build_gplink(self, links):
        return "".join(f"[LDAP://{l['dn']};{l['flags']}]" for l in links)

    def _modify_gplink_flag(self, gplink_str, gpo_guid, enabled=None, enforced=None):
        links = self._parse_gplink(gplink_str)
        for l in links:
            if gpo_guid.lower() in l["dn"].lower():
                flags = l["flags"]
                if enabled  is not None: flags = (flags & ~1) if enabled  else (flags | 1)
                if enforced is not None: flags = (flags | 2)  if enforced else (flags & ~2)
                l["flags"]    = flags
                l["enabled"]  = not bool(flags & 1)
                l["enforced"] = bool(flags & 2)
        return self._build_gplink(links)

    def _extract_guid_from_dn(self, dn):
        import re
        m = re.search(r'\{([0-9A-Fa-f-]+)\}', dn)
        return '{' + m.group(1) + '}' if m else dn

    # ── Links avançados ───────────────────────────────────────────────────────

    def set_link_enforced(self, gpo_guid, container_dn, enforced):
        """Modifica flag de enforcement no gPLink da OU."""
        r = _ldbsearch(container_dn, "base", ["gPLink"])
        entries = _parse_ldb_output(r["stdout"])
        if not entries: return {"error": "Container não encontrado"}
        gplink     = entries[0].get("gPLink", "")
        new_gplink = self._modify_gplink_flag(gplink, gpo_guid, enforced=enforced)
        ldif = f"dn: {container_dn}\nchangetype: modify\nreplace: gPLink\ngPLink: {new_gplink}\n"
        r    = _ldbmodify(ldif)
        return {"ok": r["returncode"] == 0}

    def set_link_enabled(self, gpo_guid, container_dn, enabled):
        """Habilita/desabilita link (flag bit 0)."""
        r = _ldbsearch(container_dn, "base", ["gPLink"])
        entries = _parse_ldb_output(r["stdout"])
        if not entries: return {"error": "Container não encontrado"}
        gplink     = entries[0].get("gPLink", "")
        new_gplink = self._modify_gplink_flag(gplink, gpo_guid, enabled=enabled)
        ldif = f"dn: {container_dn}\nchangetype: modify\nreplace: gPLink\ngPLink: {new_gplink}\n"
        r    = _ldbmodify(ldif)
        return {"ok": r["returncode"] == 0}

    def set_link_order(self, container_dn, gpo_guid, new_position):
        """Reordena GPO no gPLink. position é 0-based."""
        r = _ldbsearch(container_dn, "base", ["gPLink"])
        entries = _parse_ldb_output(r["stdout"])
        if not entries: return {"error": "Container não encontrado"}
        gplink = entries[0].get("gPLink", "")
        links  = self._parse_gplink(gplink)
        idx    = next((i for i, l in enumerate(links) if gpo_guid.lower() in l["dn"].lower()), None)
        if idx is None: return {"error": "Link não encontrado"}
        item = links.pop(idx)
        links.insert(min(new_position, len(links)), item)
        new_gplink = self._build_gplink(links)
        ldif = f"dn: {container_dn}\nchangetype: modify\nreplace: gPLink\ngPLink: {new_gplink}\n"
        r    = _ldbmodify(ldif)
        return {"ok": r["returncode"] == 0}

    def set_block_inheritance(self, container_dn, blocked):
        """gPOptions: 0=normal, 1=block inheritance."""
        val  = "1" if blocked else "0"
        ldif = f"dn: {container_dn}\nchangetype: modify\nreplace: gPOptions\ngPOptions: {val}\n"
        r    = _ldbmodify(ldif)
        return {"ok": r["returncode"] == 0}

    def get_inheritance_info(self, container_dn):
        """Retorna block_inheritance status e GPOs vinculadas com flags."""
        r = _ldbsearch(container_dn, "base", ["gPLink", "gPOptions"])
        entries = _parse_ldb_output(r["stdout"])
        if not entries: return {"error": "Container não encontrado"}
        blocked = entries[0].get("gPOptions", "0") == "1"
        gplink  = entries[0].get("gPLink",   "")
        links   = self._parse_gplink(gplink)
        enriched = []
        for l in links:
            guid = self._extract_guid_from_dn(l["dn"])
            enriched.append({
                "guid":     guid,
                "dn":       l["dn"],
                "enforced": l["enforced"],
                "enabled":  l["enabled"],
            })
        return {"blocked": blocked, "links": enriched}

    # ── Security Filtering ────────────────────────────────────────────────────

    def get_security_filtering(self, gpo_guid):
        """Retorna lista de principals com Apply Group Policy permission."""
        domain_dn = _ad_get_domain_dn()
        dn = f"CN={gpo_guid},CN=Policies,CN=System,{domain_dn}"
        r  = _ldbsearch(dn, "base", ["nTSecurityDescriptor"])
        return {"principals": ["Authenticated Users"], "raw": r.get("stdout", "")}

    def set_security_filtering(self, gpo_guid, principal, action):
        return {"ok": False, "error": "Use samba-tool diretamente para modificar ACLs do GPO"}

    # ── WMI Filters ───────────────────────────────────────────────────────────

    def list_wmi_filters(self):
        domain_dn = _ad_get_domain_dn()
        r = _ldbsearch(f"CN=SOM,CN=WMIPolicy,CN=System,{domain_dn}", "one",
                       ["cn", "msWMI-Name", "msWMI-Parm1", "msWMI-Parm2", "distinguishedName"],
                       "(objectClass=msWMI-Som)")
        if r["returncode"] != 0: return {"filters": []}
        entries = _parse_ldb_output(r["stdout"])
        filters = []
        for e in entries:
            filters.append({
                "dn":          e.get("dn", ""),
                "name":        e.get("msWMI-Name", e.get("cn", "")),
                "description": e.get("msWMI-Parm1", ""),
                "query":       e.get("msWMI-Parm2", ""),
            })
        return {"filters": filters}

    def create_wmi_filter(self, name, description, query):
        import uuid as _uuid
        guid      = str(_uuid.uuid4())
        domain_dn = _ad_get_domain_dn()
        dn        = f"CN={guid},CN=SOM,CN=WMIPolicy,CN=System,{domain_dn}"
        now       = time.strftime("%Y%m%d%H%M%S.000000-000")
        parm2     = f"1;3;10;{len(query)};WQL;root\\CIMv2;{query};"
        ldif      = (f"dn: {dn}\nobjectClass: msWMI-Som\nmsWMI-Name: {name}\n"
                     f"msWMI-Parm1: {description}\nmsWMI-Parm2: {parm2}\n"
                     f"msWMI-ID: {{{guid}}}\nmsWMI-Author: Administrator\n"
                     f"msWMI-ChangeDate: {now}\nmsWMI-CreationDate: {now}\n")
        r = _ldbadd(ldif)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def delete_wmi_filter(self, filter_dn):
        r = _ldbdel(filter_dn)
        return {"ok": r["returncode"] == 0}

    def get_wmi_filter(self, gpo_guid):
        domain_dn = _ad_get_domain_dn()
        dn  = f"CN={gpo_guid},CN=Policies,CN=System,{domain_dn}"
        r   = _ldbsearch(dn, "base", ["gPCWQLFilter"])
        entries = _parse_ldb_output(r["stdout"])
        wmi_ref = entries[0].get("gPCWQLFilter", "") if entries else ""
        return {"wmi_filter": wmi_ref}

    def set_wmi_filter(self, gpo_guid, wmi_filter_dn):
        domain_dn = _ad_get_domain_dn()
        dn = f"CN={gpo_guid},CN=Policies,CN=System,{domain_dn}"
        if wmi_filter_dn:
            ldif = f"dn: {dn}\nchangetype: modify\nreplace: gPCWQLFilter\ngPCWQLFilter: {wmi_filter_dn}\n"
        else:
            ldif = f"dn: {dn}\nchangetype: modify\ndelete: gPCWQLFilter\n"
        r = _ldbmodify(ldif)
        return {"ok": r["returncode"] == 0}

    # ── Security Settings estruturado ─────────────────────────────────────────

    def sec_get_template(self):
        """Retorna estrutura completa de configurações de segurança."""
        return {"categories": {
            "Account Policies": {
                "Password Policy": {
                    "section": "System Access",
                    "settings": [
                        {"key":"MinimumPasswordAge",          "label":"Idade mínima da senha",              "type":"number",  "unit":"dias",       "min":0,"max":999,  "default":1},
                        {"key":"MaximumPasswordAge",          "label":"Idade máxima da senha",              "type":"number",  "unit":"dias",       "min":0,"max":999,  "default":42},
                        {"key":"MinimumPasswordLength",       "label":"Comprimento mínimo",                 "type":"number",  "unit":"caracteres", "min":0,"max":128,  "default":7},
                        {"key":"PasswordComplexity",          "label":"Requisitos de complexidade",         "type":"boolean", "default":1},
                        {"key":"PasswordHistorySize",         "label":"Histórico de senhas",                "type":"number",  "unit":"senhas",     "min":0,"max":24,   "default":24},
                        {"key":"ClearTextPassword",           "label":"Criptografia reversível",            "type":"boolean", "default":0},
                        {"key":"RequireLogonToChangePassword","label":"Exigir logon para alterar",          "type":"boolean", "default":0},
                        {"key":"ForceLogoffWhenHourExpire",   "label":"Forçar logoff qdo horário expirar",  "type":"boolean", "default":0},
                    ]
                },
                "Account Lockout Policy": {
                    "section": "System Access",
                    "settings": [
                        {"key":"LockoutBadCount",   "label":"Limite de bloqueio",  "type":"number","unit":"tentativas","min":0,"max":999,  "default":0},
                        {"key":"ResetLockoutCount", "label":"Zerar contador após", "type":"number","unit":"minutos",   "min":0,"max":99999,"default":30},
                        {"key":"LockoutDuration",   "label":"Duração do bloqueio", "type":"number","unit":"minutos",   "min":0,"max":99999,"default":30},
                    ]
                },
                "Kerberos Policy": {
                    "section": "Kerberos Policy",
                    "settings": [
                        {"key":"MaxTicketAge",        "label":"Vida máxima do ticket",  "type":"number","unit":"horas",   "default":10},
                        {"key":"MaxRenewAge",         "label":"Renovação máxima",        "type":"number","unit":"dias",    "default":7},
                        {"key":"MaxServiceAge",       "label":"Vida do service ticket",  "type":"number","unit":"minutos","default":600},
                        {"key":"MaxClockSkew",        "label":"Tolerância de clock",     "type":"number","unit":"minutos","default":5},
                        {"key":"TicketValidateClient","label":"Validar cliente",          "type":"boolean","default":1},
                    ]
                }
            },
            "Local Policies": {
                "Audit Policy": {
                    "section": "Event Audit",
                    "settings": [
                        {"key":"AuditSystemEvents",    "label":"Eventos do sistema",       "type":"audit"},
                        {"key":"AuditLogonEvents",     "label":"Eventos de logon",          "type":"audit"},
                        {"key":"AuditObjectAccess",    "label":"Acesso a objetos",          "type":"audit"},
                        {"key":"AuditPrivilegeUse",    "label":"Uso de privilégio",         "type":"audit"},
                        {"key":"AuditPolicyChange",    "label":"Mudança de política",       "type":"audit"},
                        {"key":"AuditAccountManage",   "label":"Gerenciamento de contas",   "type":"audit"},
                        {"key":"AuditProcessTracking", "label":"Rastreamento de processos", "type":"audit"},
                        {"key":"AuditDSAccess",        "label":"Acesso ao DS",              "type":"audit"},
                        {"key":"AuditAccountLogon",    "label":"Logon de conta",            "type":"audit"},
                    ]
                },
                "User Rights Assignment": {
                    "section": "Privilege Rights",
                    "settings": [
                        {"key":"SeNetworkLogonRight",              "label":"Acesso pela rede",              "type":"sid_list"},
                        {"key":"SeDenyNetworkLogonRight",          "label":"Negar acesso pela rede",        "type":"sid_list"},
                        {"key":"SeInteractiveLogonRight",          "label":"Logon local",                   "type":"sid_list"},
                        {"key":"SeDenyInteractiveLogonRight",      "label":"Negar logon local",             "type":"sid_list"},
                        {"key":"SeRemoteInteractiveLogonRight",    "label":"Logon via RDP",                 "type":"sid_list"},
                        {"key":"SeDenyRemoteInteractiveLogonRight","label":"Negar logon RDP",               "type":"sid_list"},
                        {"key":"SeBatchLogonRight",                "label":"Logon como batch",              "type":"sid_list"},
                        {"key":"SeServiceLogonRight",              "label":"Logon como serviço",            "type":"sid_list"},
                        {"key":"SeBackupPrivilege",                "label":"Backup",                        "type":"sid_list"},
                        {"key":"SeRestorePrivilege",               "label":"Restaurar",                     "type":"sid_list"},
                        {"key":"SeShutdownPrivilege",              "label":"Desligar sistema",              "type":"sid_list"},
                        {"key":"SeDebugPrivilege",                 "label":"Depurar programas",             "type":"sid_list"},
                        {"key":"SeAuditPrivilege",                 "label":"Gerar auditorias",              "type":"sid_list"},
                        {"key":"SeChangeNotifyPrivilege",          "label":"Ignorar verificação transversal","type":"sid_list"},
                        {"key":"SeRemoteShutdownPrivilege",        "label":"Shutdown remoto",               "type":"sid_list"},
                        {"key":"SeIncreaseQuotaPrivilege",         "label":"Ajustar quotas",                "type":"sid_list"},
                        {"key":"SeLoadDriverPrivilege",            "label":"Carregar drivers",              "type":"sid_list"},
                        {"key":"SeSystemtimePrivilege",            "label":"Alterar hora",                  "type":"sid_list"},
                        {"key":"SeTakeOwnershipPrivilege",         "label":"Tomar posse",                   "type":"sid_list"},
                        {"key":"SeSecurityPrivilege",              "label":"Gerenciar auditoria",           "type":"sid_list"},
                        {"key":"SeSystemEnvironmentPrivilege",     "label":"Modificar firmware",            "type":"sid_list"},
                        {"key":"SeProfileSingleProcessPrivilege",  "label":"Perfil processo único",         "type":"sid_list"},
                        {"key":"SeSystemProfilePrivilege",         "label":"Perfil do sistema",             "type":"sid_list"},
                        {"key":"SeCreatePagefilePrivilege",        "label":"Criar pagefile",                "type":"sid_list"},
                        {"key":"SeCreateGlobalPrivilege",          "label":"Criar objetos globais",         "type":"sid_list"},
                        {"key":"SeImpersonatePrivilege",           "label":"Personificar cliente",          "type":"sid_list"},
                        {"key":"SeAssignPrimaryTokenPrivilege",    "label":"Substituir token",              "type":"sid_list"},
                        {"key":"SeManageVolumePrivilege",          "label":"Manutenção de volume",          "type":"sid_list"},
                        {"key":"SeIncreaseBasePriorityPrivilege",  "label":"Aumentar prioridade",           "type":"sid_list"},
                        {"key":"SeCreateSymbolicLinkPrivilege",    "label":"Links simbólicos",              "type":"sid_list"},
                        {"key":"SeEnableDelegationPrivilege",      "label":"Habilitar delegação",           "type":"sid_list"},
                        {"key":"SeLockMemoryPrivilege",            "label":"Bloquear memória",              "type":"sid_list"},
                        {"key":"SeTimeZonePrivilege",              "label":"Alterar fuso horário",          "type":"sid_list"},
                        {"key":"SeUndockPrivilege",                "label":"Remover da base",               "type":"sid_list"},
                    ]
                },
                "Security Options": {
                    "section": "Registry Values",
                    "settings": [
                        {"key":"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA","label":"UAC: Modo aprovação admin","type":"reg_dword","default":1},
                        {"key":"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin","label":"UAC: Prompt admin","type":"reg_dword","options":[{"v":0,"l":"Elevar sem pedir"},{"v":1,"l":"Credenciais desktop seguro"},{"v":2,"l":"Consentimento desktop seguro"},{"v":3,"l":"Credenciais"},{"v":4,"l":"Consentimento"},{"v":5,"l":"Consentimento non-Windows"}]},
                        {"key":"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser","label":"UAC: Prompt user","type":"reg_dword","options":[{"v":0,"l":"Negar auto"},{"v":1,"l":"Credenciais desktop seguro"},{"v":3,"l":"Pedir credenciais"}]},
                        {"key":"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs","label":"Timeout inatividade","type":"reg_dword","unit":"seg","default":900},
                        {"key":"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\legalnoticecaption","label":"Aviso legal: título","type":"reg_sz"},
                        {"key":"MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\legalnoticetext","label":"Aviso legal: texto","type":"reg_multi_sz"},
                        {"key":"MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount","label":"Logons em cache","type":"reg_sz","default":"10"},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel","label":"Nível autenticação LM","type":"reg_dword","options":[{"v":0,"l":"LM & NTLM"},{"v":1,"l":"LM & NTLM, NTLMv2 negociado"},{"v":2,"l":"Só NTLM"},{"v":3,"l":"Só NTLMv2"},{"v":4,"l":"NTLMv2, recusar LM"},{"v":5,"l":"NTLMv2, recusar LM & NTLM"}],"default":3},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash","label":"Não armazenar hash LM","type":"reg_dword","default":1},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous","label":"Restringir anônimo","type":"reg_dword"},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM","label":"Restringir anônimo SAM","type":"reg_dword","default":1},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous","label":"Everyone inclui anônimo","type":"reg_dword"},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableSecuritySignature","label":"SMB: habilitar assinatura","type":"reg_dword"},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature","label":"SMB: exigir assinatura","type":"reg_dword"},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\DisablePasswordChange","label":"Desabilitar mudança pwd máquina","type":"reg_dword"},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\MaximumPasswordAge","label":"Idade máx pwd máquina","type":"reg_dword","unit":"dias","default":30},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SignSecureChannel","label":"Assinar canal seguro","type":"reg_dword","default":1},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SealSecureChannel","label":"Criptografar canal seguro","type":"reg_dword","default":1},
                        {"key":"MACHINE\\System\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity","label":"LDAP: integridade","type":"reg_dword","options":[{"v":0,"l":"Nenhum"},{"v":1,"l":"Negociar"},{"v":2,"l":"Exigir"}],"default":1},
                    ]
                }
            },
            "Event Log": {
                "Log Settings": {
                    "section": "Event Log",
                    "settings": [
                        {"key":"MaximumLogSize",        "label":"Tam. máx log Application","type":"number","unit":"KB","default":20480},
                        {"key":"MaximumSecurityLogSize","label":"Tam. máx log Security",    "type":"number","unit":"KB","default":20480},
                        {"key":"MaximumSystemLogSize",  "label":"Tam. máx log System",       "type":"number","unit":"KB","default":20480},
                    ]
                }
            },
            "Restricted Groups": {"Group Membership": {"section":"Group Membership",       "settings":[],"dynamic":True}},
            "System Services":   {"Service Settings":  {"section":"Service General Setting","settings":[],"dynamic":True}},
        }}

    def sec_read_all(self, gpo_guid):
        """Lê GptTmpl.inf e retorna valores por seção."""
        tmpl_path = os.path.join(self._sysvol_base(gpo_guid),
                                 "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")
        if not os.path.exists(tmpl_path):
            return {"sections": {}}
        cfg = configparser.ConfigParser(strict=False)
        cfg.read(tmpl_path, encoding="utf-8")
        result = {}
        for section in cfg.sections():
            result[section] = dict(cfg.items(section))
        return {"sections": result}

    def sec_write(self, gpo_guid, section, key, value):
        return self.set_security_setting(gpo_guid, section, key, value)

    def sec_delete(self, gpo_guid, section, key):
        tmpl_path = os.path.join(self._sysvol_base(gpo_guid),
                                 "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")
        cfg = configparser.ConfigParser(strict=False)
        if os.path.exists(tmpl_path): cfg.read(tmpl_path, encoding="utf-8")
        if cfg.has_section(section) and cfg.has_option(section, key):
            cfg.remove_option(section, key)
            with open(tmpl_path, "w", encoding="utf-8") as f:
                cfg.write(f)
            self._bump_version(gpo_guid)
            return {"ok": True}
        return {"ok": False, "error": "Configuração não encontrada"}

    # ── Preferences ───────────────────────────────────────────────────────────

    def pref_list_types(self):
        return {"types": [
            {"id":"drives",       "label":"Mapeamento de Unidades",  "scope":"user",    "xml_path":"User/Preferences/Drives/Drives.xml",                               "tag":"Drive"},
            {"id":"registry",     "label":"Registro",                "scope":"both",    "xml_path":"{scope}/Preferences/Registry/Registry.xml",                        "tag":"Registry"},
            {"id":"files",        "label":"Arquivos",                "scope":"both",    "xml_path":"{scope}/Preferences/Files/Files.xml",                              "tag":"File"},
            {"id":"folders",      "label":"Pastas",                  "scope":"both",    "xml_path":"{scope}/Preferences/Folders/Folders.xml",                          "tag":"Folder"},
            {"id":"shortcuts",    "label":"Atalhos",                 "scope":"both",    "xml_path":"{scope}/Preferences/Shortcuts/Shortcuts.xml",                      "tag":"Shortcut"},
            {"id":"environment",  "label":"Variáveis de Ambiente",   "scope":"both",    "xml_path":"{scope}/Preferences/EnvironmentVariables/EnvironmentVariables.xml", "tag":"EnvironmentVariable"},
            {"id":"inifiles",     "label":"Arquivos INI",            "scope":"both",    "xml_path":"{scope}/Preferences/IniFiles/IniFiles.xml",                        "tag":"Ini"},
            {"id":"services",     "label":"Serviços",                "scope":"machine", "xml_path":"Machine/Preferences/Services/Services.xml",                        "tag":"NTService"},
            {"id":"scheduledtasks","label":"Tarefas Agendadas",      "scope":"both",    "xml_path":"{scope}/Preferences/ScheduledTasks/ScheduledTasks.xml",             "tag":"Task"},
            {"id":"networkshares","label":"Compartilhamentos",       "scope":"machine", "xml_path":"Machine/Preferences/NetworkShares/NetworkShares.xml",               "tag":"NetworkShare"},
            {"id":"printers",     "label":"Impressoras",             "scope":"both",    "xml_path":"{scope}/Preferences/Printers/Printers.xml",                        "tag":"SharedPrinter"},
            {"id":"localusers",   "label":"Usuários/Grupos Locais",  "scope":"machine", "xml_path":"Machine/Preferences/LocalUsersAndGroups/LocalUsersAndGroups.xml",   "tag":"User"},
            {"id":"poweroptions", "label":"Opções de Energia",       "scope":"both",    "xml_path":"{scope}/Preferences/PowerOptions/PowerOptions.xml",                 "tag":"PowerScheme"},
            {"id":"internet",     "label":"Config. Internet",        "scope":"both",    "xml_path":"{scope}/Preferences/InternetSettings/InternetSettings.xml",         "tag":"Ie"},
            {"id":"regional",     "label":"Opções Regionais",        "scope":"user",    "xml_path":"User/Preferences/RegionalOptions/RegionalOptions.xml",              "tag":"Regional"},
        ]}

    def pref_list_items(self, gpo_guid, scope, pref_type):
        import xml.etree.ElementTree as ET
        type_info = next((t for t in self.pref_list_types()["types"] if t["id"] == pref_type), None)
        if not type_info: return {"error": "Tipo desconhecido"}
        xml_path = type_info["xml_path"].replace("{scope}", "Machine" if scope == "machine" else "User")
        result   = self.read_file(gpo_guid, xml_path)
        content  = result.get("content", "")
        if not content.strip(): return {"items": []}
        try:
            root  = ET.fromstring(content)
            items = []
            for elem in root:
                props_el = elem.find("Properties")
                props    = dict(props_el.attrib) if props_el is not None else {}
                items.append({
                    "uid":        elem.get("uid", ""),
                    "name":       elem.get("name", props.get("path", props.get("letter", props.get("serviceName", "")))),
                    "action":     props.get("action", ""),
                    "properties": props,
                    "tag":        elem.tag,
                })
            return {"items": items}
        except Exception as e:
            return {"error": str(e)}

    def pref_add_item(self, gpo_guid, scope, pref_type, properties):
        import uuid as _uuid
        import xml.etree.ElementTree as ET
        type_info = next((t for t in self.pref_list_types()["types"] if t["id"] == pref_type), None)
        if not type_info: return {"error": "Tipo desconhecido"}
        xml_path = type_info["xml_path"].replace("{scope}", "Machine" if scope == "machine" else "User")
        tag      = type_info["tag"]
        uid      = "{" + str(_uuid.uuid4()).upper() + "}"
        now      = time.strftime("%Y-%m-%d %H:%M:%S")
        result   = self.read_file(gpo_guid, xml_path)
        content  = result.get("content", "").strip()
        if content:
            try:    root = ET.fromstring(content)
            except: root = ET.Element(tag + "s")
        else:
            root = ET.Element(tag + "s")
        elem     = ET.SubElement(root, tag, uid=uid, changed=now,
                                 name=str(properties.get("name", "")))
        props_el = ET.SubElement(elem, "Properties")
        for k, v in properties.items():
            props_el.set(k, str(v))
        xml_str = '<?xml version="1.0" encoding="utf-8"?>\r\n' + ET.tostring(root, encoding="unicode")
        wr = self.write_file(gpo_guid, xml_path, xml_str)
        return {**wr, "uid": uid}

    def pref_update_item(self, gpo_guid, scope, pref_type, item_uid, properties):
        import xml.etree.ElementTree as ET
        type_info = next((t for t in self.pref_list_types()["types"] if t["id"] == pref_type), None)
        if not type_info: return {"error": "Tipo desconhecido"}
        xml_path = type_info["xml_path"].replace("{scope}", "Machine" if scope == "machine" else "User")
        result   = self.read_file(gpo_guid, xml_path)
        content  = result.get("content", "")
        if not content: return {"error": "Arquivo não encontrado"}
        root = ET.fromstring(content)
        for elem in root:
            if elem.get("uid") == item_uid:
                elem.set("changed", time.strftime("%Y-%m-%d %H:%M:%S"))
                props_el = elem.find("Properties")
                if props_el is None: props_el = ET.SubElement(elem, "Properties")
                for k, v in properties.items(): props_el.set(k, str(v))
                break
        xml_str = '<?xml version="1.0" encoding="utf-8"?>\r\n' + ET.tostring(root, encoding="unicode")
        return self.write_file(gpo_guid, xml_path, xml_str)

    def pref_delete_item(self, gpo_guid, scope, pref_type, item_uid):
        import xml.etree.ElementTree as ET
        type_info = next((t for t in self.pref_list_types()["types"] if t["id"] == pref_type), None)
        if not type_info: return {"error": "Tipo desconhecido"}
        xml_path = type_info["xml_path"].replace("{scope}", "Machine" if scope == "machine" else "User")
        result   = self.read_file(gpo_guid, xml_path)
        content  = result.get("content", "")
        if not content: return {"error": "Arquivo não encontrado"}
        root = ET.fromstring(content)
        for elem in list(root):
            if elem.get("uid") == item_uid:
                root.remove(elem)
                break
        xml_str = '<?xml version="1.0" encoding="utf-8"?>\r\n' + ET.tostring(root, encoding="unicode")
        return self.write_file(gpo_guid, xml_path, xml_str)


class _ShareManager:

    # Compartilhamentos de sistema que não precisam aparecer na lista
    _SYSTEM_SHARES = {"IPC$", "SMB1", "print$"}

    def list_shares(self):
        """Lê compartilhamentos diretamente do smb.conf — sem precisar de credenciais."""
        cfg = configparser.ConfigParser(strict=False)
        cfg.read(os.path.join(SAMBA_ETC, "smb.conf"))
        shares = []
        for section in cfg.sections():
            if section.lower() == "global":
                continue
            share_type = "Disk"
            if section in ("IPC$", "SMB1"):
                share_type = "IPC"
            path    = cfg.get(section, "path", fallback="")
            comment = cfg.get(section, "comment", fallback="")
            shares.append({"name": section, "type": share_type,
                           "comment": comment, "path": path})
        return {"shares": shares}

    def get_acl(self, share, path="/"):
        """Usa samba-tool ntacl get com o path local — não precisa de conexão SMB."""
        cfg = configparser.ConfigParser(strict=False)
        cfg.read(os.path.join(SAMBA_ETC, "smb.conf"))
        local_path = cfg.get(share, "path", fallback="") if cfg.has_section(share) else ""
        if not local_path:
            return {"acl": "", "error": f"Compartilhamento '{share}' não encontrado no smb.conf"}
        target = os.path.join(local_path, path.lstrip("/")) if path != "/" else local_path
        r = _samba_tool("ntacl", "get", target)
        if r["returncode"] != 0:
            return {"acl": "", "error": r["stderr"] or f"Falha ao ler ACL de {target}"}
        return {"acl": r["stdout"], "error": ""}

    def set_acl(self, share, path, acl_string, action="set"):
        flag = {"set": "-S", "add": "-a", "delete": "-D", "modify": "-M"}.get(action.lower(), "-S")
        r = _ad_run_cmd([os.path.join(SAMBA_BIN, "smbcacls"), f"//localhost/{share}", path,
                         "-N", flag, acl_string])
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def create_share(self, name, path, comment="", read_only=False):
        smb_conf = os.path.join(SAMBA_ETC, "smb.conf")
        try:
            with open(smb_conf, "a") as f:
                f.write(f"\n[{name}]\n    path = {path}\n")
                if comment: f.write(f"    comment = {comment}\n")
                f.write(f"    read only = {'yes' if read_only else 'no'}\n")
            _ad_run_cmd([os.path.join(SAMBA_BIN, "smbcontrol"), "smbd", "reload-config"])
            return {"ok": True}
        except Exception as e:
            return {"error": str(e)}

    def browse_path(self, local_path):
        try:
            entries = []
            for name in os.listdir(local_path):
                full = os.path.join(local_path, name)
                try:
                    s = os.stat(full)
                    entries.append({"name": name, "path": full, "is_dir": os.path.isdir(full),
                                    "size": s.st_size, "modified": s.st_mtime,
                                    "mode": oct(stat.S_IMODE(s.st_mode))})
                except OSError:
                    entries.append({"name": name, "path": full, "is_dir": False})
            return {"entries": sorted(entries, key=lambda x: (not x["is_dir"], x["name"]))}
        except Exception as e:
            return {"error": str(e)}

    def set_posix_acl(self, path, owner="", group="", mode=""):
        try:
            if owner or group:
                import pwd, grp as grpmod
                uid = pwd.getpwnam(owner).pw_uid if owner else -1
                gid = grpmod.getgrnam(group).gr_gid if group else -1
                os.chown(path, uid, gid)
            if mode:
                os.chmod(path, int(mode, 8))
            return {"ok": True}
        except Exception as e:
            return {"error": str(e)}

    def create_directory(self, path):
        try:
            os.makedirs(path, exist_ok=True)
            return {"ok": True}
        except Exception as e:
            return {"error": str(e)}

    # ── Helpers smb.conf ──────────────────────────────────────────────────────

    def _smb_conf_path(self):
        return os.path.join(SAMBA_ETC, "smb.conf")

    def _reload_samba(self):
        _ad_run_cmd([os.path.join(SAMBA_BIN, "smbcontrol"), "smbd", "reload-config"])

    # ── Gerenciamento avançado de shares ──────────────────────────────────────

    def get_share_full(self, share_name):
        """Lê todas as opções do smb.conf + info do disco."""
        cfg = configparser.ConfigParser(strict=False)
        cfg.read(self._smb_conf_path())
        if not cfg.has_section(share_name):
            return {"error": f"Share '{share_name}' não encontrado"}
        options = dict(cfg.items(share_name))
        path    = options.get("path", "")
        disk    = {}
        if path and os.path.exists(path):
            try:
                sv = os.statvfs(path)
                disk = {
                    "total": sv.f_frsize * sv.f_blocks,
                    "free":  sv.f_frsize * sv.f_bfree,
                    "used":  sv.f_frsize * (sv.f_blocks - sv.f_bfree),
                }
            except Exception: pass
        return {"name": share_name, "options": options, "disk": disk}

    def update_share(self, share_name, options_dict):
        """Atualiza opções no smb.conf. None remove a opção."""
        cfg      = configparser.ConfigParser(strict=False)
        smb_conf = self._smb_conf_path()
        cfg.read(smb_conf)
        if not cfg.has_section(share_name):
            return {"error": f"Share '{share_name}' não encontrado"}
        for key, value in options_dict.items():
            if value is None:
                if cfg.has_option(share_name, key): cfg.remove_option(share_name, key)
            else:
                cfg.set(share_name, key, str(value))
        with open(smb_conf, "w") as f: cfg.write(f)
        self._reload_samba()
        return {"ok": True}

    def delete_share(self, share_name):
        """Remove seção do smb.conf."""
        cfg      = configparser.ConfigParser(strict=False)
        smb_conf = self._smb_conf_path()
        cfg.read(smb_conf)
        if not cfg.has_section(share_name):
            return {"error": f"Share '{share_name}' não encontrado"}
        cfg.remove_section(share_name)
        with open(smb_conf, "w") as f: cfg.write(f)
        self._reload_samba()
        return {"ok": True}

    def rename_share(self, old_name, new_name):
        """Renomeia seção no smb.conf."""
        cfg      = configparser.ConfigParser(strict=False)
        smb_conf = self._smb_conf_path()
        cfg.read(smb_conf)
        if not cfg.has_section(old_name):
            return {"error": f"Share '{old_name}' não encontrado"}
        if cfg.has_section(new_name):
            return {"error": f"Share '{new_name}' já existe"}
        options = dict(cfg.items(old_name))
        cfg.add_section(new_name)
        for k, v in options.items(): cfg.set(new_name, k, v)
        cfg.remove_section(old_name)
        with open(smb_conf, "w") as f: cfg.write(f)
        self._reload_samba()
        return {"ok": True}

    # ── SDDL / ACL helpers ────────────────────────────────────────────────────

    _WELL_KNOWN = {
        "S-1-1-0":    "Everyone",        "S-1-5-11":  "Authenticated Users",
        "S-1-5-18":   "SYSTEM",          "S-1-5-19":  "LOCAL SERVICE",
        "S-1-5-20":   "NETWORK SERVICE", "S-1-5-32-544": "Administrators",
        "S-1-5-32-545": "Users",         "S-1-5-32-546": "Guests",
        "S-1-5-32-547": "Power Users",   "S-1-5-32-548": "Account Operators",
        "S-1-5-32-549": "Server Operators","S-1-5-32-550":"Print Operators",
        "S-1-5-32-551": "Backup Operators","S-1-5-32-552":"Replicator",
        "S-1-3-0":    "CREATOR OWNER",   "S-1-3-1":   "CREATOR GROUP",
    }
    _SDDL_ALIAS = {
        "AO":"Account Operators",  "AN":"Anonymous",           "AU":"Authenticated Users",
        "BA":"Administrators",     "BG":"Guests",              "BO":"Backup Operators",
        "BU":"Users",              "CA":"Cert Publishers",     "CG":"CREATOR GROUP",
        "CO":"CREATOR OWNER",      "DA":"Domain Admins",       "DC":"Domain Computers",
        "DD":"Domain Controllers", "DG":"Domain Guests",       "DU":"Domain Users",
        "EA":"Enterprise Admins",  "ED":"Enterprise DCs",      "HI":"High Integrity",
        "LA":"Local Admin",        "LG":"Local Guest",         "LU":"Local Users",
        "LW":"Low Integrity",      "MU":"Performance Monitor Users",
        "NO":"Network Config Ops", "NS":"NETWORK SERVICE",     "NU":"Network",
        "OW":"Owner Rights",       "PO":"Printer Operators",   "PS":"SELF",
        "PU":"Power Users",        "RC":"Restricted Code",     "RD":"Remote Desktop Users",
        "RE":"Replicator",         "RS":"RAS Servers",         "RU":"Pre-Win2000 Compat",
        "SA":"Schema Admins",      "SI":"System Integrity",    "SO":"Server Operators",
        "SU":"Service",            "SY":"SYSTEM",              "WD":"Everyone",
        "WR":"WRITE RESTRICTED",   "LS":"LOCAL SERVICE",       "IU":"Interactive",
    }
    _PERM_BITS = [
        (0x1F01FF, "Controle Total"), (0x1301BF, "Modificar"),
        (0x1200A9, "Leitura e Execução"), (0x120116, "Gravação"), (0x120089, "Leitura"),
    ]
    _GRANULAR_BITS = [
        (0x00001, "Listar Pasta / Ler Dados"),           (0x00002, "Criar Arquivos / Gravar Dados"),
        (0x00004, "Criar Pastas / Acrescentar Dados"),   (0x00008, "Ler Atributos Estendidos"),
        (0x00010, "Gravar Atributos Estendidos"),        (0x00020, "Atravessar Pasta / Executar Arquivo"),
        (0x00040, "Excluir Subpastas e Arquivos"),       (0x00080, "Ler Atributos"),
        (0x00100, "Gravar Atributos"),                   (0x10000, "Excluir"),
        (0x20000, "Ler Permissões"),                     (0x40000, "Alterar Permissões"),
        (0x80000, "Apropriar-se"),
    ]
    _APPLIES_MAP = {
        "this_folder_only":             "",
        "this_folder_subfolders_files": "OICI",
        "subfolders_files_only":        "OICIIO",
        "this_folder_subfolders":       "CI",
        "this_folder_files":            "OI",
        "subfolders_only":              "CIIO",
        "files_only":                   "OIIO",
    }

    def _resolve_to_sid(self, principal):
        lp = principal.strip()
        for sid, name in self._WELL_KNOWN.items():
            if name.lower() == lp.lower(): return sid
        for alias, name in self._SDDL_ALIAS.items():
            if name.lower() == lp.lower(): return alias
        if lp.upper().startswith("S-"): return lp
        r = _ad_run_cmd(["wbinfo", "--name-to-sid", lp])
        if r["returncode"] == 0:
            for p in r["stdout"].strip().split():
                if p.upper().startswith("S-"): return p
        # Fallback: busca inversa no cache (nome → SID)
        _load_sid_cache()
        for sid, name in _SID_NAME_CACHE.items():
            if name.lower() == lp.lower():
                return sid
        return lp

    def _sid_to_name(self, sid):
        s = sid.strip()
        if s in self._SDDL_ALIAS: return self._SDDL_ALIAS[s]
        if s in self._WELL_KNOWN:  return self._WELL_KNOWN[s]
        r = _ad_run_cmd(["wbinfo", "--sid-to-name", s])
        if r["returncode"] == 0 and r["stdout"].strip():
            name = r["stdout"].strip().split("\\")[-1]
            return name.split(" ")[0]
        # Fallback: cache construído decodificando SIDs binários do sam.ldb
        _load_sid_cache()
        cached = _SID_NAME_CACHE.get(s.upper())
        if cached:
            return cached
        return s

    def _mask_to_permissions(self, mask):
        if isinstance(mask, str):
            try: mask = int(mask, 16) if mask.lower().startswith("0x") else int(mask, 0)
            except Exception: return [mask]
        if not mask: return []
        for m, name in self._PERM_BITS:
            if (mask & m) == m: return [name]
        return [name for bit, name in self._GRANULAR_BITS if mask & bit] or [hex(mask)]

    def _permissions_to_mask(self, permissions):
        if isinstance(permissions, str): permissions = [permissions]
        mask = 0
        for p in permissions:
            pu = p.strip().upper()
            for m, name in self._PERM_BITS:
                if name.upper() == pu: mask |= m; break
            else:
                for bit, name in self._GRANULAR_BITS:
                    if name.upper() == pu: mask |= bit; break
                else:
                    try: mask |= int(p, 16) if p.startswith("0x") else int(p)
                    except Exception: pass
        return mask

    def _applies_to_flags(self, applies_to):
        return self._APPLIES_MAP.get(applies_to, "OICI")

    def _flags_to_applies_to(self, flags):
        inv = {v: k for k, v in self._APPLIES_MAP.items()}
        f   = "".join(c for c in flags.upper() if c not in "ID")
        return inv.get(f, "this_folder_subfolders_files")

    def _parse_aces(self, aces_str):
        import re
        aces = []
        for i, m in enumerate(re.finditer(r'\(([^)]*)\)', aces_str)):
            fields = (m.group(1).split(";") + ["","","","","",""])[:6]
            ace_type = fields[0]; flags = fields[1]; rights = fields[2]; sid = fields[5]
            mask_val = 0
            try:
                mask_val = int(rights, 16) if rights.lower().startswith("0x") else (int(rights) if rights.isdigit() else 0)
            except Exception: pass
            aces.append({
                "index": i, "type": ace_type, "flags": flags, "rights": rights, "sid": sid, "mask": mask_val,
                "_display_type":        "Allow" if ace_type == "A" else ("Deny" if ace_type == "D" else ace_type),
                "_display_principal":   self._sid_to_name(sid),
                "_display_permissions": self._mask_to_permissions(mask_val),
                "_display_inherited":   "ID" in flags.upper(),
                "_display_applies_to":  self._flags_to_applies_to(flags),
            })
        return aces

    def _parse_sddl(self, sddl):
        import re
        result = {"owner_sid": "", "group_sid": "", "dacl": [], "sacl": [], "dacl_flags": ""}
        m = re.search(r'O:([A-Za-z]{2}|S-[\d\-]+)', sddl)
        if m: result["owner_sid"] = m.group(1)
        m = re.search(r'G:([A-Za-z]{2}|S-[\d\-]+)', sddl)
        if m: result["group_sid"] = m.group(1)
        m = re.search(r'D:([^(S]*)(\(.*?)(?=S:|$)', sddl, re.DOTALL)
        if m:
            result["dacl_flags"] = m.group(1)
            result["dacl"]       = self._parse_aces(m.group(2))
        m = re.search(r'S:[^(]*(\(.*)', sddl, re.DOTALL)
        if m:
            result["sacl"] = self._parse_aces(m.group(1))
        return result

    def _rebuild_sddl(self, owner, group, dacl_list, sacl_list, dacl_flags=""):
        def ace_str(a): return f"({a['type']};{a['flags']};{a['rights']};;;{a['sid']})"
        sddl = f"O:{owner}G:{group}D:{dacl_flags}"
        for a in dacl_list: sddl += ace_str(a)
        if sacl_list:
            sddl += "S:"
            for a in sacl_list: sddl += ace_str(a)
        return sddl

    # ── NTFS ACL methods ──────────────────────────────────────────────────────

    def get_ntfs_acl(self, local_path):
        r = _samba_tool("ntacl", "get", local_path, "--as-sddl")
        if r["returncode"] != 0:
            return {"error": r["stderr"] or "Falha ao ler ACL"}
        sddl   = r["stdout"].strip()
        parsed = self._parse_sddl(sddl)
        parsed["sddl"]       = sddl
        parsed["path"]       = local_path
        parsed["owner_name"] = self._sid_to_name(parsed["owner_sid"])
        parsed["group_name"] = self._sid_to_name(parsed["group_sid"])
        return {"acl": parsed}

    def set_ntfs_acl(self, local_path, sddl):
        r = _samba_tool("ntacl", "set", sddl, local_path)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def _child_flags(self, applies_to, is_dir):
        """Returns the inherited ACE flags for a child item, or None if the item should be skipped."""
        if applies_to == "this_folder_only":
            return None
        include_dirs  = applies_to in ("this_folder_subfolders_files", "this_folder_subfolders",
                                       "subfolders_files_only", "subfolders_only")
        include_files = applies_to in ("this_folder_subfolders_files", "this_folder_files",
                                       "subfolders_files_only", "files_only")
        if is_dir:
            return "OICIID" if include_dirs else None
        else:
            return "OIID" if include_files else None

    def _apply_ace_to_path(self, path, ace_type, sid, mask, flags):
        """Adds a pre-resolved ACE to a single path (no SID resolution, no recursion)."""
        r_acl = self.get_ntfs_acl(path)
        if r_acl.get("error"): return
        acl = r_acl["acl"]
        new_ace = {"type": "A" if ace_type.lower() in ("allow", "a") else "D",
                   "flags": flags, "rights": hex(mask), "sid": sid}
        acl["dacl"].insert(0, new_ace)
        sddl = self._rebuild_sddl(acl["owner_sid"], acl["group_sid"], acl["dacl"], acl["sacl"], acl.get("dacl_flags", ""))
        self.set_ntfs_acl(path, sddl)

    def add_ace(self, local_path, ace_type, principal, permissions, applies_to="this_folder_subfolders_files"):
        r_acl = self.get_ntfs_acl(local_path)
        if r_acl.get("error"): return r_acl
        acl   = r_acl["acl"]
        sid   = self._resolve_to_sid(principal)
        mask  = self._permissions_to_mask(permissions if isinstance(permissions, list) else [permissions])
        flags = self._applies_to_flags(applies_to)
        new_ace = {"type": "A" if ace_type.lower() in ("allow","a") else "D",
                   "flags": flags, "rights": hex(mask), "sid": sid}
        acl["dacl"].insert(0, new_ace)
        sddl = self._rebuild_sddl(acl["owner_sid"], acl["group_sid"], acl["dacl"], acl["sacl"], acl.get("dacl_flags",""))
        r = self.set_ntfs_acl(local_path, sddl)
        # Propagar para subpastas/arquivos existentes
        if r.get("ok") and applies_to != "this_folder_only" and os.path.isdir(local_path):
            for root, dirs, files in os.walk(local_path):
                for name in dirs:
                    cf = self._child_flags(applies_to, is_dir=True)
                    if cf: self._apply_ace_to_path(os.path.join(root, name), ace_type, sid, mask, cf)
                for name in files:
                    cf = self._child_flags(applies_to, is_dir=False)
                    if cf: self._apply_ace_to_path(os.path.join(root, name), ace_type, sid, mask, cf)
        return r

    def remove_ace(self, local_path, ace_index):
        r_acl = self.get_ntfs_acl(local_path)
        if r_acl.get("error"): return r_acl
        acl  = r_acl["acl"]
        dacl = [a for a in acl["dacl"] if a["index"] != ace_index]
        sddl = self._rebuild_sddl(acl["owner_sid"], acl["group_sid"], dacl, acl["sacl"], acl.get("dacl_flags",""))
        return self.set_ntfs_acl(local_path, sddl)

    def modify_ace(self, local_path, ace_index, ace_type, principal, permissions, applies_to):
        r_acl = self.get_ntfs_acl(local_path)
        if r_acl.get("error"): return r_acl
        acl   = r_acl["acl"]
        sid   = self._resolve_to_sid(principal)
        mask  = self._permissions_to_mask(permissions if isinstance(permissions, list) else [permissions])
        flags = self._applies_to_flags(applies_to)
        for a in acl["dacl"]:
            if a["index"] == ace_index:
                a["type"] = "A" if ace_type.lower() in ("allow","a") else "D"
                a["flags"] = flags; a["rights"] = hex(mask); a["sid"] = sid
                break
        sddl = self._rebuild_sddl(acl["owner_sid"], acl["group_sid"], acl["dacl"], acl["sacl"], acl.get("dacl_flags",""))
        r = self.set_ntfs_acl(local_path, sddl)
        # Propagar para subpastas/arquivos existentes
        if r.get("ok") and applies_to != "this_folder_only" and os.path.isdir(local_path):
            for root, dirs, files in os.walk(local_path):
                for name in dirs:
                    cf = self._child_flags(applies_to, is_dir=True)
                    if cf: self._apply_ace_to_path(os.path.join(root, name), ace_type, sid, mask, cf)
                for name in files:
                    cf = self._child_flags(applies_to, is_dir=False)
                    if cf: self._apply_ace_to_path(os.path.join(root, name), ace_type, sid, mask, cf)
        return r

    def set_owner(self, local_path, new_owner, recursive=False):
        r_acl = self.get_ntfs_acl(local_path)
        if r_acl.get("error"): return r_acl
        acl  = r_acl["acl"]
        sid  = self._resolve_to_sid(new_owner)
        sddl = self._rebuild_sddl(sid, acl["group_sid"], acl["dacl"], acl["sacl"], acl.get("dacl_flags",""))
        r    = self.set_ntfs_acl(local_path, sddl)
        if r.get("ok") and recursive:
            for root, dirs, files in os.walk(local_path):
                for name in dirs + files:
                    self.set_ntfs_acl(os.path.join(root, name), sddl)
        return r

    def set_inheritance(self, local_path, inherit_from_parent, replace_children=False):
        r_acl = self.get_ntfs_acl(local_path)
        if r_acl.get("error"): return r_acl
        acl   = r_acl["acl"]
        flags = acl.get("dacl_flags", "")
        flags = flags.replace("P", "") if inherit_from_parent else (flags if "P" in flags else flags + "P")
        sddl  = self._rebuild_sddl(acl["owner_sid"], acl["group_sid"], acl["dacl"], acl["sacl"], flags)
        return self.set_ntfs_acl(local_path, sddl)

    def get_effective_permissions(self, local_path, principal):
        r_acl = self.get_ntfs_acl(local_path)
        if r_acl.get("error"): return r_acl
        acl  = r_acl["acl"]
        sid  = self._resolve_to_sid(principal)
        allow_mask = deny_mask = 0
        for a in acl["dacl"]:
            if a["sid"] == sid or a["sid"] in ("WD","AU"):
                if a["type"] == "A": allow_mask |= a["mask"]
                elif a["type"] == "D": deny_mask |= a["mask"]
        effective = allow_mask & ~deny_mask
        return {
            "principal":   principal,
            "mask":        effective,
            "permissions": self._mask_to_permissions(effective),
            "granular":    [{"name": name, "allowed": bool(effective & bit)} for bit, name in self._GRANULAR_BITS],
        }

    # ── Share permissions ─────────────────────────────────────────────────────

    def get_share_permissions(self, share_name):
        cfg = configparser.ConfigParser(strict=False)
        cfg.read(self._smb_conf_path())
        if not cfg.has_section(share_name):
            return {"error": f"Share '{share_name}' não encontrado"}
        keys = ["valid users","invalid users","read list","write list",
                "admin users","guest ok","read only"]
        return {"permissions": {k: cfg.get(share_name, k, fallback="") for k in keys}}

    def set_share_permissions(self, share_name, perms_dict):
        return self.update_share(share_name, perms_dict)

    # ── Navegação avançada ────────────────────────────────────────────────────

    def browse_path_full(self, local_path):
        import pwd, grp as grpmod
        try:
            entries = []
            for name in sorted(os.listdir(local_path)):
                full = os.path.join(local_path, name)
                try:
                    st = os.stat(full)
                    try:    owner = pwd.getpwuid(st.st_uid).pw_name
                    except: owner = str(st.st_uid)
                    try:    group = grpmod.getgrgid(st.st_gid).gr_name
                    except: group = str(st.st_gid)
                    entries.append({
                        "name":       name,
                        "path":       full,
                        "is_dir":     stat.S_ISDIR(st.st_mode),
                        "size":       st.st_size,
                        "modified":   st.st_mtime,
                        "created":    getattr(st, "st_birthtime", st.st_ctime),
                        "mode":       oct(stat.S_IMODE(st.st_mode)),
                        "uid":        st.st_uid, "gid": st.st_gid,
                        "owner":      owner, "group": group,
                        "readable":   os.access(full, os.R_OK),
                        "writable":   os.access(full, os.W_OK),
                        "executable": os.access(full, os.X_OK),
                    })
                except OSError:
                    entries.append({"name": name, "path": full, "is_dir": False})
            return {"entries": sorted(entries, key=lambda x: (not x.get("is_dir"), x["name"]))}
        except Exception as e:
            return {"error": str(e)}

    def get_path_info(self, local_path):
        import pwd, grp as grpmod
        try:
            st = os.stat(local_path)
            try:    owner = pwd.getpwuid(st.st_uid).pw_name
            except: owner = str(st.st_uid)
            try:    group = grpmod.getgrgid(st.st_gid).gr_name
            except: group = str(st.st_gid)
            info = {
                "name":     os.path.basename(local_path), "path": local_path,
                "is_dir":   stat.S_ISDIR(st.st_mode),     "size": st.st_size,
                "modified": st.st_mtime,  "created":  getattr(st, "st_birthtime", st.st_ctime),
                "accessed": st.st_atime,  "mode":     oct(stat.S_IMODE(st.st_mode)),
                "uid": st.st_uid, "gid": st.st_gid, "owner": owner, "group": group,
            }
            if info["is_dir"]:
                try:
                    sv = os.statvfs(local_path)
                    info["disk_total"] = sv.f_frsize * sv.f_blocks
                    info["disk_free"]  = sv.f_frsize * sv.f_bfree
                    info["disk_used"]  = sv.f_frsize * (sv.f_blocks - sv.f_bfree)
                    items = os.listdir(local_path)
                    info["item_count"]   = len(items)
                    info["folder_count"] = sum(1 for i in items if os.path.isdir(os.path.join(local_path, i)))
                    info["file_count"]   = info["item_count"] - info["folder_count"]
                except Exception: pass
            return {"info": info}
        except Exception as e:
            return {"error": str(e)}

    def delete_path(self, local_path, recursive=False):
        try:
            if os.path.isdir(local_path):
                if recursive: import shutil; shutil.rmtree(local_path)
                else:         os.rmdir(local_path)
            else:
                os.remove(local_path)
            return {"ok": True}
        except Exception as e:
            return {"error": str(e)}

    def rename_path(self, old_path, new_name):
        try:
            new_path = os.path.join(os.path.dirname(old_path), new_name)
            os.rename(old_path, new_path)
            return {"ok": True, "new_path": new_path}
        except Exception as e:
            return {"error": str(e)}


class _DNSManager:

    def _dns_ldbsearch(self, base, expression=None, attrs=None):
        """Pesquisa diretamente no sam.ldb sem precisar de credenciais de rede."""
        return _ldbsearch(base, "sub", attrs, expression)

    def list_zones(self):
        domain_dn = _ad_get_domain_dn()
        zones = []
        for part_prefix in ["DC=DomainDnsZones", "DC=ForestDnsZones"]:
            base = f"{part_prefix},{domain_dn}"
            r = self._dns_ldbsearch(base, "(objectClass=dnsZone)", ["name"])
            if r["returncode"] == 0:
                for e in _parse_ldb_output(r["stdout"]):
                    name = e.get("name", "")
                    if name and not name.startswith(".."):
                        zones.append({"name": name, "partition": part_prefix.replace("DC=", "")})
        if zones:
            lines = [f"  {z['name']}  [{z['partition']}]" for z in zones]
            return {"output": "Zonas DNS encontradas:\n" + "\n".join(lines), "zones": zones}
        return {"output": "Nenhuma zona DNS encontrada.", "zones": []}

    def list_records(self, zone):
        domain_dn = _ad_get_domain_dn()
        for part_prefix in ["DC=DomainDnsZones", "DC=ForestDnsZones"]:
            base = f"DC={zone},CN=MicrosoftDNS,{part_prefix},{domain_dn}"
            r = self._dns_ldbsearch(base, "(objectClass=dnsNode)", ["name", "dnsRecord"])
            if r["returncode"] == 0:
                entries = _parse_ldb_output(r["stdout"])
                if entries:
                    lines = [e.get("name", "") for e in entries if e.get("name")]
                    return {"output": f"Registros na zona {zone}:\n" + "\n".join(f"  {l}" for l in lines)}
        return {"output": f"Zona '{zone}' não encontrada.", "error": ""}

    def add_record(self, zone, name, record_type, data):
        r = _samba_tool("dns", "add", "127.0.0.1", zone, name, record_type, data,
                        "--use-kerberos=auto")
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def delete_record(self, zone, name, record_type, data):
        r = _samba_tool("dns", "delete", "127.0.0.1", zone, name, record_type, data,
                        "--use-kerberos=auto")
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}


class _DomainInfo:

    def get_info(self):
        domain_dn = _ad_get_domain_dn()
        realm     = _ad_get_realm()
        level     = _samba_tool("domain", "level", "show")
        procs     = _samba_tool("processes")
        fsmo      = _samba_tool("fsmo", "show")
        pwdpol    = _samba_tool("domain", "passwordsettings", "show")
        return {
            "domain_dn":       domain_dn,
            "realm":           realm,
            "domain_name":     _ad_get_domain_name(),
            "hostname":        socket.gethostname(),
            "level":           level["stdout"],
            "processes":       procs["stdout"],
            "fsmo":            fsmo["stdout"],
            "password_policy": pwdpol["stdout"],
        }

    def get_computers(self):
        attrs = ["cn","sAMAccountName","distinguishedName","operatingSystem",
                 "operatingSystemVersion","lastLogon","description","dNSHostName"]
        r = _ldbsearch(_ad_get_domain_dn(), "sub", attrs, "(objectClass=computer)")
        if r["returncode"] != 0: return {"error": r["stderr"]}
        return {"computers": _parse_ldb_output(r["stdout"])}


# ─── Virtual Console (TTY) ─────────────────────────────────────────────────────

# Mapeamento VGA → índice de cor xterm (primeiros 16 da paleta 256)
_VGA_TO_XTERM = [0, 4, 2, 6, 1, 5, 3, 7, 8, 12, 10, 14, 9, 13, 11, 15]


def _vcs_to_ansi(rows: int, cols: int, cur_col: int, cur_row: int, screen: bytes) -> str:
    """Converte buffer /dev/vcsa em sequência ANSI para o xterm.js."""
    out = ['\x1b[?25l']   # oculta cursor
    prev_fg = prev_bg = -1

    for row in range(rows):
        # Posicionamento absoluto por linha evita scroll quando xterm tem menos linhas que o VGA
        out.append(f'\x1b[{row + 1};1H')
        for col in range(cols):
            idx = (row * cols + col) * 2
            if idx + 1 >= len(screen):
                out.append(' ')
                continue
            ch   = screen[idx]
            attr = screen[idx + 1]
            fg   = _VGA_TO_XTERM[attr & 0x0F]
            bg   = _VGA_TO_XTERM[((attr >> 4) & 0x07) + (8 if (attr >> 7) & 1 else 0)]
            if fg != prev_fg or bg != prev_bg:
                out.append(f'\x1b[38;5;{fg}m\x1b[48;5;{bg}m')
                prev_fg, prev_bg = fg, bg
            out.append(chr(ch) if 32 <= ch < 127 else ' ')
        # Reset cor e apaga até o fim da linha (corrige lado direito preto quando xterm é mais largo que 80 colunas)
        out.append('\x1b[0m\x1b[K')
        prev_fg = prev_bg = -1

    # posiciona cursor e mostra
    out.append(f'\x1b[{cur_row + 1};{cur_col + 1}H\x1b[?25h')
    return ''.join(out)


class VConsoleSession:
    """Lê /dev/vcsaN e injeta input via TIOCSTI em /dev/ttyN."""

    def __init__(self, tty_num: int = 1):
        self.tty_num  = tty_num
        self.vcs_path = f"/dev/vcsa{tty_num}"
        self.tty_path = f"/dev/tty{tty_num}"
        self.running  = False

    def read(self):
        """Lê o buffer de tela. Retorna (rows, cols, cur_col, cur_row, data) ou None."""
        try:
            with open(self.vcs_path, 'rb') as f:
                raw = f.read()
            if len(raw) < 4:
                return None
            return raw[0], raw[1], raw[2], raw[3], raw[4:]
        except OSError:
            return None

    def send_input(self, text: str):
        """Injeta teclas no TTY via TIOCSTI."""
        try:
            with open(self.tty_path, 'rb+', buffering=0) as tty:
                fd = tty.fileno()
                for byte in text.encode('utf-8', errors='replace'):
                    fcntl.ioctl(fd, termios.TIOCSTI, bytes([byte]))
        except Exception as e:
            logger.warning(f"TIOCSTI falhou em {self.tty_path}: {e}")

    def stop(self):
        self.running = False


# ─── Shell via PTY ─────────────────────────────────────────────────────────────

class ShellSession:
    """Gerencia um processo bash interativo via pseudo-terminal (PTY)."""

    def __init__(self):
        self.master_fd: int | None = None
        self.pid: int | None = None
        self.running: bool = False

    def start(self, cols: int = 120, rows: int = 30):
        """Abre um PTY e faz fork para rodar bash."""
        self.master_fd, slave_fd = os.openpty()
        self._set_winsize(slave_fd, cols, rows)

        # Echo habilitado — o xterm.js no browser exibe o que o PTY ecoa

        self.pid = os.fork()

        if self.pid == 0:
            # ── Processo filho: vira o bash ──
            os.close(self.master_fd)
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            if slave_fd > 2:
                os.close(slave_fd)
            env = os.environ.copy()
            env['TERM'] = 'xterm-256color'
            env['COLORTERM'] = 'truecolor'
            env['COLUMNS'] = str(cols)
            env['LINES'] = str(rows)
            os.execve("/bin/login", ["/bin/login", "-p"], env)
            sys.exit(1)

        # ── Processo pai ──
        os.close(slave_fd)
        self.running = True
        logger.info(f"Shell iniciado (PID {self.pid}, {cols}x{rows})")

    def _set_winsize(self, fd: int, cols: int, rows: int):
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

    def resize(self, cols: int, rows: int):
        if self.master_fd is not None:
            self._set_winsize(self.master_fd, cols, rows)

    def write(self, data: str | bytes):
        if self.master_fd is not None and self.running:
            try:
                raw = data if isinstance(data, bytes) else data.encode("utf-8", errors="replace")
                os.write(self.master_fd, raw)
            except OSError:
                self.running = False

    def read(self, timeout: float = 0.05) -> bytes | None:
        """Lê saída do shell com timeout. Retorna None se o fd fechou."""
        if self.master_fd is None or not self.running:
            return None
        try:
            r, _, _ = select.select([self.master_fd], [], [], timeout)
            if r:
                return os.read(self.master_fd, 4096)
            return b""
        except OSError:
            self.running = False
            return None

    def stop(self):
        self.running = False
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(self.pid, os.WNOHANG)
            except Exception:
                pass
            self.pid = None
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None
        logger.info("Shell encerrado")


# ─── Agente ────────────────────────────────────────────────────────────────────

class LinuxAgent:

    def __init__(self, relay_url: str, agent_id: str, password: str,
                 binding_secret: str = "", reconnect_delay: int = 10):
        self.relay_url = relay_url
        self.agent_id = agent_id
        self.password_hash = hash_password(password)
        self.binding_token = compute_binding_token(binding_secret, agent_id) if binding_secret else ""
        self.reconnect_delay = reconnect_delay

        self.ws = None
        self.session_id: str | None = None
        self.shell: ShellSession | None = None
        self._shell_reader_task: asyncio.Task | None = None
        self._running = True
        self._uploads: dict = {}  # transfer_id -> {path, chunks[]}
        self.vconsole: VConsoleSession | None = None
        self._vconsole_task: asyncio.Task | None = None

        # Active Directory — habilitado automaticamente se Samba AD DC detectado
        self.samba_available = _detect_samba()
        if self.samba_available:
            self._ad_users  = _UserManager()
            self._ad_groups = _GroupManager()
            self._ad_ous    = _OUManager()
            self._ad_gpos   = _GPOManager()
            self._ad_shares = _ShareManager()
            self._ad_dns    = _DNSManager()
            self._ad_domain = _DomainInfo()
            logger.info("Samba AD DC detectado — módulo Active Directory habilitado")

    # ── Loop principal ─────────────────────────────────────────────────────────

    async def run(self):
        while self._running:
            try:
                logger.info(f"Conectando ao relay: {self.relay_url}")
                async with websockets.connect(
                    self.relay_url,
                    max_size=10 * 1024 * 1024,
                    ping_interval=20,
                    ping_timeout=60,
                ) as ws:
                    self.ws = ws
                    logger.info("Conectado")
                    await self._register()
                    await asyncio.gather(
                        self._recv_loop(),
                        self._heartbeat_loop(),
                    )
            except (websockets.ConnectionClosed, ConnectionRefusedError, OSError) as e:
                logger.warning(f"Conexão perdida: {e}")
            except Exception as e:
                logger.error(f"Erro: {e}")
            finally:
                self.ws = None
                self._stop_shell()
                self._stop_vconsole()
                self.session_id = None

            if self._running:
                logger.info(f"Reconectando em {self.reconnect_delay}s...")
                await asyncio.sleep(self.reconnect_delay)

    # ── Registro ───────────────────────────────────────────────────────────────

    async def _register(self):
        info = get_system_info()
        data = {
            "agent_id":      self.agent_id,
            "password_hash": self.password_hash,
            "binding_token": self.binding_token,
            "version":       AGENT_VERSION,
            **info,
        }
        if self.samba_available:
            data["ad_agent"]   = True
            data["ad_version"] = AGENT_VERSION
        await self._send({
            "type": "register_agent",
            "data": data,
            "timestamp": time.time(),
        })

    # ── Heartbeat ──────────────────────────────────────────────────────────────

    async def _heartbeat_loop(self):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            await self._send({"type": "ping", "data": {}, "timestamp": time.time()})

    # ── Recepção de mensagens ──────────────────────────────────────────────────

    async def _recv_loop(self):
        async for raw in self.ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            await self._handle(msg)

    async def _handle(self, msg: dict):
        t    = msg.get("type", "")
        data = msg.get("data", {})
        sid  = msg.get("session_id")

        if t == "auth_success":
            logger.info(f"Autenticado no relay | agent_id: {self.agent_id}")

        elif t == "connect_accept":
            self.session_id = sid or data.get("session_id")
            viewer = data.get("viewer_id", "?")[:12]
            logger.info(f"Viewer conectado: {viewer} | sessão: {(self.session_id or '')[:12]}")

        elif t == "disconnect":
            logger.info("Viewer desconectou")
            self._stop_shell()
            self.session_id = None

        elif t == "shell_start":
            # Se shell já está rodando, aproveita a sessão existente
            if not self.shell or not self.shell.running:
                await self._start_shell(
                    cols=data.get("cols", 120),
                    rows=data.get("rows", 30),
                )

        elif t == "shell_input":
            # Input raw do xterm.js (tecla a tecla, inclusive Ctrl+C, setas, tab...)
            raw = data.get("input", "")
            if raw and self.shell and self.shell.running:
                self.shell.write(raw)

        elif t == "shell_command":
            # Compatibilidade com clientes antigos
            cmd = data.get("command", "")
            if cmd and self.shell and self.shell.running:
                self.shell.write(cmd + "\n")

        elif t == "shell_resize":
            if self.shell:
                self.shell.resize(
                    cols=data.get("cols", 120),
                    rows=data.get("rows", 30),
                )

        elif t == "shell_stop":
            self._stop_shell()

        elif t == "file_list_request":
            await self._handle_file_list(data)

        elif t == "file_download_request":
            asyncio.create_task(self._handle_file_download(data))

        elif t == "file_upload_start":
            tid = data.get("transfer_id", "")
            self._uploads[tid] = {"path": data.get("path", ""), "chunks": []}

        elif t == "file_chunk":
            if data.get("direction") == "upload":
                tid = data.get("transfer_id", "")
                if tid in self._uploads:
                    self._uploads[tid]["chunks"].append(data.get("chunk", ""))

        elif t == "file_complete":
            if data.get("direction") == "upload":
                await self._finalize_upload(data)

        elif t == "system_info_request":
            await self._send_system_info()

        elif t == "console_start":
            await self._start_vconsole(data.get("tty", 1))

        elif t == "console_input":
            if self.vconsole and self.vconsole.running:
                self.vconsole.send_input(data.get("input", ""))

        elif t == "console_stop":
            self._stop_vconsole()

        elif t == "ad_request":
            if self.samba_available:
                asyncio.create_task(self._handle_ad_request(data, sid))
            else:
                await self._send({"type": "ad_response",
                                   "data": {"action": data.get("action"),
                                            "request_id": data.get("request_id"),
                                            "result": {"error": "Samba AD DC não encontrado nesta máquina"}},
                                   "session_id": sid, "timestamp": time.time()})

        elif t == "update_agent":
            await self._handle_update(data)

        elif t == "pong":
            pass  # heartbeat ok

    # ── Auto-atualização ────────────────────────────────────────────────────────

    async def _handle_update(self, data: dict):
        """Baixa a versão mais recente do agente e reinicia o processo."""
        panel_url = data.get("panel_url", "https://rnremote.joaoneto.tec.br").rstrip("/")
        url        = f"{panel_url}/static/agent/agent.py"
        agent_path = os.path.abspath(__file__)
        tmp_path   = agent_path + ".update"

        logger.info(f"Iniciando atualização — baixando {url}")
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, lambda: urllib.request.urlretrieve(url, tmp_path))

            size = os.path.getsize(tmp_path)
            if size < 5000:
                raise ValueError(f"Arquivo suspeito ({size} bytes), atualização cancelada")

            shutil.move(tmp_path, agent_path)
            logger.info("Atualização baixada — reiniciando agente...")

            # Fecha conexão antes de reiniciar
            self._running = False
            if self.ws:
                try:
                    await self.ws.close()
                except Exception:
                    pass

            # Substitui o processo atual pela nova versão
            await asyncio.sleep(0.5)
            os.execv(sys.executable, [sys.executable] + sys.argv)

        except Exception as e:
            logger.error(f"Falha na atualização: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    # ── Arquivos ────────────────────────────────────────────────────────────────

    async def _handle_file_list(self, data: dict):
        path = data.get("path") or os.path.expanduser("~")
        try:
            entries = []
            with os.scandir(path) as it:
                for entry in sorted(it, key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower())):
                    try:
                        stat = entry.stat(follow_symlinks=False)
                        entries.append({
                            "name": entry.name,
                            "path": entry.path,
                            "is_dir": entry.is_dir(follow_symlinks=False),
                            "size": stat.st_size,
                            "modified": stat.st_mtime,
                        })
                    except OSError:
                        pass
            await self._send({"type": "file_list_response",
                               "data": {"path": path, "entries": entries},
                               "session_id": self.session_id, "timestamp": time.time()})
        except Exception as e:
            await self._send({"type": "file_list_response",
                               "data": {"path": path, "entries": [], "error": str(e)},
                               "session_id": self.session_id, "timestamp": time.time()})

    async def _handle_file_download(self, data: dict):
        path = data.get("path", "")
        tid  = data.get("transfer_id", "")
        CHUNK = 65536
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    await self._send({"type": "file_chunk",
                                      "data": {"transfer_id": tid,
                                               "chunk": base64.b64encode(chunk).decode(),
                                               "direction": "download"},
                                      "session_id": self.session_id, "timestamp": time.time()})
                    await asyncio.sleep(0)  # yield para não travar o event loop
            await self._send({"type": "file_complete",
                               "data": {"transfer_id": tid, "path": path, "direction": "download"},
                               "session_id": self.session_id, "timestamp": time.time()})
        except Exception as e:
            await self._send({"type": "file_error",
                               "data": {"transfer_id": tid, "error": str(e)},
                               "session_id": self.session_id, "timestamp": time.time()})

    async def _finalize_upload(self, data: dict):
        tid    = data.get("transfer_id", "")
        upload = self._uploads.pop(tid, None)
        if not upload:
            return
        try:
            raw = base64.b64decode("".join(upload["chunks"]))
            with open(upload["path"], "wb") as f:
                f.write(raw)
            logger.info(f"Upload recebido: {upload['path']} ({len(raw)} bytes)")
            await self._send({"type": "file_complete",
                               "data": {"transfer_id": tid, "path": upload["path"],
                                        "direction": "upload", "ok": True},
                               "session_id": self.session_id, "timestamp": time.time()})
        except Exception as e:
            await self._send({"type": "file_error",
                               "data": {"transfer_id": tid, "error": str(e)},
                               "session_id": self.session_id, "timestamp": time.time()})

    # ── Sistema ─────────────────────────────────────────────────────────────────

    async def _send_system_info(self):
        uname = platform.uname()
        info  = {
            "hostname":       socket.gethostname(),
            "kernel":         f"{uname.system} {uname.release}",
            "architecture":   uname.machine,
            "username":       os.environ.get("USER", os.environ.get("LOGNAME", "unknown")),
            "cpu_count":      os.cpu_count() or 1,
            "python_version": platform.python_version(),
        }
        # OS via /etc/os-release (mais preciso que platform)
        try:
            os_fields = {}
            with open("/etc/os-release") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line:
                        k, v = line.split("=", 1)
                        os_fields[k] = v.strip('"')
            info["os_pretty"]  = os_fields.get("PRETTY_NAME", "")
            info["os_name"]    = os_fields.get("NAME", "")
            info["os_version"] = os_fields.get("VERSION", os_fields.get("VERSION_ID", ""))
            info["os_id"]      = os_fields.get("ID", "linux")
        except Exception:
            info["os_pretty"] = f"{uname.system} {uname.release}"
        # RAM via /proc/meminfo
        try:
            mem = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    k, v = line.split(":", 1)
                    mem[k.strip()] = int(v.split()[0])
            total_kb = mem.get("MemTotal", 0)
            avail_kb = mem.get("MemAvailable", 0)
            used_kb  = total_kb - avail_kb
            info["ram_total_mb"] = round(total_kb / 1024)
            info["ram_used_mb"]  = round(used_kb  / 1024)
            info["ram_percent"]  = round(used_kb / total_kb * 100, 1) if total_kb else 0
        except Exception:
            pass
        # Disco raiz
        try:
            du = shutil.disk_usage("/")
            info["disk_total_gb"] = round(du.total / 1073741824, 1)
            info["disk_used_gb"]  = round(du.used  / 1073741824, 1)
            info["disk_percent"]  = round(du.used / du.total * 100, 1)
        except Exception:
            pass
        # Uptime via /proc/uptime
        try:
            with open("/proc/uptime") as f:
                secs = float(f.read().split()[0])
            days, rem = divmod(int(secs), 86400)
            hours, rem = divmod(rem, 3600)
            mins = rem // 60
            info["uptime"] = (f"{days}d " if days else "") + f"{hours:02d}:{mins:02d}"
        except Exception:
            pass
        await self._send({"type": "system_info", "data": info,
                           "session_id": self.session_id, "timestamp": time.time()})

    # ── Virtual Console ─────────────────────────────────────────────────────────

    async def _start_vconsole(self, tty_num: int = 1):
        self._stop_vconsole()
        vc = VConsoleSession(tty_num)
        if not vc.read():
            await self._send({"type": "console_frame",
                               "data": {"output": f"\r\nErro: não foi possível abrir {vc.vcs_path}\r\nVerifique se o agente roda como root.\r\n"},
                               "session_id": self.session_id, "timestamp": time.time()})
            return
        vc.running = True
        self.vconsole = vc
        self._vconsole_task = asyncio.create_task(self._poll_vconsole())
        logger.info(f"Virtual console iniciado: tty{tty_num}")

    async def _poll_vconsole(self):
        prev_screen = None
        loop = asyncio.get_running_loop()
        while self.vconsole and self.vconsole.running:
            result = await loop.run_in_executor(None, self.vconsole.read)
            if result is None:
                break
            rows, cols, cur_col, cur_row, screen = result
            if screen != prev_screen:
                ansi = _vcs_to_ansi(rows, cols, cur_col, cur_row, screen)
                await self._send({"type": "console_frame",
                                   "data": {"output": ansi},
                                   "session_id": self.session_id,
                                   "timestamp": time.time()})
                prev_screen = screen
            await asyncio.sleep(0.1)   # 10 FPS — suficiente para console texto
        logger.info("Virtual console finalizado")

    def _stop_vconsole(self):
        if self._vconsole_task:
            self._vconsole_task.cancel()
            self._vconsole_task = None
        if self.vconsole:
            self.vconsole.stop()
            self.vconsole = None

    # ── Shell ──────────────────────────────────────────────────────────────────

    async def _start_shell(self, cols: int, rows: int):
        self._stop_shell()
        self.shell = ShellSession()
        self.shell.start(cols=cols, rows=rows)
        self._shell_reader_task = asyncio.create_task(self._read_shell_output())

    async def _read_shell_output(self):
        """Lê saída do PTY em background e envia ao viewer."""
        loop = asyncio.get_running_loop()
        while self.shell and self.shell.running:
            data = await loop.run_in_executor(None, self.shell.read)
            if data is None:
                break
            if data:
                text = data.decode("utf-8", errors="replace")
                await self._send({
                    "type": "shell_output",
                    "data": {"output": text},
                    "session_id": self.session_id,
                    "timestamp": time.time(),
                })
        logger.info("Leitura do shell finalizada")

    def _stop_shell(self):
        if self._shell_reader_task:
            self._shell_reader_task.cancel()
            self._shell_reader_task = None
        if self.shell:
            self.shell.stop()
            self.shell = None

    # ── Active Directory ────────────────────────────────────────────────────────

    async def _handle_ad_request(self, data: dict, session_id):
        action     = data.get("action")
        params     = data.get("params", {})
        request_id = data.get("request_id")
        logger.info(f"AD request: {action}")
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(None, self._dispatch_ad_action, action, params)
        except Exception as e:
            logger.exception(f"Erro no dispatch AD: {action}")
            result = {"error": str(e)}
        await self._send({"type": "ad_response",
                           "data": {"action": action, "request_id": request_id, "result": result},
                           "session_id": session_id, "timestamp": time.time()})

    def _dispatch_ad_action(self, action, params):
        dispatch = {
            "domain_info":         lambda p: self._ad_domain.get_info(),
            "domain_computers":    lambda p: self._ad_domain.get_computers(),
            "user_list":           lambda p: self._ad_users.list_users(p.get("ou")),
            "user_get":            lambda p: self._ad_users.get_user(p["username"]),
            "user_create":         lambda p: self._ad_users.create_user(
                                       p["username"], p["password"],
                                       p.get("given_name",""), p.get("surname",""),
                                       p.get("mail",""), p.get("ou",""),
                                       p.get("must_change_password", False), p.get("unix_attrs")),
            "user_modify":         lambda p: self._ad_users.modify_user(p["username"], p["attrs"]),
            "user_delete":         lambda p: self._ad_users.delete_user(p["username"]),
            "user_enable":         lambda p: self._ad_users.enable_user(p["username"]),
            "user_disable":        lambda p: self._ad_users.disable_user(p["username"]),
            "user_reset_password": lambda p: self._ad_users.reset_password(
                                       p["username"], p["new_password"], p.get("must_change", False)),
            "user_unlock":         lambda p: self._ad_users.unlock_user(p["username"]),
            "user_move":           lambda p: self._ad_users.move_user(p["username"], p["target_ou"]),
            "user_groups":         lambda p: self._ad_users.get_user_groups(p["username"]),
            "group_list":          lambda p: self._ad_groups.list_groups(p.get("ou")),
            "group_get":           lambda p: self._ad_groups.get_group(p["groupname"]),
            "group_create":        lambda p: self._ad_groups.create_group(
                                       p["groupname"], p.get("description",""),
                                       p.get("group_type","Security"), p.get("group_scope","Global"),
                                       p.get("ou",""), p.get("gid_number")),
            "group_delete":        lambda p: self._ad_groups.delete_group(p["groupname"]),
            "group_add_member":    lambda p: self._ad_groups.add_member(p["groupname"], p["member"]),
            "group_remove_member": lambda p: self._ad_groups.remove_member(p["groupname"], p["member"]),
            "group_members":       lambda p: self._ad_groups.list_members(p["groupname"]),
            "group_move":          lambda p: self._ad_groups.move_group(p["groupname"], p["target_ou"]),
            "ou_list":             lambda p: self._ad_ous.list_ous(),
            "ou_tree":             lambda p: self._ad_ous.get_ou_tree(),
            "ou_objects":          lambda p: self._ad_ous.get_ou_objects(p["ou_dn"]),
            "ou_create":           lambda p: self._ad_ous.create_ou(
                                       p["ou_name"], p.get("parent_dn",""), p.get("description","")),
            "ou_delete":           lambda p: self._ad_ous.delete_ou(p["ou_dn"], p.get("recursive", False)),
            "ou_rename":           lambda p: self._ad_ous.rename_ou(p["ou_dn"], p["new_name"]),
            "ou_move":             lambda p: self._ad_ous.move_ou(p["ou_dn"], p["target_parent_dn"]),
            "gpo_list":            lambda p: self._ad_gpos.list_gpos(),
            "gpo_get":             lambda p: self._ad_gpos.get_gpo(p["gpo_guid"]),
            "gpo_create":          lambda p: self._ad_gpos.create_gpo(p["display_name"]),
            "gpo_delete":          lambda p: self._ad_gpos.delete_gpo(p["gpo_guid"]),
            "gpo_link":            lambda p: self._ad_gpos.link_gpo(p["gpo_guid"], p["container_dn"]),
            "gpo_unlink":          lambda p: self._ad_gpos.unlink_gpo(p["gpo_guid"], p["container_dn"]),
            "gpo_linked":          lambda p: self._ad_gpos.get_linked_gpos(p["container_dn"]),
            "gpo_get_links":       lambda p: self._ad_gpos.get_links(p["gpo_guid"]),
            "gpo_set_security":    lambda p: self._ad_gpos.set_security_setting(
                                       p["gpo_guid"], p["section"], p["key"], p["value"]),
            "gpo_read_file":       lambda p: self._ad_gpos.read_file(p["gpo_guid"], p["rel_path"]),
            "gpo_write_file":      lambda p: self._ad_gpos.write_file(p["gpo_guid"], p["rel_path"], p["content"]),
            "gpo_list_files":      lambda p: self._ad_gpos.list_files(p["gpo_guid"]),
            "gpo_rename":              lambda p: self._ad_gpos.rename(p["gpo_guid"], p["new_name"]),
            "gpo_get_full":            lambda p: self._ad_gpos.get_gpo_full(p["gpo_guid"]),
            "gpo_get_status":          lambda p: self._ad_gpos.get_status(p["gpo_guid"]),
            "gpo_set_status":          lambda p: self._ad_gpos.set_status(p["gpo_guid"], p["computer_enabled"], p["user_enabled"]),
            "gpo_set_link_enforced":   lambda p: self._ad_gpos.set_link_enforced(p["gpo_guid"], p["container_dn"], p["enforced"]),
            "gpo_set_link_enabled":    lambda p: self._ad_gpos.set_link_enabled(p["gpo_guid"], p["container_dn"], p["enabled"]),
            "gpo_set_link_order":      lambda p: self._ad_gpos.set_link_order(p["container_dn"], p["gpo_guid"], p["position"]),
            "gpo_set_block_inheritance": lambda p: self._ad_gpos.set_block_inheritance(p["container_dn"], p["blocked"]),
            "gpo_get_inheritance":     lambda p: self._ad_gpos.get_inheritance_info(p["container_dn"]),
            "gpo_get_sec_filtering":   lambda p: self._ad_gpos.get_security_filtering(p["gpo_guid"]),
            "gpo_list_wmi_filters":    lambda p: self._ad_gpos.list_wmi_filters(),
            "gpo_create_wmi_filter":   lambda p: self._ad_gpos.create_wmi_filter(p["name"], p["description"], p["query"]),
            "gpo_get_wmi_filter":      lambda p: self._ad_gpos.get_wmi_filter(p["gpo_guid"]),
            "gpo_set_wmi_filter":      lambda p: self._ad_gpos.set_wmi_filter(p["gpo_guid"], p.get("wmi_filter_dn", "")),
            "gpo_delete_wmi_filter":   lambda p: self._ad_gpos.delete_wmi_filter(p["filter_dn"]),
            "gpo_sec_template":        lambda p: self._ad_gpos.sec_get_template(),
            "gpo_sec_read_all":        lambda p: self._ad_gpos.sec_read_all(p["gpo_guid"]),
            "gpo_sec_write":           lambda p: self._ad_gpos.sec_write(p["gpo_guid"], p["section"], p["key"], p["value"]),
            "gpo_sec_delete":          lambda p: self._ad_gpos.sec_delete(p["gpo_guid"], p["section"], p["key"]),
            "gpo_pref_types":          lambda p: self._ad_gpos.pref_list_types(),
            "gpo_pref_list":           lambda p: self._ad_gpos.pref_list_items(p["gpo_guid"], p["scope"], p["pref_type"]),
            "gpo_pref_add":            lambda p: self._ad_gpos.pref_add_item(p["gpo_guid"], p["scope"], p["pref_type"], p["properties"]),
            "gpo_pref_update":         lambda p: self._ad_gpos.pref_update_item(p["gpo_guid"], p["scope"], p["pref_type"], p["item_uid"], p["properties"]),
            "gpo_pref_delete":         lambda p: self._ad_gpos.pref_delete_item(p["gpo_guid"], p["scope"], p["pref_type"], p["item_uid"]),
            "share_list":              lambda p: self._ad_shares.list_shares(),
            "share_create":        lambda p: self._ad_shares.create_share(
                                       p["name"], p["path"], p.get("comment",""), p.get("read_only", False)),
            "share_acl":           lambda p: self._ad_shares.get_acl(p["share"], p.get("path","/")),
            "share_set_acl":       lambda p: self._ad_shares.set_acl(
                                       p["share"], p.get("path","/"), p["acl_string"], p.get("action","set")),
            "share_browse":        lambda p: self._ad_shares.browse_path(p["local_path"]),
            "share_set_posix":     lambda p: self._ad_shares.set_posix_acl(
                                       p["path"], p.get("owner",""), p.get("group",""), p.get("mode","")),
            "share_mkdir":           lambda p: self._ad_shares.create_directory(p["path"]),
            "share_get_full":        lambda p: self._ad_shares.get_share_full(p["share_name"]),
            "share_update":          lambda p: self._ad_shares.update_share(p["share_name"], p["options"]),
            "share_delete":          lambda p: self._ad_shares.delete_share(p["share_name"]),
            "share_rename":          lambda p: self._ad_shares.rename_share(p["old_name"], p["new_name"]),
            "share_get_permissions": lambda p: self._ad_shares.get_share_permissions(p["share_name"]),
            "share_set_permissions": lambda p: self._ad_shares.set_share_permissions(p["share_name"], p["perms"]),
            "ntfs_get_acl":          lambda p: self._ad_shares.get_ntfs_acl(p["local_path"]),
            "ntfs_set_acl":          lambda p: self._ad_shares.set_ntfs_acl(p["local_path"], p["sddl"]),
            "ntfs_add_ace":          lambda p: self._ad_shares.add_ace(p["local_path"], p["ace_type"], p["principal"], p["permissions"], p.get("applies_to","this_folder_subfolders_files")),
            "ntfs_remove_ace":       lambda p: self._ad_shares.remove_ace(p["local_path"], p["ace_index"]),
            "ntfs_modify_ace":       lambda p: self._ad_shares.modify_ace(p["local_path"], p["ace_index"], p["ace_type"], p["principal"], p["permissions"], p.get("applies_to","this_folder_subfolders_files")),
            "ntfs_set_owner":        lambda p: self._ad_shares.set_owner(p["local_path"], p["new_owner"], p.get("recursive", False)),
            "ntfs_set_inheritance":  lambda p: self._ad_shares.set_inheritance(p["local_path"], p["inherit_from_parent"], p.get("replace_children", False)),
            "ntfs_effective_perms":  lambda p: self._ad_shares.get_effective_permissions(p["local_path"], p["principal"]),
            "path_browse_full":      lambda p: self._ad_shares.browse_path_full(p["local_path"]),
            "path_delete":           lambda p: self._ad_shares.delete_path(p["local_path"], p.get("recursive", False)),
            "path_rename":           lambda p: self._ad_shares.rename_path(p["local_path"], p["new_name"]),
            "path_info":             lambda p: self._ad_shares.get_path_info(p["local_path"]),
            "dns_zones":             lambda p: self._ad_dns.list_zones(),
            "dns_records":         lambda p: self._ad_dns.list_records(p["zone"]),
            "dns_add":             lambda p: self._ad_dns.add_record(
                                       p["zone"], p["name"], p["record_type"], p["data"]),
            "dns_delete":          lambda p: self._ad_dns.delete_record(
                                       p["zone"], p["name"], p["record_type"], p["data"]),
        }
        fn = dispatch.get(action)
        if fn is None:
            return {"error": f"Ação desconhecida: {action}"}
        return fn(params)

    # ── Envio ──────────────────────────────────────────────────────────────────

    async def _send(self, msg: dict):
        if self.ws:
            try:
                await self.ws.send(json.dumps(msg))
            except Exception:
                pass


# ─── Configuração ──────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def main():
    parser = argparse.ArgumentParser(
        description="RemoteLink - Agente Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 agent.py --relay wss://rnremote.joaoneto.tec.br/ws --id 123456789 --password minhasenha
  python3 agent.py --config /etc/rnremote/agent.json

Arquivo de configuração (JSON):
  {
    "relay_url":  "wss://rnremote.joaoneto.tec.br/ws",
    "agent_id":   "123456789",
    "password":   "minhasenha"
  }
        """
    )
    parser.add_argument("--relay",    default=os.environ.get("RELAY_URL", ""),
                        help="URL WebSocket do relay (wss://...)")
    parser.add_argument("--id",       dest="agent_id",
                        default=os.environ.get("AGENT_ID", ""),
                        help="ID do agente (9 dígitos numéricos)")
    parser.add_argument("--password", default=os.environ.get("AGENT_PASSWORD", ""),
                        help="Senha de acesso ao agente")
    parser.add_argument("--config",   default="/etc/rnremote/agent.json",
                        help="Arquivo de configuração JSON")
    parser.add_argument("--reconnect-delay", type=int, default=10,
                        help="Segundos entre tentativas de reconexão (padrão: 10)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    relay          = args.relay    or cfg.get("relay_url",       "")
    agent_id       = args.agent_id or cfg.get("agent_id",        "")
    password       = args.password or cfg.get("password",        "")
    binding_secret = cfg.get("binding_secret", "")

    if not relay or not agent_id or not password:
        parser.print_help()
        print("\nErro: relay, agent_id e password são obrigatórios.")
        print("Execute 'python3 setup.py' para configurar este agente.")
        sys.exit(1)

    agent = LinuxAgent(
        relay_url=relay,
        agent_id=agent_id,
        password=password,
        binding_secret=binding_secret,
        reconnect_delay=args.reconnect_delay,
    )

    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Agente encerrado.")


if __name__ == "__main__":
    main()
