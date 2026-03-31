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

AGENT_VERSION = "1.1.6"

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

SAMBA_BIN     = "/usr/local/samba/bin"
SAMBA_SBIN    = "/usr/local/samba/sbin"
SAMBA_PRIVATE = "/usr/local/samba/private"
SAMBA_ETC     = "/usr/local/samba/etc"
SYSVOL_PATH   = "/usr/local/samba/var/locks/sysvol"


def _detect_samba() -> bool:
    """Retorna True se Samba AD DC está instalado nesta máquina."""
    return (
        os.path.isdir(SAMBA_BIN) and
        os.path.isfile(os.path.join(SAMBA_BIN, "samba-tool")) and
        os.path.isfile(os.path.join(SAMBA_PRIVATE, "sam.ldb"))
    )


def _ad_run_cmd(cmd_list):
    env = os.environ.copy()
    path = env.get("PATH", "")
    extra = f"{SAMBA_BIN}:{SAMBA_SBIN}"
    if extra not in path:
        env["PATH"] = f"{extra}:{path}"
    try:
        proc = subprocess.run(cmd_list, capture_output=True, text=True, env=env, timeout=30)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout ao executar comando", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def _samba_tool(*args):
    return _ad_run_cmd([os.path.join(SAMBA_BIN, "samba-tool")] + list(args))


def _ldbsearch(base, scope="subtree", attrs=None, expression=None):
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
    entries = []
    current = {}
    for line in stdout.splitlines():
        if line.startswith("#"):
            continue
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith("dn: "):
            if current:
                entries.append(current)
            current = {"dn": line[4:].strip()}
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


def _ad_get_realm():
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(SAMBA_ETC, "smb.conf"))
    return cfg.get("global", "realm", fallback="").strip()


def _ad_get_domain_name():
    cfg = configparser.ConfigParser()
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
        r = _ldbsearch(base, "subtree", self._USER_ATTRS, "(&(objectClass=user)(objectCategory=person))")
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
        r = _ldbsearch(_ad_get_domain_dn(), "subtree", self._USER_ATTRS,
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
        if ou:         args += ["--userou", ou]
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
        r = _ldbsearch(base, "subtree", attrs, "(objectClass=group)")
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
        r = _ldbsearch(_ad_get_domain_dn(), "subtree", attrs, f"(sAMAccountName={groupname})")
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
        if ou:          args += ["--groupou", ou]
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


class _OUManager:

    def list_ous(self):
        r = _ldbsearch(_ad_get_domain_dn(), "subtree",
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

    def get_ou_tree(self):
        base = _ad_get_domain_dn()
        r = _ldbsearch(base, "subtree",
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
                        "description","name","userAccountControl","groupType"], None)
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
            if line.startswith("GPO") and ":" not in line:
                if current: gpos.append(current)
                current = {}
            elif ":" in line:
                key, _, value = line.partition(":")
                current[key.strip()] = value.strip()
        if current: gpos.append(current)
        return {"gpos": gpos}

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

    def set_security_setting(self, gpo_guid, section, key, value):
        realm = _ad_get_realm().lower()
        tmpl_path = os.path.join(SYSVOL_PATH, realm, "Policies", gpo_guid,
                                 "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")
        gpt_path = os.path.join(SYSVOL_PATH, realm, "Policies", gpo_guid, "GPT.INI")
        try:
            cfg = configparser.ConfigParser()
            if os.path.exists(tmpl_path): cfg.read(tmpl_path, encoding="utf-8")
            if not cfg.has_section(section): cfg.add_section(section)
            cfg.set(section, key, str(value))
            os.makedirs(os.path.dirname(tmpl_path), exist_ok=True)
            with open(tmpl_path, "w", encoding="utf-8") as f:
                cfg.write(f)
            ini = configparser.ConfigParser()
            if os.path.exists(gpt_path): ini.read(gpt_path)
            ver_str = ini.get("General", "Version", fallback="0") if ini.has_section("General") else "0"
            ver = int(ver_str) if ver_str.isdigit() else 0
            if not ini.has_section("General"): ini.add_section("General")
            ini.set("General", "Version", str(ver + 1))
            with open(gpt_path, "w") as f: ini.write(f)
            return {"ok": True}
        except Exception as e:
            return {"error": str(e)}


class _ShareManager:

    def list_shares(self):
        r = _ad_run_cmd([os.path.join(SAMBA_BIN, "smbclient"), "-L", "localhost", "-N", "--no-pass"])
        shares, in_shares = [], False
        for line in r["stdout"].splitlines():
            line = line.strip()
            if "Sharename" in line:
                in_shares = True; continue
            if in_shares:
                if not line or line.startswith("-"): continue
                if line.startswith("Server") or line.startswith("Workgroup"): break
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    shares.append({"name": parts[0], "type": parts[1] if len(parts) > 1 else "",
                                   "comment": parts[2] if len(parts) > 2 else ""})
        return {"shares": shares}

    def get_acl(self, share, path="/"):
        r = _ad_run_cmd([os.path.join(SAMBA_BIN, "smbcacls"), f"//localhost/{share}", path, "-N"])
        return {"acl": r["stdout"], "error": r["stderr"] if r["returncode"] != 0 else ""}

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


class _DNSManager:

    def list_zones(self):
        r = _samba_tool("dns", "zonelist", "localhost")
        return {"output": r["stdout"], "error": r["stderr"] if r["returncode"] != 0 else ""}

    def list_records(self, zone):
        r = _samba_tool("dns", "query", "localhost", zone, "@", "ALL")
        return {"output": r["stdout"], "error": r["stderr"] if r["returncode"] != 0 else ""}

    def add_record(self, zone, name, record_type, data):
        r = _samba_tool("dns", "add", "localhost", zone, name, record_type, data)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def delete_record(self, zone, name, record_type, data):
        r = _samba_tool("dns", "delete", "localhost", zone, name, record_type, data)
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
        r = _ldbsearch(_ad_get_domain_dn(), "subtree", attrs, "(objectClass=computer)")
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
            os.execv("/bin/login", ["/bin/login", "-p"])
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
            "ou_list":             lambda p: self._ad_ous.list_ous(),
            "ou_tree":             lambda p: self._ad_ous.get_ou_tree(),
            "ou_objects":          lambda p: self._ad_ous.get_ou_objects(p["ou_dn"]),
            "ou_create":           lambda p: self._ad_ous.create_ou(
                                       p["ou_name"], p.get("parent_dn",""), p.get("description","")),
            "ou_delete":           lambda p: self._ad_ous.delete_ou(p["ou_dn"], p.get("recursive", False)),
            "ou_rename":           lambda p: self._ad_ous.rename_ou(p["ou_dn"], p["new_name"]),
            "gpo_list":            lambda p: self._ad_gpos.list_gpos(),
            "gpo_get":             lambda p: self._ad_gpos.get_gpo(p["gpo_guid"]),
            "gpo_create":          lambda p: self._ad_gpos.create_gpo(p["display_name"]),
            "gpo_delete":          lambda p: self._ad_gpos.delete_gpo(p["gpo_guid"]),
            "gpo_link":            lambda p: self._ad_gpos.link_gpo(p["gpo_guid"], p["container_dn"]),
            "gpo_unlink":          lambda p: self._ad_gpos.unlink_gpo(p["gpo_guid"], p["container_dn"]),
            "gpo_linked":          lambda p: self._ad_gpos.get_linked_gpos(p["container_dn"]),
            "gpo_set_security":    lambda p: self._ad_gpos.set_security_setting(
                                       p["gpo_guid"], p["section"], p["key"], p["value"]),
            "share_list":          lambda p: self._ad_shares.list_shares(),
            "share_create":        lambda p: self._ad_shares.create_share(
                                       p["name"], p["path"], p.get("comment",""), p.get("read_only", False)),
            "share_acl":           lambda p: self._ad_shares.get_acl(p["share"], p.get("path","/")),
            "share_set_acl":       lambda p: self._ad_shares.set_acl(
                                       p["share"], p.get("path","/"), p["acl_string"], p.get("action","set")),
            "share_browse":        lambda p: self._ad_shares.browse_path(p["local_path"]),
            "share_set_posix":     lambda p: self._ad_shares.set_posix_acl(
                                       p["path"], p.get("owner",""), p.get("group",""), p.get("mode","")),
            "share_mkdir":         lambda p: self._ad_shares.create_directory(p["path"]),
            "dns_zones":           lambda p: self._ad_dns.list_zones(),
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
