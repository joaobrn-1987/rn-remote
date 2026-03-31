#!/usr/bin/env python3
"""
RNRemote - Agente Active Directory (Samba AD DC)
Roda no servidor CentOS 9 com Samba AD DC.

Uso:
    python3 ad_agent.py --relay wss://relay.exemplo.com/ws --id 123456789 --password senha
    python3 ad_agent.py --config /etc/rnremote/ad-agent.json
"""

import asyncio
import configparser
import hashlib
import json
import logging
import os
import signal
import socket
import stat
import subprocess
import sys
import time
import argparse

AGENT_VERSION = "1.0.0"

try:
    import websockets
except ImportError:
    print("Instale websockets: pip3 install websockets")
    sys.exit(1)

# ─── Samba Paths ───
SAMBA_BIN     = "/usr/local/samba/bin"
SAMBA_SBIN    = "/usr/local/samba/sbin"
SAMBA_PRIVATE = "/usr/local/samba/private"
SAMBA_ETC     = "/usr/local/samba/etc"
SYSVOL_PATH   = "/usr/local/samba/var/locks/sysvol"

HEARTBEAT_INTERVAL = 15

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("ad-agent")


# ─── Helpers ───

def run_cmd(cmd_list):
    env = os.environ.copy()
    path = env.get("PATH", "")
    extra = f"{SAMBA_BIN}:{SAMBA_SBIN}"
    if extra not in path:
        env["PATH"] = f"{extra}:{path}"
    try:
        proc = subprocess.run(
            cmd_list, capture_output=True, text=True, env=env, timeout=30
        )
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout ao executar comando", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def samba_tool(*args):
    return run_cmd([os.path.join(SAMBA_BIN, "samba-tool")] + list(args))


def ldbsearch(base, scope="subtree", attrs=None, expression=None):
    cmd = [
        os.path.join(SAMBA_BIN, "ldbsearch"),
        "-H", os.path.join(SAMBA_PRIVATE, "sam.ldb")
    ]
    if base:
        cmd += ["-b", base]
    if scope:
        cmd += ["-s", scope]
    if expression:
        cmd.append(expression)
    if attrs:
        if isinstance(attrs, list):
            cmd.extend(attrs)
        else:
            cmd.extend(attrs.split())
    return run_cmd(cmd)


def ldbmodify(ldif_string):
    cmd = [
        os.path.join(SAMBA_BIN, "ldbmodify"),
        "-H", os.path.join(SAMBA_PRIVATE, "sam.ldb")
    ]
    try:
        proc = subprocess.run(cmd, input=ldif_string, capture_output=True, text=True, timeout=30)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def ldbadd(ldif_string):
    cmd = [
        os.path.join(SAMBA_BIN, "ldbadd"),
        "-H", os.path.join(SAMBA_PRIVATE, "sam.ldb")
    ]
    try:
        proc = subprocess.run(cmd, input=ldif_string, capture_output=True, text=True, timeout=30)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def ldbdel(dn):
    cmd = [
        os.path.join(SAMBA_BIN, "ldbdel"),
        "-H", os.path.join(SAMBA_PRIVATE, "sam.ldb"), dn
    ]
    return run_cmd(cmd)


def parse_ldb_output(stdout):
    """Parseia saída do ldbsearch em lista de dicts. Suporta multivalor."""
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
            key = key.strip()
            value = value.strip()
            if key in current:
                existing = current[key]
                if isinstance(existing, list):
                    existing.append(value)
                else:
                    current[key] = [existing, value]
            else:
                current[key] = value
    if current:
        entries.append(current)
    return [e for e in entries if e.get("dn") and not e["dn"].startswith("ref:")]


def get_realm():
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(SAMBA_ETC, "smb.conf"))
    return cfg.get("global", "realm", fallback="").strip()


def get_domain_name():
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(SAMBA_ETC, "smb.conf"))
    return cfg.get("global", "workgroup", fallback="").strip()


def get_domain_dn():
    realm = get_realm()
    if not realm:
        return ""
    parts = realm.lower().split(".")
    return ",".join(f"DC={p}" for p in parts)


# ─── UserManager ───

class UserManager:

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
        base = ou or get_domain_dn()
        r = ldbsearch(base, "subtree", self._USER_ATTRS,
                      "(&(objectClass=user)(objectCategory=person))")
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        users = []
        for entry in parse_ldb_output(r["stdout"]):
            sam = entry.get("sAMAccountName", "")
            if isinstance(sam, list):
                sam = sam[0]
            if sam.endswith("$") or sam.lower() == "krbtgt":
                continue
            users.append(self._decode_uac(entry))
        return {"users": users}

    def get_user(self, username):
        base = get_domain_dn()
        r = ldbsearch(base, "subtree", self._USER_ATTRS,
                      f"(sAMAccountName={username})")
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        entries = parse_ldb_output(r["stdout"])
        if not entries:
            return {"error": "Usuário não encontrado"}
        return {"user": self._decode_uac(entries[0])}

    def create_user(self, username, password, given_name="", surname="",
                    mail="", ou="", must_change_password=False, unix_attrs=None):
        args = ["user", "create", username, password]
        if given_name:
            args += ["--given-name", given_name]
        if surname:
            args += ["--surname", surname]
        if mail:
            args += ["--mail-address", mail]
        if ou:
            args += ["--userou", ou]
        if must_change_password:
            args.append("--must-change-at-next-login")
        if unix_attrs:
            if unix_attrs.get("uid_number"):
                args += ["--uid-number", str(unix_attrs["uid_number"])]
            if unix_attrs.get("gid_number"):
                args += ["--gid-number", str(unix_attrs["gid_number"])]
            if unix_attrs.get("login_shell"):
                args += ["--login-shell", unix_attrs["login_shell"]]
            if unix_attrs.get("unix_home"):
                args += ["--unix-home", unix_attrs["unix_home"]]
        r = samba_tool(*args)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def modify_user(self, username, attrs_dict):
        user_data = self.get_user(username)
        if "error" in user_data:
            return {"error": user_data["error"]}
        dn = user_data["user"]["distinguishedName"]
        if isinstance(dn, list):
            dn = dn[0]
        lines = [f"dn: {dn}", "changetype: modify"]
        for attr, value in attrs_dict.items():
            if value is None or value == "":
                lines += [f"delete: {attr}", "-"]
            else:
                lines += [f"replace: {attr}", f"{attr}: {value}", "-"]
        ldif = "\n".join(lines) + "\n"
        r = ldbmodify(ldif)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def delete_user(self, username):
        r = samba_tool("user", "delete", username)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def enable_user(self, username):
        r = samba_tool("user", "enable", username)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def disable_user(self, username):
        r = samba_tool("user", "disable", username)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def reset_password(self, username, new_password, must_change=False):
        args = ["user", "setpassword", username, f"--newpassword={new_password}"]
        if must_change:
            args.append("--must-change-at-next-login")
        r = samba_tool(*args)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def unlock_user(self, username):
        user_data = self.get_user(username)
        if "error" in user_data:
            return {"error": user_data["error"]}
        dn = user_data["user"]["distinguishedName"]
        if isinstance(dn, list):
            dn = dn[0]
        ldif = f"dn: {dn}\nchangetype: modify\nreplace: lockoutTime\nlockoutTime: 0\n"
        r = ldbmodify(ldif)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def move_user(self, username, target_ou):
        r = samba_tool("user", "move", username, target_ou)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def get_user_groups(self, username):
        r = samba_tool("user", "getgroups", username)
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        groups = [g.strip() for g in r["stdout"].splitlines() if g.strip()]
        return {"groups": groups}


# ─── GroupManager ───

class GroupManager:

    def list_groups(self, ou=None):
        base = ou or get_domain_dn()
        attrs = [
            "cn", "sAMAccountName", "description", "distinguishedName",
            "member", "groupType", "whenCreated", "gidNumber", "managedBy"
        ]
        r = ldbsearch(base, "subtree", attrs, "(objectClass=group)")
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        groups = []
        for entry in parse_ldb_output(r["stdout"]):
            gt_raw = entry.get("groupType", "0") or "0"
            try:
                gt = int(gt_raw)
                if gt < 0:
                    gt = gt + 2**32
            except (ValueError, TypeError):
                gt = 0
            entry["_scope"] = (
                "global"      if gt & 0x2 else
                "domainlocal" if gt & 0x4 else
                "universal"   if gt & 0x8 else "unknown"
            )
            entry["_type"] = "security" if gt & 0x80000000 else "distribution"
            groups.append(entry)
        return {"groups": groups}

    def get_group(self, groupname):
        base = get_domain_dn()
        attrs = ["cn","sAMAccountName","description","distinguishedName",
                 "member","groupType","whenCreated","gidNumber","managedBy"]
        r = ldbsearch(base, "subtree", attrs, f"(sAMAccountName={groupname})")
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        entries = parse_ldb_output(r["stdout"])
        if not entries:
            return {"error": "Grupo não encontrado"}
        return {"group": entries[0]}

    def create_group(self, groupname, description="", group_type="Security",
                     group_scope="Global", ou="", gid_number=None):
        args = ["group", "create", groupname]
        if group_type.lower() == "distribution":
            args.append("--group-type=Distribution")
        if group_scope.lower() == "domainlocal":
            args.append("--group-scope=DomainLocal")
        elif group_scope.lower() == "universal":
            args.append("--group-scope=Universal")
        if description:
            args += ["--description", description]
        if ou:
            args += ["--groupou", ou]
        if gid_number:
            args += ["--gid-number", str(gid_number)]
        r = samba_tool(*args)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def delete_group(self, groupname):
        r = samba_tool("group", "delete", groupname)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def add_member(self, groupname, member):
        r = samba_tool("group", "addmembers", groupname, member)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def remove_member(self, groupname, member):
        r = samba_tool("group", "removemembers", groupname, member)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def list_members(self, groupname):
        r = samba_tool("group", "listmembers", groupname)
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        members = [m.strip() for m in r["stdout"].splitlines() if m.strip()]
        return {"members": members}


# ─── OUManager ───

class OUManager:

    def list_ous(self):
        base = get_domain_dn()
        r = ldbsearch(base, "subtree",
                      ["ou","description","distinguishedName","whenCreated"],
                      "(objectClass=organizationalUnit)")
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        return {"ous": parse_ldb_output(r["stdout"])}

    def create_ou(self, ou_name, parent_dn="", description=""):
        if not parent_dn:
            parent_dn = get_domain_dn()
        full_dn = f"OU={ou_name},{parent_dn}"
        r = samba_tool("ou", "create", full_dn)
        if r["returncode"] != 0:
            ldif = f"dn: {full_dn}\nobjectClass: organizationalUnit\nou: {ou_name}\n"
            if description:
                ldif += f"description: {description}\n"
            r2 = ldbadd(ldif)
            return {"ok": r2["returncode"] == 0, "output": r2["stdout"] + r2["stderr"]}
        if description:
            ldif = (f"dn: {full_dn}\nchangetype: modify\n"
                    f"replace: description\ndescription: {description}\n")
            ldbmodify(ldif)
        return {"ok": True, "output": r["stdout"]}

    def delete_ou(self, ou_dn, recursive=False):
        if recursive:
            r = ldbsearch(ou_dn, "one", ["distinguishedName", "objectClass"], None)
            for entry in parse_ldb_output(r["stdout"]):
                ldbdel(entry["dn"])
        r = samba_tool("ou", "delete", ou_dn)
        if r["returncode"] != 0:
            r = ldbdel(ou_dn)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def rename_ou(self, ou_dn, new_name):
        parent = ",".join(ou_dn.split(",")[1:])
        new_dn = f"OU={new_name},{parent}"
        cmd = [
            os.path.join(SAMBA_BIN, "ldbrename"),
            "-H", os.path.join(SAMBA_PRIVATE, "sam.ldb"),
            ou_dn, new_dn
        ]
        r = run_cmd(cmd)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def get_ou_tree(self):
        base = get_domain_dn()
        r = ldbsearch(
            base, "subtree",
            ["distinguishedName","ou","cn","objectClass","name"],
            "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))"
        )
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        entries = parse_ldb_output(r["stdout"])

        def get_type(entry):
            oc = entry.get("objectClass", "")
            oc_list = oc if isinstance(oc, list) else [oc]
            if "organizationalUnit" in oc_list:
                return "ou"
            if "builtinDomain" in oc_list:
                return "builtin"
            return "container"

        nodes = {}
        for e in entries:
            dn = e.get("dn", "")
            name = e.get("ou") or e.get("cn") or e.get("name") or dn.split(",")[0].split("=")[-1]
            if isinstance(name, list):
                name = name[0]
            nodes[dn.lower()] = {
                "dn":       dn,
                "name":     name,
                "type":     get_type(e),
                "children": []
            }

        domain_node = {
            "dn":       base,
            "name":     get_realm() or base.split(",")[0].split("=")[-1],
            "type":     "domain",
            "children": []
        }

        def build_children(parent_dn):
            children = []
            for node in nodes.values():
                dn = node["dn"]
                parent_part = ",".join(dn.split(",")[1:])
                if parent_part.lower() == parent_dn.lower():
                    node["children"] = build_children(dn)
                    children.append(node)
            return sorted(children, key=lambda x: x["name"])

        domain_node["children"] = build_children(base)
        return {"tree": domain_node}

    def get_ou_objects(self, ou_dn):
        r = ldbsearch(ou_dn, "one",
                      ["distinguishedName","objectClass","cn","sAMAccountName",
                       "description","name","userAccountControl","groupType"],
                      None)
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        objects = []
        for entry in parse_ldb_output(r["stdout"]):
            oc = entry.get("objectClass", "")
            oc_list = oc if isinstance(oc, list) else [oc]
            if "computer" in oc_list:
                entry["_type"] = "computer"
            elif "user" in oc_list and "person" in oc_list:
                entry["_type"] = "user"
            elif "group" in oc_list:
                entry["_type"] = "group"
            elif "organizationalUnit" in oc_list:
                entry["_type"] = "ou"
            elif "container" in oc_list:
                entry["_type"] = "container"
            else:
                entry["_type"] = "object"
            objects.append(entry)
        return {"objects": objects}


# ─── GPOManager ───

class GPOManager:

    def list_gpos(self):
        r = samba_tool("gpo", "listall")
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        gpos = []
        current = {}
        for line in r["stdout"].splitlines():
            if line.startswith("GPO") and ":" not in line:
                if current:
                    gpos.append(current)
                current = {}
            elif ":" in line:
                key, _, value = line.partition(":")
                current[key.strip()] = value.strip()
        if current:
            gpos.append(current)
        return {"gpos": gpos}

    def get_gpo(self, gpo_guid):
        r = samba_tool("gpo", "show", gpo_guid)
        info = {"guid": gpo_guid, "output": r["stdout"]}
        realm = get_realm().lower()
        tmpl_path = os.path.join(SYSVOL_PATH, realm, "Policies",
                                  gpo_guid, "MACHINE", "Microsoft",
                                  "Windows NT", "SecEdit", "GptTmpl.inf")
        if os.path.exists(tmpl_path):
            try:
                with open(tmpl_path, "r", encoding="utf-8", errors="replace") as f:
                    info["gpt_tmpl"] = f.read()
            except Exception:
                pass
        return {"gpo": info}

    def create_gpo(self, display_name):
        r = samba_tool("gpo", "create", display_name)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def delete_gpo(self, gpo_guid):
        r = samba_tool("gpo", "del", gpo_guid)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def link_gpo(self, gpo_guid, container_dn):
        r = samba_tool("gpo", "setlink", container_dn, gpo_guid)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def unlink_gpo(self, gpo_guid, container_dn):
        r = samba_tool("gpo", "dellink", container_dn, gpo_guid)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def get_linked_gpos(self, container_dn):
        r = samba_tool("gpo", "getlink", container_dn)
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        return {"output": r["stdout"]}

    def set_security_setting(self, gpo_guid, section, key, value):
        realm = get_realm().lower()
        tmpl_path = os.path.join(SYSVOL_PATH, realm, "Policies",
                                  gpo_guid, "MACHINE", "Microsoft",
                                  "Windows NT", "SecEdit", "GptTmpl.inf")
        gpt_path = os.path.join(SYSVOL_PATH, realm, "Policies", gpo_guid, "GPT.INI")
        try:
            cfg = configparser.ConfigParser()
            if os.path.exists(tmpl_path):
                cfg.read(tmpl_path, encoding="utf-8")
            if not cfg.has_section(section):
                cfg.add_section(section)
            cfg.set(section, key, str(value))
            os.makedirs(os.path.dirname(tmpl_path), exist_ok=True)
            with open(tmpl_path, "w", encoding="utf-8") as f:
                cfg.write(f)
            ini = configparser.ConfigParser()
            if os.path.exists(gpt_path):
                ini.read(gpt_path)
            ver_str = ini.get("General", "Version", fallback="0") if ini.has_section("General") else "0"
            ver = int(ver_str) if ver_str.isdigit() else 0
            if not ini.has_section("General"):
                ini.add_section("General")
            ini.set("General", "Version", str(ver + 1))
            with open(gpt_path, "w") as f:
                ini.write(f)
            return {"ok": True}
        except Exception as e:
            return {"error": str(e)}


# ─── ShareManager ───

class ShareManager:

    def list_shares(self):
        r = run_cmd([os.path.join(SAMBA_BIN, "smbclient"),
                     "-L", "localhost", "-N", "--no-pass"])
        shares = []
        in_shares = False
        for line in r["stdout"].splitlines():
            line = line.strip()
            if "Sharename" in line:
                in_shares = True
                continue
            if in_shares:
                if not line or line.startswith("-"):
                    continue
                if line.startswith("Server") or line.startswith("Workgroup"):
                    break
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    shares.append({
                        "name":    parts[0],
                        "type":    parts[1] if len(parts) > 1 else "",
                        "comment": parts[2] if len(parts) > 2 else ""
                    })
        return {"shares": shares}

    def get_acl(self, share, path="/"):
        r = run_cmd([os.path.join(SAMBA_BIN, "smbcacls"),
                     f"//localhost/{share}", path, "-N"])
        return {
            "acl":   r["stdout"],
            "error": r["stderr"] if r["returncode"] != 0 else ""
        }

    def set_acl(self, share, path, acl_string, action="set"):
        flags = {"set": "-S", "add": "-a", "delete": "-D", "modify": "-M"}
        flag = flags.get(action.lower(), "-S")
        r = run_cmd([os.path.join(SAMBA_BIN, "smbcacls"),
                     f"//localhost/{share}", path, "-N", flag, acl_string])
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def create_share(self, name, path, comment="", read_only=False):
        smb_conf = os.path.join(SAMBA_ETC, "smb.conf")
        try:
            with open(smb_conf, "a") as f:
                f.write(f"\n[{name}]\n")
                f.write(f"    path = {path}\n")
                if comment:
                    f.write(f"    comment = {comment}\n")
                f.write(f"    read only = {'yes' if read_only else 'no'}\n")
            run_cmd([os.path.join(SAMBA_BIN, "smbcontrol"), "smbd", "reload-config"])
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
                    entries.append({
                        "name":     name,
                        "path":     full,
                        "is_dir":   os.path.isdir(full),
                        "size":     s.st_size,
                        "modified": s.st_mtime,
                        "mode":     oct(stat.S_IMODE(s.st_mode)),
                    })
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


# ─── DNSManager ───

class DNSManager:

    def list_zones(self):
        r = samba_tool("dns", "zonelist", "localhost")
        return {
            "output": r["stdout"],
            "error":  r["stderr"] if r["returncode"] != 0 else ""
        }

    def list_records(self, zone):
        r = samba_tool("dns", "query", "localhost", zone, "@", "ALL")
        return {
            "output": r["stdout"],
            "error":  r["stderr"] if r["returncode"] != 0 else ""
        }

    def add_record(self, zone, name, record_type, data):
        r = samba_tool("dns", "add", "localhost", zone, name, record_type, data)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}

    def delete_record(self, zone, name, record_type, data):
        r = samba_tool("dns", "delete", "localhost", zone, name, record_type, data)
        return {"ok": r["returncode"] == 0, "output": r["stdout"] + r["stderr"]}


# ─── DomainInfo ───

class DomainInfo:

    def get_info(self):
        domain_dn   = get_domain_dn()
        realm       = get_realm()
        domain_name = get_domain_name()
        hostname    = socket.gethostname()

        level   = samba_tool("domain", "level", "show")
        procs   = samba_tool("processes")
        fsmo    = samba_tool("fsmo", "show")
        pwdpol  = samba_tool("domain", "passwordsettings", "show")

        return {
            "domain_dn":       domain_dn,
            "realm":           realm,
            "domain_name":     domain_name,
            "hostname":        hostname,
            "level":           level["stdout"],
            "processes":       procs["stdout"],
            "fsmo":            fsmo["stdout"],
            "password_policy": pwdpol["stdout"],
        }

    def get_computers(self):
        base  = get_domain_dn()
        attrs = [
            "cn", "sAMAccountName", "distinguishedName",
            "operatingSystem", "operatingSystemVersion",
            "lastLogon", "description", "dNSHostName"
        ]
        r = ldbsearch(base, "subtree", attrs, "(objectClass=computer)")
        if r["returncode"] != 0:
            return {"error": r["stderr"]}
        return {"computers": parse_ldb_output(r["stdout"])}


# ─── Agente Principal ───

class ADAgent:

    def __init__(self, relay_url, agent_id, password, config=None):
        self.relay_url = relay_url
        self.agent_id  = agent_id
        self.password  = password
        self.config    = config or {}
        self._running  = True

        self.users  = UserManager()
        self.groups = GroupManager()
        self.ous    = OUManager()
        self.gpos   = GPOManager()
        self.shares = ShareManager()
        self.dns    = DNSManager()
        self.domain = DomainInfo()

    def _hash_password(self, pw):
        return hashlib.sha256(pw.encode()).hexdigest()

    async def run(self):
        while self._running:
            try:
                await self._connect()
            except Exception as e:
                logger.error(f"Erro de conexão: {e}")
            if self._running:
                logger.info("Reconectando em 5s...")
                await asyncio.sleep(5)

    async def _connect(self):
        logger.info(f"Conectando a {self.relay_url}...")
        async with websockets.connect(
            self.relay_url,
            ping_interval=20,
            ping_timeout=40,
            close_timeout=10,
            max_size=10 * 1024 * 1024,
        ) as ws:
            logger.info("Conexão estabelecida")
            reg_data = {
                "agent_id":      self.agent_id,
                "password_hash": self._hash_password(self.password) if self.password else "",
                "hostname":      socket.gethostname(),
                "os_type":       "Samba AD DC",
                "os_version":    "CentOS 9",
                "username":      "root",
                "ad_agent":      True,
                "ad_version":    AGENT_VERSION,
            }
            await ws.send(json.dumps({
                "type":       "register_agent",
                "data":       reg_data,
                "session_id": None,
                "timestamp":  time.time()
            }))

            async def heartbeat():
                while True:
                    await asyncio.sleep(HEARTBEAT_INTERVAL)
                    try:
                        await ws.send(json.dumps({
                            "type": "ping", "data": {}, "session_id": None
                        }))
                    except Exception:
                        break

            hb_task = asyncio.create_task(heartbeat())
            try:
                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    await self._handle_message(ws, msg)
            finally:
                hb_task.cancel()

    async def _handle_message(self, ws, msg):
        t = msg.get("type")
        if t == "auth_success":
            logger.info(f"Agente registrado: {self.agent_id}")
        elif t == "auth_failure":
            logger.error(f"Falha de autenticação: {msg.get('data', {}).get('reason', '')}")
        elif t == "ad_request":
            await self._handle_ad_request(ws, msg)
        elif t == "connect_accept":
            logger.info(f"Sessão aceita: {str(msg.get('session_id',''))[:12]}")
        elif t == "pong":
            pass

    async def _handle_ad_request(self, ws, msg):
        data       = msg.get("data", {})
        session_id = msg.get("session_id")
        action     = data.get("action")
        params     = data.get("params", {})
        request_id = data.get("request_id")

        logger.info(f"AD request: {action} (session={str(session_id or '')[:12]})")
        try:
            result = self._dispatch_ad_action(action, params)
        except Exception as e:
            logger.exception(f"Erro no dispatch de {action}")
            result = {"error": str(e)}

        response = {
            "type": "ad_response",
            "data": {
                "action":     action,
                "request_id": request_id,
                "result":     result,
            },
            "session_id": session_id,
            "timestamp":  time.time()
        }
        try:
            await ws.send(json.dumps(response))
        except Exception as e:
            logger.error(f"Erro ao enviar resposta: {e}")

    def _dispatch_ad_action(self, action, params):
        dispatch = {
            # Domain
            "domain_info":          lambda p: self.domain.get_info(),
            "domain_computers":     lambda p: self.domain.get_computers(),
            # Users
            "user_list":            lambda p: self.users.list_users(p.get("ou")),
            "user_get":             lambda p: self.users.get_user(p["username"]),
            "user_create":          lambda p: self.users.create_user(
                                        p["username"], p["password"],
                                        p.get("given_name", ""), p.get("surname", ""),
                                        p.get("mail", ""), p.get("ou", ""),
                                        p.get("must_change_password", False),
                                        p.get("unix_attrs")),
            "user_modify":          lambda p: self.users.modify_user(
                                        p["username"], p["attrs"]),
            "user_delete":          lambda p: self.users.delete_user(p["username"]),
            "user_enable":          lambda p: self.users.enable_user(p["username"]),
            "user_disable":         lambda p: self.users.disable_user(p["username"]),
            "user_reset_password":  lambda p: self.users.reset_password(
                                        p["username"], p["new_password"],
                                        p.get("must_change", False)),
            "user_unlock":          lambda p: self.users.unlock_user(p["username"]),
            "user_move":            lambda p: self.users.move_user(
                                        p["username"], p["target_ou"]),
            "user_groups":          lambda p: self.users.get_user_groups(p["username"]),
            # Groups
            "group_list":           lambda p: self.groups.list_groups(p.get("ou")),
            "group_get":            lambda p: self.groups.get_group(p["groupname"]),
            "group_create":         lambda p: self.groups.create_group(
                                        p["groupname"], p.get("description", ""),
                                        p.get("group_type", "Security"),
                                        p.get("group_scope", "Global"),
                                        p.get("ou", ""), p.get("gid_number")),
            "group_delete":         lambda p: self.groups.delete_group(p["groupname"]),
            "group_add_member":     lambda p: self.groups.add_member(
                                        p["groupname"], p["member"]),
            "group_remove_member":  lambda p: self.groups.remove_member(
                                        p["groupname"], p["member"]),
            "group_members":        lambda p: self.groups.list_members(p["groupname"]),
            # OUs
            "ou_list":              lambda p: self.ous.list_ous(),
            "ou_tree":              lambda p: self.ous.get_ou_tree(),
            "ou_objects":           lambda p: self.ous.get_ou_objects(p["ou_dn"]),
            "ou_create":            lambda p: self.ous.create_ou(
                                        p["ou_name"], p.get("parent_dn", ""),
                                        p.get("description", "")),
            "ou_delete":            lambda p: self.ous.delete_ou(
                                        p["ou_dn"], p.get("recursive", False)),
            "ou_rename":            lambda p: self.ous.rename_ou(p["ou_dn"], p["new_name"]),
            # GPOs
            "gpo_list":             lambda p: self.gpos.list_gpos(),
            "gpo_get":              lambda p: self.gpos.get_gpo(p["gpo_guid"]),
            "gpo_create":           lambda p: self.gpos.create_gpo(p["display_name"]),
            "gpo_delete":           lambda p: self.gpos.delete_gpo(p["gpo_guid"]),
            "gpo_link":             lambda p: self.gpos.link_gpo(
                                        p["gpo_guid"], p["container_dn"]),
            "gpo_unlink":           lambda p: self.gpos.unlink_gpo(
                                        p["gpo_guid"], p["container_dn"]),
            "gpo_linked":           lambda p: self.gpos.get_linked_gpos(p["container_dn"]),
            "gpo_set_security":     lambda p: self.gpos.set_security_setting(
                                        p["gpo_guid"], p["section"], p["key"], p["value"]),
            # Shares
            "share_list":           lambda p: self.shares.list_shares(),
            "share_create":         lambda p: self.shares.create_share(
                                        p["name"], p["path"],
                                        p.get("comment", ""), p.get("read_only", False)),
            "share_acl":            lambda p: self.shares.get_acl(
                                        p["share"], p.get("path", "/")),
            "share_set_acl":        lambda p: self.shares.set_acl(
                                        p["share"], p.get("path", "/"),
                                        p["acl_string"], p.get("action", "set")),
            "share_browse":         lambda p: self.shares.browse_path(p["local_path"]),
            "share_set_posix":      lambda p: self.shares.set_posix_acl(
                                        p["path"], p.get("owner", ""),
                                        p.get("group", ""), p.get("mode", "")),
            "share_mkdir":          lambda p: self.shares.create_directory(p["path"]),
            # DNS
            "dns_zones":            lambda p: self.dns.list_zones(),
            "dns_records":          lambda p: self.dns.list_records(p["zone"]),
            "dns_add":              lambda p: self.dns.add_record(
                                        p["zone"], p["name"], p["record_type"], p["data"]),
            "dns_delete":           lambda p: self.dns.delete_record(
                                        p["zone"], p["name"], p["record_type"], p["data"]),
        }
        fn = dispatch.get(action)
        if fn is None:
            return {"error": f"Ação desconhecida: {action}"}
        return fn(params)

    def stop(self):
        self._running = False


def main():
    parser = argparse.ArgumentParser(description="RNRemote Agente Active Directory")
    parser.add_argument("--relay",    default="",  help="URL do relay WebSocket")
    parser.add_argument("--id",       dest="agent_id", default="", help="ID do agente (9 dígitos)")
    parser.add_argument("--password", default="",  help="Senha de acesso")
    parser.add_argument("--config",   default="",  help="Arquivo de configuração JSON")
    args = parser.parse_args()

    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config) as f:
            config = json.load(f)

    relay    = args.relay    or config.get("relay_url", "")
    agent_id = args.agent_id or config.get("agent_id", "")
    password = args.password or config.get("password", "")

    if not relay or not agent_id:
        parser.error("--relay e --id são obrigatórios (ou use --config)")

    agent = ADAgent(relay, agent_id, password, config)

    def handle_signal(sig, frame):
        logger.info("Encerrando agente AD...")
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT,  handle_signal)

    logger.info(f"RNRemote AD Agent v{AGENT_VERSION}")
    logger.info(f"Relay: {relay} | ID: {agent_id}")

    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Encerrado.")


if __name__ == "__main__":
    main()
