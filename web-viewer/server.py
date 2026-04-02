"""
RNRemote - Web Panel + Viewer
API REST para painel admin + serve interface web.
"""

import asyncio
import json
import os
import sys
import argparse
import logging
import time
import hmac
import hashlib
import secrets
from typing import Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from aiohttp import web

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from shared.protocol import hash_password, hash_password_bcrypt, PROTOCOL_VERSION
from shared.database import Database

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("web")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
_TOKEN_SECRET_FILE = "/etc/rnremote/token_secret"


def _load_token_secret() -> str:
    try:
        with open(_TOKEN_SECRET_FILE) as f:
            s = f.read().strip()
            if s:
                return s
    except FileNotFoundError:
        pass
    secret = secrets.token_hex(32)
    os.makedirs(os.path.dirname(_TOKEN_SECRET_FILE), exist_ok=True)
    with open(_TOKEN_SECRET_FILE, "w") as f:
        f.write(secret)
    os.chmod(_TOKEN_SECRET_FILE, 0o600)
    logger.info(f"Token secret criado em {_TOKEN_SECRET_FILE}")
    return secret


_TOKEN_SECRET = _load_token_secret()


def _generate_token(user_id: int, email: str, role: str) -> str:
    """Gera token HMAC-SHA256 com role embutido. Formato: user_id:email:role:expiry:sig"""
    expiry = int(time.time()) + 86400  # 24 horas
    payload = f"{user_id}:{email}:{role}:{expiry}"
    sig = hmac.new(_TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _verify_token(token: str) -> Optional[dict]:
    """
    Verifica token HMAC e retorna dict {user_id, email, role} se válido.
    Suporta formato novo (5 partes) e legado (4 partes sem role).
    """
    try:
        parts = token.split(":")
        if len(parts) == 5:
            user_id_s, email, role, expiry_s, sig = parts
            payload = f"{user_id_s}:{email}:{role}:{expiry_s}"
        elif len(parts) == 4:
            # Token legado sem role — tratar como não-admin para forçar re-login seguro
            user_id_s, email, expiry_s, sig = parts
            role = ""
            payload = f"{user_id_s}:{email}:{expiry_s}"
        else:
            return None
        expected = hmac.new(_TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if time.time() >= int(expiry_s):
            return None
        return {"user_id": int(user_id_s), "email": email, "role": role}
    except Exception:
        return None


def _is_admin(token_data: dict) -> bool:
    """Retorna True se o usuário tem papel admin ou superior."""
    if not token_data:
        return False
    role = token_data.get("role", "")
    email = token_data.get("email", "")
    return role in ("superadmin", "admin") or email == "app@rochaneto.com"


# ─── Rate limiting em memória (login, MFA) ───

_login_attempts: dict = {}   # {ip: [timestamp, ...]}
_mfa_attempts: dict = {}     # {mfa_session: attempt_count}
_RATE_WINDOW = 300           # 5 minutos
_RATE_MAX_LOGIN = 10         # tentativas de login por IP
_RATE_MAX_MFA = 10           # tentativas de código MFA por sessão


def _check_rate_limit(store: dict, key: str, window: int = _RATE_WINDOW,
                      max_attempts: int = _RATE_MAX_LOGIN) -> bool:
    """Retorna True se dentro do limite, False se deve bloquear."""
    now = time.time()
    attempts = [t for t in store.get(key, []) if now - t < window]
    if len(attempts) >= max_attempts:
        store[key] = attempts
        return False
    attempts.append(now)
    store[key] = attempts
    return True


def _get_client_ip(req) -> str:
    return req.headers.get("X-Real-IP") or req.headers.get("X-Forwarded-For", "").split(",")[0].strip() or req.remote or ""


# ─── MFA: armazena códigos temporários em memória ───
_mfa_pending: dict = {}
MFA_CODE_TTL = 600  # 10 minutos


def _mfa_cleanup():
    now = time.time()
    expired = [k for k, v in _mfa_pending.items() if v['expires_at'] < now]
    for k in expired:
        del _mfa_pending[k]


async def _send_mfa_email(to_email: str, code: str, smtp_cfg: dict):
    """Envia o código MFA por e-mail via SMTP configurado nas settings."""
    import smtplib
    host = smtp_cfg.get('smtp_host', '')
    port = int(smtp_cfg.get('smtp_port', 587))
    user = smtp_cfg.get('smtp_user', '')
    password = smtp_cfg.get('smtp_pass', '')
    from_addr = smtp_cfg.get('smtp_from', user)
    use_tls = smtp_cfg.get('smtp_tls', 'true').lower() in ('true', '1', 'yes')

    if not host or not user:
        raise ValueError("SMTP não configurado. Configure em Configurações > SMTP.")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Seu código de acesso — RN Remote'
    msg['From'] = from_addr or user
    msg['To'] = to_email

    body_text = f"Seu código de verificação é: {code}\n\nEste código expira em 10 minutos."
    body_html = f"""
    <div style="font-family:Arial,sans-serif;max-width:420px;margin:40px auto;background:#f0f4fa;border-radius:12px;padding:32px;border:1px solid #dde3ee">
      <h2 style="margin:0 0 8px;color:#1e293b;font-size:20px">&#128274; RN Remote</h2>
      <p style="color:#475569;margin:0 0 24px;font-size:14px">Código de verificação de acesso</p>
      <div style="background:#fff;border-radius:10px;padding:20px 24px;text-align:center;border:1px solid #dde3ee;margin-bottom:24px">
        <span style="font-size:36px;font-weight:700;letter-spacing:10px;color:#2563eb;font-family:monospace">{code}</span>
      </div>
      <p style="color:#64748b;font-size:13px;margin:0">Este código expira em <strong>10 minutos</strong>. Se não foi você, ignore este e-mail.</p>
    </div>"""

    msg.attach(MIMEText(body_text, 'plain'))
    msg.attach(MIMEText(body_html, 'html'))

    loop = asyncio.get_event_loop()
    def _send():
        if use_tls:
            srv = smtplib.SMTP(host, port)
            srv.ehlo()
            srv.starttls()
        else:
            srv = smtplib.SMTP_SSL(host, port)
        srv.login(user, password)
        srv.sendmail(msg['From'], [to_email], msg.as_string())
        srv.quit()
    await loop.run_in_executor(None, _send)


class WebPanel:

    def __init__(self, db_dsn: str):
        self.db = Database(db_dsn)

    async def init(self):
        await self.db.connect()

    # ─── Helpers de autenticação ───

    def _require_auth(self, req) -> Optional[dict]:
        """Retorna token_data {user_id, email, role} se Bearer token válido, None caso contrário."""
        auth = req.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        return _verify_token(auth[7:])

    def _require_admin(self, req) -> Optional[dict]:
        """Retorna token_data apenas se o usuário for admin ou superadmin."""
        token_data = self._require_auth(req)
        if not token_data:
            return None
        return token_data if _is_admin(token_data) else None

    # ─── Páginas ───

    async def index(self, req):
        resp = web.FileResponse(os.path.join(STATIC_DIR, "index.html"))
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp

    async def admin_page(self, req):
        return web.FileResponse(os.path.join(STATIC_DIR, "admin.html"))

    # ─── API: Auth ───

    async def api_login(self, req):
        ip = _get_client_ip(req)
        if not _check_rate_limit(_login_attempts, ip, max_attempts=_RATE_MAX_LOGIN):
            return web.json_response(
                {"ok": False, "error": "Muitas tentativas. Aguarde 5 minutos."},
                status=429
            )
        data = await req.json()
        user = await self.db.authenticate_admin(
            data.get("email", ""),
            data.get("password", "")   # senha em claro — hash feito no db.authenticate_admin
        )
        if user:
            role = user.get('role') or ''
            # Se MFA estiver ativo, enviar código por e-mail
            if user.get('mfa_enabled'):
                _mfa_cleanup()
                code = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
                mfa_session = secrets.token_hex(24)
                if _is_admin({"email": user['email'], "role": role}):
                    permissions = {'*': True}
                else:
                    permissions = await self.db.get_user_permissions(user['id'])
                access = await self.db.get_user_access(user['id'])
                _mfa_pending[mfa_session] = {
                    'user_id': user['id'],
                    'code': code,
                    'expires_at': time.time() + MFA_CODE_TTL,
                    'user_data': {
                        'token': _generate_token(user['id'], user['email'], role),
                        'user': user['display_name'] or user['email'],
                        'role': role,
                        'user_id': user['id'],
                        'profile_id': user.get('profile_id'),
                        'permissions': permissions,
                        'access': access,
                    }
                }
                try:
                    smtp_cfg = await self.db.get_all_settings()
                    await _send_mfa_email(user['email'], code, smtp_cfg)
                except Exception as e:
                    logger.error("Erro ao enviar MFA: %s", e)
                    return web.json_response({"ok": False, "error": f"Erro ao enviar código MFA: {e}"}, status=500)
                return web.json_response({"ok": True, "mfa_required": True, "mfa_session": mfa_session})

            token = _generate_token(user['id'], user['email'], role)
            if _is_admin({"email": user['email'], "role": role}):
                permissions = {'*': True}
            else:
                permissions = await self.db.get_user_permissions(user['id'])
            access = await self.db.get_user_access(user['id'])
            return web.json_response({
                "ok": True, "token": token,
                "user": user['display_name'] or user['email'],
                "role": role, "user_id": user['id'],
                "profile_id": user.get('profile_id'),
                "permissions": permissions,
                "access": access,
            })
        return web.json_response({"ok": False, "error": "Credenciais inválidas"}, status=401)

    async def api_mfa_verify(self, req):
        data = await req.json()
        mfa_session = data.get("mfa_session", "")
        code = data.get("code", "").strip()
        _mfa_cleanup()
        entry = _mfa_pending.get(mfa_session)
        if not entry:
            return web.json_response({"ok": False, "error": "Sessão MFA expirada. Faça login novamente."}, status=401)
        # Rate limiting por sessão MFA
        if not _check_rate_limit(_mfa_attempts, mfa_session, max_attempts=_RATE_MAX_MFA):
            del _mfa_pending[mfa_session]  # invalidar após excesso de tentativas
            return web.json_response({"ok": False, "error": "Muitas tentativas. Faça login novamente."}, status=429)
        if entry['code'] != code:
            return web.json_response({"ok": False, "error": "Código inválido."}, status=401)
        del _mfa_pending[mfa_session]
        _mfa_attempts.pop(mfa_session, None)
        return web.json_response({"ok": True, **entry['user_data']})

    async def api_mfa_test_smtp(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        data = await req.json()
        to_email = data.get("to_email", "").strip()
        if not to_email:
            return web.json_response({"ok": False, "error": "E-mail obrigatório"}, status=400)
        try:
            smtp_cfg = await self.db.get_all_settings()
            code = "12345678"
            await _send_mfa_email(to_email, code, smtp_cfg)
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_mfa_resend(self, req):
        data = await req.json()
        mfa_session = data.get("mfa_session", "")
        _mfa_cleanup()
        entry = _mfa_pending.get(mfa_session)
        if not entry:
            return web.json_response({"ok": False, "error": "Sessão MFA expirada. Faça login novamente."}, status=401)
        code = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
        entry['code'] = code
        entry['expires_at'] = time.time() + MFA_CODE_TTL
        user = await self.db.get_admin_user_by_id(entry['user_id'])
        if not user:
            return web.json_response({"ok": False, "error": "Usuário não encontrado."}, status=404)
        try:
            smtp_cfg = await self.db.get_all_settings()
            await _send_mfa_email(user['email'], code, smtp_cfg)
        except Exception as e:
            return web.json_response({"ok": False, "error": f"Erro ao reenviar código: {e}"}, status=500)
        return web.json_response({"ok": True})

    async def api_verify(self, req):
        auth = req.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return web.json_response({"ok": False}, status=401)
        token_data = _verify_token(auth[7:])
        if token_data:
            return web.json_response({"ok": True})
        return web.json_response({"ok": False}, status=401)

    async def api_provision_agent(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)

        data = await req.json()
        nickname        = data.get("nickname", "").strip()
        access_password = data.get("access_password", "")

        if not nickname or not access_password:
            return web.json_response(
                {"ok": False, "error": "nickname e access_password são obrigatórios"},
                status=400
            )

        binding_secret  = secrets.token_hex(32)
        password_hash   = hashlib.sha256(access_password.encode()).hexdigest()

        try:
            agent_id = await self.db.provision_agent(
                nickname=nickname,
                password_hash=password_hash,
                binding_hash="",
            )
            binding_hash = hashlib.sha256(
                (binding_secret + agent_id).encode()
            ).hexdigest()
            await self.db.update_agent_binding(agent_id, binding_hash)

        except Exception as e:
            logger.error(f"Erro ao provisionar agente: {e}")
            return web.json_response({"ok": False, "error": str(e)}, status=500)

        logger.info(f"Agente provisionado: {agent_id} ({nickname})")
        return web.json_response({
            "ok": True,
            "agent_id": agent_id,
            "binding_secret": binding_secret,
        })

    # ─── API: Perfis ───

    async def api_get_profiles(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        profiles = await self.db.get_all_profiles()
        for p in profiles:
            for k, v in p.items():
                if hasattr(v, 'isoformat'):
                    p[k] = v.isoformat()
        return web.json_response(profiles)

    async def api_create_profile(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        data = await req.json()
        name = data.get("name", "").strip()
        if not name:
            return web.json_response({"ok": False, "error": "Nome obrigatório"}, status=400)
        try:
            profile = await self.db.create_profile(name, data.get("description", ""))
            for k, v in profile.items():
                if hasattr(v, 'isoformat'):
                    profile[k] = v.isoformat()
            return web.json_response({"ok": True, "profile": profile})
        except Exception:
            return web.json_response({"ok": False, "error": "Nome já cadastrado"}, status=400)

    async def api_update_profile(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        profile_id = int(req.match_info['profile_id'])
        data = await req.json()
        kwargs = {}
        if "name" in data:
            kwargs["name"] = data["name"]
        if "description" in data:
            kwargs["description"] = data["description"]
        await self.db.update_profile(profile_id, **kwargs)
        return web.json_response({"ok": True})

    async def api_delete_profile(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        profile_id = int(req.match_info['profile_id'])
        await self.db.delete_profile(profile_id)
        return web.json_response({"ok": True})

    async def api_get_profile_permissions(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        profile_id = int(req.match_info['profile_id'])
        perms = await self.db.get_profile_permissions(profile_id)
        return web.json_response(perms)

    async def api_save_profile_permissions(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        profile_id = int(req.match_info['profile_id'])
        data = await req.json()
        permissions = data.get("permissions", [])
        await self.db.save_profile_permissions(profile_id, permissions)
        return web.json_response({"ok": True})

    async def api_get_my_permissions(self, req):
        token_data = self._require_auth(req)
        if not token_data:
            return web.json_response({}, status=401)
        perms = await self.db.get_user_permissions(token_data["user_id"])
        return web.json_response(perms)

    # ─── API: Acesso por Usuário ───

    async def api_get_user_access(self, req):
        token_data = self._require_auth(req)
        if not token_data:
            return web.json_response({"ok": False}, status=401)
        target_user_id = int(req.match_info['user_id'])
        # Admin pode ver acesso de qualquer usuário; usuário comum só o próprio
        if not _is_admin(token_data) and token_data["user_id"] != target_user_id:
            return web.json_response({"ok": False, "error": "Acesso negado"}, status=403)
        access = await self.db.get_user_access(target_user_id)
        return web.json_response(access)

    async def api_set_user_access(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        user_id = int(req.match_info['user_id'])
        data = await req.json()
        all_clients = bool(data.get("all_clients", True))
        all_groups  = bool(data.get("all_groups",  True))
        client_ids  = [int(x) for x in data.get("client_ids", [])]
        group_ids   = [int(x) for x in data.get("group_ids",  [])]
        await self.db.set_user_access(user_id, all_clients, client_ids, all_groups, group_ids)
        return web.json_response({"ok": True})

    # ─── API: Usuários Admin ───

    async def api_get_users(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        users = await self.db.get_all_admin_users_with_profile()
        for u in users:
            for k, v in u.items():
                if hasattr(v, 'isoformat'):
                    u[k] = v.isoformat()
        return web.json_response(users)

    async def api_create_user(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        data = await req.json()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        display_name = data.get("display_name", "").strip()
        role = data.get("role", "admin")
        profile_id = data.get("profile_id")
        if not email or not password:
            return web.json_response({"ok": False, "error": "E-mail e senha são obrigatórios"}, status=400)
        try:
            user = await self.db.create_admin_user(email, hash_password_bcrypt(password), display_name, role)
            if profile_id and user.get("id"):
                await self.db.update_user_profile(user["id"], int(profile_id))
            for k, v in user.items():
                if hasattr(v, 'isoformat'):
                    user[k] = v.isoformat()
            return web.json_response({"ok": True, "user": user})
        except Exception as e:
            err_str = str(e)
            logging.error("api_create_user error: %s", err_str)
            if "unique" in err_str.lower() or "duplicate" in err_str.lower():
                return web.json_response({"ok": False, "error": "E-mail já cadastrado"}, status=400)
            return web.json_response({"ok": False, "error": f"Erro ao criar usuário: {err_str}"}, status=400)

    async def api_update_user(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        user_id = int(req.match_info['user_id'])
        data = await req.json()
        kwargs = {}
        if "email" in data:
            kwargs["email"] = data["email"]
        if "password" in data and data["password"]:
            kwargs["password_hash"] = hash_password_bcrypt(data["password"])
        if "display_name" in data:
            kwargs["display_name"] = data["display_name"]
        if "role" in data:
            kwargs["role"] = data["role"]
        if "is_active" in data:
            kwargs["is_active"] = bool(data["is_active"])
        if "mfa_enabled" in data:
            kwargs["mfa_enabled"] = bool(data["mfa_enabled"])
        await self.db.update_admin_user(user_id, **kwargs)
        if "profile_id" in data:
            pid = int(data["profile_id"]) if data["profile_id"] else None
            await self.db.update_user_profile(user_id, pid)
        return web.json_response({"ok": True})

    async def api_delete_user(self, req):
        token_data = self._require_admin(req)
        if not token_data:
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        user_id = int(req.match_info['user_id'])
        # Impede deleção do próprio usuário
        if token_data["user_id"] == user_id:
            return web.json_response({"ok": False, "error": "Não é possível excluir o próprio usuário"}, status=400)
        # Protege o usuário master
        user = await self.db.get_admin_user_by_id(user_id)
        if user and user.get('email') == 'app@rochaneto.com':
            return web.json_response({"ok": False, "error": "O usuário master não pode ser removido"}, status=403)
        await self.db.delete_admin_user(user_id)
        return web.json_response({"ok": True})

    # ─── API: Dashboard ───

    async def api_stats(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        stats = await self.db.get_stats()
        return web.json_response(stats)

    async def api_agent_version(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        import re
        agent_dir = os.path.join(os.path.dirname(__file__), 'static/agent')
        versions = {}
        for key, filename in [("linux", "agent.py"), ("windows", "agent-windows.py"), ("pfsense", "agent-pfsense.py")]:
            try:
                with open(os.path.join(agent_dir, filename)) as f:
                    content = f.read(4096)
                m = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', content)
                versions[key] = m.group(1) if m else "unknown"
            except Exception:
                versions[key] = "unknown"
        versions["version"] = versions["linux"]
        return web.json_response(versions)

    async def api_agents(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        agents = await self.db.get_all_agents_safe()
        for a in agents:
            for k, v in a.items():
                if hasattr(v, 'isoformat'):
                    a[k] = v.isoformat()
        return web.json_response(agents)

    async def api_sessions(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        limit = int(req.query.get("limit", 100))
        agent_id = req.query.get("agent_id")
        sessions = await self.db.get_session_history(limit, agent_id)
        for s in sessions:
            for k, v in s.items():
                if hasattr(v, 'isoformat'):
                    s[k] = v.isoformat()
        return web.json_response(sessions)

    async def api_active_sessions(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        sessions = await self.db.get_active_sessions()
        for s in sessions:
            for k, v in s.items():
                if hasattr(v, 'isoformat'):
                    s[k] = v.isoformat()
        return web.json_response(sessions)

    async def api_audit(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        limit = int(req.query.get("limit", 200))
        logs = await self.db.get_audit_logs(limit)
        for l in logs:
            for k, v in l.items():
                if hasattr(v, 'isoformat'):
                    l[k] = v.isoformat()
        return web.json_response(logs)

    async def api_settings(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        if req.method == "GET":
            settings = await self.db.get_all_settings()
            # Não expor credenciais SMTP em claro — mascarar a senha
            if 'smtp_pass' in settings and settings['smtp_pass']:
                settings['smtp_pass'] = '********'
            return web.json_response(settings)
        elif req.method == "POST":
            data = await req.json()
            for k, v in data.items():
                # Não sobreescrever smtp_pass com o placeholder mascarado
                if k == 'smtp_pass' and v == '********':
                    continue
                await self.db.set_setting(k, str(v))
            return web.json_response({"ok": True})

    async def api_update_agent_nickname(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        agent_id = req.match_info['agent_id']
        data     = await req.json()
        nickname = data.get("nickname", "").strip()
        if not nickname:
            return web.json_response({"ok": False, "error": "Nome obrigatório"}, status=400)
        await self.db.update_agent_nickname(agent_id, nickname)
        return web.json_response({"ok": True})

    async def api_delete_agent(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        agent_id = req.match_info['agent_id']
        await self.db.delete_agent(agent_id)
        return web.json_response({"ok": True})

    # ─── API: Grupos ───

    async def api_get_groups(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        groups = await self.db.get_all_groups()
        for g in groups:
            for k, v in g.items():
                if hasattr(v, 'isoformat'):
                    g[k] = v.isoformat()
        return web.json_response(groups)

    async def api_create_group(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        data = await req.json()
        name = data.get("name", "").strip()
        if not name:
            return web.json_response({"ok": False, "error": "Nome obrigatório"}, status=400)
        try:
            cid = data.get("client_id")
            group = await self.db.create_group(
                name, data.get("description", ""), data.get("color", "#3b82f6"),
                client_id=int(cid) if cid else None,
                alert_enabled=bool(data.get("alert_enabled", False)),
                alert_message=data.get("alert_message", "")
            )
            for k, v in group.items():
                if hasattr(v, 'isoformat'):
                    group[k] = v.isoformat()
            return web.json_response({"ok": True, "group": group})
        except Exception:
            return web.json_response({"ok": False, "error": "Nome já existe"}, status=400)

    async def api_update_group(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        group_id = int(req.match_info['group_id'])
        data = await req.json()
        cid = data.get("client_id")
        alert_enabled = data.get("alert_enabled")
        await self.db.update_group(
            group_id,
            name=data.get("name"),
            description=data.get("description"),
            color=data.get("color"),
            client_id=int(cid) if cid else None,
            alert_enabled=bool(alert_enabled) if alert_enabled is not None else None,
            alert_message=data.get("alert_message")
        )
        return web.json_response({"ok": True})

    async def api_delete_group(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        group_id = int(req.match_info['group_id'])
        await self.db.delete_group(group_id)
        return web.json_response({"ok": True})

    async def api_get_client_groups(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        client_id = int(req.match_info['client_id'])
        groups = await self.db.get_client_groups(client_id)
        return web.json_response(groups)

    async def api_get_group_agents(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        group_id = int(req.match_info['group_id'])
        agents = await self.db.get_group_agents(group_id)
        return web.json_response(agents)

    async def api_get_agents_in_any_group(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        ids = await self.db.get_agents_in_any_group()
        return web.json_response(ids)

    async def api_add_agent_to_group(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        group_id = int(req.match_info['group_id'])
        data = await req.json()
        agent_id = data.get("agent_id", "").strip()
        if not agent_id:
            return web.json_response({"ok": False, "error": "agent_id obrigatório"}, status=400)
        try:
            await self.db.add_agent_to_group(group_id, agent_id)
        except Exception as e:
            if "unique" in str(e).lower() or "duplicate" in str(e).lower():
                return web.json_response({"ok": False, "error": "Esta máquina já pertence a outro grupo"}, status=400)
            raise
        return web.json_response({"ok": True})

    async def api_remove_agent_from_group(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        group_id = int(req.match_info['group_id'])
        agent_id = req.match_info['agent_id']
        await self.db.remove_agent_from_group(group_id, agent_id)
        return web.json_response({"ok": True})

    # ─── API: Clientes ───

    async def api_get_clients(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        clients = await self.db.get_all_clients()
        for c in clients:
            for k, v in c.items():
                if hasattr(v, 'isoformat'):
                    c[k] = v.isoformat()
        return web.json_response(clients)

    async def api_create_client(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        data = await req.json()
        name = data.get("name", "").strip()
        if not name:
            return web.json_response({"ok": False, "error": "Nome obrigatório"}, status=400)
        client = await self.db.create_client(
            name=name,
            document=data.get("document", ""),
            email=data.get("email", ""),
            phone=data.get("phone", ""),
            notes=data.get("notes", ""),
            alert_enabled=bool(data.get("alert_enabled", False)),
            alert_message=data.get("alert_message", ""),
        )
        for k, v in client.items():
            if hasattr(v, 'isoformat'):
                client[k] = v.isoformat()
        return web.json_response({"ok": True, "client": client})

    async def api_update_client(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        client_id = int(req.match_info['client_id'])
        data = await req.json()
        update_kwargs = dict(
            name=data.get("name"),
            document=data.get("document"),
            email=data.get("email"),
            phone=data.get("phone"),
            notes=data.get("notes"),
        )
        if "alert_enabled" in data:
            update_kwargs["alert_enabled"] = bool(data["alert_enabled"])
        if "alert_message" in data:
            update_kwargs["alert_message"] = data["alert_message"]
        await self.db.update_client(client_id, **update_kwargs)
        return web.json_response({"ok": True})

    async def api_delete_client(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        client_id = int(req.match_info['client_id'])
        await self.db.delete_client(client_id)
        return web.json_response({"ok": True})

    async def api_get_client_agents(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        client_id = int(req.match_info['client_id'])
        agents = await self.db.get_client_agents(client_id)
        return web.json_response(agents)

    async def api_get_agents_in_any_client(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        ids = await self.db.get_agents_in_any_client()
        return web.json_response(ids)

    async def api_add_agent_to_client(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        client_id = int(req.match_info['client_id'])
        data = await req.json()
        agent_id = data.get("agent_id", "").strip()
        if not agent_id:
            return web.json_response({"ok": False, "error": "agent_id obrigatório"}, status=400)
        try:
            await self.db.add_agent_to_client(client_id, agent_id)
        except Exception as e:
            if "unique" in str(e).lower() or "duplicate" in str(e).lower():
                return web.json_response({"ok": False, "error": "Esta máquina já está vinculada a outro cliente"}, status=400)
            raise
        return web.json_response({"ok": True})

    async def api_remove_agent_from_client(self, req):
        if not self._require_admin(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=403)
        client_id = int(req.match_info['client_id'])
        agent_id = req.match_info['agent_id']
        await self.db.remove_agent_from_client(client_id, agent_id)
        return web.json_response({"ok": True})

    # ─── Health ───

    async def health(self, req):
        return web.json_response({"status": "ok", "version": PROTOCOL_VERSION})


def create_app(db_dsn: str):
    panel = WebPanel(db_dsn)
    app = web.Application()

    async def on_startup(app):
        await panel.init()
    app.on_startup.append(on_startup)

    # Rotas
    app.router.add_get("/", panel.index)
    app.router.add_get("/admin", panel.admin_page)
    app.router.add_get("/health", panel.health)

    # API
    app.router.add_post("/api/login", panel.api_login)
    app.router.add_post("/api/mfa/verify", panel.api_mfa_verify)
    app.router.add_post("/api/mfa/resend", panel.api_mfa_resend)
    app.router.add_post("/api/mfa/test-smtp", panel.api_mfa_test_smtp)
    app.router.add_get("/api/verify", panel.api_verify)
    app.router.add_post("/api/agents/provision", panel.api_provision_agent)
    app.router.add_get("/api/stats", panel.api_stats)
    app.router.add_get("/api/agents", panel.api_agents)
    app.router.add_get("/api/agent/version", panel.api_agent_version)
    app.router.add_patch("/api/agents/{agent_id}/nickname", panel.api_update_agent_nickname)
    app.router.add_delete("/api/agents/{agent_id}", panel.api_delete_agent)
    app.router.add_get("/api/sessions", panel.api_sessions)
    app.router.add_get("/api/sessions/active", panel.api_active_sessions)
    app.router.add_get("/api/audit", panel.api_audit)
    app.router.add_route("*", "/api/settings", panel.api_settings)
    app.router.add_get("/api/users", panel.api_get_users)
    app.router.add_post("/api/users", panel.api_create_user)
    app.router.add_put("/api/users/{user_id}", panel.api_update_user)
    app.router.add_delete("/api/users/{user_id}", panel.api_delete_user)
    app.router.add_get("/api/users/{user_id}/access", panel.api_get_user_access)
    app.router.add_put("/api/users/{user_id}/access", panel.api_set_user_access)

    # Grupos
    app.router.add_get("/api/groups", panel.api_get_groups)
    app.router.add_post("/api/groups", panel.api_create_group)
    app.router.add_put("/api/groups/{group_id}", panel.api_update_group)
    app.router.add_delete("/api/groups/{group_id}", panel.api_delete_group)
    app.router.add_get("/api/groups/agents-allocated", panel.api_get_agents_in_any_group)
    app.router.add_get("/api/groups/{group_id}/agents", panel.api_get_group_agents)
    app.router.add_post("/api/groups/{group_id}/agents", panel.api_add_agent_to_group)
    app.router.add_delete("/api/groups/{group_id}/agents/{agent_id}", panel.api_remove_agent_from_group)

    # Clientes
    app.router.add_get("/api/clients", panel.api_get_clients)
    app.router.add_post("/api/clients", panel.api_create_client)
    app.router.add_put("/api/clients/{client_id}", panel.api_update_client)
    app.router.add_delete("/api/clients/{client_id}", panel.api_delete_client)
    app.router.add_get("/api/clients/{client_id}/groups", panel.api_get_client_groups)
    app.router.add_get("/api/clients/agents-allocated", panel.api_get_agents_in_any_client)
    app.router.add_get("/api/clients/{client_id}/agents", panel.api_get_client_agents)
    app.router.add_post("/api/clients/{client_id}/agents", panel.api_add_agent_to_client)
    app.router.add_delete("/api/clients/{client_id}/agents/{agent_id}", panel.api_remove_agent_from_client)

    # Perfis
    app.router.add_get("/api/profiles", panel.api_get_profiles)
    app.router.add_post("/api/profiles", panel.api_create_profile)
    app.router.add_put("/api/profiles/{profile_id}", panel.api_update_profile)
    app.router.add_delete("/api/profiles/{profile_id}", panel.api_delete_profile)
    app.router.add_get("/api/profiles/{profile_id}/permissions", panel.api_get_profile_permissions)
    app.router.add_put("/api/profiles/{profile_id}/permissions", panel.api_save_profile_permissions)
    app.router.add_get("/api/me/permissions", panel.api_get_my_permissions)

    # Arquivos estáticos
    app.router.add_static("/static/", STATIC_DIR, name="static")

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default=os.environ.get("DATABASE_URL", ""))
    args = parser.parse_args()

    if not args.db:
        raise RuntimeError(
            "DATABASE_URL não definida. Configure a variável de ambiente ou use --db."
        )

    app = create_app(args.db)
    logger.info(f"Web Panel em http://{args.host}:{args.port}")
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
