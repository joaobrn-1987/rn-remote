"""
RemoteLink - Web Panel + Viewer
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

from aiohttp import web

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from shared.protocol import hash_password, PROTOCOL_VERSION
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


def _generate_token(user_id: int, email: str) -> str:
    expiry = int(time.time()) + 86400  # 24 horas
    payload = f"{user_id}:{email}:{expiry}"
    sig = hmac.new(_TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _verify_token(token: str) -> bool:
    try:
        *parts, sig = token.split(":")
        payload = ":".join(parts)
        expected = hmac.new(_TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        _user_id, _email, expiry = parts[0], parts[1], parts[2]
        return time.time() < int(expiry)
    except Exception:
        return False


class WebPanel:

    def __init__(self, db_dsn: str):
        self.db = Database(db_dsn)

    async def init(self):
        await self.db.connect()

    # ─── Páginas ───

    async def index(self, req):
        return web.FileResponse(os.path.join(STATIC_DIR, "index.html"))

    async def admin_page(self, req):
        return web.FileResponse(os.path.join(STATIC_DIR, "admin.html"))

    # ─── API: Auth ───

    async def api_login(self, req):
        data = await req.json()
        user = await self.db.authenticate_admin(
            data.get("email", ""),
            hash_password(data.get("password", ""))
        )
        if user:
            token = _generate_token(user['id'], user['email'])
            return web.json_response({
                "ok": True, "token": token,
                "user": user['display_name'] or user['email'],
                "role": user['role'], "user_id": user['id']
            })
        return web.json_response({"ok": False, "error": "Credenciais inválidas"}, status=401)

    async def api_verify(self, req):
        auth = req.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return web.json_response({"ok": False}, status=401)
        if _verify_token(auth[7:]):
            return web.json_response({"ok": True})
        return web.json_response({"ok": False}, status=401)

    def _require_auth(self, req) -> bool:
        """Retorna True se o token Bearer HMAC é válido."""
        auth = req.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return _verify_token(auth[7:])

    async def api_provision_agent(self, req):
        """
        Provisiona um novo agente autenticado pelo painel.
        Retorna agent_id + binding_secret (enviado UMA única vez).
        """
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)

        data = await req.json()
        nickname        = data.get("nickname", "").strip()
        access_password = data.get("access_password", "")

        if not nickname or not access_password:
            return web.json_response(
                {"ok": False, "error": "nickname e access_password são obrigatórios"},
                status=400
            )

        # Gera binding_secret — enviado ao agente uma única vez, nunca armazenado em claro
        binding_secret  = secrets.token_hex(32)          # 64 chars hex
        password_hash   = hashlib.sha256(access_password.encode()).hexdigest()

        try:
            agent_id = await self.db.provision_agent(
                nickname=nickname,
                password_hash=password_hash,
                binding_hash="",          # será preenchido abaixo com o agent_id já gerado
            )
            # Agora que temos o agent_id, calculamos o binding_hash final
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
            "binding_secret": binding_secret,   # entregue UMA vez
        })

    # ─── API: Usuários Admin ───

    async def api_get_users(self, req):
        users = await self.db.get_all_admin_users()
        for u in users:
            for k, v in u.items():
                if hasattr(v, 'isoformat'):
                    u[k] = v.isoformat()
        return web.json_response(users)

    async def api_create_user(self, req):
        data = await req.json()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        display_name = data.get("display_name", "").strip()
        role = data.get("role", "admin")
        if not email or not password:
            return web.json_response({"ok": False, "error": "E-mail e senha são obrigatórios"}, status=400)
        try:
            user = await self.db.create_admin_user(email, hash_password(password), display_name, role)
            return web.json_response({"ok": True, "user": user})
        except Exception:
            return web.json_response({"ok": False, "error": "E-mail já cadastrado"}, status=400)

    async def api_update_user(self, req):
        user_id = int(req.match_info['user_id'])
        data = await req.json()
        kwargs = {}
        if "email" in data:
            kwargs["email"] = data["email"]
        if "password" in data and data["password"]:
            kwargs["password_hash"] = hash_password(data["password"])
        if "display_name" in data:
            kwargs["display_name"] = data["display_name"]
        if "role" in data:
            kwargs["role"] = data["role"]
        if "is_active" in data:
            kwargs["is_active"] = bool(data["is_active"])
        await self.db.update_admin_user(user_id, **kwargs)
        return web.json_response({"ok": True})

    async def api_delete_user(self, req):
        user_id = int(req.match_info['user_id'])
        await self.db.delete_admin_user(user_id)
        return web.json_response({"ok": True})

    # ─── API: Dashboard ───

    async def api_stats(self, req):
        stats = await self.db.get_stats()
        return web.json_response(stats)

    async def api_agent_version(self, req):
        """Retorna a versão de cada agente lendo diretamente dos arquivos .py."""
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
        # Mantém campo "version" (Linux) para compatibilidade
        versions["version"] = versions["linux"]
        return web.json_response(versions)

    async def api_agents(self, req):
        agents = await self.db.get_all_agents()
        for a in agents:
            for k, v in a.items():
                if hasattr(v, 'isoformat'):
                    a[k] = v.isoformat()
        return web.json_response(agents)

    async def api_sessions(self, req):
        limit = int(req.query.get("limit", 100))
        agent_id = req.query.get("agent_id")
        sessions = await self.db.get_session_history(limit, agent_id)
        for s in sessions:
            for k, v in s.items():
                if hasattr(v, 'isoformat'):
                    s[k] = v.isoformat()
        return web.json_response(sessions)

    async def api_active_sessions(self, req):
        sessions = await self.db.get_active_sessions()
        for s in sessions:
            for k, v in s.items():
                if hasattr(v, 'isoformat'):
                    s[k] = v.isoformat()
        return web.json_response(sessions)

    async def api_audit(self, req):
        limit = int(req.query.get("limit", 200))
        logs = await self.db.get_audit_logs(limit)
        for l in logs:
            for k, v in l.items():
                if hasattr(v, 'isoformat'):
                    l[k] = v.isoformat()
        return web.json_response(logs)

    async def api_settings(self, req):
        if req.method == "GET":
            settings = await self.db.get_all_settings()
            return web.json_response(settings)
        elif req.method == "POST":
            data = await req.json()
            for k, v in data.items():
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
        agent_id = req.match_info['agent_id']
        await self.db.delete_agent(agent_id)
        return web.json_response({"ok": True})

    # ─── API: Grupos ───

    async def api_get_groups(self, req):
        groups = await self.db.get_all_groups()
        for g in groups:
            for k, v in g.items():
                if hasattr(v, 'isoformat'):
                    g[k] = v.isoformat()
        return web.json_response(groups)

    async def api_create_group(self, req):
        data = await req.json()
        name = data.get("name", "").strip()
        if not name:
            return web.json_response({"ok": False, "error": "Nome obrigatório"}, status=400)
        try:
            group = await self.db.create_group(
                name, data.get("description", ""), data.get("color", "#3b82f6")
            )
            for k, v in group.items():
                if hasattr(v, 'isoformat'):
                    group[k] = v.isoformat()
            return web.json_response({"ok": True, "group": group})
        except Exception:
            return web.json_response({"ok": False, "error": "Nome já existe"}, status=400)

    async def api_update_group(self, req):
        group_id = int(req.match_info['group_id'])
        data = await req.json()
        await self.db.update_group(
            group_id,
            name=data.get("name"),
            description=data.get("description"),
            color=data.get("color")
        )
        return web.json_response({"ok": True})

    async def api_delete_group(self, req):
        group_id = int(req.match_info['group_id'])
        await self.db.delete_group(group_id)
        return web.json_response({"ok": True})

    async def api_get_group_agents(self, req):
        group_id = int(req.match_info['group_id'])
        agents = await self.db.get_group_agents(group_id)
        return web.json_response(agents)

    async def api_add_agent_to_group(self, req):
        group_id = int(req.match_info['group_id'])
        data = await req.json()
        agent_id = data.get("agent_id", "").strip()
        if not agent_id:
            return web.json_response({"ok": False, "error": "agent_id obrigatório"}, status=400)
        await self.db.add_agent_to_group(group_id, agent_id)
        return web.json_response({"ok": True})

    async def api_remove_agent_from_group(self, req):
        group_id = int(req.match_info['group_id'])
        agent_id = req.match_info['agent_id']
        await self.db.remove_agent_from_group(group_id, agent_id)
        return web.json_response({"ok": True})

    # ─── API: Clientes ───

    async def api_get_clients(self, req):
        clients = await self.db.get_all_clients()
        for c in clients:
            for k, v in c.items():
                if hasattr(v, 'isoformat'):
                    c[k] = v.isoformat()
        return web.json_response(clients)

    async def api_create_client(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
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
        )
        for k, v in client.items():
            if hasattr(v, 'isoformat'):
                client[k] = v.isoformat()
        return web.json_response({"ok": True, "client": client})

    async def api_update_client(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        client_id = int(req.match_info['client_id'])
        data = await req.json()
        await self.db.update_client(
            client_id,
            name=data.get("name"),
            document=data.get("document"),
            email=data.get("email"),
            phone=data.get("phone"),
            notes=data.get("notes"),
        )
        return web.json_response({"ok": True})

    async def api_delete_client(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        client_id = int(req.match_info['client_id'])
        await self.db.delete_client(client_id)
        return web.json_response({"ok": True})

    async def api_get_client_agents(self, req):
        client_id = int(req.match_info['client_id'])
        agents = await self.db.get_client_agents(client_id)
        return web.json_response(agents)

    async def api_add_agent_to_client(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
        client_id = int(req.match_info['client_id'])
        data = await req.json()
        agent_id = data.get("agent_id", "").strip()
        if not agent_id:
            return web.json_response({"ok": False, "error": "agent_id obrigatório"}, status=400)
        await self.db.add_agent_to_client(client_id, agent_id)
        return web.json_response({"ok": True})

    async def api_remove_agent_from_client(self, req):
        if not self._require_auth(req):
            return web.json_response({"ok": False, "error": "Não autorizado"}, status=401)
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

    # Startup
    async def on_startup(app):
        await panel.init()
    app.on_startup.append(on_startup)

    # Rotas
    app.router.add_get("/", panel.index)
    app.router.add_get("/admin", panel.admin_page)
    app.router.add_get("/health", panel.health)

    # API
    app.router.add_post("/api/login", panel.api_login)
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

    # Grupos
    app.router.add_get("/api/groups", panel.api_get_groups)
    app.router.add_post("/api/groups", panel.api_create_group)
    app.router.add_put("/api/groups/{group_id}", panel.api_update_group)
    app.router.add_delete("/api/groups/{group_id}", panel.api_delete_group)
    app.router.add_get("/api/groups/{group_id}/agents", panel.api_get_group_agents)
    app.router.add_post("/api/groups/{group_id}/agents", panel.api_add_agent_to_group)
    app.router.add_delete("/api/groups/{group_id}/agents/{agent_id}", panel.api_remove_agent_from_group)

    # Clientes
    app.router.add_get("/api/clients", panel.api_get_clients)
    app.router.add_post("/api/clients", panel.api_create_client)
    app.router.add_put("/api/clients/{client_id}", panel.api_update_client)
    app.router.add_delete("/api/clients/{client_id}", panel.api_delete_client)
    app.router.add_get("/api/clients/{client_id}/agents", panel.api_get_client_agents)
    app.router.add_post("/api/clients/{client_id}/agents", panel.api_add_agent_to_client)
    app.router.add_delete("/api/clients/{client_id}/agents/{agent_id}", panel.api_remove_agent_from_client)

    # Arquivos estáticos
    app.router.add_static("/static/", STATIC_DIR, name="static")

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default=os.environ.get(
        "DATABASE_URL",
        "postgresql://remotelink:RemoteLink2024@localhost:5432/remotelink"
    ))
    args = parser.parse_args()

    app = create_app(args.db)
    logger.info(f"Web Panel em http://{args.host}:{args.port}")
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
