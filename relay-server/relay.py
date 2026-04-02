"""
RNRemote - Relay Server com PostgreSQL
"""

import asyncio
import json
import logging
import time
import argparse
import os
import sys
import hashlib
import hmac as _hmac
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

import websockets
from websockets.server import serve

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from shared.protocol import (
    MessageType, Message, parse_message, create_message,
    generate_session_id, hash_password,
    HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT, PROTOCOL_VERSION
)
from shared.database import Database

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("relay")


# ─── Verificação de token (mesma lógica de server.py) ───

_TOKEN_SECRET_FILE = "/etc/rnremote/token_secret"

def _load_token_secret() -> str:
    try:
        with open(_TOKEN_SECRET_FILE) as f:
            s = f.read().strip()
            if s:
                return s
    except FileNotFoundError:
        pass
    logger.warning(f"Token secret não encontrado em {_TOKEN_SECRET_FILE}")
    return ""

_TOKEN_SECRET = _load_token_secret()


def _verify_viewer_token(token: str) -> Optional[dict]:
    """Verifica token Bearer do viewer. Retorna {user_id, email, role} ou None."""
    if not _TOKEN_SECRET:
        return None
    try:
        parts = token.split(":")
        if len(parts) == 5:
            user_id_s, email, role, expiry_s, sig = parts
            payload = f"{user_id_s}:{email}:{role}:{expiry_s}"
        elif len(parts) == 4:
            user_id_s, email, expiry_s, sig = parts
            role = ""
            payload = f"{user_id_s}:{email}:{expiry_s}"
        else:
            return None
        expected = _hmac.new(_TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, expected):
            return None
        if time.time() >= int(expiry_s):
            return None
        return {"user_id": int(user_id_s), "email": email, "role": role}
    except Exception:
        return None


# ─── Estruturas em memória (para performance do relay em tempo real) ───

@dataclass
class LiveAgent:
    agent_id: str
    websocket: any
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    username: str = ""
    ip_address: str = ""
    password_hash: str = ""
    last_heartbeat: float = field(default_factory=time.time)
    active_sessions: Set[str] = field(default_factory=set)
    screen_width: int = 0
    screen_height: int = 0
    version: str = ""
    ad_agent: bool = False
    ad_version: str = ""


@dataclass
class LiveViewer:
    viewer_id: str
    websocket: any
    ip_address: str = ""
    viewer_name: str = ""
    user_id: int = 0
    role: str = ""
    last_heartbeat: float = field(default_factory=time.time)
    active_sessions: Set[str] = field(default_factory=set)


@dataclass
class LiveSession:
    session_id: str
    agent_id: str
    viewer_id: str
    created_at: float = field(default_factory=time.time)
    bytes_transferred: int = 0


class RelayServer:

    def __init__(self, host: str, port: int, db_dsn: str):
        self.host = host
        self.port = port
        self.db = Database(db_dsn)

        # Estado em memória (rápido para relay real-time)
        self.agents: Dict[str, LiveAgent] = {}
        self.viewers: Dict[str, LiveViewer] = {}
        self.sessions: Dict[str, LiveSession] = {}
        self.ws_to_agent: Dict[any, str] = {}
        self.ws_to_viewer: Dict[any, str] = {}

        self.start_time = time.time()

    async def init_db(self):
        """Conecta ao banco e limpa estados stale."""
        await self.db.connect()
        await self.db.set_all_agents_offline()
        await self.db.end_all_active_sessions()
        logger.info("Banco inicializado, estados stale limpos")

    async def handle_connection(self, websocket):
        remote = websocket.remote_address
        ip = remote[0] if remote else ""
        logger.info(f"Nova conexão: {ip}")

        try:
            async for raw in websocket:
                try:
                    msg = parse_message(raw)
                    await self.route(websocket, msg, ip)
                except json.JSONDecodeError:
                    await self._send_error(websocket, "JSON inválido")
                except Exception as e:
                    logger.error(f"Erro: {e}")
        except websockets.ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"Erro conexão: {e}")
        finally:
            await self.handle_disconnect(websocket)

    async def route(self, ws, msg: Message, ip: str):
        t = msg.type
        # Registro
        if t == MessageType.REGISTER_AGENT.value:
            await self.on_register_agent(ws, msg, ip)
        elif t == MessageType.REGISTER_VIEWER.value:
            await self.on_register_viewer(ws, msg, ip)
        elif t == MessageType.AGENT_LIST.value:
            await self.send_agent_list(ws)
        elif t == MessageType.CONNECT_REQUEST.value:
            await self.on_connect_request(ws, msg, ip)
        elif t == MessageType.DISCONNECT.value:
            sid = msg.session_id or msg.data.get("session_id")
            if sid:
                await self.close_session(sid)
        elif t == MessageType.PING.value:
            await self.on_ping(ws)
        elif t == "update_agent":
            await self.on_update_agent(ws, msg)
        # Relay: agent -> viewer
        elif t in (MessageType.SCREEN_FRAME.value,
                   MessageType.SHELL_OUTPUT.value,
                   MessageType.FILE_LIST_RESPONSE.value,
                   MessageType.SYSTEM_INFO.value,
                   MessageType.CONSOLE_FRAME.value,
                   "browser_frame",
                   "browser_html",
                   "browser_status",
                   "ad_response",
                   "ad_event"):
            await self.relay_to_viewer(ws, msg)
        # Relay: viewer -> agent
        elif t in (MessageType.SCREEN_REQUEST.value,
                   MessageType.SCREEN_CONFIG.value,
                   MessageType.MOUSE_EVENT.value,
                   MessageType.KEYBOARD_EVENT.value,
                   MessageType.SHELL_START.value,
                   MessageType.SHELL_COMMAND.value,
                   MessageType.SHELL_INPUT.value,
                   MessageType.SHELL_RESIZE.value,
                   MessageType.FILE_LIST_REQUEST.value,
                   MessageType.FILE_DOWNLOAD_REQUEST.value,
                   MessageType.FILE_UPLOAD_START.value,
                   MessageType.SYSTEM_INFO_REQUEST.value,
                   MessageType.CONSOLE_START.value,
                   MessageType.CONSOLE_INPUT.value,
                   MessageType.CONSOLE_STOP.value,
                   "browser_start",
                   "browser_navigate",
                   "browser_input",
                   "browser_scroll",
                   "browser_resize",
                   "browser_stop",
                   "ad_request"):
            await self.relay_to_agent(ws, msg)
        # Relay: ambos
        elif t in (MessageType.SHELL_STOP.value,
                   MessageType.FILE_COMPLETE.value,
                   MessageType.FILE_ERROR.value):
            await self.relay_to_both(ws, msg)
        # File chunk: bidirecional
        elif t == MessageType.FILE_CHUNK.value:
            await self.relay_file_chunk(ws, msg)

    # ─── Registro ───

    async def on_register_agent(self, ws, msg, ip):
        data = msg.data
        agent_id = data.get("agent_id")
        if not agent_id:
            return await self._send_error(ws, "agent_id obrigatório")

        # ── Verificação de binding: garante que somente a máquina original se conecte ──
        existing = await self.db.get_agent(agent_id)
        if existing and existing.get("binding_hash"):
            # O agente envia binding_token = sha256(binding_secret + agent_id)
            binding_token = data.get("binding_token", "")
            if binding_token != existing["binding_hash"]:
                logger.warning(f"Binding inválido para agente {agent_id} [{ip}]")
                await self._send(ws, create_message(MessageType.AUTH_FAILURE,
                    data={"reason": "Binding inválido: este ID pertence a outra máquina"}))
                return

        # Desconectar instância antiga se existir
        if agent_id in self.agents:
            try:
                await self.agents[agent_id].websocket.close()
            except:
                pass

        pw_hash = data.get("password_hash", "")

        # Salvar no banco
        await self.db.register_agent(
            agent_id=agent_id, password_hash=pw_hash,
            hostname=data.get("hostname", ""),
            os_type=data.get("os_type", ""),
            os_version=data.get("os_version", ""),
            username=data.get("username", ""),
            ip_address=ip,
            screen_width=data.get("screen_width", 0),
            screen_height=data.get("screen_height", 0),
        )

        # Log de auditoria
        await self.db.log_event("agent_connected", agent_id=agent_id,
                                ip_address=ip,
                                details={"hostname": data.get("hostname"),
                                         "os_type": data.get("os_type")})

        # Registrar em memória
        agent = LiveAgent(
            agent_id=agent_id, websocket=ws,
            hostname=data.get("hostname", ""),
            os_type=data.get("os_type", ""),
            os_version=data.get("os_version", ""),
            username=data.get("username", ""),
            ip_address=ip, password_hash=pw_hash,
            screen_width=data.get("screen_width", 0),
            screen_height=data.get("screen_height", 0),
            version=data.get("version", ""),
            ad_agent=data.get("ad_agent", False),
            ad_version=data.get("ad_version", ""),
        )
        self.agents[agent_id] = agent
        self.ws_to_agent[ws] = agent_id

        await self._send(ws, create_message(MessageType.AUTH_SUCCESS,
            data={"agent_id": agent_id, "server_version": PROTOCOL_VERSION}))

        logger.info(f"Agente registrado: {agent_id} ({agent.hostname}/{agent.os_type}) [{ip}]")
        await self.broadcast_agent_list()

    async def on_register_viewer(self, ws, msg, ip):
        # Verificar token de autenticação
        auth_token = msg.data.get("auth_token", "")
        token_data = _verify_viewer_token(auth_token)
        if not token_data:
            logger.warning(f"Viewer rejeitado (token inválido/ausente): {ip}")
            await self._send(ws, create_message(MessageType.AUTH_FAILURE,
                data={"reason": "Token inválido ou expirado. Faça login no painel."}))
            return

        viewer_id = msg.data.get("viewer_id", generate_session_id())
        viewer_name = msg.data.get("viewer_name", token_data.get("email", ""))
        viewer = LiveViewer(
            viewer_id=viewer_id, websocket=ws, ip_address=ip,
            viewer_name=viewer_name,
            user_id=token_data["user_id"],
            role=token_data["role"],
        )
        self.viewers[viewer_id] = viewer
        self.ws_to_viewer[ws] = viewer_id

        await self._send(ws, create_message(MessageType.AUTH_SUCCESS,
            data={"viewer_id": viewer_id, "server_version": PROTOCOL_VERSION}))

        logger.info(f"Viewer registrado: {viewer_id[:12]} user={token_data['email']} [{ip}]")
        await self.send_agent_list(ws)

    # ─── Lista de Agentes ───

    async def send_agent_list(self, ws):
        agents = [{
            "agent_id": a.agent_id, "hostname": a.hostname,
            "os_type": a.os_type, "os_version": a.os_version,
            "username": a.username, "ip_address": a.ip_address,
            "has_password": bool(a.password_hash),
            "screen_width": a.screen_width, "screen_height": a.screen_height,
            "active_sessions": len(a.active_sessions),
            "is_online": True,
            "version": a.version,
            "ad_agent": a.ad_agent,
            "ad_version": a.ad_version,
        } for a in self.agents.values()]
        await self._send(ws, create_message(MessageType.AGENT_LIST,
            data={"agents": agents}))

    async def on_update_agent(self, ws, msg: Message):
        """Repassa comando de atualização do viewer para o agente alvo."""
        agent_id = msg.data.get("agent_id")
        if not agent_id or agent_id not in self.agents:
            return
        try:
            await self._send(self.agents[agent_id].websocket, msg.to_json())
            logger.info(f"Comando update_agent enviado para {agent_id}")
        except Exception as e:
            logger.error(f"Falha ao enviar update_agent: {e}")

    async def broadcast_agent_list(self):
        for v in self.viewers.values():
            try:
                await self.send_agent_list(v.websocket)
            except:
                pass

    # ─── Conexão de Sessão ───

    async def on_connect_request(self, ws, msg, ip):
        data = msg.data
        agent_id = data.get("agent_id")
        password = data.get("password", "")
        viewer_id = self.ws_to_viewer.get(ws)

        if not viewer_id:
            return await self._send_error(ws, "Viewer não registrado")

        agent = self.agents.get(agent_id)
        if not agent:
            await self.db.log_event("connect_failed", agent_id=agent_id,
                                    viewer_id=viewer_id, ip_address=ip,
                                    details={"reason": "agent_offline"})
            return await self._send(ws, create_message(MessageType.CONNECT_REJECT,
                data={"reason": "Agente não encontrado ou offline"}))

        if agent.password_hash and hash_password(password) != agent.password_hash:
            await self.db.log_event("connect_failed", agent_id=agent_id,
                                    viewer_id=viewer_id, ip_address=ip,
                                    details={"reason": "wrong_password"})
            return await self._send(ws, create_message(MessageType.CONNECT_REJECT,
                data={"reason": "Senha incorreta"}))

        # Criar sessão
        session_id = generate_session_id()
        session = LiveSession(session_id=session_id, agent_id=agent_id,
                              viewer_id=viewer_id)
        self.sessions[session_id] = session
        agent.active_sessions.add(session_id)
        self.viewers[viewer_id].active_sessions.add(session_id)

        # Persistir no banco
        vname = self.viewers[viewer_id].viewer_name if viewer_id in self.viewers else ""
        await self.db.create_session(session_id, agent_id, viewer_id, ip, viewer_name=vname)
        await self.db.log_event("session_started", agent_id=agent_id,
                                viewer_id=viewer_id, session_id=session_id,
                                ip_address=ip)

        connect_data = {
            "session_id": session_id, "agent_id": agent_id,
            "viewer_id": viewer_id, "hostname": agent.hostname,
            "os_type": agent.os_type, "screen_width": agent.screen_width,
            "screen_height": agent.screen_height,
        }
        await self._send(ws, create_message(MessageType.CONNECT_ACCEPT, data=connect_data))
        await self._send(agent.websocket, create_message(MessageType.CONNECT_ACCEPT, data=connect_data))

        logger.info(f"Sessão: {session_id[:12]} | Viewer {viewer_id[:12]} -> Agent {agent_id}")

    # ─── Relay ───

    async def relay_to_agent(self, ws, msg):
        """Relay viewer → agente. Verifica que o remetente é o viewer legítimo da sessão."""
        s = self.sessions.get(msg.session_id)
        if not s:
            return
        # Verificar ownership: apenas o viewer desta sessão pode enviar
        sender_viewer_id = self.ws_to_viewer.get(ws)
        if sender_viewer_id != s.viewer_id:
            logger.warning(
                f"relay_to_agent bloqueado: ws não é viewer da sessão {msg.session_id[:8]} "
                f"(sender={sender_viewer_id}, owner={s.viewer_id})"
            )
            return
        a = self.agents.get(s.agent_id)
        if a:
            await self._send(a.websocket, msg.to_json())

    async def relay_to_viewer(self, ws, msg):
        """Relay agente → viewer. Verifica que o remetente é o agente legítimo da sessão."""
        s = self.sessions.get(msg.session_id)
        if not s:
            return
        # Verificar ownership: apenas o agente desta sessão pode enviar
        sender_agent_id = self.ws_to_agent.get(ws)
        if sender_agent_id != s.agent_id:
            logger.warning(
                f"relay_to_viewer bloqueado: ws não é agente da sessão {msg.session_id[:8]} "
                f"(sender={sender_agent_id}, owner={s.agent_id})"
            )
            return
        v = self.viewers.get(s.viewer_id)
        if v:
            s.bytes_transferred += len(msg.to_json())
            await self._send(v.websocket, msg.to_json())

    async def relay_to_both(self, ws, msg):
        """Relay bidirecional. Verifica ownership antes de encaminhar."""
        s = self.sessions.get(msg.session_id)
        if not s:
            return
        is_agent  = self.ws_to_agent.get(ws) == s.agent_id
        is_viewer = self.ws_to_viewer.get(ws) == s.viewer_id
        if not is_agent and not is_viewer:
            logger.warning(f"relay_to_both bloqueado: ws não pertence à sessão {msg.session_id[:8]}")
            return
        a = self.agents.get(s.agent_id)
        v = self.viewers.get(s.viewer_id)
        if a and a.websocket != ws:
            await self._send(a.websocket, msg.to_json())
        if v and v.websocket != ws:
            await self._send(v.websocket, msg.to_json())

    async def relay_file_chunk(self, ws, msg):
        """Relay de chunks de arquivo com verificação de ownership."""
        s = self.sessions.get(msg.session_id)
        if not s:
            return
        sender_agent_id  = self.ws_to_agent.get(ws)
        sender_viewer_id = self.ws_to_viewer.get(ws)
        if sender_agent_id == s.agent_id:
            v = self.viewers.get(s.viewer_id)
            if v:
                s.bytes_transferred += len(msg.data.get("chunk", ""))
                await self._send(v.websocket, msg.to_json())
        elif sender_viewer_id == s.viewer_id:
            a = self.agents.get(s.agent_id)
            if a:
                await self._send(a.websocket, msg.to_json())
        else:
            logger.warning(f"relay_file_chunk bloqueado: ws não pertence à sessão {msg.session_id[:8]}")

    # ─── Heartbeat ───

    async def on_ping(self, ws):
        aid = self.ws_to_agent.get(ws)
        if aid and aid in self.agents:
            self.agents[aid].last_heartbeat = time.time()
        vid = self.ws_to_viewer.get(ws)
        if vid and vid in self.viewers:
            self.viewers[vid].last_heartbeat = time.time()
        await self._send(ws, create_message(MessageType.PONG))

    async def heartbeat_monitor(self):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            now = time.time()

            for aid in [a for a, ag in self.agents.items()
                        if now - ag.last_heartbeat > HEARTBEAT_TIMEOUT]:
                logger.warning(f"Timeout agente: {aid}")
                try:
                    await self.agents[aid].websocket.close()
                except:
                    pass
                await self.cleanup_agent(aid)

            for vid in [v for v, vw in self.viewers.items()
                        if now - vw.last_heartbeat > HEARTBEAT_TIMEOUT]:
                try:
                    await self.viewers[vid].websocket.close()
                except:
                    pass
                await self.cleanup_viewer(vid)

    # ─── Desconexão ───

    async def handle_disconnect(self, ws):
        aid = self.ws_to_agent.pop(ws, None)
        if aid:
            await self.cleanup_agent(aid)
            await self.broadcast_agent_list()
        vid = self.ws_to_viewer.pop(ws, None)
        if vid:
            await self.cleanup_viewer(vid)

    async def cleanup_agent(self, agent_id):
        agent = self.agents.pop(agent_id, None)
        if agent:
            for sid in list(agent.active_sessions):
                await self.close_session(sid)
            await self.db.set_agent_offline(agent_id)
            await self.db.log_event("agent_disconnected", agent_id=agent_id)
            logger.info(f"Agente removido: {agent_id}")

    async def cleanup_viewer(self, viewer_id):
        viewer = self.viewers.pop(viewer_id, None)
        if viewer:
            for sid in list(viewer.active_sessions):
                await self.close_session(sid)

    async def close_session(self, session_id):
        session = self.sessions.pop(session_id, None)
        if not session:
            return

        agent = self.agents.get(session.agent_id)
        if agent:
            agent.active_sessions.discard(session_id)
        viewer = self.viewers.get(session.viewer_id)
        if viewer:
            viewer.active_sessions.discard(session_id)

        # Persistir encerramento
        await self.db.end_session(session_id, session.bytes_transferred)
        await self.db.log_event("session_ended", agent_id=session.agent_id,
                                session_id=session_id,
                                details={"bytes": session.bytes_transferred})

        disc = create_message(MessageType.DISCONNECT,
            data={"session_id": session_id}, session_id=session_id)
        if agent:
            try: await self._send(agent.websocket, disc)
            except: pass
        if viewer:
            try: await self._send(viewer.websocket, disc)
            except: pass

        logger.info(f"Sessão encerrada: {session_id[:12]}")

    # ─── Helpers ───

    async def _send(self, ws, message):
        try:
            await ws.send(message if isinstance(message, str) else str(message))
        except:
            pass

    async def _send_error(self, ws, msg):
        await self._send(ws, create_message(MessageType.ERROR, data={"message": msg}))

    # ─── Start ───

    async def start(self):
        await self.init_db()

        logger.info(f"{'='*55}")
        logger.info(f"  RNRemote Relay v{PROTOCOL_VERSION}")
        logger.info(f"  ws://{self.host}:{self.port}")
        logger.info(f"  PostgreSQL conectado")
        logger.info(f"{'='*55}")

        asyncio.create_task(self.heartbeat_monitor())

        async with serve(
            self.handle_connection, self.host, self.port,
            max_size=10 * 1024 * 1024,
            ping_interval=10, ping_timeout=20,
            compression="deflate"
        ):
            await asyncio.Future()


def main():
    parser = argparse.ArgumentParser(description="RNRemote Relay")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default=os.environ.get("DATABASE_URL", ""))
    args = parser.parse_args()

    if not args.db:
        raise RuntimeError("DATABASE_URL não definida. Configure a variável de ambiente.")
    server = RelayServer(host=args.host, port=args.port, db_dsn=args.db)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("Encerrado.")


if __name__ == "__main__":
    main()
