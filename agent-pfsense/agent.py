#!/usr/bin/env python3
"""
RNRemote - Agente pfSense (FreeBSD)
Roda no pfSense e conecta ao relay para acesso via terminal no browser.

Pré-requisitos no pfSense:
    pkg install python3 py311-pip
    pip install websockets

Uso:
    python3 agent.py --relay wss://rnremote.joaoneto.tec.br/ws --id 123456789 --password suasenha
    python3 agent.py --config /usr/local/etc/rnremote/agent.json
"""

import asyncio
import json
import os
import time
import logging
import signal
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
import subprocess
import urllib.request

AGENT_VERSION = "1.0.0"

import websockets

PROTOCOL_VERSION = "1.0.0"
HEARTBEAT_INTERVAL = 15

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("agent-pfsense")


# ─── Helpers ───────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def compute_binding_token(binding_secret: str, agent_id: str) -> str:
    return hashlib.sha256(f"{binding_secret}{agent_id}".encode()).hexdigest()


def get_system_info() -> dict:
    uname = platform.uname()
    return {
        "hostname": socket.gethostname(),
        "os_type": "FreeBSD",
        "os_version": f"{uname.system} {uname.release}",
        "username": os.environ.get("USER", os.environ.get("LOGNAME", "unknown")),
        "screen_width": 0,
        "screen_height": 0,
    }


# ─── Shell via PTY ─────────────────────────────────────────────────────────────

def _find_shell() -> str:
    """Retorna o melhor shell disponível no pfSense."""
    for sh in ("/usr/local/bin/bash", "/bin/sh"):
        if os.path.isfile(sh):
            return sh
    return "/bin/sh"


class ShellSession:
    """Gerencia um processo de shell interativo via pseudo-terminal (PTY)."""

    def __init__(self):
        self.master_fd: int | None = None
        self.pid: int | None = None
        self.running: bool = False

    def start(self, cols: int = 120, rows: int = 30):
        import pty as _pty
        self.master_fd, slave_fd = os.openpty()
        self._set_winsize(slave_fd, cols, rows)

        self.pid = os.fork()

        if self.pid == 0:
            os.close(self.master_fd)
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            if slave_fd > 2:
                os.close(slave_fd)
            shell = _find_shell()
            os.execv(shell, [shell, "-l"])
            sys.exit(1)

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

class PfSenseAgent:

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
        self._uploads: dict = {}

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
                self.session_id = None

            if self._running:
                logger.info(f"Reconectando em {self.reconnect_delay}s...")
                await asyncio.sleep(self.reconnect_delay)

    # ── Registro ───────────────────────────────────────────────────────────────

    async def _register(self):
        info = get_system_info()
        await self._send({
            "type": "register_agent",
            "data": {
                "agent_id":      self.agent_id,
                "password_hash": self.password_hash,
                "binding_token": self.binding_token,
                "version":       AGENT_VERSION,
                **info,
            },
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
            if not self.shell or not self.shell.running:
                await self._start_shell(
                    cols=data.get("cols", 120),
                    rows=data.get("rows", 30),
                )

        elif t == "shell_input":
            raw = data.get("input", "")
            if raw and self.shell and self.shell.running:
                self.shell.write(raw)

        elif t == "shell_command":
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

        elif t == "update_agent":
            await self._handle_update(data)

        elif t == "pong":
            pass

    # ── Auto-atualização ────────────────────────────────────────────────────────

    async def _handle_update(self, data: dict):
        panel_url = data.get("panel_url", "https://rnremote.joaoneto.tec.br").rstrip("/")
        url        = f"{panel_url}/static/agent/agent-pfsense.py"
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

            self._running = False
            if self.ws:
                try:
                    await self.ws.close()
                except Exception:
                    pass

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
                    await asyncio.sleep(0)
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

        # OS via freebsd-version
        try:
            result = subprocess.run(["freebsd-version"], capture_output=True, text=True, timeout=5)
            fbsd_ver = result.stdout.strip()
            info["os_pretty"]  = f"pfSense / FreeBSD {fbsd_ver}"
            info["os_name"]    = "FreeBSD"
            info["os_version"] = fbsd_ver
            info["os_id"]      = "freebsd"
        except Exception:
            info["os_pretty"] = f"{uname.system} {uname.release}"

        # RAM via sysctl
        try:
            def _sysctl_int(name: str) -> int:
                r = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True, timeout=5)
                return int(r.stdout.strip())

            total_bytes = _sysctl_int("hw.physmem")
            # Memória livre: hw.usermem é uma aproximação razoável
            free_bytes  = _sysctl_int("hw.usermem")
            used_bytes  = total_bytes - free_bytes
            info["ram_total_mb"] = round(total_bytes / 1048576)
            info["ram_used_mb"]  = round(used_bytes  / 1048576)
            info["ram_percent"]  = round(used_bytes / total_bytes * 100, 1) if total_bytes else 0
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

        # Uptime via sysctl kern.boottime
        try:
            r = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=5)
            # Saída: { sec = 1700000000, usec = 0 } Thu Nov 14 ...
            import re
            m = re.search(r'sec\s*=\s*(\d+)', r.stdout)
            if m:
                boot_sec = int(m.group(1))
                secs = int(time.time()) - boot_sec
                days, rem = divmod(secs, 86400)
                hours, rem = divmod(rem, 3600)
                mins = rem // 60
                info["uptime"] = (f"{days}d " if days else "") + f"{hours:02d}:{mins:02d}"
        except Exception:
            pass

        await self._send({"type": "system_info", "data": info,
                           "session_id": self.session_id, "timestamp": time.time()})

    # ── Shell ──────────────────────────────────────────────────────────────────

    async def _start_shell(self, cols: int, rows: int):
        self._stop_shell()
        self.shell = ShellSession()
        self.shell.start(cols=cols, rows=rows)
        self._shell_reader_task = asyncio.create_task(self._read_shell_output())

    async def _read_shell_output(self):
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
        description="RNRemote - Agente pfSense",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 agent.py --relay wss://rnremote.joaoneto.tec.br/ws --id 123456789 --password minhasenha
  python3 agent.py --config /usr/local/etc/rnremote/agent.json

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
    parser.add_argument("--config",   default="/usr/local/etc/rnremote/agent.json",
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
        sys.exit(1)

    agent = PfSenseAgent(
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
