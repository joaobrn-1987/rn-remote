#!/usr/bin/env python3
"""
RNRemote - Agente Windows
Conecta ao relay para acesso via terminal no browser.
Roda como Serviço Windows e exibe ícone na bandeja do sistema.

Dependências:
    pip install websockets pystray pillow pywinpty pywin32

Uso interativo (com bandeja):
    python agent-windows.py --config C:\ProgramData\RNRemote\agent.json

Gerenciar serviço Windows:
    python agent-windows.py install   -- instala o serviço
    python agent-windows.py start     -- inicia o serviço
    python agent-windows.py stop      -- para o serviço
    python agent-windows.py remove    -- remove o serviço

Bandeja do sistema (monitora o serviço):
    python agent-windows.py --tray
"""

import asyncio
import base64
import ctypes
import hashlib
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

AGENT_VERSION = "1.0.0"

# ─── Dependências obrigatórias ──────────────────────────────────────────────────

try:
    import websockets
except ImportError:
    ctypes.windll.user32.MessageBoxW(
        0,
        "Módulo 'websockets' não encontrado.\nExecute: pip install websockets",
        "RNRemote Agent — Erro", 0x10,
    )
    sys.exit(1)

# ─── Dependências opcionais ─────────────────────────────────────────────────────

try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

try:
    import mss as _mss
    from PIL import Image as _PILImage
    import io as _io
    HAS_SCREEN = True
except ImportError:
    HAS_SCREEN = False

try:
    from pynput.mouse import Button as _MBtn, Controller as _MouseCtrl
    from pynput.keyboard import Key as _Key, Controller as _KbCtrl, KeyCode as _KeyCode
    HAS_INPUT = True
except ImportError:
    HAS_INPUT = False

try:
    import winpty
    HAS_WINPTY = True
except ImportError:
    HAS_WINPTY = False

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_WIN32SERVICE = True
except ImportError:
    HAS_WIN32SERVICE = False

# ─── Constantes ─────────────────────────────────────────────────────────────────

PROTOCOL_VERSION    = "1.0.0"
HEARTBEAT_INTERVAL  = 8
PANEL_URL           = "https://rnremote.joaoneto.tec.br"
RELAY_URL_DEFAULT   = "wss://rnremote.joaoneto.tec.br/ws"
CONFIG_PATH_DEFAULT = str(
    Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "RNRemote" / "agent.json"
)
LOG_PATH = str(
    Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "RNRemote" / "agent.log"
)
SVC_NAME         = "RNRemoteAgent"
SVC_DISPLAY_NAME = "RNRemote Agent"
SVC_DESCRIPTION  = "RNRemote - Agente de acesso remoto via browser"

# ─── Logging ─────────────────────────────────────────────────────────────────────

def _setup_logging(to_file: bool = False):
    handlers = [logging.StreamHandler(sys.stdout)]
    if to_file:
        try:
            os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
            handlers.append(logging.FileHandler(LOG_PATH, encoding="utf-8"))
        except Exception:
            pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
        force=True,
    )

logger = logging.getLogger("rnremote-win")

# ─── Mapeamento de teclas (web → pynput) ───────────────────────────────────────

def _build_key_map() -> dict:
    if not HAS_INPUT:
        return {}
    return {
        'Enter': _Key.enter, 'Return': _Key.enter,
        'Escape': _Key.esc, 'Tab': _Key.tab,
        'Backspace': _Key.backspace, 'Delete': _Key.delete,
        'Insert': _Key.insert, 'Home': _Key.home, 'End': _Key.end,
        'PageUp': _Key.page_up, 'PageDown': _Key.page_down,
        'ArrowLeft': _Key.left, 'ArrowRight': _Key.right,
        'ArrowUp': _Key.up, 'ArrowDown': _Key.down,
        'F1':  _Key.f1,  'F2':  _Key.f2,  'F3':  _Key.f3,  'F4':  _Key.f4,
        'F5':  _Key.f5,  'F6':  _Key.f6,  'F7':  _Key.f7,  'F8':  _Key.f8,
        'F9':  _Key.f9,  'F10': _Key.f10, 'F11': _Key.f11, 'F12': _Key.f12,
        'Control':      _Key.ctrl,    'ControlLeft': _Key.ctrl_l,  'ControlRight': _Key.ctrl_r,
        'Shift':        _Key.shift,   'ShiftLeft':   _Key.shift_l, 'ShiftRight':   _Key.shift_r,
        'Alt':          _Key.alt,     'AltLeft':     _Key.alt_l,   'AltRight':     _Key.alt_gr,
        'Meta':         _Key.cmd,     'Super':       _Key.cmd,
        'CapsLock':     _Key.caps_lock,
        ' ':            _Key.space,   'Space':       _Key.space,
    }

_KEY_MAP = _build_key_map()


# ─── Captura de tela (Windows) ──────────────────────────────────────────────────

class ScreenCapture:

    def __init__(self):
        self.quality = 50
        self.fps     = 15
        self.monitor = 1      # 1-based
        self._sct    = None

    def list_monitors(self) -> list:
        try:
            if not self._sct:
                self._sct = _mss.mss()
            return [
                {"index": i, "width": m["width"], "height": m["height"]}
                for i, m in enumerate(self._sct.monitors[1:], start=1)
            ]
        except Exception:
            return []

    def capture(self) -> str | None:
        try:
            if not self._sct:
                self._sct = _mss.mss()
            mons = self._sct.monitors
            idx  = self.monitor if 0 < self.monitor < len(mons) else 1
            shot = self._sct.grab(mons[idx])
            img  = _PILImage.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
            buf  = _io.BytesIO()
            img.save(buf, "JPEG", quality=self.quality, optimize=False, subsampling=2)
            return base64.b64encode(buf.getvalue()).decode()
        except Exception as e:
            logger.debug(f"Screen capture: {e}")
            return None

    def close(self):
        if self._sct:
            try:
                self._sct.close()
            except Exception:
                pass
            self._sct = None


# ─── Controle de mouse e teclado (Windows) ─────────────────────────────────────

class InputController:

    def __init__(self):
        self._mouse = _MouseCtrl() if HAS_INPUT else None
        self._kb    = _KbCtrl()    if HAS_INPUT else None

    def mouse(self, action: str, x: int, y: int, dx: int = 0, dy: int = 0):
        if not self._mouse:
            return
        try:
            if action != 'scroll':
                self._mouse.position = (x, y)
            if action == 'left_down':
                self._mouse.press(_MBtn.left)
            elif action == 'left_up':
                self._mouse.release(_MBtn.left)
            elif action == 'right_down':
                self._mouse.press(_MBtn.right)
            elif action == 'right_up':
                self._mouse.release(_MBtn.right)
            elif action == 'middle_click':
                self._mouse.click(_MBtn.middle)
            elif action == 'left_dblclick':
                self._mouse.click(_MBtn.left, 2)
            elif action == 'scroll':
                self._mouse.scroll(dx, dy)
        except Exception as e:
            logger.debug(f"Mouse: {e}")

    def keyboard(self, action: str, key: str, code: str):
        if not self._kb:
            return
        try:
            pkey = _KEY_MAP.get(key)
            if pkey is None and len(key) == 1:
                pkey = _KeyCode.from_char(key)
            if pkey is None:
                return
            if action == 'key_down':
                self._kb.press(pkey)
            elif action == 'key_up':
                self._kb.release(pkey)
        except Exception as e:
            logger.debug(f"Keyboard: {e}")


# ─── Estado global ──────────────────────────────────────────────────────────────

_tray_icon     = None
_g_status      = "disconnected"   # disconnected | connecting | connected
_g_agent       = None
_shutdown      = threading.Event()
_g_agent_loop  = None            # event loop do agente (para stop responsivo)

# ─── Ícone da bandeja ───────────────────────────────────────────────────────────

_STATUS_COLORS = {
    "connected":    (16, 185, 129),   # verde
    "connecting":   (245, 158, 11),   # amarelo/laranja
    "disconnected": (239, 68, 68),    # vermelho
    "service":      (59, 130, 246),   # azul (monitorando serviço)
}

def _make_icon(status: str) -> "Image.Image":
    sz  = 64
    col = _STATUS_COLORS.get(status, (100, 116, 139))
    img = Image.new("RGBA", (sz, sz), (0, 0, 0, 0))
    d   = ImageDraw.Draw(img)
    d.ellipse([2, 2, sz - 2, sz - 2], fill=(15, 23, 42))
    d.ellipse([14, 14, sz - 14, sz - 14], fill=col)
    return img

def _set_status(status: str):
    global _g_status, _tray_icon
    _g_status = status
    if _tray_icon and HAS_TRAY:
        try:
            _tray_icon.icon  = _make_icon(status)
            _tray_icon.title = f"RNRemote — {status}"
        except Exception:
            pass

# ─── Autostart (registro) ───────────────────────────────────────────────────────

_REG_RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

def _autostart_cmd() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --tray'
    return f'"{sys.executable}" "{os.path.abspath(__file__)}" --tray'

def is_autostart_enabled() -> bool:
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_RUN, 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, SVC_NAME + "Tray")
        winreg.CloseKey(key)
        return True
    except OSError:
        return False

def set_autostart(enable: bool):
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_RUN, 0, winreg.KEY_SET_VALUE)
        if enable:
            winreg.SetValueEx(key, SVC_NAME + "Tray", 0, winreg.REG_SZ, _autostart_cmd())
        else:
            try:
                winreg.DeleteValue(key, SVC_NAME + "Tray")
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
    except Exception as e:
        logger.warning(f"Autostart: {e}")

# ─── Helpers ────────────────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def compute_binding_token(secret: str, agent_id: str) -> str:
    return hashlib.sha256(f"{secret}{agent_id}".encode()).hexdigest()

def get_system_info() -> dict:
    return {
        "hostname":      socket.gethostname(),
        "os_type":       "Windows",
        "os_version":    platform.version(),
        "username":      os.environ.get("USERNAME", "unknown"),
        "screen_width":  0,
        "screen_height": 0,
    }

# ─── Shell Session (Windows) ────────────────────────────────────────────────────

class WindowsShellSession:
    """PTY via pywinpty (ConPTY) ou asyncio subprocess como fallback."""

    def __init__(self):
        self.running = False
        self._pty    = None   # winpty.PtyProcess
        self._proc   = None   # asyncio.subprocess.Process

    async def start(self, cols: int = 120, rows: int = 30):
        shell = "powershell.exe" if shutil.which("powershell.exe") else "cmd.exe"

        if HAS_WINPTY:
            loop = asyncio.get_running_loop()
            try:
                self._pty = await loop.run_in_executor(
                    None,
                    lambda: winpty.PtyProcess.spawn(shell, dimensions=(rows, cols)),
                )
                self.running = True
                logger.info(f"Shell PTY: {shell} ({cols}x{rows})")
                return
            except Exception as e:
                logger.warning(f"pywinpty falhou ({e}), usando subprocess")

        # Fallback: asyncio subprocess
        args = [shell]
        if "powershell" in shell.lower():
            args += ["-NoLogo", "-NoExit"]
        self._proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self.running = True
        logger.info(f"Shell subprocess: {shell} ({cols}x{rows})")

    def resize(self, cols: int, rows: int):
        if self._pty:
            try:
                self._pty.setwinsize(rows, cols)
            except Exception:
                pass

    def write(self, data):
        if not self.running:
            return
        try:
            if self._pty:
                text = data if isinstance(data, str) else data.decode("utf-8", errors="replace")
                self._pty.write(text)
            elif self._proc and self._proc.stdin:
                raw = data if isinstance(data, bytes) else data.encode("utf-8", errors="replace")
                self._proc.stdin.write(raw)
        except Exception:
            self.running = False

    async def read(self):
        if not self.running:
            return None
        try:
            if self._pty:
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(None, lambda: self._pty.read(4096))
                return text.encode("utf-8", errors="replace") if text else b""
            elif self._proc and self._proc.stdout:
                data = await self._proc.stdout.read(4096)
                if not data:
                    self.running = False
                    return None
                return data
        except EOFError:
            self.running = False
            return None
        except Exception as e:
            logger.debug(f"Shell read: {e}")
            self.running = False
            return None
        return b""

    def stop(self):
        self.running = False
        if self._pty:
            try:
                self._pty.terminate()
            except Exception:
                pass
            self._pty = None
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
            self._proc = None
        logger.info("Shell encerrado")

# ─── Agente ─────────────────────────────────────────────────────────────────────

class WindowsAgent:

    def __init__(self, relay_url: str, agent_id: str, password: str,
                 binding_secret: str = "", reconnect_delay: int = 10):
        self.relay_url       = relay_url
        self.agent_id        = agent_id
        self.password_hash   = hash_password(password)
        self.binding_token   = compute_binding_token(binding_secret, agent_id) if binding_secret else ""
        self.reconnect_delay = reconnect_delay
        self.ws              = None
        self.session_id      = None
        self.shell           = None
        self._reader_task    = None
        self._running        = True
        self._uploads        = {}
        self.screen          = ScreenCapture()   if HAS_SCREEN else None
        self.input_ctrl      = InputController() if HAS_INPUT  else None
        self._screen_task    = None
        self._screen_active  = False

    async def run(self):
        while self._running and not _shutdown.is_set():
            _set_status("connecting")
            try:
                logger.info(f"Conectando: {self.relay_url}")
                async with websockets.connect(
                    self.relay_url,
                    max_size=10 * 1024 * 1024,
                    ping_interval=10,
                    ping_timeout=20,
                ) as ws:
                    self.ws = ws
                    _set_status("connected")
                    logger.info("Conectado ao relay")
                    await self._register()
                    await asyncio.gather(self._recv_loop(), self._heartbeat_loop())
            except (websockets.ConnectionClosed, ConnectionRefusedError, OSError) as e:
                logger.warning(f"Conexão perdida: {e}")
            except Exception as e:
                logger.error(f"Erro: {e}")
            finally:
                self.ws = None
                self._stop_shell()
                self._stop_screen()
                self.session_id = None
                _set_status("disconnected")

            if self._running and not _shutdown.is_set():
                logger.info(f"Reconectando em {self.reconnect_delay}s...")
                # Sleep interrompível: verifica _shutdown a cada 0.2s
                for _ in range(self.reconnect_delay * 5):
                    if not self._running or _shutdown.is_set():
                        return
                    await asyncio.sleep(0.2)

    async def _register(self):
        await self._send({
            "type": "register_agent",
            "data": {
                "agent_id":      self.agent_id,
                "password_hash": self.password_hash,
                "binding_token": self.binding_token,
                "version":       AGENT_VERSION,
                **get_system_info(),
            },
            "timestamp": time.time(),
        })

    async def _heartbeat_loop(self):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            await self._send({"type": "ping", "data": {}, "timestamp": time.time()})

    async def _recv_loop(self):
        async for raw in self.ws:
            try:
                await self._handle(json.loads(raw))
            except json.JSONDecodeError:
                continue

    async def _handle(self, msg: dict):
        t    = msg.get("type", "")
        data = msg.get("data", {})
        sid  = msg.get("session_id")

        if t == "auth_success":
            logger.info(f"Autenticado | agent_id: {self.agent_id}")
        elif t == "connect_accept":
            self.session_id = sid or data.get("session_id")
            logger.info(f"Viewer conectado | sessão: {(self.session_id or '')[:12]}")
        elif t == "disconnect":
            logger.info("Viewer desconectou")
            self._stop_shell()
            self.session_id = None
        elif t == "shell_start":
            if not self.shell or not self.shell.running:
                await self._start_shell(data.get("cols", 120), data.get("rows", 30))
        elif t == "shell_input":
            if data.get("input") and self.shell and self.shell.running:
                self.shell.write(data["input"])
        elif t == "shell_command":
            if data.get("command") and self.shell and self.shell.running:
                self.shell.write(data["command"] + "\r\n")
        elif t == "shell_resize":
            if self.shell:
                self.shell.resize(data.get("cols", 120), data.get("rows", 30))
        elif t == "shell_stop":
            self._stop_shell()
        elif t == "file_list_request":
            await self._handle_file_list(data)
        elif t == "file_download_request":
            asyncio.create_task(self._handle_file_download(data))
        elif t == "file_upload_start":
            self._uploads[data.get("transfer_id", "")] = {
                "path": data.get("path", ""), "chunks": []
            }
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
        elif t == "screen_request":
            if data.get("action", "start") == "start":
                await self._start_screen()
            else:
                self._stop_screen()

        elif t == "screen_config":
            if self.screen:
                if "quality" in data:
                    self.screen.quality = max(10, min(95, int(data["quality"])))
                if "fps" in data:
                    self.screen.fps = max(1, min(30, int(data["fps"])))
                if "monitor" in data:
                    self.screen.monitor = max(1, int(data["monitor"]))

        elif t == "mouse_event":
            if self.input_ctrl:
                self.input_ctrl.mouse(
                    action=data.get("action", ""),
                    x=int(data.get("x", 0)),
                    y=int(data.get("y", 0)),
                    dx=int(data.get("dx", 0)),
                    dy=int(data.get("dy", 0)),
                )

        elif t == "keyboard_event":
            if self.input_ctrl:
                self.input_ctrl.keyboard(
                    action=data.get("action", ""),
                    key=data.get("key", ""),
                    code=data.get("code", ""),
                )

        elif t == "update_agent":
            await self._handle_update(data)
        elif t == "pong":
            pass

    # ── Captura de tela ───────────────────────────────────────────────────────────

    async def _start_screen(self):
        if not self.screen:
            await self._send({
                "type": "error",
                "data": {"message": "Captura de tela indisponível. Instale: pip install mss pillow"},
                "session_id": self.session_id, "timestamp": time.time(),
            })
            return
        self._screen_active = True
        if not self._screen_task or self._screen_task.done():
            self._screen_task = asyncio.create_task(self._screen_loop())

    def _stop_screen(self):
        self._screen_active = False
        if self._screen_task:
            self._screen_task.cancel()
            self._screen_task = None

    async def _screen_loop(self):
        loop = asyncio.get_running_loop()
        while self._screen_active and self.ws:
            t0    = time.monotonic()
            frame = await loop.run_in_executor(None, self.screen.capture)
            if frame:
                await self._send({
                    "type": "screen_frame",
                    "data": {"frame": frame},
                    "session_id": self.session_id,
                    "timestamp": time.time(),
                })
            elapsed  = time.monotonic() - t0
            interval = 1.0 / max(1, self.screen.fps)
            sleep    = max(0.0, interval - elapsed)
            if sleep:
                await asyncio.sleep(sleep)
        logger.info("Screen loop finalizado")

    # ── Arquivos ──────────────────────────────────────────────────────────────────

    async def _handle_file_list(self, data: dict):
        path = data.get("path") or os.path.expanduser("~")
        try:
            entries = []
            with os.scandir(path) as it:
                for e in sorted(it, key=lambda x: (not x.is_dir(follow_symlinks=False), x.name.lower())):
                    try:
                        st = e.stat(follow_symlinks=False)
                        entries.append({
                            "name":     e.name,
                            "path":     e.path,
                            "is_dir":   e.is_dir(follow_symlinks=False),
                            "size":     st.st_size,
                            "modified": st.st_mtime,
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
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(65536)
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
            logger.info(f"Upload: {upload['path']} ({len(raw)} bytes)")
            await self._send({"type": "file_complete",
                               "data": {"transfer_id": tid, "path": upload["path"],
                                        "direction": "upload", "ok": True},
                               "session_id": self.session_id, "timestamp": time.time()})
        except Exception as e:
            await self._send({"type": "file_error",
                               "data": {"transfer_id": tid, "error": str(e)},
                               "session_id": self.session_id, "timestamp": time.time()})

    # ── Sistema ───────────────────────────────────────────────────────────────────

    async def _send_system_info(self):
        info = {
            "hostname":       socket.gethostname(),
            "os_type":        "Windows",
            "os_pretty":      f"Windows {platform.release()}",
            "os_name":        "Windows",
            "os_version":     platform.version(),
            "architecture":   platform.machine(),
            "username":       os.environ.get("USERNAME", "unknown"),
            "cpu_count":      os.cpu_count() or 1,
            "python_version": platform.python_version(),
        }
        try:
            class _MEM(ctypes.Structure):
                _fields_ = [
                    ("dwLength",               ctypes.c_ulong),
                    ("dwMemoryLoad",            ctypes.c_ulong),
                    ("ullTotalPhys",            ctypes.c_ulonglong),
                    ("ullAvailPhys",            ctypes.c_ulonglong),
                    ("ullTotalPageFile",        ctypes.c_ulonglong),
                    ("ullAvailPageFile",        ctypes.c_ulonglong),
                    ("ullTotalVirtual",         ctypes.c_ulonglong),
                    ("ullAvailVirtual",         ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            ms = _MEM()
            ms.dwLength = ctypes.sizeof(_MEM)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            total = ms.ullTotalPhys // (1024 * 1024)
            avail = ms.ullAvailPhys // (1024 * 1024)
            info["ram_total_mb"] = total
            info["ram_used_mb"]  = total - avail
            info["ram_percent"]  = round((total - avail) / total * 100, 1) if total else 0
        except Exception:
            pass
        try:
            du = shutil.disk_usage("C:\\")
            info["disk_total_gb"] = round(du.total / 1_073_741_824, 1)
            info["disk_used_gb"]  = round(du.used  / 1_073_741_824, 1)
            info["disk_percent"]  = round(du.used / du.total * 100, 1)
        except Exception:
            pass
        try:
            ticks = ctypes.windll.kernel32.GetTickCount64()
            secs  = ticks // 1000
            days, rem  = divmod(secs, 86400)
            hours, rem = divmod(rem, 3600)
            mins = rem // 60
            info["uptime"] = (f"{days}d " if days else "") + f"{hours:02d}:{mins:02d}"
        except Exception:
            pass
        if self.screen:
            monitors = self.screen.list_monitors()
            if monitors:
                info["monitors"]      = monitors
                info["monitor_count"] = len(monitors)
        await self._send({"type": "system_info", "data": info,
                           "session_id": self.session_id, "timestamp": time.time()})

    # ── Auto-update ───────────────────────────────────────────────────────────────

    async def _handle_update(self, data: dict):
        panel_url = data.get("panel_url", PANEL_URL).rstrip("/")
        loop = asyncio.get_running_loop()

        if getattr(sys, "frozen", False):
            url     = f"{panel_url}/static/agent/RNRemote-Agent.exe"
            cur_exe = sys.executable
            tmp_exe = cur_exe + ".new"
            bat     = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "rnremote_update.bat")
            logger.info(f"Atualizando .exe: {url}")
            try:
                await loop.run_in_executor(None, lambda: urllib.request.urlretrieve(url, tmp_exe))
                if os.path.getsize(tmp_exe) < 100_000:
                    raise ValueError(f"Arquivo suspeito ({os.path.getsize(tmp_exe)} bytes)")
                with open(bat, "w") as f:
                    f.write(
                        f"@echo off\ntimeout /t 3 /nobreak >nul\n"
                        f"move /Y \"{tmp_exe}\" \"{cur_exe}\"\n"
                        f"start \"\" \"{cur_exe}\"\ndel \"%~f0\"\n"
                    )
                self._running = False
                _shutdown.set()
                subprocess.Popen(
                    ["cmd.exe", "/C", bat],
                    creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
                )
                if _tray_icon:
                    _tray_icon.stop()
            except Exception as e:
                logger.error(f"Falha update .exe: {e}")
        else:
            url        = f"{panel_url}/static/agent/agent-windows.py"
            agent_path = os.path.abspath(__file__)
            tmp_path   = agent_path + ".update"
            logger.info(f"Atualizando .py: {url}")
            try:
                await loop.run_in_executor(None, lambda: urllib.request.urlretrieve(url, tmp_path))
                if os.path.getsize(tmp_path) < 5000:
                    raise ValueError(f"Arquivo suspeito ({os.path.getsize(tmp_path)} bytes)")
                shutil.move(tmp_path, agent_path)
                logger.info("Atualização OK — reiniciando...")
                self._running = False
                os.execv(sys.executable, [sys.executable] + sys.argv)
            except Exception as e:
                logger.error(f"Falha update .py: {e}")
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

    # ── Shell ─────────────────────────────────────────────────────────────────────

    async def _start_shell(self, cols: int, rows: int):
        self._stop_shell()
        self.shell = WindowsShellSession()
        await self.shell.start(cols=cols, rows=rows)
        self._reader_task = asyncio.create_task(self._read_shell())

    async def _read_shell(self):
        while self.shell and self.shell.running:
            data = await self.shell.read()
            if data is None:
                break
            if data:
                await self._send({
                    "type": "shell_output",
                    "data": {"output": data.decode("utf-8", errors="replace")},
                    "session_id": self.session_id,
                    "timestamp": time.time(),
                })
        logger.info("Leitura do shell finalizada")

    def _stop_shell(self):
        if self._reader_task:
            self._reader_task.cancel()
            self._reader_task = None
        if self.shell:
            self.shell.stop()
            self.shell = None

    # ── Send ──────────────────────────────────────────────────────────────────────

    async def _send(self, msg: dict):
        if self.ws:
            try:
                await self.ws.send(json.dumps(msg))
            except Exception:
                pass


# ─── Windows Service ─────────────────────────────────────────────────────────────

if HAS_WIN32SERVICE:
    class RNRemoteService(win32serviceutil.ServiceFramework):
        _svc_name_         = SVC_NAME
        _svc_display_name_ = SVC_DISPLAY_NAME
        _svc_description_  = SVC_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)
            _shutdown.set()
            if _g_agent:
                _g_agent._running = False
            # Cancela qualquer coroutine pendente no loop do agente
            if _g_agent_loop and not _g_agent_loop.is_closed():
                _g_agent_loop.call_soon_threadsafe(_g_agent_loop.stop)

        def SvcDoRun(self):
            try:
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, ""),
                )
            except Exception:
                pass
            _setup_logging(to_file=True)
            logger.info(f"Serviço {SVC_NAME} iniciado (SYSTEM, independente de sessão de usuário)")
            cfg = _load_config(CONFIG_PATH_DEFAULT)
            # Roda o agente em thread separada para não bloquear o thread do serviço
            t = threading.Thread(target=_run_agent, args=(cfg,), daemon=True)
            t.start()
            # Aguarda sinal de parada do SCM (Stop-Service / desligamento do Windows)
            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
            _shutdown.set()
            if _g_agent:
                _g_agent._running = False
            t.join(timeout=15)
            logger.info(f"Serviço {SVC_NAME} encerrado")


def _is_service_running() -> bool:
    if not HAS_WIN32SERVICE:
        return False
    try:
        status = win32serviceutil.QueryServiceStatus(SVC_NAME)
        return status[1] == win32service.SERVICE_RUNNING
    except Exception:
        return False

def _service_control(action: str):
    """Inicia ou para o serviço a partir da bandeja."""
    try:
        if action == "start":
            win32serviceutil.StartService(SVC_NAME)
        elif action == "stop":
            win32serviceutil.StopService(SVC_NAME)
    except Exception as e:
        logger.warning(f"Controle de serviço ({action}): {e}")

# ─── Thread do agente (modo interativo) ─────────────────────────────────────────

def _run_agent(cfg: dict):
    global _g_agent, _g_agent_loop
    relay          = cfg.get("relay_url",      RELAY_URL_DEFAULT)
    agent_id       = cfg.get("agent_id",       "")
    password       = cfg.get("password",       "")
    binding_secret = cfg.get("binding_secret", "")

    if not relay or not agent_id or not password:
        logger.error("Configuração incompleta — relay_url, agent_id e password são obrigatórios.")
        return

    _g_agent = WindowsAgent(
        relay_url=relay,
        agent_id=agent_id,
        password=password,
        binding_secret=binding_secret,
    )
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _g_agent_loop = loop
    try:
        loop.run_until_complete(_g_agent.run())
    finally:
        _g_agent_loop = None
        loop.close()

# ─── Bandeja do sistema ──────────────────────────────────────────────────────────

def _open_panel(icon, item):
    webbrowser.open(PANEL_URL)

def _open_log(icon, item):
    if os.path.exists(LOG_PATH):
        os.startfile(LOG_PATH)

def _toggle_autostart(icon, item):
    set_autostart(not is_autostart_enabled())

def _start_service(icon, item):
    _service_control("start")

def _stop_service(icon, item):
    _service_control("stop")

def _quit(icon, item):
    global _g_agent
    _shutdown.set()
    if _g_agent:
        _g_agent._running = False
    icon.stop()

def _build_tray_menu(service_mode: bool) -> "pystray.Menu":
    items = [
        pystray.MenuItem(SVC_DISPLAY_NAME, None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Abrir Painel", _open_panel),
        pystray.MenuItem("Ver Log", _open_log),
    ]
    if service_mode and HAS_WIN32SERVICE:
        items += [
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Iniciar Serviço", _start_service),
            pystray.MenuItem("Parar Serviço",   _stop_service),
        ]
    items += [
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "Iniciar com Windows",
            _toggle_autostart,
            checked=lambda item: is_autostart_enabled(),
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Sair", _quit),
    ]
    return pystray.Menu(*items)

def _run_tray_service_monitor():
    """Modo bandeja para monitorar o serviço Windows (sem agente embutido)."""
    global _tray_icon
    icon = pystray.Icon(
        "rnremote",
        icon=_make_icon("service"),
        title=f"{SVC_DISPLAY_NAME} — monitorando serviço",
        menu=_build_tray_menu(service_mode=True),
    )
    _tray_icon = icon

    def _monitor():
        while not _shutdown.is_set():
            running = _is_service_running()
            _set_status("connected" if running else "disconnected")
            time.sleep(5)

    t = threading.Thread(target=_monitor, daemon=True)
    t.start()
    icon.run()

def _run_tray_interactive(cfg: dict):
    """Modo interativo: agente + bandeja na mesma instância."""
    global _tray_icon
    icon = pystray.Icon(
        "rnremote",
        icon=_make_icon("connecting"),
        title=f"{SVC_DISPLAY_NAME} — conectando...",
        menu=_build_tray_menu(service_mode=False),
    )
    _tray_icon = icon

    t = threading.Thread(target=_run_agent, args=(cfg,), daemon=True, name="rnremote-agent")
    t.start()
    icon.run()

# ─── Config ──────────────────────────────────────────────────────────────────────

def _load_config(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8-sig") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Erro ao ler configuração: {e}")
    return {}

# ─── Main ────────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="RNRemote Agent - Windows")
    parser.add_argument("--config",   default=CONFIG_PATH_DEFAULT)
    parser.add_argument("--relay",    default="")
    parser.add_argument("--id",       dest="agent_id", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--no-tray",  action="store_true")
    parser.add_argument("--tray",     action="store_true",
                        help="Apenas bandeja do sistema (monitora o serviço)")
    args, remaining = parser.parse_known_args()

    # ── Gerenciamento de serviço (install/remove/start/stop/debug) ───────────────
    svc_cmds = {"install", "remove", "start", "stop", "debug", "restart",
                "update", "querystate", "--startup"}
    if remaining and remaining[0].lower().lstrip("-") in {c.lstrip("-") for c in svc_cmds}:
        if not HAS_WIN32SERVICE:
            print("ERRO: pywin32 necessário para gerenciar o serviço.")
            print("Execute: pip install pywin32")
            sys.exit(1)
        sys.argv = [sys.argv[0]] + remaining
        win32serviceutil.HandleCommandLine(RNRemoteService)
        return

    _setup_logging()

    # ── Modo bandeja de monitoramento (serviço já instalado) ─────────────────────
    if args.tray:
        if not HAS_TRAY:
            print("AVISO: pystray/Pillow não disponível.")
            sys.exit(0)
        _run_tray_service_monitor()
        return

    # ── Modo normal: agente + bandeja (sem serviço) ───────────────────────────────
    cfg = _load_config(args.config)
    if args.relay:    cfg["relay_url"] = args.relay
    if args.agent_id: cfg["agent_id"]  = args.agent_id
    if args.password: cfg["password"]  = args.password

    if not cfg.get("relay_url") or not cfg.get("agent_id") or not cfg.get("password"):
        msg = (
            "Configuração incompleta.\n\n"
            f"Arquivo esperado:\n{args.config}\n\n"
            '{\n  "relay_url": "wss://rnremote.joaoneto.tec.br/ws",\n'
            '  "agent_id": "SEU_ID",\n  "password": "SUA_SENHA"\n}'
        )
        if HAS_TRAY:
            ctypes.windll.user32.MessageBoxW(0, msg, f"{SVC_DISPLAY_NAME} — Configuração", 0x10)
        else:
            print(msg)
        sys.exit(1)

    if HAS_TRAY and not args.no_tray:
        _run_tray_interactive(cfg)
    else:
        logger.info("Rodando sem bandeja. Ctrl+C para sair.")
        try:
            _run_agent(cfg)
        except KeyboardInterrupt:
            _shutdown.set()


if __name__ == "__main__":
    # Quando PyInstaller compila como .exe sem console, evita erros de stdout
    if getattr(sys, "frozen", False) and not sys.stdout:
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")
    main()
