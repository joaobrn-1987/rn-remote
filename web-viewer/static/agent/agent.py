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
import json
import os
import pty
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
import urllib.request

AGENT_VERSION = "1.3.1"

import websockets

# ─── Dependências opcionais (captura de tela e controle de input) ───────────────

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

PROTOCOL_VERSION = "1.0.0"
HEARTBEAT_INTERVAL = 8

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


# ─── Captura de tela ────────────────────────────────────────────────────────────

def _find_display() -> str | None:
    """Detecta o DISPLAY X11 ativo (necessário quando rodando como root/service)."""
    if os.environ.get("DISPLAY"):
        return os.environ["DISPLAY"]
    # Tenta detectar a partir do processo Xorg
    try:
        import subprocess
        out = subprocess.check_output(
            ["pgrep", "-a", "Xorg"], text=True, timeout=2
        )
        for line in out.splitlines():
            for part in line.split():
                if part.startswith(":"):
                    return part
    except Exception:
        pass
    return ":0"


class ScreenCapture:

    def __init__(self):
        self.quality = 50     # JPEG quality (10–95)
        self.fps     = 15     # frames por segundo
        self.monitor = 1      # 1-based (1 = primeiro monitor)
        self._sct    = None

    def _prepare(self):
        display = _find_display()
        if display:
            os.environ.setdefault("DISPLAY", display)
        # Tenta XAUTHORITY se não estiver definido
        if not os.environ.get("XAUTHORITY"):
            for path in (
                f"/run/user/{os.getuid()}/Xauthority",
                os.path.expanduser("~/.Xauthority"),
                "/tmp/.Xauthority",
            ):
                if os.path.exists(path):
                    os.environ["XAUTHORITY"] = path
                    break
        if not self._sct:
            self._sct = _mss.mss()

    def list_monitors(self) -> list:
        try:
            self._prepare()
            return [
                {"index": i, "width": m["width"], "height": m["height"]}
                for i, m in enumerate(self._sct.monitors[1:], start=1)
            ]
        except Exception:
            return []

    def capture(self) -> str | None:
        try:
            self._prepare()
            mons = self._sct.monitors
            idx = self.monitor if 0 < self.monitor < len(mons) else 1
            shot = self._sct.grab(mons[idx])
            img = _PILImage.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
            buf = _io.BytesIO()
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


# ─── Controle de mouse e teclado ────────────────────────────────────────────────

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


# ─── Headless Browser (Chromium via Playwright) ─────────────────────────────

class HeadlessBrowser:
    """Controla Chromium headless para renderizar páginas web remotamente."""

    def __init__(self):
        self.running = False
        self._browser = None
        self._page = None
        self._pw = None
        self._playwright = None
        self.current_url = ""
        self.width = 1280
        self.height = 720

    @staticmethod
    async def _ensure_playwright():
        """Instala playwright e Chromium se não estiverem disponíveis."""
        import subprocess as _sp
        loop = asyncio.get_running_loop()

        try:
            import playwright  # noqa
        except ImportError:
            logger.info("Playwright não encontrado — instalando via pip...")
            await loop.run_in_executor(None, lambda: _sp.run(
                [sys.executable, "-m", "pip", "install", "playwright", "-q"],
                check=True
            ))
            logger.info("Playwright instalado.")

        # Tenta importar; se o pacote acabou de ser instalado precisa reimportar
        import importlib
        try:
            pw_mod = importlib.import_module("playwright.async_api")
        except Exception as e:
            raise RuntimeError(f"Falha ao importar playwright após instalação: {e}")

        # Tenta lançar o Chromium para ver se o executável existe
        try:
            _pw = await pw_mod.async_playwright().__aenter__()
            _br = await _pw.chromium.launch(headless=True)
            await _br.close()
            await _pw.__aexit__(None, None, None)
        except Exception as e:
            if "executable" in str(e).lower() or "not found" in str(e).lower() or "chromium" in str(e).lower():
                logger.info("Chromium não instalado — baixando agora (~200MB)...")
                await loop.run_in_executor(None, lambda: _sp.run(
                    [sys.executable, "-m", "playwright", "install", "chromium", "--with-deps"],
                    check=True
                ))
                logger.info("Chromium instalado com sucesso.")
            else:
                raise

    async def start(self, width: int = 1280, height: int = 720):
        await self._ensure_playwright()
        from playwright.async_api import async_playwright

        self.width = width
        self.height = height
        self._playwright = async_playwright()
        self._pw = await self._playwright.start()
        self._browser = await self._pw.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-dev-shm-usage',
                  '--disable-gpu', '--disable-software-rasterizer'],
        )
        self._page = await self._browser.new_page(
            viewport={"width": width, "height": height}
        )
        self.running = True
        logger.info(f"Headless browser iniciado ({width}x{height})")

    async def navigate(self, url: str, timeout: int = 15000) -> dict:
        if not self._page:
            return {"error": "Browser não iniciado"}
        try:
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            self.current_url = url
            response = await self._page.goto(url, timeout=timeout,
                                              wait_until="domcontentloaded")
            title = await self._page.title()
            return {"url": self._page.url, "title": title,
                    "status": response.status if response else 0}
        except Exception as e:
            return {"url": url, "error": str(e)}

    async def screenshot(self, quality: int = 60) -> bytes:
        if not self._page:
            return b""
        try:
            return await self._page.screenshot(type="jpeg", quality=quality,
                                                full_page=False)
        except Exception:
            return b""

    async def click(self, x: int, y: int):
        if self._page:
            try:
                await self._page.mouse.click(x, y)
            except Exception:
                pass

    async def scroll(self, x: int, y: int, delta_x: int, delta_y: int):
        if self._page:
            try:
                await self._page.mouse.move(x, y)
                await self._page.mouse.wheel(delta_x, delta_y)
            except Exception:
                pass

    async def type_text(self, text: str):
        if self._page:
            try:
                await self._page.keyboard.type(text)
            except Exception:
                pass

    async def press_key(self, key: str):
        if self._page:
            try:
                await self._page.keyboard.press(key)
            except Exception:
                pass

    async def resize(self, width: int, height: int):
        if self._page:
            self.width = width
            self.height = height
            try:
                await self._page.set_viewport_size({"width": width, "height": height})
            except Exception:
                pass

    async def go_back(self):
        if self._page:
            try:
                await self._page.go_back(timeout=5000)
            except Exception:
                pass

    async def go_forward(self):
        if self._page:
            try:
                await self._page.go_forward(timeout=5000)
            except Exception:
                pass

    async def reload(self):
        if self._page:
            try:
                await self._page.reload(timeout=10000)
            except Exception:
                pass

    async def stop(self):
        self.running = False
        for obj, method in [
            (self._page, 'close'), (self._browser, 'close'), (self._pw, 'stop')
        ]:
            if obj:
                try:
                    await getattr(obj, method)()
                except Exception:
                    pass
        self._page = self._browser = self._pw = self._playwright = None
        logger.info("Headless browser encerrado")


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
        self._uploads: dict = {}
        self.vconsole: VConsoleSession | None = None
        self._vconsole_task: asyncio.Task | None = None
        self.screen      = ScreenCapture()    if HAS_SCREEN else None
        self.input_ctrl  = InputController()  if HAS_INPUT  else None
        self._screen_task: asyncio.Task | None = None
        self._screen_active = False
        self.browser = None
        self._browser_stream_task: asyncio.Task | None = None
        self._browser_fps = 5
        self._browser_quality = 60

    # ── Loop principal ─────────────────────────────────────────────────────────

    async def run(self):
        while self._running:
            try:
                logger.info(f"Conectando ao relay: {self.relay_url}")
                async with websockets.connect(
                    self.relay_url,
                    max_size=10 * 1024 * 1024,
                    ping_interval=10,
                    ping_timeout=20,
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
                self._stop_screen()
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
            await self._handle_browser_stop()
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

        elif t == "browser_start":
            await self._handle_browser_start(data)

        elif t == "browser_navigate":
            await self._handle_browser_navigate(data)

        elif t == "browser_input":
            await self._handle_browser_input(data)

        elif t == "browser_scroll":
            await self._handle_browser_scroll(data)

        elif t == "browser_resize":
            await self._handle_browser_resize(data)

        elif t == "browser_stop":
            await self._handle_browser_stop()

        elif t == "update_agent":
            await self._handle_update(data)

        elif t == "pong":
            pass  # heartbeat ok

    # ── Web Browser (Headless) ──────────────────────────────────────────────────

    async def _handle_browser_start(self, data: dict):
        await self._handle_browser_stop()
        width = data.get("width", 1280)
        height = data.get("height", 720)
        self._browser_fps = data.get("fps", 5)
        self._browser_quality = data.get("quality", 60)
        self.browser = HeadlessBrowser()
        try:
            await self.browser.start(width, height)
            await self._send({
                "type": "browser_status",
                "data": {"status": "started", "mode": "headless",
                         "width": width, "height": height},
                "session_id": self.session_id, "timestamp": time.time(),
            })
            self._browser_stream_task = asyncio.create_task(self._browser_stream_loop())
        except Exception as e:
            logger.error(f"Erro iniciando browser: {e}")
            await self._send({
                "type": "browser_status",
                "data": {"status": "error", "error": str(e)},
                "session_id": self.session_id, "timestamp": time.time(),
            })
            self.browser = None

    async def _handle_browser_navigate(self, data: dict):
        if not self.browser or not self.browser.running:
            return
        url = data.get("url", "")
        action = data.get("action", "goto")
        if action == "back":
            await self.browser.go_back()
        elif action == "forward":
            await self.browser.go_forward()
        elif action == "reload":
            await self.browser.reload()
        elif url:
            result = await self.browser.navigate(url)
            await self._send({
                "type": "browser_status",
                "data": {"status": "navigated", **result},
                "session_id": self.session_id, "timestamp": time.time(),
            })

    async def _handle_browser_input(self, data: dict):
        if not self.browser or not self.browser.running:
            return
        action = data.get("action", "")
        if action == "click":
            await self.browser.click(data.get("x", 0), data.get("y", 0))
        elif action == "type":
            await self.browser.type_text(data.get("text", ""))
        elif action == "key":
            await self.browser.press_key(data.get("key", ""))

    async def _handle_browser_scroll(self, data: dict):
        if not self.browser or not self.browser.running:
            return
        await self.browser.scroll(data.get("x", 0), data.get("y", 0),
                                   data.get("dx", 0), data.get("dy", 0))

    async def _handle_browser_resize(self, data: dict):
        if not self.browser or not self.browser.running:
            return
        self._browser_fps = data.get("fps", self._browser_fps)
        self._browser_quality = data.get("quality", self._browser_quality)
        await self.browser.resize(data.get("width", 1280), data.get("height", 720))

    async def _handle_browser_stop(self):
        if self._browser_stream_task:
            self._browser_stream_task.cancel()
            try:
                await self._browser_stream_task
            except asyncio.CancelledError:
                pass
            self._browser_stream_task = None
        if self.browser:
            await self.browser.stop()
            self.browser = None

    async def _browser_stream_loop(self):
        prev_frame = None
        while self.browser and self.browser.running:
            try:
                frame_bytes = await self.browser.screenshot(quality=self._browser_quality)
                if frame_bytes and frame_bytes != prev_frame:
                    frame_b64 = base64.b64encode(frame_bytes).decode('ascii')
                    await self._send({
                        "type": "browser_frame",
                        "data": {"frame": frame_b64, "url": self.browser.current_url,
                                 "width": self.browser.width, "height": self.browser.height},
                        "session_id": self.session_id, "timestamp": time.time(),
                    })
                    prev_frame = frame_bytes
                await asyncio.sleep(1.0 / self._browser_fps)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Erro browser stream: {e}")
                await asyncio.sleep(1)

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
        # Monitores disponíveis
        if self.screen:
            monitors = self.screen.list_monitors()
            if monitors:
                info["monitors"]      = monitors
                info["monitor_count"] = len(monitors)
        await self._send({"type": "system_info", "data": info,
                           "session_id": self.session_id, "timestamp": time.time()})

    # ── Captura de tela ─────────────────────────────────────────────────────────

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
            t0 = time.monotonic()
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
