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
import urllib.parse
import http.cookiejar

AGENT_VERSION = "1.2.11"

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


def _get_pfsense_version() -> str:
    """Return pfSense version string, e.g. '2.7.2-RELEASE'."""
    for path in ("/etc/version", "/etc/version.patch"):
        try:
            with open(path) as f:
                ver = f.read().strip()
            if ver:
                return ver
        except Exception:
            pass
    try:
        r = subprocess.run(["freebsd-version"], capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except Exception:
        return platform.release()


def get_system_info() -> dict:
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    if not user:
        try:
            import pwd
            user = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            user = "root"
    return {
        "hostname": socket.gethostname(),
        "os_type": "pfSense",
        "os_version": _get_pfsense_version(),
        "username": user,
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


_PFSENSE_AUTH_SCRIPT = r'''
import sys, os, getpass, xml.etree.ElementTree as ET

try:
    import warnings as _w
    with _w.catch_warnings():
        _w.simplefilter("ignore", DeprecationWarning)
        import crypt as _crypt
    def _check_hash(pw, stored):
        return _crypt.crypt(pw, stored) == stored
except ImportError:
    # Python 3.13+ removeu o módulo crypt
    def _check_hash(pw, stored):
        try:
            import bcrypt as _bc
            return _bc.checkpw(pw.encode(), stored.encode() if isinstance(stored, str) else stored)
        except Exception:
            return False

def _read_hashes():
    try:
        root = ET.parse('/conf/config.xml').getroot()
        h = {}
        for u in root.findall('.//system/user'):
            n = (u.findtext('name') or '').strip()
            p = (u.findtext('bcrypt-hash') or u.findtext('password') or '').strip()
            if n and p: h[n] = p
        return h
    except:
        return {}

def _verify(user, pw, hashes):
    stored = hashes.get(user)
    # 'root' pode ser alias de 'admin' no pfSense
    if not stored and user == 'root':
        stored = hashes.get('admin')
    if not stored:
        return False
    try:
        return _check_hash(pw, stored)
    except Exception:
        return False

hashes = _read_hashes()
if not hashes:
    sys.stdout.write('\r\n\033[33m[AVISO] Nao foi possivel ler /conf/config.xml\033[0m\r\n')
    sys.stdout.flush()

for attempt in range(3):
    try:
        sys.stdout.write('\r\nlogin: ')
        sys.stdout.flush()
        user = ''
        while True:
            c = sys.stdin.read(1)
            if c in ('\r', '\n', ''):
                break
            elif c == '\x7f':
                if user:
                    user = user[:-1]
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            else:
                user += c
                sys.stdout.write(c)
                sys.stdout.flush()
        sys.stdout.write('\r\n')
        sys.stdout.flush()
        try:
            pw = getpass.getpass('Password: ')
        except Exception:
            pw = ''
    except (EOFError, KeyboardInterrupt):
        sys.stdout.write('\r\n')
        sys.exit(0)
    if _verify(user, pw, hashes):
        sys.stdout.write('\r\n')
        sys.stdout.flush()
        # Resolve o usuário real (admin -> root no pfSense)
        real_user = user
        if user == 'admin':
            real_user = 'root'
        # Configura variáveis de ambiente do usuário
        import pwd as _pwd
        try:
            pw_entry = _pwd.getpwnam(real_user)
            os.environ['HOME']    = pw_entry.pw_dir
            os.environ['USER']    = real_user
            os.environ['LOGNAME'] = real_user
        except Exception:
            pass
        # No pfSense o menu interativo é /etc/rc.initial — igual ao que o SSH executa.
        # O shell em /etc/passwd do root é /bin/sh, não o menu, então sempre
        # preferimos /etc/rc.initial primeiro.
        if os.path.isfile('/etc/rc.initial'):
            os.execv('/etc/rc.initial', ['/etc/rc.initial'])
        elif os.path.isfile('/usr/local/bin/bash'):
            os.execv('/usr/local/bin/bash', ['-bash'])
        else:
            os.execv('/bin/sh', ['-sh'])
    sys.stdout.write('\r\nLogin incorrect\r\n')
    sys.stdout.flush()

sys.stdout.write('\r\nMaximo de tentativas atingido.\r\n')
sys.exit(1)
'''


def _find_login_cmd() -> list:
    """Retorna comando de auth via config.xml do pfSense (ignora restrições de TTY do FreeBSD)."""
    return [sys.executable, "-c", _PFSENSE_AUTH_SCRIPT.strip()]


class ShellSession:
    """Shell interativo via PTY (preferido) com fallback para pipes.
    PTY: pty.fork() → setsid + TIOCSCTTY + open(ttyname) — correto no FreeBSD.
    Pipe: subprocess com stdin/stdout PIPE — fallback se PTY não disponível.
    """

    def __init__(self):
        self.master_fd: int | None = None
        self._pid: int | None = None
        self._proc = None          # subprocess.Popen (modo pipe)
        self._use_pipe: bool = False
        self.running: bool = False

    def _env(self) -> dict:
        env = os.environ.copy()
        env.setdefault("TERM", "xterm-256color")
        env.setdefault("HOME", "/root")
        env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        env["SHELL"] = _find_shell()
        return env

    def start(self, cols: int = 120, rows: int = 30) -> str:
        """Retorna 'pty' ou 'pipe' indicando o modo iniciado."""
        try:
            self._start_pty(cols, rows)
            return "pty"
        except Exception as e:
            logger.warning(f"PTY falhou ({e}), tentando modo pipe")
            self._start_pipe()
            return "pipe"

    def _start_pty(self, cols: int, rows: int):
        import pty as _pty
        env = self._env()
        # Usa /usr/bin/login para exigir usuário+senha antes de abrir o shell
        cmd = _find_login_cmd()
        pid, master_fd = _pty.fork()
        if pid == 0:
            # Filho — nunca retorna ao asyncio
            try:
                os.execve(cmd[0], cmd, env)
            except Exception:
                pass
            os._exit(1)
        # Pai
        self.master_fd = master_fd
        self._set_winsize(master_fd, cols, rows)
        self._pid = pid
        self.running = True
        logger.info(f"Shell PTY iniciado (PID {pid}, {cols}x{rows})")

    def _start_pipe(self):
        env = self._env()
        cmd = _find_login_cmd()
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            bufsize=0,
        )
        self._use_pipe = True
        self.running = True
        logger.info(f"Shell PIPE iniciado (PID {self._proc.pid})")

    def _set_winsize(self, fd: int, cols: int, rows: int):
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

    def resize(self, cols: int, rows: int):
        if not self._use_pipe and self.master_fd is not None:
            self._set_winsize(self.master_fd, cols, rows)

    def write(self, data: str | bytes):
        if not self.running:
            return
        raw = data if isinstance(data, bytes) else data.encode("utf-8", errors="replace")
        try:
            if self._use_pipe:
                self._proc.stdin.write(raw)
                self._proc.stdin.flush()
            else:
                os.write(self.master_fd, raw)
        except OSError:
            self.running = False

    def read(self, timeout: float = 0.05) -> bytes | None:
        if not self.running:
            return None
        try:
            if self._use_pipe:
                fd = self._proc.stdout.fileno()
            else:
                fd = self.master_fd
                # FreeBSD: ao sair do processo filho, o slave PTY fecha e
                # select() pode bloquear indefinidamente no master_fd.
                # Verificamos o estado do filho antes de bloquear.
                if self._pid:
                    try:
                        pid_done, _ = os.waitpid(self._pid, os.WNOHANG)
                        if pid_done != 0:
                            self._pid = None
                            self.running = False
                            return None
                    except ChildProcessError:
                        self._pid = None
                        self.running = False
                        return None
            r, _, _ = select.select([fd], [], [], timeout)
            if r:
                data = os.read(fd, 4096)
                if not data:          # EOF explícito
                    self.running = False
                    return None
                return data
            return b""
        except OSError:
            self.running = False
            return None

    def stop(self):
        self.running = False
        if self._use_pipe:
            if self._proc:
                try: self._proc.kill()
                except Exception: pass
                try: self._proc.wait(timeout=1)
                except Exception: pass
                self._proc = None
        else:
            if self._pid:
                # SIGKILL (não pode ser ignorado) + WNOHANG (não bloqueia asyncio)
                try: os.kill(self._pid, signal.SIGKILL)
                except OSError: pass
                try: os.waitpid(self._pid, os.WNOHANG)
                except Exception: pass
                self._pid = None
            if self.master_fd is not None:
                try: os.close(self.master_fd)
                except OSError: pass
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
        self._browser_active = False
        # Cookie jar com política permissiva: aceita cookies de localhost e hosts sem domínio
        self._cookie_jar = http.cookiejar.CookieJar(
            policy=self._make_cookie_policy()
        )
        self._browser_opener = self._make_opener()

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
            except asyncio.CancelledError:
                raise  # Encerramento intencional — não tenta reconectar
            except Exception:
                logger.exception("Erro inesperado no loop principal")
            except BaseException:
                logger.exception("BaseException inesperada no loop principal — reconectando")
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
            try:
                await self._handle(msg)
            except Exception:
                logger.exception("Erro não tratado em _handle — mantendo conexão")

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
            self._browser_active = False
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

        elif t == "browser_start":
            await self._handle_browser_start(data)

        elif t == "browser_navigate":
            await self._handle_browser_navigate(data)

        elif t == "browser_stop":
            self._browser_active = False

        elif t == "update_agent":
            await self._handle_update(data)

        elif t == "pong":
            pass

    # ── Web Browser (Proxy Mode) ────────────────────────────────────────────────

    @staticmethod
    def _make_cookie_policy():
        """Política permissiva: aceita e envia todos os cookies, incluindo os de localhost."""
        class _AllowAll(http.cookiejar.DefaultCookiePolicy):
            def set_ok(self, cookie, request):
                return True
            def return_ok(self, cookie, request):
                return True
            def domain_return_ok(self, domain, request):
                return True
            def path_return_ok(self, path, request):
                return True
        return _AllowAll()

    @staticmethod
    def _get_webgui_url() -> str:
        """Lê /conf/config.xml e retorna a URL base do webConfigurator do pfSense.
        Usa o IP da interface LAN (mais confiável que localhost para sessão/cookies)."""
        try:
            import xml.etree.ElementTree as ET
            tree  = ET.parse("/conf/config.xml")
            root  = tree.getroot()

            # Protocolo e porta do webgui
            webgui = root.find(".//system/webgui")
            proto  = "https"
            port   = ""
            if webgui is not None:
                proto = (webgui.findtext("protocol") or "https").strip().lower()
                port  = (webgui.findtext("port") or "").strip()

            # IP da interface LAN (primeiro endereço estático encontrado)
            host = "localhost"
            for iface in root.findall(".//interfaces/"):
                ipaddr = (iface.findtext("ipaddr") or "").strip()
                # Filtra dhcp, track6, etc. — pega apenas IPs estáticos reais
                if ipaddr and "." in ipaddr and not ipaddr.startswith(("dhcp", "track", "ppp")):
                    # Prefere LAN (ou qualquer primeira interface com IP)
                    tag = iface.tag.lower()
                    if "lan" in tag or host == "localhost":
                        host = ipaddr
                    if "lan" in tag:
                        break

            default_port = "443" if proto == "https" else "80"
            if port and port != default_port:
                return f"{proto}://{host}:{port}"
            return f"{proto}://{host}"
        except Exception:
            return "https://localhost"

    def _make_opener(self):
        """Cria urllib opener com cookie jar e SSL permissivo (certificados auto-assinados)."""
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        https_handler  = urllib.request.HTTPSHandler(context=ctx)
        cookie_handler = urllib.request.HTTPCookieProcessor(self._cookie_jar)
        return urllib.request.build_opener(https_handler, cookie_handler)

    # Script injetado no HTML — intercepta cliques e forms, usando base_url como âncora
    @staticmethod
    def _make_inject_js(base_url: str) -> str:
        return f"""
<script>
(function(){{
  var _BASE = {json.dumps(base_url)};
  function _abs(href){{
    try{{ return new URL(href, _BASE).href; }}catch(e){{ return href; }}
  }}
  function rnSend(msg){{ window.parent.postMessage(JSON.stringify(msg),'*'); }}
  // Intercepta cliques em links
  document.addEventListener('click', function(e){{
    var el = e.target.closest('a');
    if(!el) return;
    var href = el.getAttribute('href');
    if(!href || href.startsWith('#') || href.startsWith('javascript')) return;
    e.preventDefault();
    rnSend({{type:'nav', url:_abs(href), method:'GET'}});
  }}, true);
  // Intercepta envio de formulários
  document.addEventListener('submit', function(e){{
    e.preventDefault();
    var form = e.target;
    var rawAction = form.getAttribute('action') || '';
    var action = _abs(rawAction || _BASE);
    var method = (form.method || 'GET').toUpperCase();
    var data = {{}};
    new FormData(form).forEach(function(v,k){{ data[k]=v; }});
    // Inclui o botão de submit que disparou o evento (ex: login=Sign In no pfSense)
    var sub = e.submitter;
    if(sub && sub.name){{ data[sub.name] = sub.value || ''; }}
    else {{
      // Fallback: inclui o primeiro submit com name
      var btn = form.querySelector('input[type=submit][name],button[type=submit][name]');
      if(btn && !(btn.name in data)){{ data[btn.name] = btn.value || ''; }}
    }}
    rnSend({{type:'nav', url:action, method:method, body:data}});
  }}, true);
}})();
</script>
"""

    async def _handle_browser_start(self, data: dict):
        self._browser_active = True
        # Recria cookie jar (limpo) com a mesma política permissiva
        self._cookie_jar = http.cookiejar.CookieJar(policy=self._make_cookie_policy())
        self._browser_opener = self._make_opener()
        webgui_url = self._get_webgui_url()
        await self._send({
            "type": "browser_status",
            "data": {"status": "started", "mode": "proxy", "webgui_url": webgui_url},
            "session_id": self.session_id, "timestamp": time.time(),
        })
        logger.info(f"Browser proxy mode ativado — webgui: {webgui_url}")

    async def _handle_browser_navigate(self, data: dict):
        if not self._browser_active:
            return
        url = data.get("url", "")
        if not url:
            return
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        method  = (data.get("method", "GET")).upper()
        body    = data.get("body")   # dict com campos de formulário, ou None

        loop = asyncio.get_running_loop()
        try:
            def _fetch():
                import re as _re

                post_data = None
                if method == "POST" and body:
                    post_data = urllib.parse.urlencode(body, doseq=True).encode("utf-8")

                # Extrai origem (scheme://host:port) para Referer/Origin
                parsed   = urllib.parse.urlparse(url)
                origin   = f"{parsed.scheme}://{parsed.netloc}"

                hdrs = {
                    "User-Agent": "Mozilla/5.0 (X11; FreeBSD amd64) AppleWebKit/537.36 Chrome/120",
                    "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Referer":    url,
                    "Origin":     origin,
                }
                if post_data:
                    hdrs["Content-Type"] = "application/x-www-form-urlencoded"

                req  = urllib.request.Request(url, data=post_data, headers=hdrs, method=method)
                cookie_count = len(list(self._cookie_jar))
                cookie_names = [c.name for c in self._cookie_jar]
                logger.info(f"Browser proxy {method} {url} cookies={cookie_count} {cookie_names}")
                resp = self._browser_opener.open(req, timeout=15)
                final_url    = resp.geturl()
                content_type = resp.headers.get("Content-Type", "")
                if method == "POST":
                    logger.info(f"Browser POST resp: status={resp.status} final_url={final_url} cookies_after={[c.name for c in self._cookie_jar]}")
                body_bytes  = resp.read()

                charset = "utf-8"
                if "charset=" in content_type:
                    charset = content_type.split("charset=")[-1].split(";")[0].strip()
                try:
                    html = body_bytes.decode(charset)
                except Exception:
                    html = body_bytes.decode("utf-8", errors="replace")

                # Detecta resposta JSON com fragmento HTML (ex: modal de copyright do pfSense)
                stripped = html.strip()
                if stripped.startswith('{') or 'application/json' in content_type:
                    try:
                        json_obj = json.loads(stripped)
                        if isinstance(json_obj, dict) and 'html' in json_obj:
                            inner_html = json_obj['html']
                            # Substitui botão Accept para navegar de volta via postMessage
                            login_url = f"{parsed.scheme}://{parsed.netloc}/index.php"
                            inner_html = inner_html.replace(
                                "onClick=\"$('.modal').modal('hide');\"",
                                f"onclick=\"window.parent.postMessage(JSON.stringify({{type:'nav',url:{json.dumps(login_url)},method:'GET'}}),'*');\" style=\"cursor:pointer\""
                            )
                            html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
html,body{{margin:0;padding:0;background:#1e3f75;color:white;font-family:sans-serif;font-size:14px;}}
.modal-body{{padding:24px;max-height:calc(100vh - 80px);overflow-y:auto;}}
.modal-footer{{padding:12px 24px;background:#1a3565;border-top:1px solid #2d5fa0;position:sticky;bottom:0;}}
.btn-xs.btn-success{{background:#27ae60;border:none;color:white;padding:8px 24px;font-size:14px;border-radius:6px;cursor:pointer;font-weight:600;}}
.btn-xs.btn-success:hover{{background:#219a52;}}
</style></head><body>
{inner_html}
</body></html>"""
                            title = 'pfSense — Aviso de Copyright'
                            logger.info(f"Browser: resposta JSON com HTML detectada (pfSense modal), URL: {final_url}")
                    except Exception:
                        pass

                # URL base para resolver referências relativas
                base = final_url

                def _abs(href):
                    try:
                        return urllib.parse.urljoin(base, href)
                    except Exception:
                        return href

                def _fetch_text(asset_url, timeout=20):
                    try:
                        r = self._browser_opener.open(
                            urllib.request.Request(asset_url, headers={"User-Agent": "Mozilla/5.0 (RNRemote Proxy)"}),
                            timeout=timeout,
                        )
                        ct = r.headers.get("Content-Type", "")
                        raw = r.read()
                        enc = "utf-8"
                        if "charset=" in ct:
                            enc = ct.split("charset=")[-1].split(";")[0].strip()
                        return raw.decode(enc, errors="replace")
                    except Exception as _e:
                        logger.warning(f"Browser: falha ao buscar {asset_url}: {_e}")
                        return None

                def _fetch_b64(asset_url, timeout=10):
                    try:
                        r = self._browser_opener.open(
                            urllib.request.Request(asset_url, headers={"User-Agent": "Mozilla/5.0 (RNRemote Proxy)"}),
                            timeout=timeout,
                        )
                        ct = r.headers.get("Content-Type", "image/png")
                        return f"data:{ct};base64," + base64.b64encode(r.read()).decode()
                    except Exception:
                        return None

                # Inline CSS: <link rel="stylesheet" href="..."> → <style>...</style>
                def _inline_css(m):
                    href = m.group(1) or m.group(2)
                    if not href or href.startswith("data:"):
                        return m.group(0)
                    css_url = _abs(href)
                    css = _fetch_text(css_url)
                    if css is None:
                        # Mantém o link mas com URL absoluta (relativas não resolvem no srcdoc)
                        return m.group(0).replace(href, css_url)
                    # Substitui url() dentro do CSS com data URIs
                    def _css_url(cm):
                        asset = cm.group(1).strip("'\" \t")
                        if asset.startswith("data:") or asset.startswith("#") or not asset:
                            return cm.group(0)
                        abs_asset = urllib.parse.urljoin(css_url, asset)
                        data = _fetch_b64(abs_asset)
                        if data:
                            return f"url('{data}')"
                        # Fallback: URL absoluta dentro do CSS
                        return f"url('{abs_asset}')"
                    css = _re.sub(r"url\(\s*([^)]+?)\s*\)", _css_url, css)
                    # Segue @import dentro do CSS
                    def _follow_import(im):
                        raw_url = im.group(1).strip("'\" ")
                        if raw_url.startswith("http"):
                            imp_url = raw_url
                        else:
                            imp_url = urllib.parse.urljoin(css_url, raw_url)
                        imp_css = _fetch_text(imp_url)
                        if imp_css is None:
                            return f"/* @import {imp_url} failed */"
                        return imp_css
                    css = _re.sub(r'@import\s+["\']([^"\']+)["\']', _follow_import, css)
                    return f"<style>/* {css_url} */\n{css}\n</style>"

                html = _re.sub(
                    r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\'][^>]*/?>|'
                    r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']stylesheet["\'][^>]*/?>',
                    _inline_css, html, flags=_re.IGNORECASE,
                )

                # Inline JS: <script src="..."> → <script>...</script>
                def _inline_js(m):
                    src = m.group(1)
                    if not src or src.startswith("data:"):
                        return m.group(0)
                    js_url = _abs(src)
                    js = _fetch_text(js_url)
                    if js is None:
                        # Usa URL absoluta — relativa não resolve em srcdoc
                        return m.group(0).replace(src, js_url)
                    return f"<script>/* {js_url} */\n{js}\n</script>"

                html = _re.sub(
                    r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>\s*</script>',
                    _inline_js, html, flags=_re.IGNORECASE,
                )

                # Inline imagens <img src="..."> → data URI
                def _inline_img(m):
                    src = m.group(1)
                    if not src or src.startswith("data:"):
                        return m.group(0)
                    data = _fetch_b64(_abs(src))
                    if data is None:
                        return m.group(0)
                    return m.group(0).replace(src, data)

                html = _re.sub(r'<img[^>]+src=["\']([^"\']+)["\']', _inline_img, html, flags=_re.IGNORECASE)

                # Extrai título
                title_m = _re.search(r'<title[^>]*>([^<]+)</title>', html, _re.IGNORECASE)
                title = title_m.group(1).strip() if title_m else ""

                # Remove tag <base> existente e injeta a correta
                html = _re.sub(r'<base[^>]*/?>', '', html, flags=_re.IGNORECASE)
                # Adiciona <base href> no <head> — garante que URLs não inlinadas
                # (fontes, recursos que falharam) resolvam relativamente ao pfSense
                parsed_base = urllib.parse.urlparse(final_url)
                base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
                base_tag = f'<base href="{base_origin}/">'
                if '<head>' in html.lower():
                    html = _re.sub(r'(<head[^>]*>)', r'\1' + base_tag, html, count=1, flags=_re.IGNORECASE)
                inject = PfSenseAgent._make_inject_js(final_url)
                if "</body>" in html.lower():
                    html = _re.sub(r'</body>', inject + '</body>', html, count=1, flags=_re.IGNORECASE)
                else:
                    html += inject

                return {"url": final_url, "status": resp.status,
                        "content_type": content_type, "html": html, "title": title}

            result = await loop.run_in_executor(None, _fetch)
            await self._send({
                "type": "browser_html",
                "data": result,
                "session_id": self.session_id, "timestamp": time.time(),
            })
        except Exception as e:
            logger.warning(f"Browser proxy erro: {e}")
            await self._send({
                "type": "browser_status",
                "data": {"status": "error", "error": str(e), "url": url},
                "session_id": self.session_id, "timestamp": time.time(),
            })

    # ── Auto-atualização ────────────────────────────────────────────────────────

    async def _handle_update(self, data: dict):
        import ssl as _ssl
        panel_url  = data.get("panel_url", "https://rnremote.joaoneto.tec.br").rstrip("/")
        url        = f"{panel_url}/api/agents/download/agent-pfsense.py"
        agent_path = os.path.abspath(__file__)
        tmp_path   = agent_path + ".update"

        logger.info(f"Iniciando atualização — baixando {url}")

        async def _notify(ok: bool, msg: str):
            await self._send({
                "type":       "update_agent_result",
                "data":       {"ok": ok, "message": msg, "agent_id": self.agent_id},
                "session_id": self.session_id,
                "timestamp":  time.time(),
            })

        loop = asyncio.get_running_loop()
        try:
            def _download_with_auth():
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = _ssl.CERT_NONE
                req = urllib.request.Request(url, headers={
                    "X-Agent-Id":      self.agent_id,
                    "X-Binding-Token": self.binding_token,
                })
                handler = urllib.request.HTTPSHandler(context=ctx)
                opener  = urllib.request.build_opener(handler)
                with opener.open(req, timeout=30) as resp:
                    content = resp.read()
                with open(tmp_path, "wb") as f:
                    f.write(content)

            await loop.run_in_executor(None, _download_with_auth)

            size = os.path.getsize(tmp_path)
            if size < 5000:
                raise ValueError(f"Arquivo suspeito ({size} bytes)")

            shutil.move(tmp_path, agent_path)
            logger.info("Atualização baixada — reiniciando agente...")
            await _notify(True, "Agente atualizado. Reiniciando...")

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
            await _notify(False, str(e))
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
            "username":       get_system_info()["username"],
            "cpu_count":      os.cpu_count() or 1,
            "python_version": platform.python_version(),
        }

        # OS version: pfSense version + FreeBSD kernel
        pfsense_ver = _get_pfsense_version()
        try:
            fbsd_result = subprocess.run(["freebsd-version"], capture_output=True, text=True, timeout=5)
            fbsd_ver = fbsd_result.stdout.strip()
        except Exception:
            fbsd_ver = f"{uname.release}"
        info["os_type"]    = "pfSense"
        info["os_version"] = pfsense_ver
        info["os_pretty"]  = f"pfSense {pfsense_ver} / FreeBSD {fbsd_ver}"
        info["os_name"]    = "pfSense"
        info["os_id"]      = "pfsense"

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

        async def _out(text: str):
            await self._send({
                "type": "shell_output",
                "data": {"output": text},
                "session_id": self.session_id, "timestamp": time.time(),
            })

        await _out("\r\n\033[32m[RNRemote] Iniciando terminal...\033[0m\r\n")
        try:
            self.shell = ShellSession()
            mode = self.shell.start(cols=cols, rows=rows)
            await _out(f"\033[32m[RNRemote] Shell iniciado (modo: {mode})\033[0m\r\n")
            self._shell_reader_task = asyncio.create_task(self._read_shell_output())
        except Exception as e:
            logger.error(f"Falha ao iniciar shell: {e}")
            await _out(f"\033[31m[ERRO] Falha ao iniciar shell: {e}\033[0m\r\n")
            self.shell = None

    async def _read_shell_output(self):
        loop = asyncio.get_running_loop()
        try:
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
        except asyncio.CancelledError:
            logger.info("Shell reader cancelado")
            return
        except Exception:
            logger.exception("Erro na leitura do shell")
        finally:
            logger.info("Leitura do shell finalizada — limpando")
            # NÃO chamar self._stop_shell() aqui: ele cancela self._shell_reader_task
            # que é a própria task atual, agendando CancelledError no próximo await.
            # Fazemos a limpeza diretamente sem cancelar a task atual.
            self._shell_reader_task = None
            if self.shell:
                try:
                    self.shell.stop()
                except Exception:
                    pass
                self.shell = None
            # Notifica o viewer que o terminal encerrou
            if self.session_id:
                try:
                    await self._send({
                        "type": "shell_output",
                        "data": {"output": "\r\n\033[33m[Terminal encerrado — pressione o botão Terminal para nova sessão]\033[0m\r\n"},
                        "session_id": self.session_id,
                        "timestamp": time.time(),
                    })
                except Exception:
                    pass

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
    parser.add_argument("--reconnect-delay", type=int, default=5,
                        help="Segundos entre tentativas de reconexão (padrão: 5)")
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

    # SIGHUP: ignorar — no FreeBSD pode ser enviado quando sessão PTY encerra.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    # SIGPIPE: ignorar — sem este handler, os.write() num fd fechado (PTY slave
    # encerrado) gera SIGPIPE que mata o processo silenciosamente no FreeBSD.
    # Com SIG_IGN, os.write() levanta BrokenPipeError (OSError) em vez disso.
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Agente encerrado.")


if __name__ == "__main__":
    main()
