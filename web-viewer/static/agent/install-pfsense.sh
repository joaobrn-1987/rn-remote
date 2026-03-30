#!/bin/sh
# RNRemote - Instalador do Agente pfSense
# Execute no pfSense como root:
#   curl -fsSL https://rnremote.joaoneto.tec.br/static/agent/install-pfsense.sh | sh

PANEL_URL="https://rnremote.joaoneto.tec.br"
RELAY_URL="wss://rnremote.joaoneto.tec.br/ws"
AGENT_DIR="/usr/local/rnremote"
AGENT_BIN="${AGENT_DIR}/agent.py"
CONFIG_DIR="/usr/local/etc/rnremote"
CONFIG_FILE="${CONFIG_DIR}/agent.json"
RC_SCRIPT="/usr/local/etc/rc.d/rnremote_agent"

ok()   { printf "  [OK] %s\n" "$1"; }
err()  { printf "  [X]  %s\n" "$1" >&2; exit 1; }
info() { printf "  ->   %s\n" "$1"; }
warn() { printf "  [!]  %s\n" "$1"; }
step() { printf "\n[%s] %s\n" "$1" "$2"; }

printf "\n"
printf "  ╔══════════════════════════════════════════╗\n"
printf "  ║   RNRemote — Instalador do Agente        ║\n"
printf "  ║   pfSense / FreeBSD                      ║\n"
printf "  ╚══════════════════════════════════════════╝\n\n"

# ── Root ─────────────────────────────────────────────────────────────────────
[ "$(id -u)" -ne 0 ] && err "Execute como root."
uname -s | grep -q FreeBSD || err "Este script é exclusivo para pfSense/FreeBSD."

# ── Passo 1: Python ──────────────────────────────────────────────────────────
step "1/5" "Verificando Python 3..."

PYTHON=""
for cmd in python3 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    info "Instalando Python..."
    for pkg in python311 python310 python39 python38; do
        pkg install -y "$pkg" 2>/dev/null && break
    done
    for cmd in python3 python3.11 python3.10 python3.9; do
        command -v "$cmd" >/dev/null 2>&1 && PYTHON="$cmd" && break
    done
fi

[ -z "$PYTHON" ] && err "Não foi possível instalar Python3. Tente: pkg install python311"
ok "Python: $PYTHON ($($PYTHON --version 2>&1))"

# Cria symlink python3 se não existir (necessário para o serviço)
if ! command -v python3 >/dev/null 2>&1; then
    PYABS=$(command -v "$PYTHON")
    ln -sf "$PYABS" /usr/local/bin/python3
    ok "Symlink: python3 -> $PYABS"
fi

# ── Passo 2: Dependências ────────────────────────────────────────────────────
step "2/5" "Instalando dependências Python..."

# pip
if ! command -v pip3 >/dev/null 2>&1 && ! $PYTHON -m pip --version >/dev/null 2>&1; then
    PYVER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')" 2>/dev/null || echo "311")
    pkg install -y "py${PYVER}-pip" 2>/dev/null || \
        $PYTHON -m ensurepip --upgrade 2>/dev/null || true
fi

PIP=""
for cmd in pip3 pip3.11 pip3.10 pip; do
    command -v "$cmd" >/dev/null 2>&1 && PIP="$cmd" && break
done
[ -z "$PIP" ] && PIP="$PYTHON -m pip"

$PIP install --quiet websockets 2>/dev/null || true
$PYTHON -c "import websockets" 2>/dev/null || err "Não foi possível instalar websockets. Tente: $PIP install websockets"
ok "Dependências OK"

# ── Passo 3: Configuração (login no painel) ──────────────────────────────────
step "3/5" "Configurando o agente..."

NEED_CONFIG=1
if [ -f "$CONFIG_FILE" ]; then
    printf "  Configuração existente encontrada. Reconfigurar? [s/N]: "
    read -r RESP </dev/tty
    case "$RESP" in
        [sSyY]*) NEED_CONFIG=1 ;;
        *)       NEED_CONFIG=0; ok "Configuração mantida." ;;
    esac
fi

if [ "$NEED_CONFIG" -eq 1 ]; then
    printf "\n  Informe suas credenciais do painel RNRemote:\n\n"

    # E-mail
    printf "  E-mail: "
    read -r EMAIL </dev/tty

    # Senha do painel
    printf "  Senha do painel: "
    stty -echo </dev/tty 2>/dev/null
    read -r PANEL_PASS </dev/tty
    stty echo </dev/tty 2>/dev/null
    printf "\n"

    # Login na API
    LOGIN_RESP=$(curl -fsSL --max-time 15 -X POST \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${EMAIL}\",\"password\":\"${PANEL_PASS}\"}" \
        "${PANEL_URL}/api/login" 2>/dev/null) || err "Falha ao conectar ao painel."

    TOKEN=$($PYTHON -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('token',''))" <<EOF
$LOGIN_RESP
EOF
)
    LOGIN_OK=$($PYTHON -c "import sys,json; d=json.loads(sys.stdin.read()); print('ok' if d.get('ok') else d.get('error','erro'))" <<EOF
$LOGIN_RESP
EOF
)

    if [ "$LOGIN_OK" != "ok" ]; then
        err "Login inválido: $LOGIN_OK"
    fi
    ok "Autenticado no painel"

    # Apelido da máquina
    DEFAULT_NICK=$(hostname)
    printf "\n  Apelido para esta máquina [%s]: " "$DEFAULT_NICK"
    read -r NICK </dev/tty
    [ -z "$NICK" ] && NICK="$DEFAULT_NICK"

    # Senha de acesso remoto
    printf "\n  Defina a senha de acesso remoto a esta máquina:\n"
    ACCESS_PASS=""
    while [ -z "$ACCESS_PASS" ]; do
        printf "  Senha de acesso: "
        stty -echo </dev/tty 2>/dev/null
        read -r P1 </dev/tty
        stty echo </dev/tty 2>/dev/null
        printf "\n  Confirme: "
        stty -echo </dev/tty 2>/dev/null
        read -r P2 </dev/tty
        stty echo </dev/tty 2>/dev/null
        printf "\n"
        if [ -z "$P1" ]; then
            warn "Senha não pode ser vazia."
        elif [ "$P1" != "$P2" ]; then
            warn "Senhas não coincidem. Tente novamente."
        else
            ACCESS_PASS="$P1"
        fi
    done

    # Provisionar agente no painel
    # Escapa aspas simples no nick para JSON seguro
    NICK_ESC=$(printf '%s' "$NICK" | sed "s/'/\\\\'/g")
    PASS_ESC=$(printf '%s' "$ACCESS_PASS" | sed 's/"/\\"/g')

    PROV_RESP=$(curl -fsSL --max-time 15 -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "{\"nickname\":\"${NICK_ESC}\",\"access_password\":\"${PASS_ESC}\"}" \
        "${PANEL_URL}/api/agents/provision" 2>/dev/null) || err "Falha ao registrar agente."

    AGENT_ID=$($PYTHON -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('agent_id',''))" <<EOF
$PROV_RESP
EOF
)
    BINDING_SECRET=$($PYTHON -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('binding_secret',''))" <<EOF
$PROV_RESP
EOF
)
    PROV_OK=$($PYTHON -c "import sys,json; d=json.loads(sys.stdin.read()); print('ok' if d.get('ok') else d.get('error','erro'))" <<EOF
$PROV_RESP
EOF
)

    if [ "$PROV_OK" != "ok" ] || [ -z "$AGENT_ID" ]; then
        err "Registro falhou: $PROV_OK"
    fi
    ok "Agente registrado — ID: $AGENT_ID"

    # Salva config
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<EOF
{
  "relay_url": "${RELAY_URL}",
  "agent_id": "${AGENT_ID}",
  "password": "${ACCESS_PASS}",
  "binding_secret": "${BINDING_SECRET}",
  "nickname": "${NICK}"
}
EOF
    chmod 600 "$CONFIG_FILE"
    ok "Config salva em $CONFIG_FILE"
fi

# ── Passo 4: Download do agente ──────────────────────────────────────────────
step "4/5" "Baixando agente..."

mkdir -p "$AGENT_DIR"
fetch -q -o "$AGENT_BIN" "${PANEL_URL}/static/agent/agent-pfsense.py" 2>/dev/null || \
    $PYTHON -c "import urllib.request; urllib.request.urlretrieve('${PANEL_URL}/static/agent/agent-pfsense.py', '${AGENT_BIN}')" || \
    err "Falha ao baixar o agente."
chmod 750 "$AGENT_BIN"
ok "Agente salvo em $AGENT_BIN"

# ── Passo 5: Serviço rc.d ────────────────────────────────────────────────────
step "5/5" "Instalando serviço..."

PYTHON_ABS=$(command -v python3)

cat > "$RC_SCRIPT" <<RCEOF
#!/bin/sh
#
# PROVIDE: rnremote_agent
# REQUIRE: networking
# KEYWORD: shutdown

. /etc/rc.subr

name="rnremote_agent"
rcvar="rnremote_agent_enable"
pidfile="/var/run/\${name}.pid"
logfile="/var/log/rnremote.log"

# Usa /usr/sbin/daemon para daemonizar o processo Python
command="/usr/sbin/daemon"
command_args="-p \${pidfile} -o \${logfile} ${PYTHON_ABS} ${AGENT_BIN} --config ${CONFIG_FILE}"

load_rc_config \$name
: \${rnremote_agent_enable:="NO"}

run_rc_command "\$1"
RCEOF

chmod 555 "$RC_SCRIPT"

grep -q "rnremote_agent_enable" /etc/rc.conf 2>/dev/null || \
    echo 'rnremote_agent_enable="YES"' >> /etc/rc.conf

# Para instância anterior se existir
service rnremote_agent stop 2>/dev/null || true
# Mata qualquer processo restante
pkill -f "${AGENT_BIN}" 2>/dev/null || true
sleep 1

service rnremote_agent start
sleep 2

# Verifica se está rodando
if [ -f "/var/run/rnremote_agent.pid" ] && kill -0 "$(cat /var/run/rnremote_agent.pid 2>/dev/null)" 2>/dev/null; then
    ok "Serviço rodando (PID $(cat /var/run/rnremote_agent.pid))"
else
    warn "Serviço não iniciou via rc.d. Iniciando diretamente..."
    /usr/sbin/daemon -p /var/run/rnremote_agent.pid -o /var/log/rnremote.log \
        "$PYTHON_ABS" "$AGENT_BIN" --config "$CONFIG_FILE"
    sleep 1
    if [ -f "/var/run/rnremote_agent.pid" ] && kill -0 "$(cat /var/run/rnremote_agent.pid 2>/dev/null)" 2>/dev/null; then
        ok "Agente iniciado (PID $(cat /var/run/rnremote_agent.pid))"
    else
        warn "Verifique os logs: tail -f /var/log/rnremote.log"
    fi
fi

printf "\n"
printf "  ╔══════════════════════════════════════════╗\n"
printf "  ║      Instalação concluída com sucesso!   ║\n"
printf "  ╚══════════════════════════════════════════╝\n\n"
printf "  Agente  : %s\n" "$AGENT_BIN"
printf "  Config  : %s\n" "$CONFIG_FILE"
printf "  Serviço : service rnremote_agent {start|stop|restart|status}\n"
printf "  Logs    : tail -f /var/log/rnremote.log\n\n"
