#!/bin/sh
# RNRemote - Script de instalação do agente pfSense
# Execute no pfSense como root:
#   curl -fsSL https://rnremote.joaoneto.tec.br/static/agent/install-pfsense.sh | sh

set -e

PANEL_URL="https://rnremote.joaoneto.tec.br"
AGENT_DIR="/usr/local/rnremote"
AGENT_BIN="${AGENT_DIR}/agent.py"
CONFIG_DIR="/usr/local/etc/rnremote"
CONFIG_FILE="${CONFIG_DIR}/agent.json"
RC_SCRIPT="/usr/local/etc/rc.d/rnremote_agent"

echo "==> RNRemote pfSense Agent Installer"
echo ""

# ── Verificar root ───────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: Execute como root."
    exit 1
fi

# ── Verificar pfSense / FreeBSD ──────────────────────────────────────────────
if ! uname -s | grep -q FreeBSD; then
    echo "ERRO: Este script é exclusivo para pfSense/FreeBSD."
    exit 1
fi

# ── Instalar Python3 se necessário ───────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    echo "==> Instalando Python3..."
    pkg install -y python3
fi

# ── Instalar websockets via pip ──────────────────────────────────────────────
if ! python3 -c "import websockets" 2>/dev/null; then
    echo "==> Instalando websockets..."
    if ! command -v pip >/dev/null 2>&1; then
        pkg install -y py311-pip 2>/dev/null || pkg install -y python3-pip 2>/dev/null || \
            python3 -m ensurepip --upgrade
    fi
    pip install --quiet websockets
fi

# ── Criar diretórios ─────────────────────────────────────────────────────────
mkdir -p "${AGENT_DIR}" "${CONFIG_DIR}"

# ── Baixar agente ────────────────────────────────────────────────────────────
echo "==> Baixando agente..."
fetch -q -o "${AGENT_BIN}" "${PANEL_URL}/static/agent/agent-pfsense.py" || \
    python3 -c "import urllib.request; urllib.request.urlretrieve('${PANEL_URL}/static/agent/agent-pfsense.py', '${AGENT_BIN}')"
chmod 750 "${AGENT_BIN}"

# ── Configurar agente ────────────────────────────────────────────────────────
if [ ! -f "${CONFIG_FILE}" ]; then
    printf "\n"
    printf "==> Configuração do agente\n"
    printf "Relay URL [wss://rnremote.joaoneto.tec.br/ws]: "
    read RELAY_URL
    RELAY_URL="${RELAY_URL:-wss://rnremote.joaoneto.tec.br/ws}"

    printf "ID do agente (9 dígitos): "
    read AGENT_ID

    printf "Senha do agente: "
    read -s AGENT_PASS
    printf "\n"

    cat > "${CONFIG_FILE}" <<EOF
{
  "relay_url": "${RELAY_URL}",
  "agent_id": "${AGENT_ID}",
  "password": "${AGENT_PASS}"
}
EOF
    chmod 600 "${CONFIG_FILE}"
    echo "==> Config salva em ${CONFIG_FILE}"
else
    echo "==> Config existente mantida: ${CONFIG_FILE}"
fi

# ── Criar rc.d script ────────────────────────────────────────────────────────
cat > "${RC_SCRIPT}" <<'RCEOF'
#!/bin/sh
#
# PROVIDE: rnremote_agent
# REQUIRE: networking
# KEYWORD: shutdown

. /etc/rc.subr

name="rnremote_agent"
rcvar="rnremote_agent_enable"
command="/usr/local/bin/python3"
command_args="/usr/local/rnremote/agent.py --config /usr/local/etc/rnremote/agent.json"
pidfile="/var/run/${name}.pid"
start_precmd="rnremote_prestart"

rnremote_prestart()
{
    touch "${pidfile}"
}

load_rc_config $name
: ${rnremote_agent_enable:="NO"}

run_rc_command "$1"
RCEOF

chmod 555 "${RC_SCRIPT}"

# ── Habilitar e iniciar serviço ──────────────────────────────────────────────
if ! grep -q "rnremote_agent_enable" /etc/rc.conf 2>/dev/null; then
    echo 'rnremote_agent_enable="YES"' >> /etc/rc.conf
fi

echo "==> Iniciando serviço..."
service rnremote_agent start 2>/dev/null || \
    /usr/local/bin/python3 "${AGENT_BIN}" --config "${CONFIG_FILE}" &

echo ""
echo "==> Instalação concluída!"
echo "    Agente: ${AGENT_BIN}"
echo "    Config: ${CONFIG_FILE}"
echo "    Serviço: service rnremote_agent {start|stop|restart|status}"
