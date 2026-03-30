#!/bin/bash
# RNRemote - Instalação / Atualização do agente (CentOS Stream 9 / RHEL 9)
# Uso: sudo bash install-centos.sh

set -e

BOLD="\033[1m"; GREEN="\033[32m"; RED="\033[31m"; CYAN="\033[36m"; YELLOW="\033[33m"; DIM="\033[2m"; RESET="\033[0m"
ok()   { echo -e "  ${GREEN}✔${RESET}  $1"; }
err()  { echo -e "  ${RED}✘${RESET}  $1"; exit 1; }
info() { echo -e "  ${DIM}→${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }

echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════════╗"
echo -e "║  RNRemote — Instalação (CentOS/RHEL 9)   ║"
echo -e "╚══════════════════════════════════════════╝${RESET}\n"

# ── Root ──────────────────────────────────────────────────────────────────────
[ "$EUID" -ne 0 ] && err "Execute como root: sudo bash install-centos.sh"

SERVICE="rnremote-agent"
INSTALL_DIR="/opt/rnremote"
CONF_DIR="/etc/rnremote"
SVC_FILE="/etc/systemd/system/${SERVICE}.service"
PANEL_URL="https://rnremote.joaoneto.tec.br"

# ── Garante python3 e pip ─────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    info "Instalando python3..."
    dnf install -y python3 -q
fi
if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null 2>&1; then
    info "Instalando python3-pip..."
    dnf install -y python3-pip -q 2>/dev/null || \
    dnf install -y python3-setuptools -q 2>/dev/null || true
fi
PYTHON=$(command -v python3)

# ── Detecta versão local ───────────────────────────────────────────────────────
LOCAL_VERSION=""
if [ -f "$INSTALL_DIR/agent.py" ]; then
    LOCAL_VERSION=$(grep -oP 'AGENT_VERSION\s*=\s*"\K[^"]+' "$INSTALL_DIR/agent.py" 2>/dev/null || true)
fi

# ── Detecta versão remota ──────────────────────────────────────────────────────
REMOTE_VERSION=$(curl -fsSL --max-time 10 "$PANEL_URL/api/agent/version" 2>/dev/null \
    | grep -oP '"version"\s*:\s*"\K[^"]+' || true)

echo -e "  Versão local  : ${DIM}${LOCAL_VERSION:-desconhecida}${RESET}"
echo -e "  Versão remota : ${DIM}${REMOTE_VERSION:-indisponível}${RESET}\n"

# ── Caso 1: serviço já está rodando → apenas atualiza ─────────────────────────
if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then

    if [ -n "$REMOTE_VERSION" ] && [ "$LOCAL_VERSION" = "$REMOTE_VERSION" ]; then
        ok "Agente já está na versão mais recente (${REMOTE_VERSION}) e rodando."
        exit 0
    fi

    echo -e "${BOLD}[1/3] Atualizando agent.py...${RESET}"
    mkdir -p "$INSTALL_DIR"
    if curl -fsSL --max-time 30 "$PANEL_URL/static/agent/agent.py" -o "$INSTALL_DIR/agent.py.new" 2>/dev/null; then
        SIZE=$(wc -c < "$INSTALL_DIR/agent.py.new")
        if [ "$SIZE" -lt 5000 ]; then
            rm -f "$INSTALL_DIR/agent.py.new"
            err "Arquivo baixado parece inválido ($SIZE bytes). Abortando."
        fi
        mv "$INSTALL_DIR/agent.py.new" "$INSTALL_DIR/agent.py"
        chmod +x "$INSTALL_DIR/agent.py"
        NEW_VER=$(grep -oP 'AGENT_VERSION\s*=\s*"\K[^"]+' "$INSTALL_DIR/agent.py" 2>/dev/null || true)
        ok "agent.py atualizado${NEW_VER:+ para v${NEW_VER}}"
    else
        err "Não foi possível baixar agent.py do painel ($PANEL_URL)"
    fi

    echo -e "\n${BOLD}[2/3] Reiniciando serviço...${RESET}"
    systemctl restart "$SERVICE"
    sleep 2
    ok "Serviço ${SERVICE} reiniciado"

    echo -e "\n${BOLD}[3/3] Verificando...${RESET}"
    if systemctl is-active --quiet "$SERVICE"; then
        ok "Serviço ${SERVICE} rodando"
    else
        echo -e "  ${RED}✘${RESET}  Serviço não iniciou. Verifique com:"
        echo -e "      journalctl -u ${SERVICE} -n 30"
        exit 1
    fi

    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════╗"
    echo -e "║        Atualização concluída!            ║"
    echo -e "╚══════════════════════════════════════════╝${RESET}"
    echo -e "\n  Serviço : ${CYAN}${SERVICE}${RESET}"
    echo -e "  Versão  : ${DIM}${NEW_VER:-${REMOTE_VERSION}}${RESET}"
    echo -e "  Logs    : ${DIM}journalctl -u ${SERVICE} -f${RESET}\n"
    exit 0
fi

# ── Caso 2: instalação nova ────────────────────────────────────────────────────

echo -e "${BOLD}[1/5] Registrando agente no painel...${RESET}"
echo -e "  ${DIM}Informe as credenciais de administrador do painel RNRemote${RESET}\n"

read -rp "  E-mail do admin: " ADMIN_EMAIL
[ -z "$ADMIN_EMAIL" ] && err "E-mail é obrigatório."

read -rsp "  Senha do admin: " ADMIN_PASS
echo
[ -z "$ADMIN_PASS" ] && err "Senha é obrigatória."

DEFAULT_NICKNAME=$(hostname 2>/dev/null || echo "agente")
read -rp "  Nome desta máquina [${DEFAULT_NICKNAME}]: " INPUT_NICK
NICKNAME="${INPUT_NICK:-$DEFAULT_NICKNAME}"

read -rsp "  Senha de acesso ao agente (usada para conectar): " ACCESS_PASS
echo
[ -z "$ACCESS_PASS" ] && err "Senha de acesso é obrigatória."

info "Autenticando no painel..."
LOGIN_RESP=$(curl -fsSL --max-time 15 -X POST "$PANEL_URL/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null) || \
    err "Não foi possível conectar ao painel ($PANEL_URL)"

JWT=$(echo "$LOGIN_RESP" | grep -oP '"token"\s*:\s*"\K[^"]+' || true)
[ -z "$JWT" ] && err "Login falhou. Verifique e-mail e senha."
ok "Autenticado no painel"

info "Registrando agente..."
PROV_RESP=$(curl -fsSL --max-time 15 -X POST "$PANEL_URL/api/agents/provision" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${JWT}" \
    -d "{\"nickname\":\"${NICKNAME}\",\"access_password\":\"${ACCESS_PASS}\"}" 2>/dev/null) || \
    err "Não foi possível provisionar o agente no painel"

AGENT_ID=$(echo "$PROV_RESP" | grep -oP '"agent_id"\s*:\s*"\K[^"]+' || true)
BINDING_SECRET=$(echo "$PROV_RESP" | grep -oP '"binding_secret"\s*:\s*"\K[^"]+' || true)

[ -z "$AGENT_ID" ] && err "Falha ao registrar agente: $PROV_RESP"
ok "Agente registrado: ID ${AGENT_ID} | Nome: ${NICKNAME}"

# ── Dependências Python ───────────────────────────────────────────────────────
echo -e "\n${BOLD}[2/5] Verificando dependências Python...${RESET}"

for pkg in websockets mss pillow pynput; do
    if ! $PYTHON -c "import ${pkg/pillow/PIL}" 2>/dev/null; then
        info "Instalando $pkg..."
        $PYTHON -m pip install --quiet "$pkg" --break-system-packages 2>/dev/null || \
        $PYTHON -m pip install --quiet "$pkg" 2>/dev/null || \
        dnf install -y "python3-${pkg}" -q 2>/dev/null || true
    fi
done

$PYTHON -c "import websockets" 2>/dev/null && ok "Dependências OK" || \
    err "websockets não instalado. Execute: pip3 install websockets --break-system-packages"

# ── Baixa agent.py ─────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[3/5] Baixando agent.py...${RESET}"

mkdir -p "$INSTALL_DIR"
if curl -fsSL --max-time 30 "$PANEL_URL/static/agent/agent.py" -o "$INSTALL_DIR/agent.py.new" 2>/dev/null; then
    SIZE=$(wc -c < "$INSTALL_DIR/agent.py.new")
    if [ "$SIZE" -lt 5000 ]; then
        rm -f "$INSTALL_DIR/agent.py.new"
        err "Arquivo baixado parece inválido ($SIZE bytes). Abortando."
    fi
    mv "$INSTALL_DIR/agent.py.new" "$INSTALL_DIR/agent.py"
    chmod +x "$INSTALL_DIR/agent.py"
    NEW_VER=$(grep -oP 'AGENT_VERSION\s*=\s*"\K[^"]+' "$INSTALL_DIR/agent.py" 2>/dev/null || true)
    ok "agent.py baixado${NEW_VER:+ (v${NEW_VER})}"
else
    err "Não foi possível baixar agent.py de $PANEL_URL"
fi

# ── Cria configuração ──────────────────────────────────────────────────────────
echo -e "\n${BOLD}[4/5] Criando configuração...${RESET}"

mkdir -p "$CONF_DIR"
cat > "$CONF_DIR/agent.json" <<EOF
{
  "relay_url":      "wss://rnremote.joaoneto.tec.br/ws",
  "agent_id":       "${AGENT_ID}",
  "password":       "${ACCESS_PASS}",
  "binding_secret": "${BINDING_SECRET}"
}
EOF
chmod 600 "$CONF_DIR/agent.json"
ok "Config criada em $CONF_DIR/agent.json"

# ── Cria e inicia serviço ─────────────────────────────────────────────────────
echo -e "\n${BOLD}[5/5] Instalando serviço systemd...${RESET}"

cat > "$SVC_FILE" <<EOF
[Unit]
Description=RNRemote Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$PYTHON $INSTALL_DIR/agent.py --config $CONF_DIR/agent.json
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE" --quiet
systemctl start "$SERVICE"
sleep 2

if systemctl is-active --quiet "$SERVICE"; then
    ok "Serviço ${SERVICE} rodando"
else
    echo -e "  ${RED}✘${RESET}  Serviço não iniciou. Verifique com:"
    echo -e "      journalctl -u ${SERVICE} -n 30"
    exit 1
fi

FINAL_VER=$(grep -oP 'AGENT_VERSION\s*=\s*"\K[^"]+' "$INSTALL_DIR/agent.py" 2>/dev/null || echo "desconhecida")

echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════╗"
echo -e "║      Instalação concluída com sucesso!   ║"
echo -e "╚══════════════════════════════════════════╝${RESET}"
echo -e "\n  Serviço : ${CYAN}${SERVICE}${RESET}"
echo -e "  Agente  : ${DIM}${AGENT_ID} (${NICKNAME})${RESET}"
echo -e "  Versão  : ${DIM}${FINAL_VER}${RESET}"
echo -e "  Config  : ${DIM}${CONF_DIR}/agent.json${RESET}"
echo -e "  Logs    : ${DIM}journalctl -u ${SERVICE} -f${RESET}\n"
