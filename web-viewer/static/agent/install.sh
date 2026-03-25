#!/bin/bash
# RNRemote - Instalador do Agente Linux
# Uso: bash <(curl -fsSL https://rnremote.joaoneto.tec.br/static/agent/install.sh)

set -e

PANEL_URL="https://rnremote.joaoneto.tec.br"
INSTALL_DIR="/opt/rnremote"
CONFIG_DIR="/etc/remotelink"
CONFIG_FILE="$CONFIG_DIR/agent.json"
SERVICE_FILE="/etc/systemd/system/rnremote-agent.service"

# ── Cores ─────────────────────────────────────────────────────────────────────
BOLD="\033[1m"; GREEN="\033[32m"; RED="\033[31m"; CYAN="\033[36m"
DIM="\033[2m"; RESET="\033[0m"
ok()   { echo -e "  ${GREEN}✔${RESET}  $1"; }
err()  { echo -e "  ${RED}✘${RESET}  $1"; exit 1; }
info() { echo -e "  ${DIM}→${RESET}  $1"; }

# ── Root ──────────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    err "Execute como root: sudo bash install.sh"
fi

echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════════╗"
echo -e "║    RNRemote — Instalador do Agente     ║"
echo -e "╚══════════════════════════════════════════╝${RESET}\n"

# ── Passo 1: Dependências ─────────────────────────────────────────────────────
echo -e "${BOLD}[1/5] Verificando dependências...${RESET}"

command -v python3 &>/dev/null || err "python3 não encontrado. Instale com: apt install python3"

PYTHON=$(command -v python3)
PIP=$(command -v pip3 2>/dev/null || echo "")

if [ -z "$PIP" ]; then
    info "pip3 não encontrado, instalando..."
    apt-get install -y python3-pip -qq 2>/dev/null || \
    $PYTHON -m ensurepip --upgrade 2>/dev/null || \
    err "Não foi possível instalar pip3"
    PIP=$(command -v pip3)
fi

info "Instalando websockets..."
$PYTHON -m pip install --quiet websockets 2>/dev/null || \
$PYTHON -m pip install --quiet websockets --break-system-packages 2>/dev/null || \
apt-get install -y python3-websockets -qq 2>/dev/null || \
err "Não foi possível instalar websockets"

ok "Dependências OK"

# ── Passo 2: Download dos arquivos ────────────────────────────────────────────
echo -e "\n${BOLD}[2/5] Baixando arquivos...${RESET}"

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

DL=""
if command -v curl &>/dev/null; then DL="curl -fsSL -o";
elif command -v wget &>/dev/null; then DL="wget -qO";
else err "curl ou wget são necessários"; fi

$DL "$INSTALL_DIR/agent.py" "$PANEL_URL/static/agent/agent.py"   || err "Falha ao baixar agent.py"
$DL "$INSTALL_DIR/setup.py" "$PANEL_URL/static/agent/setup.py"   || err "Falha ao baixar setup.py"
chmod +x "$INSTALL_DIR/agent.py" "$INSTALL_DIR/setup.py"

ok "Arquivos salvos em $INSTALL_DIR"

# ── Passo 3: Serviço systemd ──────────────────────────────────────────────────
echo -e "\n${BOLD}[3/5] Instalando serviço systemd...${RESET}"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=RNRemote Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$PYTHON $INSTALL_DIR/agent.py --config $CONFIG_FILE
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "Serviço instalado"

# ── Passo 4: Setup interativo ─────────────────────────────────────────────────
echo -e "\n${BOLD}[4/5] Configurando o agente...${RESET}"
echo -e "${DIM}Você precisará informar suas credenciais do painel RN Remote.${RESET}\n"

$PYTHON "$INSTALL_DIR/setup.py" --panel "$PANEL_URL" || err "Setup falhou"

# ── Passo 5: Iniciar serviço ──────────────────────────────────────────────────
echo -e "\n${BOLD}[5/5] Iniciando serviço...${RESET}"

systemctl enable rnremote-agent --quiet
systemctl restart rnremote-agent
sleep 2

if systemctl is-active --quiet rnremote-agent; then
    ok "Serviço rodando"
else
    echo -e "  ${RED}✘${RESET}  Serviço não iniciou. Verifique com: journalctl -u rnremote-agent -n 20"
    exit 1
fi

# ── Conclusão ─────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════╗"
echo -e "║     Instalação concluída com sucesso!    ║"
echo -e "╚══════════════════════════════════════════╝${RESET}"
echo -e "\n  Painel: ${CYAN}$PANEL_URL${RESET}"
echo -e "  Config: ${DIM}$CONFIG_FILE${RESET}"
echo -e "  Logs:   ${DIM}journalctl -u rnremote-agent -f${RESET}\n"
