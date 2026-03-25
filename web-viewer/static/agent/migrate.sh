#!/bin/bash
# RNRemote - Instalação / Migração / Atualização do agente
# Uso: sudo bash migrate.sh

set -e

BOLD="\033[1m"; GREEN="\033[32m"; RED="\033[31m"; CYAN="\033[36m"; YELLOW="\033[33m"; DIM="\033[2m"; RESET="\033[0m"
ok()   { echo -e "  ${GREEN}✔${RESET}  $1"; }
err()  { echo -e "  ${RED}✘${RESET}  $1"; exit 1; }
info() { echo -e "  ${DIM}→${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }

echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════════╗"
echo -e "║   RNRemote — Agente: Install/Migrate     ║"
echo -e "╚══════════════════════════════════════════╝${RESET}\n"

# ── Root ──────────────────────────────────────────────────────────────────────
[ "$EUID" -ne 0 ] && err "Execute como root: sudo bash migrate.sh"

OLD_SERVICE="remotelink-agent"
NEW_SERVICE="rnremote-agent"
OLD_DIR="/opt/remotelink"
NEW_DIR="/opt/rnremote"
OLD_CONF="/etc/remotelink"
NEW_CONF="/etc/rnremote"
OLD_SVC_FILE="/etc/systemd/system/${OLD_SERVICE}.service"
NEW_SVC_FILE="/etc/systemd/system/${NEW_SERVICE}.service"
PANEL_URL="https://rnremote.joaoneto.tec.br"
PYTHON=$(command -v python3)

# ── Detecta versão local ───────────────────────────────────────────────────────
LOCAL_VERSION=""
if [ -f "$NEW_DIR/agent.py" ]; then
    LOCAL_VERSION=$(grep -oP 'AGENT_VERSION\s*=\s*"\K[^"]+' "$NEW_DIR/agent.py" 2>/dev/null || true)
fi

# ── Detecta versão remota ──────────────────────────────────────────────────────
REMOTE_VERSION=$(curl -fsSL --max-time 10 "$PANEL_URL/api/agent/version" 2>/dev/null \
    | grep -oP '"version"\s*:\s*"\K[^"]+' || true)

echo -e "  Versão local  : ${DIM}${LOCAL_VERSION:-desconhecida}${RESET}"
echo -e "  Versão remota : ${DIM}${REMOTE_VERSION:-indisponível}${RESET}\n"

# ── Caso 1: serviço novo já está rodando ──────────────────────────────────────
if systemctl is-active --quiet "$NEW_SERVICE" 2>/dev/null; then

    if [ -n "$REMOTE_VERSION" ] && [ "$LOCAL_VERSION" = "$REMOTE_VERSION" ]; then
        ok "Agente já está na versão mais recente (${REMOTE_VERSION}) e rodando."
        exit 0
    fi

    echo -e "${BOLD}[1/3] Atualizando agent.py...${RESET}"
    mkdir -p "$NEW_DIR"
    if curl -fsSL --max-time 30 "$PANEL_URL/static/agent/agent.py" -o "$NEW_DIR/agent.py.new" 2>/dev/null; then
        SIZE=$(wc -c < "$NEW_DIR/agent.py.new")
        if [ "$SIZE" -lt 5000 ]; then
            rm -f "$NEW_DIR/agent.py.new"
            err "Arquivo baixado parece inválido ($SIZE bytes). Abortando."
        fi
        mv "$NEW_DIR/agent.py.new" "$NEW_DIR/agent.py"
        chmod +x "$NEW_DIR/agent.py"
        NEW_VER=$(grep -oP 'AGENT_VERSION\s*=\s*"\K[^"]+' "$NEW_DIR/agent.py" 2>/dev/null || true)
        ok "agent.py atualizado${NEW_VER:+ para v${NEW_VER}}"
    else
        err "Não foi possível baixar agent.py do painel ($PANEL_URL)"
    fi

    echo -e "\n${BOLD}[2/3] Reiniciando serviço...${RESET}"
    systemctl restart "$NEW_SERVICE"
    sleep 2
    ok "Serviço ${NEW_SERVICE} reiniciado"

    echo -e "\n${BOLD}[3/3] Verificando...${RESET}"
    if systemctl is-active --quiet "$NEW_SERVICE"; then
        ok "Serviço ${NEW_SERVICE} rodando"
    else
        echo -e "  ${RED}✘${RESET}  Serviço não iniciou. Verifique com:"
        echo -e "      journalctl -u ${NEW_SERVICE} -n 30"
        exit 1
    fi

    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════╗"
    echo -e "║        Atualização concluída!            ║"
    echo -e "╚══════════════════════════════════════════╝${RESET}"
    echo -e "\n  Serviço : ${CYAN}${NEW_SERVICE}${RESET}"
    echo -e "  Versão  : ${DIM}${NEW_VER:-${REMOTE_VERSION}}${RESET}"
    echo -e "  Logs    : ${DIM}journalctl -u ${NEW_SERVICE} -f${RESET}\n"
    exit 0
fi

# ── Caso 2: migração remotelink → rnremote (ou instalação do zero) ─────────────

# ── Verifica instalação antiga ────────────────────────────────────────────────
echo -e "${BOLD}[1/5] Verificando instalação existente...${RESET}"

if [ ! -f "$OLD_CONF/agent.json" ] && [ ! -f "$NEW_CONF/agent.json" ]; then
    err "Nenhuma configuração encontrada em $OLD_CONF/agent.json nem $NEW_CONF/agent.json"
fi

# Se config já está no novo caminho, só recria o serviço
if [ -f "$NEW_CONF/agent.json" ] && [ ! -f "$OLD_CONF/agent.json" ]; then
    info "Config já em $NEW_CONF — apenas recriando serviço"
    CONFIG_ALREADY_MOVED=1
else
    CONFIG_ALREADY_MOVED=0
fi

ok "Verificação concluída"

# ── Para e desativa serviço antigo ────────────────────────────────────────────
echo -e "\n${BOLD}[2/5] Parando serviço antigo...${RESET}"

if systemctl is-active --quiet "$OLD_SERVICE" 2>/dev/null; then
    systemctl stop "$OLD_SERVICE"
    ok "Serviço ${OLD_SERVICE} parado"
else
    info "Serviço ${OLD_SERVICE} não estava rodando"
fi

if systemctl is-enabled --quiet "$OLD_SERVICE" 2>/dev/null; then
    systemctl disable "$OLD_SERVICE"
    ok "Serviço ${OLD_SERVICE} desativado"
fi

# ── Copia/baixa arquivos ───────────────────────────────────────────────────────
echo -e "\n${BOLD}[3/5] Migrando arquivos...${RESET}"

if [ "$CONFIG_ALREADY_MOVED" -eq 0 ]; then
    mkdir -p "$NEW_CONF"
    cp "$OLD_CONF/agent.json" "$NEW_CONF/agent.json"
    chmod 600 "$NEW_CONF/agent.json"
    ok "Config copiada: $OLD_CONF/agent.json → $NEW_CONF/agent.json"
fi

mkdir -p "$NEW_DIR"

if curl -fsSL --max-time 30 "$PANEL_URL/static/agent/agent.py" -o "$NEW_DIR/agent.py.new" 2>/dev/null; then
    SIZE=$(wc -c < "$NEW_DIR/agent.py.new")
    if [ "$SIZE" -lt 5000 ]; then
        rm -f "$NEW_DIR/agent.py.new"
        warn "Download inválido ($SIZE bytes); tentando cópia local..."
        if [ -f "$OLD_DIR/agent.py" ]; then
            cp "$OLD_DIR/agent.py" "$NEW_DIR/agent.py"
            sed -i 's|/etc/remotelink/|/etc/rnremote/|g' "$NEW_DIR/agent.py"
            ok "agent.py copiado de $OLD_DIR e atualizado"
        else
            err "Não foi possível obter agent.py"
        fi
    else
        mv "$NEW_DIR/agent.py.new" "$NEW_DIR/agent.py"
        NEW_VER=$(grep -oP 'AGENT_VERSION\s*=\s*"\K[^"]+' "$NEW_DIR/agent.py" 2>/dev/null || true)
        ok "agent.py baixado do painel${NEW_VER:+ (v${NEW_VER})}"
    fi
elif [ -f "$OLD_DIR/agent.py" ]; then
    cp "$OLD_DIR/agent.py" "$NEW_DIR/agent.py"
    sed -i 's|/etc/remotelink/|/etc/rnremote/|g' "$NEW_DIR/agent.py"
    ok "agent.py copiado de $OLD_DIR e atualizado"
else
    err "Não foi possível obter agent.py"
fi

chmod +x "$NEW_DIR/agent.py"

# ── Cria novo serviço ─────────────────────────────────────────────────────────
echo -e "\n${BOLD}[4/5] Instalando novo serviço...${RESET}"

cat > "$NEW_SVC_FILE" <<EOF
[Unit]
Description=RNRemote Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$PYTHON $NEW_DIR/agent.py --config $NEW_CONF/agent.json
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$NEW_SERVICE" --quiet
systemctl start "$NEW_SERVICE"
sleep 2

ok "Serviço ${NEW_SERVICE} instalado"

# ── Verifica ──────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[5/5] Verificando...${RESET}"

if systemctl is-active --quiet "$NEW_SERVICE"; then
    ok "Serviço ${NEW_SERVICE} rodando"
else
    echo -e "  ${RED}✘${RESET}  Serviço não iniciou. Verifique com:"
    echo -e "      journalctl -u ${NEW_SERVICE} -n 30"
    exit 1
fi

# ── Limpeza ───────────────────────────────────────────────────────────────────
if [ -f "$OLD_SVC_FILE" ]; then
    rm -f "$OLD_SVC_FILE"
    systemctl daemon-reload
    info "Arquivo de serviço antigo removido"
fi

FINAL_VER=$(grep -oP 'AGENT_VERSION\s*=\s*"\K[^"]+' "$NEW_DIR/agent.py" 2>/dev/null || echo "desconhecida")

echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════╗"
echo -e "║        Migração concluída com sucesso!   ║"
echo -e "╚══════════════════════════════════════════╝${RESET}"
echo -e "\n  Serviço : ${CYAN}${NEW_SERVICE}${RESET}"
echo -e "  Versão  : ${DIM}${FINAL_VER}${RESET}"
echo -e "  Config  : ${DIM}${NEW_CONF}/agent.json${RESET}"
echo -e "  Logs    : ${DIM}journalctl -u ${NEW_SERVICE} -f${RESET}\n"
