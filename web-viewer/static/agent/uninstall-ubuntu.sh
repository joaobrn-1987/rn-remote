#!/bin/bash
# RNRemote - Remoção do Agente (Ubuntu / Debian)
# Uso: sudo bash uninstall-ubuntu.sh

BOLD="\033[1m"; GREEN="\033[32m"; RED="\033[31m"; CYAN="\033[36m"; YELLOW="\033[33m"; DIM="\033[2m"; RESET="\033[0m"
ok()   { echo -e "  ${GREEN}✔${RESET}  $1"; }
err()  { echo -e "  ${RED}✘${RESET}  $1"; exit 1; }
info() { echo -e "  ${DIM}→${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }

echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════════╗"
echo -e "║   RNRemote — Remoção (Ubuntu/Debian)     ║"
echo -e "╚══════════════════════════════════════════╝${RESET}\n"

[ "$EUID" -ne 0 ] && err "Execute como root: sudo bash uninstall-ubuntu.sh"

SERVICE="rnremote-agent"
INSTALL_DIR="/opt/rnremote"
CONF_DIR="/etc/rnremote"
SVC_FILE="/etc/systemd/system/${SERVICE}.service"

read -rp "  Tem certeza que deseja remover o RNRemote Agent? [s/N]: " CONFIRM
[[ ! "$CONFIRM" =~ ^[sSyY]$ ]] && { echo -e "  Cancelado.\n"; exit 0; }

echo -e "\n${BOLD}[1/4] Parando e desativando serviço...${RESET}"
if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    systemctl stop "$SERVICE"
    ok "Serviço parado"
else
    info "Serviço não estava rodando"
fi
if systemctl is-enabled --quiet "$SERVICE" 2>/dev/null; then
    systemctl disable "$SERVICE" --quiet
    ok "Serviço desativado"
fi

echo -e "\n${BOLD}[2/4] Removendo arquivo de serviço...${RESET}"
if [ -f "$SVC_FILE" ]; then
    rm -f "$SVC_FILE"
    systemctl daemon-reload
    ok "Arquivo de serviço removido"
else
    info "Arquivo de serviço não encontrado"
fi

echo -e "\n${BOLD}[3/4] Removendo arquivos do agente...${RESET}"
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    ok "Diretório $INSTALL_DIR removido"
else
    info "$INSTALL_DIR não encontrado"
fi

echo -e "\n${BOLD}[4/4] Removendo configuração...${RESET}"
if [ -d "$CONF_DIR" ]; then
    rm -rf "$CONF_DIR"
    ok "Diretório $CONF_DIR removido"
else
    info "$CONF_DIR não encontrado"
fi

echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════╗"
echo -e "║        Remoção concluída com sucesso!    ║"
echo -e "╚══════════════════════════════════════════╝${RESET}\n"
