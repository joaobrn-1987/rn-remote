#!/bin/sh
# RNRemote - Remoção do Agente pfSense / FreeBSD
# Execute no pfSense como root:
#   curl -fsSL https://rnremote.joaoneto.tec.br/static/agent/uninstall-pfsense.sh | sh

ok()   { printf "  [OK] %s\n" "$1"; }
err()  { printf "  [X]  %s\n" "$1" >&2; exit 1; }
info() { printf "  ->   %s\n" "$1"; }

printf "\n"
printf "  ╔══════════════════════════════════════════╗\n"
printf "  ║   RNRemote — Remoção (pfSense/FreeBSD)   ║\n"
printf "  ╚══════════════════════════════════════════╝\n\n"

[ "$(id -u)" -ne 0 ] && err "Execute como root."

AGENT_DIR="/usr/local/rnremote"
CONFIG_DIR="/usr/local/etc/rnremote"
RC_SCRIPT="/usr/local/etc/rc.d/rnremote_agent"

printf "  Tem certeza que deseja remover o RNRemote Agent? [s/N]: "
read -r CONFIRM </dev/tty
case "$CONFIRM" in
    [sSyY]*) ;;
    *) printf "  Cancelado.\n\n"; exit 0 ;;
esac

printf "\n[1/4] Parando serviço...\n"
if [ -f "$RC_SCRIPT" ]; then
    service rnremote_agent stop 2>/dev/null || true
    ok "Serviço parado"
else
    info "Serviço rc.d não encontrado"
fi
pkill -f "${AGENT_DIR}/agent.py" 2>/dev/null || true

printf "\n[2/4] Removendo serviço rc.d...\n"
if [ -f "$RC_SCRIPT" ]; then
    rm -f "$RC_SCRIPT"
    ok "Script rc.d removido"
fi
if grep -q "rnremote_agent_enable" /etc/rc.conf 2>/dev/null; then
    sed -i '' '/rnremote_agent_enable/d' /etc/rc.conf
    ok "Entrada removida de /etc/rc.conf"
fi

printf "\n[3/4] Removendo arquivos do agente...\n"
if [ -d "$AGENT_DIR" ]; then
    rm -rf "$AGENT_DIR"
    ok "Diretório $AGENT_DIR removido"
else
    info "$AGENT_DIR não encontrado"
fi
rm -f /var/run/rnremote_agent.pid 2>/dev/null || true

printf "\n[4/4] Removendo configuração...\n"
if [ -d "$CONFIG_DIR" ]; then
    rm -rf "$CONFIG_DIR"
    ok "Diretório $CONFIG_DIR removido"
else
    info "$CONFIG_DIR não encontrado"
fi
rm -f /var/log/rnremote.log 2>/dev/null || true

printf "\n"
printf "  ╔══════════════════════════════════════════╗\n"
printf "  ║        Remoção concluída com sucesso!    ║\n"
printf "  ╚══════════════════════════════════════════╝\n\n"
