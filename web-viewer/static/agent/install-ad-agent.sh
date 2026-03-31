#!/bin/bash
# RNRemote - Instalador do Agente Active Directory (Samba AD DC)
# Testado em CentOS 9 / AlmaLinux 9 com Samba compilado em /usr/local/samba
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   RNRemote - Agente Active Directory     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── Verifica root ───
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERRO: Execute como root${NC}"
    exit 1
fi

# ─── Verifica Samba ───
if [ ! -d "/usr/local/samba" ]; then
    echo -e "${RED}ERRO: Samba não encontrado em /usr/local/samba${NC}"
    echo "Este agente requer Samba AD DC compilado localmente."
    exit 1
fi

if [ ! -f "/usr/local/samba/bin/samba-tool" ]; then
    echo -e "${RED}ERRO: samba-tool não encontrado${NC}"
    exit 1
fi

echo -e "${GREEN}✔ Samba AD DC encontrado em /usr/local/samba${NC}"

# ─── Instala Python3 e pip ───
echo -e "\n${YELLOW}→ Verificando Python3...${NC}"
if ! command -v python3 &>/dev/null; then
    dnf install -y python3 python3-pip
fi
python3 --version

echo -e "${YELLOW}→ Instalando websockets...${NC}"
pip3 install --quiet websockets

# ─── Cria diretórios ───
echo -e "${YELLOW}→ Criando diretórios...${NC}"
mkdir -p /opt/rnremote-ad
mkdir -p /etc/rnremote

# ─── Copia ou baixa o agente ───
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/ad_agent.py" ]; then
    echo -e "${YELLOW}→ Copiando ad_agent.py...${NC}"
    cp "$SCRIPT_DIR/ad_agent.py" /opt/rnremote-ad/ad_agent.py
else
    echo -e "${YELLOW}→ Informe a URL do painel para baixar o agente${NC}"
    read -p "URL do painel (ex: https://rnremote.exemplo.com): " PANEL_URL
    if [ -n "$PANEL_URL" ]; then
        curl -fsSL "${PANEL_URL}/static/agent/ad_agent.py" -o /opt/rnremote-ad/ad_agent.py
    else
        echo -e "${RED}ERRO: Não foi possível obter ad_agent.py${NC}"
        exit 1
    fi
fi
chmod 755 /opt/rnremote-ad/ad_agent.py
echo -e "${GREEN}✔ ad_agent.py instalado${NC}"

# ─── Configuração interativa ───
echo ""
echo -e "${CYAN}─── Configuração do Agente ───────────────────${NC}"

read -p "URL do Relay WebSocket (ex: wss://relay.exemplo.com/ws): " RELAY_URL
if [ -z "$RELAY_URL" ]; then
    echo -e "${RED}ERRO: URL do relay obrigatória${NC}"
    exit 1
fi

# Gera ID aleatório de 9 dígitos
DEFAULT_ID=$(tr -dc '0-9' < /dev/urandom | head -c 9)
read -p "ID do agente [$DEFAULT_ID]: " AGENT_ID
AGENT_ID="${AGENT_ID:-$DEFAULT_ID}"

read -s -p "Senha de acesso: " AGENT_PASSWORD
echo ""
if [ -z "$AGENT_PASSWORD" ]; then
    echo -e "${YELLOW}Aviso: sem senha — qualquer viewer poderá conectar${NC}"
fi

# ─── Salva configuração ───
cat > /etc/rnremote/ad-agent.json << EOF
{
    "relay_url": "$RELAY_URL",
    "agent_id":  "$AGENT_ID",
    "password":  "$AGENT_PASSWORD"
}
EOF
chmod 600 /etc/rnremote/ad-agent.json
echo -e "${GREEN}✔ Configuração salva em /etc/rnremote/ad-agent.json${NC}"

# ─── Cria serviço systemd ───
cat > /etc/systemd/system/rnremote-ad.service << EOF
[Unit]
Description=RNRemote Active Directory Agent
After=network.target samba.service
Requires=samba.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/rnremote-ad
ExecStart=/usr/bin/python3 /opt/rnremote-ad/ad_agent.py --config /etc/rnremote/ad-agent.json
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable rnremote-ad
systemctl start  rnremote-ad

# ─── Verifica status ───
sleep 2
STATUS=$(systemctl is-active rnremote-ad)
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         Instalação Concluída             ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""
if [ "$STATUS" = "active" ]; then
    echo -e "${GREEN}✔ Serviço ativo e rodando${NC}"
else
    echo -e "${RED}✘ Serviço com problema — verifique os logs${NC}"
fi
echo ""
echo -e "  ${YELLOW}Agent ID:${NC}  $AGENT_ID"
echo -e "  ${YELLOW}Relay:${NC}     $RELAY_URL"
echo -e "  ${YELLOW}Config:${NC}    /etc/rnremote/ad-agent.json"
echo -e "  ${YELLOW}Serviço:${NC}   rnremote-ad"
echo ""
echo -e "${CYAN}Comandos úteis:${NC}"
echo "  systemctl status rnremote-ad"
echo "  journalctl -u rnremote-ad -f"
echo "  systemctl restart rnremote-ad"
