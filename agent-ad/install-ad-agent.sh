#!/bin/bash
# RNRemote - Instalador do Agente Active Directory (Samba AD DC)
# Auto-provisiona no painel via API — nenhuma configuração manual necessária.
# Testado em CentOS 9 / AlmaLinux 9 com Samba compilado em /usr/local/samba
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   RNRemote - Agente Active Directory     ║${NC}"
echo -e "${CYAN}║   Instalação automática via painel       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── Verifica root ───
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERRO: Execute como root${NC}"
    exit 1
fi

# ─── Verifica Samba ───
if [ ! -d "/usr/local/samba" ] || [ ! -f "/usr/local/samba/bin/samba-tool" ]; then
    echo -e "${RED}ERRO: Samba AD DC não encontrado em /usr/local/samba${NC}"
    exit 1
fi
echo -e "${GREEN}✔ Samba AD DC encontrado${NC}"

# ─── Verifica curl/python3 ───
for cmd in curl python3; do
    if ! command -v $cmd &>/dev/null; then
        dnf install -y $cmd
    fi
done

echo -e "${YELLOW}→ Instalando websockets...${NC}"
pip3 install --quiet websockets

# ─── Configura diretórios ───
mkdir -p /opt/rnremote-ad /etc/rnremote

# ─── Copia agente ───
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/ad_agent.py" ]; then
    cp "$SCRIPT_DIR/ad_agent.py" /opt/rnremote-ad/ad_agent.py
fi

# ─── Coleta informações ───
echo ""
echo -e "${CYAN}─── Configuração ────────────────────────────────${NC}"

# Detecta hostname para sugerir como nickname
DEFAULT_NICK=$(hostname -s)
read -p "Nome desta máquina no painel [$DEFAULT_NICK]: " NICKNAME
NICKNAME="${NICKNAME:-$DEFAULT_NICK}"

read -p "URL do painel RNRemote (ex: https://rnremote.empresa.com): " PANEL_URL
PANEL_URL="${PANEL_URL%/}"

if [ -z "$PANEL_URL" ]; then
    echo -e "${RED}ERRO: URL do painel obrigatória${NC}"
    exit 1
fi

# Tenta detectar URL do relay a partir da URL do painel
DEFAULT_RELAY="${PANEL_URL/https:\/\//wss://}/ws"
DEFAULT_RELAY="${DEFAULT_RELAY/http:\/\//ws://}"
read -p "URL do Relay WebSocket [$DEFAULT_RELAY]: " RELAY_URL
RELAY_URL="${RELAY_URL:-$DEFAULT_RELAY}"

read -p "E-mail admin do painel: " ADMIN_EMAIL
read -s -p "Senha admin do painel: " ADMIN_PASS
echo ""

read -s -p "Senha de acesso para este agente (protege conexões): " AGENT_PASSWORD
echo ""

# ─── Login no painel ───
echo -e "\n${YELLOW}→ Autenticando no painel...${NC}"
LOGIN_RESP=$(curl -sf -X POST "${PANEL_URL}/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASS}\"}" 2>&1) || {
    echo -e "${RED}ERRO: Não foi possível conectar ao painel em ${PANEL_URL}${NC}"
    echo "Verifique a URL e que o painel está acessível."
    exit 1
}

AUTH_TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)
if [ -z "$AUTH_TOKEN" ]; then
    LOGIN_OK=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ok','false'))" 2>/dev/null)
    if [ "$LOGIN_OK" != "True" ] && [ "$LOGIN_OK" != "true" ]; then
        ERR=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','credenciais inválidas'))" 2>/dev/null)
        echo -e "${RED}ERRO de autenticação: ${ERR}${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}✔ Autenticado com sucesso${NC}"

# ─── Provisiona agente no painel ───
echo -e "${YELLOW}→ Provisionando agente AD no painel...${NC}"
PROV_RESP=$(curl -sf -X POST "${PANEL_URL}/api/agents/provision" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${AUTH_TOKEN}" \
    -d "{\"nickname\":\"${NICKNAME} (AD)\",\"access_password\":\"${AGENT_PASSWORD}\"}" 2>&1) || {
    echo -e "${RED}ERRO ao provisionar agente${NC}"
    exit 1
}

AGENT_ID=$(echo "$PROV_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('agent_id',''))" 2>/dev/null)
BINDING_SECRET=$(echo "$PROV_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('binding_secret',''))" 2>/dev/null)
PROV_OK=$(echo "$PROV_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ok','false'))" 2>/dev/null)

if [ "$PROV_OK" != "True" ] && [ "$PROV_OK" != "true" ] || [ -z "$AGENT_ID" ]; then
    ERR=$(echo "$PROV_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','falha desconhecida'))" 2>/dev/null)
    echo -e "${RED}ERRO ao provisionar: ${ERR}${NC}"
    exit 1
fi
echo -e "${GREEN}✔ Agente provisionado: ID ${AGENT_ID}${NC}"

# ─── Baixa ad_agent.py se não disponível localmente ───
if [ ! -f "/opt/rnremote-ad/ad_agent.py" ]; then
    echo -e "${YELLOW}→ Baixando ad_agent.py do painel...${NC}"
    curl -fsSL "${PANEL_URL}/static/agent/ad_agent.py" -o /opt/rnremote-ad/ad_agent.py || {
        echo -e "${RED}ERRO: Não foi possível baixar ad_agent.py${NC}"
        exit 1
    }
fi
chmod 755 /opt/rnremote-ad/ad_agent.py

# ─── Salva configuração ───
cat > /etc/rnremote/ad-agent.json << EOF
{
    "relay_url":      "${RELAY_URL}",
    "agent_id":       "${AGENT_ID}",
    "password":       "${AGENT_PASSWORD}",
    "binding_secret": "${BINDING_SECRET}",
    "nickname":       "${NICKNAME}"
}
EOF
chmod 600 /etc/rnremote/ad-agent.json
echo -e "${GREEN}✔ Configuração salva em /etc/rnremote/ad-agent.json${NC}"

# ─── Cria serviço systemd ───
cat > /etc/systemd/system/rnremote-ad.service << EOF
[Unit]
Description=RNRemote Active Directory Agent - ${NICKNAME}
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

sleep 2
STATUS=$(systemctl is-active rnremote-ad)

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         Instalação Concluída             ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""
if [ "$STATUS" = "active" ]; then
    echo -e "${GREEN}✔ Agente ativo e conectando ao relay${NC}"
else
    echo -e "${RED}✘ Problema ao iniciar — verifique os logs${NC}"
fi
echo ""
echo -e "  ${YELLOW}Máquina:${NC}   ${NICKNAME}"
echo -e "  ${YELLOW}Agent ID:${NC}  ${AGENT_ID}"
echo -e "  ${YELLOW}Painel:${NC}    ${PANEL_URL}"
echo ""
echo -e "${GREEN}A máquina '${NICKNAME} (AD)' já aparece no painel RNRemote.${NC}"
echo -e "${GREEN}Clique em 'Conectar' para abrir o gerenciador de AD.${NC}"
echo ""
echo -e "${CYAN}Comandos úteis:${NC}"
echo "  systemctl status rnremote-ad"
echo "  journalctl -u rnremote-ad -f"
