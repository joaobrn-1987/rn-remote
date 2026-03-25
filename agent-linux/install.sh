#!/bin/bash
# RNRemote - Instalação do Agente Linux
# Uso: bash install.sh

set -e

echo ""
echo "RNRemote - Instalação do Agente Linux"
echo "========================================"
echo ""

# ── Dependências ─────────────────────────────────────────────────────────────
echo "[1/3] Verificando dependências..."

if ! command -v python3 &>/dev/null; then
    echo "ERRO: python3 não encontrado. Instale com: apt install python3"
    exit 1
fi

pip3 install --quiet websockets 2>/dev/null || {
    python3 -m pip install --quiet websockets 2>/dev/null || true
}

echo "      OK"

# ── Arquivos ──────────────────────────────────────────────────────────────────
echo "[2/3] Copiando arquivos..."

mkdir -p /opt/rnremote
cp agent.py /opt/rnremote/agent.py
cp setup.py /opt/rnremote/setup.py
chmod +x /opt/rnremote/agent.py /opt/rnremote/setup.py

echo "      OK"

# ── Serviço systemd ───────────────────────────────────────────────────────────
echo "[3/3] Instalando serviço systemd..."

cat > /etc/systemd/system/rnremote-agent.service <<'EOF'
[Unit]
Description=RNRemote Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/rnremote/agent.py --config /etc/rnremote/agent.json
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo "      OK"
echo ""
echo "========================================"
echo " Agora execute o setup para configurar:"
echo ""
echo "   python3 /opt/rnremote/setup.py"
echo ""
echo " Depois inicie o serviço:"
echo ""
echo "   systemctl enable --now rnremote-agent"
echo "========================================"
echo ""
