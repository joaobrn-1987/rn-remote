#!/usr/bin/env python3
"""
RemoteLink - Setup interativo do Agente Linux

Autentica no painel RemoteLink, registra esta máquina e cria o arquivo
de configuração em /etc/rnremote/agent.json.

Uso:
    python3 setup.py
    python3 setup.py --panel https://rnremote.joaoneto.tec.br
"""

import argparse
import getpass
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error

try:
    import urllib.parse
except ImportError:
    pass

CONFIG_PATH   = "/etc/rnremote/agent.json"
DEFAULT_PANEL = "https://rnremote.joaoneto.tec.br"
DEFAULT_RELAY = "wss://rnremote.joaoneto.tec.br/ws"


# ─── HTTP helpers (sem dependências externas) ──────────────────────────────────

def http_post(url: str, payload: dict, token: str = "") -> dict:
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        method="POST"
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())
    except Exception as e:
        print(f"\nErro de conexão: {e}")
        sys.exit(1)


# ─── Formatação do terminal ────────────────────────────────────────────────────

BOLD  = "\033[1m"
GREEN = "\033[32m"
RED   = "\033[31m"
CYAN  = "\033[36m"
DIM   = "\033[2m"
RESET = "\033[0m"

def header():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════╗
║       RemoteLink — Setup do Agente       ║
╚══════════════════════════════════════════╝{RESET}
""")

def ok(msg):   print(f"  {GREEN}✔{RESET}  {msg}")
def err(msg):  print(f"  {RED}✘{RESET}  {msg}")
def info(msg): print(f"  {DIM}→{RESET}  {msg}")
def ask(prompt, secret=False):
    try:
        return (getpass.getpass(f"  {BOLD}{prompt}{RESET} ") if secret
                else input(f"  {BOLD}{prompt}{RESET} ")).strip()
    except (KeyboardInterrupt, EOFError):
        print("\nCancelado.")
        sys.exit(0)


# ─── Verificação de instalação existente ──────────────────────────────────────

def check_existing():
    if not os.path.exists(CONFIG_PATH):
        return
    print(f"{DIM}Configuração existente encontrada em {CONFIG_PATH}{RESET}")
    resp = ask("Deseja reconfigurar? [s/N]")
    if resp.lower() not in ("s", "sim", "y", "yes"):
        print("Nada alterado.")
        sys.exit(0)


# ─── Fluxo principal ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="RemoteLink Agent Setup")
    parser.add_argument("--panel", default=DEFAULT_PANEL,
                        help=f"URL do painel (padrão: {DEFAULT_PANEL})")
    parser.add_argument("--relay", default=DEFAULT_RELAY,
                        help=f"URL WebSocket do relay (padrão: {DEFAULT_RELAY})")
    args = parser.parse_args()

    panel_url = args.panel.rstrip("/")
    relay_url = args.relay

    header()
    check_existing()

    # ── Passo 1: Autenticação no painel ───────────────────────────────────────
    print(f"{BOLD}Passo 1 — Autenticação no painel{RESET}")
    info(f"Painel: {panel_url}")
    print()

    for attempt in range(3):
        email    = ask("E-mail:")
        password = ask("Senha:", secret=True)

        result = http_post(f"{panel_url}/api/login", {
            "email": email,
            "password": password,
        })

        if result.get("ok"):
            token = result["token"]
            user  = result.get("user", email)
            ok(f"Autenticado como {BOLD}{user}{RESET}")
            break
        else:
            err(result.get("error", "Credenciais inválidas"))
            if attempt == 2:
                print("\nNúmero máximo de tentativas atingido.")
                sys.exit(1)
            print()
    else:
        sys.exit(1)

    # ── Passo 2: Nome desta máquina ───────────────────────────────────────────
    print(f"\n{BOLD}Passo 2 — Identificação da máquina{RESET}")

    import socket
    default_nick = socket.gethostname()
    nickname = ask(f"Apelido para esta máquina [{default_nick}]:")
    if not nickname:
        nickname = default_nick

    # ── Passo 3: Senha de acesso remoto ───────────────────────────────────────
    print(f"\n{BOLD}Passo 3 — Senha de acesso remoto{RESET}")
    info("Esta senha será usada no painel para conectar a esta máquina.")
    print()

    for attempt in range(3):
        pw1 = ask("Senha de acesso remoto:", secret=True)
        pw2 = ask("Confirme a senha:", secret=True)
        if pw1 == pw2 and pw1:
            access_password = pw1
            break
        if pw1 != pw2:
            err("Senhas não coincidem, tente novamente.")
        else:
            err("A senha não pode estar vazia.")
    else:
        print("\nNão foi possível definir a senha.")
        sys.exit(1)

    # ── Passo 4: Provisionar no painel ────────────────────────────────────────
    print(f"\n{BOLD}Passo 4 — Registrando no painel...{RESET}")

    result = http_post(f"{panel_url}/api/agents/provision", {
        "nickname":        nickname,
        "access_password": access_password,
    }, token=token)

    if not result.get("ok"):
        err(result.get("error", "Erro ao registrar no painel"))
        sys.exit(1)

    agent_id       = result["agent_id"]
    binding_secret = result["binding_secret"]

    ok(f"Agente registrado com ID {BOLD}{agent_id}{RESET}")

    # ── Passo 5: Salvar configuração ──────────────────────────────────────────
    print(f"\n{BOLD}Passo 5 — Salvando configuração...{RESET}")

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

    config = {
        "relay_url":      relay_url,
        "agent_id":       agent_id,
        "password":       access_password,
        "binding_secret": binding_secret,
        "nickname":       nickname,
    }

    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_PATH, 0o600)  # somente root lê

    ok(f"Configuração salva em {CONFIG_PATH}")

    # ── Resumo final ──────────────────────────────────────────────────────────
    print(f"""
{GREEN}{BOLD}╔══════════════════════════════════════════╗
║          Instalação concluída!           ║
╚══════════════════════════════════════════╝{RESET}

  Máquina  : {BOLD}{nickname}{RESET}
  ID       : {BOLD}{agent_id}{RESET}
  Senha    : {BOLD}{'*' * len(access_password)}{RESET}
  Relay    : {relay_url}

{DIM}Guarde bem a senha de acesso — ela não pode ser recuperada.{RESET}

Para iniciar o agente agora:
  {CYAN}python3 agent.py --config {CONFIG_PATH}{RESET}

Para instalar como serviço:
  {CYAN}bash install.sh --relay {relay_url} --id {agent_id} --password <senha>{RESET}
  {DIM}(ou ajuste o serviço systemd para usar --config {CONFIG_PATH}){RESET}
""")


if __name__ == "__main__":
    main()
