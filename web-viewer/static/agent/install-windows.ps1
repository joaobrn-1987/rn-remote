# RNRemote - Instalador do Agente Windows
# Instala como Servico Windows + atalho de bandeja na inicializacao
#
# Uso (PowerShell como Administrador):
#   irm https://rnremote.joaoneto.tec.br/static/agent/install-windows.ps1 | iex
#   -- ou --
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

$PANEL_URL   = "https://rnremote.joaoneto.tec.br"
$INSTALL_DIR = "$env:ProgramFiles\RNRemote"
$CONFIG_DIR  = "$env:ProgramData\RNRemote"
$CONFIG_FILE = "$CONFIG_DIR\agent.json"
$LOG_FILE    = "$CONFIG_DIR\agent.log"
$SVC_NAME    = "RNRemoteAgent"
$SVC_DISPLAY = "RNRemote Agent"
$SVC_DESC    = "RNRemote - Agente de acesso remoto via browser"

function Write-Step($n, $msg) { Write-Host "`n[$n] $msg" -ForegroundColor Cyan }
function Write-OK($msg)        { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg)      { Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Fail($msg)      { Write-Host "`n  [X]  $msg`n" -ForegroundColor Red; Write-Host "  Pressione ENTER para fechar..." -ForegroundColor DarkGray; Read-Host | Out-Null; exit 1 }
function Write-Info($msg)      { Write-Host "  ->   $msg" -ForegroundColor Gray }

Write-Host @"

  ╔══════════════════════════════════════════╗
  ║   RNRemote — Instalador do Agente Win    ║
  ╚══════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# ── Passo 1: Python ─────────────────────────────────────────────────────────────
Write-Step "1/6" "Verificando Python 3.8+..."

$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3\.([89]|1\d)") {
            $python = $cmd
            Write-OK "Python: $ver"
            break
        }
    } catch {}
}

if (-not $python) {
    Write-Warn "Python 3.8+ nao encontrado. Tentando instalar via winget..."
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        try {
            Write-Info "Instalando Python 3.11 (aguarde)..."
            winget install --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
            # Recarrega PATH da sessao atual
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Write-OK "Python instalado via winget"
        } catch {
            Write-Warn "winget falhou: $_"
        }
    } else {
        Write-Warn "winget nao disponivel neste sistema."
    }

    # Tenta novamente apos instalacao
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match "Python 3\.([89]|1\d)") {
                $python = $cmd
                Write-OK "Python: $ver"
                break
            }
        } catch {}
    }

    if (-not $python) {
        Write-Fail "Nao foi possivel localizar Python 3.8+.`n  Instale manualmente em https://www.python.org/downloads/`n  (marque 'Add Python to PATH') e execute o instalador novamente."
    }
}

# ── Passo 2: Dependencias Python ────────────────────────────────────────────────
Write-Step "2/6" "Instalando dependencias Python..."

# Garante que o pip esta disponivel (necessario apos instalacao via winget)
Write-Info "Verificando pip..."
$pipOut = & $python -m ensurepip --upgrade 2>&1
$ErrorActionPreference = "Continue"
& $python -m pip install --quiet --upgrade pip 2>&1 | Out-Null
$ErrorActionPreference = "Stop"

# Resolve o caminho absoluto do Python para usar no pip
$pythonPath = (& $python -c "import sys; print(sys.executable)" 2>&1).Trim()

$packages = @(
    "websockets",
    "pystray",
    "pillow",
    "pywinpty",
    "pywin32",
    "mss",
    "pynput"
)

foreach ($pkg in $packages) {
    Write-Host "  -> $pkg " -NoNewline -ForegroundColor Gray
    $ErrorActionPreference = "Continue"
    $out = & "$pythonPath" -m pip install --quiet --upgrade $pkg 2>&1
    $ok  = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = "Stop"
    if ($ok) {
        Write-Host "OK" -ForegroundColor Green
    } else {
        Write-Host "FALHA" -ForegroundColor Yellow
        Write-Host "    $out" -ForegroundColor DarkGray
    }
}

# pywin32 requer post-install
$ErrorActionPreference = "Continue"
$siteDir = (& "$pythonPath" -c "import site; print(site.getsitepackages()[0])" 2>&1).Trim()
$postScript = Join-Path $siteDir "pywin32_postinstall.py"
if (Test-Path $postScript) {
    & "$pythonPath" $postScript -install 2>&1 | Out-Null
}
$ErrorActionPreference = "Stop"

Write-OK "Dependencias instaladas"

# ── Passo 3: Download do agente ─────────────────────────────────────────────────
Write-Step "3/6" "Baixando agente..."

New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $CONFIG_DIR  | Out-Null

$agentFile = "$INSTALL_DIR\agent-windows.py"

try {
    Invoke-WebRequest -Uri "$PANEL_URL/static/agent/agent-windows.py" `
        -OutFile $agentFile -UseBasicParsing
    Write-OK "Agente salvo em: $agentFile"
} catch {
    Write-Fail "Falha ao baixar agent-windows.py: $_"
}

# ── Passo 4: Configuracao ────────────────────────────────────────────────────────
Write-Step "4/6" "Configurando o agente..."

$needConfig = $true
if (Test-Path $CONFIG_FILE) {
    $resp = Read-Host "  Configuracao existente encontrada. Reconfigurar? [s/N]"
    if ($resp -notmatch "^[sSyY]") {
        Write-OK "Configuracao mantida."
        $needConfig = $false
    }
}

if ($needConfig) {
    Write-Host ""
    Write-Host "  Informe suas credenciais do painel RNRemote:" -ForegroundColor White
    Write-Host ""

    # Login
    $email  = Read-Host "  E-mail"
    $secPwd = Read-Host "  Senha do painel" -AsSecureString
    $panelPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPwd)
    )

    $loginBody = @{ email = $email; password = $panelPassword } | ConvertTo-Json
    try {
        $loginResp = Invoke-RestMethod -Uri "$PANEL_URL/api/login" `
            -Method POST -Body $loginBody -ContentType "application/json"
    } catch {
        Write-Fail "Falha na conexao com o painel: $_"
    }
    if (-not $loginResp.ok) {
        Write-Fail "Login invalido: $($loginResp.error)"
    }
    $token = $loginResp.token
    Write-OK "Autenticado como: $($loginResp.user)"

    # Apelido
    $defaultNick = $env:COMPUTERNAME
    Write-Host ""
    $nick = Read-Host "  Apelido para esta maquina [$defaultNick]"
    if (-not $nick) { $nick = $defaultNick }

    # Senha de acesso remoto
    Write-Host ""
    Write-Host "  Defina a senha de acesso remoto a esta maquina:" -ForegroundColor White
    $accessPassword = $null
    do {
        $sec1 = Read-Host "  Senha de acesso" -AsSecureString
        $sec2 = Read-Host "  Confirme"       -AsSecureString
        $p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec1))
        $p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec2))
        if ($p1 -ne $p2 -or -not $p1) {
            Write-Host "  Senhas nao coincidem ou estao vazias. Tente novamente." -ForegroundColor Red
        } else {
            $accessPassword = $p1
        }
    } while (-not $accessPassword)

    # Provisionar
    $provBody = @{ nickname = $nick; access_password = $accessPassword } | ConvertTo-Json
    try {
        $provResp = Invoke-RestMethod -Uri "$PANEL_URL/api/agents/provision" `
            -Method POST -Body $provBody -ContentType "application/json" `
            -Headers @{ Authorization = "Bearer $token" }
    } catch {
        Write-Fail "Erro ao registrar agente: $_"
    }
    if (-not $provResp.ok) {
        Write-Fail "Registro falhou: $($provResp.error)"
    }

    $config = [ordered]@{
        relay_url      = "wss://rnremote.joaoneto.tec.br/ws"
        agent_id       = $provResp.agent_id
        password       = $accessPassword
        binding_secret = $provResp.binding_secret
        nickname       = $nick
    } | ConvertTo-Json

    # Salva sem BOM para que o Python consiga ler o JSON normalmente
    [System.IO.File]::WriteAllText($CONFIG_FILE, $config, (New-Object System.Text.UTF8Encoding $false))
    # Protege o arquivo de config usando SIDs (funciona mesmo sem confianca de dominio)
    try {
        $acl = Get-Acl $CONFIG_FILE
        $acl.SetAccessRuleProtection($true, $false)
        # S-1-5-18 = SYSTEM  |  S-1-5-32-544 = Administrators (built-in, nao depende de dominio)
        foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {
            $principal = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $principal, "FullControl", "Allow"
            )
            $acl.AddAccessRule($rule)
        }
        Set-Acl $CONFIG_FILE $acl
        Write-OK "Permissoes do arquivo de config restritas"
    } catch {
        Write-Warn "Nao foi possivel restringir permissoes do config: $_"
    }

    Write-OK "Agente ID : $($provResp.agent_id)"
    Write-OK "Config    : $CONFIG_FILE"
}

# ── Passo 5: Servico Windows ─────────────────────────────────────────────────────
Write-Step "5/6" "Instalando servico Windows..."

# Remove servico anterior se existir
$existingSvc = Get-Service -Name $SVC_NAME -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Info "Removendo servico anterior..."
    if ($existingSvc.Status -eq "Running") {
        Stop-Service -Name $SVC_NAME -Force
        Start-Sleep -Seconds 2
    }
    & "$pythonPath" "$agentFile" remove 2>&1 | Out-Null
    Start-Sleep -Seconds 1
}

# Instala via pywin32
$ErrorActionPreference = "Continue"
$installOut = & "$pythonPath" "$agentFile" --config "$CONFIG_FILE" install 2>&1
$ErrorActionPreference = "Stop"
if ($LASTEXITCODE -eq 0) {
    Write-OK "Servico instalado via pywin32"
} else {
    Write-Warn "Falha ao instalar via pywin32. Tentando via sc.exe..."
    $binPath = "`"$pythonPath`" `"$agentFile`" --config `"$CONFIG_FILE`" --no-tray"
    sc.exe create $SVC_NAME binPath= $binPath start= auto DisplayName= $SVC_DISPLAY | Out-Null
    sc.exe description $SVC_NAME $SVC_DESC | Out-Null
    Write-OK "Servico instalado via sc.exe"
}

# Configura inicio automatico
sc.exe config $SVC_NAME start= auto | Out-Null
sc.exe failure $SVC_NAME reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# Inicia o servico
Start-Service -Name $SVC_NAME -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

$svc = Get-Service -Name $SVC_NAME -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-OK "Servico '$SVC_NAME' iniciado e rodando"
} else {
    Write-Warn "Servico instalado mas nao iniciou automaticamente."
    Write-Info "Verifique com: Get-EventLog -LogName Application -Source $SVC_NAME -Newest 10"
}

# ── Passo 6: Bandeja do sistema (atalho para TODOS os usuarios) ──────────────────
Write-Step "6/6" "Configurando bandeja do sistema (todos os usuarios)..."

# CommonStartup = C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
# Executa para QUALQUER usuario que fizer login neste computador
$startupDir   = [Environment]::GetFolderPath("CommonStartup")
$shortcutPath = "$startupDir\RNRemote Agent Tray.lnk"

try {
    $WScript  = New-Object -ComObject WScript.Shell
    $shortcut = $WScript.CreateShortcut($shortcutPath)
    $shortcut.TargetPath       = $pythonPath
    $shortcut.Arguments        = "`"$agentFile`" --config `"$CONFIG_FILE`" --tray"
    $shortcut.WorkingDirectory = $INSTALL_DIR
    $shortcut.WindowStyle      = 7   # minimizado
    $shortcut.Description      = "RNRemote Agent - Bandeja do Sistema"
    $shortcut.Save()
    Write-OK "Atalho de bandeja criado: $shortcutPath"
} catch {
    Write-Warn "Nao foi possivel criar atalho de bandeja: $_"
}

# Inicia a bandeja agora
try {
    Start-Process "$pythonPath" -ArgumentList "`"$agentFile`" --config `"$CONFIG_FILE`" --tray" `
        -WindowStyle Hidden
    Write-OK "Bandeja do sistema iniciada"
} catch {
    Write-Warn "Nao foi possivel iniciar a bandeja agora (sera iniciada no proximo login)."
}

# ── Resumo ───────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║      Instalacao concluida com sucesso!   ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Servico  : $SVC_NAME — roda como SYSTEM, independente de login" -ForegroundColor Gray
Write-Host "  Bandeja  : aparece para TODOS os usuarios ao fazer login" -ForegroundColor Gray
Write-Host "  Config   : $CONFIG_FILE" -ForegroundColor Gray
Write-Host "  Log      : $LOG_FILE" -ForegroundColor Gray
Write-Host ""
Write-Host "  Comandos uteis:" -ForegroundColor DarkGray
Write-Host "    Get-Service $SVC_NAME                       # status do servico" -ForegroundColor DarkGray
Write-Host "    Start-Service $SVC_NAME                     # iniciar" -ForegroundColor DarkGray
Write-Host "    Stop-Service $SVC_NAME                      # parar" -ForegroundColor DarkGray
Write-Host "    Get-Content '$LOG_FILE' -Tail 50 -Wait      # logs em tempo real" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Pressione ENTER para fechar..." -ForegroundColor DarkGray
Read-Host | Out-Null
