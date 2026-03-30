# RNRemote - Remoção do Agente Windows
# Uso (PowerShell como Administrador):
#   irm https://rnremote.joaoneto.tec.br/static/agent/uninstall-windows.ps1 | iex
#   -- ou --
#   powershell -ExecutionPolicy Bypass -File uninstall-windows.ps1

#Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"

$INSTALL_DIR = "$env:ProgramFiles\RNRemote"
$CONFIG_DIR  = "$env:ProgramData\RNRemote"
$SVC_NAME    = "RNRemoteAgent"
$STARTUP_LNK = "$([Environment]::GetFolderPath('CommonStartup'))\RNRemote Agent Tray.lnk"

function Write-Step($n, $msg) { Write-Host "`n[$n] $msg" -ForegroundColor Cyan }
function Write-OK($msg)        { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Info($msg)      { Write-Host "  ->   $msg" -ForegroundColor Gray }

Write-Host @"

  ╔══════════════════════════════════════════╗
  ║   RNRemote — Remoção do Agente Windows   ║
  ╚══════════════════════════════════════════╝

"@ -ForegroundColor Cyan

$confirm = Read-Host "  Tem certeza que deseja remover o RNRemote Agent? [s/N]"
if ($confirm -notmatch "^[sSyY]") {
    Write-Host "  Cancelado.`n"
    exit 0
}

Write-Step "1/4" "Parando e removendo serviço Windows..."
$svc = Get-Service -Name $SVC_NAME -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") {
        Stop-Service -Name $SVC_NAME -Force
        Start-Sleep -Seconds 2
        Write-OK "Serviço parado"
    }
    sc.exe delete $SVC_NAME | Out-Null
    Write-OK "Serviço '$SVC_NAME' removido"
} else {
    Write-Info "Serviço '$SVC_NAME' não encontrado"
}

Write-Step "2/4" "Encerrando processo da bandeja..."
Get-Process -Name python* -ErrorAction SilentlyContinue | Where-Object {
    $_.MainModule.FileName -like "*RNRemote*" -or
    ($_.CommandLine -like "*agent-windows*" 2>$null)
} | Stop-Process -Force -ErrorAction SilentlyContinue
Write-OK "Processos encerrados"

Write-Step "3/4" "Removendo atalho da bandeja (inicialização)..."
if (Test-Path $STARTUP_LNK) {
    Remove-Item $STARTUP_LNK -Force
    Write-OK "Atalho removido: $STARTUP_LNK"
} else {
    Write-Info "Atalho não encontrado"
}

Write-Step "4/4" "Removendo arquivos..."
if (Test-Path $INSTALL_DIR) {
    Remove-Item $INSTALL_DIR -Recurse -Force
    Write-OK "Diretório removido: $INSTALL_DIR"
} else {
    Write-Info "$INSTALL_DIR não encontrado"
}
if (Test-Path $CONFIG_DIR) {
    Remove-Item $CONFIG_DIR -Recurse -Force
    Write-OK "Diretório removido: $CONFIG_DIR"
} else {
    Write-Info "$CONFIG_DIR não encontrado"
}

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║        Remoção concluída com sucesso!    ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Pressione ENTER para fechar..." -ForegroundColor DarkGray
Read-Host | Out-Null
