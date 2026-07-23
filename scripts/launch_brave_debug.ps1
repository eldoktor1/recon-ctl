# =============================================================================
# launch_brave_debug.ps1 — start the operator's Brave with DevTools remote
# debugging so the in-UI Co-Pilot can drive it over CDP (mcp__brave__* tools).
#
# Recent Chromium BLOCKS --remote-debugging-port on the DEFAULT profile, so this
# uses a DEDICATED --user-data-dir. Log into your bug-bounty platforms / targets
# in THIS window once; the profile persists across launches. This is your
# "authed testing" Brave, isolated from daily browsing.
#
# Hard line (mirrors CLAUDE.md): only ever drive in-scope + PAYING assets; the
# Co-Pilot's browser use is read-only/safe by default, 2 owned accounts for IDOR,
# never third-party IDs, confirm-then-stop. You supervise every turn.
#
# Usage:  powershell -ExecutionPolicy Bypass -File launch_brave_debug.ps1
#         (optional)  -Port 9222  -ProfileDir "C:\Users\you\brave-recon-debug"
# =============================================================================
param(
  [int]$Port = 9222,
  [string]$ProfileDir = "$env:USERPROFILE\brave-recon-debug"
)

$ErrorActionPreference = 'Stop'
$brave = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe"
if (-not (Test-Path $brave)) {
  Write-Host "brave.exe not found at $brave" -ForegroundColor Red
  exit 1
}

# Already listening? Reuse it (never launch a second debug instance).
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
  Write-Host "Debug-Brave already listening on 127.0.0.1:$Port - reusing it." -ForegroundColor Green
  exit 0
}

New-Item -ItemType Directory -Force -Path $ProfileDir | Out-Null
Write-Host "Launching Brave  (debug :$Port  profile: $ProfileDir)" -ForegroundColor Cyan
Write-Host "-> Log into your platforms/targets in THIS window. The Co-Pilot can now drive it." -ForegroundColor Yellow

Start-Process -FilePath $brave -ArgumentList @(
  "--remote-debugging-port=$Port",
  "--remote-debugging-address=127.0.0.1",
  "--user-data-dir=`"$ProfileDir`"",
  "--no-default-browser-check",
  "--restore-last-session"
)

Start-Sleep -Seconds 2
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
  Write-Host "OK - CDP up on 127.0.0.1:$Port. Co-Pilot browser tools go live on its next turn." -ForegroundColor Green
} else {
  Write-Host "Started, but port $Port not listening yet - give Brave a moment, then check." -ForegroundColor Yellow
}
