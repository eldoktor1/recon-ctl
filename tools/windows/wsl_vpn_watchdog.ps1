<#
  wsl_vpn_watchdog.ps1 -- Windows-side recovery watchdog for the recon pipeline.

  Problem it solves: a Mullvad reconnect/rekey can WEDGE the WSL2 network stack
  (netlink/sockets block; no egress; no default route) while Mullvad-on-Windows
  stays perfectly up. The pipeline's egress check runs INSIDE WSL, so it can
  never reach am.i.mullvad to clear the fail-closed 'vpn_down' flag -- the hunt
  latches paused for hours. The only fix is 'wsl --shutdown' (full VM teardown),
  which the WSL VM cannot do to itself -- hence a Windows-side watchdog.

  It is CONSERVATIVE and gated. It remediates ONLY when ALL hold for >= THRESHOLD
  consecutive checks:
    1. kali-linux is running, AND the recon daemon (recon_daemon.sh) is running
       -- i.e. the pipeline is SUPPOSED to be up. Never fights a manual stop or a
       cold/off machine; it recovers wedges, it does not cold-start the pipeline.
    2. Windows-Mullvad is a CONFIRMED exit. If Mullvad itself is down, the
       vpn_down latch is CORRECT and a WSL restart would not help -> stand down.
    3. An in-WSL egress probe to am.i.mullvad is wedged (empty/timeout) despite
       (2). That gap == a WSL-local network wedge.

  Safety rails: per-remediation COOLDOWN, an hourly cap that SELF-DISABLES on a
  storm, and a 'watchdog_disabled' opt-out sentinel. Every wsl call is hard-
  timeout-bounded so a wedged VM can't hang the watchdog. NB: 'wsl --shutdown'
  bounces the WHOLE WSL2 VM (docker-desktop too) -- that is the only thing that
  clears a VM-level vNIC wedge; '--terminate <distro>' does not.

  Run every few minutes via Task Scheduler (see install_wsl_vpn_watchdog.ps1).
  ASCII-only on purpose: PowerShell 5.1 mis-decodes non-ASCII in a BOM-less .ps1.
#>
[CmdletBinding()]
param(
  [switch]$WhatIfRemediate   # log decision + "would remediate" but do NOT shutdown (for testing)
)

$ErrorActionPreference = 'Stop'
$Distro = 'kali-linux'
$Dir    = 'C:\Users\mhabs\recon-watchdog'
$State  = Join-Path $Dir 'state'
$Log    = Join-Path $Dir 'watchdog.log'
$StreakFile  = Join-Path $State 'wedge_streak'
$LastRemFile = Join-Path $State 'last_remediation'
$HourFile    = Join-Path $State 'restart_hour'
$Disable     = Join-Path $Dir  'watchdog_disabled'    # New-Item this file to opt out

# --- tunables ---
$THRESHOLD    = 3      # consecutive wedge checks before acting (approx interval x 3)
$COOLDOWN_MIN = 20     # minimum minutes between remediations
$MAX_PER_HOUR = 3      # exceed -> self-disable to avoid a restart storm

New-Item -ItemType Directory -Force -Path $State | Out-Null
function Log([string]$m) {
  $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
  Add-Content -Path $Log -Value "$ts $m"
}
function Get-Streak { if (Test-Path $StreakFile) { try { [int](Get-Content $StreakFile -Raw) } catch { 0 } } else { 0 } }
function Set-Streak([int]$n) { Set-Content -Path $StreakFile -Value $n }

# Run a wsl command with a HARD timeout so a wedged VM can never hang the watchdog.
# Returns trimmed stdout, or $null on timeout (treated as wedged/unknown).
function Invoke-WslTimed([string]$cmdline, [int]$timeoutSec) {
  $job = Start-Job -ScriptBlock {
    param($d, $c)
    & wsl.exe -d $d -- bash -lc $c 2>$null
  } -ArgumentList $Distro, $cmdline
  if (Wait-Job $job -Timeout $timeoutSec) {
    $out = Receive-Job $job
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    if ($null -eq $out) { return '' }
    return (($out -join "`n").Trim())
  }
  Stop-Job $job -ErrorAction SilentlyContinue
  Remove-Job $job -Force -ErrorAction SilentlyContinue
  return $null
}

# --- 0. opt-out sentinel ---
if (Test-Path $Disable) { exit 0 }

# --- 1. cooldown (let a fresh remediation settle before judging again) ---
if (Test-Path $LastRemFile) {
  try {
    $lastDt = [datetime]((Get-Content $LastRemFile -Raw).Trim())
    if (((Get-Date) - $lastDt).TotalMinutes -lt $COOLDOWN_MIN) { exit 0 }
  } catch { }
}

# --- 2. is kali-linux running? (null-strip: wsl -l emits UTF-16 with NULs) ---
$running = ((& wsl.exe -l --running 2>$null | Out-String) -replace "`0","")
if ($running -notmatch [regex]::Escape($Distro)) { if ((Get-Streak) -ne 0) { Set-Streak 0 }; exit 0 }

# --- 3. is the recon daemon running? (non-network; fast even during a wedge) ---
#     If it isn't, the operator intentionally stopped the pipeline -> never auto-start it.
$dpid = Invoke-WslTimed 'pgrep -f recon_daemon.sh | head -1' 15
if ([string]::IsNullOrWhiteSpace($dpid)) { if ((Get-Streak) -ne 0) { Set-Streak 0 }; exit 0 }

# --- 4. Windows-Mullvad must be a confirmed exit (else not a WSL wedge) ---
$winMullvad = $false
try {
  $r = Invoke-RestMethod -Uri 'https://am.i.mullvad.net/json' -TimeoutSec 10
  if ($r.mullvad_exit_ip -eq $true) { $winMullvad = $true }
} catch { $winMullvad = $false }
if (-not $winMullvad) { if ((Get-Streak) -ne 0) { Set-Streak 0 }; exit 0 }

# --- 5. in-WSL egress probe -- is WSL itself wedged? ---
$probe = Invoke-WslTimed 'curl -s -m10 https://am.i.mullvad.net/json' 18
$wslOk = ($null -ne $probe) -and ($probe -match '"mullvad_exit_ip"\s*:\s*true')
if ($wslOk) {
  if ((Get-Streak) -ne 0) { Set-Streak 0; Log 'WSL egress recovered on its own -- streak reset' }
  exit 0
}

# --- WEDGED: Mullvad up + daemon up, but WSL has no egress ---
$n = (Get-Streak) + 1
Set-Streak $n
Log "WSL egress WEDGED (Mullvad up, daemon up) -- streak $n/$THRESHOLD"
if ($n -lt $THRESHOLD) { exit 0 }

# --- hourly cap (storm guard) ---
$hourTag = (Get-Date).ToString('yyyyMMddHH')
$cnt = 0
if (Test-Path $HourFile) {
  $parts = ((Get-Content $HourFile -Raw).Trim()) -split '\s+'
  if ($parts.Count -ge 2 -and $parts[0] -eq $hourTag) { $cnt = [int]$parts[1] }
}
if ($cnt -ge $MAX_PER_HOUR) {
  Log "HOURLY CAP hit ($cnt/$MAX_PER_HOUR) -- SELF-DISABLING to avoid a restart storm. Investigate, then delete '$Disable' to re-enable."
  New-Item -ItemType File -Force -Path $Disable | Out-Null
  exit 0
}

if ($WhatIfRemediate) {
  Log 'WOULD REMEDIATE (WhatIfRemediate set): wsl --shutdown + safe relaunch -- skipped.'
  exit 0
}

# --- remediate: wsl --shutdown + safe relaunch (preflight + VPN gate) ---
Log 'REMEDIATING: wsl --shutdown + safe relaunch (bounces the whole WSL2 VM)'
try { & wsl.exe --shutdown 2>$null } catch { }
Start-Sleep -Seconds 8
$relaunch = Invoke-WslTimed 'cd ~/recon-ctl && timeout 120 bash tools/start_recon_safe.sh 2>&1 | tail -4' 150
if ($null -eq $relaunch) { $relaunch = '(relaunch timed out)' }
Log ('relaunch: ' + ($relaunch -replace "`r?`n", ' | '))

Start-Sleep -Seconds 4
$verify = Invoke-WslTimed 'curl -s -m10 https://am.i.mullvad.net/json' 18
if ($verify -match '"mullvad_exit_ip"\s*:\s*true') { Log 'POST-REMEDIATION: WSL egress confirmed on Mullvad -- OK' }
else { Log 'POST-REMEDIATION: egress still NOT confirmed -- will reassess after cooldown' }

Set-Content -Path $LastRemFile -Value (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
Set-Content -Path $HourFile -Value "$hourTag $($cnt + 1)"
Set-Streak 0
exit 0
