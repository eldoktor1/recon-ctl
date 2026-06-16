<#
  install_wsl_vpn_watchdog.ps1 -- deploy + register the WSL VPN watchdog.

  Copies wsl_vpn_watchdog.ps1 (canonical copy lives in the repo) to a Windows-
  native dir so the scheduled task never depends on WSL being up to READ the
  script, then registers a Task Scheduler job that runs it every $IntervalMin
  minutes (and at logon). Re-run this installer after editing the repo script to
  redeploy. No elevation needed (a user may shut down their own WSL and register
  their own interactive task).

  Uninstall:  Unregister-ScheduledTask -TaskName 'ReconWSLVpnWatchdog' -Confirm:$false
  Pause:      New-Item C:\Users\mhabs\recon-watchdog\watchdog_disabled
  Resume:     Remove-Item C:\Users\mhabs\recon-watchdog\watchdog_disabled
#>
[CmdletBinding()]
param(
  [int]$IntervalMin = 3,
  [string]$TaskName = 'ReconWSLVpnWatchdog'
)
$ErrorActionPreference = 'Stop'

$Dir   = 'C:\Users\mhabs\recon-watchdog'
$Dest  = Join-Path $Dir 'wsl_vpn_watchdog.ps1'
$Src   = Join-Path $PSScriptRoot 'wsl_vpn_watchdog.ps1'

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item -Path $Src -Destination $Dest -Force
Write-Host "Deployed watchdog -> $Dest"

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument "-NonInteractive -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Dest`""

# repeat every $IntervalMin forever (PS 5.1: graft a .Repetition from a helper trigger)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
$rep = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMin) `
        -RepetitionDuration (New-TimeSpan -Days 3650)).Repetition
$trigger.Repetition = $rep
$atLogon = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -MultipleInstances IgnoreNew `
  -StartWhenAvailable `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

$me = "$env:USERDOMAIN\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action `
  -Trigger @($trigger, $atLogon) -Settings $settings -Principal $principal `
  -Description 'Recovers a wedged WSL2 network stack (wsl --shutdown + safe relaunch) when Mullvad-on-Windows is up but WSL egress is dead. See recon-pipeline/tools/windows/wsl_vpn_watchdog.ps1.' `
  -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName' (every $IntervalMin min + at logon) as $me"
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table -AutoSize
