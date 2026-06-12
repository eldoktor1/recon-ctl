<#
  install_host_thermal_task.ps1 — register the reboot-persistent ReconHostThermal producer
  (same persistence model as ReconWatchdog: a hidden launcher run at logon).

  REFUSES to register if no sensor source (HWiNFO shared memory / LibreHardwareMonitor or
  OpenHardwareMonitor WMI) is present — it never registers a reader that can only write
  nothing/fakes. If none is found it prints exactly what to install and exits non-zero.

  Run from an elevated PowerShell:
    powershell -ExecutionPolicy Bypass -File tools\install_host_thermal_task.ps1
#>
$ErrorActionPreference = 'Stop'

$HwinfoExe = if ($env:HWINFO_EXE) { $env:HWINFO_EXE } else { 'C:\Program Files\HWiNFO64\HWiNFO64.EXE' }

function Test-Sensor {
    # running sensor (best) ...
    if (Get-CimInstance -Namespace root/LibreHardwareMonitor -ClassName Sensor -ErrorAction SilentlyContinue) { return 'LibreHardwareMonitor (WMI)' }
    if (Get-CimInstance -Namespace root/OpenHardwareMonitor  -ClassName Sensor -ErrorAction SilentlyContinue) { return 'OpenHardwareMonitor (WMI)' }
    foreach ($n in @('Global\HWiNFO_SENS_SM2','HWiNFO_SENS_SM2')) {
        try { $m = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting($n); if ($m) { $m.Dispose(); return 'HWiNFO (shared memory, running)' } } catch {}
    }
    # ... or HWiNFO INSTALLED (the producer launches it on demand only while recon scans)
    if (Test-Path $HwinfoExe) { return 'HWiNFO (installed; producer will run it on demand)' }
    return $null
}

$sensor = Test-Sensor
if (-not $sensor) {
    Write-Host "REFUSING to register ReconHostThermal: no CPU thermal sensor source detected." -ForegroundColor Red
    Write-Host ""
    Write-Host "Install ONE of these on the Windows host, then re-run this script:"
    Write-Host "  * LibreHardwareMonitor (simplest): https://github.com/LibreHardwareMonitor/LibreHardwareMonitor"
    Write-Host "      - run it, Options -> 'Run on Windows startup' + 'Minimize to tray' + 'Start minimized'"
    Write-Host "      - it exposes CPU Package temp over WMI automatically (root/LibreHardwareMonitor)."
    Write-Host "  * HWiNFO (gives the REAL hardware Thermal-Throttling flag): https://www.hwinfo.com/"
    Write-Host "      - run Sensors-only, Settings -> Safety -> 'Shared Memory Support' = ON,"
    Write-Host "        and 'Minimize Sensors on startup' + auto-start."
    Write-Host ""
    Write-Host "Until then the WSL watchdog (recon_watchdog.sh) stays correct: host_thermal.json"
    Write-Host "is simply absent, so it skips the thermal check (no false alarms)."
    exit 2
}

Write-Host "Sensor source detected: $sensor" -ForegroundColor Green

$dst = 'C:\recon'
New-Item -ItemType Directory -Force -Path $dst | Out-Null
$producerSrc = Join-Path $PSScriptRoot 'host_thermal_producer.ps1'
$producerDst = Join-Path $dst 'host_thermal_producer.ps1'
Copy-Item -Force -Path $producerSrc -Destination $producerDst

# hidden launcher (same pattern as C:\recon\recon_watchdog.vbs)
$vbs = Join-Path $dst 'host_thermal_producer.vbs'
$cmd = 'CreateObject("Wscript.Shell").Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ' + $producerDst + '", 0, False'
Set-Content -Path $vbs -Value $cmd -Encoding ASCII

# reboot-persistent: run the hidden launcher at logon (the producer then loops internally ~45s)
schtasks /Create /TN "ReconHostThermal" /SC ONLOGON /RL LIMITED /F /TR ("wscript.exe `"$vbs`"") | Out-Null
schtasks /Run /TN "ReconHostThermal" | Out-Null
Write-Host "Registered + started ReconHostThermal (logon-persistent, ~45s cadence)." -ForegroundColor Green
Write-Host "The producer launches HWiNFO HIDDEN only while recon is scanning, and closes it when"
Write-Host "recon stops (gated on the vpn_status.json heartbeat) -- HWiNFO is never left open 24/7."
Write-Host ""
Write-Host "ONE-TIME HWiNFO setup so its launches are silent + expose the sensor (do this once):" -ForegroundColor Yellow
Write-Host "  run HWiNFO -> 'Sensors-only'; Settings: enable 'Shared Memory Support',"
Write-Host "  'Minimize Main Window on startup', 'Minimize Sensors on startup', 'Minimize to Tray';"
Write-Host "  DISABLE 'Auto Start' (the producer launches it on demand). Then close HWiNFO."
