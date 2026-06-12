<#
  host_thermal_producer.ps1 — Windows-host CPU thermal producer for the recon pipeline.

  WSL2 CANNOT read the real Windows host CPU temperature, and a sensor agent (HWiNFO /
  LibreHardwareMonitor) MUST be running to expose it. To avoid leaving HWiNFO open 24/7,
  this producer runs HWiNFO ONLY WHILE RECON IS ACTIVELY SCANNING (that's the only time
  thermal matters) and shuts it down when recon stops — gated on the recon heartbeat
  (vpn_status.json, refreshed every ~20s by recon_vpnguard while the daemon runs).

  Each active cycle it reads the real DTS package temp + throttling flag and writes
  host_thermal.json {ts,cpu_pkg_c,cpu_throttling,throttle_sustained_sec,gpu_c,source} to the
  WSL state dir. When recon is idle it stops the HWiNFO instance IT launched (never the
  user's own) and removes host_thermal.json so the watchdog skips the thermal check.

  Sensor source (first available): HWiNFO shared memory (real throttling flag) -> LHM/OHM WMI.

  ONE-TIME HWiNFO SETUP (so launches are silent + expose shared memory):
    run HWiNFO once -> choose "Sensors-only"; in Settings enable "Shared Memory Support",
    "Minimize Main Window on startup", "Minimize Sensors on startup", "Minimize to Tray";
    DISABLE "Auto Start" (this producer launches it on demand). Then close HWiNFO.

  Env: THERMAL_POLL_SEC(45) THERMAL_THROTTLE_INFER_C(99) HOST_THERMAL_OUT HWINFO_EXE
       RECON_HEARTBEAT_FILE RECON_HEARTBEAT_SEC(120) HWINFO_PIDFILE.  Switch: -Once (one cycle).
#>
param([switch]$Once)
$ErrorActionPreference = 'SilentlyContinue'

# single-instance guard: every logon/Run of the task must NOT stack another producer loop
if (-not $Once) {
    $script:__mtx = New-Object System.Threading.Mutex($false, 'Global\recon_host_thermal_producer')
    if (-not $script:__mtx.WaitOne(0)) { exit 0 }   # another producer already running
}

$PollSec        = if ($env:THERMAL_POLL_SEC)         { [int]$env:THERMAL_POLL_SEC }         else { 45 }
$ThrottleInferC = if ($env:THERMAL_THROTTLE_INFER_C) { [int]$env:THERMAL_THROTTLE_INFER_C } else { 99 }
$OutFile        = if ($env:HOST_THERMAL_OUT)         { $env:HOST_THERMAL_OUT }              else { '\\wsl.localhost\kali-linux\home\d0k\recon\state\host_thermal.json' }
$HwinfoExe      = if ($env:HWINFO_EXE)               { $env:HWINFO_EXE }                    else { 'C:\Program Files\HWiNFO64\HWiNFO64.EXE' }
$HeartbeatFile  = if ($env:RECON_HEARTBEAT_FILE)     { $env:RECON_HEARTBEAT_FILE }          else { '\\wsl.localhost\kali-linux\home\d0k\recon\state\vpn_status.json' }
$HeartbeatSec   = if ($env:RECON_HEARTBEAT_SEC)      { [int]$env:RECON_HEARTBEAT_SEC }      else { 120 }
$ManagedPidFile = if ($env:HWINFO_PIDFILE)           { $env:HWINFO_PIDFILE }                else { (Join-Path $env:TEMP 'recon_hwinfo_managed.pid') }
# free HWiNFO disables Shared Memory after 12h of runtime — recycle OUR managed instance
# before that so a multi-day recon session never goes blind (no HWiNFO Pro needed).
$HwinfoMaxRunH  = if ($env:HWINFO_MAX_RUNTIME_H)     { [double]$env:HWINFO_MAX_RUNTIME_H }   else { 11 }

function Test-ReconActive {
    try {
        if (-not (Test-Path $HeartbeatFile)) { return $false }
        return ((New-TimeSpan -Start (Get-Item $HeartbeatFile).LastWriteTime -End (Get-Date)).TotalSeconds -lt $HeartbeatSec)
    } catch { return $false }
}

function Test-HWiNFORunning { [bool](Get-Process HWiNFO64 -ErrorAction SilentlyContinue) }

function Start-ManagedHWiNFO {
    if (Test-HWiNFORunning) { return }           # the user's own instance is up -> use it, don't manage
    if (-not (Test-Path $HwinfoExe)) { return }
    try {
        $p = Start-Process -FilePath $HwinfoExe -WindowStyle Minimized -PassThru
        if ($p) { Set-Content -Path $ManagedPidFile -Value $p.Id -Encoding ASCII }
    } catch {}
}

function Stop-ManagedHWiNFO {
    if (-not (Test-Path $ManagedPidFile)) { return }
    try {
        $hpid = [int](Get-Content $ManagedPidFile -ErrorAction SilentlyContinue)
        $p = Get-Process -Id $hpid -ErrorAction SilentlyContinue
        if ($p -and $p.Name -eq 'HWiNFO64') { Stop-Process -Id $hpid -Force -ErrorAction SilentlyContinue }
    } catch {}
    Remove-Item -Force $ManagedPidFile -ErrorAction SilentlyContinue
}

function Read-HWiNFO {
    $mmf = $null
    foreach ($name in @('Global\HWiNFO_SENS_SM2', 'HWiNFO_SENS_SM2')) {
        try {
            $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting(
                       $name, [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::Read)
            if ($mmf) { break }
        } catch {}
    }
    if (-not $mmf) { return $null }
    try {
        $acc = $mmf.CreateViewAccessor(0, 0, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read)
        $offReading = [int64]$acc.ReadUInt32(32)   # dwOffsetOfReadingSection
        $szReading  = [int64]$acc.ReadUInt32(36)   # dwSizeOfReadingElement
        $numReading = [int64]$acc.ReadUInt32(40)   # dwNumReadingElements
        if ($szReading -le 0 -or $numReading -le 0 -or $numReading -gt 200000) { $acc.Dispose(); $mmf.Dispose(); return $null }
        $pkg = $null; $gpu = $null; $throt = $false
        $buf = New-Object byte[] 128
        for ($i = 0; $i -lt $numReading; $i++) {
            $base = $offReading + $i * $szReading
            $type = $acc.ReadUInt32($base + 0)                 # tReading: 1 = Temperature
            [void]$acc.ReadArray($base + 140, $buf, 0, 128)    # szLabelUser[128]
            $label = ([System.Text.Encoding]::ASCII.GetString($buf)).Split([char]0)[0]
            $val = $acc.ReadDouble($base + 284)                # Value (double)
            if ($type -eq 1) {
                if (($label -match 'CPU Package' -or $label -match 'CPU \(Tctl' -or $label -match 'Package') -and ($null -eq $pkg)) { $pkg = $val }
                elseif (($label -match 'GPU') -and ($null -eq $gpu)) { $gpu = $val }
            }
            if (($label -match 'Thermal Throttling') -and ($val -gt 0)) { $throt = $true }
        }
        $acc.Dispose(); $mmf.Dispose()
        if ($null -eq $pkg) { return $null }
        return @{ cpu_pkg_c = [int][math]::Round([double]$pkg)
                  cpu_throttling = [bool]$throt
                  gpu_c = [int][math]::Round([double]($(if ($null -ne $gpu) { $gpu } else { 0 })))
                  source = 'hwinfo-sm2' }
    } catch { try { $mmf.Dispose() } catch {}; return $null }
}

function Read-LHMWmi {
    foreach ($ns in @('root/LibreHardwareMonitor', 'root/OpenHardwareMonitor')) {
        $s = Get-CimInstance -Namespace $ns -ClassName Sensor -ErrorAction SilentlyContinue
        if (-not $s) { continue }
        $temps = @($s | Where-Object { $_.SensorType -eq 'Temperature' })
        if (-not $temps) { continue }
        $pkg = $temps | Where-Object { $_.Name -match 'CPU Package' -or $_.Name -match 'Core \(Tctl' } | Select-Object -First 1
        if (-not $pkg) { $pkg = $temps | Where-Object { $_.Name -match 'CPU' } | Sort-Object Value -Descending | Select-Object -First 1 }
        if (-not $pkg) { continue }
        $gpu = $temps | Where-Object { $_.Name -match 'GPU' } | Sort-Object Value -Descending | Select-Object -First 1
        $c = [int][math]::Round([double]$pkg.Value)
        $g = if ($gpu) { [int][math]::Round([double]$gpu.Value) } else { 0 }
        $tag = if ($ns -match 'Libre') { 'lhm-wmi' } else { 'ohm-wmi' }
        return @{ cpu_pkg_c = $c; cpu_throttling = ($c -ge $ThrottleInferC); gpu_c = $g; source = "$tag(throttle-inferred>=${ThrottleInferC}C)" }
    }
    return $null
}

$script:throttleSince = $null

function Invoke-Cycle {
    if (Test-ReconActive) {
        Start-ManagedHWiNFO
        # recycle our managed HWiNFO before the free-version 12h shared-memory cutoff
        if (Test-Path $ManagedPidFile) {
            try {
                $hpid = [int](Get-Content $ManagedPidFile -ErrorAction SilentlyContinue)
                $hp = Get-Process -Id $hpid -ErrorAction SilentlyContinue
                if ($hp -and $hp.Name -eq 'HWiNFO64' -and
                    (New-TimeSpan -Start $hp.StartTime -End (Get-Date)).TotalHours -ge $HwinfoMaxRunH) {
                    Stop-ManagedHWiNFO; Start-ManagedHWiNFO
                }
            } catch {}
        }
        $t = Read-HWiNFO
        if (-not $t) { $t = Read-LHMWmi }
        if ($t) {
            $nowEpoch = [int][double][math]::Floor((Get-Date).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds)
            if ($t.cpu_throttling) {
                if ($null -eq $script:throttleSince) { $script:throttleSince = $nowEpoch }
                $sustain = $nowEpoch - $script:throttleSince
            } else { $script:throttleSince = $null; $sustain = 0 }
            $obj = [ordered]@{
                ts = $nowEpoch; cpu_pkg_c = [int]$t.cpu_pkg_c; cpu_throttling = [bool]$t.cpu_throttling
                throttle_sustained_sec = [int]$sustain; gpu_c = [int]$t.gpu_c; source = [string]$t.source
            }
            try {
                $tmp = "$OutFile.tmp"
                [System.IO.File]::WriteAllText($tmp, ($obj | ConvertTo-Json -Compress))
                Move-Item -Force -Path $tmp -Destination $OutFile
            } catch {}
        }
        # else: HWiNFO still spinning up (no reading yet) -> next cycle will have it
    } else {
        Stop-ManagedHWiNFO
        $script:throttleSince = $null
        try { if (Test-Path $OutFile) { Remove-Item -Force $OutFile -ErrorAction SilentlyContinue } } catch {}
    }
}

# startup reconcile: if recon is idle but a previous run left a managed HWiNFO, stop it
if (-not (Test-ReconActive)) { Stop-ManagedHWiNFO }

if ($Once) { Invoke-Cycle; return }
while ($true) { Invoke-Cycle; Start-Sleep -Seconds $PollSec }
