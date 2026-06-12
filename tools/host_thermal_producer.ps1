<#
  host_thermal_producer.ps1 — Windows-host CPU thermal producer for the recon pipeline.

  WSL2 CANNOT read the real Windows host CPU temperature (/sys/class/thermal is fake in WSL2,
  and MSAcpi_ThermalZoneTemperature WMI is unreliable on Dell). This runs on the WINDOWS host
  and writes the real DTS package temp + throttling flag to the WSL state dir every ~45s, so
  the WSL watchdog (recon_watchdog.sh section 9) can alarm on SILENT thermal degradation.

  Sensor source (first one available, in order):
    1. HWiNFO64 shared memory ("Global\HWiNFO_SENS_SM2") — RECOMMENDED: exposes the REAL
       hardware "Thermal Throttling" flag. Requires HWiNFO running with
       Settings -> Safety -> "Shared Memory Support" = ON.
    2. LibreHardwareMonitor / OpenHardwareMonitor WMI (root/LibreHardwareMonitor) — CPU
       Package temp; throttling INFERRED from temp (pkg >= THERMAL_THROTTLE_INFER_C).

  Output (atomic write) to $HOST_THERMAL_OUT (default the WSL state dir, next to vpn_status.json):
    {ts, cpu_pkg_c:int, cpu_throttling:bool, throttle_sustained_sec:int, gpu_c:int, source}
  throttle_sustained_sec = how long throttling has been CONTINUOUSLY true (this poller knows
  it at 45s resolution; the hourly watchdog just samples it).

  Env overrides: THERMAL_POLL_SEC (45), THERMAL_THROTTLE_INFER_C (99), HOST_THERMAL_OUT.
  Never fakes a reading: if no sensor source is present it writes nothing (the watchdog's
  stale-file check then reports "blind").
#>
$ErrorActionPreference = 'SilentlyContinue'

$PollSec        = if ($env:THERMAL_POLL_SEC)         { [int]$env:THERMAL_POLL_SEC }         else { 45 }
$ThrottleInferC = if ($env:THERMAL_THROTTLE_INFER_C) { [int]$env:THERMAL_THROTTLE_INFER_C } else { 99 }
$OutFile        = if ($env:HOST_THERMAL_OUT)         { $env:HOST_THERMAL_OUT }              else { '\\wsl.localhost\kali-linux\home\d0k\recon\state\host_thermal.json' }

function Read-HWiNFO {
    # Parse the HWiNFO SM2 shared-memory block (documented layout). Returns a hashtable or $null.
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
        # header: ... dwOffsetOfReadingSection@32, dwSizeOfReadingElement@36, dwNumReadingElements@40
        $offReading = [int64]$acc.ReadUInt32(32)
        $szReading  = [int64]$acc.ReadUInt32(36)
        $numReading = [int64]$acc.ReadUInt32(40)
        if ($szReading -le 0 -or $numReading -le 0 -or $numReading -gt 200000) {
            $acc.Dispose(); $mmf.Dispose(); return $null
        }
        $pkg = $null; $gpu = $null; $throt = $false
        $buf = New-Object byte[] 128
        for ($i = 0; $i -lt $numReading; $i++) {
            $base = $offReading + $i * $szReading
            # reading element: tReading@0 (1=Temp), szLabelUser@140 (128B ASCII), Value(double)@284
            $type = $acc.ReadUInt32($base + 0)
            [void]$acc.ReadArray($base + 140, $buf, 0, 128)
            $label = ([System.Text.Encoding]::ASCII.GetString($buf)).Split([char]0)[0]
            $val = $acc.ReadDouble($base + 284)
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
        return @{ cpu_pkg_c = $c
                  cpu_throttling = ($c -ge $ThrottleInferC)   # LHM/OHM have no throttle flag -> infer from temp
                  gpu_c = $g
                  source = "$tag(throttle-inferred>=${ThrottleInferC}C)" }
    }
    return $null
}

$throttleSince = $null
while ($true) {
    $t = Read-HWiNFO
    if (-not $t) { $t = Read-LHMWmi }
    if ($t) {
        $nowEpoch = [int][double]::Parse((Get-Date).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds)
        if ($t.cpu_throttling) {
            if ($null -eq $throttleSince) { $throttleSince = $nowEpoch }
            $sustain = $nowEpoch - $throttleSince
        } else { $throttleSince = $null; $sustain = 0 }
        $obj = [ordered]@{
            ts                     = $nowEpoch
            cpu_pkg_c              = [int]$t.cpu_pkg_c
            cpu_throttling         = [bool]$t.cpu_throttling
            throttle_sustained_sec = [int]$sustain
            gpu_c                  = [int]$t.gpu_c
            source                 = [string]$t.source
        }
        try {
            $json = ($obj | ConvertTo-Json -Compress)
            $tmp  = "$OutFile.tmp"
            [System.IO.File]::WriteAllText($tmp, $json)
            Move-Item -Force -Path $tmp -Destination $OutFile
        } catch {}
    }
    Start-Sleep -Seconds $PollSec
}
