# Collect-RTX4090-Baseline.ps1
#
# Read-only Windows identity + environment capture for the 4090 Tensor-unlock
# research. Writes a timestamped folder of text/JSON files and a SHA-256
# manifest. It does NOT read BAR0 (impossible from user mode), does NOT flash,
# does NOT change boot configuration, and does NOT install anything.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\Collect-RTX4090-Baseline.ps1 -OutDir E:\EVIDENCE
#
# Status: NOT executed during the stage that added it (no Windows host was
# available). Treat the output as unverified until it has been run once and the
# transcript reviewed.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutDir,
    [string]$Label = "perf"
)

$ErrorActionPreference = "Continue"
$stamp = Get-Date -Format "yyyyMMddTHHmmssZ"
$root = Join-Path $OutDir ("identity-" + $Label + "-" + $stamp)
New-Item -ItemType Directory -Force -Path $root | Out-Null

function Save-Text {
    param([string]$Name, [string]$Text)
    $path = Join-Path $root $Name
    $Text | Out-File -FilePath $path -Encoding utf8
    Write-Host ("wrote " + $path)
}

function Invoke-Capture {
    param([string]$Name, [scriptblock]$Block)
    try {
        $out = & $Block 2>&1 | Out-String
        Save-Text $Name $out
    } catch {
        Save-Text $Name ("ERROR: " + $_.Exception.Message)
    }
}

# --- GPU identity -----------------------------------------------------------
Invoke-Capture "nvidia-smi.txt" {
    nvidia-smi --query-gpu=name,pci.bus_id,pci.device_id,pci.sub_device_id,vbios_version,driver_version,power.limit,power.default_limit,power.max_limit,clocks.max.sm,memory.total --format=csv
}
Invoke-Capture "nvidia-smi-full.txt" { nvidia-smi -q }
Invoke-Capture "pnp.txt" {
    Get-CimInstance Win32_VideoController |
        Select-Object Name, PNPDeviceID, DriverVersion, AdapterRAM, Status |
        Format-List
}
Invoke-Capture "board.txt" {
    Get-CimInstance Win32_BaseBoard | Format-List Manufacturer, Product, Version, SerialNumber
    Get-CimInstance Win32_BIOS | Format-List Manufacturer, SMBIOSBIOSVersion, ReleaseDate
    Get-CimInstance Win32_ComputerSystem | Format-List Manufacturer, Model, TotalPhysicalMemory
}
Invoke-Capture "os.txt" {
    Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber, OSArchitecture
}

# --- Boot security ----------------------------------------------------------
Invoke-Capture "secureboot.txt" {
    try { "SecureBoot: " + (Confirm-SecureBootUEFI) } catch { "SecureBoot query failed: " + $_.Exception.Message }
}
Invoke-Capture "bitlocker.txt" {
    try { manage-bde -status C: } catch { "manage-bde failed: " + $_.Exception.Message }
}

# --- Software that matters for the measurements -----------------------------
Invoke-Capture "toolkit.txt" {
    foreach ($exe in @("nvflash64.exe", "nvflash.exe", "python.exe", "python3.exe")) {
        $c = Get-Command $exe -ErrorAction SilentlyContinue
        if ($c) { $exe + " -> " + $c.Source } else { $exe + " -> not found" }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        python -c "import torch,sys; print('torch', torch.__version__); print('cuda', torch.version.cuda); print('device', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'none')" 2>&1
    }
}

# --- Manifest ---------------------------------------------------------------
$files = Get-ChildItem -Path $root -File | Sort-Object Name
$manifest = foreach ($f in $files) {
    [pscustomobject]@{
        file   = $f.Name
        bytes  = $f.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -Path $f.FullName).Hash.ToLower()
    }
}
$manifest | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $root "manifest.json") -Encoding utf8

$summary = [pscustomobject]@{
    collected_utc = (Get-Date).ToUniversalTime().ToString("o")
    label         = $Label
    host          = $env:COMPUTERNAME
    note          = "Identity/environment only. BAR0 registers are captured pre-OS (docs/07 Path A/B); this script cannot read them."
    files         = $files.Count
}
$summary | ConvertTo-Json | Out-File -FilePath (Join-Path $root "summary.json") -Encoding utf8

Write-Host ""
Write-Host ("Baseline written to " + $root)
Write-Host "Next: copy cap-S0-*.json from the pre-OS capture into ..\regs\ and run bench\tensor_gates.py gate2."
