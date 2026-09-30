<# ============================================================
 OpenEyes agent — zero-touch installer for Windows
 (Windows 10/11 and Windows Server, x64 and ARM64)

 Installs the agent, enrolls it, and registers a scheduled
 task that starts it at boot and restarts it on failure.
 After this script finishes the agent runs autonomously —
 no user interaction is ever required again.

 Usage (elevated PowerShell):
   .\Install-Agent.ps1 -ServerUrl https://eyes.example.com:8080 `
       -EnrollToken <token-from-dashboard> `
       [-Labels "branch-office,floor-2"] [-Lat 14.5995 -Lng 120.9842]
============================================================ #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [Parameter(Mandatory=$true)][string]$EnrollToken,
    [string]$Labels = "",
    [double]$Lat = [double]::NaN,
    [double]$Lng = [double]::NaN,
    [switch]$Insecure,
    [string]$InstallDir = "C:\Program Files\OpenEyes"
)

$ErrorActionPreference = "Stop"

# --- must run elevated -----------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this script from an elevated PowerShell." }

# --- locate Python ---------------------------------------------------------
$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) { $Python = Get-Command py -ErrorAction SilentlyContinue }
if (-not $Python) { throw "Python 3.9+ is required on PATH (winget install Python.Python.3.12)." }
$PyExe = $Python.Source

$SrcDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppDir = Join-Path $InstallDir "agent"
$ConfDir = Join-Path $env:ProgramData "OpenEyes"
$ConfFile = Join-Path $ConfDir "agent.json"
$TaskName = "OpenEyes Agent"

Write-Host "[1/4] Installing agent to $AppDir ..."
New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
Copy-Item -Recurse -Force (Join-Path $SrcDir "openeyes_agent") $AppDir

Write-Host "[2/4] Writing configuration ..."
New-Item -ItemType Directory -Force -Path $ConfDir | Out-Null
$labelList = @($Labels -split "," | Where-Object { $_ } | ForEach-Object { $_.Trim() })
$location = $null
if (-not [double]::IsNaN($Lat) -and -not [double]::IsNaN($Lng)) {
    $location = @{ lat = $Lat; lng = $Lng }
}
$cfg = [ordered]@{
    server_url       = $ServerUrl.TrimEnd("/")
    enrollment_token = $EnrollToken
    labels           = $labelList
    location         = $location
    insecure_tls     = [bool]$Insecure
    state_path       = (Join-Path $ConfDir "state.json")
}
$cfg | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfFile -Encoding UTF8

Write-Host "[3/4] Registering scheduled task (starts at boot, restarts on failure) ..."
$ArgString = "-m openeyes_agent --config `"$ConfFile`""
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$Action   = New-ScheduledTaskAction -Execute $PyExe -Argument $ArgString -WorkingDirectory $AppDir
$Trigger  = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Seconds 30) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
    -Settings $Settings -Principal $Principal `
    -Description "OpenEyes monitoring agent (autonomous)" | Out-Null
# also run it right now
Start-ScheduledTask -TaskName $TaskName

Write-Host "[4/4] Verifying ..."
Start-Sleep -Seconds 3
$info = Get-ScheduledTaskInfo -TaskName $TaskName
if ($info.LastRunResult -in 0, 267009) {
    Write-Host "OK: OpenEyes agent is running and will start automatically on boot."
} else {
    Write-Host "NOTE: task last result = $($info.LastRunResult) - the agent keeps retrying enrollment autonomously."
}
Write-Host "Config : $ConfFile"
Write-Host "Logs   : Task Scheduler -> 'OpenEyes Agent', or run manually: $PyExe $ArgString"
