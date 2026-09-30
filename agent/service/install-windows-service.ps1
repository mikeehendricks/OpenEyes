# OpenEyes agent — install as a Windows scheduled/service task.
# Requires: Python 3.10+ on PATH (or point $AgentExe at a built .exe).
# Run from an elevated PowerShell.

param(
    [string]$AgentExe = "python",
    [string]$ConfigPath = "C:\openeyes\agent.json"
)

$TaskName = "OpenEyes Agent"
$AgentDir = Split-Path $MyInvocation.MyCommand.Path

if ($AgentExe -eq "python") {
    $Args = "-m openeyes_agent --config `"$ConfigPath`""
} else {
    $Args = "--config `"$ConfigPath`""
}

# Remove any previous registration
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$Action  = New-ScheduledTaskAction -Execute $AgentExe -Argument $Args -WorkingDirectory $AgentDir
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
             -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
    -Settings $Settings -Principal $Principal -Description "OpenEyes monitoring agent" | Out-Null

Start-ScheduledTask -TaskName $TaskName
Write-Host "OpenEyes agent registered and started as scheduled task '$TaskName'."
Write-Host "Tip: for a real Windows service you can also wrap the agent with NSSM:"
Write-Host "     nssm install OpenEyesAgent `"$AgentExe`" $Args"
