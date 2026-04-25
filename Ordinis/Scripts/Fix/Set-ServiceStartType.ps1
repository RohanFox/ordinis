<#
.SYNOPSIS  Change a Windows service start type.
.PARAMETER ServiceName  Service name (short name)
.PARAMETER StartType    Disabled | Manual | Automatic | AutomaticDelayedStart
#>
param(
    [Parameter(Mandatory)][string]$ServiceName,
    [Parameter(Mandatory)][string]$StartType
)

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Error "Service '$ServiceName' not found."
    exit 1
}

Set-Service -Name $ServiceName -StartupType $StartType

if ($StartType -eq 'Disabled') {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
}

Write-Host "Service '$ServiceName' start type set to '$StartType'"
exit 0
