<#
.SYNOPSIS  Safely set a registry value.
.PARAMETER RegistryPath   Full registry path (e.g. HKLM:\SOFTWARE\...)
.PARAMETER RegistryItem   Value name
.PARAMETER RegistryValue  New value
#>
param(
    [Parameter(Mandatory)][string]$RegistryPath,
    [Parameter(Mandatory)][string]$RegistryItem,
    [Parameter(Mandatory)][string]$RegistryValue
)

$ErrorActionPreference = 'Stop'

# Determine value type
if ($RegistryValue -match '^\d+$') {
    $type  = 'DWord'
    $value = [int]$RegistryValue
} else {
    $type  = 'String'
    $value = $RegistryValue
}

# Create path if missing
if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}

Set-ItemProperty -Path $RegistryPath -Name $RegistryItem -Value $value -Type $type
Write-Host "Set $RegistryPath\$RegistryItem = $RegistryValue ($type)"
exit 0
