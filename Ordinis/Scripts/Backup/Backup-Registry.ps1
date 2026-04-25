<#
.SYNOPSIS  Export a registry key to a .reg file.
.PARAMETER RegistryPath  Full path (e.g. HKLM\SOFTWARE\Policies\...)
.PARAMETER OutputFile    Full path for the output .reg file
#>
param(
    [Parameter(Mandatory)][string]$RegistryPath,
    [Parameter(Mandatory)][string]$OutputFile
)

# Normalise HKLM:\ to HKLM\
$regPath = $RegistryPath -replace '^HKLM:\\', 'HKLM\' `
                         -replace '^HKCU:\\', 'HKCU\' `
                         -replace '^HKCC:\\', 'HKCC\'

$dir = Split-Path $OutputFile -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

reg export $regPath $OutputFile /y

if ($LASTEXITCODE -ne 0) {
    Write-Error "reg export failed for: $regPath"
    exit $LASTEXITCODE
}

Write-Host "Registry backup saved: $OutputFile"
exit 0
