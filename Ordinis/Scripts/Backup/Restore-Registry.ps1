<#
.SYNOPSIS  Restore a registry key from a .reg file.
.PARAMETER RegFile  Full path to the .reg backup file
#>
param([Parameter(Mandatory)][string]$RegFile)

if (-not (Test-Path $RegFile)) {
    Write-Error "Backup file not found: $RegFile"
    exit 1
}

reg import $RegFile
if ($LASTEXITCODE -ne 0) { Write-Error "reg import failed"; exit $LASTEXITCODE }
Write-Host "Registry restored from: $RegFile"
exit 0
