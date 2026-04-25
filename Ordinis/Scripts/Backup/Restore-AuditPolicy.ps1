<#
.SYNOPSIS  Restore audit policy from an auditpol CSV backup.
.PARAMETER CsvFile  Full path to the .csv backup file
#>
param([Parameter(Mandatory)][string]$CsvFile)

if (-not (Test-Path $CsvFile)) { Write-Error "Backup not found: $CsvFile"; exit 1 }
auditpol /restore /file:$CsvFile
if ($LASTEXITCODE -ne 0) { Write-Error "auditpol restore failed"; exit $LASTEXITCODE }
Write-Host "Audit policy restored from: $CsvFile"
exit 0
