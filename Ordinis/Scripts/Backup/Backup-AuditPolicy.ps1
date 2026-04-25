<#
.SYNOPSIS  Export the audit policy to a CSV file.
.PARAMETER OutputFile  Full path for the output .csv file
#>
param([Parameter(Mandatory)][string]$OutputFile)

$dir = Split-Path $OutputFile -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

auditpol /backup /file:$OutputFile

if ($LASTEXITCODE -ne 0) {
    Write-Error "auditpol backup failed (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

Write-Host "Audit policy backup saved: $OutputFile"
exit 0
