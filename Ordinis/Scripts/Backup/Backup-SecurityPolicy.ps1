<#
.SYNOPSIS  Export the full local security policy to an INI file.
.PARAMETER OutputFile  Full path for the output .ini file
#>
param([Parameter(Mandatory)][string]$OutputFile)

$dir = Split-Path $OutputFile -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

secedit /export /cfg $OutputFile /areas SECURITYPOLICY,USER_RIGHTS,AUDITPOLICY

if ($LASTEXITCODE -ne 0) {
    Write-Error "secedit export failed (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

Write-Host "Security policy backup saved: $OutputFile"
exit 0
