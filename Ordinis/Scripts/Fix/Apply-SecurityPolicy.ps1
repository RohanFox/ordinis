<#
.SYNOPSIS  Apply a single security policy value via secedit.
.PARAMETER PolicyKey    INI key name (e.g. MinimumPasswordLength)
.PARAMETER PolicyValue  New value
#>
param(
    [Parameter(Mandatory)][string]$PolicyKey,
    [Parameter(Mandatory)][string]$PolicyValue
)

$ErrorActionPreference = 'Stop'

$cfgFile = [System.IO.Path]::GetTempFileName()
$dbFile  = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), '.sdb')

# Export current policy
secedit /export /cfg $cfgFile /areas SECURITYPOLICY | Out-Null

# Read, update, write back
$content = Get-Content $cfgFile
$updated = $content -replace "^($PolicyKey\s*=\s*).*", "`$1$PolicyValue"

# If line not present at all, append to [System Access] section
if ($updated -notmatch "^$PolicyKey\s*=") {
    $updated = $updated -replace '(\[System Access\])', "`$1`r`n$PolicyKey = $PolicyValue"
}

Set-Content -Path $cfgFile -Value $updated -Encoding Unicode

# Apply
secedit /configure /cfg $cfgFile /overwrite /areas SECURITYPOLICY /db $dbFile /quiet

if ($LASTEXITCODE -ne 0) {
    Write-Error "secedit returned exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Remove-Item $cfgFile, $dbFile -Force -ErrorAction SilentlyContinue
Write-Host "Applied: $PolicyKey = $PolicyValue"
exit 0
