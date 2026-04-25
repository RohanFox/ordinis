<#
.SYNOPSIS  Restore local security policy from a secedit INI backup.
.PARAMETER IniFile  Full path to the .ini backup file
#>
param([Parameter(Mandatory)][string]$IniFile)

if (-not (Test-Path $IniFile)) { Write-Error "Backup not found: $IniFile"; exit 1 }

$db = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), '.sdb')
secedit /configure /cfg $IniFile /overwrite /areas SECURITYPOLICY,USER_RIGHTS,AUDITPOLICY /db $db /quiet

if ($LASTEXITCODE -ne 0) { Write-Error "secedit restore failed"; exit $LASTEXITCODE }
Remove-Item $db -Force -ErrorAction SilentlyContinue
Write-Host "Security policy restored from: $IniFile"
exit 0
