<#
.SYNOPSIS  Set a User Rights Assignment privilege via secedit.
.PARAMETER Privilege  Privilege constant (e.g. SeNetworkLogonRight)
.PARAMETER Accounts   Semicolon-separated list of accounts (e.g. Administrators;NETWORK SERVICE)
                      Use empty string to remove all accounts from the privilege.
#>
param(
    [Parameter(Mandatory)][string]$Privilege,
    [string]$Accounts = ''
)

$cfgFile = [System.IO.Path]::GetTempFileName()
$dbFile  = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), '.sdb')

secedit /export /cfg $cfgFile /areas USER_RIGHTS | Out-Null

$content = Get-Content $cfgFile -Encoding Unicode

# Build the replacement line
$accountList = if ($Accounts) {
    ($Accounts -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ','
} else { '' }

$newLine = if ($accountList) { "$Privilege = $accountList" } else { "$Privilege = " }

# Replace existing or insert
if ($content -match "^$Privilege\s*=") {
    $content = $content -replace "^$Privilege\s*=.*", $newLine
} else {
    $content += "`r`n$newLine"
}

Set-Content -Path $cfgFile -Value $content -Encoding Unicode

secedit /configure /cfg $cfgFile /overwrite /areas USER_RIGHTS /db $dbFile /quiet

if ($LASTEXITCODE -ne 0) {
    Write-Error "secedit configure failed (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

Remove-Item $cfgFile, $dbFile -Force -ErrorAction SilentlyContinue
Write-Host "User rights applied: $Privilege"
exit 0
