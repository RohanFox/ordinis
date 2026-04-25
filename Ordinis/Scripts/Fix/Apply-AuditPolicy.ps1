<#
.SYNOPSIS  Set an audit policy subcategory.
.PARAMETER Subcategory  Audit subcategory name
.PARAMETER Setting      Target value (Success, Failure, 'Success and Failure', 'No Auditing')
#>
param(
    [Parameter(Mandatory)][string]$Subcategory,
    [Parameter(Mandatory)][string]$Setting
)

$success = if ($Setting -ilike '*success*') { 'enable' } else { 'disable' }
$failure = if ($Setting -ilike '*failure*') { 'enable' } else { 'disable' }

auditpol /set /subcategory:"$Subcategory" /success:$success /failure:$failure

if ($LASTEXITCODE -ne 0) {
    Write-Error "auditpol returned exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Audit policy set: $Subcategory -> $Setting"
exit 0
