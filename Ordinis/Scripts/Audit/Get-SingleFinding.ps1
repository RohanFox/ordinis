<#
.SYNOPSIS  Audit a single finding – used by the remote execution path.
.PARAMETER Method          Check method (registry, secedit, auditpol, service, etc.)
.PARAMETER RegistryPath    Registry hive\key path
.PARAMETER RegistryItem    Registry value name
.PARAMETER MethodArgument  Argument for secedit/auditpol/service methods
#>
param(
    [string]$Method         = '',
    [string]$RegistryPath   = '',
    [string]$RegistryItem   = '',
    [string]$MethodArgument = ''
)

$ErrorActionPreference = 'SilentlyContinue'

switch ($Method.ToLower()) {
    'registry' {
        try {
            $val = Get-ItemPropertyValue -Path $RegistryPath -Name $RegistryItem
            Write-Output $val
        } catch {
            Write-Output '-NODATA-'
        }
    }
    'secedit' {
        $tmp = [System.IO.Path]::GetTempFileName()
        secedit /export /cfg $tmp /areas SECURITYPOLICY | Out-Null
        $content = Get-Content $tmp
        Remove-Item $tmp -Force
        $line = $content | Where-Object { $_ -match "^$MethodArgument" }
        if ($line) { Write-Output ($line -split '=')[1].Trim() }
        else       { Write-Output '-NODATA-' }
    }
    'auditpol' {
        $tmp = [System.IO.Path]::GetTempFileName() + '.csv'
        auditpol /backup /file:$tmp | Out-Null
        $csv = Import-Csv $tmp
        Remove-Item $tmp -Force
        $row = $csv | Where-Object { $_.Subcategory -eq $MethodArgument }
        if ($row) { Write-Output $row.'Inclusion Setting' }
        else      { Write-Output '-NODATA-' }
    }
    'service' {
        $svc = Get-Service -Name $MethodArgument -ErrorAction SilentlyContinue
        if ($svc) { Write-Output $svc.StartType }
        else      { Write-Output '-NODATA-' }
    }
    default {
        Write-Output '-NODATA-'
    }
}
