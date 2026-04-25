<#
.SYNOPSIS  Configure IPv6 adapter settings and transition protocols.
.PARAMETER AdapterName  Adapter name (* for all adapters)
.PARAMETER Action       DisableAdapter | DisableTeredo | DisableISATAP | Disable6to4 |
                        EnablePrivacyExtensions | DisableAll
#>
param(
    [string]$AdapterName = '*',
    [Parameter(Mandatory)][string]$Action
)

$ErrorActionPreference = 'Continue'

switch ($Action.ToLower()) {
    'disableadapter' {
        $adapters = if ($AdapterName -eq '*') {
            Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        } else {
            Get-NetAdapter -Name $AdapterName
        }
        foreach ($a in $adapters) {
            Disable-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            Write-Host "Disabled IPv6 on: $($a.Name)"
        }
    }
    'disableteredo' {
        netsh interface teredo set state disabled
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' `
            -Name 'DisabledComponents' -Value 0x01 -Type DWord -Force
        Write-Host 'Teredo disabled.'
    }
    'disableisatap' {
        netsh interface isatap set state disabled
        Write-Host 'ISATAP disabled.'
    }
    'disable6to4' {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\6to4' `
            -Name 'Start' -Value 4 -Type DWord -Force
        Write-Host '6to4 disabled.'
    }
    'enableprivacyextensions' {
        netsh interface ipv6 set privacy state=enabled store=persistent
        Write-Host 'IPv6 privacy extensions enabled.'
    }
    'disableall' {
        # Disable all IPv6 transition technologies (CIS recommended)
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' `
            -Name 'DisabledComponents' -Value 0xFF -Type DWord -Force
        netsh interface teredo set state disabled
        netsh interface isatap set state disabled
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\6to4' -Name 'Start' -Value 4 -Type DWord -Force
        Write-Host 'All IPv6 transition technologies disabled.'
    }
    default {
        Write-Error "Unknown action: $Action"
        exit 1
    }
}
exit 0
