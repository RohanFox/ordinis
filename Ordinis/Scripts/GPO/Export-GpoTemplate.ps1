<#
.SYNOPSIS  Export registry-based findings to an LGPO.exe-compatible text file.
.PARAMETER FindingsJson  Path to a JSON array of finding objects (registry method only).
.PARAMETER OutputFile    Destination .txt file for LGPO /t import.
#>
param(
    [Parameter(Mandatory)][string]$FindingsJson,
    [Parameter(Mandatory)][string]$OutputFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $FindingsJson)) {
    Write-Error "Findings file not found: $FindingsJson"
    exit 1
}

$findings = Get-Content $FindingsJson -Raw | ConvertFrom-Json

$outDir = Split-Path $OutputFile -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$lines = [System.Collections.Generic.List[string]]::new()

foreach ($f in $findings) {
    # Only registry-method findings can go into LGPO text format
    if ($f.Method -ne 'registry') { continue }

    $params = $f.CheckParams
    $regPath = $params.RegistryPath
    $regItem = $params.RegistryItem
    $value   = $f.ExpectedValue

    if ([string]::IsNullOrWhiteSpace($regPath) -or [string]::IsNullOrWhiteSpace($regItem)) { continue }

    # Determine LGPO hive section
    $section = if ($regPath -match '^HKLM[:\\]') { 'Computer' }
               elseif ($regPath -match '^HKCU[:\\]') { 'User' }
               else { continue }

    # Strip hive prefix to get the subkey path
    $subkey = $regPath -replace '^HK[LC][MU][:\\]', ''

    # Determine registry value type
    $valType = 'DWORD'
    try {
        $numericValue = [int]$value
        $valType = 'DWORD'
        $valData = $numericValue
    } catch {
        $valType = 'SZ'
        $valData = $value
    }

    # LGPO text format: Section / SubKey / ValueName / Type:Data
    $lines.Add($section)
    $lines.Add($subkey)
    $lines.Add($regItem)
    $lines.Add("${valType}:${valData}")
    $lines.Add('')   # blank line between entries
}

if ($lines.Count -eq 0) {
    Write-Warning "No registry findings found in the input file. Output file not written."
    exit 0
}

Set-Content -Path $OutputFile -Value $lines -Encoding UTF8
Write-Host "LGPO template written: $OutputFile ($($lines.Count / 5) entries)"
exit 0
