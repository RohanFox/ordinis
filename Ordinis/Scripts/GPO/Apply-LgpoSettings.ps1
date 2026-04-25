<#
.SYNOPSIS  Apply a pre-built LGPO text file using LGPO.exe.
           Falls back to direct registry writes if LGPO.exe is not available.
.PARAMETER LgpoFile   Path to the LGPO .txt template file (from Export-GpoTemplate.ps1).
.PARAMETER LgpoExe    Path to LGPO.exe (default: .\Tools\LGPO.exe next to the script).
#>
param(
    [Parameter(Mandatory)][string]$LgpoFile,
    [string]$LgpoExe = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $LgpoFile)) {
    Write-Error "LGPO file not found: $LgpoFile"
    exit 1
}

# Resolve LGPO.exe path
if ([string]::IsNullOrWhiteSpace($LgpoExe)) {
    $scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
    $LgpoExe = Join-Path (Split-Path $scriptDir -Parent | Split-Path -Parent) 'Tools\LGPO.exe'
}

if (Test-Path $LgpoExe) {
    Write-Host "Applying LGPO template via LGPO.exe: $LgpoFile"
    & $LgpoExe /t $LgpoFile
    if ($LASTEXITCODE -ne 0) {
        Write-Error "LGPO.exe exited with code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    Write-Host "LGPO settings applied successfully."
    exit 0
}

# Fallback: parse the LGPO text file and apply directly via registry
Write-Warning "LGPO.exe not found at '$LgpoExe'. Applying settings directly via registry."

$lines  = Get-Content $LgpoFile -Encoding UTF8 | Where-Object { $_ -ne $null }
$i      = 0
$applied = 0
$errors  = 0

while ($i -lt $lines.Count) {
    # Expect: Section / SubKey / ValueName / Type:Data (then blank line)
    if (($i + 3) -ge $lines.Count) { break }

    $section   = $lines[$i].Trim()
    $subkey    = $lines[$i+1].Trim()
    $valueName = $lines[$i+2].Trim()
    $typeData  = $lines[$i+3].Trim()
    $i += 5   # advance past entry + blank line

    if ([string]::IsNullOrWhiteSpace($section)) { continue }

    $hive = if ($section -eq 'Computer') { 'HKLM' } else { 'HKCU' }
    $fullPath = "${hive}:\${subkey}"

    if ($typeData -notmatch '^(\w+):(.*)$') {
        Write-Warning "Skipping malformed entry: $typeData"
        continue
    }
    $regType = $Matches[1]
    $regData = $Matches[2]

    try {
        if (-not (Test-Path $fullPath)) {
            New-Item -Path $fullPath -Force | Out-Null
        }

        switch ($regType.ToUpper()) {
            'DWORD'  { Set-ItemProperty -Path $fullPath -Name $valueName -Value ([int]$regData) -Type DWord }
            'QWORD'  { Set-ItemProperty -Path $fullPath -Name $valueName -Value ([long]$regData) -Type QWord }
            'SZ'     { Set-ItemProperty -Path $fullPath -Name $valueName -Value $regData -Type String }
            'EXSZ'   { Set-ItemProperty -Path $fullPath -Name $valueName -Value $regData -Type ExpandString }
            default  { Set-ItemProperty -Path $fullPath -Name $valueName -Value $regData }
        }
        $applied++
        Write-Verbose "Set $fullPath\$valueName = $regData ($regType)"
    } catch {
        Write-Warning "Failed to set ${fullPath}\${valueName}: $_"
        $errors++
    }
}

Write-Host "Registry fallback complete: $applied applied, $errors errors."
if ($errors -gt 0) { exit 1 } else { exit 0 }
