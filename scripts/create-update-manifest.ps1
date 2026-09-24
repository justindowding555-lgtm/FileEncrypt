param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$InstallerPath,
    [string]$Repository = 'justindowding555-lgtm/FileEncrypt',
    [string]$Notes = ''
)

$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw 'Version must be SemVer, for example 0.2.0.'
}
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$appVersion = (Get-Content -LiteralPath (Join-Path $projectRoot 'src-tauri/tauri.conf.json') -Raw | ConvertFrom-Json).version
if ($Version -ne $appVersion) { throw "Version $Version does not match app version $appVersion." }
$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$signaturePath = "$installer.sig"
if (-not (Test-Path -LiteralPath $signaturePath -PathType Leaf)) {
    throw "Missing signature: $signaturePath"
}
$signature = (Get-Content -LiteralPath $signaturePath -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($signature)) { throw 'The signature file is empty.' }
$filename = [Uri]::EscapeDataString([IO.Path]::GetFileName($installer))
$manifest = @{
    version = $Version
    notes = $Notes
    platforms = @{
        'windows-x86_64' = @{
            url = "https://github.com/$Repository/releases/download/v$Version/$filename"
            signature = $signature
        }
    }
}
$output = Join-Path ([IO.Path]::GetDirectoryName($installer)) 'latest.json'
$json = $manifest | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($output, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Created $output"
