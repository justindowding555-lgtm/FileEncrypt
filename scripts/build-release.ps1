param(
    [Parameter(Mandatory = $true)][string]$PrivateKeyPath,
    [Parameter(Mandatory = $true)][string]$PublicKeyPath
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$private = (Resolve-Path -LiteralPath $PrivateKeyPath).Path
$public = (Get-Content -LiteralPath $PublicKeyPath -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($public)) {
    throw 'The updater public key is empty.'
}
$releasePublic = (Get-Content -LiteralPath (Join-Path $projectRoot 'src-tauri/tauri.release.conf.json') -Raw | ConvertFrom-Json).plugins.updater.pubkey
if ($releasePublic -ne $public) {
    throw 'The release configuration public key does not match the selected keypair.'
}
$tauriVersion = (Get-Content -LiteralPath (Join-Path $projectRoot 'src-tauri/tauri.conf.json') -Raw | ConvertFrom-Json).version
$npmVersion = (Get-Content -LiteralPath (Join-Path $projectRoot 'package.json') -Raw | ConvertFrom-Json).version
$cargoManifest = Get-Content -LiteralPath (Join-Path $projectRoot 'src-tauri/Cargo.toml') -Raw
$cargoVersion = [regex]::Match($cargoManifest, '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
if ($tauriVersion -ne $npmVersion -or $tauriVersion -ne $cargoVersion) {
    throw "Version mismatch: Tauri=$tauriVersion, npm=$npmVersion, Cargo=$cargoVersion."
}

$previousPrivate = $env:TAURI_SIGNING_PRIVATE_KEY
$previousPrivatePath = $env:TAURI_SIGNING_PRIVATE_KEY_PATH
$previousPassword = $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD
$previousPublic = $env:FILEENCRYPT_UPDATER_PUBKEY
$env:TAURI_SIGNING_PRIVATE_KEY = (Get-Content -LiteralPath $private -Raw).Trim()
Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PATH -ErrorAction SilentlyContinue
$env:FILEENCRYPT_UPDATER_PUBKEY = $public
Push-Location $projectRoot
try {
    if ([string]::IsNullOrEmpty($env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD)) {
        $protected = Read-Host 'Enter the updater signing key password' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($protected)
        try {
            $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            $protected.Dispose()
        }
    }
    if ([string]::IsNullOrEmpty($env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD)) {
        throw 'The updater signing key password cannot be empty.'
    }
    npm run tauri build -- --config src-tauri/tauri.release.conf.json --bundles nsis
    if ($LASTEXITCODE -ne 0) { throw "Tauri release build failed ($LASTEXITCODE)." }
} finally {
    Pop-Location
    if ($null -eq $previousPrivate) { Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY -ErrorAction SilentlyContinue }
    else { $env:TAURI_SIGNING_PRIVATE_KEY = $previousPrivate }
    if ($null -eq $previousPrivatePath) { Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PATH -ErrorAction SilentlyContinue }
    else { $env:TAURI_SIGNING_PRIVATE_KEY_PATH = $previousPrivatePath }
    if ($null -eq $previousPassword) { Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD -ErrorAction SilentlyContinue }
    else { $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = $previousPassword }
    if ($null -eq $previousPublic) { Remove-Item Env:FILEENCRYPT_UPDATER_PUBKEY -ErrorAction SilentlyContinue }
    else { $env:FILEENCRYPT_UPDATER_PUBKEY = $previousPublic }
}

Write-Host 'Signed installer and .sig are in src-tauri/target/release/bundle/nsis.'
