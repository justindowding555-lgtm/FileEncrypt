param(
    [Parameter(Mandatory = $true)][string]$NotesPath,
    [switch]$Publish
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$version = (Get-Content -LiteralPath (Join-Path $projectRoot 'src-tauri/tauri.conf.json') -Raw | ConvertFrom-Json).version
$tag = "v$version"
$artifactDirectory = Join-Path $projectRoot 'src-tauri/target/release/bundle/nsis'
$installer = Join-Path $artifactDirectory "FileEncrypt_${version}_x64-setup.exe"
$manifestPath = Join-Path $artifactDirectory 'latest.json'
node (Join-Path $PSScriptRoot 'verify-update.mjs') $installer $manifestPath
if ($LASTEXITCODE -ne 0) { throw 'Release artifact validation failed.' }
$notes = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $NotesPath).Path)
Push-Location $projectRoot
try {
    if (git status --porcelain) { throw 'Commit the release source before publishing.' }
    $commit = (git rev-parse HEAD).Trim()
    $credentialLines = "protocol=https`nhost=github.com`n`n" | git credential fill
    if ($LASTEXITCODE -ne 0) { throw 'GitHub credentials are unavailable.' }
    $credentialFields = @{}
    foreach ($line in $credentialLines) {
        $parts = $line -split '=', 2
        if ($parts.Length -eq 2) { $credentialFields[$parts[0]] = $parts[1] }
    }
    if (-not $credentialFields['password']) { throw 'GitHub access credential is missing.' }
    $headers = @{
        Authorization = 'Bearer ' + $credentialFields['password']
        'User-Agent' = 'FileEncrypt-release'
        Accept = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
    }
    $api = 'https://api.github.com/repos/justindowding555-lgtm/FileEncrypt'
    # Confirm the exact release commit is already on GitHub.
    $remoteCommit = Invoke-RestMethod -Uri "$api/commits/$commit" -Headers $headers
    if ($remoteCommit.sha -ne $commit) { throw 'Release commit is not available on GitHub.' }
    $releases = Invoke-RestMethod -Uri "$api/releases" -Headers $headers
    $release = $releases | Where-Object { $_.tag_name -eq $tag } | Select-Object -First 1
    if ($release -and -not $release.draft) { throw "$tag is already published; use a new version." }
    if ($release -and $release.target_commitish -ne $commit) { throw 'The existing draft targets a different source commit. Inspect it before proceeding.' }
    if (-not $release) {
        $body = @{tag_name=$tag;target_commitish=$commit;name="FileEncrypt $version";body=$notes;draft=$true;prerelease=$false} | ConvertTo-Json
        $release = Invoke-RestMethod -Method Post -Uri "$api/releases" -Headers $headers -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body))
    } else {
        $body = @{name="FileEncrypt $version";body=$notes} | ConvertTo-Json
        $release = Invoke-RestMethod -Method Patch -Uri "$api/releases/$($release.id)" -Headers $headers -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body))
    }
    foreach ($path in @($installer, "$installer.sig", $manifestPath)) {
        $name = [IO.Path]::GetFileName($path)
        $localHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $existing = @($release.assets) | Where-Object { $_.name -eq $name } | Select-Object -First 1
        if ($existing) {
            if ($existing.digest -ne "sha256:$localHash") { throw "Existing draft asset $name differs; inspect it before replacement." }
            continue
        }
        $upload = ($release.upload_url -replace '\{.*$', '') + '?name=' + [Uri]::EscapeDataString($name)
        $asset = Invoke-RestMethod -Method Post -Uri $upload -Headers $headers -ContentType 'application/octet-stream' -InFile $path
        if ($asset.size -ne (Get-Item -LiteralPath $path).Length -or $asset.digest -ne "sha256:$localHash") { throw "Uploaded $name failed size or checksum validation." }
        Write-Host "Uploaded and verified $name"
    }
    $release = Invoke-RestMethod -Uri "$api/releases/$($release.id)" -Headers $headers
    foreach ($path in @($installer, "$installer.sig", $manifestPath)) {
        $name = [IO.Path]::GetFileName($path)
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $asset = @($release.assets) | Where-Object { $_.name -eq $name } | Select-Object -First 1
        if (-not $asset -or $asset.state -ne 'uploaded' -or $asset.digest -ne "sha256:$hash") { throw "Draft asset validation failed for $name." }
    }
    if ($Publish) {
        $body = @{draft=$false;prerelease=$false;make_latest='true'} | ConvertTo-Json
        $release = Invoke-RestMethod -Method Patch -Uri "$api/releases/$($release.id)" -Headers $headers -ContentType 'application/json' -Body $body
        Write-Host "Published $($release.html_url)"
    } else { Write-Host "Verified draft: $($release.html_url)" }
} finally {
    if ($credentialFields) { $credentialFields.Clear() }
    $credentialLines = $null
    $headers = $null
    Pop-Location
}
