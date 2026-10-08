$Command = @($args)
$ErrorActionPreference = 'Stop'
if (-not $Command) { throw 'Provide a command, for example cargo check --manifest-path src-tauri/Cargo.toml.' }
if ($env:OS -eq 'Windows_NT' -and -not (Get-Command clang-cl.exe -ErrorAction SilentlyContinue) -and -not $env:CC) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install the Visual Studio C++ build tools or configure CC with a supported C compiler.' }
    $installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $installation) { throw 'The Visual Studio C++ tools are required to compile the runtime-dispatched cipher.' }
    $setup = Join-Path $installation 'Common7/Tools/VsDevCmd.bat'
    # Capture only compiler environment variables, without printing the process environment.
    $compilerEnvironment = & $env:ComSpec /d /c "call `"$setup`" -no_logo -arch=x64 -host_arch=x64 && set"
    if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the Visual Studio compiler environment.' }
    foreach ($line in $compilerEnvironment) {
        if ($line -match '^(PATH|INCLUDE|LIB|LIBPATH|VCToolsInstallDir|WindowsSdkDir|WindowsSDKVersion)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }
    $env:CC = (Get-Command cl.exe -ErrorAction Stop).Source
}
$executable = $Command[0]
$arguments = if ($Command.Length -gt 1) { $Command[1..($Command.Length - 1)] } else { @() }
& $executable @arguments
exit $LASTEXITCODE
