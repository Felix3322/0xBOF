param(
    [Parameter(Mandatory=$true)][string]$BuildDir,
    [Parameter(Mandatory=$true)][string]$OutputDir,
    [string]$Version = '1.0.1'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$binaryRoot = [IO.Path]::GetFullPath($BuildDir)
if (Test-Path -LiteralPath (Join-Path $binaryRoot 'Release\0xbof.exe')) {
    $binaryRoot = Join-Path $binaryRoot 'Release'
}
$packageName = "0xBOF-$Version-windows-x64"
$outputRoot = [IO.Path]::GetFullPath($OutputDir)
$archivePath = Join-Path $outputRoot ($packageName + '.zip')
if (Test-Path -LiteralPath $archivePath) { throw "Refusing to overwrite $archivePath" }
foreach ($binaryName in @('0xbof.exe','0xbof-benchmark.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $binaryRoot $binaryName))) { throw "Missing $binaryName" }
}
$reportedVersion = & (Join-Path $binaryRoot '0xbof.exe') --version
if ($LASTEXITCODE -ne 0 -or $reportedVersion.Trim() -ne $Version) { throw 'Executable version does not match package version' }
$buildManifest = Get-Content -LiteralPath (Join-Path $projectRoot 'results/build-windows-x64.json') -Raw | ConvertFrom-Json
if ($buildManifest.version -ne $Version) { throw 'Create the matching build manifest before packaging this version' }
foreach ($binaryName in @('0xbof.exe','0xbof-benchmark.exe')) {
    $binaryHash = (Get-FileHash -LiteralPath (Join-Path $binaryRoot $binaryName) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($buildManifest.binaries.$binaryName -ne $binaryHash) { throw "Build manifest hash mismatch: $binaryName" }
}
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$stagingRoot = Join-Path ([IO.Path]::GetFullPath($BuildDir)) ('package-' + [Guid]::NewGuid().ToString('N'))
$packageRoot = Join-Path $stagingRoot $packageName
New-Item -ItemType Directory -Path $packageRoot | Out-Null
foreach ($binaryName in @('0xbof.exe','0xbof-benchmark.exe')) {
    Copy-Item -LiteralPath (Join-Path $binaryRoot $binaryName) -Destination $packageRoot
}
foreach ($fileName in @('LICENSE','README.md','THIRD_PARTY_NOTICES.md')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $fileName) -Destination $packageRoot
}
foreach ($directoryName in @('licenses','docs','results')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $directoryName) -Destination $packageRoot -Recurse
}
$hashLines = Get-ChildItem -LiteralPath $packageRoot -File -Recurse | Sort-Object FullName | ForEach-Object {
    $relativeName = [IO.Path]::GetRelativePath($packageRoot, $_.FullName).Replace('\','/')
    $digest = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$digest  $relativeName"
}
[IO.File]::WriteAllLines((Join-Path $packageRoot 'SHA256SUMS.txt'), $hashLines, [Text.UTF8Encoding]::new($false))
Compress-Archive -LiteralPath $packageRoot -DestinationPath $archivePath -CompressionLevel Optimal
Get-Item -LiteralPath $archivePath | Select-Object FullName,Length
