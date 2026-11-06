$ErrorActionPreference = 'Stop'
$projectDirectory = $PSScriptRoot
$pythonPath = Join-Path $projectDirectory '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    python -m venv (Join-Path $projectDirectory '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create build environment' }
}
Push-Location -LiteralPath $projectDirectory
try {
    & $pythonPath -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
    & $pythonPath -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    if (Test-Path -LiteralPath .git) {
        & $pythonPath scripts/check_secrets.py --all
        if ($LASTEXITCODE -ne 0) { throw 'Source secret check failed' }
    }
    & $pythonPath -m PyInstaller --noconfirm --onefile --windowed --name JoplinPluginVault --collect-all cryptography --specpath build --workpath build/pyinstaller main.py
    if ($LASTEXITCODE -ne 0) { throw 'Packaging failed' }
    Copy-Item -LiteralPath README.md,README.en.md -Destination dist

    $version = & $pythonPath -c 'from vault import __version__; print(__version__)'
    if ($LASTEXITCODE -ne 0) { throw 'Could not read application version' }
    New-Item -ItemType Directory -Path release -Force | Out-Null
    $portableArchive = "release/JoplinPluginVault-$version-win-x64.zip"
    $sourceArchive = "release/JoplinPluginVault-$version-source.zip"
    Compress-Archive -LiteralPath dist/JoplinPluginVault.exe,dist/README.md,dist/README.en.md -DestinationPath $portableArchive -Force

    # Copy only source files, excluding caches and local application data.
    $sourceStage = Join-Path $projectDirectory ('build/source-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $sourceStage | Out-Null
    try {
        Copy-Item -LiteralPath main.py,build.ps1,requirements.txt,README.md,README.en.md,.gitignore,.gitattributes -Destination $sourceStage
        foreach ($folder in @('vault', 'tests', 'scripts')) {
            $targetFolder = Join-Path $sourceStage $folder
            New-Item -ItemType Directory -Path $targetFolder | Out-Null
            Get-ChildItem -LiteralPath $folder -File -Filter '*.py' | Copy-Item -Destination $targetFolder
        }
        New-Item -ItemType Directory -Path (Join-Path $sourceStage '.githooks') | Out-Null
        Copy-Item -LiteralPath .githooks/pre-commit -Destination (Join-Path $sourceStage '.githooks/pre-commit')
        Compress-Archive -Path (Join-Path $sourceStage '*') -DestinationPath $sourceArchive -Force
    } finally {
        $resolvedStage = [System.IO.Path]::GetFullPath($sourceStage)
        $stageParent = [System.IO.Path]::GetFullPath((Join-Path $projectDirectory 'build'))
        if ([System.IO.Path]::GetDirectoryName($resolvedStage) -ne $stageParent) { throw 'Invalid source staging path' }
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
    $checksums = @($portableArchive, $sourceArchive) | ForEach-Object {
        $hash = Get-FileHash -LiteralPath $_ -Algorithm SHA256
        '{0}  {1}' -f $hash.Hash.ToLowerInvariant(), [System.IO.Path]::GetFileName($hash.Path)
    }
    $checksums | Set-Content -LiteralPath "release/SHA256SUMS-$version.txt" -Encoding ascii
} finally { Pop-Location }
