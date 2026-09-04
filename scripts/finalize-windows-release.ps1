[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $SourceDirectory,

    [Parameter(Mandatory)]
    [string] $OutputDirectory,

    [Parameter(Mandatory)]
    [string] $VersionTag
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AbsolutePath([string] $Path) {
    if ([IO.Path]::IsPathFullyQualified($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}
$sourcePath = Get-AbsolutePath $SourceDirectory
$outputPath = Get-AbsolutePath $OutputDirectory
$version = $VersionTag.TrimStart('v')
$targets = @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')

if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
    throw "Windows artifact source '$sourcePath' does not exist."
}

New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

foreach ($target in $targets) {
    $archiveDirectoryName = "koi-$VersionTag-$target"
    $matches = @(Get-ChildItem -LiteralPath $sourcePath -Recurse -File -Filter koi.exe |
        Where-Object { $_.Directory.Name -eq $archiveDirectoryName })
    if ($matches.Count -ne 1) {
        throw "Expected one '$archiveDirectoryName/koi.exe' under '$sourcePath'; found $($matches.Count)."
    }

    $executable = $matches[0]
    $metadata = $executable.VersionInfo
    $expectedMetadata = [ordered]@{
        ProductName = 'Koi'
        ProductVersion = $version
        FileVersion = $version
        CompanyName = 'Sylin.org'
        OriginalFilename = 'koi.exe'
        LegalCopyright = 'Copyright (c) Sylin.org contributors'
    }
    foreach ($entry in $expectedMetadata.GetEnumerator()) {
        $actual = [string]$metadata.($entry.Key)
        if ($actual -ne $entry.Value) {
            throw "$target metadata '$($entry.Key)' is '$actual'; expected '$($entry.Value)'."
        }
    }

    $archivePath = Join-Path $outputPath "$archiveDirectoryName.zip"
    if (Test-Path -LiteralPath $archivePath) {
        throw "Final archive '$archivePath' already exists."
    }

    Push-Location -LiteralPath $executable.Directory.Parent.FullName
    try {
        & 7z a -tzip $archivePath $archiveDirectoryName
        if ($LASTEXITCODE -ne 0) { throw "7z failed for '$archiveDirectoryName'." }
    }
    finally { Pop-Location }

    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumPath = "$archivePath.sha256"
    [IO.File]::WriteAllText(
        $checksumPath,
        "$hash  $([IO.Path]::GetFileName($archivePath))`n",
        [Text.UTF8Encoding]::new($false))

    Write-Host "WINDOWS-RELEASE|$target|UNSIGNED|$([IO.Path]::GetFileName($archivePath))"
}
