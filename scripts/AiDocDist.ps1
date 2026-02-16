<#
.SYNOPSIS
Prepares Koi documentation for AI/LLM distribution.

.DESCRIPTION
Dynamically discovers all folders and .md files under docs/ and consolidates them
into namespaced files suitable for flat-folder AI ingestion. Merges related documents
by folder while preserving all essential content.

ADRs (docs/adr/) are excluded by default - they document historical decisions and
add noise for most LLM tasks. Use -IncludeADRs to override.

New folders added under docs/ are automatically discovered and consolidated.

.PARAMETER OutputDir
Target directory for AI distribution. Default: dist/ai-context

.PARAMETER IncludeADRs
Include Architecture Decision Records (docs/adr/) in the distribution.

.PARAMETER Validate
Run validation checks after generation.

.EXAMPLE
.\scripts\AiDocDist.ps1
.\scripts\AiDocDist.ps1 -Validate
.\scripts\AiDocDist.ps1 -IncludeADRs -Validate
#>

param(
    [string]$OutputDir = "dist/ai-context",
    [switch]$IncludeADRs,
    [switch]$Validate
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
$SourceRoot = Join-Path $RootDir "docs"
$Namespace = "koi"

# Resolve OutputDir relative to repo root
if (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path $RootDir $OutputDir
}

# Folders to skip (always)
$SkipFolders = @("adr")

Write-Host "=== Koi AI Distribution Generator ===" -ForegroundColor Cyan
Write-Host "Source: docs/"
Write-Host "Target: $OutputDir"
if ($IncludeADRs) {
    $SkipFolders = @()
    Write-Host "ADRs:   included" -ForegroundColor Yellow
}
else {
    Write-Host "ADRs:   excluded (use -IncludeADRs to include)"
}
Write-Host ""

# ============================================================================
# SETUP
# ============================================================================

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Clean old distribution files
$oldFiles = Get-ChildItem -Path $OutputDir -Filter "*.md" -File
if ($oldFiles.Count -gt 0) {
    $oldFiles | Remove-Item -Force
    Write-Host "Cleaned $($oldFiles.Count) old files" -ForegroundColor Gray
}

# ============================================================================
# HELPERS
# ============================================================================

function Strip-Frontmatter {
    param([string]$Content)
    if ($Content -match '(?s)^---\r?\n.*?\r?\n---\r?\n(.*)$') {
        return $Matches[1].TrimStart()
    }
    return $Content
}

function Extract-Title {
    param([string]$Content, [string]$Fallback)
    if ($Content -match '(?m)^#\s+(.+)$') {
        return $Matches[1]
    }
    return ($Fallback -replace '-', ' ').Trim() | ForEach-Object { (Get-Culture).TextInfo.ToTitleCase($_) }
}

function Build-LinkMap {
    <#
    .SYNOPSIS
    Dynamically builds a link transformation map from discovered docs/ folders
    and root-level markdown files. Maps original doc paths to consolidated filenames.
    #>
    param(
        [string[]]$Folders,
        [string[]]$RootFiles
    )

    $map = @{}

    foreach ($folder in $Folders) {
        $key = "docs/$folder/"
        $target = "$Namespace-$folder-all.md#"
        $map[$key] = $target
    }

    # Root-level doc files
    foreach ($file in $RootFiles) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file).ToLower()
        $map["$file"] = "$Namespace-$baseName.md"
    }

    # Common relative references from within docs/
    $map["../GUIDE.md"] = "$Namespace-guide.md"
    $map["../README.md"] = "$Namespace-readme.md"
    $map["../CONTAINERS.md"] = "$Namespace-containers.md"
    $map["../CONTRIBUTING.md"] = "$Namespace-contributing.md"

    return $map
}

function Transform-Links {
    param(
        [string]$Content,
        [hashtable]$LinkMap
    )

    foreach ($pattern in $LinkMap.Keys) {
        $replacement = $LinkMap[$pattern]

        if ($pattern -match '/$') {
            # Folder pattern: docs/guides/file.md → koi-guides-all.md#file
            $escaped = [regex]::Escape($pattern)
            $Content = $Content -replace "\]\($escaped([^/)]+)\.md\)", "]($replacement`$1)"
            $Content = $Content -replace "\]\($escaped([^/)]+)\.md#([^)]+)\)", "]($replacement`$1)"
        }
        else {
            # Exact file pattern
            $escaped = [regex]::Escape($pattern)
            $Content = $Content -replace "\]\($escaped\)", "]($replacement)"
        }
    }

    return $Content
}

function Merge-Folder {
    <#
    .SYNOPSIS
    Consolidates all .md files in a docs/ subfolder into a single namespaced file.
    Recurses into subdirectories. Generates a TOC.
    #>
    param(
        [string]$FolderName,
        [string]$FolderPath,
        [hashtable]$LinkMap
    )

    $outputName = "$Namespace-$FolderName-all.md"

    if (-not (Test-Path $FolderPath)) {
        Write-Warning "  Folder not found: $FolderName (skipping)"
        return @{ Files = @(); OutputName = $null }
    }

    $files = Get-ChildItem -Path $FolderPath -Filter "*.md" -File -Recurse | Sort-Object FullName

    if ($files.Count -eq 0) {
        Write-Warning "  No .md files in: $FolderName (skipping)"
        return @{ Files = @(); OutputName = $null }
    }

    # Friendly title from folder name
    $title = (Get-Culture).TextInfo.ToTitleCase(($FolderName -replace '-', ' '))

    Write-Host "  $outputName ($($files.Count) files)" -ForegroundColor Yellow

    $tocEntries = @()
    $sections = @()

    foreach ($file in $files) {
        $fileContent = Get-Content $file.FullName -Raw -Encoding UTF8
        $stripped = Strip-Frontmatter $fileContent
        $stripped = Transform-Links $stripped $LinkMap
        $fileTitle = Extract-Title $stripped $file.BaseName

        # Note subfolder origin for files in nested directories
        $relativePath = $file.FullName.Substring($FolderPath.Length).TrimStart('\', '/')
        $subfolderNote = ""
        $tocSubfolder = ""
        if ($relativePath -match '[\\/]') {
            $subfolder = Split-Path $relativePath -Parent
            $subfolderNote = " *(from $subfolder)*"
            $tocSubfolder = " ($subfolder)"
        }

        $anchor = $fileTitle.ToLower() -replace '[^a-z0-9\s-]', '' -replace '\s+', '-'

        $tocEntries += "- [$fileTitle$tocSubfolder](#$anchor)"
        $sections += "`n## $fileTitle$subfolderNote`n`n$stripped`n`n---`n"
    }

    $dateStr = Get-Date -Format "MMMM dd, yyyy"
    $content = "# Koi - $title`n`n"
    $content += "**Consolidated from:** ``docs/$FolderName/`` ($($files.Count) files)`n"
    $content += "**Generated:** $dateStr`n`n"
    $content += "## Table of Contents`n`n"
    $content += ($tocEntries -join "`n")
    $content += "`n`n---`n"
    $content += ($sections -join "`n")

    $targetPath = Join-Path $OutputDir $outputName
    Set-Content -Path $targetPath -Value $content -Encoding UTF8
    Write-Host "    ✓ $outputName" -ForegroundColor Green

    return @{
        Files      = $files | ForEach-Object { $_.FullName }
        OutputName = $outputName
    }
}

# ============================================================================
# DISCOVER FOLDERS
# ============================================================================

$allFolders = Get-ChildItem -Path $SourceRoot -Directory |
Where-Object { $SkipFolders -notcontains $_.Name } |
Sort-Object Name

$folderNames = $allFolders | ForEach-Object { $_.Name }

# Root-level special files
$rootSpecialFiles = @("README.md", "GUIDE.md", "CONTAINERS.md", "CONTRIBUTING.md")

# Build the link map dynamically
$linkMap = Build-LinkMap -Folders $folderNames -RootFiles $rootSpecialFiles

Write-Host "Discovered $($allFolders.Count) doc folders: $($folderNames -join ', ')" -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# CONSOLIDATE EACH FOLDER
# ============================================================================

$stepNum = 0
$processedFiles = @()

Write-Host "Consolidating doc folders..." -ForegroundColor Cyan

foreach ($folder in $allFolders) {
    $stepNum++
    Write-Host "`n$stepNum. $($folder.Name)/" -ForegroundColor Cyan

    $result = Merge-Folder -FolderName $folder.Name -FolderPath $folder.FullName -LinkMap $linkMap
    $processedFiles += $result.Files
}

# ============================================================================
# ROOT-LEVEL DOCS FILES (loose .md in docs/)
# ============================================================================

$rootDocFiles = Get-ChildItem -Path $SourceRoot -Filter "*.md" -File |
Where-Object { $processedFiles -notcontains $_.FullName }

if ($rootDocFiles.Count -gt 0) {
    $stepNum++
    Write-Host "`n$stepNum. Root-level docs/ files ($($rootDocFiles.Count))..." -ForegroundColor Cyan

    foreach ($file in $rootDocFiles) {
        $targetName = "$Namespace-docs-$($file.BaseName.ToLower()).md"
        $content = Get-Content $file.FullName -Raw -Encoding UTF8
        $content = Strip-Frontmatter $content
        $content = Transform-Links $content $linkMap

        Set-Content -Path (Join-Path $OutputDir $targetName) -Value $content -Encoding UTF8
        Write-Host "    ✓ $targetName" -ForegroundColor Green
        $processedFiles += $file.FullName
    }
}

# ============================================================================
# SPECIAL ROOT FILES (outside docs/)
# ============================================================================

$stepNum++
Write-Host "`n$stepNum. Root project files..." -ForegroundColor Cyan

$specialFiles = @(
    @{ Source = "README.md"; Target = "$Namespace-readme.md" }
    @{ Source = "GUIDE.md"; Target = "$Namespace-guide.md" }
    @{ Source = "CONTAINERS.md"; Target = "$Namespace-containers.md" }
    @{ Source = "CONTRIBUTING.md"; Target = "$Namespace-contributing.md" }
)

foreach ($spec in $specialFiles) {
    $sourcePath = Join-Path $RootDir $spec.Source
    if (Test-Path $sourcePath) {
        $content = Get-Content $sourcePath -Raw -Encoding UTF8
        $content = Transform-Links $content $linkMap
        Set-Content -Path (Join-Path $OutputDir $spec.Target) -Value $content -Encoding UTF8
        Write-Host "    ✓ $($spec.Target)" -ForegroundColor Green
    }
}

# ============================================================================
# DISTRIBUTION INDEX
# ============================================================================

$stepNum++
Write-Host "`n$stepNum. Generating distribution index..." -ForegroundColor Cyan

$outputFiles = Get-ChildItem -Path $OutputDir -Filter "*.md" | Sort-Object Name
$dateStr = Get-Date -Format "MMMM dd, yyyy HH:mm"

# --- Distribution README ---

$categoryList = ($folderNames | ForEach-Object {
        "- **$Namespace-$_-all.md** - ``docs/$_/`` consolidated"
    }) -join "`n"

$specialList = ($specialFiles | ForEach-Object {
        "- **$($_.Target)** - $($_.Source)"
    }) -join "`n"

$distReadme = @"
# Koi AI Distribution

**Documentation set optimized for LLM ingestion.**

Koi is a cross-platform local network toolkit - service discovery, local DNS,
certificate mesh, health monitoring, and TLS proxy in a single binary.

## Reading Order

1. **$Namespace-readme.md** - what Koi is and why it exists
2. **$Namespace-guide.md** - tutorial walkthrough
3. **$Namespace-reference-all.md** - architecture, HTTP API, CLI, wire protocol
4. **$Namespace-guides-all.md** - per-capability deep-dives

## Consolidated Docs

$categoryList

## Root Files

$specialList

## File Naming

All files follow: ``$Namespace-[category].md``

Consolidated folder docs end with ``-all``. Root project files use their
lowercase name (e.g., ``$Namespace-readme.md``).

## ADRs

$(if ($IncludeADRs) { "Architecture Decision Records are **included** in this distribution." } else { "Architecture Decision Records (``docs/adr/``) are **excluded** from this distribution.`nRe-generate with ``-IncludeADRs`` to include them." })

## Generated

$dateStr
Total files: $($outputFiles.Count)
"@

Set-Content -Path (Join-Path $OutputDir "$Namespace-distribution-readme.md") -Value $distReadme -Encoding UTF8
Write-Host "    ✓ $Namespace-distribution-readme.md" -ForegroundColor Green

# --- Distribution Index ---

$indexContent = "# Koi Distribution Index`n`n**Generated:** $dateStr`n`n---`n`n"

# Re-read after adding the readme
$outputFiles = Get-ChildItem -Path $OutputDir -Filter "*.md" | Sort-Object Name

foreach ($file in $outputFiles) {
    $size = [math]::Round($file.Length / 1KB, 1)

    $firstLines = Get-Content $file.FullName -First 5 -Encoding UTF8
    $desc = "Documentation"
    foreach ($line in $firstLines) {
        if ($line -match '^#\s+(.+)$') {
            $desc = $Matches[1]
            break
        }
    }

    $indexContent += "- **$($file.Name)** ($size KB) - $desc`n"
}

$totalSize = ($outputFiles | Measure-Object -Property Length -Sum).Sum / 1MB
$indexContent += "`n---`n`n**Total:** $([math]::Round($totalSize, 2)) MB across $($outputFiles.Count) files"

Set-Content -Path (Join-Path $OutputDir "$Namespace-distribution-index.md") -Value $indexContent -Encoding UTF8
Write-Host "    ✓ $Namespace-distribution-index.md" -ForegroundColor Green

# ============================================================================
# VALIDATION
# ============================================================================

if ($Validate) {
    Write-Host "`n=== Validation ===" -ForegroundColor Cyan

    $finalFiles = Get-ChildItem -Path $OutputDir -Filter "*.md"
    $allSourceFiles = Get-ChildItem -Path $SourceRoot -Filter "*.md" -File -Recurse

    # Count source files (respecting skip list)
    $includedSourceFiles = $allSourceFiles | Where-Object {
        $relativePath = $_.FullName.Substring($SourceRoot.Length).TrimStart('\', '/')
        $topFolder = ($relativePath -split '[\\/]')[0]
        $SkipFolders -notcontains $topFolder
    }

    Write-Host ""
    Write-Host "Source files in docs/:   $($allSourceFiles.Count)" -ForegroundColor White
    Write-Host "  Included:              $($includedSourceFiles.Count)" -ForegroundColor Green
    Write-Host "  Skipped (ADRs):        $($allSourceFiles.Count - $includedSourceFiles.Count)" -ForegroundColor $(if ($IncludeADRs) { "Gray" } else { "Yellow" })
    Write-Host "Distribution files:      $($finalFiles.Count)" -ForegroundColor Green

    # Namespace check
    $nonCompliant = $finalFiles | Where-Object { $_.Name -notmatch "^$Namespace-" }
    if ($nonCompliant) {
        Write-Warning "Files not following namespace convention:"
        $nonCompliant | ForEach-Object { Write-Warning "  $($_.Name)" }
    }
    else {
        Write-Host "Namespace compliance:    ✓ all files use '$Namespace-' prefix" -ForegroundColor Green
    }

    # Size
    $totalSize = ($finalFiles | Measure-Object -Property Length -Sum).Sum / 1MB
    Write-Host "Total size:              $([math]::Round($totalSize, 2)) MB" -ForegroundColor Green

    # Empty file check
    $emptyFiles = $finalFiles | Where-Object { $_.Length -lt 50 }
    if ($emptyFiles) {
        Write-Warning "Suspiciously small files (<50 bytes):"
        $emptyFiles | ForEach-Object { Write-Warning "  $($_.Name) ($($_.Length) bytes)" }
    }

    Write-Host "`nValidation complete." -ForegroundColor Green
}

# ============================================================================
# DONE
# ============================================================================

Write-Host "`n=== Complete ===" -ForegroundColor Cyan
$finalCount = (Get-ChildItem -Path $OutputDir -Filter "*.md").Count
Write-Host "Generated $finalCount files in $OutputDir"
Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  Ingest all .md files from $OutputDir into your LLM context."
Write-Host "  Start with $Namespace-distribution-readme.md for reading order."
Write-Host ""
