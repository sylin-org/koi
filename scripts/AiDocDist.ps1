<#
.SYNOPSIS
Prepares Koi documentation for AI/LLM distribution.

.DESCRIPTION
Dynamically discovers all folders and .md files under docs/ and consolidates them
into namespaced files suitable for flat-folder AI ingestion. Merges related documents
by folder while preserving all essential content.

The default bundle contains current operating documentation and the current
decision/epic/ledger. Dated ADR and research corpora are opt-in. Navigation-only
retired plan directories are never consolidated into the current reading path.

New folders added under docs/ are automatically discovered and consolidated.

.PARAMETER OutputDir
Target directory for AI distribution. Default: dist/ai-context

.PARAMETER IncludeADRs
Include Architecture Decision Records (docs/adr/) in the distribution.

.PARAMETER IncludeResearch
Include dated assessments, research and prior-art evidence.

.PARAMETER Validate
Run validation checks after generation.

.EXAMPLE
.\scripts\AiDocDist.ps1
.\scripts\AiDocDist.ps1 -Validate
.\scripts\AiDocDist.ps1 -IncludeADRs -Validate
.\scripts\AiDocDist.ps1 -IncludeResearch -Validate
#>

param(
    [string]$OutputDir = "dist/ai-context",
    [switch]$IncludeADRs,
    [switch]$IncludeResearch,
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

# Current navigation does not ingest retired-plan landing pages.
$SkipFolders = @("archive", "plans", "prompts", "proposals")
$SkipRootFiles = @()
if (-not $IncludeADRs) { $SkipFolders += "adr" }
if (-not $IncludeResearch) {
    $SkipFolders += @("assessment", "research", "prior-art")
    $SkipRootFiles += "distribution-prior-art.md"
}

Write-Host "=== Koi AI Distribution Generator ===" -ForegroundColor Cyan
Write-Host "Source: docs/"
Write-Host "Target: $OutputDir"
if ($IncludeADRs) {
    Write-Host "ADRs:   included" -ForegroundColor Yellow
}
else {
    Write-Host "ADR corpus: excluded (current decision is included; use -IncludeADRs for all)"
}
Write-Host "Research corpus: $(if ($IncludeResearch) { 'included' } else { 'excluded (use -IncludeResearch)' })"
Write-Host ""

# ============================================================================
# SETUP
# ============================================================================

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Clean old distribution files
$oldFiles = Get-ChildItem -Path $OutputDir -Filter "$Namespace-*.md" -File
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

function Get-MarkdownLines {
    # Fenced examples must not supply headings, anchors, or navigable links.
    param([string]$Content)
    $fence = $null
    foreach ($line in ($Content -split '\r?\n')) {
        $prose = -not $fence
        if ($line -match '^\s{0,3}(`{3,}|~{3,})') {
            $marker = $Matches[1]
            if (-not $fence) { $fence = $marker }
            elseif ($marker[0] -eq $fence[0] -and $marker.Length -ge $fence.Length -and
                $line -match '^\s{0,3}(`{3,}|~{3,})\s*$') { $fence = $null }
            $prose = $false
        }
        [pscustomobject]@{ Text = $line; Prose = $prose }
    }
}

function Get-HeadingSlug {
    param([string]$Title, [hashtable]$Counts)
    $plain = $Title.Trim() -replace '\s+#+\s*$', ''
    $plain = $plain -replace '\[([^]]+)\]\([^)]+\)', '$1' -replace '<[^>]+>', ''
    $plain = [System.Net.WebUtility]::HtmlDecode($plain).ToLowerInvariant()
    $slug = $plain -replace '[^\p{L}\p{N}\p{M}_\s-]', '' -replace '\s', '-'
    $anchor = $slug
    $suffix = 0
    while ($Counts.ContainsKey($anchor)) {
        $suffix++
        $anchor = "$slug-$suffix"
    }
    $Counts[$anchor] = $true
    return $anchor
}

function Get-RepositoryPath {
    param([string]$Path)
    # Uri works on Windows PowerShell 5.1 as well as PowerShell 7.
    $rootUri = [uri]($RootDir.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar)
    return [uri]::UnescapeDataString($rootUri.MakeRelativeUri([uri]$Path).ToString())
}

function Register-Source {
    param([string]$Source, [string]$Target, [bool]$Merged = $false)
    $path = [System.IO.Path]::GetFullPath((Join-Path $RootDir $Source))
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
    $content = Strip-Frontmatter (Get-Content -LiteralPath $path -Raw -Encoding UTF8)
    $prefix = 'doc-' + ((Get-RepositoryPath $path) -replace '\.md$', '' -replace '[^a-zA-Z0-9-]', '-').ToLowerInvariant()
    $anchors = @{}
    $counts = @{}
    $lines = foreach ($line in (Get-MarkdownLines $content)) {
        $text = $line.Text
        if ($line.Prose) {
            if ($text -match '^\s{0,3}#{1,6}\s+(.+)$') {
                $anchor = Get-HeadingSlug $Matches[1] $counts
                $anchors[$anchor] = if ($Merged) { "$prefix--$anchor" } else { $anchor }
                if ($Merged) { '<a id="' + $anchors[$anchor] + '"></a>' }
            }
            $text = [regex]::Replace($text, '<a\s+(?:id|name)=["'']([^"'']+)["'']\s*>', {
                param($match)
                $anchor = $match.Groups[1].Value
                $anchors[$anchor] = if ($Merged) { "$prefix--$anchor" } else { $anchor }
                return '<a id="' + $anchors[$anchor] + '">'
            })
        }
        $text
    }
    # Explicit source-prefixed anchors make repeated headings in merged files
    # unambiguous, independently of a renderer's automatic heading suffixes.
    $sourceMap[$path] = @{
        Source = $path; Target = $Target; Content = ($lines -join "`n")
        Title = Extract-Title $content ([System.IO.Path]::GetFileNameWithoutExtension($path))
        Section = $(if ($Merged) { $prefix } else { '' }); Anchors = $anchors
    }
}

function Edit-MarkdownLinks {
    param([string]$Content, [scriptblock]$Rewrite)
    # Inline/image links (including angle destinations and titles), reference
    # definitions, and inline code. Code is matched first and left untouched.
    $pattern = '(?<code>`+[^`]*`+)|(?<prefix>!?\[[^\]\r\n]*\]\(\s*)(?<destination><[^>\r\n]+>|(?:\\.|[^()\s\\]|\((?:\\.|[^()\\])*\))+)(?<suffix>\s+(?:"[^"\r\n]*"|''[^''\r\n]*''|\([^)\r\n]*\))\s*\)|\s*\))|(?<reference>^\s{0,3}\[[^\]^\r\n]+\]:\s*)(?<refdestination><[^>\r\n]+>|\S+)'
    $lines = foreach ($line in (Get-MarkdownLines $Content)) {
        if (-not $line.Prose) { $line.Text; continue }
        [regex]::Replace($line.Text, $pattern, {
            param($match)
            if ($match.Groups['code'].Success) { return $match.Value }
            $reference = $match.Groups['reference'].Success
            $group = if ($reference) { 'refdestination' } else { 'destination' }
            $raw = $match.Groups[$group].Value
            $angle = $raw.StartsWith('<')
            $url = if ($angle) { $raw.Substring(1, $raw.Length - 2) } else { $raw }
            $rewritten = & $Rewrite $url
            if ($angle) { $rewritten = "<$rewritten>" }
            if ($reference) { return $match.Groups['reference'].Value + $rewritten }
            return $match.Groups['prefix'].Value + $rewritten + $match.Groups['suffix'].Value
        })
    }
    return $lines -join "`n"
}

function Get-RepositoryUrl {
    param([string]$Path, [string]$Suffix)
    $relative = Get-RepositoryPath $Path
    $encoded = ($relative.Split('/') | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
    $kind = if (Test-Path -LiteralPath $Path -PathType Container) { 'tree' } else { 'blob' }
    return "https://github.com/sylin-org/koi/$kind/dev/$encoded$Suffix"
}

function Transform-Links {
    param([hashtable]$Document)
    return Edit-MarkdownLinks $Document.Content {
        param($url)
        if ($url -match '^[a-zA-Z][a-zA-Z0-9+.-]*:|^//') { return $url }
        if ($url -notmatch '^(?<path>[^?#]*)(?<query>\?[^#]*)?(?:#(?<fragment>.*))?$') { return $url }
        $relative = [uri]::UnescapeDataString($Matches['path']) -replace '\\([ ()])', '$1'
        $query = $Matches['query']
        $fragment = [uri]::UnescapeDataString($Matches['fragment'])
        $suffix = $query + $(if ($fragment) { "#$fragment" } else { '' })
        $path = if (-not $relative) { $Document.Source }
        elseif ($relative.StartsWith('/')) { [System.IO.Path]::GetFullPath((Join-Path $RootDir $relative.TrimStart('/'))) }
        else { [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $Document.Source) $relative)) }
        $directoryKey = $path.TrimEnd('\', '/')
        if (-not $fragment -and $folderMap.ContainsKey($directoryKey)) {
            return $folderMap[$directoryKey] + $query
        }
        if ($sourceMap.ContainsKey($path)) {
            $target = $sourceMap[$path]
            $anchor = $target.Section
            if ($fragment) {
                if (-not $target.Anchors.ContainsKey($fragment)) {
                    $sourceLinkWarnings.Add("$(Get-RepositoryPath $Document.Source): $url (source anchor does not exist)") | Out-Null
                    return Get-RepositoryUrl $path $suffix
                }
                $anchor = $target.Anchors[$fragment]
            }
            return $target.Target + $query + $(if ($anchor) { "#$anchor" } else { '' })
        }
        if (-not (Test-Path -LiteralPath $path)) {
            $sourceLinkWarnings.Add("$(Get-RepositoryPath $Document.Source): $url (source path does not exist)") | Out-Null
        }
        # Excluded corpora and code remain repository links, not missing files
        # inside the flat bundle. These external destinations are not certified.
        return Get-RepositoryUrl $path $suffix
    }
}

function Test-DistributionLinks {
    param([string]$Directory)
    $files = @(Get-ChildItem -LiteralPath $Directory -Filter "$Namespace-*.md" -File)
    $documents = @{}
    foreach ($file in $files) {
        $content = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
        $anchors = @{}
        $counts = @{}
        foreach ($line in (Get-MarkdownLines $content)) {
            if (-not $line.Prose) { continue }
            if ($line.Text -match '^\s{0,3}#{1,6}\s+(.+)$') {
                $anchors[(Get-HeadingSlug $Matches[1] $counts)] = $true
            }
            foreach ($match in [regex]::Matches($line.Text, '<a\s+(?:id|name)=["'']([^"'']+)["'']\s*>')) {
                $anchors[$match.Groups[1].Value] = $true
            }
        }
        $documents[$file.FullName] = @{ Content = $content; Anchors = $anchors }
    }
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $files) {
        $null = Edit-MarkdownLinks $documents[$file.FullName].Content {
            param($url)
            if ($url -match '^[a-zA-Z][a-zA-Z0-9+.-]*:|^//') { return $url }
            $parts = $url -split '#', 2
            $relative = [uri]::UnescapeDataString(($parts[0] -split '\?', 2)[0])
            $path = if ($relative) { [System.IO.Path]::GetFullPath((Join-Path $Directory $relative)) } else { $file.FullName }
            if (-not $documents.ContainsKey($path)) { $errors.Add("$($file.Name): missing bundled file $url") }
            elseif ($parts.Count -gt 1 -and $parts[1] -and
                -not $documents[$path].Anchors.ContainsKey([uri]::UnescapeDataString($parts[1]))) {
                $errors.Add("$($file.Name): missing bundled anchor $url")
            }
            return $url
        }
    }
    if ($errors.Count) { throw "Generated navigation failed validation:`n$($errors -join "`n")" }
    Write-Host "Local navigation:        all generated files and anchors resolve" -ForegroundColor Green
}

function Merge-Folder {
    <#
    .SYNOPSIS
    Consolidates all .md files in a docs/ subfolder into a single namespaced file.
    Recurses into subdirectories. Generates a TOC.
    #>
    param(
        [string]$FolderName,
        [string]$FolderPath
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
        $document = $sourceMap[$file.FullName]
        if ($FolderName -eq 'adr' -and $file.Name -eq '046-container-lan-adoption.md') {
            $document = $mergedCurrentDecision
        }
        $stripped = Transform-Links $document
        $fileTitle = $document.Title

        # Note subfolder origin for files in nested directories
        $relativePath = $file.FullName.Substring($FolderPath.Length).TrimStart('\', '/')
        $subfolderNote = ""
        $tocSubfolder = ""
        if ($relativePath -match '[\\/]') {
            $subfolder = Split-Path $relativePath -Parent
            $subfolderNote = " *(from $subfolder)*"
            $tocSubfolder = " ($subfolder)"
        }

        $anchor = $document.Section

        $tocEntries += "- [$fileTitle$tocSubfolder](#$anchor)"
        $sections += "`n<a id=""$anchor""></a>`n`n## $fileTitle$subfolderNote`n`n$stripped`n`n---`n"
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

$currentContracts = @(
    @{ Source = "docs/adr/046-container-lan-adoption.md"; Target = "$Namespace-current-decision.md" }
    @{ Source = "fleet/epics/004-container-lan-adoption.md"; Target = "$Namespace-launch-epic.md" }
    @{ Source = "fleet/launch/LEDGER.md"; Target = "$Namespace-launch-ledger.md" }
)
$specialFiles = @(
    @{ Source = "README.md"; Target = "$Namespace-readme.md" }
    @{ Source = "GUIDE.md"; Target = "$Namespace-guide.md" }
    @{ Source = "CONTAINERS.md"; Target = "$Namespace-containers.md" }
    @{ Source = "CONTRIBUTING.md"; Target = "$Namespace-contributing.md" }
) + $currentContracts

# Register the complete corpus before rendering any links. The always-included
# current decision takes precedence over its duplicate in the optional ADR book.
$sourceMap = @{}
$folderMap = @{}
$sourceLinkWarnings = [System.Collections.Generic.HashSet[string]]::new()
foreach ($folder in $allFolders) {
    $folderMap[$folder.FullName] = "$Namespace-$($folder.Name)-all.md"
    foreach ($file in (Get-ChildItem -LiteralPath $folder.FullName -Filter '*.md' -File -Recurse | Sort-Object FullName)) {
        Register-Source (Get-RepositoryPath $file.FullName) "$Namespace-$($folder.Name)-all.md" $true
    }
}
$rootDocFiles = @(Get-ChildItem -LiteralPath $SourceRoot -Filter '*.md' -File |
    Where-Object { $SkipRootFiles -notcontains $_.Name })
foreach ($file in $rootDocFiles) {
    Register-Source (Get-RepositoryPath $file.FullName) "$Namespace-docs-$($file.BaseName.ToLower()).md"
}
$mergedCurrentDecision = $sourceMap[(Join-Path $RootDir $currentContracts[0].Source)]
foreach ($spec in $specialFiles) { Register-Source $spec.Source $spec.Target }

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

    $result = Merge-Folder -FolderName $folder.Name -FolderPath $folder.FullName
    $processedFiles += $result.Files
}

# ============================================================================
# ROOT-LEVEL DOCS FILES (loose .md in docs/)
# ============================================================================

$rootDocFiles = Get-ChildItem -Path $SourceRoot -Filter "*.md" -File |
Where-Object { $processedFiles -notcontains $_.FullName -and $SkipRootFiles -notcontains $_.Name }

if ($rootDocFiles.Count -gt 0) {
    $stepNum++
    Write-Host "`n$stepNum. Root-level docs/ files ($($rootDocFiles.Count))..." -ForegroundColor Cyan

    foreach ($file in $rootDocFiles) {
        $targetName = "$Namespace-docs-$($file.BaseName.ToLower()).md"
        $content = Transform-Links $sourceMap[$file.FullName]

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

foreach ($spec in $specialFiles) {
    $sourcePath = Join-Path $RootDir $spec.Source
    if (Test-Path $sourcePath) {
        $content = Transform-Links $sourceMap[$sourcePath]
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

Koi helps container/LAN operators label a container, open its application from
another computer, and keep names and state correct when the container changes.
The operator preview precedes the optional trusted-service extension.

## Reading Order

1. **$Namespace-readme.md** - what Koi is and why it exists
2. **$Namespace-current-decision.md** - product scope and evidence requirements
3. **$Namespace-launch-epic.md** and **$Namespace-launch-ledger.md** - current work
4. **$Namespace-launch-all.md** - artifact readiness, proof and user trials
5. **$Namespace-guide.md** and **$Namespace-guides-all.md** - supported tasks
6. **$Namespace-reference-all.md** - precise architecture and protocol contracts

## Consolidated Docs

$categoryList

## Root Files

$specialList

## File Naming

All files follow: ``$Namespace-[category].md``

Consolidated folder docs end with ``-all``. Root project files use their
lowercase name (e.g., ``$Namespace-readme.md``).

## Evidence corpora

The current decision is always included. $(if ($IncludeADRs) { "The full ADR corpus is included as dated evidence." } else { "Use -IncludeADRs to include the full ADR corpus." })
$(if ($IncludeResearch) { "Research and assessments are included as dated evidence, not current task instructions." } else { "Use -IncludeResearch to include research and assessments." })

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
        $SkipFolders -notcontains $topFolder -and $SkipRootFiles -notcontains $relativePath
    }

    Write-Host ""
    Write-Host "Source files in docs/:   $($allSourceFiles.Count)" -ForegroundColor White
    Write-Host "  Included:              $($includedSourceFiles.Count)" -ForegroundColor Green
    Write-Host "  Skipped corpora:       $($allSourceFiles.Count - $includedSourceFiles.Count)" -ForegroundColor Yellow
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

    Test-DistributionLinks $OutputDir
    Write-Host "`nValidation complete." -ForegroundColor Green
}

if ($sourceLinkWarnings.Count) {
    Write-Warning "Pre-existing source references need review ($($sourceLinkWarnings.Count)); retained as repository URLs, not validated bundle links:"
    $sourceLinkWarnings | Sort-Object | ForEach-Object { Write-Warning "  $_" }
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
