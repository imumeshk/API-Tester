<#
.SYNOPSIS
    API Tester release manager - one script for the whole GitHub release workflow:
    changelog, version, release notes, build, tag, push, GitHub releases, assets and updater verification.

.DESCRIPTION
    Run it from anywhere inside the repository with an action as the first argument:

      Status        Local version, git state, unreleased CHANGELOG entries and the latest GitHub release.
      Init          One-time clean-up: .gitignore entries, stop tracking user data (dist\Configuration, History, Logs)
                    and the internal documents in docs\internal.
      AddChange     Add an entry to "## [Unreleased]" in CHANGELOG.md            (-Type Added|Changed|Fixed|... -Message "...")
      NextVersion   Show the next version                                         (-Bump Major|Minor|Patch [-PreRelease beta.1])
      Notes         Create / refresh docs\releases\vX.Y.Z.md from the CHANGELOG   (-Version, -Force to overwrite)
      Prepare       Set the version, turn "Unreleased" into a version section, write the release notes, build, verify.
      Publish       Prepare + commit + tag + push + create the GitHub release (by the Release workflow or the API).
      UpdateNotes   Replace the text of an existing GitHub release with its notes file (or -NotesFile).
      UploadAssets  Build and (re)upload API-Tester.ps1 and API-Tester.ps1.sha256 to an existing release.
      Verify        Check exactly what the in-app updater sees: latest release, tag vs version, assets, checksum.
      List          List the GitHub releases.
      Delete        Delete a GitHub release (and with -DeleteTag its git tag) after confirmation.

    GitHub access
      Read-only actions (Status, Verify, List) work without a token for a public repository.
      Creating, editing and deleting releases need a token with "Contents: Read and write" permission, taken from
      -Token, $env:GITHUB_TOKEN, $env:GH_TOKEN or the GitHub CLI ("gh auth token").
      Publish in Workflow mode (the default when .github\workflows\release.yml exists) only needs "git push" rights:
      GitHub Actions builds and publishes the release when the tag arrives.

    -DryRun shows what would be written, committed, pushed or sent to GitHub without doing it.

.EXAMPLE
    .\tools\Release.ps1 Status

.EXAMPLE
    .\tools\Release.ps1 AddChange -Type Fixed -Message "Monitor e-mails use the configured sender."

.EXAMPLE
    .\tools\Release.ps1 Publish -Bump Patch
    Next patch version (for example 3.0.1): CHANGELOG + notes + build, commit, tag v3.0.1, push, wait for the
    Release workflow, then verify what the updater sees.

.EXAMPLE
    .\tools\Release.ps1 Publish -Version 3.1.0-beta.1 -Mode Api -Draft
    Pre-release as a draft, created through the GitHub API (needs a token).

.EXAMPLE
    .\tools\Release.ps1 UpdateNotes -Version 3.0.0
    Edit docs\releases\v3.0.0.md, then push the new text to the existing GitHub release.

.EXAMPLE
    .\tools\Release.ps1 Verify
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Status', 'Init', 'AddChange', 'NextVersion', 'Notes', 'Prepare', 'Publish', 'UpdateNotes', 'UploadAssets', 'Verify', 'List', 'Delete')]
    [string]$Action,

    [string]$Version,
    [ValidateSet('Major', 'Minor', 'Patch')][string]$Bump,
    [string]$PreRelease,

    [ValidateSet('Added', 'Changed', 'Deprecated', 'Removed', 'Fixed', 'Security')][string]$Type = 'Changed',
    [string]$Message,

    [string]$NotesFile,
    [ValidateSet('Auto', 'Workflow', 'Api')][string]$Mode = 'Auto',
    [string]$Repository,
    [string]$Token,
    [string]$Remote = 'origin',
    [string]$Branch = 'main',
    [int]$WaitMinutes = 20,

    [switch]$Draft,
    [switch]$SkipBuild,
    [switch]$NoWait,
    [switch]$DeleteTag,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 } catch { }

# ---------------------------------------------------------------------------------------------------------------------
# Paths and console output
# ---------------------------------------------------------------------------------------------------------------------
$root = Split-Path -Parent $PSScriptRoot
$paths = @{
    Constants   = Join-Path $root 'src\Config\Constants.ps1'
    Changelog   = Join-Path $root 'CHANGELOG.md'
    ReleasesDir = Join-Path $root 'docs\releases'
    Build       = Join-Path $root 'Build.ps1'
    Dist        = Join-Path $root 'dist\API-Tester.ps1'
    Hash        = Join-Path $root 'dist\API-Tester.ps1.sha256'
    Workflow    = Join-Path $root '.github\workflows\release.yml'
    GitIgnore   = Join-Path $root '.gitignore'
}
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
$changeTypes = @('Added', 'Changed', 'Deprecated', 'Removed', 'Fixed', 'Security')
$userDataPattern = '^(dist/)?(Configuration|History|Logs)/'
# Internal documents stay local (docs/internal is ignored); the old locations are blocked too.
$privateDocsPattern = '^docs/internal/|^docs/(CODE_AUDIT|ENHANCEMENTS|UPDATER|NAMING_CONVENTIONS)\.md$'

function Write-Step { param([string]$Text) Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "  [ OK ] $Text" -ForegroundColor Green }
function Write-Info { param([string]$Text) Write-Host "  [INFO] $Text" }
function Write-Note { param([string]$Text) Write-Host "  [WARN] $Text" -ForegroundColor Yellow }
function Write-Bad  { param([string]$Text) Write-Host "  [FAIL] $Text" -ForegroundColor Red }

function Read-TextFile { param([string]$Path) return [System.IO.File]::ReadAllText($Path) }

function Write-TextFile {
    param([string]$Path, [string]$Text)
    if ($DryRun) { Write-Info "(dry run) would write $Path"; return }
    $folder = Split-Path -Parent $Path
    if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Text, $utf8Bom)
}

function Get-NewLine { param([string]$Text) if ($Text -match "`r`n") { return "`r`n" } return "`n" }

# ---------------------------------------------------------------------------------------------------------------------
# Version (src\Config\Constants.ps1)
# ---------------------------------------------------------------------------------------------------------------------
function Get-AppConstant {
    param([string]$Name)
    $text = Read-TextFile $paths.Constants
    if ($text -match ('\$script:' + $Name + '\s*=\s*"([^"]*)"')) { return $Matches[1] }
    throw "`$script:$Name was not found in $($paths.Constants)."
}

function Set-AppVersion {
    param([string]$NewVersion)
    $text = Read-TextFile $paths.Constants
    $updated = [regex]::Replace($text, '(\$script:AppVersion\s*=\s*")[^"]*(")', '${1}' + $NewVersion + '${2}')
    if ($updated -ne $text) { Write-TextFile -Path $paths.Constants -Text $updated }
    Write-Ok "Version in src\Config\Constants.ps1: $NewVersion"
}

function Test-SemVer { param([string]$Value) return ($Value -match '^\d+\.\d+\.\d+(-[0-9A-Za-z][0-9A-Za-z.\-]*)?$') }

function ConvertTo-CoreVersion {
    param([string]$Value)
    if ($Value -match '(\d+)\.(\d+)\.(\d+)') { return [System.Version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3]) }
    return $null
}

function Get-NextVersion {
    param([string]$Current, [string]$Part, [string]$Suffix)
    $core = ConvertTo-CoreVersion $Current
    if (-not $core) { throw "The current version '$Current' is not x.y.z." }
    $major = $core.Major; $minor = $core.Minor; $patch = $core.Build
    $isPreRelease = $Current -match '-'
    switch ($Part) {
        'Major' { $major++; $minor = 0; $patch = 0 }
        'Minor' { $minor++; $patch = 0 }
        'Patch' { if (-not $isPreRelease) { $patch++ } }   # 3.1.0-beta.2 -> Patch -> 3.1.0 (the final release)
    }
    $next = "$major.$minor.$patch"
    if ($Suffix) { $next += "-$($Suffix.TrimStart('-'))" }
    return $next
}

function Resolve-TargetVersion {
    $current = Get-AppConstant 'AppVersion'
    $target = if ($Version) { $Version.TrimStart('v', 'V') } elseif ($Bump) { Get-NextVersion -Current $current -Part $Bump -Suffix $PreRelease } else { $current }
    if (-not (Test-SemVer $target)) { throw "'$target' is not a valid version (expected x.y.z or x.y.z-label, for example 3.1.0 or 3.1.0-beta.1)." }
    return $target
}

# ---------------------------------------------------------------------------------------------------------------------
# CHANGELOG.md (Keep a Changelog)
# ---------------------------------------------------------------------------------------------------------------------
function Get-ChangelogSectionMatch {
    param([string]$Text, [string]$Heading)
    $pattern = '(?ms)^## \[' + [regex]::Escape($Heading) + '\][^\r\n]*\r?\n(.*?)(?=^## \[|^\[[^\]]+\]:\s|\z)'
    return [regex]::Match($Text, $pattern)
}

function Get-ChangelogSection {
    param([string]$Heading)
    $match = Get-ChangelogSectionMatch -Text (Read-TextFile $paths.Changelog) -Heading $Heading
    if ($match.Success) { return $match.Groups[1].Value.Trim() }
    return $null
}

function ConvertFrom-ChangelogBody {
    param([string]$Body)
    $groups = [ordered]@{}
    $loose = New-Object System.Collections.Generic.List[string]
    $current = $null
    foreach ($line in ($Body -split "\r?\n")) {
        if ($line -match '^###\s+(.+?)\s*$') {
            $current = $Matches[1]
            if (-not $groups.Contains($current)) { $groups[$current] = New-Object System.Collections.Generic.List[string] }
            continue
        }
        if ($line -match '^\s*$') { continue }
        if ($current) { $groups[$current].Add($line) } else { $loose.Add($line) }
    }
    return @{ Groups = $groups; Loose = $loose }
}

function ConvertTo-ChangelogBody {
    param($Parsed, [string]$NewLine)
    $parts = New-Object System.Collections.Generic.List[string]
    if ($Parsed.Loose.Count -gt 0) { $parts.Add(($Parsed.Loose -join $NewLine)) }
    $names = @($changeTypes | Where-Object { $Parsed.Groups.Contains($_) }) + @($Parsed.Groups.Keys | Where-Object { $changeTypes -notcontains $_ })
    foreach ($name in $names) {
        if ($Parsed.Groups[$name].Count -gt 0) { $parts.Add("### $name$NewLine" + ($Parsed.Groups[$name] -join $NewLine)) }
    }
    return ($parts -join "$NewLine$NewLine")
}

function Initialize-UnreleasedSection {
    param([string]$Text)
    if ($Text -match '(?m)^## \[Unreleased\]') { return $Text }
    $newLine = Get-NewLine $Text
    $first = [regex]::Match($Text, '(?m)^## \[')
    if ($first.Success) { return $Text.Insert($first.Index, "## [Unreleased]$newLine$newLine") }
    return $Text.TrimEnd() + "$newLine$newLine## [Unreleased]$newLine"
}

function Add-ChangelogEntry {
    param([string]$EntryType, [string]$EntryText)
    $text = Initialize-UnreleasedSection (Read-TextFile $paths.Changelog)
    $newLine = Get-NewLine $text
    $match = Get-ChangelogSectionMatch -Text $text -Heading 'Unreleased'
    $parsed = ConvertFrom-ChangelogBody -Body $match.Groups[1].Value
    if (-not $parsed.Groups.Contains($EntryType)) { $parsed.Groups[$EntryType] = New-Object System.Collections.Generic.List[string] }
    $entry = $EntryText.Trim()
    if (-not $entry.StartsWith('- ')) { $entry = "- $entry" }
    $parsed.Groups[$EntryType].Add($entry)
    $section = "## [Unreleased]$newLine$newLine" + (ConvertTo-ChangelogBody -Parsed $parsed -NewLine $newLine) + "$newLine$newLine"
    $text = $text.Remove($match.Index, $match.Length).Insert($match.Index, $section)
    Write-TextFile -Path $paths.Changelog -Text $text
    Write-Ok "CHANGELOG [Unreleased] / $EntryType : $($entry.Substring(2))"
}

function Update-ChangelogLinks {
    param([string]$Text, [string]$NewVersion)
    $newLine = Get-NewLine $Text
    $base = "https://github.com/$Repository"
    $Text = [regex]::Replace($Text, '(?m)^\[Unreleased\]:[^\r\n]*\r?\n?', '')
    $links = "[Unreleased]: $base/compare/v$NewVersion...HEAD"
    if ($Text -notmatch ('(?m)^\[' + [regex]::Escape($NewVersion) + '\]:')) { $links += "$newLine[$NewVersion]: $base/releases/tag/v$NewVersion" }
    $firstLink = [regex]::Match($Text, '(?m)^\[[^\]]+\]:\s')
    if ($firstLink.Success) { return $Text.Insert($firstLink.Index, "$links$newLine") }
    return $Text.TrimEnd() + "$newLine$newLine$links$newLine"
}

# Turns the [Unreleased] notes into "## [x.y.z] - date" and leaves an empty [Unreleased] section on top.
function Move-UnreleasedToVersion {
    param([string]$NewVersion)
    $text = Initialize-UnreleasedSection (Read-TextFile $paths.Changelog)
    if ($text -match ('(?m)^## \[' + [regex]::Escape($NewVersion) + '\]')) { Write-Ok "CHANGELOG already has a [$NewVersion] section"; return }
    $newLine = Get-NewLine $text
    $match = Get-ChangelogSectionMatch -Text $text -Heading 'Unreleased'
    $body = ConvertTo-ChangelogBody -Parsed (ConvertFrom-ChangelogBody -Body $match.Groups[1].Value) -NewLine $newLine
    if (-not $body) {
        if (-not $Force) { throw "CHANGELOG.md has no entries under [Unreleased]. Add them first, for example:`n  .\tools\Release.ps1 AddChange -Type Fixed -Message 'Describe the fix'`nor run again with -Force to release without notes." }
        $body = '- Maintenance release.'
    }
    $section = "## [Unreleased]$newLine$newLine## [$NewVersion] - $(Get-Date -Format 'yyyy-MM-dd')$newLine$newLine$body$newLine$newLine"
    $text = $text.Remove($match.Index, $match.Length).Insert($match.Index, $section)
    $text = Update-ChangelogLinks -Text $text -NewVersion $NewVersion
    Write-TextFile -Path $paths.Changelog -Text $text
    Write-Ok "CHANGELOG: [Unreleased] moved to [$NewVersion]"
}

# ---------------------------------------------------------------------------------------------------------------------
# Release notes (docs\releases\vX.Y.Z.md) - used as the GitHub release text by this script and by release.yml
# ---------------------------------------------------------------------------------------------------------------------
function Get-NotesPath { param([string]$NewVersion) if ($NotesFile) { return (Resolve-Path $NotesFile).Path } return (Join-Path $paths.ReleasesDir "v$NewVersion.md") }

function New-ReleaseNotes {
    param([string]$NewVersion, [switch]$Overwrite)
    $file = Join-Path $paths.ReleasesDir "v$NewVersion.md"
    if ((Test-Path $file) -and -not $Overwrite) { Write-Ok "Release notes kept (hand-written): docs\releases\v$NewVersion.md"; return $file }
    $section = Get-ChangelogSection -Heading $NewVersion
    if (-not $section -and $DryRun) { $section = Get-ChangelogSection -Heading 'Unreleased' }
    if (-not $section) { throw "CHANGELOG.md has no [$NewVersion] section - run Prepare (or AddChange + Prepare) first." }
    $assetName = Get-AppConstant 'AppGitHubAsset'
    $notes = @"
# API Tester v$NewVersion

$section

## Upgrading
- **From the app:** Help -> About API Tester -> Check for updates -> Download & update, then restart.
- **Manually:** download ``$assetName`` below and replace your copy. Keep the ``Configuration``, ``History`` and ``Logs`` folders next to it.

Full history: [CHANGELOG.md](https://github.com/$Repository/blob/$Branch/CHANGELOG.md)

## Checksum
<!-- checksum:start -->
<!-- checksum:end -->
"@
    Write-TextFile -Path $file -Text ($notes -replace "\r?\n", "`r`n")
    Write-Ok "Release notes written: docs\releases\v$NewVersion.md"
    return $file
}

function Set-ReleaseNotesChecksum {
    param([string]$File, [string]$Hash)
    if (-not (Test-Path $File)) { return }
    $assetName = Get-AppConstant 'AppGitHubAsset'
    $text = Read-TextFile $File
    $newLine = Get-NewLine $text
    $line = "SHA-256 of ``$assetName``: ``$Hash``"
    if ($text -match '(?s)<!-- checksum:start -->.*?<!-- checksum:end -->') {
        $text = [regex]::Replace($text, '(?s)<!-- checksum:start -->.*?<!-- checksum:end -->', "<!-- checksum:start -->$newLine$line$newLine<!-- checksum:end -->")
    } else {
        $text = $text.TrimEnd() + "$newLine$newLine## Checksum$newLine<!-- checksum:start -->$newLine$line$newLine<!-- checksum:end -->$newLine"
    }
    Write-TextFile -Path $File -Text $text
    Write-Ok "Checksum added to the release notes"
}

# ---------------------------------------------------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------------------------------------------------
function Invoke-Build {
    Write-Step 'Building dist\API-Tester.ps1'
    if ($DryRun) { Write-Info '(dry run) would run Build.ps1'; return '<checksum>' }
    $hostPath = (Get-Process -Id $PID).Path
    & $hostPath -NoProfile -ExecutionPolicy Bypass -File $paths.Build | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Build.ps1 failed - fix the errors above before releasing.' }
    $expected = ((Read-TextFile $paths.Hash).Trim() -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Path $paths.Dist -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { throw 'dist\API-Tester.ps1.sha256 does not match dist\API-Tester.ps1.' }
    $builtVersion = if ((Read-TextFile $paths.Dist) -match '\$script:AppVersion\s*=\s*"([^"]+)"') { $Matches[1] } else { '?' }
    Write-Ok "Built v$builtVersion - SHA-256 $actual"
    return $actual
}

# ---------------------------------------------------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------------------------------------------------
# Runs git in the repository. Deliberately has no param() block: arguments such as -a / -m / -d must reach git
# untouched instead of being bound to a PowerShell parameter.
function Invoke-Git {
    $gitArguments = @($args | ForEach-Object { [string]$_ })
    $mutating = @('add', 'commit', 'tag', 'push', 'rm')
    $isReadOnlyTag = ($gitArguments[0] -eq 'tag' -and $gitArguments -contains '--list')
    if ($DryRun -and $mutating -contains $gitArguments[0] -and -not $isReadOnlyTag) { Write-Info "(dry run) git $($gitArguments -join ' ')"; return @() }
    # git writes progress to stderr; Windows PowerShell 5.1 would turn that into errors with ErrorAction Stop.
    $ErrorActionPreference = 'Continue'
    $output = @(& git -C $root @gitArguments 2>&1 | ForEach-Object { "$_" })
    if ($LASTEXITCODE -ne 0) { throw "git $($gitArguments -join ' ') failed:`n$($output -join "`n")" }
    return $output
}

function Test-GitAvailable { if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git is not installed or not on PATH: https://git-scm.com/download/win' } }

function Test-TagExists {
    param([string]$Tag)
    $local = @(Invoke-Git tag --list $Tag) | Where-Object { $_ -eq $Tag }
    $remoteTags = @()
    try { $remoteTags = @(Invoke-Git ls-remote --tags $Remote "refs/tags/$Tag") | Where-Object { $_ } } catch { Write-Note "Could not reach '$Remote' to check tags: $($_.Exception.Message)" }
    return [bool]($local -or $remoteTags)
}

# ---------------------------------------------------------------------------------------------------------------------
# GitHub REST API
# ---------------------------------------------------------------------------------------------------------------------
function Get-GitHubToken {
    param([switch]$Required)
    if ($script:resolvedToken) { return $script:resolvedToken }
    $value = $null
    if ($Token) { $value = $Token } elseif ($env:GITHUB_TOKEN) { $value = $env:GITHUB_TOKEN } elseif ($env:GH_TOKEN) { $value = $env:GH_TOKEN }
    if (-not $value -and (Get-Command gh -ErrorAction SilentlyContinue)) {
        try { $ErrorActionPreference = 'Continue'; $value = (& gh auth token 2>$null | Select-Object -First 1) } catch { $value = $null }
    }
    if (-not $value -and $Required) {
        throw "A GitHub token is needed for this action. Create one at https://github.com/settings/personal-access-tokens (Repository access: $Repository, Permissions: Contents = Read and write), then:`n  `$env:GITHUB_TOKEN = '<token>'`nor pass -Token, or sign in with the GitHub CLI (gh auth login)."
    }
    $script:resolvedToken = $value
    return $value
}

function Get-GitHubHeaders {
    param([switch]$Required)
    $headers = @{ 'Accept' = 'application/vnd.github+json'; 'User-Agent' = 'API-Tester-Release-Script'; 'X-GitHub-Api-Version' = '2022-11-28' }
    $tokenValue = Get-GitHubToken -Required:$Required
    if ($tokenValue) { $headers['Authorization'] = "Bearer $tokenValue" }
    return $headers
}

function Invoke-GitHubApi {
    param([string]$Method = 'GET', [string]$Path, $Body = $null, [switch]$AllowNotFound, [switch]$Write)
    $uri = if ($Path -match '^https://') { $Path } else { "https://api.github.com$Path" }
    if ($Write -and $DryRun) { Write-Info "(dry run) GitHub API $Method $uri"; return $null }
    $request = @{ Method = $Method; Uri = $uri; Headers = (Get-GitHubHeaders -Required:$Write); UseBasicParsing = $true }
    if ($null -ne $Body) {
        $request['Body'] = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 6))
        $request['ContentType'] = 'application/json; charset=utf-8'
    }
    try { return (Invoke-RestMethod @request) }
    catch {
        $status = 0
        try { $status = [int]$_.Exception.Response.StatusCode } catch { }
        if ($AllowNotFound -and $status -eq 404) { return $null }
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        if ($status -eq 403 -and $detail -match 'rate limit') { $detail += ' - set $env:GITHUB_TOKEN to raise the limit.' }
        throw "GitHub API $Method $uri failed (HTTP $status): $detail"
    }
}

# Finds a release by tag, including drafts (which the tags endpoint does not return).
function Find-Release {
    param([string]$Tag)
    $release = Invoke-GitHubApi -Path "/repos/$Repository/releases/tags/$Tag" -AllowNotFound
    if ($release) { return $release }
    if (Get-GitHubToken) {
        foreach ($candidate in @(Invoke-GitHubApi -Path "/repos/$Repository/releases?per_page=50")) { if ($candidate.tag_name -eq $Tag) { return $candidate } }
    }
    return $null
}

function New-GitHubRelease {
    param([string]$Tag, [string]$Body, [bool]$IsDraft, [bool]$IsPreRelease, [string]$Target)
    $payload = [ordered]@{ tag_name = $Tag; target_commitish = $Target; name = "API Tester $Tag"; body = $Body; draft = $IsDraft; prerelease = $IsPreRelease }
    if (-not $IsDraft -and -not $IsPreRelease) { $payload['make_latest'] = 'true' }
    return (Invoke-GitHubApi -Method POST -Path "/repos/$Repository/releases" -Body $payload -Write)
}

function Send-ReleaseAsset {
    param($Release, [string]$FilePath, [string]$AssetName, [string]$ContentType = 'application/octet-stream')
    foreach ($existing in @($Release.assets | Where-Object { $_.name -eq $AssetName })) {
        Invoke-GitHubApi -Method DELETE -Path "/repos/$Repository/releases/assets/$($existing.id)" -Write | Out-Null
        Write-Info "Replaced the old $AssetName"
    }
    $uploadUri = ($Release.upload_url -replace '\{.*\}$', '') + '?name=' + [uri]::EscapeDataString($AssetName)
    if ($DryRun) { Write-Info "(dry run) upload $FilePath -> $AssetName"; return }
    Invoke-RestMethod -Method POST -Uri $uploadUri -Headers (Get-GitHubHeaders -Required) -ContentType $ContentType -InFile $FilePath -UseBasicParsing | Out-Null
    Write-Ok "Uploaded $AssetName"
}

function Send-ReleaseAssets {
    param($Release)
    $assetName = Get-AppConstant 'AppGitHubAsset'
    Send-ReleaseAsset -Release $Release -FilePath $paths.Dist -AssetName $assetName -ContentType 'application/octet-stream'
    Send-ReleaseAsset -Release $Release -FilePath $paths.Hash -AssetName "$assetName.sha256" -ContentType 'text/plain'
}

function Wait-WorkflowRelease {
    param([string]$Tag)
    $assetName = Get-AppConstant 'AppGitHubAsset'
    Write-Step "Waiting for the GitHub 'Release' workflow to publish $Tag (up to $WaitMinutes minutes)"
    Write-Info "Progress: https://github.com/$Repository/actions/workflows/release.yml"
    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    while ((Get-Date) -lt $deadline) {
        $release = $null
        try { $release = Find-Release -Tag $Tag } catch { Write-Note $_.Exception.Message }
        if ($release) {
            $names = @($release.assets | ForEach-Object { $_.name })
            if ($names -contains $assetName -and $names -contains "$assetName.sha256") { Write-Host ''; Write-Ok "Published: $($release.html_url)"; return $release }
        }
        Write-Host '.' -NoNewline
        Start-Sleep -Seconds 20
    }
    Write-Host ''
    throw "The release did not appear within $WaitMinutes minutes. Check https://github.com/$Repository/actions - if the workflow failed, fix it and run: .\tools\Release.ps1 UploadAssets -Version $($Tag.TrimStart('v'))"
}

# ---------------------------------------------------------------------------------------------------------------------
# Updater verification - mirrors what Help -> About -> Check for updates does
# ---------------------------------------------------------------------------------------------------------------------
function Test-UpdaterRelease {
    param([string]$ExpectedVersion)
    $assetName = Get-AppConstant 'AppGitHubAsset'
    Write-Step "Checking what the in-app updater sees (https://github.com/$Repository)"
    $failures = 0
    $latest = Invoke-GitHubApi -Path "/repos/$Repository/releases/latest" -AllowNotFound
    if (-not $latest) { Write-Bad 'No published release. The updater ignores drafts and pre-releases.'; return $false }
    Write-Info "Latest release: $($latest.tag_name) - $($latest.html_url)"
    $tagVersion = $latest.tag_name.TrimStart('v', 'V')
    if (-not (ConvertTo-CoreVersion $tagVersion)) { Write-Bad "The tag '$($latest.tag_name)' has no x.y.z version, so the updater cannot compare it."; $failures++ }
    if ($ExpectedVersion -and $tagVersion -ne $ExpectedVersion) { Write-Bad "Latest is $($latest.tag_name), expected v$ExpectedVersion (draft, pre-release or not published yet?)."; $failures++ }
    elseif ($ExpectedVersion) { Write-Ok "Latest release is v$ExpectedVersion" }

    $scriptAsset = @($latest.assets | Where-Object { $_.name -eq $assetName })[0]
    $hashAsset = @($latest.assets | Where-Object { $_.name -eq "$assetName.sha256" })[0]
    if (-not $scriptAsset) { Write-Bad "Asset '$assetName' is missing - the updater would only open the releases page."; $failures++ }
    else { Write-Ok "Asset $assetName ($([Math]::Round($scriptAsset.size / 1KB)) KB)" }
    if (-not $hashAsset) { Write-Note "Asset '$assetName.sha256' is missing - downloads cannot be verified." }

    if ($scriptAsset) {
        $temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("api-tester-verify-{0}" -f [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $temporary | Out-Null
        try {
            $downloaded = Join-Path $temporary $assetName
            Invoke-WebRequest -Uri $scriptAsset.browser_download_url -OutFile $downloaded -UseBasicParsing -Headers @{ 'User-Agent' = 'API-Tester-Release-Script' }
            $actualHash = (Get-FileHash -Path $downloaded -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($hashAsset) {
                $hashFile = Join-Path $temporary "$assetName.sha256"
                Invoke-WebRequest -Uri $hashAsset.browser_download_url -OutFile $hashFile -UseBasicParsing -Headers @{ 'User-Agent' = 'API-Tester-Release-Script' }
                $expectedHash = ((Read-TextFile $hashFile).Trim() -split '\s+')[0].ToLowerInvariant()
                if ($expectedHash -eq $actualHash) { Write-Ok "Checksum matches ($actualHash)" } else { Write-Bad "Checksum mismatch: file $actualHash, .sha256 says $expectedHash"; $failures++ }
            }
            $content = Read-TextFile $downloaded
            if ($content -match '\$script:AppVersion\s*=\s*"([^"]+)"') {
                if ($Matches[1] -eq $tagVersion) { Write-Ok "The downloaded script reports version $($Matches[1])" }
                else { Write-Bad "The downloaded script reports version $($Matches[1]) but the tag is $($latest.tag_name) - users would be offered the update again and again."; $failures++ }
            } else { Write-Bad 'The downloaded file does not look like API Tester.'; $failures++ }
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($downloaded, [ref]$null, [ref]$parseErrors)
            if ($parseErrors -and $parseErrors.Count -gt 0) { Write-Bad "The downloaded script has $($parseErrors.Count) syntax error(s)."; $failures++ } else { Write-Ok 'The downloaded script parses without errors' }
        } finally { Remove-Item -Path $temporary -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if ($failures -eq 0) { Write-Ok 'The updater will offer this release to older versions.' }
    return ($failures -eq 0)
}

# ---------------------------------------------------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------------------------------------------------
function Invoke-Status {
    $local = Get-AppConstant 'AppVersion'
    Write-Step 'Local'
    Write-Info "Version        : $local"
    Write-Info "Repository     : $Repository"
    try {
        Test-GitAvailable
        $currentBranch = @(Invoke-Git rev-parse --abbrev-ref HEAD)[0]
        Write-Info "Branch         : $currentBranch$(if ($currentBranch -ne $Branch) { "  (releases are made from '$Branch')" })"
        $changes = @(Invoke-Git status --porcelain | Where-Object { $_ })
        if ($changes.Count -gt 0) { Write-Note "$($changes.Count) uncommitted change(s)" } else { Write-Ok 'Working tree clean' }
        try {
            Invoke-Git fetch --quiet $Remote | Out-Null
            $counts = (@(Invoke-Git rev-list --left-right --count "HEAD...$Remote/$Branch")[0] -split '\s+')
            Write-Info "Ahead / behind : $($counts[0]) / $($counts[1]) commit(s) compared with $Remote/$Branch"
        } catch { Write-Note "Could not compare with $Remote/$Branch." }
        $tracked = @(Invoke-Git ls-files | Where-Object { $_ -match $userDataPattern -or $_ -match $privateDocsPattern })
        if ($tracked.Count -gt 0) { Write-Note "$($tracked.Count) user-data / internal file(s) are tracked by git (for example $($tracked[0])) - run: .\tools\Release.ps1 Init" }
    } catch { Write-Note $_.Exception.Message }

    Write-Step 'CHANGELOG [Unreleased]'
    $unreleased = Get-ChangelogSection -Heading 'Unreleased'
    if ($unreleased) { $unreleased -split "\r?\n" | ForEach-Object { Write-Host "    $_" } } else { Write-Info 'No unreleased entries.' }

    Write-Step 'GitHub'
    try {
        $latest = Invoke-GitHubApi -Path "/repos/$Repository/releases/latest" -AllowNotFound
        if (-not $latest) { Write-Info 'No published release yet.' }
        else {
            Write-Info "Latest release : $($latest.tag_name) ($(([datetime]$latest.published_at).ToString('yyyy-MM-dd'))) - $(@($latest.assets).Count) asset(s)"
            $localCore = ConvertTo-CoreVersion $local; $latestCore = ConvertTo-CoreVersion $latest.tag_name
            if ($localCore -and $latestCore) {
                if ($localCore -gt $latestCore) { Write-Ok "Local v$local is newer - ready to publish: .\tools\Release.ps1 Publish" }
                elseif ($localCore -eq $latestCore) { Write-Info "v$local is already released - next: .\tools\Release.ps1 Publish -Bump Patch (or Minor / Major)" }
                else { Write-Note "Local v$local is older than the latest release $($latest.tag_name)." }
            }
        }
    } catch { Write-Note $_.Exception.Message }
}

function Invoke-Init {
    Test-GitAvailable
    Write-Step 'Repository clean-up'
    $required = @('dist/Configuration/', 'dist/History/', 'dist/Logs/', 'Configuration/', 'History/', 'Logs/', '*.new.ps1', '*.bak.ps1', 'dist/*.sha256', 'RELEASE_NOTES.md', 'grpcurl.exe', 'docs/internal/')
    $existing = if (Test-Path $paths.GitIgnore) { @(Get-Content $paths.GitIgnore) } else { @() }
    $missing = @($required | Where-Object { $existing -notcontains $_ })
    if ($missing.Count -gt 0) {
        $text = if (Test-Path $paths.GitIgnore) { (Read-TextFile $paths.GitIgnore).TrimEnd() + "`n`n# Added by tools/Release.ps1 Init`n" } else { "# User data and build output`n" }
        Write-TextFile -Path $paths.GitIgnore -Text ($text + ($missing -join "`n") + "`n")
        Write-Ok ".gitignore: added $($missing -join ', ')"
    } else { Write-Ok '.gitignore is complete' }
    $tracked = @(Invoke-Git ls-files | Where-Object { $_ -match $userDataPattern -or $_ -match $privateDocsPattern -or $_ -match '\.bak\.ps1$|\.ps1\.bak$' })
    if ($tracked.Count -gt 0) {
        foreach ($file in $tracked) { Invoke-Git rm --cached --quiet $file | Out-Null }
        Write-Ok "Stopped tracking $($tracked.Count) user-data / internal / backup file(s) (they stay on disk)"
        Write-Info 'Commit the change: git commit -m "Stop tracking user data"'
    } else { Write-Ok 'No user data is tracked' }
}

function Invoke-Prepare {
    param([string]$NewVersion)
    Write-Step "Preparing v$NewVersion"
    Set-AppVersion -NewVersion $NewVersion
    Move-UnreleasedToVersion -NewVersion $NewVersion
    $notes = New-ReleaseNotes -NewVersion $NewVersion -Overwrite:$Force
    if (-not $SkipBuild) {
        $hash = Invoke-Build
        Set-ReleaseNotesChecksum -File $notes -Hash $hash
    } else { Write-Note 'Build skipped (-SkipBuild).' }
    return $notes
}

function Invoke-Publish {
    param([string]$NewVersion)
    Test-GitAvailable
    $tag = "v$NewVersion"
    $isPreRelease = $NewVersion -match '-'
    $useWorkflow = ($Mode -eq 'Workflow') -or ($Mode -eq 'Auto' -and (Test-Path $paths.Workflow))
    if ($useWorkflow -and $Draft) { throw 'The Release workflow always publishes. For a draft use -Mode Api -Draft.' }
    if (-not $useWorkflow) { [void](Get-GitHubToken -Required) }

    Write-Step "Publishing $tag ($(if ($useWorkflow) { 'GitHub Actions workflow' } else { 'GitHub API' })$(if ($isPreRelease) { ', pre-release' })$(if ($Draft) { ', draft' }))"
    $currentBranch = @(Invoke-Git rev-parse --abbrev-ref HEAD)[0]
    if ($currentBranch -ne $Branch -and -not $Force) { throw "You are on '$currentBranch'. Releases are made from '$Branch' (switch branch, or use -Branch / -Force)." }
    try {
        Invoke-Git fetch --quiet $Remote | Out-Null
        $behind = [int]((@(Invoke-Git rev-list --left-right --count "HEAD...$Remote/$Branch")[0] -split '\s+')[1])
        if ($behind -gt 0 -and -not $Force) { throw "Your branch is $behind commit(s) behind $Remote/$Branch - run 'git pull' first." }
    } catch { if ($_.Exception.Message -match 'behind') { throw } else { Write-Note "Could not compare with $Remote/$Branch." } }
    if (Test-TagExists -Tag $tag) { throw "Tag $tag already exists. To change that release use UpdateNotes / UploadAssets, or remove it with: .\tools\Release.ps1 Delete -Version $NewVersion -DeleteTag" }

    $notes = Invoke-Prepare -NewVersion $NewVersion

    Write-Step 'Commit, tag and push'
    Invoke-Git add -A | Out-Null
    $staged = @(Invoke-Git diff --cached --name-only | Where-Object { $_ })
    $userData = @(Invoke-Git diff --cached --name-only --diff-filter=d | Where-Object { $_ -and ($_ -match $userDataPattern -or $_ -match $privateDocsPattern) })
    if ($userData.Count -gt 0) { throw "User data or internal documents would be committed ($($userData[0]) ...). Run .\tools\Release.ps1 Init first." }
    if ($staged.Count -gt 0) { Invoke-Git commit --quiet -m "Release $tag" | Out-Null; Write-Ok "Committed $($staged.Count) file(s): Release $tag" }
    else { Write-Info 'Nothing new to commit - tagging the current commit.' }
    Invoke-Git tag -a $tag -m "API Tester $tag" | Out-Null
    Write-Ok "Tagged $tag"
    Invoke-Git push --quiet $Remote "HEAD:$Branch" | Out-Null
    Invoke-Git push --quiet $Remote $tag | Out-Null
    Write-Ok "Pushed $Branch and $tag to $Remote"
    if ($DryRun) { Write-Info '(dry run) stops here.'; return }

    if ($useWorkflow) {
        if ($NoWait) { Write-Info "The Release workflow publishes ${tag}: https://github.com/$Repository/actions"; return }
        $release = Wait-WorkflowRelease -Tag $tag
    } else {
        Write-Step 'Creating the GitHub release'
        $target = @(Invoke-Git rev-parse HEAD)[0]
        $release = New-GitHubRelease -Tag $tag -Body (Read-TextFile $notes) -IsDraft ([bool]$Draft) -IsPreRelease $isPreRelease -Target $target
        Write-Ok "Release created: $($release.html_url)"
        Send-ReleaseAssets -Release $release
    }
    if (-not $Draft -and -not $isPreRelease) {
        if (-not (Test-UpdaterRelease -ExpectedVersion $NewVersion)) { throw 'The release is published but the updater check failed (see above).' }
    }
    Write-Step "Done - $tag"
}

function Get-ExistingRelease {
    param([string]$NewVersion)
    $tag = "v$NewVersion"
    $release = Find-Release -Tag $tag
    if (-not $release) { throw "No GitHub release for $tag. Create it with: .\tools\Release.ps1 Publish -Version $NewVersion" }
    return $release
}

# ---------------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------------
if (-not $Repository) { $Repository = Get-AppConstant 'AppGitHubRepo' }
if ($DryRun) { Write-Host '(dry run - nothing is written, committed, pushed or sent to GitHub)' -ForegroundColor Yellow }

switch ($Action) {
    'Status' { Invoke-Status }
    'Init' { Invoke-Init }
    'AddChange' {
        if ([string]::IsNullOrWhiteSpace($Message)) { throw 'AddChange needs -Message "..." (and optionally -Type Added|Changed|Deprecated|Removed|Fixed|Security).' }
        Add-ChangelogEntry -EntryType $Type -EntryText $Message
    }
    'NextVersion' {
        if (-not $Bump) { throw 'NextVersion needs -Bump Major|Minor|Patch.' }
        $current = Get-AppConstant 'AppVersion'
        Write-Host "$current -> $(Get-NextVersion -Current $current -Part $Bump -Suffix $PreRelease)"
    }
    'Notes' {
        $target = Resolve-TargetVersion
        $file = New-ReleaseNotes -NewVersion $target -Overwrite:$Force
        Write-Info "Edit it, then (for an existing release) run: .\tools\Release.ps1 UpdateNotes -Version $target"
        Write-Output $file
    }
    'Prepare' {
        $target = Resolve-TargetVersion
        $notes = Invoke-Prepare -NewVersion $target
        Write-Step 'Prepared'
        Write-Info "Review CHANGELOG.md and $notes, then: .\tools\Release.ps1 Publish -Version $target"
    }
    'Publish' { Invoke-Publish -NewVersion (Resolve-TargetVersion) }
    'UpdateNotes' {
        $target = Resolve-TargetVersion
        $release = Get-ExistingRelease -NewVersion $target
        $file = Get-NotesPath -NewVersion $target
        if (-not (Test-Path $file)) { throw "Notes file not found: $file (create it with: .\tools\Release.ps1 Notes -Version $target)" }
        Invoke-GitHubApi -Method PATCH -Path "/repos/$Repository/releases/$($release.id)" -Body @{ body = (Read-TextFile $file) } -Write | Out-Null
        Write-Ok "Release text of v$target updated from $file - $($release.html_url)"
        Write-Info 'Also commit the notes file so the repository matches the release.'
    }
    'UploadAssets' {
        $target = Resolve-TargetVersion
        $release = Get-ExistingRelease -NewVersion $target
        if (-not $SkipBuild) { [void](Invoke-Build) }
        $built = if ((Read-TextFile $paths.Dist) -match '\$script:AppVersion\s*=\s*"([^"]+)"') { $Matches[1] } else { '' }
        if ($built -ne $target -and -not $Force) { throw "dist\API-Tester.ps1 is version '$built', the release is v$target. Set the version first (Prepare) or use -Force." }
        Send-ReleaseAssets -Release $release
        if (-not $release.draft -and -not $release.prerelease) { [void](Test-UpdaterRelease -ExpectedVersion $target) }
    }
    'Verify' {
        $expected = if ($Version -or $Bump) { Resolve-TargetVersion } else { $null }
        if (-not (Test-UpdaterRelease -ExpectedVersion $expected)) { exit 1 }
    }
    'List' {
        $releases = @(Invoke-GitHubApi -Path "/repos/$Repository/releases?per_page=30")
        $latest = Invoke-GitHubApi -Path "/repos/$Repository/releases/latest" -AllowNotFound
        if ($releases.Count -eq 0) { Write-Info 'No releases.' }
        $releases | ForEach-Object {
            [PSCustomObject]@{
                Tag       = $_.tag_name
                State     = if ($_.draft) { 'draft' } elseif ($_.prerelease) { 'pre-release' } elseif ($latest -and $_.id -eq $latest.id) { 'latest' } else { 'published' }
                Published = if ($_.published_at) { ([datetime]$_.published_at).ToString('yyyy-MM-dd') } else { '' }
                Assets    = (@($_.assets | ForEach-Object { $_.name }) -join ', ')
                Url       = $_.html_url
            }
        } | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
    }
    'Delete' {
        if (-not $Version) { throw 'Delete needs -Version x.y.z.' }
        $target = Resolve-TargetVersion
        $tag = "v$target"
        $release = Find-Release -Tag $tag
        if (-not $release -and -not $DeleteTag) { throw "No GitHub release for $tag." }
        if (-not $Force -and -not $DryRun) {
            $answer = Read-Host "Type $tag to delete the release$(if ($DeleteTag) { ' and its tag' })"
            if ($answer -ne $tag) { Write-Info 'Cancelled.'; return }
        }
        if ($release) {
            Invoke-GitHubApi -Method DELETE -Path "/repos/$Repository/releases/$($release.id)" -Write | Out-Null
            Write-Ok "Release $tag deleted"
        }
        if ($DeleteTag) {
            Test-GitAvailable
            try { Invoke-Git push --quiet $Remote ":refs/tags/$tag" | Out-Null; Write-Ok "Remote tag $tag deleted" } catch { Write-Note $_.Exception.Message }
            try { if (-not $DryRun) { Invoke-Git tag -d $tag | Out-Null }; Write-Ok "Local tag $tag deleted" } catch { Write-Note $_.Exception.Message }
        }
    }
}
