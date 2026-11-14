function Invoke-UpdateCheck {
    param(
        [System.Windows.Forms.Label]$StatusLabel,
        [System.Windows.Forms.Button]$DownloadButton,
        [System.Windows.Forms.Form]$ParentForm
    )

    $StatusLabel.Text      = "Checking for updates..."
    $StatusLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#6c757d")
    $DownloadButton.Visible = $false
    [System.Windows.Forms.Application]::DoEvents()

    try {
        $apiUrl = "https://api.github.com/repos/$($script:AppGitHubRepo)/releases/latest"
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell-API-Tester/$($script:AppVersion)")
        $json = $webClient.DownloadString($apiUrl)
        $release = $json | ConvertFrom-Json

        # Extract the leading X.Y[.Z[.W]] so tags like 'v2.1.0-beta' still parse.
        if ($release.tag_name -notmatch '(\d+\.\d+(?:\.\d+){0,2})') {
            $StatusLabel.Text      = "[!] Could not read the latest release version (tag: '$($release.tag_name)')."
            $StatusLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#d93025")
            return
        }
        $rawTag = $Matches[1]
        $latestVersion  = [System.Version]::new($rawTag)
        $currentVersion = [System.Version]::new(($script:AppVersion -replace '[^\d\.].*$', ''))

        if ($latestVersion -gt $currentVersion) {
            $StatusLabel.Text      = "v$rawTag is available! (you have v$($script:AppVersion))"
            $StatusLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#0078d4")
            $DownloadButton.Tag     = $release
            $DownloadButton.Visible = $true
        } else {
            $StatusLabel.Text      = "[OK] You are on the latest version (v$($script:AppVersion))"
            $StatusLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#107c10")
        }
    } catch {
        $StatusLabel.Text      = "[!] Could not check for updates. Check your internet connection."
        $StatusLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#d93025")
    }
}

# Downloads the updated script from the GitHub release asset and replaces the current file.
function Invoke-DownloadUpdate {
    param(
        $Release,
        [System.Windows.Forms.Label]$StatusLabel
    )

    try {
        # Find the matching asset by name
        $asset = $Release.assets | Where-Object { $_.name -eq $script:AppGitHubAsset } | Select-Object -First 1

        if (-not $asset) {
            # Fallback: open the releases page in the browser
            [System.Diagnostics.Process]::Start("https://github.com/$($script:AppGitHubRepo)/releases") | Out-Null
            $StatusLabel.Text      = "Opened releases page in browser."
            $StatusLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#6c757d")
            return
        }

        $StatusLabel.Text      = "Downloading update..."
        $StatusLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#6c757d")
        [System.Windows.Forms.Application]::DoEvents()

        $scriptPath  = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.ScriptName }
        $newPath     = [System.IO.Path]::ChangeExtension($scriptPath, ".new.ps1")
        $backupPath  = [System.IO.Path]::ChangeExtension($scriptPath, ".bak.ps1")

        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell-API-Tester/$($script:AppVersion)")
        $webClient.DownloadFile($asset.browser_download_url, $newPath)

        # Integrity check: if the release publishes '<asset>.sha256', the download must match it before we swap files.
        $hashAsset = $Release.assets | Where-Object { $_.name -eq "$($script:AppGitHubAsset).sha256" } | Select-Object -First 1
        if ($hashAsset) {
            $expectedHash = ($webClient.DownloadString($hashAsset.browser_download_url).Trim() -split '\s+')[0].ToUpperInvariant()
            $actualHash   = (Get-FileHash -Path $newPath -Algorithm SHA256).Hash.ToUpperInvariant()
            if ($expectedHash -ne $actualHash) {
                Remove-Item $newPath -Force -ErrorAction SilentlyContinue
                throw "Checksum mismatch - the downloaded file was discarded."
            }
        }

        # Swap files
        if (Test-Path $backupPath) { Remove-Item $backupPath -Force }
        Copy-Item  $scriptPath $backupPath -Force
        Copy-Item  $newPath    $scriptPath -Force
        Remove-Item $newPath -Force

        $StatusLabel.Text      = "[OK] Update downloaded! Restart the app to apply changes."
        $StatusLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#107c10")

        [System.Windows.Forms.MessageBox]::Show(
            "Update downloaded successfully!`n`nA backup of the previous version was saved as:`n$backupPath`n`nPlease restart the application to apply the update.",
            "Update Ready",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null

    } catch {
        $StatusLabel.Text      = "[!] Download failed: $($_.Exception.Message)"
        $StatusLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#d93025")
    }
}

# Shows a quick Keyboard Shortcuts reference dialog.

# ---- UI-independent update functions (used by the XAML About window) ---------------------------------------------
# Returns @{ State = 'Error'|'Current'|'Available'; Message; Release; Version }.
function Get-UpdateStatus {
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell-API-Tester/$($script:AppVersion)")
        $release = $webClient.DownloadString("https://api.github.com/repos/$($script:AppGitHubRepo)/releases/latest") | ConvertFrom-Json
        if ($release.tag_name -notmatch '(\d+\.\d+(?:\.\d+){0,2})') { return @{ State = 'Error'; Message = "Could not read the latest release version (tag: '$($release.tag_name)')." } }
        $rawTag = $Matches[1]
        $latestVersion = [System.Version]::new($rawTag)
        $currentVersion = [System.Version]::new(($script:AppVersion -replace '[^\d\.].*$', ''))
        if ($latestVersion -gt $currentVersion) { return @{ State = 'Available'; Message = "v$rawTag is available! (you have v$($script:AppVersion))"; Release = $release; Version = $rawTag } }
        return @{ State = 'Current'; Message = "You are on the latest version (v$($script:AppVersion))"; Version = $rawTag }
    } catch {
        return @{ State = 'Error'; Message = 'Could not check for updates. Check your internet connection.' }
    }
}

# Downloads and installs a release asset (verifying <asset>.sha256 when published). Returns @{ Success; Message }.
function Install-UpdateRelease {
    param($Release)
    try {
        $asset = $Release.assets | Where-Object { $_.name -eq $script:AppGitHubAsset } | Select-Object -First 1
        if (-not $asset) {
            Start-Process "https://github.com/$($script:AppGitHubRepo)/releases"
            return @{ Success = $true; Message = 'Opened the releases page in your browser.' }
        }
        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.ScriptName }
        $newPath = [System.IO.Path]::ChangeExtension($scriptPath, '.new.ps1')
        $backupPath = [System.IO.Path]::ChangeExtension($scriptPath, '.bak.ps1')
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell-API-Tester/$($script:AppVersion)")
        $webClient.DownloadFile($asset.browser_download_url, $newPath)
        $hashAsset = $Release.assets | Where-Object { $_.name -eq "$($script:AppGitHubAsset).sha256" } | Select-Object -First 1
        if ($hashAsset) {
            $expectedHash = ($webClient.DownloadString($hashAsset.browser_download_url).Trim() -split '\s+')[0].ToUpperInvariant()
            if ($expectedHash -ne (Get-FileHash -Path $newPath -Algorithm SHA256).Hash.ToUpperInvariant()) {
                Remove-Item $newPath -Force -ErrorAction SilentlyContinue
                throw 'Checksum mismatch - the downloaded file was discarded.'
            }
        }
        if (Test-Path $backupPath) { Remove-Item $backupPath -Force }
        Copy-Item $scriptPath $backupPath -Force
        Copy-Item $newPath $scriptPath -Force
        Remove-Item $newPath -Force
        return @{ Success = $true; Message = "Update installed. A backup was saved as $backupPath - restart the app to apply it." }
    } catch {
        return @{ Success = $false; Message = "Download failed: $($_.Exception.Message)" }
    }
}

# ---- Startup update check -------------------------------------------------------------------------------------------
# Runs on a background runspace (never delays start-up), at most once every 24 hours, unless switched off in Settings
# (CheckForUpdatesOnStartup). When a newer release exists the header shows it and Help -> About offers the download.

function ConvertTo-ReleaseVersion {
    param([string]$Tag)
    if ($Tag -match '(\d+\.\d+(?:\.\d+){0,2})') { return [System.Version]::new($Matches[1]) }
    return $null
}

function Start-StartupUpdateCheck {
    if ($script:settings.CheckForUpdatesOnStartup -eq $false) { return }
    $lastCheck = [datetime]::MinValue
    if ($script:settings.LastUpdateCheck -and [datetime]::TryParse([string]$script:settings.LastUpdateCheck, [ref]$lastCheck) -and ([datetime]::Now - $lastCheck).TotalHours -lt 24) { return }
    $worker = [PowerShell]::Create()
    [void]$worker.AddScript({
        param($Repository, $Version)
        try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 } catch { }
        $client = New-Object System.Net.WebClient
        $client.Headers.Add('User-Agent', "PowerShell-API-Tester/$Version")
        ($client.DownloadString("https://api.github.com/repos/$Repository/releases/latest") | ConvertFrom-Json).tag_name
    }).AddArgument($script:AppGitHubRepo).AddArgument($script:AppVersion)
    $script:updateCheckJob = @{ Worker = $worker; Handle = $worker.BeginInvoke() }
    $script:updateCheckTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:updateCheckTimer.Interval = [TimeSpan]::FromSeconds(1)
    $script:updateCheckTimer.Add_Tick({ Invoke-UiGuard { Complete-StartupUpdateCheck } 'Update check' })
    $script:updateCheckTimer.Start()
}

function Complete-StartupUpdateCheck {
    $job = $script:updateCheckJob
    if (-not $job -or -not $job.Handle.IsCompleted) { return }
    $script:updateCheckTimer.Stop()
    $script:updateCheckJob = $null
    try {
        $tag = [string](@($job.Worker.EndInvoke($job.Handle)) | Select-Object -Last 1)
        $script:settings.LastUpdateCheck = (Get-Date).ToString('o')
        Save-Settings
        $latest = ConvertTo-ReleaseVersion -Tag $tag
        $current = ConvertTo-ReleaseVersion -Tag $script:AppVersion
        if ($latest -and $current -and $latest -gt $current) {
            Set-UiStatus "API Tester $tag is available - open Help -> About API Tester to update."
            if ($script:ui -and $script:ui.MenuAbout) { $script:ui.MenuAbout.Header = "_About API Tester... ($tag available)" }
            Write-Log "Update available: $tag (running v$($script:AppVersion))." -Level Info
        }
    } catch { Write-Log "Startup update check failed: $($_.Exception.Message)" -Level Debug }
    finally { try { $job.Worker.Dispose() } catch { } }
}
