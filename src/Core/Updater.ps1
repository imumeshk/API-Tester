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

        $rawTag = $release.tag_name -replace '^v', ''
        $latestVersion  = [System.Version]::new($rawTag)
        $currentVersion = [System.Version]::new($script:AppVersion)

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
