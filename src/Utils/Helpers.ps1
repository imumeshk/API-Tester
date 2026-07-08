function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('Info', 'Debug')][string]$Level = 'Debug' # Default to Debug for existing calls
    )
    if ($script:settings.EnableLogs) {
        # Log Rotation: Check if file exceeds 5MB and rotate if necessary
        if (Test-Path $logFilePath) {
            try {
                if ((Get-Item $logFilePath).Length -gt 5MB) {
                    $timestamp = (Get-Date).ToString('yyyyMMddHHmmss')
                    $logName = [System.IO.Path]::GetFileName($logFilePath)
                    Rename-Item -Path $logFilePath -NewName "$logName.$timestamp.bak" -ErrorAction SilentlyContinue

                    # Cleanup old logs (keep last 5)
                    $logDir = [System.IO.Path]::GetDirectoryName($logFilePath)
                    Get-ChildItem -Path $logDir -Filter "$logName.*.bak" | Sort-Object CreationTime -Descending | Select-Object -Skip 5 | Remove-Item -Force -ErrorAction SilentlyContinue
                }
            } catch { }
        }
        # Only log if the level is 'Info' or if the configured level is 'Debug'
        if ($Level -eq 'Info' -or $script:settings.LogLevel -eq 'Debug') {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            if (-not (Test-Path $logFilePath)) {
                Add-Content -Path $logFilePath -Value "Timestamp,Level,Message"
            }
            $safeMessage = '"' + $Message.Replace('"', '""') + '"'
            $logEntry = "$timestamp,$Level,$safeMessage"
            Add-Content -Path $logFilePath -Value $logEntry
        }
    }
}

# Factory function to create a System.Windows.Forms.Label control.
function Test-IsHtmlBody {
    param([string]$Body)
    if ([string]::IsNullOrWhiteSpace($Body)) { return $false }
    return ($Body -match '<\s*(html|body|div|span|p|br|table|tr|td|a|b|i|strong|em|ul|ol|li)\b')
}

# Factory function to create a standardized TableLayoutPanel for authentication details.
function Protect-String {
    param([string]$String)
    if ([string]::IsNullOrEmpty($String)) { return $String }
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Convert]::ToBase64String($encrypted)
    } catch { return $String }
}

function Unprotect-String {
    param([string]$String)
    if ([string]::IsNullOrEmpty($String)) { return $String }
    try {
        $bytes = [Convert]::FromBase64String($String)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    } catch { return $String } # Return original if decryption fails (e.g. plain text)
}

# Sends an email using SMTP XOAUTH2 (required for Gmail/Outlook Modern Auth).
