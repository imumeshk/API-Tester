#region Monitor alert channels (Teams / Slack / webhook) and quiet hours

# True when the current time is inside "HH:mm"-"HH:mm" (the range may cross midnight).
function Test-InQuietHours {
    param([string]$Start, [string]$End)
    $startTime = [TimeSpan]::Zero; $endTime = [TimeSpan]::Zero
    if (-not [TimeSpan]::TryParse([string]$Start, [ref]$startTime) -or -not [TimeSpan]::TryParse([string]$End, [ref]$endTime) -or $startTime -eq $endTime) { return $false }
    $now = (Get-Date).TimeOfDay
    if ($startTime -lt $endTime) { return ($now -ge $startTime -and $now -lt $endTime) }
    return ($now -ge $startTime -or $now -lt $endTime)
}

# Posts an alert to Microsoft Teams (incoming-webhook MessageCard), Slack (incoming webhook) or any URL (JSON).
function Send-MonitorWebhookAlert {
    param([string]$Url, [string]$Type = 'Generic', [string]$Title, [hashtable]$Data, [string]$Kind)
    if ([string]::IsNullOrWhiteSpace($Url)) { return }
    $line = "$($Data.Message) - HTTP $($Data.StatusCode) in $($Data.TimeMs) ms"
    $payload = switch ($Type) {
        'Teams' { [ordered]@{ '@type' = 'MessageCard'; '@context' = 'https://schema.org/extensions'; summary = $Title; themeColor = $(if ($Kind -eq 'Recovered') { '107C10' } elseif ($Kind -eq 'Slow') { 'B45309' } else { 'D93025' }); title = $Title; text = "$line<br/>$($Data.Url)<br/>$($Data.Timestamp)" } }
        'Slack' { [ordered]@{ text = "*$Title*`n$line`n$($Data.Url)" } }
        default { [ordered]@{ title = $Title; kind = $Kind; monitorName = $Data.MonitorName; status = $Data.Status; statusCode = $Data.StatusCode; url = $Data.Url; timeMs = $Data.TimeMs; message = $Data.Message; timestamp = $Data.Timestamp } }
    }
    try {
        Add-Type -AssemblyName System.Net.Http
        Enable-ModernTls
        if (-not $script:alertWebhookClient) { $script:alertWebhookClient = New-Object System.Net.Http.HttpClient; $script:alertWebhookClient.Timeout = [TimeSpan]::FromSeconds(15) }
        [void]$script:alertWebhookClient.PostAsync($Url, (New-Object System.Net.Http.StringContent((ConvertTo-Json -InputObject $payload -Depth 5 -Compress), [System.Text.Encoding]::UTF8, 'application/json')))
    } catch { Write-Log "Failed to send the $Type alert: $($_.Exception.Message)" -Level Info }
}

function Get-LatencyPercentile {
    param([int[]]$SortedValues, [double]$Fraction)
    if (-not $SortedValues -or $SortedValues.Count -eq 0) { return $null }
    return $SortedValues[[Math]::Min($SortedValues.Count - 1, [Math]::Max(0, [int][Math]::Ceiling($SortedValues.Count * $Fraction) - 1))]
}
#endregion
