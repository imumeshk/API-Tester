#region Report Builder
# Builds the HTML monitor report from the monitor CSV log. $Options: IncludeSummaryCards, IncludeMonitorStats, DetailedLogColumns.
function New-MonitorReportHtml {
    param([Parameter(Mandatory = $true)]$Data, [Parameter(Mandatory = $true)]$Options)

    $encode = { param($value) [System.Net.WebUtility]::HtmlEncode([string]$value) }
    $html = New-Object System.Text.StringBuilder
    [void]$html.AppendLine(@"
<!DOCTYPE html>
<html>
<head>
<title>API Test Report</title>
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f4f4; }
h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
.summary { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
.card { border: 1px solid #ddd; padding: 20px; border-radius: 8px; background: white; min-width: 150px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.card h3 { margin: 0 0 10px 0; font-size: 1em; color: #666; text-transform: uppercase; letter-spacing: 1px; }
.card .value { font-size: 2em; font-weight: bold; color: #333; }
.pass { color: #28a745; }
.fail { color: #dc3545; }
table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
th { background-color: #0078d4; color: white; font-weight: 600; }
tr:last-child td { border-bottom: none; }
tr:hover { background-color: #f9f9f9; }
</style>
</head>
<body>
<h1>API Test Execution Report</h1>
<p>Generated on $(Get-Date)</p>
"@)
    $rows = @($Data)
    if ($Options.IncludeSummaryCards) {
        $totalRuns = $rows.Count
        $passed = @($rows | Where-Object { $_.Success -eq 'True' }).Count
        $failed = $totalRuns - $passed
        $passRate = if ($totalRuns -gt 0) { [Math]::Round(($passed / $totalRuns) * 100, 2) } else { 0 }
        $rateClass = if ($passRate -ge 90) { 'pass' } else { 'fail' }
        [void]$html.AppendLine("<div class=`"summary`"><div class=`"card`"><h3>Total Runs</h3><div class=`"value`">$totalRuns</div></div><div class=`"card`"><h3>Pass Rate</h3><div class=`"value $rateClass`">$passRate%</div></div><div class=`"card`"><h3>Passed</h3><div class=`"value pass`">$passed</div></div><div class=`"card`"><h3>Failed</h3><div class=`"value fail`">$failed</div></div></div>")
    }
    if ($Options.IncludeMonitorStats) {
        [void]$html.AppendLine('<h2>Detailed Statistics</h2><table><thead><tr><th>Monitor Name</th><th>Runs</th><th>Pass %</th><th>Avg Time (ms)</th><th>Max Time (ms)</th><th>Last Status</th></tr></thead><tbody>')
        foreach ($group in ($rows | Group-Object MonitorName)) {
            $runs = $group.Group.Count
            $groupPassed = @($group.Group | Where-Object { $_.Success -eq 'True' }).Count
            $times = @($group.Group | ForEach-Object { [int]$_.TimeMs })
            $average = ($times | Measure-Object -Average).Average
            $maximum = ($times | Measure-Object -Maximum).Maximum
            $lastMessage = $group.Group[$group.Group.Count - 1].Message
            [void]$html.AppendLine("<tr><td>$(& $encode $group.Name)</td><td>$runs</td><td>$([Math]::Round(($groupPassed / $runs) * 100, 2))%</td><td>$([Math]::Round($average, 0))</td><td>$maximum</td><td>$(& $encode $lastMessage)</td></tr>")
        }
        [void]$html.AppendLine('</tbody></table>')
    }
    if (@($Options.DetailedLogColumns).Count -gt 0) {
        [void]$html.AppendLine('<h2>Detailed Log</h2><table><thead><tr>')
        foreach ($column in $Options.DetailedLogColumns) { [void]$html.Append("<th>$column</th>") }
        [void]$html.AppendLine('</tr></thead><tbody>')
        foreach ($row in $rows) {
            [void]$html.Append('<tr>')
            foreach ($column in $Options.DetailedLogColumns) { [void]$html.Append("<td>$(& $encode $row.$column)</td>") }
            [void]$html.AppendLine('</tr>')
        }
        [void]$html.AppendLine('</tbody></table>')
    }
    [void]$html.AppendLine('</body></html>')
    return $html.ToString()
}
#endregion
