function Show-ReportCustomizationDialog {
    param($parentForm)

    $dialog = New-Object System.Windows.Forms.Form -Property @{
        Text = "Customize Report"
        Size = New-Object System.Drawing.Size(400, 500)
        StartPosition = "CenterParent"
        FormBorderStyle = "FixedDialog"
        MaximizeBox = $false
        MinimizeBox = $false
    }

    $layout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; Padding = [System.Windows.Forms.Padding]::new(10); ColumnCount = 1 }
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $chkSummaryCards = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Include Summary Cards"; Checked = $true; AutoSize = $true }
    $chkMonitorStats = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Include Monitor Statistics Table"; Checked = $true; AutoSize = $true }
    
    $groupDetailedLog = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Detailed Log Columns"; Dock = 'Fill' }
    $clbColumns = New-Object System.Windows.Forms.CheckedListBox -Property @{ Dock = 'Fill'; CheckOnClick = $true; BorderStyle = 'None' }
    
    $availableColumns = @("Timestamp", "MonitorName", "URL", "Success", "StatusCode", "TimeMs", "Message")
    $clbColumns.Items.AddRange($availableColumns)
    for ($i = 0; $i -lt $clbColumns.Items.Count; $i++) {
        $clbColumns.SetItemChecked($i, $true)
    }
    $groupDetailedLog.Controls.Add($clbColumns)

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ FlowDirection = 'RightToLeft'; Dock = 'Fill'; AutoSize = $true }
    $btnGenerate = New-Button -Text "Generate" -Style 'Primary' -Property @{ Width = 100; Height = 32 } -OnClick {
        $selectedColumns = @()
        foreach ($item in $clbColumns.CheckedItems) {
            $selectedColumns += $item
        }
        $dialog.Tag = [PSCustomObject]@{
            IncludeSummaryCards = $chkSummaryCards.Checked
            IncludeMonitorStats = $chkMonitorStats.Checked
            DetailedLogColumns = $selectedColumns
        }
        $dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $dialog.Close()
    }
    $btnCancel = New-Button -Text "Cancel" -Style 'Secondary' -Property @{ Width = 100; Height = 32 } -OnClick {
        $dialog.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $dialog.Close()
    }
    $buttons.Controls.AddRange(@($btnGenerate, $btnCancel))

    $layout.Controls.Add($chkSummaryCards, 0, 0)
    $layout.Controls.Add($chkMonitorStats, 0, 1)
    $layout.Controls.Add($groupDetailedLog, 0, 2)
    $layout.Controls.Add($buttons, 0, 3)

    $dialog.Controls.Add($layout)
    $result = $dialog.ShowDialog($parentForm)

    return [PSCustomObject]@{
        Result = $result
        Options = $dialog.Tag
    }
}

# --- Report Generator Window ---
function Show-ReportGenerator {
    param($parentForm)    
    
    if (-not (Test-Path $monitorLogFilePath)) {
        [System.Windows.Forms.MessageBox]::Show("No monitor log file found to generate report.", "Info", "OK", "Information")
        return
    }

    # Show customization dialog
    $customization = Show-ReportCustomizationDialog -parentForm $parentForm
    if ($customization.Result -ne [System.Windows.Forms.DialogResult]::OK) {
        return # User cancelled
    }
    $options = $customization.Options

    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "HTML Report (*.html)|*.html"
    $sfd.FileName = "API_Test_Report_$((Get-Date).ToString('yyyyMMdd')).html"
    
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $data = Import-Csv $monitorLogFilePath
            if ($data.Count -eq 0) { throw "Log file is empty." }

            $html = @"
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
"@
            if ($options.IncludeSummaryCards) {
                $totalRuns = $data.Count
                $passed = ($data | Where-Object { $_.Success -eq 'True' }).Count
                $failed = $totalRuns - $passed
                $passRate = if ($totalRuns -gt 0) { "{0:N2}" -f (($passed / $totalRuns) * 100) } else { 0 }
                $html += @"
<div class="summary">
    <div class="card"><h3>Total Runs</h3><div class="value">$totalRuns</div></div>
    <div class="card"><h3>Pass Rate</h3><div class="value $(if([double]$passRate -ge 90){'pass'}else{'fail'})">$passRate%</div></div>
    <div class="card"><h3>Passed</h3><div class="value pass">$passed</div></div>
    <div class="card"><h3>Failed</h3><div class="value fail">$failed</div></div>
</div>
"@
            }

            if ($options.IncludeMonitorStats) {
                $monitors = $data | Group-Object MonitorName
                $html += @"
<h2>Detailed Statistics</h2>
<table>
<thead><tr><th>Monitor Name</th><th>Runs</th><th>Pass %</th><th>Avg Time (ms)</th><th>Max Time (ms)</th><th>Last Status</th></tr></thead>
<tbody>
"@
                foreach ($m in $monitors) {
                    $mRuns = $m.Group.Count
                    $mPassed = ($m.Group | Where-Object { $_.Success -eq 'True' }).Count
                    $mPassRate = "{0:N2}" -f (($mPassed / $mRuns) * 100)
                    $times = $m.Group | ForEach-Object { [int]$_.TimeMs }
                    $avgTime = "{0:N0}" -f ($times | Measure-Object -Average).Average
                    $maxTime = ($times | Measure-Object -Maximum).Maximum
                    $lastStatus = $m.Group[$m.Group.Count - 1].Message
                    
                    $html += "<tr><td>$($m.Name)</td><td>$mRuns</td><td>$mPassRate%</td><td>$avgTime</td><td>$maxTime</td><td>$lastStatus</td></tr>"
                }
                $html += @"
</tbody>
</table>
"@
            }

            if ($options.DetailedLogColumns.Count -gt 0) {
                $html += @"
<h2>Detailed Log</h2>
<table>
<thead><tr>
"@
                foreach ($col in $options.DetailedLogColumns) {
                    $html += "<th>$col</th>"
                }
                $html += "</tr></thead><tbody>"

                foreach ($row in $data) {
                    $html += "<tr>"
                    foreach ($col in $options.DetailedLogColumns) {
                        $html += "<td>$($row.$col)</td>"
                    }
                    $html += "</tr>"
                }

                $html += "</tbody></table>"
            }

            $html += @"
</body>
</html>
"@
            $html | Set-Content -Path $sfd.FileName -Encoding UTF8
            Start-Process $sfd.FileName
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to generate report: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
}

# --- Monitor Editor Window ---
