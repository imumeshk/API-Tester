function Show-MonitoringDashboard {
    param($parentForm)

    # Check for charting assemblies
    try {
        $chartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Charting assemblies not found. Please ensure .NET Framework 4.x is installed.", "Error", "OK", "Error")
        return
    }

    $dashboardForm = New-Object System.Windows.Forms.Form -Property @{
        Text = "Monitoring Dashboard"
        Size = New-Object System.Drawing.Size(1000, 700)
        StartPosition = "CenterParent"
        BackColor = $script:Theme.FormBackground
    }

    # --- Main Layout ---
    $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        RowCount = 3
        Padding = [System.Windows.Forms.Padding]::new(10)
    }
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    
    # --- Toolbar ---
    $toolbar = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; AutoSize = $true; WrapContents = $true }
    $lblMonitorFilter = New-Label -Text "Monitor:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,5,0) }
    $comboMonitorFilter = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle='DropDownList'; Width=200; Margin=[System.Windows.Forms.Padding]::new(0,3,10,0) }
    $lblFrom = New-Label -Text "From:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(10,6,5,0) }
    $dtpFrom = New-Object System.Windows.Forms.DateTimePicker -Property @{ Format='Short'; Width=100; ShowCheckBox=$true; Checked=$false; Margin=[System.Windows.Forms.Padding]::new(0,3,10,0) }
    $lblTo = New-Label -Text "To:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,5,0) }
    $dtpTo = New-Object System.Windows.Forms.DateTimePicker -Property @{ Format='Short'; Width=100; ShowCheckBox=$true; Checked=$false; Margin=[System.Windows.Forms.Padding]::new(0,3,10,0) }
    $btnRefresh = New-Button -Text "Refresh" -Style 'Primary' -Property @{ Width=100; Height=32; Margin=[System.Windows.Forms.Padding]::new(10,0,0,0) }
    $btnExportData = New-Button -Text "Export Data" -Style 'Secondary' -Property @{ Width=120; Height=32; Margin=[System.Windows.Forms.Padding]::new(10,0,0,0) }
    $btnSaveChart = New-Button -Text "Save Chart" -Style 'Secondary' -Property @{ Width=120; Height=32; Margin=[System.Windows.Forms.Padding]::new(5,0,0,0) }
    $toolbar.Controls.AddRange(@($lblMonitorFilter, $comboMonitorFilter, $lblFrom, $dtpFrom, $lblTo, $dtpTo, $btnRefresh, $btnExportData, $btnSaveChart))

    # --- Dashboard Cards ---
    $dashboardCardsLayout = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; AutoScroll = $true; AutoSize=$true }

    function New-DashboardCard {
        param([string]$Title, [string]$InitialValue = "...")
        $card = New-Object System.Windows.Forms.Panel -Property @{ Size = New-Object System.Drawing.Size(180, 100); BackColor = $script:Theme.GroupBackground; Margin = [System.Windows.Forms.Padding]::new(10) }
        $lblTitle = New-Label -Text $Title -Property @{ Dock = 'Top'; Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold); ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#6c757d"); TextAlign = 'MiddleCenter'; Height = 30 }
        $lblValue = New-Label -Text $InitialValue -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Segoe UI", 22, [System.Drawing.FontStyle]::Bold); TextAlign = 'MiddleCenter' }
        $card.Controls.AddRange(@($lblValue, $lblTitle))
        return [PSCustomObject]@{ Panel = $card; ValueLabel = $lblValue }
    }

    $uptimeCard = New-DashboardCard -Title "Uptime"
    $latencyCard = New-DashboardCard -Title "Avg. Latency"
    $totalRunsCard = New-DashboardCard -Title "Total Runs"
    $passedCard = New-DashboardCard -Title "Passed"
    $failedCard = New-DashboardCard -Title "Failed"

    $dashboardCardsLayout.Controls.AddRange(@($uptimeCard.Panel, $latencyCard.Panel, $totalRunsCard.Panel, $passedCard.Panel, $failedCard.Panel))

    # --- Chart ---
    $chartGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Latency Over Time"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor=$script:Theme.GroupBackground }
    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart -Property @{ Dock='Fill' }
    $chartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
    $chartArea.AxisX.LabelStyle.Format = "HH:mm"
    $chartArea.AxisY.Title = "Latency (ms)"
    $chart.ChartAreas.Add($chartArea)
    
    $latencySeries = New-Object System.Windows.Forms.DataVisualization.Charting.Series("Latency")
    $latencySeries.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
    $latencySeries.BorderWidth = 2
    $latencySeries.Color = [System.Drawing.ColorTranslator]::FromHtml("#0078d4")
    $chart.Series.Add($latencySeries)
    $chartGroup.Controls.Add($chart)

    # --- Update Logic ---
    $script:filteredDashboardData = $null
    function Update-DashboardData {
        if (-not (Test-Path $monitorLogFilePath)) {
            $uptimeCard.ValueLabel.Text = "N/A"; $latencyCard.ValueLabel.Text = "N/A"; $totalRunsCard.ValueLabel.Text = "N/A"; $passedCard.ValueLabel.Text = "N/A"; $failedCard.ValueLabel.Text = "N/A"
            $latencySeries.Points.Clear()
            return
        }
        try {
            $allData = Import-Csv $monitorLogFilePath
            
            # Populate filter dropdown
            $currentFilter = $comboMonitorFilter.SelectedItem
            $monitors = $allData | Select-Object -ExpandProperty MonitorName -Unique | Sort-Object
            $comboMonitorFilter.Items.Clear()
            $comboMonitorFilter.Items.Add("All Monitors")
            $comboMonitorFilter.Items.AddRange($monitors)
            if ($currentFilter -and $comboMonitorFilter.Items.Contains($currentFilter)) { $comboMonitorFilter.SelectedItem = $currentFilter } else { $comboMonitorFilter.SelectedIndex = 0 }

            # Filter data based on selection
            $data = $allData
            if ($comboMonitorFilter.SelectedItem -ne "All Monitors") {
                $data = $allData | Where-Object { $_.MonitorName -eq $comboMonitorFilter.SelectedItem }
            }

            # Date filtering
            if ($dtpFrom.Checked) {
                $data = $data | Where-Object { ([DateTime]$_.Timestamp) -ge $dtpFrom.Value.Date }
            }
            if ($dtpTo.Checked) {
                $data = $data | Where-Object { ([DateTime]$_.Timestamp) -le $dtpTo.Value.Date.AddDays(1).AddTicks(-1) }
            }

            $script:filteredDashboardData = $data

            if ($data.Count -eq 0) { throw "No data for selected monitor and date range." }

            $totalRuns = $data.Count
            $passed = ($data | Where-Object { $_.Success -eq 'True' }).Count
            $failed = $totalRuns - $passed
            $uptime = if ($totalRuns -gt 0) { ($passed / $totalRuns) } else { 0 }
            $avgLatency = ($data | Measure-Object -Property TimeMs -Average).Average

            $uptimeCard.ValueLabel.Text = "{0:P2}" -f $uptime
            $latencyCard.ValueLabel.Text = "{0:N0} ms" -f $avgLatency
            $totalRunsCard.ValueLabel.Text = $totalRuns
            $passedCard.ValueLabel.Text = $passed
            $failedCard.ValueLabel.Text = $failed

            if ($uptime -ge 0.99) { $uptimeCard.ValueLabel.ForeColor = [System.Drawing.Color]::DarkGreen }
            elseif ($uptime -ge 0.95) { $uptimeCard.ValueLabel.ForeColor = [System.Drawing.Color]::Orange }
            else { $uptimeCard.ValueLabel.ForeColor = [System.Drawing.Color]::DarkRed }

            # Update Chart
            $latencySeries.Points.Clear()
            $data | ForEach-Object {
                $ts = [DateTime]$_.Timestamp
                $latencySeries.Points.AddXY($ts, [int]$_.TimeMs) | Out-Null
            }
            $chartArea.AxisX.LabelStyle.Format = if (($data[-1].Timestamp -as [datetime]) - ($data[0].Timestamp -as [datetime]).TotalDays -gt 1) { "MM-dd HH:mm" } else { "HH:mm:ss" }
            $chart.DataManipulator.Sort("X", $latencySeries)

        } catch {
            $uptimeCard.ValueLabel.Text = "N/A"; $latencyCard.ValueLabel.Text = "N/A"; $totalRunsCard.ValueLabel.Text = "N/A"; $passedCard.ValueLabel.Text = "N/A"; $failedCard.ValueLabel.Text = "N/A"
            $latencySeries.Points.Clear()
        }
    }

    $dtpFrom.Add_ValueChanged({ Update-DashboardData })
    $dtpTo.Add_ValueChanged({ Update-DashboardData })
    $btnRefresh.Add_Click({ Update-DashboardData })
    $comboMonitorFilter.Add_SelectedIndexChanged({ Update-DashboardData })

    $btnExportData.Add_Click({
        if (-not $script:filteredDashboardData -or $script:filteredDashboardData.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("There is no data to export.", "Info", "OK", "Information")
            return
        }
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = "CSV File (*.csv)|*.csv"
        $sfd.FileName = "monitor_data_export_$((Get-Date).ToString('yyyyMMdd')).csv"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $script:filteredDashboardData | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
                [System.Windows.Forms.MessageBox]::Show("Data exported successfully.", "Success", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to export data: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    })

    $btnSaveChart.Add_Click({
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = "PNG Image|*.png|JPEG Image|*.jpg|Bitmap Image|*.bmp"
        $sfd.Title = "Save Chart Image"
        $sfd.FileName = "MonitorChart.png"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Png
                if ($sfd.FileName.EndsWith(".jpg", [System.StringComparison]::OrdinalIgnoreCase)) { $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Jpeg }
                elseif ($sfd.FileName.EndsWith(".bmp", [System.StringComparison]::OrdinalIgnoreCase)) { $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Bmp }
                
                $chart.SaveImage($sfd.FileName, $format)
                [System.Windows.Forms.MessageBox]::Show("Chart saved successfully.", "Success", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to save chart: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    })

    # --- Assemble Form ---
    $mainLayout.Controls.Add($toolbar, 0, 0)
    $mainLayout.Controls.Add($dashboardCardsLayout, 0, 1)
    $mainLayout.Controls.Add($chartGroup, 0, 2)
    $dashboardForm.Controls.Add($mainLayout)

    $dashboardForm.Add_Load({ Update-DashboardData })
    $dashboardForm.ShowDialog($parentForm)
}

# --- Report Customization Dialog ---
