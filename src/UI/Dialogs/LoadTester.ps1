function Show-LoadTester {
    param(
        [PSCustomObject]$RequestObject,
        [System.Windows.Forms.Form]$parentForm
    )

    Add-Type -AssemblyName System.Windows.Forms.DataVisualization -ErrorAction SilentlyContinue

    $testerForm = New-Object System.Windows.Forms.Form -Property @{
        Text = "Load Tester"
        Size = New-Object System.Drawing.Size(900, 600)
        StartPosition = "CenterParent"
    }

    $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'; ColumnCount = 2; RowCount = 2
        Padding = [System.Windows.Forms.Padding]::new(10)
    }
    $mainLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 300))) | Out-Null
    $mainLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 60))) | Out-Null

    # Settings Panel
    $settingsPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; FlowDirection = 'TopDown' }
    
    $lblUrl = New-Label -Text "URL:"
    $txtUrl = New-TextBox -Property @{ Width = 280; Text = if ($RequestObject) { $RequestObject.Url } else { "https://httpbin.org/get" } }
    
    $lblMethod = New-Label -Text "Method:"
    $comboMethod = New-Object System.Windows.Forms.ComboBox -Property @{ Width = 100; DropDownStyle = 'DropDownList' }
    $comboMethod.Items.AddRange(@("GET", "POST", "PUT", "DELETE", "PATCH"))
    $comboMethod.SelectedItem = if ($RequestObject -and $RequestObject.Method) { $RequestObject.Method } else { "GET" }

    $lblThreads = New-Label -Text "Concurrent Threads:"
    $numThreads = New-Object System.Windows.Forms.NumericUpDown -Property @{ Minimum = 1; Maximum = 100; Value = 10; Width = 100 }
    
    $lblDuration = New-Label -Text "Duration (Seconds):"
    $numDuration = New-Object System.Windows.Forms.NumericUpDown -Property @{ Minimum = 1; Maximum = 3600; Value = 5; Width = 100 }

    $lblStats = New-Label -Text "Stats:" -Property @{ Margin = [System.Windows.Forms.Padding]::new(0,20,0,0); Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold) }
    $lblReqCount = New-Label -Text "Requests: 0"
    $lblSuccess = New-Label -Text "Success: 0"
    $lblFailed = New-Label -Text "Failed: 0"
    $lblAvgLat = New-Label -Text "Avg Latency: 0ms"

    $settingsPanel.Controls.AddRange(@($lblUrl, $txtUrl, $lblMethod, $comboMethod, $lblThreads, $numThreads, $lblDuration, $numDuration, $lblStats, $lblReqCount, $lblSuccess, $lblFailed, $lblAvgLat))
    $mainLayout.Controls.Add($settingsPanel, 0, 0)

    # Chart Panel
    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart -Property @{ Dock = 'Fill' }
    $chartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
    $chart.ChartAreas.Add($chartArea)

    $seriesRps = New-Object System.Windows.Forms.DataVisualization.Charting.Series -Property @{
        Name = "Requests/Sec"
        ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
        BorderWidth = 2
        Color = [System.Drawing.Color]::DodgerBlue
    }
    $seriesLat = New-Object System.Windows.Forms.DataVisualization.Charting.Series -Property @{
        Name = "Latency (ms)"
        ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
        BorderWidth = 2
        Color = [System.Drawing.Color]::Orange
        YAxisType = [System.Windows.Forms.DataVisualization.Charting.AxisType]::Secondary
    }
    $chart.Series.Add($seriesRps)
    $chart.Series.Add($seriesLat)

    $chart.Legends.Add((New-Object System.Windows.Forms.DataVisualization.Charting.Legend))

    $mainLayout.Controls.Add($chart, 1, 0)

    # Buttons
    $btnPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; FlowDirection = 'RightToLeft' }
    $mainLayout.SetColumnSpan($btnPanel, 2)

    $btnStart = New-Button -Text "Start Test" -Style 'Primary' -Property @{ Width = 120 }
    $btnStop = New-Button -Text "Stop" -Style 'Danger' -Property @{ Width = 100; Enabled = $false }
    $btnPanel.Controls.AddRange(@($btnStart, $btnStop))
    $mainLayout.Controls.Add($btnPanel, 0, 1)

    $testerForm.Controls.Add($mainLayout)

    # Theme
    if ($script:Theme) {
        $testerForm.BackColor = $script:Theme.FormBackground
        $settingsPanel.BackColor = $script:Theme.GroupBackground
        $chart.BackColor = $script:Theme.GroupBackground
        $chartArea.BackColor = $script:Theme.GroupBackground
        $chartArea.AxisX.LabelStyle.ForeColor = $script:Theme.TextColor
        $chartArea.AxisY.LabelStyle.ForeColor = $script:Theme.TextColor
        $chartArea.AxisY2.LabelStyle.ForeColor = $script:Theme.TextColor
        $chart.Legends[0].BackColor = $script:Theme.GroupBackground
        $chart.Legends[0].ForeColor = $script:Theme.TextColor
        $txtUrl.BackColor = $script:Theme.TextBoxBackground
        $txtUrl.ForeColor = $script:Theme.TextColor
        $comboMethod.BackColor = $script:Theme.TextBoxBackground
        $comboMethod.ForeColor = $script:Theme.TextColor
        
        foreach ($ctrl in $settingsPanel.Controls) {
            if ($ctrl -is [System.Windows.Forms.Label]) { $ctrl.ForeColor = $script:Theme.TextColor }
        }
    }

    # Load Testing Engine Variables
    $script:loadTestRunspacePool = $null
    $script:loadTestJobs = @()
    $script:loadTestTimer = $null
    $script:loadTestIsRunning = $false
    $script:loadTestStartTime = $null

    # Thread-safe hashtable for stats
    $script:loadTestStats = [hashtable]::Synchronized(@{
        TotalRequests = 0
        Success = 0
        Failed = 0
        TotalLatency = 0
    })

    $btnStart.Add_Click({
        $btnStart.Enabled = $false
        $btnStop.Enabled = $true
        $script:loadTestIsRunning = $true
        
        $script:loadTestStats.TotalRequests = 0
        $script:loadTestStats.Success = 0
        $script:loadTestStats.Failed = 0
        $script:loadTestStats.TotalLatency = 0

        $seriesRps.Points.Clear()
        $seriesLat.Points.Clear()

        $threadCount = [int]$numThreads.Value
        $script:loadTestRunspacePool = [runspacefactory]::CreateRunspacePool(1, $threadCount)
        $script:loadTestRunspacePool.Open()

        $url = $txtUrl.Text
        $method = $comboMethod.SelectedItem
        $headers = if ($RequestObject -and $RequestObject.Headers) { $RequestObject.Headers } else { @{} }
        $body = if ($RequestObject -and $RequestObject.Body) { $RequestObject.Body } else { "" }
        $durationSeconds = [int]$numDuration.Value
        $script:loadTestStartTime = [DateTime]::Now

        $scriptBlock = {
            param($url, $method, $headers, $body, $duration, $startTime, $stats)
            $stopTime = $startTime.AddSeconds($duration)
            while ([DateTime]::Now -lt $stopTime) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    if ($method -in @('POST','PUT','PATCH') -and $body) {
                        Invoke-WebRequest -Uri $url -Method $method -Body $body -Headers $headers -UseBasicParsing -ErrorAction Stop | Out-Null
                    } else {
                        Invoke-WebRequest -Uri $url -Method $method -Headers $headers -UseBasicParsing -ErrorAction Stop | Out-Null
                    }
                    $sw.Stop()
                    $stats.Success++
                } catch {
                    $sw.Stop()
                    $stats.Failed++
                }
                $stats.TotalRequests++
                $stats.TotalLatency += $sw.ElapsedMilliseconds
            }
        }

        $script:loadTestJobs = @()
        for ($i = 0; $i -lt $threadCount; $i++) {
            $ps = [powershell]::Create().AddScript($scriptBlock).AddArgument($url).AddArgument($method).AddArgument($headers).AddArgument($body).AddArgument($durationSeconds).AddArgument($script:loadTestStartTime).AddArgument($script:loadTestStats)
            $ps.RunspacePool = $script:loadTestRunspacePool
            $script:loadTestJobs += [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
        }

        $script:loadTestTimer = New-Object System.Windows.Forms.Timer
        $script:loadTestTimer.Interval = 1000
        $script:loadTestTimer.Add_Tick({
            $lblReqCount.Text = "Requests: $($script:loadTestStats.TotalRequests)"
            $lblSuccess.Text = "Success: $($script:loadTestStats.Success)"
            $lblFailed.Text = "Failed: $($script:loadTestStats.Failed)"
            
            $reqCount = $script:loadTestStats.TotalRequests
            $avgLat = if ($reqCount -gt 0) { [math]::Round($script:loadTestStats.TotalLatency / $reqCount, 2) } else { 0 }
            $lblAvgLat.Text = "Avg Latency: $($avgLat)ms"

            $elapsedSeconds = ([DateTime]::Now - $script:loadTestStartTime).TotalSeconds
            $rps = if ($elapsedSeconds -gt 0) { [math]::Round($reqCount / $elapsedSeconds, 2) } else { 0 }

            $seriesRps.Points.AddY($rps) | Out-Null
            $seriesLat.Points.AddY($avgLat) | Out-Null
            $chart.Invalidate()

            # Check if done
            $allDone = $true
            foreach ($job in $script:loadTestJobs) {
                if ($job.Handle.IsCompleted -eq $false) { $allDone = $false }
            }

            if ($allDone -or ([DateTime]::Now -ge $script:loadTestStartTime.AddSeconds($durationSeconds))) {
                $btnStop.PerformClick()
            }
        })
        $script:loadTestTimer.Start()
    })

    $btnStop.Add_Click({
        $script:loadTestIsRunning = $false
        if ($script:loadTestTimer) { $script:loadTestTimer.Stop(); $script:loadTestTimer.Dispose() }
        foreach ($job in $script:loadTestJobs) {
            try { $job.PS.Stop() } catch {}
            try { $job.PS.Dispose() } catch {}
        }
        if ($script:loadTestRunspacePool) {
            try { $script:loadTestRunspacePool.Close(); $script:loadTestRunspacePool.Dispose() } catch {}
        }
        $btnStart.Enabled = $true
        $btnStop.Enabled = $false
    })

    $testerForm.Add_FormClosing({
        if ($script:loadTestIsRunning) {
            $btnStop.PerformClick()
        }
    })

    $testerForm.ShowDialog() | Out-Null
    $testerForm.Dispose()
}
