function Show-MonitorChartWindow {
    param($parentForm)
    
    if (-not (Test-Path $monitorLogFilePath)) {
        [System.Windows.Forms.MessageBox]::Show("No monitor log file found.", "Info", "OK", "Information")
        return
    }

    try {
        $chartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Charting assemblies not found. Please ensure .NET Framework 4.x is installed.", "Error", "OK", "Error")
        return
    }

    $form = New-Object System.Windows.Forms.Form -Property @{ Text="Monitor Analytics"; Size=New-Object System.Drawing.Size(1000, 700); StartPosition="CenterParent" }
    
    # Load Data
    $data = Import-Csv $monitorLogFilePath | Select-Object @{N='Time';E={[DateTime]$_.Timestamp}}, MonitorName, @{N='Ms';E={[int]$_.TimeMs}}
    $monitors = $data | Select-Object -ExpandProperty MonitorName -Unique

    # Controls
    $panelTop = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Top'; AutoSize=$true; Padding=[System.Windows.Forms.Padding]::new(5) }
    $lblSel = New-Label -Text "Select Monitor:" -Property @{ AutoSize=$true; TextAlign='MiddleLeft'; Margin=[System.Windows.Forms.Padding]::new(0,6,0,0) }
    $comboMon = New-Object System.Windows.Forms.ComboBox -Property @{ Width=200; DropDownStyle='DropDownList'; Margin=[System.Windows.Forms.Padding]::new(3,3,10,3) }
    $comboMon.Items.AddRange($monitors)
    
    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart -Property @{ Dock='Fill' }
    $chartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
    $chart.ChartAreas.Add($chartArea)
    $series = New-Object System.Windows.Forms.DataVisualization.Charting.Series
    $series.ChartType = $chartType
    $series.BorderWidth = 2
    $chart.Series.Add($series)
    $title = New-Object System.Windows.Forms.DataVisualization.Charting.Title
    $title.Text = "Response Time (ms)"
    $chart.Titles.Add($title)

    $comboMon.Add_SelectedIndexChanged({
        $selected = $comboMon.SelectedItem
        $subset = $data | Where-Object { $_.MonitorName -eq $selected }
        $series.Points.Clear()
        foreach ($row in $subset) {
            $series.Points.AddXY($row.Time.ToString("HH:mm:ss"), $row.Ms) | Out-Null
        }
        $title.Text = "$selected - Response Time (ms)"
    })

    if ($comboMon.Items.Count -gt 0) { $comboMon.SelectedIndex = 0 }

    $btnSaveImage = New-Button -Text "Save Image" -Property @{ AutoSize=$true } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = "PNG Image|*.png|JPEG Image|*.jpg|Bitmap Image|*.bmp"
        $sfd.Title = "Save Chart Image"
        $sfd.FileName = "MonitorChart.png"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Png
                if ($sfd.FileName.EndsWith(".jpg")) { $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Jpeg }
                elseif ($sfd.FileName.EndsWith(".bmp")) { $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Bmp }
                
                $chart.SaveImage($sfd.FileName, $format)
                [System.Windows.Forms.MessageBox]::Show("Chart saved successfully.", "Success", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to save chart: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    }

    $panelTop.Controls.AddRange(@($lblSel, $comboMon, $btnSaveImage))
    $form.Controls.AddRange(@($chart, $panelTop))
    $form.ShowDialog($parentForm)
}

# --- WebSocket Client Window ---
