function Show-MonitorManager {
    param([System.Windows.Forms.Form]$parentForm)

    $monitorForm = New-Object System.Windows.Forms.Form -Property @{
        Text = "API Monitor Manager"
        Size = New-Object System.Drawing.Size(1280, 650)
        MinimumSize = New-Object System.Drawing.Size(1280, 500)
        StartPosition = "CenterParent"
    }
    
    $listMonitors = New-Object System.Windows.Forms.ListView -Property @{ Dock = 'Fill'; View = 'Details'; FullRowSelect = $true; GridLines = $true }
    $listMonitors.Columns.Add("Name", 150) | Out-Null
    $listMonitors.Columns.Add("URL", 250) | Out-Null
    $listMonitors.Columns.Add("Interval (s)", 80) | Out-Null
    $listMonitors.Columns.Add("Status", 80) | Out-Null
    $listMonitors.Columns.Add("Last Run", 120) | Out-Null

    function Refresh-List {
        $listMonitors.Items.Clear()
        foreach ($m in $script:monitors) {
            $item = New-Object System.Windows.Forms.ListViewItem($m.Name)
            $item.SubItems.Add($m.Request.Url) | Out-Null
            $item.SubItems.Add($m.IntervalSeconds) | Out-Null
            $item.SubItems.Add($m.Status) | Out-Null
            $lastRun = if ($m.LastRun) { [DateTime]$m.LastRun } else { "Never" }
            $item.SubItems.Add($lastRun.ToString()) | Out-Null
            $item.Tag = $m
            $listMonitors.Items.Add($item) | Out-Null
        }
    }
    Refresh-List

    $panelBtn = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Bottom'; AutoSize = $true; ColumnCount = 3; Padding = [System.Windows.Forms.Padding]::new(0, 5, 0, 5) }
    $panelBtn.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null
    $panelBtn.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $panelBtn.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null
    
    $btnAdd = New-Button -Text "Add Monitor..." -Property @{ Width = 130; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        $newMonitor = @{
            Id = [Guid]::NewGuid().ToString()
            Name = "New Monitor"
            Status = "Stopped"
            IntervalSeconds = 60
            Request = @{ Method="GET"; Url="http://"; Headers=""; Body=""; BodyType="multipart/form-data"; RequestTimeoutSeconds=30; Authentication = @{ Type = "No Auth" } }
            Alerts = @{ OnFailure=$true; OnSlow=$false; ThresholdMs=1000; SendEmail=$false; EmailTo="" }
            AnalyticsUrl = ""
            LastRun = $null
        }
        if ((Show-MonitorEditor -Monitor $newMonitor) -eq [System.Windows.Forms.DialogResult]::OK) {
            $script:monitors += $newMonitor
            Save-Monitors
            Refresh-List
        }
    }

    $btnEdit = New-Button -Text "Edit" -Property @{ Width = 100; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if ($listMonitors.SelectedItems.Count -gt 0) {
            $m = $listMonitors.SelectedItems[0].Tag
            # Deep clone the monitor object to prevent auto-saving on cancel
            $monitorToEdit = $m | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            if ((Show-MonitorEditor -Monitor $monitorToEdit) -eq [System.Windows.Forms.DialogResult]::OK) {
                # Find the original monitor by its ID and replace it with the edited version
                $originalMonitorIndex = -1
                for ($i = 0; $i -lt $script:monitors.Count; $i++) {
                    if ($script:monitors[$i].Id -eq $m.Id) {
                        $originalMonitorIndex = $i
                        break
                    }
                }
                if ($originalMonitorIndex -ne -1) { $script:monitors[$originalMonitorIndex] = $monitorToEdit }
                Save-Monitors # Save the entire updated array
                Refresh-List
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please select a monitor to edit.", "Selection Required", "OK", "Warning")
        }
    }

    $btnToggle = New-Button -Text "Start/Stop" -Property @{ Width = 110; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if ($listMonitors.SelectedItems.Count -gt 0) {
            $m = $listMonitors.SelectedItems[0].Tag
            if ($m.Status -eq "Running") { $m.Status = "Stopped" } else { $m.Status = "Running"; $m.LastRun = $null }
            Save-Monitors
            Refresh-List
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please select a monitor to start or stop.", "Selection Required", "OK", "Warning")
        }
    }

    $btnDelete = New-Button -Text "Delete" -Property @{ Width = 100; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if ($listMonitors.SelectedItems.Count -gt 0) {
            $m = $listMonitors.SelectedItems[0].Tag
            if ([System.Windows.Forms.MessageBox]::Show("Are you sure you want to delete monitor '$($m.Name)'?", "Confirm Delete", "YesNo", "Warning") -eq "Yes") {
                $script:monitors = $script:monitors | Where-Object { $_.Id -ne $m.Id }
                Save-Monitors
                Refresh-List
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please select a monitor to delete.", "Selection Required", "OK", "Warning")
        }
    }

    $btnOpenLog = New-Button -Text "Open Log" -Property @{ Width = 180; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if (Test-Path $monitorLogFilePath) {
            try {
                Start-Process $monitorLogFilePath
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to open log file: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Log file not found yet.", "Info", "OK", "Information")
        }
    }

    $btnCharts = New-Button -Text "Visualize" -Property @{ Width = 110; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        Show-MonitorChartWindow -parentForm $monitorForm
    }

    $btnEmailConfig = New-Button -Text "Email Config" -Property @{ Width = 130; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        Show-MonitorEmailSettings -parentForm $monitorForm
    }

    $btnClearLog = New-Button -Text "Clear Log" -Property @{ Width = 180; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if ([System.Windows.Forms.MessageBox]::Show("Clear the monitor log file?", "Confirm", "YesNo", "Warning") -eq "Yes") {
            Clear-Content $monitorLogFilePath -ErrorAction SilentlyContinue
            [System.Windows.Forms.MessageBox]::Show("Log cleared.", "Info", "OK", "Information")
        }
    }

    $btnArchiveLog = New-Button -Text "Archive Log" -Property @{ Width = 120; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if (Test-Path $monitorLogFilePath) {
            $archiveName = "$monitorLogFilePath.$((Get-Date).ToString('yyyyMMdd-HHmmss')).csv"
            Rename-Item $monitorLogFilePath $archiveName
            [System.Windows.Forms.MessageBox]::Show("Log archived to:`n$archiveName", "Info", "OK", "Information")
        }
    }

    $buttonsFlow = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ AutoSize = $true; FlowDirection = 'LeftToRight'; WrapContents = $false; Margin = [System.Windows.Forms.Padding]::new(0); Padding = [System.Windows.Forms.Padding]::new(5,0,5,0) }
    $buttonsFlow.Controls.AddRange(@($btnCharts, $btnOpenLog, $btnAdd, $btnEdit, $btnToggle, $btnDelete, $btnEmailConfig, $btnClearLog, $btnArchiveLog))
    $panelBtn.Controls.Add($buttonsFlow, 1, 0)
    $monitorForm.Controls.AddRange(@($listMonitors, $panelBtn))
    $monitorForm.ShowDialog($parentForm)
}

# --- JWT Tool Window ---
