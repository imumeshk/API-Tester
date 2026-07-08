function Show-LogViewer {
    param($parentForm)    
    $logForm = New-Object System.Windows.Forms.Form -Property @{ Text="Log Viewer"; Size=New-Object System.Drawing.Size(1000, 600); StartPosition="CenterParent" }
    $grid = New-Object System.Windows.Forms.DataGridView -Property @{ Dock="Fill"; ReadOnly=$true; AllowUserToAddRows=$false; SelectionMode="FullRowSelect"; AutoSizeColumnsMode="Fill"; RowHeadersVisible=$false } #FIX: Corrected DataGridView creation
    
    try {
        # Read with FileShare to avoid locking issues if logging happens simultaneously
        $fs = New-Object System.IO.FileStream($logFilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs)
        $content = $sr.ReadToEnd()
        $sr.Close(); $fs.Close()
        
        $data = $content | ConvertFrom-Csv
        $table = New-Object System.Data.DataTable
        $table.Columns.Add("Timestamp", [DateTime]); $table.Columns.Add("Level"); $table.Columns.Add("Message")
        
        foreach ($row in $data) { 
            $dt = [DateTime]::MinValue
            if ([DateTime]::TryParse($row.Timestamp, [ref]$dt)) {
                $table.Rows.Add($dt, $row.Level, $row.Message) | Out-Null 
            }
        }
        $grid.DataSource = $table
        
        if ($grid.Columns["Timestamp"]) { 
            $grid.Columns["Timestamp"].FillWeight = 20 
            $grid.Columns["Timestamp"].DefaultCellStyle.Format = "yyyy-MM-dd HH:mm:ss"
        }
        if ($grid.Columns["Level"]) { $grid.Columns["Level"].FillWeight = 10 }
        if ($grid.Columns["Message"]) { $grid.Columns["Message"].FillWeight = 70 }
    } catch { [System.Windows.Forms.MessageBox]::Show("Failed to load logs: $($_.Exception.Message)", "Error", "OK", "Error") }
    
    $panel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock="Top"; AutoSize=$true; Padding=[System.Windows.Forms.Padding]::new(5) }
    
    $lblSearch = New-Label -Text "Search:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,5,0,0) }
    $txtFilter = New-TextBox -Property @{ Width=200 }
    
    $lblFrom = New-Label -Text "From:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(10,5,0,0) }
    $dtpFrom = New-Object System.Windows.Forms.DateTimePicker -Property @{ Format="Short"; Width=100; ShowCheckBox=$true; Checked=$false }
    $lblTo = New-Label -Text "To:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(10,5,0,0) }
    $dtpTo = New-Object System.Windows.Forms.DateTimePicker -Property @{ Format="Short"; Width=100; ShowCheckBox=$true; Checked=$false }

    $updateFilter = { 
        $dv = $grid.DataSource.DefaultView
        $parts = @()
        
        # Text Filter #FIX: Corrected text filter
        $f = $txtFilter.Text
        if ($f) { $parts += "(Message LIKE '%$f%' OR Level LIKE '%$f%')" }
        
        # Date Filter
        if ($dtpFrom.Checked) {
            $d = $dtpFrom.Value.Date.ToString("MM/dd/yyyy")
            $parts += "Timestamp >= #$d#"
        }
        if ($dtpTo.Checked) {
            # End of day
            $d = $dtpTo.Value.Date.AddDays(1).AddTicks(-1).ToString("MM/dd/yyyy HH:mm:ss")
            $parts += "Timestamp <= #$d#"
        }
        
        if ($parts.Count -gt 0) { $dv.RowFilter = $parts -join " AND " } else { $dv.RowFilter = "" }
    }

    $txtFilter.Add_TextChanged($updateFilter)
    $dtpFrom.Add_ValueChanged($updateFilter)
    $dtpTo.Add_ValueChanged($updateFilter)

    $btnExport = New-Button -Text "Export" -Property @{ Width=100; Height=30; Margin=[System.Windows.Forms.Padding]::new(10,5,0,0) } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = "CSV Files (*.csv)|*.csv"
        $sfd.FileName = "filtered_logs.csv"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $dv = $grid.DataSource.DefaultView
                $exportData = @()
                foreach ($rowView in $dv) {
                    $exportData += [PSCustomObject]@{
                        Timestamp = $rowView["Timestamp"].ToString("yyyy-MM-dd HH:mm:ss")
                        Level     = $rowView["Level"]
                        Message   = $rowView["Message"]
                    }
                }
                $exportData | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
                [System.Windows.Forms.MessageBox]::Show("Export successful.", "Info", "OK", "Information")
            } catch { [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error") }
        }
    }

    $panel.Controls.AddRange(@($lblSearch, $txtFilter, $lblFrom, $dtpFrom, $lblTo, $dtpTo, $btnExport))
    $logForm.Controls.AddRange(@($grid, $panel))
    $logForm.ShowDialog($parentForm)
}

# Displays the main settings window, allowing users to configure application behavior.
