function Show-CookieJar {
    param($parentForm)
    $form = New-Object System.Windows.Forms.Form -Property @{ Text="Cookie Jar"; Size=New-Object System.Drawing.Size(600, 400); StartPosition="CenterParent"; BackColor=$script:Theme.FormBackground }
    
    $grid = New-Object System.Windows.Forms.DataGridView -Property @{ Dock='Fill'; ReadOnly=$true; AllowUserToAddRows=$false; RowHeadersVisible=$false; AutoSizeColumnsMode='Fill'; BackgroundColor='White' }
    $grid.Columns.Add("Domain", "Domain") | Out-Null
    $grid.Columns.Add("Name", "Name") | Out-Null
    $grid.Columns.Add("Value", "Value") | Out-Null
    $grid.Columns.Add("Path", "Path") | Out-Null
    $grid.Columns.Add("Expires", "Expires") | Out-Null

    function Refresh-Grid {
        $grid.Rows.Clear()
        if ($script:cookieJar) {
            foreach ($cookie in $script:cookieJar) {
                $grid.Rows.Add($cookie.Domain, $cookie.Name, $cookie.Value, $cookie.Path, $cookie.Expires) | Out-Null
            }
        }
    }
    Refresh-Grid

    $panelBtn = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Bottom'; AutoSize=$true; FlowDirection='RightToLeft'; Padding=[System.Windows.Forms.Padding]::new(5) }
    $btnClose = New-Button -Text "Close" -Style 'Secondary' -Property @{ Width=80; Height=30 } -OnClick { $form.Close() }
    $btnClear = New-Button -Text "Clear All" -Style 'Danger' -Property @{ Width=100; Height=30; Margin=[System.Windows.Forms.Padding]::new(0,0,5,0) } -OnClick {
        if ($script:cookieJar) { $script:cookieJar.Clear() }
        Refresh-Grid
    }
    $panelBtn.Controls.AddRange(@($btnClose, $btnClear))

    $btnExport = New-Button -Text "Export..." -Style 'Secondary' -Property @{ Width=80; Height=30; Margin=[System.Windows.Forms.Padding]::new(0,0,5,0) } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog -Property @{ Filter="JSON Files (*.json)|*.json"; FileName="cookies.json" }
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $script:cookieJar | ConvertTo-Json -Depth 5 | Set-Content -Path $sfd.FileName
                [System.Windows.Forms.MessageBox]::Show("Cookies exported successfully.", "Success", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to export cookies: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    }

    $btnImport = New-Button -Text "Import..." -Style 'Secondary' -Property @{ Width=80; Height=30; Margin=[System.Windows.Forms.Padding]::new(0,0,5,0) } -OnClick {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter="JSON Files (*.json)|*.json" }
        if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $importedCookies = Get-Content -Path $ofd.FileName -Raw | ConvertFrom-Json
                if ($importedCookies) {
                    if ($importedCookies -isnot [array]) { $importedCookies = @($importedCookies) }
                    $script:cookieJar.Clear()
                    foreach ($c in $importedCookies) {
                        try {
                            $cookie = New-Object System.Net.Cookie
                            $cookie.Name = $c.Name
                            $cookie.Value = $c.Value
                            $cookie.Domain = $c.Domain
                            $cookie.Path = if ($c.Path) { $c.Path } else { "/" }
                            if ($c.Expires) { 
                                if ($c.Expires -is [string]) { $cookie.Expires = [DateTime]::Parse($c.Expires) }
                                elseif ($c.Expires -is [DateTime]) { $cookie.Expires = $c.Expires }
                            }
                            $cookie.HttpOnly = if ($c.HttpOnly) { $c.HttpOnly } else { $false }
                            $cookie.Secure = if ($c.Secure) { $c.Secure } else { $false }
                            [void]$script:cookieJar.Add($cookie)
                        } catch {}
                    }
                    Refresh-Grid
                    [System.Windows.Forms.MessageBox]::Show("Cookies imported successfully.", "Success", "OK", "Information")
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to import cookies: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    }

    $panelBtn.Controls.AddRange(@($btnClose, $btnClear, $btnExport, $btnImport))

    $form.Controls.AddRange(@($grid, $panelBtn))
    $form.ShowDialog($parentForm)
}

#region About & Update Functions

# Checks GitHub Releases API for a newer version.
# Populates the $statusLabel and optionally shows the $downloadButton.
