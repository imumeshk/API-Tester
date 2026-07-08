function Show-KeyboardShortcuts {
    param([System.Windows.Forms.Form]$parentForm)

    $kbForm = New-Object System.Windows.Forms.Form -Property @{
        Text            = "Keyboard Shortcuts"
        Size            = New-Object System.Drawing.Size(420, 300)
        StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterParent
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        MaximizeBox     = $false
        MinimizeBox     = $false
        BackColor       = $script:Theme.FormBackground
        Padding         = [System.Windows.Forms.Padding]::new(15)
    }

    $layout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock        = 'Fill'
        ColumnCount = 2
        AutoSize    = $true
        Padding     = [System.Windows.Forms.Padding]::new(5)
    }
    $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 45))) | Out-Null
    $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 55))) | Out-Null

    $shortcuts = @(
        @{ Key = "Ctrl + Enter";          Action = "Send Request"              },
        @{ Key = "Ctrl + F";              Action = "Find in Response"          },
        @{ Key = "Ctrl + Shift + Enter";  Action = "Run Console Command"       },
        @{ Key = "Alt + F4";              Action = "Close Application"         }
    )

    $headerFont  = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $normalFont  = New-Object System.Drawing.Font("Segoe UI", 9)
    $codeFont    = New-Object System.Drawing.Font("Courier New", 9)
    $grayColor   = [System.Drawing.ColorTranslator]::FromHtml("#6c757d")

    $lblKeyHeader    = New-Label -Text "Shortcut" -Property @{ Font = $headerFont; AutoSize = $true; ForeColor = $grayColor }
    $lblActionHeader = New-Label -Text "Action"   -Property @{ Font = $headerFont; AutoSize = $true; ForeColor = $grayColor }
    $layout.Controls.Add($lblKeyHeader,    0, 0)
    $layout.Controls.Add($lblActionHeader, 1, 0)

    $row = 1
    foreach ($s in $shortcuts) {
        $lblKey    = New-Label -Text $s.Key    -Property @{ Font = $codeFont;   AutoSize = $true; ForeColor = $script:Theme.TextColor }
        $lblAction = New-Label -Text $s.Action -Property @{ Font = $normalFont; AutoSize = $true; ForeColor = $script:Theme.TextColor }
        $layout.Controls.Add($lblKey,    0, $row)
        $layout.Controls.Add($lblAction, 1, $row)
        $row++
    }

    $btnClose = New-Button -Text "Close" -Style 'Secondary' -OnClick { $kbForm.Close() } -Property @{
        Dock = 'Bottom'; Height = 32; Margin = [System.Windows.Forms.Padding]::new(0, 10, 0, 0)
    }

    $kbForm.Controls.AddRange(@($layout, $btnClose))
    $kbForm.ShowDialog($parentForm) | Out-Null
    $kbForm.Dispose()
}

# Shows a styled About dialog with version info, author, GitHub link, and in-app updater.
function Show-AboutDialog {
    param([System.Windows.Forms.Form]$parentForm)

    $aboutForm = New-Object System.Windows.Forms.Form -Property @{
        Text            = "About PowerShell API Tester"
        Size            = New-Object System.Drawing.Size(480, 520)
        StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterParent
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        MaximizeBox     = $false
        MinimizeBox     = $false
        BackColor       = $script:Theme.FormBackground
        Padding         = [System.Windows.Forms.Padding]::new(20)
    }

    # --- Header panel (icon + app name) ---
    $headerPanel = New-Object System.Windows.Forms.Panel -Property @{
        Dock      = 'Top'
        Height    = 80
        BackColor = $script:Theme.PrimaryButton
        Padding   = [System.Windows.Forms.Padding]::new(15, 10, 15, 10)
    }

    $picIcon = New-Object System.Windows.Forms.PictureBox -Property @{
        Image    = [System.Drawing.SystemIcons]::Application.ToBitmap()
        Size     = New-Object System.Drawing.Size(48, 48)
        Location = New-Object System.Drawing.Point(15, 16)
        SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
    }

    $lblAppName = New-Label -Text "PowerShell API Tester" -Property @{
        Font      = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
        ForeColor = [System.Drawing.Color]::White
        Location  = New-Object System.Drawing.Point(73, 12)
        Size      = New-Object System.Drawing.Size(370, 30)
    }

    $lblTagline = New-Label -Text "Feature-rich REST / gRPC API testing tool for Windows" -Property @{
        Font      = New-Object System.Drawing.Font("Segoe UI", 8)
        ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#cfe8fc")
        Location  = New-Object System.Drawing.Point(74, 44)
        Size      = New-Object System.Drawing.Size(370, 20)
    }

    $headerPanel.Controls.AddRange(@($picIcon, $lblAppName, $lblTagline))

    # --- Details panel ---
    $detailsPanel = New-Object System.Windows.Forms.Panel -Property @{
        Dock      = 'Top'
        Height    = 180
        BackColor = $script:Theme.GroupBackground
        Padding   = [System.Windows.Forms.Padding]::new(20, 15, 20, 10)
    }

    $boldFont   = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $normalFont = New-Object System.Drawing.Font("Segoe UI", 9)
    $grayColor  = [System.Drawing.ColorTranslator]::FromHtml("#6c757d")
    $blueColor  = [System.Drawing.ColorTranslator]::FromHtml("#0078d4")

    $infoRows = @(
        @{ Label = "Version:";  Value = "v$($script:AppVersion)";  IsLink = $false },
        @{ Label = "Author:";   Value = "Umesh Kashyap";            IsLink = $false },
        @{ Label = "License:";  Value = "MIT";                      IsLink = $false },
        @{ Label = "GitHub:";   Value = "github.com/$($script:AppGitHubRepo)"; IsLink = $true }
    )

    $yPos = 15
    foreach ($row in $infoRows) {
        $lblKey = New-Label -Text $row.Label -Property @{
            Font      = $boldFont
            ForeColor = $grayColor
            Location  = New-Object System.Drawing.Point(0, $yPos)
            Size      = New-Object System.Drawing.Size(80, 22)
        }

        if ($row.IsLink) {
            $lnk = New-Object System.Windows.Forms.LinkLabel -Property @{
                Text      = $row.Value
                Font      = $normalFont
                Location  = New-Object System.Drawing.Point(90, $yPos)
                Size      = New-Object System.Drawing.Size(310, 22)
                LinkColor = $blueColor
            }
            $repoUrl = "https://github.com/$($script:AppGitHubRepo)"
            $lnk.Add_LinkClicked({
                try { [System.Diagnostics.Process]::Start($repoUrl) | Out-Null } catch {}
            })
            $detailsPanel.Controls.Add($lnk)
        } else {
            $lblVal = New-Label -Text $row.Value -Property @{
                Font      = $normalFont
                ForeColor = $script:Theme.TextColor
                Location  = New-Object System.Drawing.Point(90, $yPos)
                Size      = New-Object System.Drawing.Size(310, 22)
            }
            $detailsPanel.Controls.Add($lblVal)
        }

        $detailsPanel.Controls.Add($lblKey)
        $yPos += 30
    }

    # Description line
    $lblDesc = New-Label -Text "A feature-rich API testing tool built entirely in PowerShell & WinForms." -Property @{
        Font      = $normalFont
        ForeColor = $grayColor
        Location  = New-Object System.Drawing.Point(0, $yPos + 5)
        Size      = New-Object System.Drawing.Size(400, 40)
        AutoSize  = $false
    }
    $detailsPanel.Controls.Add($lblDesc)

    # --- Separator ---
    $sep = New-Object System.Windows.Forms.Panel -Property @{
        Dock      = 'Top'
        Height    = 2
        BackColor = [System.Drawing.ColorTranslator]::FromHtml("#dee2e6")
    }

    # --- Update panel ---
    $updatePanel = New-Object System.Windows.Forms.Panel -Property @{
        Dock      = 'Top'
        Height    = 110
        BackColor = $script:Theme.FormBackground
        Padding   = [System.Windows.Forms.Padding]::new(20, 10, 20, 10)
    }

    $lblUpdateTitle = New-Label -Text "Software Update" -Property @{
        Font      = $boldFont
        ForeColor = $script:Theme.TextColor
        Location  = New-Object System.Drawing.Point(0, 10)
        AutoSize  = $true
    }

    $lblUpdateStatus = New-Label -Text "Click 'Check for Updates' to check." -Property @{
        Font      = $normalFont
        ForeColor = $grayColor
        Location  = New-Object System.Drawing.Point(0, 35)
        Size      = New-Object System.Drawing.Size(420, 20)
        AutoSize  = $false
    }

    $btnDownload = New-Button -Text "Download & Update" -Style 'Primary' -OnClick {
        $release = $btnDownload.Tag
        if ($release) {
            Invoke-DownloadUpdate -Release $release -StatusLabel $lblUpdateStatus
        }
    } -Property @{
        Location = New-Object System.Drawing.Point(0, 60)
        Size     = New-Object System.Drawing.Size(160, 32)
        Visible  = $false
    }
    $btnDownload.Name = "btnDownload"

    $btnCheck = New-Button -Text "Check for Updates" -Style 'Secondary' -OnClick {
        Invoke-UpdateCheck -StatusLabel $lblUpdateStatus -DownloadButton $btnDownload -ParentForm $aboutForm
    } -Property @{
        Location = New-Object System.Drawing.Point(170, 60)
        Size     = New-Object System.Drawing.Size(150, 32)
    }

    $updatePanel.Controls.AddRange(@($lblUpdateTitle, $lblUpdateStatus, $btnDownload, $btnCheck))

    # --- Footer (Close button) ---
    $footerPanel = New-Object System.Windows.Forms.Panel -Property @{
        Dock      = 'Bottom'
        Height    = 50
        BackColor = $script:Theme.FormBackground
        Padding   = [System.Windows.Forms.Padding]::new(0, 10, 0, 0)
    }

    $btnClose = New-Button -Text "Close" -Style 'Secondary' -OnClick { $aboutForm.Close() } -Property @{
        Dock   = 'Right'
        Width  = 80
        Height = 32
    }
    $footerPanel.Controls.Add($btnClose)

    # Add controls in reverse dock order (Bottom ? Top)
    $aboutForm.Controls.AddRange(@($footerPanel, $updatePanel, $sep, $detailsPanel, $headerPanel))

    $aboutForm.ShowDialog($parentForm) | Out-Null
    $aboutForm.Dispose()
}

#endregion About & Update Functions

# The main function that constructs and displays the primary application window.
