Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:Theme = @{
    FormBackground  = [System.Drawing.ColorTranslator]::FromHtml('#ffffff')
    GroupBackground = [System.Drawing.ColorTranslator]::FromHtml('#f8f9fa')
    PrimaryButton   = [System.Drawing.ColorTranslator]::FromHtml('#0078d4')
    TextColor       = [System.Drawing.ColorTranslator]::FromHtml('#212529')
}
$script:AppVersion = '2.0.0'
$script:AppGitHubRepo = 'imumeshk/API-Tester'

function New-Label {
    param ($Text, $Property)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Text
    if ($Property) { foreach ($k in $Property.Keys) { $lbl.$k = $Property.$k } }
    return $lbl
}

function New-Button {
    param ($Text, $Property, $OnClick, $Style)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text
    if ($Property) { foreach ($k in $Property.Keys) { $btn.$k = $Property.$k } }
    if ($OnClick) { $btn.Add_Click($OnClick) }
    return $btn
}

# The refactored About dialog
function Show-AboutDialog {
    $aboutForm = New-Object System.Windows.Forms.Form -Property @{
        Text            = 'About PowerShell API Tester'
        Size            = [System.Drawing.Size]::new(520, 520)
        StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterScreen
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        MaximizeBox     = $false
        MinimizeBox     = $false
        BackColor       = $script:Theme.FormBackground
    }

    $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        RowCount = 5
        BackColor = $script:Theme.FormBackground
    }
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 2))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    # Header
    $headerPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 2
        RowCount = 1
        BackColor = $script:Theme.PrimaryButton
        AutoSize = $true
        Padding = [System.Windows.Forms.Padding]::new(15, 15, 15, 15)
        Margin = [System.Windows.Forms.Padding]::new(0)
    }
    $headerPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $headerPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $picIcon = New-Object System.Windows.Forms.PictureBox -Property @{
        Image    = [System.Drawing.SystemIcons]::Application.ToBitmap()
        Size     = [System.Drawing.Size]::new(48, 48)
        SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
        Margin   = [System.Windows.Forms.Padding]::new(0, 0, 15, 0)
    }

    $headerTextFlow = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
        Dock = 'Fill'
        FlowDirection = 'TopDown'
        AutoSize = $true
        WrapContents = $false
        Margin = [System.Windows.Forms.Padding]::new(0)
    }
    $headerTextFlow.Controls.Add((New-Label -Text 'PowerShell API Tester' -Property @{ Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold); ForeColor = [System.Drawing.Color]::White; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0) }))
    $headerTextFlow.Controls.Add((New-Label -Text 'Feature-rich REST / gRPC API testing tool for Windows' -Property @{ Font = New-Object System.Drawing.Font('Segoe UI', 9); ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#cfe8fc'); AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 5, 0, 0) }))

    $headerPanel.Controls.Add($picIcon, 0, 0)
    $headerPanel.Controls.Add($headerTextFlow, 1, 0)

    # Details
    $detailsPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 2
        AutoSize = $true
        Padding = [System.Windows.Forms.Padding]::new(20, 20, 20, 20)
        Margin = [System.Windows.Forms.Padding]::new(0)
        BackColor = $script:Theme.GroupBackground
    }
    $detailsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $detailsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $boldFont   = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $normalFont = New-Object System.Drawing.Font('Segoe UI', 9)
    $grayColor  = [System.Drawing.ColorTranslator]::FromHtml('#6c757d')

    $infoRows = @(
        @{ Label = 'Version:';  Value = 'v' + $script:AppVersion },
        @{ Label = 'Author:';   Value = 'Umesh Kashyap' },
        @{ Label = 'License:';  Value = 'MIT' },
        @{ Label = 'GitHub:';   Value = 'github.com/' + $script:AppGitHubRepo; IsLink = $true }
    )

    $row = 0
    foreach ($r in $infoRows) {
        $detailsPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
        $lblKey = New-Label -Text $r.Label -Property @{ Font = $boldFont; ForeColor = $grayColor; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 0, 15, 10) }
        $detailsPanel.Controls.Add($lblKey, 0, $row)

        if ($r.IsLink) {
            $lnk = New-Object System.Windows.Forms.LinkLabel -Property @{ Text = $r.Value; Font = $normalFont; AutoSize = $true; LinkColor = [System.Drawing.ColorTranslator]::FromHtml('#0078d4'); Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
            $detailsPanel.Controls.Add($lnk, 1, $row)
        } else {
            $detailsPanel.Controls.Add((New-Label -Text $r.Value -Property @{ Font = $normalFont; AutoSize = $true; ForeColor = $script:Theme.TextColor; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }), 1, $row)
        }
        $row++
    }
    
    $detailsPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $lblDesc = New-Label -Text 'A feature-rich API testing tool built entirely in PowerShell & WinForms.' -Property @{ Font = $normalFont; ForeColor = $grayColor; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 10, 0, 0) }
    $detailsPanel.Controls.Add($lblDesc, 0, $row)
    $detailsPanel.SetColumnSpan($lblDesc, 2)

    # Separator
    $sep = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Fill'; Margin = [System.Windows.Forms.Padding]::new(0); BackColor = [System.Drawing.ColorTranslator]::FromHtml('#dee2e6') }

    # Update Panel
    $updatePanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        AutoSize = $true
        Padding = [System.Windows.Forms.Padding]::new(20, 15, 20, 15)
        Margin = [System.Windows.Forms.Padding]::new(0)
    }
    $updatePanel.Controls.Add((New-Label -Text 'Software Update' -Property @{ Font = $boldFont; ForeColor = $script:Theme.TextColor; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 5) }), 0, 0)
    $updatePanel.Controls.Add((New-Label -Text 'Click ''Check for Updates'' to check.' -Property @{ Font = $normalFont; ForeColor = $grayColor; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 15) }), 0, 1)

    $btnCheck = New-Button -Text 'Check for Updates' -Property @{ AutoSize = $true; Height = 32; Margin = [System.Windows.Forms.Padding]::new(0) }
    $updatePanel.Controls.Add($btnCheck, 0, 2)

    # Footer
    $footerFlow = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
        Dock = 'Fill'
        FlowDirection = 'RightToLeft'
        AutoSize = $true
        Padding = [System.Windows.Forms.Padding]::new(10)
        Margin = [System.Windows.Forms.Padding]::new(0)
        BackColor = $script:Theme.GroupBackground
    }
    $btnClose = New-Button -Text 'Close' -Property @{ AutoSize = $true; Height = 32; Margin = [System.Windows.Forms.Padding]::new(0) } -OnClick { $aboutForm.Close() }
    $footerFlow.Controls.Add($btnClose)

    $mainLayout.Controls.Add($headerPanel, 0, 0)
    $mainLayout.Controls.Add($detailsPanel, 0, 1)
    $mainLayout.Controls.Add($sep, 0, 2)
    $mainLayout.Controls.Add($updatePanel, 0, 3)
    $mainLayout.Controls.Add($footerFlow, 0, 4)

    $aboutForm.Controls.Add($mainLayout)

    # $aboutForm.ShowDialog() | Out-Null
    return $aboutForm
}
$frm = Show-AboutDialog
$frm.ShowDialog()
