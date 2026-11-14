function Show-KeyboardShortcutsFallback {
    param([System.Windows.Forms.Form]$parentForm)

    $kbForm = New-Object System.Windows.Forms.Form -Property @{
        Text            = "Keyboard Shortcuts"
        Size            = [System.Drawing.Size]::new(420, 300)
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

# Shows the Keyboard Shortcuts reference (XAML dialog, WinForms fallback if WPF is unavailable).
function Show-KeyboardShortcuts {
    param($parentForm)

    try {
        $shortcuts = @(
            @{ Key = "Ctrl + Enter";          Action = "Send Request"        },
            @{ Key = "Ctrl + F";              Action = "Find in Response"    },
            @{ Key = "Ctrl + Shift + Enter";  Action = "Run Console Command" },
            @{ Key = "Alt + F4";              Action = "Close Application"   }
        )
        $rowsXaml = ($shortcuts | ForEach-Object {
            $keyText = [System.Security.SecurityElement]::Escape($_.Key)
            $actionText = [System.Security.SecurityElement]::Escape($_.Action)
            "<Grid Margin=`"0,5,0,0`"><Grid.ColumnDefinitions><ColumnDefinition Width=`"170`"/><ColumnDefinition Width=`"*`"/></Grid.ColumnDefinitions><Border Background=`"{StaticResource Soft}`" CornerRadius=`"4`" Padding=`"8,3`" HorizontalAlignment=`"Left`"><TextBlock FontFamily=`"Consolas`" Foreground=`"{StaticResource SoftText}`" Text=`"$keyText`"/></Border><TextBlock Grid.Column=`"1`" VerticalAlignment=`"Center`" Text=`"$actionText`"/></Grid>"
        }) -join ""

        $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Keyboard Shortcuts" Width="440" SizeToContent="Height" ResizeMode="NoResize" ShowInTaskbar="False"
        WindowStartupLocation="CenterScreen" Background="@FORM@" Foreground="@TEXT@" FontFamily="Segoe UI">
  <Window.Resources><!--APP_RESOURCES--></Window.Resources>
  <StackPanel Margin="22,18,22,18">
    <TextBlock Text="Keyboard Shortcuts" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <Border Margin="0,12,0,0" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="14,10,14,14">
      <StackPanel>
        <TextBlock Style="{StaticResource SectionLabel}" Text="SHORTCUT / ACTION"/>
        @ROWS@
      </StackPanel>
    </Border>
    <Button x:Name="CloseButton" Style="{StaticResource PrimaryButton}" IsDefault="True" IsCancel="True" Width="90" HorizontalAlignment="Right" Margin="0,16,0,0" Content="Close"/>
  </StackPanel>
</Window>
'@
        $ui = New-WpfWindowFromXaml -Xaml ($xaml.Replace('@ROWS@', $rowsXaml)) -ControlNames 'CloseButton'
        $window = $ui.Window
        $ui.Controls['CloseButton'].Add_Click({ $window.Close() })
        Show-WpfDialog -Window $window -OwnerForm $parentForm | Out-Null
    } catch {
        Write-Log "WPF shortcuts dialog failed, using WinForms fallback: $($_.Exception.Message)" -Level Info
        Show-KeyboardShortcutsFallback -parentForm $(if ($parentForm -is [System.Windows.Forms.Form]) { $parentForm } else { $null })
    }
}

# Shows a styled About dialog with version info, author, GitHub link, and in-app updater.
function Show-AboutDialog {
    param([System.Windows.Forms.Form]$parentForm)

    $aboutForm = New-Object System.Windows.Forms.Form -Property @{
        Text            = "About PowerShell API Tester"
        Size            = [System.Drawing.Size]::new(580, 560)
        StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterParent
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        MaximizeBox     = $false
        MinimizeBox     = $false
        BackColor       = $script:Theme.FormBackground
        AutoSize        = $true
        AutoSizeMode    = 'GrowAndShrink'
    }

    $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock         = 'Fill'
        ColumnCount  = 1
        RowCount     = 5
        BackColor    = $script:Theme.FormBackground
        AutoSize     = $true
        AutoSizeMode = 'GrowAndShrink'
    }
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 2))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    # --- Header ---
    $headerPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock         = 'Fill'
        ColumnCount  = 2
        RowCount     = 1
        BackColor    = $script:Theme.PrimaryButton
        AutoSize     = $true
        AutoSizeMode = 'GrowAndShrink'
        Padding      = [System.Windows.Forms.Padding]::new(15, 15, 15, 15)
        Margin       = [System.Windows.Forms.Padding]::new(0)
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
        Dock          = 'Fill'
        FlowDirection = 'TopDown'
        AutoSize      = $true
        AutoSizeMode  = 'GrowAndShrink'
        WrapContents  = $false
        Margin        = [System.Windows.Forms.Padding]::new(0)
    }
    $headerTextFlow.Controls.Add((New-Label -Text "PowerShell API Tester" -Property @{ 
        Font      = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
        ForeColor = [System.Drawing.Color]::White
        AutoSize  = $true
        Margin    = [System.Windows.Forms.Padding]::new(0)
    }))
    $headerTextFlow.Controls.Add((New-Label -Text "Feature-rich REST / gRPC API testing tool for Windows" -Property @{ 
        Font        = New-Object System.Drawing.Font("Segoe UI", 9)
        ForeColor   = [System.Drawing.ColorTranslator]::FromHtml("#cfe8fc")
        AutoSize    = $true
        MaximumSize = [System.Drawing.Size]::new(450, 0)
        Margin      = [System.Windows.Forms.Padding]::new(0, 5, 0, 0)
    }))

    $headerPanel.Controls.Add($picIcon, 0, 0)
    $headerPanel.Controls.Add($headerTextFlow, 1, 0)

    # --- Details ---
    $detailsPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock         = 'Fill'
        ColumnCount  = 2
        AutoSize     = $true
        AutoSizeMode = 'GrowAndShrink'
        Padding      = [System.Windows.Forms.Padding]::new(20, 20, 20, 20)
        Margin       = [System.Windows.Forms.Padding]::new(0)
        BackColor    = $script:Theme.GroupBackground
    }
    $detailsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $detailsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $boldFont   = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $normalFont = New-Object System.Drawing.Font("Segoe UI", 9)
    $grayColor  = [System.Drawing.ColorTranslator]::FromHtml("#6c757d")
    $blueColor  = [System.Drawing.ColorTranslator]::FromHtml("#0078d4")

    $infoRows = @(
        @{ Label = "Version:";  Value = "v$($script:AppVersion)"; IsLink = $false },
        @{ Label = "Author:";   Value = "Umesh Kashyap";          IsLink = $false },
        @{ Label = "License:";  Value = "MIT";                    IsLink = $false },
        @{ Label = "GitHub:";   Value = "github.com/$($script:AppGitHubRepo)"; IsLink = $true }
    )

    $row = 0
    foreach ($r in $infoRows) {
        $detailsPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
        $lblKey = New-Label -Text $r.Label -Property @{ Font = $boldFont; ForeColor = $grayColor; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 0, 15, 10) }
        $detailsPanel.Controls.Add($lblKey, 0, $row)

        if ($r.IsLink) {
            $lnk = New-Object System.Windows.Forms.LinkLabel -Property @{ Text = $r.Value; Font = $normalFont; AutoSize = $true; LinkColor = $blueColor; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
            $repoUrl = "https://github.com/$($script:AppGitHubRepo)"
            $lnk.Add_LinkClicked({
                try { [System.Diagnostics.Process]::Start($repoUrl) | Out-Null } catch {}
            })
            $detailsPanel.Controls.Add($lnk, 1, $row)
        } else {
            $lblVal = New-Label -Text $r.Value -Property @{ Font = $normalFont; AutoSize = $true; ForeColor = $script:Theme.TextColor; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
            $detailsPanel.Controls.Add($lblVal, 1, $row)
        }
        $row++
    }
    
    $detailsPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $lblDesc = New-Label -Text "A feature-rich API testing tool built entirely in PowerShell & WinForms." -Property @{ 
        Font        = $normalFont
        ForeColor   = $grayColor
        AutoSize    = $true
        MaximumSize = [System.Drawing.Size]::new(480, 0)
        Margin      = [System.Windows.Forms.Padding]::new(0, 10, 0, 0)
    }
    $detailsPanel.Controls.Add($lblDesc, 0, $row)
    $detailsPanel.SetColumnSpan($lblDesc, 2)

    # --- Separator ---
    $sep = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Fill'; Margin = [System.Windows.Forms.Padding]::new(0); BackColor = [System.Drawing.ColorTranslator]::FromHtml("#dee2e6") }

    # --- Update Panel ---
    $updatePanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock         = 'Fill'
        ColumnCount  = 1
        RowCount     = 4
        AutoSize     = $true
        AutoSizeMode = 'GrowAndShrink'
        Padding      = [System.Windows.Forms.Padding]::new(20, 15, 20, 15)
        Margin       = [System.Windows.Forms.Padding]::new(0)
    }
    $lblUpdateTitle = New-Label -Text "Software Update" -Property @{ Font = $boldFont; ForeColor = $script:Theme.TextColor; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 5) }
    $lblUpdateStatus = New-Label -Text "Click 'Check for Updates' to check." -Property @{ Font = $normalFont; ForeColor = $grayColor; AutoSize = $true; MaximumSize = [System.Drawing.Size]::new(480, 0); Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 15) }
    
    $updatePanel.Controls.Add($lblUpdateTitle, 0, 0)
    $updatePanel.Controls.Add($lblUpdateStatus, 0, 1)

    $btnFlow = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
        Dock          = 'Fill'
        FlowDirection = 'LeftToRight'
        AutoSize      = $true
        AutoSizeMode  = 'GrowAndShrink'
        Margin        = [System.Windows.Forms.Padding]::new(0)
    }

    $btnDownload = New-Button -Text "Download & Update" -Style 'Primary' -OnClick {
        $release = $btnDownload.Tag
        if ($release) {
            Invoke-DownloadUpdate -Release $release -StatusLabel $lblUpdateStatus
        }
    } -Property @{
        AutoSize = $true
        Height   = 32
        Visible  = $false
        Margin   = [System.Windows.Forms.Padding]::new(0, 0, 10, 0)
    }
    $btnDownload.Name = "btnDownload"

    $btnCheck = New-Button -Text "Check for Updates" -Style 'Secondary' -OnClick {
        Invoke-UpdateCheck -StatusLabel $lblUpdateStatus -DownloadButton $btnDownload -ParentForm $aboutForm
    } -Property @{
        AutoSize = $true
        Height   = 32
        Margin   = [System.Windows.Forms.Padding]::new(0)
    }
    $btnFlow.Controls.AddRange(@($btnDownload, $btnCheck))
    $updatePanel.Controls.Add($btnFlow, 0, 2)

    # --- Footer ---
    $footerFlow = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
        Dock          = 'Fill'
        FlowDirection = 'RightToLeft'
        AutoSize      = $true
        AutoSizeMode  = 'GrowAndShrink'
        Padding       = [System.Windows.Forms.Padding]::new(15)
        Margin        = [System.Windows.Forms.Padding]::new(0)
        BackColor     = $script:Theme.GroupBackground
    }
    $btnClose = New-Button -Text "Close" -Style 'Secondary' -OnClick { $aboutForm.Close() } -Property @{ 
        AutoSize = $true
        Height   = 32
        Margin   = [System.Windows.Forms.Padding]::new(0) 
    }
    $footerFlow.Controls.Add($btnClose)

    $mainLayout.Controls.Add($headerPanel, 0, 0)
    $mainLayout.Controls.Add($detailsPanel, 0, 1)
    $mainLayout.Controls.Add($sep, 0, 2)
    $mainLayout.Controls.Add($updatePanel, 0, 3)
    $mainLayout.Controls.Add($footerFlow, 0, 4)

    $aboutForm.Controls.Add($mainLayout)

    $aboutForm.ShowDialog($parentForm) | Out-Null
    $aboutForm.Dispose()
}

#endregion About & Update Functions

# The main function that constructs and displays the primary application window.




