function Show-SettingsWindow {
    param (
        [System.Windows.Forms.Form]$parentForm
    )

    $settingsForm = New-Object System.Windows.Forms.Form -Property @{
        Text            = "Settings"
        Size            = New-Object System.Drawing.Size(950, 950)
        StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterParent
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        MaximizeBox     = $true
        MinimizeBox     = $false
        MinimumSize     = New-Object System.Drawing.Size(900, 850)
        BackColor     = $script:Theme.FormBackground
        Padding         = [System.Windows.Forms.Padding]::new(15)
        AutoScroll      = $true
    }
    
    $settingsToolTip = New-Object System.Windows.Forms.ToolTip

    # Main vertical layout
    $mainTableLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock         = [System.Windows.Forms.DockStyle]::Top
        AutoSize     = $true
        AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        ColumnCount  = 1
        RowCount     = 4 
        Padding      = [System.Windows.Forms.Padding]::new(0)
    }
    $mainTableLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    
    # --- Group 1: UI & Panel Visibility (Unchanged) ---
    $groupPanels = New-Object System.Windows.Forms.GroupBox -Property @{
        Dock         = [System.Windows.Forms.DockStyle]::Top
        AutoSize     = $true
        Text         = "UI & Panel Visibility"
        Padding      = [System.Windows.Forms.Padding]::new(10)
        BackColor    = $script:Theme.GroupBackground
        Margin       = [System.Windows.Forms.Padding]::new(0, 0, 0, 15)
    }
    $panelsTable = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; AutoSize = $true; ColumnCount = 3; RowCount = 4 }
    $panelsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.33)))
    $panelsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.33)))
    $panelsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.33)))
    
    $checkShowEnvironment = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Environment Panel"; Checked = $script:settings.ShowEnvironmentPanel; AutoSize = $true }
    $checkShowHistory = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "History Panel"; Checked = $script:settings.ShowHistory; AutoSize = $true }
    $checkShowRequestHeaders = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Request Headers Tab"; Checked = $script:settings.ShowRequestHeadersTab; AutoSize = $true }
    $checkShowAuth = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Authentication Tab"; Checked = $script:settings.ShowAuthTab; AutoSize = $true }
    $checkShowPreRequest = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Pre-request Script Tab"; Checked = $script:settings.ShowPreRequestTab; AutoSize = $true }
    $checkShowTests = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Tests Tab"; Checked = $script:settings.ShowTestsTab; AutoSize = $true }
    $checkShowTestResults = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Test Results Tab"; Checked = $script:settings.ShowTestResultsTab; AutoSize = $true }
    $checkShowResponse = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Response Tab"; Checked = $script:settings.ShowResponse; AutoSize = $true }
    $checkShowJsonTree = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "JSON Tree Tab"; Checked = $script:settings.ShowJsonTreeTab; AutoSize = $true }
    $checkShowResponseHeaders = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Response Headers Tab"; Checked = $script:settings.ShowResponseHeaders; AutoSize = $true }
    $checkShowCurl = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Code Snippets Tab"; Checked = $script:settings.ShowCurl; AutoSize = $true }
    $checkShowConsole = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Console Tab"; Checked = $script:settings.ShowConsoleTab; AutoSize = $true }
    
    $panelTheme = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ AutoSize = $true; FlowDirection = 'LeftToRight'; Margin = [System.Windows.Forms.Padding]::new(0, 10, 0, 0) }
    $labelTheme = New-Object System.Windows.Forms.Label -Property @{ Text = "App Theme:"; AutoSize = $true; Anchor = 'Left'; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(0, 5, 5, 0) }
    $comboTheme = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 120 }
    $comboTheme.Items.AddRange(@("Light", "Dark"))
    if ($script:settings.AppTheme) { $comboTheme.SelectedItem = $script:settings.AppTheme } else { $comboTheme.SelectedItem = "Light" }
    $panelTheme.Controls.AddRange(@($labelTheme, $comboTheme))

    $panelsTable.Controls.AddRange(@($checkShowEnvironment, $checkShowHistory, $checkShowRequestHeaders, $checkShowAuth, $checkShowPreRequest, $checkShowTests, $checkShowTestResults, $checkShowResponse, $checkShowJsonTree, $checkShowResponseHeaders, $checkShowCurl, $checkShowConsole, $panelTheme))
    $groupPanels.Controls.Add($panelsTable)

    # --- Group 2: Configuration (FIXED CUTOFFS) ---
    $groupConfiguration = New-Object System.Windows.Forms.GroupBox -Property @{
        Dock         = [System.Windows.Forms.DockStyle]::Top
        AutoSize     = $true
        Text         = "Configuration"
        Padding      = [System.Windows.Forms.Padding]::new(10)
        BackColor    = $script:Theme.GroupBackground
        Margin       = [System.Windows.Forms.Padding]::new(0, 0, 0, 15)
    }

    # 2-column grid (50% / 50%)
    $configTable = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; AutoSize = $true; ColumnCount = 2; RowCount = 7 }
    $configTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
    $configTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))

    $stdMargin = [System.Windows.Forms.Padding]::new(3, 6, 3, 3)

    # Row 0: Logs
    $checkEnableLogs = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Enable Logging"; Checked = $script:settings.EnableLogs; AutoSize = $true; Margin = $stdMargin }
    $panelLogLvl = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; AutoSize=$true; FlowDirection='LeftToRight' }
    $lblLog = New-Label -Text "Level:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,5,0) }
    $comboLogLevel = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; Width = 100 }
    $comboLogLevel.Items.AddRange(@("Info", "Debug")); $comboLogLevel.SelectedItem = $script:settings.LogLevel
    $panelLogLvl.Controls.AddRange(@($lblLog, $comboLogLevel))
    
    $configTable.Controls.Add($checkEnableLogs, 0, 0)
    $configTable.Controls.Add($panelLogLvl, 1, 0)

    # Row 1: History | Auto-Run
    $checkEnableHistory = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Enable History Tracking"; Checked = $script:settings.EnableHistory; AutoSize = $true; Margin = $stdMargin }
    $checkAutoRunHistory = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Auto-Run on History Double-Click"; Checked = $script:settings.AutoRunHistory; AutoSize = $true; Margin = $stdMargin }
    
    $configTable.Controls.Add($checkEnableHistory, 0, 1)
    $configTable.Controls.Add($checkAutoRunHistory, 1, 1)

    # Row 2: All Methods | SSL
    $checkEnableAllMethods = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Allow all request methods"; Checked = $script:settings.EnableAllMethods; AutoSize = $true; Margin = $stdMargin }
    $checkIgnoreSsl = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Ignore SSL Errors"; Checked = $script:settings.IgnoreSslErrors; AutoSize = $true; Margin = $stdMargin }
    
    $configTable.Controls.Add($checkEnableAllMethods, 0, 2)
    $configTable.Controls.Add($checkIgnoreSsl, 1, 2)

    # Row 3: Postman | Curl
    $checkEnablePostman = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Enable Postman Import"; Checked = $script:settings.EnablePostmanImport; AutoSize = $true; Margin = $stdMargin }
    $checkEnableCurl = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Enable cURL Import"; Checked = $script:settings.EnableCurlImport; AutoSize = $true; Margin = $stdMargin }
    
    $configTable.Controls.Add($checkEnablePostman, 0, 3)
    $configTable.Controls.Add($checkEnableCurl, 1, 3)

    # Row 4: Console Language | Dropdown
    $labelConsoleLang = New-Label -Text "Default Console Language:" -Property @{ AutoSize = $true; Anchor = 'Left'; TextAlign = 'MiddleLeft'; Margin = $stdMargin }
    $comboConsoleLang = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; Width = 200; Margin = $stdMargin }
    $comboConsoleLang.Items.AddRange(@("PowerShell", "JavaScript (Node.js)", "Python", "PHP", "Ruby", "Go", "Batch", "Bash"))
    if ($script:settings.DefaultConsoleLanguage) { $comboConsoleLang.SelectedItem = $script:settings.DefaultConsoleLanguage } else { $comboConsoleLang.SelectedIndex = 0 }
    
    $configTable.Controls.Add($labelConsoleLang, 0, 4)
    $configTable.Controls.Add($comboConsoleLang, 1, 4)

    # Row 5: Timeout | Font Size
    $panelTimeout = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; AutoSize=$true; FlowDirection='LeftToRight'; Padding=[System.Windows.Forms.Padding]::new(0) }
    $labelTimeout = New-Label -Text "Timeout (s):" -Property @{ AutoSize=$true; TextAlign='MiddleLeft'; Margin=[System.Windows.Forms.Padding]::new(3,6,3,0) }
    $textTimeout = New-TextBox -Property @{ Text = $script:settings.RequestTimeoutSeconds; Width = 50; Margin=[System.Windows.Forms.Padding]::new(0,3,0,0) }
    $panelTimeout.Controls.AddRange(@($labelTimeout, $textTimeout))

    $panelFontSize = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; AutoSize=$true; FlowDirection='LeftToRight'; Padding=[System.Windows.Forms.Padding]::new(0) }
    $labelFontSize = New-Label -Text "Font Size:" -Property @{ AutoSize=$true; TextAlign='MiddleLeft'; Margin=[System.Windows.Forms.Padding]::new(0,6,3,0) }
    $numFontSize = New-Object System.Windows.Forms.NumericUpDown -Property @{ Minimum = 8; Maximum = 72; Value = $script:settings.ResponseFontSize; Width = 50; Margin=[System.Windows.Forms.Padding]::new(0,3,0,0) }
    $panelFontSize.Controls.AddRange(@($labelFontSize, $numFontSize))
    
    $configTable.Controls.Add($panelTimeout, 0, 5)
    $configTable.Controls.Add($panelFontSize, 1, 5)

    # Row 6: Repeat Request
    $checkEnableRepeat = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Enable Repeat Request"; Checked = $script:settings.EnableRepeatRequest; AutoSize = $true; Margin = $stdMargin }
    $panelRepeatCount = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; AutoSize=$true; FlowDirection='LeftToRight'; Padding=[System.Windows.Forms.Padding]::new(0) }
    $labelRepeatCount = New-Label -Text "Max Repeats:" -Property @{ AutoSize=$true; TextAlign='MiddleLeft'; Margin=[System.Windows.Forms.Padding]::new(0,6,3,0) }
    $numRepeatCount = New-Object System.Windows.Forms.NumericUpDown -Property @{ Minimum = 1; Maximum = 100; Value = $script:settings.MaxRepeatCount; Width = 50; Margin=[System.Windows.Forms.Padding]::new(0,3,0,0) }
    $panelRepeatCount.Controls.AddRange(@($labelRepeatCount, $numRepeatCount))
    
    $configTable.Controls.Add($checkEnableRepeat, 0, 6)
    $configTable.Controls.Add($panelRepeatCount, 1, 6)

    $groupConfiguration.Controls.Add($configTable)

    # --- Group 3: Auto-Save ---
    $groupAutoSave = New-Object System.Windows.Forms.GroupBox -Property @{
        Dock         = [System.Windows.Forms.DockStyle]::Top
        AutoSize     = $true
        Text         = "Auto-Save & Renaming"
        Padding      = [System.Windows.Forms.Padding]::new(10)
        BackColor    = $script:Theme.GroupBackground
        Margin       = [System.Windows.Forms.Padding]::new(0, 0, 0, 15)
    }
    
    $autoSaveTable = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; AutoSize = $true; ColumnCount = 2; RowCount = 4 }
    $autoSaveTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $autoSaveTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))

    # Row 0: Enable Checkbox (Span 2)
    $checkAutoSave = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Auto-Save to Folder"; Checked = $script:settings.AutoSaveToFile; AutoSize = $true; Margin = $stdMargin }
    $autoSaveTable.Controls.Add($checkAutoSave, 0, 0); $autoSaveTable.SetColumnSpan($checkAutoSave, 2)

    # Row 1: Path + Button
    $textAutoSavePath = New-TextBox -Multiline $false -Property @{ Text = $script:settings.AutoSavePath; Dock = 'Fill'; Height = 30; Margin = [System.Windows.Forms.Padding]::new(3,3,3,3) }
    
    $btnBrowseAutoSavePath = New-Button -Text "Browse..." -Size (New-Object System.Drawing.Size(90, 30)) -OnClick {
        $folderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($textAutoSavePath.Text -and [System.IO.Directory]::Exists($textAutoSavePath.Text)) { $folderBrowserDialog.SelectedPath = $textAutoSavePath.Text }
        if ($folderBrowserDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $textAutoSavePath.Text = $folderBrowserDialog.SelectedPath }
    }
    $autoSaveTable.Controls.Add($textAutoSavePath, 0, 1)
    $autoSaveTable.Controls.Add($btnBrowseAutoSavePath, 1, 1)

    # Row 2: Rename Checkbox (Span 2)
    $checkAutoRename = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Auto-Rename Output File (from inputs)"; Checked = $script:settings.AutoRenameFile; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(3,10,3,3) }
    $autoSaveTable.Controls.Add($checkAutoRename, 0, 2); $autoSaveTable.SetColumnSpan($checkAutoRename, 2)

    # Row 3: Prefix (Span 2)
    $panelPrefixRow = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; AutoSize = $true; FlowDirection = 'LeftToRight'; Margin = [System.Windows.Forms.Padding]::new(0) }
    
    $checkEnablePrefix = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Enable Prefix:"; Checked = $script:settings.EnableAutoRenamePrefix; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(3, 6, 5, 0) } 
    $textAutoRenamePrefix = New-TextBox -Property @{ Text = $script:settings.AutoRenamePrefix; Width = 200; Margin = [System.Windows.Forms.Padding]::new(0,0,0,0) }
    
    $panelPrefixRow.Controls.Add($checkEnablePrefix)
    $panelPrefixRow.Controls.Add($textAutoRenamePrefix)

    $autoSaveTable.Controls.Add($panelPrefixRow, 0, 3); $autoSaveTable.SetColumnSpan($panelPrefixRow, 2)

    $groupAutoSave.Controls.Add($autoSaveTable)

    # Logic for enabling/disabling controls
    $checkEnableLogs.Add_CheckedChanged({ $lblLog.Enabled = $checkEnableLogs.Checked; $comboLogLevel.Enabled = $checkEnableLogs.Checked })
    $lblLog.Enabled = $checkEnableLogs.Checked; $comboLogLevel.Enabled = $checkEnableLogs.Checked
    
    $checkEnableHistory.Add_CheckedChanged({ $checkShowHistory.Enabled = $checkEnableHistory.Checked; $checkAutoRunHistory.Enabled = $checkEnableHistory.Checked })
    $checkShowHistory.Enabled = $checkEnableHistory.Checked; $checkAutoRunHistory.Enabled = $checkEnableHistory.Checked

    $checkAutoSave.Add_CheckedChanged({ $textAutoSavePath.Enabled = $checkAutoSave.Checked; $btnBrowseAutoSavePath.Enabled = $checkAutoSave.Checked })
    $textAutoSavePath.Enabled = $checkAutoSave.Checked; $btnBrowseAutoSavePath.Enabled = $checkAutoSave.Checked
    
    $checkEnablePrefix.Add_CheckedChanged({ $textAutoRenamePrefix.Enabled = $checkEnablePrefix.Checked })
    $textAutoRenamePrefix.Enabled = $checkEnablePrefix.Checked

    $checkEnableRepeat.Add_CheckedChanged({
        $labelRepeatCount.Enabled = $checkEnableRepeat.Checked
        $numRepeatCount.Enabled = $checkEnableRepeat.Checked
    })
    $labelRepeatCount.Enabled = $checkEnableRepeat.Checked
    $numRepeatCount.Enabled = $checkEnableRepeat.Checked

    # --- Buttons (Centered Inline Row) ---
    $stdBtnSize = New-Object System.Drawing.Size(110, 35)
    $restoreBtnSize = New-Object System.Drawing.Size(180, 35)
    $btnMargin = [System.Windows.Forms.Padding]::new(5)
    $btnRestore = New-Button -Text "Restore Defaults" -Style 'Danger' -Property @{ Size = $restoreBtnSize; Margin = $btnMargin } -OnClick {
        $confirm = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to restore default settings? This will revert all configuration changes to their original defaults.", "Restore Defaults", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
            # Restore logic
            $checkShowResponse.Checked = $script:defaultSettings.ShowResponse
            $checkShowJsonTree.Checked = $script:defaultSettings.ShowJsonTreeTab
            $checkShowEnvironment.Checked = $script:defaultSettings.ShowEnvironmentPanel
            $checkShowRequestHeaders.Checked = $script:defaultSettings.ShowRequestHeadersTab
            $checkShowAuth.Checked = $script:defaultSettings.ShowAuthTab
            $checkShowPreRequest.Checked = $script:defaultSettings.ShowPreRequestTab
            $checkShowTests.Checked = $script:defaultSettings.ShowTestsTab
            $checkShowTestResults.Checked = $script:defaultSettings.ShowTestResultsTab
            $checkShowResponseHeaders.Checked = $script:defaultSettings.ShowResponseHeaders
            $checkShowCurl.Checked = $script:defaultSettings.ShowCurl
            $checkShowConsole.Checked = $script:defaultSettings.ShowConsoleTab
            $script:settings.ResponseDockState = $script:defaultSettings.ResponseDockState
            $script:settings.LastActiveEnvironment = $script:defaultSettings.LastActiveEnvironment
            $checkShowHistory.Checked = $script:defaultSettings.ShowHistory
            $checkAutoSave.Checked = $script:defaultSettings.AutoSaveToFile
            $textAutoSavePath.Text = $script:defaultSettings.AutoSavePath
            $checkAutoRename.Checked = $script:defaultSettings.AutoRenameFile
            $checkEnablePrefix.Checked = $script:defaultSettings.EnableAutoRenamePrefix
            $textAutoRenamePrefix.Text = $script:defaultSettings.AutoRenamePrefix
            $checkEnableLogs.Checked = $script:defaultSettings.EnableLogs
            $checkEnableHistory.Checked = $script:defaultSettings.EnableHistory
            $comboLogLevel.SelectedItem = $script:defaultSettings.LogLevel
            $checkAutoRunHistory.Checked = $script:defaultSettings.AutoRunHistory
            $script:settings.EnableAllMethods = $script:defaultSettings.EnableAllMethods
            $script:settings.IncludeFilename = $script:defaultSettings.IncludeFilename
            $checkEnableAllMethods.Checked = $script:defaultSettings.EnableAllMethods
            $checkIgnoreSsl.Checked = $script:defaultSettings.IgnoreSslErrors
            $textTimeout.Text = $script:defaultSettings.RequestTimeoutSeconds
            $numFontSize.Value = $script:defaultSettings.ResponseFontSize
            $checkEnableCurl.Checked = $script:defaultSettings.EnableCurlImport
            $checkEnablePostman.Checked = $script:defaultSettings.EnablePostmanImport
            $comboConsoleLang.SelectedItem = $script:defaultSettings.DefaultConsoleLanguage
            $checkEnableRepeat.Checked = $script:defaultSettings.EnableRepeatRequest
            $numRepeatCount.Value = $script:defaultSettings.MaxRepeatCount
        }
    }
    
    $btnViewLogs = New-Button -Text "View Logs" -Style 'Secondary' -Property @{ Size = $stdBtnSize; Margin = $btnMargin } -OnClick { Show-LogViewer -parentForm $settingsForm }
    $btnOpenLogs = New-Button -Text "Open Logs" -Style 'Secondary' -Property @{ Size = $stdBtnSize; Margin = $btnMargin } -OnClick { if (Test-Path $logsDir) { Invoke-Item $logsDir } else { [System.Windows.Forms.MessageBox]::Show("Logs folder not found.", "Error", "OK", "Error") } }
    $btnClearLogs = New-Button -Text "Clear Logs" -Style 'Secondary' -Property @{ Size = $stdBtnSize; Margin = $btnMargin } -OnClick {
        $confirm = [System.Windows.Forms.MessageBox]::Show("Are you sure?", "Confirm Clear Logs", "YesNo", "Warning")
        if ($confirm -eq 'Yes') { try { Clear-Content -Path $logFilePath -ErrorAction Stop; Add-Content -Path $logFilePath -Value "Timestamp,Level,Message"; [System.Windows.Forms.MessageBox]::Show("Logs cleared.", "Success") } catch { [System.Windows.Forms.MessageBox]::Show("Failed to clear logs.", "Error") } }
    }
    
    $btnCancel = New-Button -Text "Cancel" -Style 'Secondary' -Property @{ Size = $stdBtnSize; Margin = $btnMargin } -OnClick { $settingsForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $settingsForm.Close() }
    
    $btnSave = New-Button -Text "Save" -Style 'Primary' -Property @{ Size = $stdBtnSize; Margin = $btnMargin } -OnClick {
        if ($checkEnablePrefix.Checked -and [string]::IsNullOrWhiteSpace($textAutoRenamePrefix.Text)) { [System.Windows.Forms.MessageBox]::Show("Prefix cannot be blank.", "Error"); return }
        if ($checkAutoSave.Checked -and [string]::IsNullOrWhiteSpace($textAutoSavePath.Text)) { [System.Windows.Forms.MessageBox]::Show("Auto-Save path cannot be blank.", "Error"); return }
        if ($checkAutoSave.Checked -and -not (Test-Path -Path $textAutoSavePath.Text -PathType Container)) { [System.Windows.Forms.MessageBox]::Show("Auto-Save path does not exist.", "Error"); return }
        if (-not [int]::TryParse($textTimeout.Text, [ref]$null) -or [int]$textTimeout.Text -le 0) { [System.Windows.Forms.MessageBox]::Show("Invalid Timeout.", "Error"); return }

        $script:settings.ShowResponse = $checkShowResponse.Checked
        $script:settings.ShowJsonTreeTab = $checkShowJsonTree.Checked
        $script:settings.ShowResponseHeaders = $checkShowResponseHeaders.Checked
        $script:settings.ShowCurl = $checkShowCurl.Checked
        $script:settings.ShowConsoleTab = $checkShowConsole.Checked
        $script:settings.ShowHistory = $checkShowHistory.Checked
        $script:settings.AutoSaveToFile = $checkAutoSave.Checked
        $script:settings.AutoSavePath = $textAutoSavePath.Text
        $script:settings.AutoRenameFile = $checkAutoRename.Checked
        $script:settings.EnableAutoRenamePrefix = $checkEnablePrefix.Checked
        $script:settings.AutoRenamePrefix = $textAutoRenamePrefix.Text
        $script:settings.EnableLogs = $checkEnableLogs.Checked
        $script:settings.EnableHistory = $checkEnableHistory.Checked
        $script:settings.LogLevel = $comboLogLevel.SelectedItem
        $script:settings.ShowEnvironmentPanel = $checkShowEnvironment.Checked
        $script:settings.ShowRequestHeadersTab = $checkShowRequestHeaders.Checked
        $script:settings.ShowAuthTab = $checkShowAuth.Checked
        $script:settings.ShowPreRequestTab = $checkShowPreRequest.Checked
        $script:settings.ShowTestsTab = $checkShowTests.Checked
        $script:settings.ShowTestResultsTab = $checkShowTestResults.Checked
        $script:settings.AutoRunHistory = $checkAutoRunHistory.Checked
        $script:settings.EnableAllMethods = $checkEnableAllMethods.Checked
        $script:settings.IgnoreSslErrors = $checkIgnoreSsl.Checked
        $script:settings.EnablePostmanImport = $checkEnablePostman.Checked
        $script:settings.EnableCurlImport = $checkEnableCurl.Checked
        $script:settings.DefaultConsoleLanguage = $comboConsoleLang.SelectedItem
        if ([int]::TryParse($textTimeout.Text, [ref]$null)) { $script:settings.RequestTimeoutSeconds = [int]$textTimeout.Text } else { $script:settings.RequestTimeoutSeconds = 60 }
        $script:settings.ResponseFontSize = $numFontSize.Value
        $script:settings.EnableRepeatRequest = $checkEnableRepeat.Checked
        $script:settings.MaxRepeatCount = [int]$numRepeatCount.Value
        
        $oldTheme = $script:settings.AppTheme
        $script:settings.AppTheme = $comboTheme.SelectedItem
        
        Save-Settings
        
        if ($oldTheme -ne $script:settings.AppTheme) {
            Set-AppTheme -Form $parentForm
        }
        $settingsForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $settingsForm.Close()
    }

    # Center the button row using a 3-column layout with an autosized middle cell.
    $buttonsRow = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock        = [System.Windows.Forms.DockStyle]::Top
        AutoSize    = $true
        ColumnCount = 3
        RowCount    = 1
        Padding     = [System.Windows.Forms.Padding]::new(0, 10, 0, 0)
    }
    $buttonsRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null
    $buttonsRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $buttonsRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null

    $buttonsFlow = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
        AutoSize     = $true
        FlowDirection = 'LeftToRight'
        WrapContents = $false
        Margin       = [System.Windows.Forms.Padding]::new(0)
        Padding      = [System.Windows.Forms.Padding]::new(0, 0, 0, 10)
    }
    $buttonsFlow.Controls.AddRange(@($btnRestore, $btnViewLogs, $btnOpenLogs, $btnClearLogs, $btnCancel, $btnSave))
    $buttonsRow.Controls.Add($buttonsFlow, 1, 0)

    $mainTableLayout.Controls.Add($groupPanels, 0, 0)
    $mainTableLayout.Controls.Add($groupConfiguration, 0, 1)
    $mainTableLayout.Controls.Add($groupAutoSave, 0, 2)
    $mainTableLayout.Controls.Add($buttonsRow, 0, 3) 

    $settingsForm.Controls.Add($mainTableLayout)
    
    return $settingsForm.ShowDialog($parentForm)
}

# --- Proxy Settings Window ---
