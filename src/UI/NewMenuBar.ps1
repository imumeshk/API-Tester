#region XAML Main Window - Menu bar (Phase B)
# Wires the Menu / Tools / Monitor / Help menus of the XAML main window.
#   Menu     : native XAML (cURL import, collection import, workspace import/export, reset layout, exit)
#   Tools / Monitor / Help : native XAML dialogs (NewToolDialogs.ps1, NewNetworkDialogs.ps1, NewMonitorUi.ps1)
# State shared with the window lives in $script:MainWindowContext (set by Show-MainWindow), because event
# handlers run after the function that registered them has returned.

function Get-MainWindow { return $script:MainWindowContext.Window }

function Write-UiLog {
    param([string]$Message)
    # The new window has no log panel; activity goes to the application log file (Settings > Log level).
    Write-Log $Message -Level Info
}

function Set-UiStatus {
    param([string]$Message)
    $statusText = $script:MainWindowContext.Controls.StatusText
    if ($statusText) { $statusText.Text = $Message }
}

function Show-UiMessage {
    param([string]$Message, [string]$Title = 'API Tester', [string]$Icon = 'Information')
    [void][System.Windows.MessageBox]::Show((Get-MainWindow), $Message, $Title, 'OK', $Icon)
}

# Opens a classic WinForms dialog from the WPF window. A hidden WinForms form sits over the main window as the
# dialog's owner, and the main window is disabled while the dialog is open (so it behaves modally).
# The script block receives the owner form:  Invoke-LegacyDialog { param($owner) Show-CookieJar -parentForm $owner }
function Invoke-LegacyDialog {
    param([Parameter(Mandatory = $true)][scriptblock]$Action)

    $window = Get-MainWindow
    $ownerForm = New-Object System.Windows.Forms.Form
    $ownerForm.ShowInTaskbar = $false
    $ownerForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
    $ownerForm.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
    $ownerForm.Opacity = 0
    $scale = 1.0
    $presentationSource = [System.Windows.PresentationSource]::FromVisual($window)
    if ($presentationSource) { $scale = $presentationSource.CompositionTarget.TransformToDevice.M11 }
    $ownerForm.Bounds = New-Object System.Drawing.Rectangle ([int]($window.Left * $scale)), ([int]($window.Top * $scale)), ([int]($window.ActualWidth * $scale)), ([int]($window.ActualHeight * $scale))

    $window.IsEnabled = $false
    try {
        $ownerForm.Show()
        return (& $Action $ownerForm)
    } catch {
        Write-UiLog "Dialog error: $($_.Exception.Message)"
        Show-UiMessage "The dialog could not be opened: $($_.Exception.Message)" 'API Tester' 'Error'
    } finally {
        $ownerForm.Close()
        $ownerForm.Dispose()
        $window.IsEnabled = $true
        [void]$window.Activate()
    }
}

# ---------------------------------------------------------------------------------------------
# Small XAML dialogs
# ---------------------------------------------------------------------------------------------

# Multi-line text prompt for a pasted cURL command. Returns the text, or $null when cancelled.
function Show-CurlImportDialog {
    param($Owner)

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Import cURL" Width="640" Height="460" MinWidth="480" MinHeight="320" ShowInTaskbar="False"
        WindowStartupLocation="CenterOwner" Background="@FORM@" Foreground="@TEXT@" FontFamily="Segoe UI">
  <Window.Resources><!--APP_RESOURCES--></Window.Resources>
  <Grid Margin="22,18,22,18">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="Import cURL" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <TextBlock Grid.Row="1" Margin="0,2,0,10" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Text="Paste a cURL command. Method, URL, headers, body and basic/bearer auth are loaded into the request editor."/>
    <TextBox x:Name="CurlBox" Grid.Row="2" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="13"/>
    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="ImportButton" Style="{StaticResource PrimaryButton}" IsDefault="False" Width="100" Content="Import"/>
      <Button x:Name="CancelButton" IsCancel="True" Width="90" Margin="10,0,0,0" Content="Cancel"/>
    </StackPanel>
  </Grid>
</Window>
'@
    $ui = New-WpfWindowFromXaml -Xaml $xaml -ControlNames 'CurlBox', 'ImportButton', 'CancelButton'
    $dialogWindow = $ui.Window
    $dialogControls = $ui.Controls
    $script:curlDialogResult = $null
    $dialogControls['ImportButton'].Add_Click({
        if ([string]::IsNullOrWhiteSpace($dialogControls['CurlBox'].Text)) { return }
        $script:curlDialogResult = $dialogControls['CurlBox'].Text
        $dialogWindow.DialogResult = $true
    })
    $dialogWindow.Add_ContentRendered({ $dialogControls['CurlBox'].Focus() | Out-Null })
    [void](Show-WpfDialog -Window $dialogWindow -OwnerForm $Owner)
    return $script:curlDialogResult
}

# Generic "pick what to include" dialog. $Options = @( @{ Name; Text; Checked; Enabled } ... ).
# Returns a hashtable Name -> bool, or $null when cancelled.
function Show-OptionsDialog {
    param($Owner, [string]$Title, [string]$Message, $Options, [string]$ConfirmText = 'OK', [string]$Note = '')

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Options" Width="480" SizeToContent="Height" ResizeMode="NoResize" ShowInTaskbar="False"
        WindowStartupLocation="CenterOwner" Background="@FORM@" Foreground="@TEXT@" FontFamily="Segoe UI">
  <Window.Resources><!--APP_RESOURCES--></Window.Resources>
  <StackPanel Margin="24,18,24,18">
    <TextBlock x:Name="TitleText" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <TextBlock x:Name="MessageText" Margin="0,2,0,12" Foreground="{StaticResource Muted}" TextWrapping="Wrap"/>
    <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="14,12">
      <StackPanel x:Name="OptionsPanel"/>
    </Border>
    <TextBlock x:Name="NoteText" Margin="0,10,0,0" Foreground="{StaticResource Muted}" TextWrapping="Wrap"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
      <Button x:Name="ConfirmButton" Style="{StaticResource PrimaryButton}" IsDefault="True" Width="110"/>
      <Button x:Name="CancelButton" IsCancel="True" Width="90" Margin="10,0,0,0" Content="Cancel"/>
    </StackPanel>
  </StackPanel>
</Window>
'@
    $ui = New-WpfWindowFromXaml -Xaml $xaml -ControlNames 'TitleText', 'MessageText', 'OptionsPanel', 'NoteText', 'ConfirmButton', 'CancelButton'
    $dialogWindow = $ui.Window
    $dialogControls = $ui.Controls
    $dialogWindow.Title = $Title
    $dialogControls['TitleText'].Text = $Title
    $dialogControls['MessageText'].Text = $Message
    $dialogControls['NoteText'].Text = $Note
    $dialogControls['NoteText'].Visibility = if ($Note) { 'Visible' } else { 'Collapsed' }
    $dialogControls['ConfirmButton'].Content = $ConfirmText

    $script:optionCheckBoxes = @{}
    foreach ($option in $Options) {
        $checkBox = New-Object System.Windows.Controls.CheckBox
        $checkBox.Content = $option.Text
        $checkBox.IsEnabled = [bool]$option.Enabled
        $checkBox.IsChecked = ([bool]$option.Checked -and [bool]$option.Enabled)
        $checkBox.Margin = [System.Windows.Thickness]::new(0, 4, 0, 4)
        [void]$dialogControls['OptionsPanel'].Children.Add($checkBox)
        $script:optionCheckBoxes[$option.Name] = $checkBox
    }

    $script:optionsDialogResult = $null
    $dialogControls['ConfirmButton'].Add_Click({
        $chosen = @{}
        foreach ($name in $script:optionCheckBoxes.Keys) { $chosen[$name] = ($script:optionCheckBoxes[$name].IsChecked -eq $true) }
        $script:optionsDialogResult = $chosen
        $dialogWindow.DialogResult = $true
    })
    [void](Show-WpfDialog -Window $dialogWindow -OwnerForm $Owner)
    return $script:optionsDialogResult
}

# ---------------------------------------------------------------------------------------------
# Workspace export / import (UI independent)
# ---------------------------------------------------------------------------------------------

# Writes a workspace file. Encrypted setting values (SMTP/proxy passwords, tokens) are never exported.
function Export-WorkspaceFile {
    param([string]$FilePath, [hashtable]$Include)

    $exportedSettings = $script:settings.Clone()
    foreach ($key in $script:encryptedSettingKeys) { [void]$exportedSettings.Remove($key) }
    $workspace = [ordered]@{ Settings = $exportedSettings }
    if ($Include.Environments) {
        $environmentsCopy = @{}
        foreach ($name in @($script:environments.Keys)) {
            $copy = ConvertFrom-JsonToHashtable -Json (ConvertTo-Json -InputObject $script:environments[$name] -Depth 10)
            if ($copy.Variables) { $copy.Variables = ConvertTo-ProtectedVariables -Variables $copy.Variables -SecretNames (Get-SecretNames $copy) -Blank }
            $environmentsCopy[$name] = $copy
        }
        $workspace['Environments'] = $environmentsCopy
    }
    if ($Include.History)      { $workspace['History'] = $script:history }
    if ($Include.Globals)      { $workspace['Globals'] = ConvertTo-ProtectedVariables -Variables $script:globals -SecretNames @($script:settings.SecretGlobalNames) -Blank }
    if ($Include.Collections)  { $workspace['Collections'] = Get-CollectionsForStorage -Collections $script:collections -ForExport }
    $workspace | ConvertTo-Json -Depth 10 | Set-Content -Path $FilePath -Encoding UTF8 -ErrorAction Stop
}

# Applies a parsed workspace object to the app state and the files on disk.
function Import-WorkspaceData {
    param($Workspace, [hashtable]$Include)

    if ($Include.Settings -and $Workspace.Settings) {
        foreach ($property in $Workspace.Settings.PSObject.Properties) {
            if ($property.Name -in $script:encryptedSettingKeys) { continue }   # keep this machine's secrets
            $script:settings[$property.Name] = $property.Value
        }
        Save-Settings
    }
    if ($Include.Environments) {
        $Workspace.Environments | ConvertTo-Json -Depth 5 | Set-Content -Path $environmentsFilePath -ErrorAction Stop
        Import-Environments
        Save-Environments
    }
    if ($Include.History) {
        $Workspace.History | ConvertTo-Json -Depth 5 | Set-Content -Path $historyFilePath -ErrorAction Stop
        Import-History
    }
    if ($Include.Globals) {
        $Workspace.Globals | ConvertTo-Json -Depth 5 | Set-Content -Path $globalsFilePath -ErrorAction Stop
        Import-Globals
    }
    if ($Include.Collections) {
        $Workspace.Collections | ConvertTo-Json -Depth 10 | Set-Content -Path $collectionsFilePath -ErrorAction Stop
        Import-Collections
    }
}

# Refreshes the environment drop-down after environments were reloaded.
function Update-EnvironmentChoices {
    $environmentBox = $script:MainWindowContext.Controls.EnvironmentBox
    $current = [string]$environmentBox.SelectedItem
    $script:isSwitchingRequestTab = $true
    try {
        $environmentBox.Items.Clear()
        [void]$environmentBox.Items.Add('No Environment')
        foreach ($environmentName in @($script:environments.Keys | Sort-Object)) { [void]$environmentBox.Items.Add($environmentName) }
        $environmentBox.SelectedItem = if ($current -and $environmentBox.Items.Contains($current)) { $current } else { 'No Environment' }
    } finally { $script:isSwitchingRequestTab = $false }
    $script:activeEnvironment = [string]$environmentBox.SelectedItem
    if (Get-Command Update-HistoryEnvironmentChoices -ErrorAction SilentlyContinue) { Update-HistoryEnvironmentChoices }
}

function Update-ImportMenuVisibility {
    $controls = $script:MainWindowContext.Controls
    $controls.MenuImportCurl.Visibility = if ($script:settings.EnableCurlImport) { 'Visible' } else { 'Collapsed' }
    $controls.MenuImportPostman.Visibility = if ($script:settings.EnablePostmanImport) { 'Visible' } else { 'Collapsed' }
}

# ---------------------------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------------------------

function Invoke-MenuImportCurl {
    $curlText = Show-CurlImportDialog -Owner (Get-MainWindow)
    if ([string]::IsNullOrWhiteSpace($curlText)) { return }
    try {
        $parsedRequest = ConvertFrom-CurlCommand -CommandText $curlText
        if (-not $parsedRequest.Url) { Show-UiMessage 'No URL was found in that cURL command.' 'Import cURL' 'Warning'; return }
        $state = New-RequestTabState -Name "$($parsedRequest.Method) $($parsedRequest.Url)" -Method $parsedRequest.Method -Url $parsedRequest.Url -Headers $parsedRequest.HeaderText `            -Body $parsedRequest.Body -BodyType $parsedRequest.BodyType -Authentication $parsedRequest.Authentication
        Open-RequestState -Data $state -Name $state.Name -NewTab
        foreach ($warning in $parsedRequest.Warnings) { Write-UiLog "cURL import: $warning" }
        Set-UiStatus "Imported cURL command ($($parsedRequest.Method)) into a new tab."
        if ($parsedRequest.Warnings.Count -gt 0) { Show-UiMessage ($parsedRequest.Warnings -join "`n`n") 'Import cURL - notes' 'Warning' }
    } catch {
        Write-UiLog "cURL import failed: $($_.Exception.Message)"
        Show-UiMessage "Could not import the cURL command: $($_.Exception.Message)" 'Import cURL' 'Error'
    }
}

function Invoke-MenuImportCollection {
    $fileDialog = New-Object Microsoft.Win32.OpenFileDialog
    $fileDialog.Title = 'Import Postman / Insomnia / HAR / OpenAPI / API Tester collections'
    $fileDialog.Filter = 'Collections (*.json;*.yaml;*.yml;*.har)|*.json;*.yaml;*.yml;*.har|All files (*.*)|*.*'
    if ($fileDialog.ShowDialog((Get-MainWindow)) -ne $true) { return }
    try {
        $imported = @(Import-CollectionFile -FilePath $fileDialog.FileName)
        if ($imported.Count -eq 0) { Show-UiMessage 'The file did not contain any collections.' 'Import' 'Warning'; return }
        $script:collections = @($script:collections) + $imported
        Initialize-CollectionVariables -Items $script:collections
        Save-Collections
        Update-CollectionsTree
        $names = ($imported | ForEach-Object { $_.Name }) -join ', '
        Write-UiLog "Imported $($imported.Count) collection(s): $names"
        Set-UiStatus "Imported $($imported.Count) collection(s)."
        Show-UiMessage "Imported $($imported.Count) collection(s): $names" 'Import Complete'
    } catch {
        Write-UiLog "Collection import failed: $($_.Exception.Message)"
        Show-UiMessage "Import failed: $($_.Exception.Message)" 'Import Error' 'Error'
    }
}

function Invoke-MenuExportWorkspace {
    $options = @(
        @{ Name = 'Environments'; Text = 'Environments';             Checked = $true; Enabled = ($script:environments -and $script:environments.Count -gt 0) },
        @{ Name = 'History';      Text = 'Request history';          Checked = $true; Enabled = ($script:history -and @($script:history).Count -gt 0) },
        @{ Name = 'Globals';      Text = 'Global variables';         Checked = $true; Enabled = ($script:globals -and $script:globals.Count -gt 0) },
        @{ Name = 'Collections';  Text = 'Collections';              Checked = $true; Enabled = ($script:collections -and @($script:collections).Count -gt 0) }
    )
    $chosen = Show-OptionsDialog -Owner (Get-MainWindow) -Title 'Export Workspace' -Message 'Choose what to include. Application settings are always included (passwords and tokens are left out).' `
        -Options $options -ConfirmText 'Export...' -Note 'The workspace file is not encrypted. Variables marked secret are left out; other values are exported as they are.'
    if (-not $chosen) { return }

    $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
    $saveDialog.Title = 'Export Workspace'
    $saveDialog.Filter = 'API Tester Workspace (*.apw)|*.apw'
    $saveDialog.DefaultExt = 'apw'
    $saveDialog.FileName = 'api_tester_workspace.apw'
    if (Test-Path $configDir) { $saveDialog.InitialDirectory = $configDir }
    if ($saveDialog.ShowDialog((Get-MainWindow)) -ne $true) { return }
    try {
        Export-WorkspaceFile -FilePath $saveDialog.FileName -Include $chosen
        Write-UiLog "Workspace exported to $($saveDialog.FileName)"
        Show-UiMessage 'Workspace exported successfully.' 'Export Complete'
    } catch {
        Write-UiLog "Workspace export failed: $($_.Exception.Message)"
        Show-UiMessage "Failed to export workspace: $($_.Exception.Message)" 'Export Error' 'Error'
    }
}

function Invoke-MenuImportWorkspace {
    $openDialog = New-Object Microsoft.Win32.OpenFileDialog
    $openDialog.Title = 'Import Workspace'
    $openDialog.Filter = 'API Tester Workspace (*.apw)|*.apw|All files (*.*)|*.*'
    if (Test-Path $configDir) { $openDialog.InitialDirectory = $configDir }
    if ($openDialog.ShowDialog((Get-MainWindow)) -ne $true) { return }
    try {
        $workspace = Get-Content -Path $openDialog.FileName -Raw | ConvertFrom-Json
        $names = @($workspace.PSObject.Properties.Name)
        if ($names -notcontains 'Settings') { Show-UiMessage 'The selected file is not a valid workspace file.' 'Import Error' 'Error'; return }

        $options = @(
            @{ Name = 'Settings';     Text = 'Settings';          Checked = $true; Enabled = ($names -contains 'Settings') },
            @{ Name = 'Environments'; Text = 'Environments';      Checked = $true; Enabled = ($names -contains 'Environments') },
            @{ Name = 'History';      Text = 'Request history';   Checked = $true; Enabled = ($names -contains 'History') },
            @{ Name = 'Globals';      Text = 'Global variables';  Checked = $true; Enabled = ($names -contains 'Globals') },
            @{ Name = 'Collections';  Text = 'Collections';       Checked = $true; Enabled = ($names -contains 'Collections') }
        )
        $chosen = Show-OptionsDialog -Owner (Get-MainWindow) -Title 'Import Workspace' -Message 'Choose which parts of the workspace to import. Existing data of the same kind is replaced.' `
            -Options $options -ConfirmText 'Import' -Note 'Passwords and tokens in your current settings are kept.'
        if (-not $chosen) { return }

        Import-WorkspaceData -Workspace $workspace -Include $chosen
        Update-EnvironmentChoices
        Update-CollectionsTree
        Update-HistoryList
        Update-UiFromSettings
        Write-UiLog "Workspace imported from $($openDialog.FileName)"
        Set-UiStatus 'Workspace imported.'
        Set-AppThemeLive -ThemeName ([string]$script:settings.AppTheme)
        Show-UiMessage 'Workspace imported.' 'Import Successful'
        Complete-ThemeSwitch
    } catch {
        Write-UiLog "Workspace import failed: $($_.Exception.Message)"
        Show-UiMessage "Failed to import workspace: $($_.Exception.Message)" 'Import Error' 'Error'
    }
}

function Invoke-MenuResetLayout {
    $window = Get-MainWindow
    $controls = $script:MainWindowContext.Controls
    $window.WindowState = [System.Windows.WindowState]::Normal
    $workArea = Get-WindowWorkArea -Reference $window
    $window.Width = [Math]::Min(1440, $workArea.Width - 24)
    $window.Height = [Math]::Min(900, $workArea.Height - 24)
    $script:settings.WindowBounds = $null
    $window.Left = $workArea.Left + [Math]::Max(0, ($workArea.Width - $window.Width) / 2)
    $window.Top = $workArea.Top + [Math]::Max(0, ($workArea.Height - $window.Height) / 2)
    Set-SidebarDocked -Docked $true
    $controls.SidebarColumn.Width = [System.Windows.GridLength]::new(310)
    Set-ResponseDock -Dock 'Right'
    $script:settings.ResponseDockState = 'Right'
    Save-Settings
    $controls.WrapBox.IsChecked = $false
    Set-UiStatus 'Layout reset to defaults.'
}

function Invoke-MenuSettings {
    $script:themeAppliedLive = $true
    if (Show-SettingsDialog) {
        Update-UiFromSettings
        Write-UiLog 'Settings saved.'
        Set-UiStatus 'Settings saved.'
        Complete-ThemeSwitch
    }
}

function Invoke-MenuGlobalVariables {
    $current = if ($script:globals) { $script:globals } else { @{} }
    $edited = Show-VariablesDialog -Title 'Global Variables' -Variables $current -SecretNames @($script:settings.SecretGlobalNames)
    if ($null -eq $edited) { return }
    $script:globals = $edited.Variables
    $script:settings.SecretGlobalNames = @($edited.SecretNames)
    Save-Settings
    Save-Globals
    Update-ExtractVariableChoices
    Update-AllCodeHighlights -Except 'ResponseBody'
    Set-UiStatus 'Global variables updated.'
}

function Invoke-MenuLoadTester {
    $state = Get-EditorState
    $headerTable = @{}
    foreach ($entry in (ConvertFrom-HeaderText -HeaderText (Expand-Variables -InputString $state.Headers))) { $headerTable[$entry.Name] = $entry.Value }
    $currentRequest = [PSCustomObject]@{ Url = (Expand-Variables -InputString $state.Url); Method = $state.Method; Headers = $headerTable; Body = (Expand-Variables -InputString $state.Body) }
    Show-LoadTestDialog -RequestObject $currentRequest
}

function Register-MainMenuHandlers {
    param([Parameter(Mandatory = $true)]$Controls)

    # Menu
    $Controls.MenuImportCurl.Add_Click({ Invoke-MenuImportCurl })
    $Controls.MenuImportPostman.Add_Click({ Invoke-MenuImportCollection })
    $Controls.MenuImportWorkspace.Add_Click({ Invoke-MenuImportWorkspace })
    $Controls.MenuExportWorkspace.Add_Click({ Invoke-MenuExportWorkspace })
    $Controls.MenuResetLayout.Add_Click({ Invoke-MenuResetLayout })
    $Controls.MenuSettings.Add_Click({ Invoke-MenuSettings })
    $Controls.MenuExit.Add_Click({ (Get-MainWindow).Close() })

    # Tools
    $Controls.MenuEnvironments.Add_Click({ Invoke-UiGuard { Show-EnvironmentManager } 'Environments' })
    $Controls.MenuTemplates.Add_Click({ Invoke-UiGuard { Show-RequestTemplatesDialog } 'Templates' })
    $Controls.MenuGlobalVariables.Add_Click({ Invoke-MenuGlobalVariables })
    $Controls.MenuProxy.Add_Click({ Show-ProxySettings -parentForm (Get-MainWindow) })
    $Controls.MenuCookieJar.Add_Click({ Invoke-UiGuard { Show-CookieJarDialog } 'Cookie jar' })
    $Controls.MenuJwt.Add_Click({ Invoke-UiGuard { Show-JwtDialog } 'JWT utility' })
    $Controls.MenuReport.Add_Click({ Invoke-UiGuard { Show-ReportDialog } 'Report' })
    $Controls.MenuWebSocket.Add_Click({ Invoke-UiGuard { Show-WebSocketDialog } 'WebSocket client' })
    $Controls.MenuGrpc.Add_Click({ Invoke-UiGuard { Show-GrpcDialog } 'gRPC client' })
    $Controls.MenuLoadTester.Add_Click({ Invoke-UiGuard { Invoke-MenuLoadTester } 'Load tester' })

    # Monitor
    $Controls.MenuMonitorManager.Add_Click({ Invoke-UiGuard { Show-MonitorManagerWindow } 'Monitor manager' })
    $Controls.MenuMonitorDashboard.Add_Click({ Invoke-UiGuard { Show-MonitoringDashboardWindow } 'Monitoring dashboard' })
    $Controls.MenuMonitorBrowser.Add_Click({ Invoke-UiGuard { Open-MonitorDashboardInBrowser } 'Open monitors in browser' })

    # Help
    $Controls.MenuAbout.Add_Click({ Invoke-UiGuard { Show-AboutWindow } 'About' })
    $Controls.MenuShortcuts.Add_Click({ Invoke-UiGuard { Show-ShortcutEditorDialog } 'Keyboard shortcuts' })

    Update-ImportMenuVisibility
}
#endregion
