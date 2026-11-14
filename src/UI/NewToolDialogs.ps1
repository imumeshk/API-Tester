#region XAML tool dialogs (Settings, Log viewer, Cookie jar, JWT, About, Diff viewer, Report)

# ------------------------------------------------------------------------------------------------
# Settings
# ------------------------------------------------------------------------------------------------

function Show-SettingsDialog {
    $checkGroups = @(
        @{ Title = 'UI & panel visibility'; Items = @(
            @('ShowEnvironmentPanel', 'Environment panel'), @('ShowHistory', 'History panel'), @('ShowRequestHeadersTab', 'Request headers tab'),
            @('ShowAuthTab', 'Authentication tab'), @('ShowPreRequestTab', 'Pre-request script tab'), @('ShowTestsTab', 'Tests tab'),
            @('ShowTestResultsTab', 'Test results tab'), @('ShowResponse', 'Response panel'), @('ShowJsonTreeTab', 'JSON tree tab'),
            @('ShowResponseHeaders', 'Response headers tab'), @('ShowCurl', 'Code snippets tab'), @('ShowConsoleTab', 'Console tab')) },
        @{ Title = 'Configuration'; Items = @(
            @('EnableLogs', 'Enable logging'), @('EnableHistory', 'Enable history tracking'), @('AutoRunHistory', 'Auto-run on history double-click'),
            @('EnableAllMethods', 'Allow all request methods'), @('IgnoreSslErrors', 'Ignore SSL errors'), @('EnablePostmanImport', 'Enable Postman import'),
            @('EnableCurlImport', 'Enable cURL import'), @('EnableRepeatRequest', 'Enable repeat request'), @('RestoreRequestTabs', 'Restore request tabs from the last session'),
            @('HistorySaveResponses', 'Save responses in history'), @('CheckForUpdatesOnStartup', 'Check for updates at start-up')) }
    )
    $checkKeys = @($checkGroups | ForEach-Object { $_.Items } | ForEach-Object { $_[0] }) + @('AutoSaveToFile', 'AutoRenameFile', 'EnableAutoRenamePrefix')

    $groupXaml = foreach ($group in $checkGroups) {
        # Text is XML-escaped: a raw '&' (as in "UI & panel visibility") makes the XAML invalid.
        $boxes = foreach ($item in $group.Items) { "<CheckBox x:Name=`"Chk$($item[0])`" Content=`"$([System.Security.SecurityElement]::Escape($item[1]))`" Width=`"235`" Margin=`"0,4,8,4`"/>" }
        "<Border Background=`"{StaticResource Surface}`" BorderBrush=`"{StaticResource Border}`" BorderThickness=`"1`" CornerRadius=`"8`" Padding=`"14,10`" Margin=`"0,0,0,12`"><StackPanel><TextBlock Style=`"{StaticResource SectionLabel}`" Text=`"$([System.Security.SecurityElement]::Escape($group.Title.ToUpper()))`"/><WrapPanel Margin=`"0,6,0,0`">$($boxes -join '')</WrapPanel></StackPanel></Border>"
    }
    $body = @"
  <Grid Margin="22,16,22,16">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="Settings" FontSize="22" FontWeight="SemiBold" Foreground="{StaticResource Primary}" Margin="0,0,0,10"/>
    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
      <StackPanel Margin="0,0,10,0">
        $($groupXaml -join "`n")
        <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="14,10" Margin="0,0,0,12">
          <WrapPanel>
            <StackPanel Margin="0,0,24,8"><TextBlock Style="{StaticResource SectionLabel}" Text="APP THEME"/><ComboBox x:Name="CmbAppTheme" Width="170" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
            <StackPanel Margin="0,0,24,8"><TextBlock Style="{StaticResource SectionLabel}" Text="LOG LEVEL"/><ComboBox x:Name="CmbLogLevel" Width="120" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
            <StackPanel Margin="0,0,24,8"><TextBlock Style="{StaticResource SectionLabel}" Text="DEFAULT CONSOLE LANGUAGE"/><ComboBox x:Name="CmbDefaultConsoleLanguage" Width="200" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
            <StackPanel Margin="0,0,24,8"><TextBlock Style="{StaticResource SectionLabel}" Text="TIMEOUT (SECONDS)"/><TextBox x:Name="TxtRequestTimeoutSeconds" Width="90" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
            <StackPanel Margin="0,0,24,8"><TextBlock Style="{StaticResource SectionLabel}" Text="RESPONSE FONT SIZE (8-72)"/><TextBox x:Name="TxtResponseFontSize" Width="90" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
            <StackPanel Margin="0,0,24,8"><TextBlock Style="{StaticResource SectionLabel}" Text="MAX REPEATS (1-100)"/><TextBox x:Name="TxtMaxRepeatCount" Width="90" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
          </WrapPanel>
        </Border>
        <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="14,10">
          <StackPanel>
            <TextBlock Style="{StaticResource SectionLabel}" Text="AUTO-SAVE &amp; RENAMING"/>
            <CheckBox x:Name="ChkAutoSaveToFile" Content="Auto-save downloaded files (binary or attachment responses) to a folder" Margin="0,8,0,6"/>
            <DockPanel Margin="0,0,0,6"><Button x:Name="BrowseAutoSaveButton" DockPanel.Dock="Right" Margin="8,0,0,0" Padding="14,3" Content="Browse..."/><TextBox x:Name="TxtAutoSavePath" Height="28" VerticalContentAlignment="Center"/></DockPanel>
            <CheckBox x:Name="ChkAutoRenameFile" Content="Name saved files after the uploaded file(s)" Margin="0,4,0,6"/>
            <DockPanel><CheckBox x:Name="ChkEnableAutoRenamePrefix" Content="Prefix:" VerticalAlignment="Center" Margin="0,0,8,0"/><TextBox x:Name="TxtAutoRenamePrefix" Height="28" Width="240" HorizontalAlignment="Left" VerticalContentAlignment="Center"/></DockPanel>
          </StackPanel>
        </Border>
      </StackPanel>
    </ScrollViewer>
    <DockPanel Grid.Row="2" Margin="0,14,0,0">
      <StackPanel DockPanel.Dock="Left" Orientation="Horizontal">
        <Button x:Name="RestoreButton" Padding="14,6" Margin="0,0,8,0" Content="Restore defaults"/>
        <Button x:Name="ViewLogsButton" Padding="14,6" Margin="0,0,8,0" Content="View logs"/>
        <Button x:Name="OpenLogsButton" Padding="14,6" Margin="0,0,8,0" Content="Open logs folder"/>
        <Button x:Name="ClearLogsButton" Padding="14,6" Content="Clear logs"/>
      </StackPanel>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <TextBlock x:Name="SettingsStatus" VerticalAlignment="Center" Margin="0,0,12,0" Foreground="#D93025"/>
        <Button x:Name="SaveButton" Style="{StaticResource PrimaryButton}" Width="100" Content="Save"/>
        <Button x:Name="CancelButton" IsCancel="True" Width="90" Margin="10,0,0,0" Content="Cancel"/>
      </StackPanel>
    </DockPanel>
  </Grid>
"@
    $names = @($checkKeys | ForEach-Object { "Chk$_" }) + @('CmbAppTheme', 'CmbLogLevel', 'CmbDefaultConsoleLanguage', 'TxtRequestTimeoutSeconds', 'TxtResponseFontSize', 'TxtMaxRepeatCount', 'TxtAutoSavePath', 'TxtAutoRenamePrefix',
        'BrowseAutoSaveButton', 'RestoreButton', 'ViewLogsButton', 'OpenLogsButton', 'ClearLogsButton', 'SettingsStatus', 'SaveButton', 'CancelButton')
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title 'Settings' -Width 940 -Height 820
    $window = $dialog.Window; $controls = $dialog.Controls
    $script:settingsDialogSaved = $false

    foreach ($theme in @($script:Themes.Keys | Sort-Object)) { [void]$controls['CmbAppTheme'].Items.Add($theme) }
    foreach ($level in @('Info', 'Debug')) { [void]$controls['CmbLogLevel'].Items.Add($level) }
    foreach ($language in @('PowerShell', 'JavaScript (Node.js)', 'Python', 'PHP', 'Ruby', 'Go', 'Batch', 'Bash')) { [void]$controls['CmbDefaultConsoleLanguage'].Items.Add($language) }

    $loadFrom = {
        param($Source)
        foreach ($key in $checkKeys) { $controls["Chk$key"].IsChecked = [bool]$Source[$key] }
        $controls['CmbAppTheme'].SelectedItem = if ($Source['AppTheme'] -and $controls['CmbAppTheme'].Items.Contains($Source['AppTheme'])) { $Source['AppTheme'] } else { 'Light' }
        $controls['CmbLogLevel'].SelectedItem = if ($Source['LogLevel']) { $Source['LogLevel'] } else { 'Info' }
        $controls['CmbDefaultConsoleLanguage'].SelectedItem = if ($Source['DefaultConsoleLanguage']) { $Source['DefaultConsoleLanguage'] } else { 'PowerShell' }
        $controls['TxtRequestTimeoutSeconds'].Text = [string]$Source['RequestTimeoutSeconds']
        $controls['TxtResponseFontSize'].Text = [string]$Source['ResponseFontSize']
        $controls['TxtMaxRepeatCount'].Text = [string]$Source['MaxRepeatCount']
        $controls['TxtAutoSavePath'].Text = [string]$Source['AutoSavePath']
        $controls['TxtAutoRenamePrefix'].Text = [string]$Source['AutoRenamePrefix']
    }
    & $loadFrom $script:settings

    # Dependent controls
    $updateDependencies = {
        $historyOn = [bool]$controls['ChkEnableHistory'].IsChecked
        $controls['ChkShowHistory'].IsEnabled = $historyOn; $controls['ChkAutoRunHistory'].IsEnabled = $historyOn
        $controls['CmbLogLevel'].IsEnabled = [bool]$controls['ChkEnableLogs'].IsChecked
        $controls['TxtAutoSavePath'].IsEnabled = [bool]$controls['ChkAutoSaveToFile'].IsChecked; $controls['BrowseAutoSaveButton'].IsEnabled = [bool]$controls['ChkAutoSaveToFile'].IsChecked
        $controls['TxtAutoRenamePrefix'].IsEnabled = [bool]$controls['ChkEnableAutoRenamePrefix'].IsChecked
        $controls['TxtMaxRepeatCount'].IsEnabled = [bool]$controls['ChkEnableRepeatRequest'].IsChecked
    }
    foreach ($key in @('EnableHistory', 'EnableLogs', 'AutoSaveToFile', 'EnableAutoRenamePrefix', 'EnableRepeatRequest')) { $controls["Chk$key"].Add_Click($updateDependencies) }
    & $updateDependencies

    $controls['BrowseAutoSaveButton'].Add_Click({
        $picker = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($controls['TxtAutoSavePath'].Text -and (Test-Path $controls['TxtAutoSavePath'].Text)) { $picker.SelectedPath = $controls['TxtAutoSavePath'].Text }
        if ($picker.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $controls['TxtAutoSavePath'].Text = $picker.SelectedPath }
    })
    $controls['RestoreButton'].Add_Click({
        $answer = [System.Windows.MessageBox]::Show($window, 'Restore all settings to their defaults?', 'Restore defaults', 'YesNo', 'Warning')
        if ($answer -eq 'Yes') { & $loadFrom $script:defaultSettings; & $updateDependencies }
    })
    $controls['ViewLogsButton'].Add_Click({ Show-LogViewerDialog -Owner $window })
    $controls['OpenLogsButton'].Add_Click({
        if (Test-Path $logsDir) { Invoke-Item $logsDir } else { [void][System.Windows.MessageBox]::Show($window, 'Logs folder not found.', 'Open logs', 'OK', 'Information') }
    })
    $controls['ClearLogsButton'].Add_Click({
        if ([System.Windows.MessageBox]::Show($window, 'Clear the log file?', 'Clear logs', 'YesNo', 'Warning') -ne 'Yes') { return }
        try { Set-Content -Path $logFilePath -Value 'Timestamp,Level,Message' -ErrorAction Stop; $controls['SettingsStatus'].Text = '' } catch { $controls['SettingsStatus'].Text = "Could not clear logs: $($_.Exception.Message)" }
    })
    $controls['SaveButton'].Add_Click({
        $timeout = 0; $fontSize = 0; $repeats = 0
        if ([bool]$controls['ChkEnableAutoRenamePrefix'].IsChecked -and [string]::IsNullOrWhiteSpace($controls['TxtAutoRenamePrefix'].Text)) { $controls['SettingsStatus'].Text = 'Prefix cannot be blank.'; return }
        if ([bool]$controls['ChkAutoSaveToFile'].IsChecked) {
            if ([string]::IsNullOrWhiteSpace($controls['TxtAutoSavePath'].Text)) { $controls['SettingsStatus'].Text = 'Auto-save path cannot be blank.'; return }
            if (-not (Test-Path -Path $controls['TxtAutoSavePath'].Text -PathType Container)) { $controls['SettingsStatus'].Text = 'Auto-save path does not exist.'; return }
        }
        if (-not [int]::TryParse($controls['TxtRequestTimeoutSeconds'].Text, [ref]$timeout) -or $timeout -le 0) { $controls['SettingsStatus'].Text = 'Invalid timeout.'; return }
        if (-not [int]::TryParse($controls['TxtResponseFontSize'].Text, [ref]$fontSize) -or $fontSize -lt 8 -or $fontSize -gt 72) { $controls['SettingsStatus'].Text = 'Font size must be 8-72.'; return }
        if (-not [int]::TryParse($controls['TxtMaxRepeatCount'].Text, [ref]$repeats) -or $repeats -lt 1 -or $repeats -gt 100) { $controls['SettingsStatus'].Text = 'Max repeats must be 1-100.'; return }
        foreach ($key in $checkKeys) { $script:settings[$key] = [bool]$controls["Chk$key"].IsChecked }
        $previousTheme = [string]$script:settings.AppTheme
        $script:settings.AppTheme = [string]$controls['CmbAppTheme'].SelectedItem
        if ($script:settings.AppTheme -ne $previousTheme) { Set-AppThemeLive -ThemeName $script:settings.AppTheme }
        $script:settings.LogLevel = [string]$controls['CmbLogLevel'].SelectedItem
        $script:settings.DefaultConsoleLanguage = [string]$controls['CmbDefaultConsoleLanguage'].SelectedItem
        $script:settings.RequestTimeoutSeconds = $timeout; $script:settings.ResponseFontSize = $fontSize; $script:settings.MaxRepeatCount = $repeats
        $script:settings.AutoSavePath = $controls['TxtAutoSavePath'].Text; $script:settings.AutoRenamePrefix = $controls['TxtAutoRenamePrefix'].Text
        Save-Settings
        $script:settingsDialogSaved = $true
        $window.DialogResult = $true
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
    return $script:settingsDialogSaved
}

# ------------------------------------------------------------------------------------------------
# Log viewer
# ------------------------------------------------------------------------------------------------

function Show-LogViewerDialog {
    param($Owner)
    if (-not (Test-Path $logFilePath)) { [void][System.Windows.MessageBox]::Show($Owner, 'No log file found yet.', 'Log viewer', 'OK', 'Information'); return }
    $body = @'
  <Grid Margin="18,14,18,14">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="Application log" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <WrapPanel Grid.Row="1" Margin="0,10,0,8">
      <TextBox x:Name="FilterBox" Width="300" Height="28" VerticalContentAlignment="Center" Margin="0,0,8,0" ToolTip="Filter by message text"/>
      <ComboBox x:Name="LevelBox" Width="120" Height="28" VerticalContentAlignment="Center" Margin="0,0,8,0"/>
      <Button x:Name="RefreshButton" Style="{StaticResource SmallButton}" Content="Refresh"/>
      <TextBlock x:Name="CountText" VerticalAlignment="Center" Foreground="{StaticResource Muted}"/>
    </WrapPanel>
    <DataGrid x:Name="LogGrid" Grid.Row="2" AutoGenerateColumns="False" IsReadOnly="True" HeadersVisibility="Column" GridLinesVisibility="Horizontal" Background="Transparent" RowBackground="Transparent">
      <DataGrid.Columns>
        <DataGridTextColumn Header="Time" Binding="{Binding C1}" Width="160"/>
        <DataGridTextColumn Header="Level" Binding="{Binding C2}" Width="70"/>
        <DataGridTextColumn Header="Message" Binding="{Binding C3}" Width="*"/>
      </DataGrid.Columns>
    </DataGrid>
    <Button x:Name="CloseButton" Grid.Row="3" HorizontalAlignment="Right" IsCancel="True" Width="90" Margin="0,12,0,0" Content="Close"/>
  </Grid>
'@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'FilterBox', 'LevelBox', 'RefreshButton', 'CountText', 'LogGrid', 'CloseButton' -Title 'Log viewer' -Width 960 -Height 640
    $window = $dialog.Window; $controls = $dialog.Controls
    foreach ($level in @('All levels', 'Info', 'Debug', 'Error')) { [void]$controls['LevelBox'].Items.Add($level) }
    $controls['LevelBox'].SelectedIndex = 0
    $script:logRowsAll = @()
    $load = {
        try { $script:logRowsAll = @(Import-Csv -Path $logFilePath | Select-Object -Last 5000) } catch { $script:logRowsAll = @() }
        & $apply
    }
    $apply = {
        $level = [string]$controls['LevelBox'].SelectedItem; $text = $controls['FilterBox'].Text
        $rows = @($script:logRowsAll)
        if ($level -and $level -ne 'All levels') { $rows = @($rows | Where-Object { $_.Level -eq $level }) }
        if ($text) { $rows = @($rows | Where-Object { $_.Message -like "*$text*" -or $_.Level -like "*$text*" }) }
        $display = New-Object 'System.Collections.ObjectModel.ObservableCollection[SimpleRow]'
        foreach ($row in $rows) { $item = New-Object SimpleRow; $item.C1 = [string]$row.Timestamp; $item.C2 = [string]$row.Level; $item.C3 = [string]$row.Message; $display.Add($item) }
        $controls['LogGrid'].ItemsSource = $display
        $controls['CountText'].Text = "   $($display.Count) of $($script:logRowsAll.Count) entries"
    }
    $controls['FilterBox'].Add_TextChanged({ & $apply })
    $controls['LevelBox'].Add_SelectionChanged({ & $apply })
    $controls['RefreshButton'].Add_Click({ & $load })
    & $load
    [void](Show-WpfDialog -Window $window -OwnerForm $Owner)
}

# ------------------------------------------------------------------------------------------------
# Cookie jar
# ------------------------------------------------------------------------------------------------

function Show-CookieJarDialog {
    $body = @'
  <Grid Margin="18,14,18,14">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="Cookie jar" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}" Margin="0,0,0,10"/>
    <DataGrid x:Name="CookieGrid" Grid.Row="1" AutoGenerateColumns="False" IsReadOnly="True" HeadersVisibility="Column" SelectionMode="Extended" GridLinesVisibility="Horizontal" Background="Transparent" RowBackground="Transparent">
      <DataGrid.Columns>
        <DataGridTextColumn Header="Domain" Binding="{Binding C1}" Width="160"/><DataGridTextColumn Header="Name" Binding="{Binding C2}" Width="140"/>
        <DataGridTextColumn Header="Value" Binding="{Binding C3}" Width="*"/><DataGridTextColumn Header="Path" Binding="{Binding C4}" Width="80"/>
        <DataGridTextColumn Header="Expires" Binding="{Binding C5}" Width="150"/>
      </DataGrid.Columns>
    </DataGrid>
    <WrapPanel Grid.Row="2" Margin="0,12,0,0" HorizontalAlignment="Right">
      <Button x:Name="ImportButton" Margin="0,0,8,0" Padding="14,6" Content="Import..."/>
      <Button x:Name="ExportButton" Margin="0,0,8,0" Padding="14,6" Content="Export..."/>
      <Button x:Name="DeleteSelectedButton" Margin="0,0,8,0" Padding="14,6" Content="Delete selected"/>
      <Button x:Name="ClearAllButton" Margin="0,0,8,0" Padding="14,6" Content="Clear all"/>
      <Button x:Name="CloseButton" IsCancel="True" Padding="14,6" Content="Close"/>
    </WrapPanel>
  </Grid>
'@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'CookieGrid', 'ImportButton', 'ExportButton', 'DeleteSelectedButton', 'ClearAllButton', 'CloseButton' -Title 'Cookie jar' -Width 880 -Height 520
    $window = $dialog.Window; $controls = $dialog.Controls
    if (-not $script:cookieJar) { $script:cookieJar = New-Object System.Collections.ArrayList }
    $refresh = {
        $rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[SimpleRow]'
        foreach ($cookie in $script:cookieJar) {
            $row = New-Object SimpleRow
            $row.C1 = [string]$cookie.Domain; $row.C2 = [string]$cookie.Name; $row.C3 = [string]$cookie.Value; $row.C4 = [string]$cookie.Path; $row.C5 = [string]$cookie.Expires; $row.Item = $cookie
            $rows.Add($row)
        }
        $controls['CookieGrid'].ItemsSource = $rows
    }
    & $refresh
    $controls['ClearAllButton'].Add_Click({ $script:cookieJar.Clear(); & $refresh })
    $controls['DeleteSelectedButton'].Add_Click({ foreach ($row in @($controls['CookieGrid'].SelectedItems)) { $script:cookieJar.Remove($row.Item) }; & $refresh })
    $controls['ExportButton'].Add_Click({
        $picker = New-Object Microsoft.Win32.SaveFileDialog; $picker.Filter = 'JSON files (*.json)|*.json'; $picker.FileName = 'cookies.json'
        if ($picker.ShowDialog($window) -ne $true) { return }
        try { @($script:cookieJar) | ConvertTo-Json -Depth 5 | Set-Content -Path $picker.FileName; [void][System.Windows.MessageBox]::Show($window, 'Cookies exported.', 'Cookie jar', 'OK', 'Information') }
        catch { [void][System.Windows.MessageBox]::Show($window, "Failed to export cookies: $($_.Exception.Message)", 'Cookie jar', 'OK', 'Error') }
    })
    $controls['ImportButton'].Add_Click({
        $picker = New-Object Microsoft.Win32.OpenFileDialog; $picker.Filter = 'JSON files (*.json)|*.json'
        if ($picker.ShowDialog($window) -ne $true) { return }
        try {
            $imported = @(Get-Content -Path $picker.FileName -Raw | ConvertFrom-Json)
            $script:cookieJar.Clear()
            foreach ($entry in $imported) {
                if (-not $entry.Name) { continue }
                [void]$script:cookieJar.Add([PSCustomObject]@{ Name = $entry.Name; Value = $entry.Value; Domain = $entry.Domain; Path = $(if ($entry.Path) { $entry.Path } else { '/' }); Expires = [string]$entry.Expires })
            }
            & $refresh
        } catch { [void][System.Windows.MessageBox]::Show($window, "Failed to import cookies: $($_.Exception.Message)", 'Cookie jar', 'OK', 'Error') }
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}

# ------------------------------------------------------------------------------------------------
# JWT utility
# ------------------------------------------------------------------------------------------------

function ConvertFrom-Base64UrlText {
    param([string]$Text)
    $padded = $Text.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) { 2 { $padded += '==' } 3 { $padded += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
}

function ConvertTo-Base64UrlText {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function Show-JwtDialog {
    $body = @'
  <TabControl Margin="14" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}">
    <TabItem Header="Decoder">
      <Grid Margin="12">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="1*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="1.4*"/></Grid.RowDefinitions>
        <TextBlock Style="{StaticResource SectionLabel}" Text="JWT"/>
        <TextBox x:Name="JwtInputBox" Grid.Row="1" Margin="0,6,0,8" TextWrapping="Wrap" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/>
        <DockPanel Grid.Row="2" Margin="0,0,0,8">
          <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" Margin="8,0,0,0">
            <Button x:Name="VerifyButton" Margin="0,0,6,0" Padding="14,5" Content="Verify signature"/>
            <Button x:Name="DecodeButton" Style="{StaticResource PrimaryButton}" Margin="0,0,6,0" Padding="14,5" Content="Decode"/>
            <Button x:Name="ClearJwtButton" Padding="14,5" Content="Clear"/>
          </StackPanel>
          <TextBlock Text="Secret" VerticalAlignment="Center" Margin="0,0,8,0"/>
          <PasswordBox x:Name="VerifySecretBox" Height="28" VerticalContentAlignment="Center"/>
        </DockPanel>
        <TextBlock x:Name="VerifyResultText" Grid.Row="3" Margin="0,0,0,6" FontWeight="SemiBold"/>
        <TextBox x:Name="JwtOutputBox" Grid.Row="4" IsReadOnly="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
      </Grid>
    </TabItem>
    <TabItem Header="Generator (HS256)">
      <Grid Margin="12">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="1.2*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="1*"/></Grid.RowDefinitions>
        <TextBlock Style="{StaticResource SectionLabel}" Text="PAYLOAD (JSON)"/>
        <TextBox x:Name="PayloadBox" Grid.Row="1" Margin="0,6,0,8" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/>
        <DockPanel Grid.Row="2" Margin="0,0,0,8"><TextBlock Text="Secret" VerticalAlignment="Center" Margin="0,0,8,0"/><TextBox x:Name="GenSecretBox" Height="28" VerticalContentAlignment="Center"/></DockPanel>
        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,0,0,8">
          <Button x:Name="GenerateButton" Style="{StaticResource PrimaryButton}" Padding="16,6" Margin="0,0,8,0" Content="Generate JWT"/>
          <Button x:Name="CopyJwtButton" Padding="16,6" Content="Copy"/>
        </StackPanel>
        <TextBox x:Name="GeneratedBox" Grid.Row="4" IsReadOnly="True" TextWrapping="Wrap" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/>
      </Grid>
    </TabItem>
  </TabControl>
'@
    $names = 'JwtInputBox', 'VerifyButton', 'DecodeButton', 'ClearJwtButton', 'VerifySecretBox', 'VerifyResultText', 'JwtOutputBox', 'PayloadBox', 'GenSecretBox', 'GenerateButton', 'CopyJwtButton', 'GeneratedBox'
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title 'JWT utility' -Width 900 -Height 680
    $window = $dialog.Window; $controls = $dialog.Controls
    $controls['PayloadBox'].Text = '{ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 }'
    $controls['GenSecretBox'].Text = 'secret'
    $jwtPattern = '^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$'

    $controls['DecodeButton'].Add_Click({
        $token = $controls['JwtInputBox'].Text.Trim()
        $controls['VerifyResultText'].Text = ''
        if ($token -notmatch $jwtPattern) { $controls['JwtOutputBox'].Text = 'Invalid JWT format.'; return }
        $parts = $token.Split('.')
        try {
            $header = ConvertFrom-Base64UrlText $parts[0] | ConvertFrom-Json | ConvertTo-Json
            $payload = ConvertFrom-Base64UrlText $parts[1] | ConvertFrom-Json | ConvertTo-Json
            $controls['JwtOutputBox'].Text = "HEADER:`r`n$header`r`n`r`nPAYLOAD:`r`n$payload`r`n`r`nSIGNATURE:`r`n$($parts[2])"
        } catch { $controls['JwtOutputBox'].Text = "Error decoding JWT: $($_.Exception.Message)" }
    })
    $controls['VerifyButton'].Add_Click({
        $token = $controls['JwtInputBox'].Text.Trim(); $secret = $controls['VerifySecretBox'].Password
        $brushes = [System.Windows.Media.Brushes]
        if (-not $token -or -not $secret) { $controls['VerifyResultText'].Text = 'Enter the JWT and the secret.'; $controls['VerifyResultText'].Foreground = $brushes::DarkOrange; return }
        if ($token -notmatch $jwtPattern) { $controls['VerifyResultText'].Text = 'Invalid JWT format.'; $controls['VerifyResultText'].Foreground = $brushes::Firebrick; return }
        $parts = $token.Split('.')
        try {
            $algorithm = (ConvertFrom-Base64UrlText $parts[0] | ConvertFrom-Json).alg
            if ($algorithm -ne 'HS256') { $controls['VerifyResultText'].Text = "Only HS256 is supported (token uses $algorithm)."; $controls['VerifyResultText'].Foreground = $brushes::DarkOrange; return }
            $hmac = New-Object System.Security.Cryptography.HMACSHA256(, [System.Text.Encoding]::UTF8.GetBytes($secret))
            $calculated = ConvertTo-Base64UrlText $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])"))
            if ($calculated -eq $parts[2]) { $controls['VerifyResultText'].Text = 'Signature verified.'; $controls['VerifyResultText'].Foreground = $brushes::SeaGreen }
            else { $controls['VerifyResultText'].Text = 'Signature does NOT match.'; $controls['VerifyResultText'].Foreground = $brushes::Firebrick }
        } catch { $controls['VerifyResultText'].Text = "Error: $($_.Exception.Message)"; $controls['VerifyResultText'].Foreground = $brushes::Firebrick }
    })
    $controls['ClearJwtButton'].Add_Click({ $controls['JwtInputBox'].Clear(); $controls['JwtOutputBox'].Clear(); $controls['VerifyResultText'].Text = '' })
    $controls['GenerateButton'].Add_Click({
        try {
            $payloadJson = $controls['PayloadBox'].Text; $null = $payloadJson | ConvertFrom-Json
            $header = ConvertTo-Base64UrlText ([System.Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
            $payload = ConvertTo-Base64UrlText ([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
            $hmac = New-Object System.Security.Cryptography.HMACSHA256(, [System.Text.Encoding]::UTF8.GetBytes($controls['GenSecretBox'].Text))
            $signature = ConvertTo-Base64UrlText $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$header.$payload"))
            $controls['GeneratedBox'].Text = "$header.$payload.$signature"
        } catch { $controls['GeneratedBox'].Text = "Error: $($_.Exception.Message)" }
    })
    $controls['CopyJwtButton'].Add_Click({ if ($controls['GeneratedBox'].Text) { [System.Windows.Clipboard]::SetText($controls['GeneratedBox'].Text) } })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}

# ------------------------------------------------------------------------------------------------
# About + update check
# ------------------------------------------------------------------------------------------------

function Show-AboutWindow {
    $body = @'
  <StackPanel>
    <Border Padding="22,18">
      <Border.Background><LinearGradientBrush StartPoint="0,0" EndPoint="1,0"><GradientStop Color="#3659C9" Offset="0"/><GradientStop Color="#243E9E" Offset="1"/></LinearGradientBrush></Border.Background>
      <StackPanel><TextBlock Text="PowerShell API Tester" FontSize="24" FontWeight="SemiBold" Foreground="White"/>
        <TextBlock Text="Feature-rich REST / gRPC API testing tool for Windows" Foreground="#DCE7FF" Margin="0,2,0,0"/></StackPanel>
    </Border>
    <Grid Margin="22,16,22,8">
      <Grid.ColumnDefinitions><ColumnDefinition Width="90"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
      <TextBlock Text="Version" FontWeight="SemiBold" Margin="0,3"/><TextBlock x:Name="VersionText" Grid.Column="1" Margin="0,3"/>
      <TextBlock Grid.Row="1" Text="Author" FontWeight="SemiBold" Margin="0,3"/><TextBlock Grid.Row="1" Grid.Column="1" Text="Umesh Kashyap" Margin="0,3"/>
      <TextBlock Grid.Row="2" Text="License" FontWeight="SemiBold" Margin="0,3"/><TextBlock Grid.Row="2" Grid.Column="1" Text="MIT" Margin="0,3"/>
      <TextBlock Grid.Row="3" Text="GitHub" FontWeight="SemiBold" Margin="0,3"/>
      <TextBlock Grid.Row="3" Grid.Column="1" Margin="0,3"><Hyperlink x:Name="RepoLink"><TextBlock x:Name="RepoText"/></Hyperlink></TextBlock>
      <TextBlock Grid.Row="4" Grid.ColumnSpan="2" Margin="0,10,0,0" TextWrapping="Wrap" Foreground="{StaticResource Muted}" Text="A feature-rich API testing tool built entirely in PowerShell, with a WPF interface."/>
    </Grid>
    <Border BorderBrush="{StaticResource Border}" BorderThickness="0,1,0,0" Margin="22,8,22,0" Padding="0,14,0,0">
      <StackPanel>
        <TextBlock Text="Updates" FontWeight="SemiBold" FontSize="14"/>
        <TextBlock x:Name="UpdateStatusText" Margin="0,6,0,8" TextWrapping="Wrap" Text="Not checked yet."/>
        <StackPanel Orientation="Horizontal">
          <Button x:Name="CheckUpdateButton" Margin="0,0,8,0" Padding="14,5" Content="Check for updates"/>
          <Button x:Name="DownloadUpdateButton" Style="{StaticResource PrimaryButton}" Padding="14,5" Content="Download &amp; update" Visibility="Collapsed"/>
        </StackPanel>
      </StackPanel>
    </Border>
    <Button x:Name="CloseButton" HorizontalAlignment="Right" IsCancel="True" Width="90" Margin="22,14,22,18" Content="Close"/>
  </StackPanel>
'@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'VersionText', 'RepoLink', 'RepoText', 'UpdateStatusText', 'CheckUpdateButton', 'DownloadUpdateButton', 'CloseButton' -Title 'About PowerShell API Tester' -Width 560
    $window = $dialog.Window; $controls = $dialog.Controls
    $controls['VersionText'].Text = "v$($script:AppVersion)"
    $controls['RepoText'].Text = "github.com/$($script:AppGitHubRepo)"
    $controls['RepoLink'].Add_Click({ try { Start-Process "https://github.com/$($script:AppGitHubRepo)" } catch { } })
    $script:aboutRelease = $null
    $controls['CheckUpdateButton'].Add_Click({
        $controls['UpdateStatusText'].Text = 'Checking for updates...'; $controls['DownloadUpdateButton'].Visibility = 'Collapsed'
        Update-UiNow
        $status = Get-UpdateStatus
        $controls['UpdateStatusText'].Text = $status.Message
        $controls['UpdateStatusText'].Foreground = switch ($status.State) { 'Current' { [System.Windows.Media.Brushes]::SeaGreen } 'Available' { [System.Windows.Media.Brushes]::RoyalBlue } default { [System.Windows.Media.Brushes]::Firebrick } }
        if ($status.State -eq 'Available') { $script:aboutRelease = $status.Release; $controls['DownloadUpdateButton'].Visibility = 'Visible' }
    })
    $controls['DownloadUpdateButton'].Add_Click({
        if (-not $script:aboutRelease) { return }
        $controls['UpdateStatusText'].Text = 'Downloading update...'
        Update-UiNow
        $installed = Install-UpdateRelease -Release $script:aboutRelease
        $controls['UpdateStatusText'].Text = $installed.Message
        $controls['UpdateStatusText'].Foreground = if ($installed.Success) { [System.Windows.Media.Brushes]::SeaGreen } else { [System.Windows.Media.Brushes]::Firebrick }
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}

# ------------------------------------------------------------------------------------------------
# Diff viewer (sends both history requests and compares the live responses)
# ------------------------------------------------------------------------------------------------

function Format-ForDiff {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    try { if ($Text.TrimStart() -match '^[\{\[]') { return @((Format-JsonText -Text $Text) -split "`r?`n") } } catch { }
    return @($Text -split "`r?`n")
}

function Show-DiffDialog {
    param($Request1, $Request2, $SavedBody1 = $null, $SavedBody2 = $null)
    $body = @'
  <Grid Margin="18,14,18,14">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="Compare responses" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <Grid Grid.Row="1" Margin="0,8,0,8"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <TextBlock x:Name="OldText" TextTrimming="CharacterEllipsis" FontWeight="SemiBold"/><TextBlock x:Name="NewText" Grid.Column="1" TextTrimming="CharacterEllipsis" FontWeight="SemiBold"/></Grid>
    <ScrollViewer Grid.Row="2" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" Background="{StaticResource Surface}">
      <TextBlock x:Name="DiffText" FontFamily="Consolas" FontSize="13" Margin="8"/>
    </ScrollViewer>
    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <TextBlock x:Name="DiffSummary" VerticalAlignment="Center" Margin="0,0,14,0" Foreground="{StaticResource Muted}"/>
      <Button x:Name="CloseButton" IsCancel="True" Width="90" Content="Close"/>
    </StackPanel>
  </Grid>
'@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'OldText', 'NewText', 'DiffText', 'DiffSummary', 'CloseButton' -Title 'Diff viewer - compare responses' -Width 1000 -Height 700
    $window = $dialog.Window; $controls = $dialog.Controls
    $controls['OldText'].Text = "Old: [$($Request1.Method)] $($Request1.Url)"
    $controls['NewText'].Text = "New: [$($Request2.Method)] $($Request2.Url)"
    $controls['DiffSummary'].Text = 'Sending both requests...'
    $window.Add_ContentRendered({
        $timeout = if ($script:settings.RequestTimeoutSeconds -gt 0) { [int]$script:settings.RequestTimeoutSeconds } else { 60 }
        if ($null -ne $SavedBody1 -and $null -ne $SavedBody2) {
            $first = @{ Success = $true; Body = $SavedBody1 }; $second = @{ Success = $true; Body = $SavedBody2 }
        } else {
            $first = Invoke-HttpRequestSync -Request $Request1 -TimeoutSeconds $timeout
            $second = Invoke-HttpRequestSync -Request $Request2 -TimeoutSeconds $timeout
        }
        $lines1 = Format-ForDiff $(if ($first.Success) { $first.Body } else { "[ERROR] $($first.ErrorMessage)" })
        $lines2 = Format-ForDiff $(if ($second.Success) { $second.Body } else { "[ERROR] $($second.ErrorMessage)" })
        $added = 0; $removed = 0
        foreach ($entry in (Compare-Object -ReferenceObject $lines1 -DifferenceObject $lines2 -IncludeEqual)) {
            $run = New-Object System.Windows.Documents.Run
            switch ($entry.SideIndicator) {
                '==' { $run.Text = "  $($entry.InputObject)`r`n" }
                '<=' { $run.Text = "- $($entry.InputObject)`r`n"; $run.Foreground = [System.Windows.Media.Brushes]::IndianRed; $removed++ }
                '=>' { $run.Text = "+ $($entry.InputObject)`r`n"; $run.Foreground = [System.Windows.Media.Brushes]::MediumSeaGreen; $added++ }
            }
            [void]$controls['DiffText'].Inlines.Add($run)
        }
        $controls['DiffSummary'].Text = "$added added, $removed removed"
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}

# ------------------------------------------------------------------------------------------------
# HTML report from the monitor log
# ------------------------------------------------------------------------------------------------

function Show-ReportDialog {
    if (-not (Test-Path $monitorLogFilePath)) { Show-UiMessage 'No monitor log file found to generate a report.' 'Generate report' 'Information'; return }
    $body = @'
  <Grid Margin="22,18,22,18">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="Customize report" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <StackPanel Grid.Row="1" Margin="0,12,0,8">
      <CheckBox x:Name="SummaryCardsBox" Content="Include summary cards" IsChecked="True" Margin="0,3"/>
      <CheckBox x:Name="MonitorStatsBox" Content="Include monitor statistics table" IsChecked="True" Margin="0,3"/>
    </StackPanel>
    <Border Grid.Row="2" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="12,8">
      <StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="DETAILED LOG COLUMNS"/><StackPanel x:Name="ColumnsPanel" Margin="0,6,0,0"/></StackPanel>
    </Border>
    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="GenerateButton" Style="{StaticResource PrimaryButton}" IsDefault="True" Width="110" Content="Generate"/>
      <Button x:Name="CancelButton" IsCancel="True" Width="90" Margin="10,0,0,0" Content="Cancel"/>
    </StackPanel>
  </Grid>
'@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'SummaryCardsBox', 'MonitorStatsBox', 'ColumnsPanel', 'GenerateButton', 'CancelButton' -Title 'Customize report' -Width 440 -Height 520
    $window = $dialog.Window; $controls = $dialog.Controls
    $columnBoxes = @{}
    foreach ($column in @('Timestamp', 'MonitorName', 'URL', 'Success', 'StatusCode', 'TimeMs', 'Message')) {
        $box = New-Object System.Windows.Controls.CheckBox; $box.Content = $column; $box.IsChecked = $true; $box.Margin = [System.Windows.Thickness]::new(0, 3, 0, 3)
        [void]$controls['ColumnsPanel'].Children.Add($box); $columnBoxes[$column] = $box
    }
    $script:reportOptions = $null
    $controls['GenerateButton'].Add_Click({
        $script:reportOptions = [PSCustomObject]@{
            IncludeSummaryCards = [bool]$controls['SummaryCardsBox'].IsChecked; IncludeMonitorStats = [bool]$controls['MonitorStatsBox'].IsChecked
            DetailedLogColumns = @($columnBoxes.Keys | Where-Object { $columnBoxes[$_].IsChecked } | Sort-Object { @('Timestamp', 'MonitorName', 'URL', 'Success', 'StatusCode', 'TimeMs', 'Message').IndexOf($_) })
        }
        $window.DialogResult = $true
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
    if (-not $script:reportOptions) { return }

    $picker = New-Object Microsoft.Win32.SaveFileDialog
    $picker.Filter = 'HTML report (*.html)|*.html'; $picker.FileName = "API_Test_Report_$((Get-Date).ToString('yyyyMMdd')).html"
    if ($picker.ShowDialog((Get-MainWindow)) -ne $true) { return }
    try {
        $data = @(Import-Csv $monitorLogFilePath)
        if ($data.Count -eq 0) { throw 'The log file is empty.' }
        New-MonitorReportHtml -Data $data -Options $script:reportOptions | Set-Content -Path $picker.FileName -Encoding UTF8
        Start-Process $picker.FileName
    } catch { Show-UiMessage "Failed to generate the report: $($_.Exception.Message)" 'Generate report' 'Error' }
}
#endregion
