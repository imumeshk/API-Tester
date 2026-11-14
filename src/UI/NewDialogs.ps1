#region XAML Main Window - dialogs (variables, environments, templates, save-to-collection, collection runner)

# Shows a small modal XAML dialog built from a header, a body element and OK/Cancel buttons.
# $ControlNames are resolved with FindName; returns @{ Window; Controls }.
function New-DialogWindow {
    param([string]$BodyXaml, [string[]]$ControlNames, [string]$Title, [int]$Width = 520, [int]$Height = 0)
    $heightAttribute = if ($Height -gt 0) { "Height=`"$Height`"" } else { 'SizeToContent="Height"' }
    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Dialog" Width="$Width" $heightAttribute ShowInTaskbar="False" WindowStartupLocation="CenterOwner"
        Background="@FORM@" Foreground="@TEXT@" FontFamily="Segoe UI">
  <Window.Resources><!--APP_RESOURCES--></Window.Resources>
  $BodyXaml
</Window>
"@
    $bundle = New-WpfWindowFromXaml -Xaml $xaml -ControlNames $ControlNames
    $bundle.Window.Title = $Title
    return $bundle
}

# ------------------------------------------------------------------------------------------------
# Variables (name / value / secret grid)
# ------------------------------------------------------------------------------------------------

# XAML for a variables grid; values of secret rows are masked until "Show secret values" is ticked.
function Get-VariablesGridXaml {
    param([string]$Prefix)
    return @"
<DockPanel>
  <WrapPanel DockPanel.Dock="Top" Margin="0,0,0,6">
    <Button x:Name="${Prefix}AddButton" Style="{StaticResource SmallButton}" Content="+ Add variable"/>
    <Button x:Name="${Prefix}RemoveButton" Style="{StaticResource SmallButton}" Content="Remove selected"/>
    <CheckBox x:Name="${Prefix}RevealBox" Content="Show secret values" VerticalAlignment="Center" Margin="8,0,0,0"/>
  </WrapPanel>
  <DataGrid x:Name="${Prefix}Grid" AutoGenerateColumns="False" CanUserAddRows="False" HeadersVisibility="Column" GridLinesVisibility="Horizontal" Background="Transparent" RowBackground="Transparent" SelectionMode="Extended" MinHeight="120">
    <DataGrid.Columns>
      <DataGridTextColumn Header="Name" Binding="{Binding Name, UpdateSourceTrigger=PropertyChanged}" Width="200"/>
      <DataGridTemplateColumn Header="Value" Width="*">
        <DataGridTemplateColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding DisplayValue}" Margin="4,0" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/></DataTemplate></DataGridTemplateColumn.CellTemplate>
        <DataGridTemplateColumn.CellEditingTemplate><DataTemplate><TextBox Text="{Binding Value, UpdateSourceTrigger=PropertyChanged}" BorderThickness="0" Padding="2,0"/></DataTemplate></DataGridTemplateColumn.CellEditingTemplate>
      </DataGridTemplateColumn>
      <DataGridCheckBoxColumn Header="Secret" Binding="{Binding IsSecret, UpdateSourceTrigger=PropertyChanged}" Width="70"/>
    </DataGrid.Columns>
  </DataGrid>
</DockPanel>
"@
}

function New-VariableRows {
    param($Variables, [string[]]$SecretNames = @())
    $rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[VariableRow]'
    $pairs = if ($Variables -is [System.Collections.IDictionary]) { @($Variables.GetEnumerator() | Sort-Object Name | ForEach-Object { @{ Name = [string]$_.Name; Value = [string]$_.Value } }) }
             elseif ($Variables) { @($Variables.PSObject.Properties | ForEach-Object { @{ Name = $_.Name; Value = [string]$_.Value } }) } else { @() }
    foreach ($pair in $pairs) {
        $row = New-Object VariableRow
        $row.Name = $pair.Name; $row.Value = $pair.Value; $row.IsSecret = (@($SecretNames) -contains $pair.Name)
        $rows.Add($row)
    }
    return ,$rows
}

function ConvertFrom-VariableRows {
    param($Rows)
    $variables = @{}; $secretNames = New-Object System.Collections.Generic.List[string]
    foreach ($row in @($Rows)) {
        if ([string]::IsNullOrWhiteSpace($row.Name)) { continue }
        $variables[$row.Name.Trim()] = [string]$row.Value
        if ($row.IsSecret) { $secretNames.Add($row.Name.Trim()) }
    }
    return @{ Variables = $variables; SecretNames = @($secretNames) }
}

# Wires the add / remove / reveal buttons of a variables grid.
function Register-VariablesGrid {
    param($Controls, [string]$Prefix)
    $grid = $Controls["${Prefix}Grid"]
    $Controls["${Prefix}AddButton"].Tag = $grid
    $Controls["${Prefix}AddButton"].Add_Click({ param($sender) $row = New-Object VariableRow; $row.Name = 'name'; $row.Value = ''; $sender.Tag.ItemsSource.Add($row); $sender.Tag.SelectedItem = $row })
    $Controls["${Prefix}RemoveButton"].Tag = $grid
    $Controls["${Prefix}RemoveButton"].Add_Click({ param($sender) foreach ($row in @($sender.Tag.SelectedItems)) { [void]$sender.Tag.ItemsSource.Remove($row) } })
    $Controls["${Prefix}RevealBox"].Tag = $grid
    $Controls["${Prefix}RevealBox"].Add_Click({ param($sender) foreach ($row in @($sender.Tag.ItemsSource)) { $row.Reveal = [bool]$sender.IsChecked } })
}

# Edits a table of variables with optional secret flags. Returns @{ Variables; SecretNames } or $null when cancelled.
function Show-VariablesDialog {
    param([string]$Title = 'Variables', $Variables = @{}, [string[]]$SecretNames = @())
    $body = @"
  <Grid Margin="22,18,22,18">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock x:Name="TitleText" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}" Margin="0,0,0,10"/>
    <Grid Grid.Row="1">$(Get-VariablesGridXaml -Prefix 'Vars')</Grid>
    <TextBlock Grid.Row="2" Margin="0,8,0,0" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Text="Use a variable as {{name}}. Secret values are masked here, encrypted on disk and left out of exports."/>
    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="OkButton" Style="{StaticResource PrimaryButton}" IsDefault="True" Width="90" Content="Save"/>
      <Button x:Name="CancelButton" IsCancel="True" Width="90" Margin="10,0,0,0" Content="Cancel"/>
    </StackPanel>
  </Grid>
"@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'TitleText', 'VarsAddButton', 'VarsRemoveButton', 'VarsRevealBox', 'VarsGrid', 'OkButton', 'CancelButton' -Title $Title -Width 720 -Height 520
    $controls = $dialog.Controls; $window = $dialog.Window
    $controls['TitleText'].Text = $Title
    $controls['VarsGrid'].ItemsSource = New-VariableRows -Variables $Variables -SecretNames $SecretNames
    Register-VariablesGrid -Controls $controls -Prefix 'Vars'
    $script:variablesDialogResult = $null
    $controls['OkButton'].Add_Click({
        [void]$controls['VarsGrid'].CommitEdit([System.Windows.Controls.DataGridEditingUnit]::Row, $true)
        $script:variablesDialogResult = ConvertFrom-VariableRows -Rows $controls['VarsGrid'].ItemsSource
        $window.DialogResult = $true
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
    return $script:variablesDialogResult
}

# ------------------------------------------------------------------------------------------------
# Folder / collection settings: auth, headers and scripts inherited by the requests inside
# ------------------------------------------------------------------------------------------------

function Show-ContainerSettingsDialog {
    param($Item)
    $body = @'
  <Grid Margin="20,16,20,16">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock x:Name="TitleText" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <TextBlock Grid.Row="1" Margin="0,2,0,10" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Text="Requests inside inherit these settings: auth when their Auth type is 'Inherit', headers are added (the request wins on the same name), and scripts run collection -> folder -> request."/>
    <TabControl Grid.Row="2" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}">
      <TabItem Header="Auth"><StackPanel Margin="12">
        <ComboBox x:Name="CsAuthTypeBox" Width="220" Height="30" HorizontalAlignment="Left" VerticalContentAlignment="Center" Margin="0,0,0,10"/>
        <WrapPanel>
          <StackPanel x:Name="CsField1Panel" Margin="0,0,12,8"><TextBlock x:Name="CsLabel1" Style="{StaticResource SectionLabel}"/><TextBox x:Name="CsField1Box" Width="280" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
          <StackPanel x:Name="CsField2Panel" Margin="0,0,12,8"><TextBlock x:Name="CsLabel2" Style="{StaticResource SectionLabel}"/><TextBox x:Name="CsField2Box" Width="280" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
          <StackPanel x:Name="CsField3Panel" Margin="0,0,12,8"><TextBlock x:Name="CsLabel3" Style="{StaticResource SectionLabel}"/><ComboBox x:Name="CsAddToBox" Width="170" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
        </WrapPanel>
      </StackPanel></TabItem>
      <TabItem Header="Headers"><TextBox x:Name="CsHeadersBox" Margin="10" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto" ToolTip="Name: value, one per line"/></TabItem>
      <TabItem Header="Pre-request"><TextBox x:Name="CsPreRequestBox" Margin="10" AcceptsReturn="True" AcceptsTab="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/></TabItem>
      <TabItem Header="Tests"><TextBox x:Name="CsTestsBox" Margin="10" AcceptsReturn="True" AcceptsTab="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/></TabItem>
    </TabControl>
    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="OkButton" Style="{StaticResource PrimaryButton}" Width="90" Content="Save"/>
      <Button x:Name="CancelButton" IsCancel="True" Width="90" Margin="10,0,0,0" Content="Cancel"/>
    </StackPanel>
  </Grid>
'@
    $names = 'TitleText', 'CsAuthTypeBox', 'CsField1Panel', 'CsLabel1', 'CsField1Box', 'CsField2Panel', 'CsLabel2', 'CsField2Box', 'CsField3Panel', 'CsLabel3', 'CsAddToBox', 'CsHeadersBox', 'CsPreRequestBox', 'CsTestsBox', 'OkButton', 'CancelButton'
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title "Settings - $($Item.Name)" -Width 760 -Height 600
    $controls = $dialog.Controls; $window = $dialog.Window
    $controls['TitleText'].Text = "$($Item.Type) settings - $($Item.Name)"
    foreach ($type in @('Inherit', 'No Auth', 'API Key', 'Bearer Token', 'Basic Auth')) { [void]$controls['CsAuthTypeBox'].Items.Add($type) }
    foreach ($location in @('Header', 'Query Parameter')) { [void]$controls['CsAddToBox'].Items.Add($location) }
    $auth = Get-ObjectProperty $Item 'Auth' $null
    $authType = [string](Get-ObjectProperty $auth 'Type' 'Inherit')
    $controls['CsAuthTypeBox'].SelectedItem = if ($controls['CsAuthTypeBox'].Items.Contains($authType)) { $authType } else { 'Inherit' }
    $updateFields = {
        $labels = switch ([string]$controls['CsAuthTypeBox'].SelectedItem) { 'API Key' { @('KEY NAME', 'VALUE', 'ADD TO') } 'Bearer Token' { @('TOKEN', '', '') } 'Basic Auth' { @('USERNAME', 'PASSWORD', '') } default { @('', '', '') } }
        $controls['CsLabel1'].Text = $labels[0]; $controls['CsLabel2'].Text = $labels[1]; $controls['CsLabel3'].Text = $labels[2]
        $controls['CsField1Panel'].Visibility = if ($labels[0]) { 'Visible' } else { 'Collapsed' }
        $controls['CsField2Panel'].Visibility = if ($labels[1]) { 'Visible' } else { 'Collapsed' }
        $controls['CsField3Panel'].Visibility = if ($labels[2]) { 'Visible' } else { 'Collapsed' }
    }
    $controls['CsAuthTypeBox'].Add_SelectionChanged($updateFields)
    & $updateFields
    switch ($authType) {
        'API Key'      { $controls['CsField1Box'].Text = [string](Get-ObjectProperty $auth 'Key' ''); $controls['CsField2Box'].Text = [string](Get-ObjectProperty $auth 'Value' ''); $controls['CsAddToBox'].SelectedItem = [string](Get-ObjectProperty $auth 'AddTo' 'Header') }
        'Bearer Token' { $controls['CsField1Box'].Text = [string](Get-ObjectProperty $auth 'Token' '') }
        'Basic Auth'   { $controls['CsField1Box'].Text = [string](Get-ObjectProperty $auth 'Username' ''); $controls['CsField2Box'].Text = [string](Get-ObjectProperty $auth 'Password' '') }
    }
    if (-not $controls['CsAddToBox'].SelectedItem) { $controls['CsAddToBox'].SelectedIndex = 0 }
    $controls['CsHeadersBox'].Text = [string](Get-ObjectProperty $Item 'Headers' '')
    $controls['CsPreRequestBox'].Text = [string](Get-ObjectProperty $Item 'PreRequestScript' '')
    $controls['CsTestsBox'].Text = [string](Get-ObjectProperty $Item 'Tests' '')
    $script:containerSettingsSaved = $false
    $controls['OkButton'].Add_Click({
        $type = [string]$controls['CsAuthTypeBox'].SelectedItem
        $newAuth = @{ Type = $type }
        switch ($type) {
            'API Key'      { $newAuth.Key = $controls['CsField1Box'].Text; $newAuth.Value = $controls['CsField2Box'].Text; $newAuth.AddTo = [string]$controls['CsAddToBox'].SelectedItem }
            'Bearer Token' { $newAuth.Token = $controls['CsField1Box'].Text }
            'Basic Auth'   { $newAuth.Username = $controls['CsField1Box'].Text; $newAuth.Password = $controls['CsField2Box'].Text }
        }
        Set-ObjectProperty -Object $Item -Name 'Auth' -Value $(if ($type -eq 'Inherit') { $null } else { $newAuth })
        Set-ObjectProperty -Object $Item -Name 'Headers' -Value $controls['CsHeadersBox'].Text
        Set-ObjectProperty -Object $Item -Name 'PreRequestScript' -Value $controls['CsPreRequestBox'].Text
        Set-ObjectProperty -Object $Item -Name 'Tests' -Value $controls['CsTestsBox'].Text
        $script:containerSettingsSaved = $true
        $window.DialogResult = $true
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
    return $script:containerSettingsSaved
}

# ------------------------------------------------------------------------------------------------
# Choose a collection / folder to save into
# ------------------------------------------------------------------------------------------------

function Get-ContainerChoices {
    param($Items, $Root, [string]$Prefix = '')
    foreach ($item in @($Items)) {
        if (-not $item -or $item.Type -notin @('Collection', 'Folder')) { continue }
        $rootItem = if ($Root) { $Root } else { $item }
        [PSCustomObject]@{ Label = "$Prefix$($item.Name)"; Container = $item; Root = $rootItem }
        Get-ContainerChoices -Items $item.Items -Root $rootItem -Prefix "$Prefix    "
    }
}

# Returns @{ Container; Root } for the chosen destination (creating a new collection if asked), or $null.
function Show-ChooseContainerDialog {
    $choices = @(Get-ContainerChoices -Items $script:collections -Root $null)
    if ($choices.Count -eq 0) {
        $name = Show-InputBox -Prompt 'There are no collections yet. Name for a new collection:' -Title 'Save Request' -DefaultText 'My Collection'
        if ([string]::IsNullOrWhiteSpace($name)) { return $null }
        $collection = [PSCustomObject]@{ Name = $name.Trim(); Type = 'Collection'; Items = @(); Variables = @{} }
        $script:collections = @($script:collections) + $collection
        return @{ Container = $collection; Root = $collection }
    }
    $body = @'
  <Grid Margin="22,18,22,18">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="Save to..." FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <ListBox x:Name="ChoiceList" Grid.Row="1" Margin="0,12,0,0"/>
    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="OkButton" Style="{StaticResource PrimaryButton}" IsDefault="True" Width="90" Content="Select"/>
      <Button x:Name="CancelButton" IsCancel="True" Width="90" Margin="10,0,0,0" Content="Cancel"/>
    </StackPanel>
  </Grid>
'@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'ChoiceList', 'OkButton', 'CancelButton' -Title 'Save Request' -Width 460 -Height 420
    $window = $dialog.Window; $controls = $dialog.Controls
    foreach ($choice in $choices) {
        $listItem = New-Object System.Windows.Controls.ListBoxItem
        $listItem.Content = $choice.Label; $listItem.Tag = $choice
        [void]$controls['ChoiceList'].Items.Add($listItem)
    }
    $controls['ChoiceList'].SelectedIndex = 0
    $script:chooseContainerResult = $null
    $accept = { if ($controls['ChoiceList'].SelectedItem) { $script:chooseContainerResult = $controls['ChoiceList'].SelectedItem.Tag; $window.DialogResult = $true } }
    $controls['OkButton'].Add_Click($accept)
    $controls['ChoiceList'].Add_MouseDoubleClick($accept)
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
    return $script:chooseContainerResult
}

# ------------------------------------------------------------------------------------------------
# Request templates
# ------------------------------------------------------------------------------------------------

function Show-RequestTemplatesDialog {
    $body = @'
  <Grid Margin="22,18,22,18">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="Request Templates" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <ListBox x:Name="TemplateList" Grid.Row="1" Margin="0,12,0,0"/>
    <WrapPanel Grid.Row="2" Margin="0,14,0,0">
      <Button x:Name="SaveTemplateButton" Style="{StaticResource PrimaryButton}" Margin="0,0,8,0" Content="Save current as template..."/>
      <Button x:Name="LoadTemplateButton" Margin="0,0,8,0" Content="Load"/>
      <Button x:Name="NewTabTemplateButton" Margin="0,0,8,0" Content="Open in new tab"/>
      <Button x:Name="DeleteTemplateButton" Margin="0,0,8,0" Content="Delete"/>
      <Button x:Name="CloseButton" IsCancel="True" Content="Close"/>
    </WrapPanel>
  </Grid>
'@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'TemplateList', 'SaveTemplateButton', 'LoadTemplateButton', 'NewTabTemplateButton', 'DeleteTemplateButton', 'CloseButton' -Title 'Request Templates' -Width 620 -Height 460
    $window = $dialog.Window; $controls = $dialog.Controls
    $refresh = {
        $controls['TemplateList'].Items.Clear()
        foreach ($template in @($script:requestTemplates)) {
            $item = New-Object System.Windows.Controls.ListBoxItem
            $item.Content = "$($template.Name)    -    $($template.Method) $($template.Url)"
            $item.Tag = $template
            [void]$controls['TemplateList'].Items.Add($item)
        }
    }
    & $refresh
    $controls['SaveTemplateButton'].Add_Click({
        $name = Show-InputBox -Prompt 'Template name:' -Title 'Save template' -DefaultText 'My template'
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        $template = Get-EditorState
        $template.Id = [guid]::NewGuid().ToString()
        $template.Name = $name.Trim()
        $script:requestTemplates = @($script:requestTemplates) + $template
        Save-RequestTemplates
        & $refresh
    })
    $controls['LoadTemplateButton'].Add_Click({
        $selected = $controls['TemplateList'].SelectedItem
        if ($selected) { Open-RequestState -Data $selected.Tag -Name ([string]$selected.Tag.Name); $window.Close() }
    })
    $controls['NewTabTemplateButton'].Add_Click({
        $selected = $controls['TemplateList'].SelectedItem
        if ($selected) { Open-RequestState -Data $selected.Tag -Name ([string]$selected.Tag.Name) -NewTab; $window.Close() }
    })
    $controls['DeleteTemplateButton'].Add_Click({
        $selected = $controls['TemplateList'].SelectedItem
        if (-not $selected) { return }
        $target = $selected.Tag
        $script:requestTemplates = @($script:requestTemplates | Where-Object { $_ -ne $target })
        Save-RequestTemplates
        & $refresh
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}

# ------------------------------------------------------------------------------------------------
# Environment manager
# ------------------------------------------------------------------------------------------------

function Show-EnvironmentManager {
    $body = @'
  <Grid Margin="22,18,22,18">
    <Grid.ColumnDefinitions><ColumnDefinition Width="210"/><ColumnDefinition Width="16"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Grid.ColumnSpan="3" Text="Manage Environments" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}" Margin="0,0,0,12"/>
    <Grid Grid.Row="1">
      <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
      <ListBox x:Name="EnvironmentList"/>
      <WrapPanel Grid.Row="1" Margin="0,8,0,0">
        <Button x:Name="AddEnvironmentButton" Style="{StaticResource SmallButton}" Content="Add..."/>
        <Button x:Name="SaveCurrentButton" Style="{StaticResource SmallButton}" Content="Save current..." ToolTip="Create an environment from the request in the editor"/>
        <Button x:Name="RemoveEnvironmentButton" Style="{StaticResource SmallButton}" Content="Remove"/>
      </WrapPanel>
    </Grid>
    <ScrollViewer Grid.Row="1" Grid.Column="2" VerticalScrollBarVisibility="Auto">
      <StackPanel x:Name="EditorPanel" IsEnabled="False">
        <TextBlock Style="{StaticResource SectionLabel}" Text="URL"/>
        <TextBox x:Name="EnvUrlBox" Margin="0,4,0,10" Height="28" VerticalContentAlignment="Center"/>
        <TextBlock Style="{StaticResource SectionLabel}" Text="HEADERS (Name: value, one per line)"/>
        <TextBox x:Name="EnvHeadersBox" Margin="0,4,0,10" Height="70" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/>
        <TextBlock Style="{StaticResource SectionLabel}" Text="VARIABLES"/>
        <Grid Margin="0,4,0,10" Height="190">@@ENVVARS@@</Grid>
        <TextBlock Style="{StaticResource SectionLabel}" Text="AUTHENTICATION"/>
        <ComboBox x:Name="EnvAuthTypeBox" Margin="0,4,0,8" Width="200" HorizontalAlignment="Left" Height="28" VerticalContentAlignment="Center"/>
        <Grid x:Name="EnvAuthFields">
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="10"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <StackPanel x:Name="EnvAuthField1Panel"><TextBlock x:Name="EnvAuthLabel1" Style="{StaticResource SectionLabel}"/><TextBox x:Name="EnvAuthField1Box" Margin="0,4,0,8" Height="28" VerticalContentAlignment="Center"/></StackPanel>
          <StackPanel x:Name="EnvAuthField2Panel" Grid.Column="2"><TextBlock x:Name="EnvAuthLabel2" Style="{StaticResource SectionLabel}"/><TextBox x:Name="EnvAuthField2Box" Margin="0,4,0,8" Height="28" VerticalContentAlignment="Center"/></StackPanel>
          <StackPanel x:Name="EnvAuthField3Panel" Grid.Row="1"><TextBlock x:Name="EnvAuthLabel3" Style="{StaticResource SectionLabel}"/><ComboBox x:Name="EnvAuthAddToBox" Margin="0,4,0,8" Height="28" VerticalContentAlignment="Center"/></StackPanel>
        </Grid>
        <TextBlock x:Name="EnvAuthNote" Foreground="{StaticResource Muted}" TextWrapping="Wrap"/>
      </StackPanel>
    </ScrollViewer>
    <StackPanel Grid.Row="2" Grid.ColumnSpan="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <TextBlock x:Name="EnvStatusText" VerticalAlignment="Center" Margin="0,0,14,0" Foreground="{StaticResource Muted}"/>
      <Button x:Name="ApplyButton" Style="{StaticResource PrimaryButton}" Width="100" Content="Save"/>
      <Button x:Name="CloseButton" IsCancel="True" Width="90" Margin="10,0,0,0" Content="Close"/>
    </StackPanel>
  </Grid>
'@
    $names = 'EnvironmentList', 'AddEnvironmentButton', 'SaveCurrentButton', 'RemoveEnvironmentButton', 'EditorPanel', 'EnvUrlBox', 'EnvHeadersBox', 'EnvVarsAddButton', 'EnvVarsRemoveButton', 'EnvVarsRevealBox', 'EnvVarsGrid', 'EnvAuthTypeBox',
        'EnvAuthFields', 'EnvAuthField1Panel', 'EnvAuthLabel1', 'EnvAuthField1Box', 'EnvAuthField2Panel', 'EnvAuthLabel2', 'EnvAuthField2Box', 'EnvAuthField3Panel', 'EnvAuthLabel3', 'EnvAuthAddToBox',
        'EnvAuthNote', 'EnvStatusText', 'ApplyButton', 'CloseButton'
    $body = $body.Replace('@@ENVVARS@@', (Get-VariablesGridXaml -Prefix 'EnvVars'))
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title 'Manage Environments' -Width 900 -Height 720
    $window = $dialog.Window; $controls = $dialog.Controls

    foreach ($authType in @('No Auth', 'API Key', 'Bearer Token', 'Basic Auth', 'Auth2', 'Client Certificate')) { [void]$controls['EnvAuthTypeBox'].Items.Add($authType) }
    foreach ($location in @('Header', 'Query Parameter')) { [void]$controls['EnvAuthAddToBox'].Items.Add($location) }
    $script:envEditing = $null     # name of the environment shown in the editor
    $script:envAuthExtras = @{}    # auth values this simple editor does not expose (OAuth / certificate fields) are preserved

    $refreshList = {
        $controls['EnvironmentList'].Items.Clear()
        foreach ($name in @($script:environments.Keys | Sort-Object)) { [void]$controls['EnvironmentList'].Items.Add($name) }
    }
    $updateAuthFields = {
        $type = [string]$controls['EnvAuthTypeBox'].SelectedItem
        $labels = switch ($type) {
            'API Key'      { @('KEY NAME', 'VALUE', 'ADD TO') }
            'Bearer Token' { @('TOKEN', '', '') }
            'Basic Auth'   { @('USERNAME', 'PASSWORD', '') }
            default        { @('', '', '') }
        }
        $controls['EnvAuthLabel1'].Text = $labels[0]; $controls['EnvAuthLabel2'].Text = $labels[1]; $controls['EnvAuthLabel3'].Text = $labels[2]
        $controls['EnvAuthField1Panel'].Visibility = if ($labels[0]) { 'Visible' } else { 'Collapsed' }
        $controls['EnvAuthField2Panel'].Visibility = if ($labels[1]) { 'Visible' } else { 'Collapsed' }
        $controls['EnvAuthField3Panel'].Visibility = if ($labels[2]) { 'Visible' } else { 'Collapsed' }
        $controls['EnvAuthNote'].Text = if ($type -in @('Auth2', 'Client Certificate')) { "$type settings are kept as they are. Edit them on the request's Auth tab and use 'Save current...'." } else { '' }
    }
    $controls['EnvAuthTypeBox'].Add_SelectionChanged($updateAuthFields)

    $loadIntoEditor = {
        param([string]$Name)
        $script:envEditing = $Name
        if (-not $Name -or -not $script:environments.ContainsKey($Name)) { $controls['EditorPanel'].IsEnabled = $false; return }
        $data = $script:environments[$Name]
        $controls['EditorPanel'].IsEnabled = $true
        $controls['EnvUrlBox'].Text = [string](Get-ObjectProperty $data 'Url' '')
        $controls['EnvHeadersBox'].Text = [string](Get-ObjectProperty $data 'Headers' '')
        $controls['EnvVarsGrid'].ItemsSource = New-VariableRows -Variables (Get-ObjectProperty $data 'Variables' @{}) -SecretNames (Get-SecretNames $data)
        $controls['EnvVarsRevealBox'].IsChecked = $false
        $auth = Get-ObjectProperty $data 'Authentication' @{ Type = 'No Auth' }
        $type = [string](Get-ObjectProperty $auth 'Type' 'No Auth')
        if (-not $controls['EnvAuthTypeBox'].Items.Contains($type)) { $type = 'No Auth' }
        $script:envAuthExtras = @{}
        if ($auth -is [hashtable]) { foreach ($key in $auth.Keys) { $script:envAuthExtras[$key] = $auth[$key] } } elseif ($auth) { foreach ($property in $auth.PSObject.Properties) { $script:envAuthExtras[$property.Name] = $property.Value } }
        $controls['EnvAuthTypeBox'].SelectedItem = $type
        & $updateAuthFields
        switch ($type) {
            'API Key'      { $controls['EnvAuthField1Box'].Text = [string]$script:envAuthExtras['Key']; $controls['EnvAuthField2Box'].Text = [string]$script:envAuthExtras['Value']; $controls['EnvAuthAddToBox'].SelectedItem = if ($script:envAuthExtras['AddTo']) { [string]$script:envAuthExtras['AddTo'] } else { 'Header' } }
            'Bearer Token' { $controls['EnvAuthField1Box'].Text = [string]$script:envAuthExtras['Token']; $controls['EnvAuthField2Box'].Text = '' }
            'Basic Auth'   { $controls['EnvAuthField1Box'].Text = [string]$script:envAuthExtras['Username']; $controls['EnvAuthField2Box'].Text = [string]$script:envAuthExtras['Password'] }
            default        { $controls['EnvAuthField1Box'].Text = ''; $controls['EnvAuthField2Box'].Text = '' }
        }
        $controls['EnvStatusText'].Text = ''
    }

    $collectFromEditor = {
        [void]$controls['EnvVarsGrid'].CommitEdit([System.Windows.Controls.DataGridEditingUnit]::Row, $true)
        $variableData = ConvertFrom-VariableRows -Rows $controls['EnvVarsGrid'].ItemsSource
        $variables = $variableData.Variables
        $type = [string]$controls['EnvAuthTypeBox'].SelectedItem
        $auth = @{ Type = $type }
        switch ($type) {
            'API Key'      { $auth.Key = $controls['EnvAuthField1Box'].Text; $auth.Value = $controls['EnvAuthField2Box'].Text; $auth.AddTo = [string]$controls['EnvAuthAddToBox'].SelectedItem }
            'Bearer Token' { $auth.Token = $controls['EnvAuthField1Box'].Text }
            'Basic Auth'   { $auth.Username = $controls['EnvAuthField1Box'].Text; $auth.Password = $controls['EnvAuthField2Box'].Text }
            { $_ -in @('Auth2', 'Client Certificate') } { foreach ($key in $script:envAuthExtras.Keys) { $auth[$key] = $script:envAuthExtras[$key] }; $auth.Type = $type }
        }
        return @{ Url = $controls['EnvUrlBox'].Text; Headers = $controls['EnvHeadersBox'].Text; Authentication = $auth; Variables = $variables; SecretVariables = @($variableData.SecretNames) }
    }

    Register-VariablesGrid -Controls $controls -Prefix 'EnvVars'
    & $refreshList
    $controls['EnvironmentList'].Add_SelectionChanged({ & $loadIntoEditor ([string]$controls['EnvironmentList'].SelectedItem) })

    $controls['AddEnvironmentButton'].Add_Click({
        $name = Show-InputBox -Prompt 'Environment name:' -Title 'Add environment' -DefaultText 'New Environment'
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        $name = $name.Trim()
        if ($script:environments.ContainsKey($name)) { $controls['EnvStatusText'].Text = "'$name' already exists."; return }
        $script:environments[$name] = @{ Url = ''; Headers = ''; Authentication = @{ Type = 'No Auth' }; Variables = @{} }
        Save-Environments; & $refreshList; Update-EnvironmentChoices; Update-HistoryEnvironmentChoices
        $controls['EnvironmentList'].SelectedItem = $name
    })
    $controls['SaveCurrentButton'].Add_Click({
        $name = Show-InputBox -Prompt 'Name for the new environment:' -Title 'Save current request as environment' -DefaultText 'My Environment'
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        $name = $name.Trim()
        if ($script:environments.ContainsKey($name)) { $controls['EnvStatusText'].Text = "'$name' already exists."; return }
        $state = Get-EditorState
        $authCopy = @{}
        foreach ($property in (Copy-RequestData $state.Authentication).PSObject.Properties) { $authCopy[$property.Name] = $property.Value }
        $script:environments[$name] = @{ Url = $state.Url; Headers = $state.Headers; Authentication = $authCopy; Variables = @{} }
        Save-Environments; & $refreshList; Update-EnvironmentChoices; Update-HistoryEnvironmentChoices
        $controls['EnvironmentList'].SelectedItem = $name
    })
    $controls['RemoveEnvironmentButton'].Add_Click({
        $name = [string]$controls['EnvironmentList'].SelectedItem
        if (-not $name) { return }
        $answer = [System.Windows.MessageBox]::Show($window, "Remove the '$name' environment?", 'Confirm removal', 'YesNo', 'Warning')
        if ($answer -ne 'Yes') { return }
        $script:environments.Remove($name)
        if ($script:activeEnvironment -eq $name) { $script:activeEnvironment = 'No Environment' }
        Save-Environments; & $refreshList; & $loadIntoEditor ''; Update-EnvironmentChoices; Update-HistoryEnvironmentChoices
    })
    $controls['ApplyButton'].Add_Click({
        if (-not $script:envEditing) { return }
        $script:environments[$script:envEditing] = & $collectFromEditor
        Save-Environments
        $controls['EnvStatusText'].Text = "Saved '$($script:envEditing)'."
        Update-ExtractVariableChoices
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
    Update-EnvironmentChoices
}

# ------------------------------------------------------------------------------------------------
# Collection runner
# ------------------------------------------------------------------------------------------------

function Get-RequestsFromItem {
    param($Item, [string]$Path = '')
    foreach ($child in @($Item.Items)) {
        if (-not $child) { continue }
        if ($child.Type -eq 'Request') { [PSCustomObject]@{ Item = $child; Path = $Path } }
        elseif ($child.Type -eq 'Folder') { Get-RequestsFromItem -Item $child -Path "$Path$($child.Name) / " }
    }
}

function Import-RunnerDataFile {
    param([string]$Path)
    if ($Path -match '\.csv$') { return @(Import-Csv -Path $Path) }
    $json = Get-Content -Path $Path -Raw | ConvertFrom-Json
    return @($json)
}

function Show-CollectionRunner {
    param($Item, $Root)

    $body = @'
  <Grid Margin="18,14,18,14">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock x:Name="RunnerTitle" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <WrapPanel Grid.Row="1" Margin="0,10,0,0">
      <TextBlock Text="Delay (ms)" VerticalAlignment="Center" Margin="0,0,6,0"/>
      <TextBox x:Name="DelayBox" Width="70" Height="26" VerticalContentAlignment="Center" Text="0"/>
      <TextBlock Text="Parallel" VerticalAlignment="Center" Margin="16,0,6,0"/>
      <TextBox x:Name="ParallelBox" Width="44" Height="26" VerticalContentAlignment="Center" ToolTip="How many requests run at the same time (1-10)"/>
      <TextBlock Text="Retries" VerticalAlignment="Center" Margin="16,0,6,0"/>
      <TextBox x:Name="RetriesBox" Width="44" Height="26" VerticalContentAlignment="Center" ToolTip="How many times a failing request is retried before it counts as failed (0-5)"/>
      <CheckBox x:Name="StopOnFailBox" Content="Stop on failure" VerticalAlignment="Center" Margin="16,0,0,0"/>
      <CheckBox x:Name="SelectAllBox" Content="Select all" IsChecked="True" VerticalAlignment="Center" Margin="16,0,0,0"/>
      <Button x:Name="DataFileButton" Style="{StaticResource SmallButton}" Margin="16,0,6,0" Content="Data file..."/>
      <TextBox x:Name="DataFileBox" Width="220" Height="26" IsReadOnly="True" VerticalContentAlignment="Center" ToolTip="CSV or JSON. Each row is one iteration; use {{column}} in your requests."/>
      <Button x:Name="ClearDataFileButton" Style="{StaticResource SmallButton}" Margin="6,0,0,0" Content="Clear"/>
    </WrapPanel>
    <StackPanel Grid.Row="2" Margin="0,10,0,8">
      <TextBlock x:Name="SummaryText" Text="Ready to run." Margin="0,0,0,4"/>
      <ProgressBar x:Name="RunProgress" Height="10" Minimum="0" Maximum="1" Value="0"/>
    </StackPanel>
    <DataGrid x:Name="RunnerGrid" Grid.Row="3" AutoGenerateColumns="False" CanUserAddRows="False" HeadersVisibility="Column" SelectionMode="Extended" GridLinesVisibility="Horizontal" Background="Transparent" RowBackground="Transparent" IsReadOnly="False">
      <DataGrid.RowStyle>
        <Style TargetType="DataGridRow">
          <Style.Triggers>
            <DataTrigger Binding="{Binding Status}" Value="PASS"><Setter Property="Background" Value="#DDF3E4"/><Setter Property="Foreground" Value="#14532D"/></DataTrigger>
            <DataTrigger Binding="{Binding Status}" Value="FAIL"><Setter Property="Background" Value="#F8D7DA"/><Setter Property="Foreground" Value="#7F1D1D"/></DataTrigger>
            <DataTrigger Binding="{Binding Status}" Value="ERROR"><Setter Property="Background" Value="#F8D7DA"/><Setter Property="Foreground" Value="#7F1D1D"/></DataTrigger>
            <DataTrigger Binding="{Binding Status}" Value="Running..."><Setter Property="Background" Value="#FFF3CD"/><Setter Property="Foreground" Value="#7A5B00"/></DataTrigger>
          </Style.Triggers>
        </Style>
      </DataGrid.RowStyle>
      <DataGrid.Columns>
        <DataGridCheckBoxColumn Header="Run" Binding="{Binding Run}" Width="46"/>
        <DataGridTextColumn Header="Request" Binding="{Binding Name}" IsReadOnly="True" Width="*"/>
        <DataGridTextColumn Header="Method" Binding="{Binding Method}" IsReadOnly="True" Width="70"/>
        <DataGridTextColumn Header="Status" Binding="{Binding Status}" IsReadOnly="True" Width="80"/>
        <DataGridTextColumn Header="Result" Binding="{Binding Result}" IsReadOnly="True" Width="190"/>
        <DataGridTextColumn Header="Time (ms)" Binding="{Binding TimeMs}" IsReadOnly="True" Width="80"/>
        <DataGridTextColumn Header="Tests" Binding="{Binding Tests}" IsReadOnly="True" Width="110"/>
      </DataGrid.Columns>
    </DataGrid>
    <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <Button x:Name="HtmlReportButton" Margin="0,0,8,0" Padding="14,6" Content="HTML report..."/>
      <Button x:Name="ExportCsvButton" Margin="0,0,8,0" Padding="14,6" Content="Export CSV..."/>
      <Button x:Name="RetryButton" Margin="0,0,8,0" Padding="14,6" Content="Retry failed" IsEnabled="False"/>
      <Button x:Name="StopRunButton" Margin="0,0,8,0" Padding="14,6" Content="Stop run" IsEnabled="False"/>
      <Button x:Name="StartRunButton" Style="{StaticResource PrimaryButton}" Margin="0,0,8,0" Padding="18,6" Content="Start run"/>
      <Button x:Name="CloseButton" IsCancel="True" Padding="14,6" Content="Close"/>
    </StackPanel>
  </Grid>
'@
    $names = 'RunnerTitle', 'DelayBox', 'ParallelBox', 'RetriesBox', 'StopOnFailBox', 'SelectAllBox', 'DataFileButton', 'DataFileBox', 'ClearDataFileButton', 'SummaryText', 'RunProgress', 'RunnerGrid',
        'HtmlReportButton', 'ExportCsvButton', 'RetryButton', 'StopRunButton', 'StartRunButton', 'CloseButton'
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title "Collection Runner: $($Item.Name)" -Width 1000 -Height 700
    $window = $dialog.Window; $controls = $dialog.Controls
    $controls['RunnerTitle'].Text = "Collection Runner: $($Item.Name)"
    $controls['DelayBox'].Text = [string]$(if ($script:settings.CollectionRunnerDelay) { $script:settings.CollectionRunnerDelay } else { 0 })
    $controls['StopOnFailBox'].IsChecked = [bool]$script:settings.CollectionRunnerStopOnFail
    $controls['ParallelBox'].Text = [string]$(if ([int]$script:settings.CollectionRunnerParallel -gt 0) { $script:settings.CollectionRunnerParallel } else { 1 })
    $controls['RetriesBox'].Text = [string][int]$script:settings.CollectionRunnerRetries

    $script:runnerRows = New-Object 'System.Collections.ObjectModel.ObservableCollection[RunnerRow]'
    $controls['RunnerGrid'].ItemsSource = $script:runnerRows
    $script:runner = @{ Controls = $controls; Window = $window; Root = $Root; Queue = (New-Object System.Collections.Queue); Running = $false; Stop = $false; Current = $null
        Pending = $null; Expanded = $false; CurrentRequest = $null; Total = 0; Done = 0; Passed = 0; Failed = 0; DelayUntil = [datetime]::MinValue; Delay = 0; StopOnFail = $false; Item = $Item }

    Initialize-RunnerRows
    $controls['SummaryText'].Text = "$($script:runnerRows.Count) request(s) ready to run."

    $controls['SelectAllBox'].Add_Click({ foreach ($row in $script:runnerRows) { $row.Run = [bool]$script:runner.Controls['SelectAllBox'].IsChecked } })
    $controls['DataFileButton'].Add_Click({
        $picker = New-Object Microsoft.Win32.OpenFileDialog
        $picker.Filter = 'Data files (*.csv;*.json)|*.csv;*.json|All files (*.*)|*.*'
        if ($picker.ShowDialog($script:runner.Window) -eq $true) { $script:runner.Controls['DataFileBox'].Text = $picker.FileName }
    })
    $controls['ClearDataFileButton'].Add_Click({ $script:runner.Controls['DataFileBox'].Text = '' })
    $controls['StartRunButton'].Add_Click({ Invoke-UiGuard { Start-CollectionRun } 'Start run' })
    $controls['RetryButton'].Add_Click({ Invoke-UiGuard { Start-CollectionRun -RetryFailed } 'Retry' })
    $controls['StopRunButton'].Add_Click({ $script:runner.Stop = $true; $script:runner.Controls['SummaryText'].Text = 'Stopping after the current request...' })
    $controls['ExportCsvButton'].Add_Click({ Invoke-UiGuard { Export-RunnerResults } 'Export' })
    $controls['HtmlReportButton'].Add_Click({ Invoke-UiGuard { Export-RunnerHtmlReport } 'HTML report' })

    $script:runnerTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:runnerTimer.Interval = [TimeSpan]::FromMilliseconds(100)
    $script:runnerTimer.Add_Tick({ Invoke-UiGuard { Step-CollectionRun } 'Collection run' })
    $window.Add_Closing({
        try { $script:runnerTimer.Stop() } catch { }
        foreach ($flight in @($script:runner.InFlight)) { try { $flight.State.Cancellation.Cancel() } catch { } }
        $script:iterationVariables = $null
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
    $script:runner = $null
}

# (Re)creates one grid row per request in the collection/folder being run.
function Initialize-RunnerRows {
    $script:runnerRows.Clear()
    foreach ($entry in @(Get-RequestsFromItem -Item $script:runner.Item)) {
        $data = Get-RequestObjectFromItem -Item $entry.Item
        $row = New-Object RunnerRow
        $row.Run = $true; $row.Name = "$($entry.Path)$($entry.Item.Name)"; $row.Method = [string](Get-ObjectProperty $data 'Method' ''); $row.Url = [string](Get-ObjectProperty $data 'Url' '')
        $row.Status = ''; $row.Result = ''; $row.TimeMs = ''; $row.Tests = ''; $row.Item = $entry.Item
        $script:runnerRows.Add($row)
    }
}

function Start-CollectionRun {
    param([switch]$RetryFailed)
    $runner = $script:runner
    $controls = $runner.Controls
    if ($runner.Running) { return }

    $delay = 0; $parallel = 1; $retries = 0
    [void][int]::TryParse($controls['DelayBox'].Text, [ref]$delay)
    if (-not [int]::TryParse($controls['ParallelBox'].Text, [ref]$parallel) -or $parallel -lt 1) { $parallel = 1 }
    if (-not [int]::TryParse($controls['RetriesBox'].Text, [ref]$retries) -or $retries -lt 0) { $retries = 0 }
    $parallel = [Math]::Min($parallel, 10); $retries = [Math]::Min($retries, 5)
    $script:settings.CollectionRunnerDelay = $delay
    $script:settings.CollectionRunnerStopOnFail = [bool]$controls['StopOnFailBox'].IsChecked
    $script:settings.CollectionRunnerParallel = $parallel
    $script:settings.CollectionRunnerRetries = $retries
    Save-Settings
    $runner.Delay = $delay; $runner.Parallel = $parallel; $runner.Retries = $retries
    $runner.StopOnFail = [bool]$controls['StopOnFailBox'].IsChecked
    $runner.Queue = New-Object System.Collections.ArrayList
    $runner.InFlight = New-Object System.Collections.ArrayList
    $runner.Attempts = @{}
    $runner.Stop = $false

    if ($RetryFailed) {
        $failed = @($script:runnerRows | Where-Object { $_.Status -in @('FAIL', 'ERROR') })
        if ($failed.Count -eq 0) { $controls['SummaryText'].Text = 'No failed requests to retry.'; return }
        foreach ($row in $failed) { $row.Status = 'Queued'; $row.Result = ''; $row.TimeMs = ''; $row.Tests = ''; [void]$runner.Queue.Add($row) }
    } else {
        if ($runner.Expanded) { Initialize-RunnerRows; $runner.Expanded = $false }
        $selected = @($script:runnerRows | Where-Object { $_.Run })
        if ($selected.Count -eq 0) { $controls['SummaryText'].Text = 'Select at least one request.'; return }
        $iterations = @(@{})
        if ($controls['DataFileBox'].Text) {
            try { $dataRows = @(Import-RunnerDataFile -Path $controls['DataFileBox'].Text) } catch { $controls['SummaryText'].Text = "Could not read the data file: $($_.Exception.Message)"; return }
            if ($dataRows.Count -gt 0) { $iterations = @(foreach ($dataRow in $dataRows) { $variables = @{}; foreach ($property in $dataRow.PSObject.Properties) { $variables[$property.Name] = [string]$property.Value }; $variables }) }
        }
        $baseRows = @($selected)
        $script:runnerRows.Clear()
        $runner.Expanded = $true
        foreach ($iterationIndex in 0..($iterations.Count - 1)) {
            foreach ($baseRow in $baseRows) {
                $row = New-Object RunnerRow
                $row.Run = $true
                $row.Name = if ($iterations.Count -gt 1) { "$($baseRow.Name)  [#$($iterationIndex + 1)]" } else { $baseRow.Name }
                $row.Method = $baseRow.Method; $row.Url = $baseRow.Url; $row.Item = $baseRow.Item; $row.Variables = $iterations[$iterationIndex]
                $row.Status = 'Queued'; $row.Result = ''; $row.TimeMs = ''; $row.Tests = ''
                $script:runnerRows.Add($row)
                [void]$runner.Queue.Add($row)
            }
        }
    }

    $runner.Total = $runner.Queue.Count; $runner.Done = 0; $runner.Passed = 0; $runner.Failed = 0
    $controls['RunProgress'].Maximum = [Math]::Max(1, $runner.Total); $controls['RunProgress'].Value = 0
    $controls['SummaryText'].Text = "Running $($runner.Total) request(s)$(if ($parallel -gt 1) { ", $parallel at a time" })..."
    $controls['StartRunButton'].IsEnabled = $false; $controls['RetryButton'].IsEnabled = $false; $controls['StopRunButton'].IsEnabled = $true
    $runner.Running = $true; $runner.NextStartAt = [datetime]::MinValue
    $script:runnerTimer.Start()
}

# One tick: finish completed requests (retrying flaky ones), then start new ones up to the parallel limit.
function Step-CollectionRun {
    $runner = $script:runner
    if (-not $runner -or -not $runner.Running) { return }

    foreach ($flight in @($runner.InFlight)) {
        if (-not $flight.State.Task.IsCompleted) { continue }
        [void]$runner.InFlight.Remove($flight)
        $script:iterationVariables = $flight.Row.Variables
        $result = Get-HttpRequestResult -RequestState $flight.State
        Complete-RunnerRequest -Flight $flight -Result $result
    }

    $stopStarting = $runner.Stop -or ($runner.StopOnFail -and $runner.Failed -gt 0)
    while (-not $stopStarting -and $runner.Queue.Count -gt 0 -and $runner.InFlight.Count -lt $runner.Parallel -and [datetime]::Now -ge $runner.NextStartAt) {
        $row = $runner.Queue[0]
        $runner.Queue.RemoveAt(0)
        Start-RunnerRequest -Row $row
        if ($runner.Delay -gt 0) { $runner.NextStartAt = [datetime]::Now.AddMilliseconds($runner.Delay); break }
    }

    if ($runner.InFlight.Count -eq 0 -and ($runner.Queue.Count -eq 0 -or $stopStarting)) { Complete-CollectionRun }
}

function Start-RunnerRequest {
    param($Row)
    $runner = $script:runner
    $attempt = [int]$runner.Attempts[$Row] + 1
    $runner.Attempts[$Row] = $attempt
    $Row.Status = if ($attempt -gt 1) { "Retry $($attempt - 1)..." } else { 'Running...' }
    $script:iterationVariables = $Row.Variables
    try {
        $data = Get-RequestObjectFromItem -Item $Row.Item
        if (-not $data) { throw 'Missing request data.' }
        $request = Copy-RequestData $data
        Initialize-RequestTabDefaults -TabState $request
        $request = Resolve-InheritedRequest -Request $request -Root $runner.Root -Item $Row.Item
        if ($request.PreRequestScript -match '\S') {
            $modified = Invoke-PreRequestScript -ScriptText $request.PreRequestScript -Request $request
            $request.Method = [string]$modified.Method; $request.Url = [string]$modified.Url; $request.Headers = [string]$modified.Headers; $request.Body = [string]$modified.Body
        }
        $timeout = if ($script:settings.RequestTimeoutSeconds -gt 0) { [int]$script:settings.RequestTimeoutSeconds } else { 60 }
        $state = Start-HttpRequestFromObject -Request $request -TimeoutSeconds $timeout
        [void]$runner.InFlight.Add(@{ Row = $Row; State = $state; Request = $request })
    } catch {
        Complete-RunnerRequest -Flight @{ Row = $Row; Request = $null } -Result @{ Success = $false; ErrorMessage = $_.Exception.Message; ElapsedMs = 0 }
    }
}

function Complete-RunnerRequest {
    param($Flight, $Result)
    $runner = $script:runner
    $row = $Flight.Row
    $row.TimeMs = [string]$Result.ElapsedMs
    $status = 'PASS'
    if (-not $Result.Success) { $status = 'ERROR'; $row.Result = [string]$Result.ErrorMessage }
    else {
        $row.Result = "$($Result.StatusCode) $($Result.ReasonPhrase)".Trim()
        $testScript = if ($Flight.Request) { [string]$Flight.Request.Tests } else { '' }
        $testsPassed = $true
        if ($testScript -match '\S') {
            $testResults = @(Invoke-TestScript -ScriptText $testScript -Result $Result)
            $failedTests = @($testResults | Where-Object { $_.Status -ne 'PASS' })
            $row.Tests = "$($testResults.Count - $failedTests.Count)/$($testResults.Count) passed"
            $testsPassed = ($failedTests.Count -eq 0)
        }
        if ($Result.StatusCode -ge 400 -or -not $testsPassed) { $status = 'FAIL' }
    }
    # Flaky requests: try again (up to the Retries setting) before counting a failure.
    if ($status -ne 'PASS' -and [int]$runner.Attempts[$row] -le $runner.Retries -and -not $runner.Stop) {
        $row.Status = "Retrying ($([int]$runner.Attempts[$row])/$($runner.Retries))"
        $runner.Queue.Insert(0, $row)
        return
    }
    if ([int]$runner.Attempts[$row] -gt 1) { $row.Result = "$($row.Result)  (after $([int]$runner.Attempts[$row] - 1) retr$(if ([int]$runner.Attempts[$row] -eq 2) { 'y' } else { 'ies' }))" }
    $row.Status = $status
    $runner.Done++
    if ($status -eq 'PASS') { $runner.Passed++ } else { $runner.Failed++ }
    $runner.Controls['RunProgress'].Value = $runner.Done
}

function Complete-CollectionRun {
    $runner = $script:runner
    $script:runnerTimer.Stop()
    $runner.Running = $false
    $script:iterationVariables = $null
    foreach ($row in $script:runnerRows) { if ($row.Status -eq 'Queued' -or $row.Status -like 'Retrying*') { $row.Status = 'Skipped' } }
    $controls = $runner.Controls
    $controls['StartRunButton'].IsEnabled = $true; $controls['StopRunButton'].IsEnabled = $false
    $controls['RetryButton'].IsEnabled = ($runner.Failed -gt 0)
    $controls['SummaryText'].Text = "Finished: $($runner.Passed) passed, $($runner.Failed) failed of $($runner.Total)."
    Set-UiStatus "Collection run finished: $($runner.Passed) passed, $($runner.Failed) failed."
}

function Export-RunnerHtmlReport {
    $picker = New-Object Microsoft.Win32.SaveFileDialog
    $picker.Title = 'Save HTML report'; $picker.Filter = 'HTML report (*.html)|*.html'; $picker.FileName = "collection_run_$((Get-Date).ToString('yyyyMMdd_HHmmss')).html"
    if ($picker.ShowDialog($script:runner.Window) -ne $true) { return }
    New-RunnerReportHtml -Title "Collection run: $($script:runner.Item.Name)" -Rows @($script:runnerRows) | Set-Content -Path $picker.FileName -Encoding UTF8
    Start-Process $picker.FileName
}

function Export-RunnerResults {
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title = 'Export run results'
    $dialog.Filter = 'CSV files (*.csv)|*.csv'
    $dialog.FileName = 'collection_run_results.csv'
    if ($dialog.ShowDialog($script:runner.Window) -ne $true) { return }
    $script:runnerRows | ForEach-Object { [PSCustomObject]@{ Request = $_.Name; Method = $_.Method; Url = $_.Url; Status = $_.Status; Result = $_.Result; TimeMs = $_.TimeMs; Tests = $_.Tests } } |
        Export-Csv -Path $dialog.FileName -NoTypeInformation -Encoding UTF8
    $script:runner.Controls['SummaryText'].Text = "Results exported to $($dialog.FileName)"
}
#endregion
