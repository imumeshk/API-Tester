#region XAML Main Window - sidebar (collections tree + history)

function New-RequestDataFromState {
    param($State)
    return [PSCustomObject]@{
        Timestamp = Get-Date; Method = $State.Method; Url = $State.Url; Headers = $State.Headers; Body = $State.Body; BodyType = $State.BodyType
        OutputFormat = $State.OutputFormat; Tests = $State.Tests; PreRequestScript = $State.PreRequestScript
        Authentication = (Copy-RequestData $State.Authentication); GqlQuery = $State.GqlQuery; GqlVars = $State.GqlVars
        IncludeFilename = $State.IncludeFilename; IncludeContentType = $State.IncludeContentType; Environment = $State.Environment
    }
}

function New-SidebarMenuItem {
    param([string]$Header, [scriptblock]$OnClick)
    $item = New-Object System.Windows.Controls.MenuItem
    $item.Header = $Header
    $item.Add_Click($OnClick)
    return $item
}

function Get-MethodBrush {
    param([string]$Method)
    $color = switch ($Method.ToUpperInvariant()) { 'GET' { '#107C10' } 'POST' { '#B45309' } 'PUT' { '#2563EB' } 'PATCH' { '#7C3AED' } 'DELETE' { '#D93025' } default { '#64748B' } }
    return (New-Object System.Windows.Media.BrushConverter).ConvertFromString($color)
}

function Register-SidebarHandlers {
    $controls = $script:ui

    # ---- collections ----
    $controls.CollectionFilterBox.Add_TextChanged({ Invoke-UiGuard { Update-CollectionsTree } 'Filter collections' })
    $controls.NewCollectionButton.Add_Click({ Invoke-UiGuard { New-CollectionFromPrompt } 'New collection' })
    $controls.ImportCollectionsButton.Add_Click({ Invoke-UiGuard { Invoke-MenuImportCollection } 'Import' })
    $controls.ExportCollectionsButton.Add_Click({ Invoke-UiGuard { Export-AllCollections } 'Export' })
    $controls.CollectionsTree.Add_MouseDoubleClick({ Invoke-UiGuard { Open-SelectedTreeRequest } 'Open request' })
    $controls.CollectionsTree.Add_PreviewMouseRightButtonDown({
        param($sender, $mouseArgs)
        try {
            $source = $mouseArgs.OriginalSource -as [System.Windows.DependencyObject]
            while ($source -and $source -isnot [System.Windows.Controls.TreeViewItem]) {
                if ($source -is [System.Windows.FrameworkContentElement]) { $source = $source.Parent } else { $source = [System.Windows.Media.VisualTreeHelper]::GetParent($source) }
            }
            if ($source) { $source.IsSelected = $true; [void]$source.Focus() }
        } catch { }
    })

    $script:treeMenu = New-Object System.Windows.Controls.ContextMenu
    $script:treeMenuItems = [ordered]@{}
    $definitions = @(
        @('Open',               { Invoke-UiGuard { Open-SelectedTreeRequest } 'Open' }),
        @('Open in new tab',    { Invoke-UiGuard { Open-SelectedTreeRequest -NewTab } 'Open' }),
        @('-', $null),
        @('New Collection',     { Invoke-UiGuard { New-CollectionFromPrompt } 'New collection' }),
        @('New Folder',         { Invoke-UiGuard { New-FolderFromPrompt } 'New folder' }),
        @('Save Current Request', { Invoke-UiGuard { Save-CurrentRequest -IntoSelection } 'Save request' }),
        @('Edit Variables...',  { Invoke-UiGuard { Edit-CollectionVariables } 'Variables' }),
        @('Settings (auth, headers, scripts)...', { Invoke-UiGuard { Edit-ContainerSettings } 'Settings' }),
        @('-', $null),
        @('Run...',             { Invoke-UiGuard { Start-SelectedCollectionRun } 'Run' }),
        @('Load Test...',       { Invoke-UiGuard { Start-SelectedLoadTest } 'Load test' }),
        @('Import OpenAPI Spec...', { Invoke-UiGuard { Import-OpenApiIntoTree } 'Import OpenAPI' }),
        @('-', $null),
        @('Rename',             { Invoke-UiGuard { Rename-SelectedTreeItem } 'Rename' }),
        @('Delete',             { Invoke-UiGuard { Remove-SelectedTreeItem } 'Delete' }),
        @('Export...',          { Invoke-UiGuard { Export-SelectedTreeItem } 'Export' }),
        @('Export as Postman collection...', { Invoke-UiGuard { Export-SelectedTreeItem -Postman } 'Export to Postman' })
    )
    foreach ($definition in $definitions) {
        if ($definition[0] -eq '-') { [void]$script:treeMenu.Items.Add((New-Object System.Windows.Controls.Separator)); continue }
        $menuItem = New-SidebarMenuItem -Header $definition[0] -OnClick $definition[1]
        $script:treeMenuItems[$definition[0]] = $menuItem
        [void]$script:treeMenu.Items.Add($menuItem)
    }
    $script:treeMenu.Add_Opened({ Update-TreeMenuState })
    $controls.CollectionsTree.ContextMenu = $script:treeMenu

    # ---- history ----
    $controls.HistoryFilterBox.Add_TextChanged({ Invoke-UiGuard { Update-HistoryList } 'Filter history' })
    $controls.HistoryEnvironmentBox.Add_SelectionChanged({ Invoke-UiGuard { Update-HistoryList } 'Filter history' })
    $controls.HistoryList.Add_MouseDoubleClick({ Invoke-UiGuard { Open-SelectedHistoryEntry -RunIfEnabled } 'Open history' })
    $controls.ClearHistoryButton.Add_Click({ Invoke-UiGuard { Clear-HistoryWithConfirm } 'Clear history' })
    $controls.ExportHistoryButton.Add_Click({ Invoke-UiGuard { Export-HistoryToFile } 'Export history' })

    $script:historyMenu = New-Object System.Windows.Controls.ContextMenu
    $script:historyMenuItems = [ordered]@{}
    $historyDefinitions = @(
        @('Open',               { Invoke-UiGuard { Open-SelectedHistoryEntry } 'Open' }),
        @('Open in new tab',    { Invoke-UiGuard { Open-SelectedHistoryEntry -NewTab } 'Open' }),
        @('View saved response', { Invoke-UiGuard { Show-SavedHistoryResponse } 'Saved response' }),
        @('Compare Responses',  { Invoke-UiGuard { Compare-SelectedHistoryEntries } 'Compare' }),
        @('-', $null),
        @('Copy as cURL',       { Invoke-UiGuard { Copy-HistoryAsCode -Language 'cURL' } 'Copy' }),
        @('Copy as PowerShell', { Invoke-UiGuard { Copy-HistoryAsCode -Language 'PowerShell' } 'Copy' }),
        @('Copy as Python',     { Invoke-UiGuard { Copy-HistoryAsCode -Language 'Python' } 'Copy' }),
        @('Copy as C#',         { Invoke-UiGuard { Copy-HistoryAsCode -Language 'C#' } 'Copy' }),
        @('-', $null),
        @('Delete',             { Invoke-UiGuard { Remove-SelectedHistoryEntries } 'Delete' })
    )
    foreach ($definition in $historyDefinitions) {
        if ($definition[0] -eq '-') { [void]$script:historyMenu.Items.Add((New-Object System.Windows.Controls.Separator)); continue }
        $menuItem = New-SidebarMenuItem -Header $definition[0] -OnClick $definition[1]
        $script:historyMenuItems[$definition[0]] = $menuItem
        [void]$script:historyMenu.Items.Add($menuItem)
    }
    $script:historyMenu.Add_Opened({
        $selectedCount = $script:ui.HistoryList.SelectedItems.Count
        foreach ($name in @('Open', 'Open in new tab', 'Copy as cURL', 'Copy as PowerShell', 'Copy as Python', 'Copy as C#')) { $script:historyMenuItems[$name].IsEnabled = ($selectedCount -eq 1) }
        $script:historyMenuItems['Compare Responses'].IsEnabled = ($selectedCount -eq 2)
        $script:historyMenuItems['View saved response'].IsEnabled = ($selectedCount -eq 1 -and $script:ui.HistoryList.SelectedItem.Tag.Response)
        $script:historyMenuItems['Delete'].IsEnabled = ($selectedCount -ge 1)
    })
    $controls.HistoryList.ContextMenu = $script:historyMenu
}

# =================================================================================================
# Collections
# =================================================================================================

function Add-CollectionTreeNode {
    param($ParentItems, $Item, $ParentItem, $Root, [string]$Filter)
    if (-not $Item) { return $false }
    $type = [string]$Item.Type
    $name = [string]$Item.Name
    $node = New-Object System.Windows.Controls.TreeViewItem
    $node.Tag = @{ Item = $Item; Parent = $ParentItem; Root = $Root }

    if ($type -eq 'Request') {
        $requestData = Get-RequestObjectFromItem -Item $Item
        $url = [string](Get-ObjectProperty $requestData 'Url' '')
        if ($Filter -and $name.IndexOf($Filter, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and $url.IndexOf($Filter, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
        $method = [string](Get-ObjectProperty $requestData 'Method' 'GET')
        $panel = New-Object System.Windows.Controls.StackPanel
        $panel.Orientation = 'Horizontal'
        $methodText = New-Object System.Windows.Controls.TextBlock
        $methodText.Text = $method.ToUpperInvariant(); $methodText.FontSize = 10; $methodText.FontWeight = 'Bold'; $methodText.Width = 46
        $methodText.VerticalAlignment = 'Center'; $methodText.Foreground = Get-MethodBrush -Method $method
        $nameText = New-Object System.Windows.Controls.TextBlock
        $nameText.Text = $name; $nameText.VerticalAlignment = 'Center'
        [void]$panel.Children.Add($methodText); [void]$panel.Children.Add($nameText)
        $node.Header = $panel
        $node.ToolTip = $url
        [void]$ParentItems.Add($node)
        return $true
    }

    $icon = if ($type -eq 'Collection') { [char]::ConvertFromUtf32(0x1F4DA) } else { [char]::ConvertFromUtf32(0x1F4C1) }
    $node.Header = "$icon  $name"
    $node.FontWeight = if ($type -eq 'Collection') { 'SemiBold' } else { 'Normal' }
    $anyChild = $false
    foreach ($child in @($Item.Items)) {
        if (Add-CollectionTreeNode -ParentItems $node.Items -Item $child -ParentItem $Item -Root $Root -Filter $Filter) { $anyChild = $true }
    }
    $nameMatches = (-not $Filter) -or ($name.IndexOf($Filter, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    if ($Filter -and -not $anyChild -and -not $nameMatches) { return $false }
    if ($Filter) { $node.IsExpanded = $true }
    [void]$ParentItems.Add($node)
    return $true
}

function Update-CollectionsTree {
    $tree = $script:ui.CollectionsTree
    $filter = $script:ui.CollectionFilterBox.Text.Trim()
    $expanded = @{}
    foreach ($node in $tree.Items) { if ($node.IsExpanded -and $node.Tag) { $expanded[[string]$node.Tag.Item.Name] = $true } }
    $tree.Items.Clear()
    foreach ($collection in @($script:collections)) {
        if (-not $collection) { continue }
        [void](Add-CollectionTreeNode -ParentItems $tree.Items -Item $collection -ParentItem $null -Root $collection -Filter $filter)
    }
    foreach ($node in $tree.Items) { if ($expanded[[string]$node.Tag.Item.Name]) { $node.IsExpanded = $true } }
}

function Get-SelectedTreeInfo {
    $selected = $script:ui.CollectionsTree.SelectedItem
    if ($selected -and $selected.Tag) { return $selected.Tag }
    return $null
}

function Update-TreeMenuState {
    $info = Get-SelectedTreeInfo
    $type = if ($info) { [string]$info.Item.Type } else { '' }
    $isContainer = $type -in @('Collection', 'Folder')
    $items = $script:treeMenuItems
    $items['Open'].IsEnabled = ($type -eq 'Request')
    $items['Open in new tab'].IsEnabled = ($type -eq 'Request')
    $items['New Collection'].IsEnabled = $true
    $items['New Folder'].IsEnabled = $isContainer
    $items['Save Current Request'].IsEnabled = $isContainer
    $items['Edit Variables...'].IsEnabled = ($type -eq 'Collection')
    $items['Run...'].IsEnabled = $isContainer
    $items['Load Test...'].IsEnabled = ($type -eq 'Request')
    $items['Import OpenAPI Spec...'].IsEnabled = $true
    $items['Rename'].IsEnabled = ($null -ne $info)
    $items['Delete'].IsEnabled = ($null -ne $info)
    $items['Export...'].IsEnabled = $isContainer
    $items['Export as Postman collection...'].IsEnabled = $isContainer
    $items['Settings (auth, headers, scripts)...'].IsEnabled = $isContainer
}

function Save-CollectionsAndRefresh {
    Save-Collections
    Update-CollectionsTree
}

function Add-ItemToContainer {
    param($Container, $NewItem)
    if (-not ($Container.PSObject.Properties.Name -contains 'Items')) { $Container | Add-Member -MemberType NoteProperty -Name 'Items' -Value @() -Force }
    $Container.Items = @($Container.Items) + $NewItem
}

function New-CollectionFromPrompt {
    $name = Show-InputBox -Prompt 'Collection name:' -Title 'New Collection' -DefaultText 'New Collection'
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    $script:collections = @($script:collections) + [PSCustomObject]@{ Name = $name.Trim(); Type = 'Collection'; Items = @(); Variables = @{} }
    Save-CollectionsAndRefresh
    Set-UiStatus "Created collection '$name'."
}

function New-FolderFromPrompt {
    $info = Get-SelectedTreeInfo
    if (-not $info -or $info.Item.Type -notin @('Collection', 'Folder')) { Set-UiStatus 'Select a collection or folder first.'; return }
    $name = Show-InputBox -Prompt 'Folder name:' -Title 'New Folder' -DefaultText 'New Folder'
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    Add-ItemToContainer -Container $info.Item -NewItem ([PSCustomObject]@{ Name = $name.Trim(); Type = 'Folder'; Items = @() })
    Save-CollectionsAndRefresh
}

# Saves the current request. If the tab was opened from a collection it is updated in place; otherwise it is added to
# the selected collection/folder (or one chosen in a dialog).
function Save-CurrentRequest {
    param([switch]$IntoSelection)
    Save-ActiveRequestTab
    $state = Get-EditorState
    $source = $script:tabSources[[string]$state.Id]
    if ($source -and $source.Item -and -not $IntoSelection) {
        $source.Item.RequestData = New-RequestDataFromState -State $state
        Save-CollectionsAndRefresh
        Set-UiStatus "Updated '$($source.Item.Name)' in the collection."
        return
    }

    $container = $null; $root = $null
    $info = Get-SelectedTreeInfo
    if ($info) {
        if ($info.Item.Type -in @('Collection', 'Folder')) { $container = $info.Item; $root = $info.Root }
        elseif ($info.Item.Type -eq 'Request' -and $info.Parent) { $container = $info.Parent; $root = $info.Root }
    }
    if (-not $container) {
        $choice = Show-ChooseContainerDialog
        if (-not $choice) { return }
        $container = $choice.Container; $root = $choice.Root
    }
    $name = Show-InputBox -Prompt 'Request name:' -Title 'Save Request' -DefaultText "$($state.Method) $($state.Url)"
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    $newItem = [PSCustomObject]@{ Name = $name.Trim(); Type = 'Request'; RequestData = (New-RequestDataFromState -State $state) }
    Add-ItemToContainer -Container $container -NewItem $newItem
    $script:tabSources[[string]$state.Id] = @{ Item = $newItem; Root = $root }
    Set-ActiveCollectionContext -Root $root
    Save-CollectionsAndRefresh
    Set-UiStatus "Saved '$($name.Trim())' to '$($container.Name)'."
}

function Set-ActiveCollectionContext {
    param($Root)
    $script:activeCollection = $Root
    $script:activeCollectionVariables = if ($Root -and $Root.Variables) { $Root.Variables } else { @{} }
    Update-ExtractVariableChoices
}

# Loads a collection request (or a history entry) into the active tab, or into a new tab.
function Open-RequestState {
    param($Data, [string]$Name, $Source = $null, [switch]$NewTab)
    if (-not $Data) { return }
    $state = Copy-RequestData $Data
    Initialize-RequestTabDefaults -TabState $state
    $state.Name = if ($Name) { $Name } else { "$($state.Method) $($state.Url)" }
    if ($NewTab) {
        [void](Add-RequestTab -InitialState $state)
        $tabId = $script:activeRequestTabId
    } else {
        $tabId = $script:activeRequestTabId
        $state.Id = $tabId
        for ($index = 0; $index -lt $script:requestTabs.Count; $index++) { if ($script:requestTabs[$index].Id -eq $tabId) { $script:requestTabs[$index] = $state; break } }
        $script:tabResults.Remove($tabId)
        Set-EditorState -State $state
        Update-RequestTabsStrip
        Save-RequestTabs
    }
    if ($Source) { $script:tabSources[$tabId] = $Source; Set-ActiveCollectionContext -Root $Source.Root }
    else { $script:tabSources.Remove($tabId); Set-ActiveCollectionContext -Root $null }
    Set-UiStatus "Loaded '$($state.Name)'."
}

function Open-SelectedTreeRequest {
    param([switch]$NewTab)
    $info = Get-SelectedTreeInfo
    if (-not $info -or $info.Item.Type -ne 'Request') { return }
    $data = Get-RequestObjectFromItem -Item $info.Item
    Open-RequestState -Data $data -Name ([string]$info.Item.Name) -Source @{ Item = $info.Item; Root = $info.Root } -NewTab:$NewTab
}

function Rename-SelectedTreeItem {
    $info = Get-SelectedTreeInfo
    if (-not $info) { return }
    $newName = Show-InputBox -Prompt 'New name:' -Title 'Rename' -DefaultText ([string]$info.Item.Name)
    if ([string]::IsNullOrWhiteSpace($newName)) { return }
    $info.Item.Name = $newName.Trim()
    Save-CollectionsAndRefresh
}

function Remove-SelectedTreeItem {
    $info = Get-SelectedTreeInfo
    if (-not $info) { return }
    $answer = [System.Windows.MessageBox]::Show((Get-MainWindow), "Delete '$($info.Item.Name)'? This cannot be undone.", 'Confirm delete', 'YesNo', 'Warning')
    if ($answer -ne 'Yes') { return }
    $target = $info.Item
    if ($info.Parent) { $info.Parent.Items = @($info.Parent.Items | Where-Object { $_ -ne $target }) }
    else { $script:collections = @($script:collections | Where-Object { $_ -ne $target }) }
    foreach ($tabId in @($script:tabSources.Keys)) { if ($script:tabSources[$tabId].Item -eq $target) { $script:tabSources.Remove($tabId) } }
    Save-CollectionsAndRefresh
}

function Export-SelectedTreeItem {
    param([switch]$Postman)
    $info = Get-SelectedTreeInfo
    if (-not $info) { return }
    if ($Postman) {
        $picker = New-Object Microsoft.Win32.SaveFileDialog
        $picker.Title = 'Export as Postman collection (v2.1)'
        $picker.Filter = 'Postman collection (*.json)|*.json'
        $picker.FileName = (([string]$info.Item.Name) -replace '[\\/:*?"<>|]', '_') + '.postman_collection.json'
        if ($picker.ShowDialog((Get-MainWindow)) -ne $true) { return }
        ConvertTo-PostmanCollectionJson -Item $info.Item | Set-Content -Path $picker.FileName -Encoding UTF8
        Set-UiStatus "Exported '$($info.Item.Name)' as a Postman collection (secret variables and PowerShell scripts are not included)."
        return
    }
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title = 'Export'
    $dialog.Filter = 'JSON files (*.json)|*.json'
    $dialog.FileName = (([string]$info.Item.Name) -replace '[\\/:*?"<>|]', '_') + '.json'
    if ($dialog.ShowDialog((Get-MainWindow)) -ne $true) { return }
    $exportItem = if ($info.Item.Type -eq 'Collection') { $safe = Get-CollectionsForStorage -Collections @($info.Item) -ForExport; $safe[0] } else { $info.Item }
    ConvertTo-Json -InputObject @($exportItem) -Depth 50 | Set-Content -Path $dialog.FileName -Encoding UTF8
    Set-UiStatus "Exported to $($dialog.FileName)"
}

function Export-AllCollections {
    if (@($script:collections).Count -eq 0) { Set-UiStatus 'There are no collections to export.'; return }
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title = 'Export all collections'
    $dialog.Filter = 'JSON files (*.json)|*.json'
    $dialog.FileName = 'api_tester_collections.json'
    if ($dialog.ShowDialog((Get-MainWindow)) -ne $true) { return }
    ConvertTo-Json -InputObject (Get-CollectionsForStorage -Collections $script:collections -ForExport) -Depth 50 | Set-Content -Path $dialog.FileName -Encoding UTF8
    Set-UiStatus "Exported collections to $($dialog.FileName)"
}

function Edit-CollectionVariables {
    $info = Get-SelectedTreeInfo
    if (-not $info -or $info.Item.Type -ne 'Collection') { return }
    $collection = $info.Item
    $current = @{}
    if ($collection.Variables -is [hashtable]) { $current = $collection.Variables }
    elseif ($collection.Variables) { foreach ($property in $collection.Variables.PSObject.Properties) { $current[$property.Name] = $property.Value } }
    $edited = Show-VariablesDialog -Title "Variables - $($collection.Name)" -Variables $current -SecretNames (Get-SecretNames $collection)
    if ($null -eq $edited) { return }
    Set-ObjectProperty -Object $collection -Name 'Variables' -Value $edited.Variables
    Set-ObjectProperty -Object $collection -Name 'SecretVariables' -Value @($edited.SecretNames)
    Save-Collections
    if ($script:activeCollection -eq $collection) { Set-ActiveCollectionContext -Root $collection }
    Update-AllCodeHighlights
    Set-UiStatus 'Collection variables saved.'
}

function Edit-ContainerSettings {
    $info = Get-SelectedTreeInfo
    if (-not $info -or $info.Item.Type -notin @('Collection', 'Folder')) { return }
    if (Show-ContainerSettingsDialog -Item $info.Item) { Save-Collections; Set-UiStatus "Saved settings for '$($info.Item.Name)'." }
}

function Start-SelectedCollectionRun {
    $info = Get-SelectedTreeInfo
    if (-not $info -or $info.Item.Type -notin @('Collection', 'Folder')) { return }
    Show-CollectionRunner -Item $info.Item -Root $info.Root
}

function Start-SelectedLoadTest {
    $info = Get-SelectedTreeInfo
    if (-not $info -or $info.Item.Type -ne 'Request') { return }
    $data = Get-RequestObjectFromItem -Item $info.Item
    $headerTable = @{}
    foreach ($entry in (ConvertFrom-HeaderText -HeaderText (Expand-Variables -InputString ([string]$data.Headers)))) { $headerTable[$entry.Name] = $entry.Value }
    $loadRequest = [PSCustomObject]@{ Url = (Expand-Variables -InputString ([string]$data.Url)); Method = [string]$data.Method; Headers = $headerTable; Body = (Expand-Variables -InputString ([string]$data.Body)) }
    Show-LoadTestDialog -RequestObject $loadRequest
}

function Import-OpenApiIntoTree {
    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Title = 'Import OpenAPI specification'
    $dialog.Filter = 'JSON/YAML files (*.json;*.yaml;*.yml)|*.json;*.yaml;*.yml|All files (*.*)|*.*'
    if ($dialog.ShowDialog((Get-MainWindow)) -ne $true) { return }
    try {
        $imported = ConvertFrom-OpenApiSpec -FilePath $dialog.FileName
        $script:collections = @($script:collections) + $imported
        Save-CollectionsAndRefresh
        [void][System.Windows.MessageBox]::Show((Get-MainWindow), 'OpenAPI specification imported successfully.', 'Import', 'OK', 'Information')
    } catch {
        [void][System.Windows.MessageBox]::Show((Get-MainWindow), "Failed to import the OpenAPI spec: $($_.Exception.Message)", 'Import error', 'OK', 'Error')
    }
}

# =================================================================================================
# History
# =================================================================================================

function Add-HistoryEntry {
    param($State)
    if (-not $script:settings.EnableHistory) { return }
    $entry = New-RequestDataFromState -State $State
    $script:history = @($entry) + @($script:history | Where-Object { $_ })
    if ($script:history.Count -gt 50) { $script:history = @($script:history[0..49]) }
    Save-History
    Update-HistoryList
    return $entry
}

# Stores the response with its history entry (status, headers and - unless switched off or too large - the body).
function Set-HistoryResponse {
    param($Entry, $Result)
    if (-not $Entry -or $script:settings.HistorySaveResponses -eq $false) { return }
    $limitBytes = [int]$(if ($script:settings.HistoryResponseBodyLimitKB -gt 0) { $script:settings.HistoryResponseBodyLimitKB } else { 256 }) * 1024
    $saved = [ordered]@{ Timestamp = (Get-Date).ToString('o'); Success = [bool]$Result.Success; ElapsedMs = [int]$Result.ElapsedMs }
    if ($Result.Success) {
        $saved.StatusCode = [int]$Result.StatusCode; $saved.ReasonPhrase = [string]$Result.ReasonPhrase; $saved.SizeBytes = [int]$Result.SizeBytes
        $saved.ContentType = [string]$Result.ContentType; $saved.Headers = (@($Result.HeaderLines) -join "`r`n")
        $saved.Body = if (-not $Result.IsBinary -and ([string]$Result.Body).Length -le $limitBytes) { [string]$Result.Body } else { $null }
        $saved.BodyOmitted = ($null -eq $saved.Body)
    } else { $saved.ErrorMessage = [string]$Result.ErrorMessage }
    $Entry | Add-Member -MemberType NoteProperty -Name 'Response' -Value ([PSCustomObject]$saved) -Force
    Save-History
    Update-HistoryList
}

function ConvertFrom-SavedResponse {
    param($Saved)
    if (-not $Saved) { return $null }
    if (-not $Saved.Success) { return @{ Success = $false; ErrorMessage = [string]$Saved.ErrorMessage; ElapsedMs = [int]$Saved.ElapsedMs } }
    $body = if ($null -ne $Saved.Body) { [string]$Saved.Body } else { '[The body was not saved - it was binary or larger than the history limit.]' }
    return @{ Success = $true; StatusCode = [int]$Saved.StatusCode; ReasonPhrase = [string]$Saved.ReasonPhrase; ElapsedMs = [int]$Saved.ElapsedMs; SizeBytes = [int]$Saved.SizeBytes
        Body = $body; BodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body); IsBinary = $false; HeaderLines = @(([string]$Saved.Headers) -split "`r?`n" | Where-Object { $_ }); ContentType = [string]$Saved.ContentType; ContentDispositionName = '' }
}

function Show-SavedHistoryResponse {
    $entries = Get-SelectedHistoryEntries
    if ($entries.Count -ne 1 -or -not $entries[0].Response) { return }
    $entry = $entries[0]
    Open-RequestState -Data $entry -Name "$($entry.Method) $($entry.Url)" -NewTab
    $result = ConvertFrom-SavedResponse -Saved $entry.Response
    $script:tabResults[[string]$script:activeRequestTabId] = $result
    Show-ResponseResult -Result $result
    Set-UiStatus "Showing the response saved on $(([datetime]$entry.Response.Timestamp).ToString()) (offline)."
}

function ConvertTo-HistoryTime {
    param($Timestamp)
    $text = if ($Timestamp -is [PSCustomObject] -and $Timestamp.PSObject.Properties.Name -contains 'DateTime') { $Timestamp.DateTime } else { $Timestamp }
    $parsed = [datetime]::MinValue
    if ($text -is [datetime]) { return $text }
    if ([datetime]::TryParse([string]$text, [ref]$parsed)) { return $parsed }
    if ([datetime]::TryParse([string]$text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) { return $parsed }
    return $null
}

function Update-HistoryEnvironmentChoices {
    $box = $script:ui.HistoryEnvironmentBox
    $current = [string]$box.SelectedItem
    $script:isRefreshingHistoryFilter = $true
    try {
        $box.Items.Clear()
        [void]$box.Items.Add('All Environments')
        foreach ($name in @($script:environments.Keys | Sort-Object)) { [void]$box.Items.Add($name) }
        $box.SelectedItem = if ($current -and $box.Items.Contains($current)) { $current } else { 'All Environments' }
    } finally { $script:isRefreshingHistoryFilter = $false }
}

function Update-HistoryList {
    $controls = $script:ui
    if (-not $controls -or $script:isRefreshingHistoryFilter) { return }
    if ($controls.HistoryEnvironmentBox.Items.Count -eq 0) { Update-HistoryEnvironmentChoices }
    $textFilter = $controls.HistoryFilterBox.Text.Trim()
    $environmentFilter = [string]$controls.HistoryEnvironmentBox.SelectedItem
    $entries = @($script:history | Where-Object { $_ })
    if ($textFilter) { $entries = @($entries | Where-Object { $_.Method -like "*$textFilter*" -or $_.Url -like "*$textFilter*" }) }
    if ($environmentFilter -and $environmentFilter -ne 'All Environments') { $entries = @($entries | Where-Object { $_.Environment -eq $environmentFilter }) }
    $controls.HistoryList.Items.Clear()
    foreach ($entry in $entries) {
        if (-not ($entry.Method -and $entry.Url)) { continue }
        $time = ConvertTo-HistoryTime -Timestamp $entry.Timestamp
        $item = New-Object System.Windows.Controls.ListBoxItem
        $statusText = if ($entry.Response) { if ($entry.Response.Success) { [string]$entry.Response.StatusCode } else { 'ERR' } } else { '...' }
        $item.Content = "$(if ($time) { $time.ToString('HH:mm:ss') } else { '??:??:??' }) | $statusText | $($entry.Method) | $($entry.Url)"
        $item.ToolTip = [string]$entry.Url
        $item.Tag = $entry
        [void]$controls.HistoryList.Items.Add($item)
    }
}

function Get-SelectedHistoryEntries {
    return @($script:ui.HistoryList.SelectedItems | ForEach-Object { $_.Tag })
}

function Open-SelectedHistoryEntry {
    param([switch]$NewTab, [switch]$RunIfEnabled)
    $entries = Get-SelectedHistoryEntries
    if ($entries.Count -ne 1) { return }
    $entry = $entries[0]
    Open-RequestState -Data $entry -Name "$($entry.Method) $($entry.Url)" -NewTab:$NewTab
    # Settings > "Auto-run on history double-click"
    if ($RunIfEnabled -and $script:settings.AutoRunHistory) { Invoke-SendRequest }
}

function Remove-SelectedHistoryEntries {
    $entries = Get-SelectedHistoryEntries
    if ($entries.Count -eq 0) { return }
    $script:history = @($script:history | Where-Object { $_ -and ($entries -notcontains $_) })
    Save-History
    Update-HistoryList
}

function Clear-HistoryWithConfirm {
    $answer = [System.Windows.MessageBox]::Show((Get-MainWindow), 'Clear all history? This cannot be undone.', 'Confirm clear', 'YesNo', 'Warning')
    if ($answer -ne 'Yes') { return }
    $script:history = @()
    Save-History
    Update-HistoryList
}

function Export-HistoryToFile {
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title = 'Export history'
    $dialog.Filter = 'JSON files (*.json)|*.json'
    $dialog.FileName = 'api_tester_history_export.json'
    if ($dialog.ShowDialog((Get-MainWindow)) -ne $true) { return }
    @($script:history | Where-Object { $_ }) | ConvertTo-Json -Depth 20 | Set-Content -Path $dialog.FileName -Encoding UTF8
    Set-UiStatus "Exported history to $($dialog.FileName)"
}

function Copy-HistoryAsCode {
    param([string]$Language)
    $entries = Get-SelectedHistoryEntries
    if ($entries.Count -ne 1) { return }
    [System.Windows.Clipboard]::SetText((New-CodeSnippet -RequestItem $entries[0] -Language $Language))
    Set-UiStatus "Copied history item as $Language."
}

function Compare-SelectedHistoryEntries {
    $entries = Get-SelectedHistoryEntries
    if ($entries.Count -ne 2) { return }
    $first = $entries[0]; $second = $entries[1]
    # Both responses saved: compare them offline. Otherwise both requests are sent again.
    if ($first.Response -and $second.Response -and $null -ne $first.Response.Body -and $null -ne $second.Response.Body) {
        Show-DiffDialog -Request1 $first -Request2 $second -SavedBody1 ([string]$first.Response.Body) -SavedBody2 ([string]$second.Response.Body)
    } else { Show-DiffDialog -Request1 $first -Request2 $second }
}
#endregion
