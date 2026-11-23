#region XAML Main Window - code editors (syntax highlighting, line numbers, variable hover), Params tab,
# test snippets, tab drag-and-drop, request in a new window, live theme switching

# ------------------------------------------------------------------------------------------------
# Syntax highlighting
# Each code editor is a transparent-text TextBox laid over a TextBlock that shows the same text in colour, inside
# one ScrollViewer (so both scroll together); a separate gutter shows line numbers. Editing, selection, copy and
# undo all stay native TextBox behaviour.
# ------------------------------------------------------------------------------------------------

$script:codeEditors = @{}

function Get-SyntaxPalette {
    $isDark = ($script:settings.AppTheme -eq 'Dark')
    if ($isDark) { return @{ key = '#7DD3FC'; string = '#A5D6A7'; number = '#F9A8D4'; literal = '#FBBF24'; tag = '#93C5FD'; attribute = '#C4B5FD'; comment = '#64748B'; punctuation = '#94A3B8'; variable = '#FDBA74'; missing = '#F87171' } }
    return @{ key = '#1D4ED8'; string = '#047857'; number = '#B45309'; literal = '#7C3AED'; tag = '#1D4ED8'; attribute = '#9333EA'; comment = '#6B7280'; punctuation = '#64748B'; variable = '#C2410C'; missing = '#DC2626' }
}

$script:syntaxPatterns = @{
    json = '(?<variable>\{\{[^{}]+?\}\})|(?<key>"(?:\\.|[^"\\])*"(?=\s*:))|(?<string>"(?:\\.|[^"\\])*")|(?<number>-?\b\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?\b)|(?<literal>\btrue\b|\bfalse\b|\bnull\b)|(?<punctuation>[{}\[\],:])'
    xml  = '(?<variable>\{\{[^{}]+?\}\})|(?<comment><!--[\s\S]*?-->)|(?<tag></?[\w:.\-]+|/?>|\?>|<\?[\w:.\-]+)|(?<attribute>\b[\w:.\-]+(?=\s*=\s*["'']))|(?<string>"[^"]*"|''[^'']*'')'
    text = '(?<variable>\{\{[^{}]+?\}\})'
}

function Get-CodeLanguage {
    param([string]$Text, [string]$Hint = '')
    if ($Hint -match 'json') { return 'json' }
    if ($Hint -match 'xml|html') { return 'xml' }
    $start = $Text.TrimStart()
    if ($start.StartsWith('{') -or $start.StartsWith('[')) { return 'json' }
    if ($start.StartsWith('<')) { return 'xml' }
    return 'text'
}

# Shared brush per token kind. A theme change recolours these brushes, so highlighted text never has to be redone.
function Update-SyntaxPalette {
    $palette = Get-SyntaxPalette
    if ($script:fastHighlighter) { [ApiTesterHighlighter]::SetPalette($palette); return }
    if (-not $script:syntaxBrushes) { $script:syntaxBrushes = @{} }
    foreach ($kind in $palette.Keys) {
        $color = [System.Windows.Media.ColorConverter]::ConvertFromString($palette[$kind])
        if ($script:syntaxBrushes.ContainsKey($kind)) { $script:syntaxBrushes[$kind].Color = $color }
        else { $script:syntaxBrushes[$kind] = New-Object System.Windows.Media.SolidColorBrush $color }
    }
}

function Initialize-SyntaxHighlighter {
    if ($script:syntaxHighlighterReady) { return }
    if ($script:fastHighlighter) { foreach ($language in $script:syntaxPatterns.Keys) { [ApiTesterHighlighter]::SetPattern($language, $script:syntaxPatterns[$language]) } }
    Update-SyntaxPalette
    $script:syntaxHighlighterReady = $true
}

function Update-CodeHighlight {
    param([string]$Name)
    $editor = $script:codeEditors[$Name]
    if (-not $editor) { return }
    Initialize-SyntaxHighlighter
    $box = $editor.Box; $highlight = $editor.Highlight
    $text = [string]$box.Text
    # The compiled highlighter handles large responses quickly; the PowerShell fallback stops earlier to stay responsive.
    $limit = if ($script:fastHighlighter) { 400000 } else { 60000 }
    $editor.Variables = @()
    if ($text.Length -gt $limit -or $editor.Disabled) {
        $highlight.Inlines.Clear(); $highlight.Text = ''
        $box.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, 'Text')
        Update-CodeLineNumbers -Name $Name
        return
    }
    $box.Foreground = [System.Windows.Media.Brushes]::Transparent
    $language = Get-CodeLanguage -Text $text -Hint $(if ($editor.LanguageHint) { & $editor.LanguageHint } else { '' })
    if ($script:fastHighlighter) {
        $editor.Variables = [ApiTesterHighlighter]::Apply($highlight, $text, $language, [string[]]@(Get-KnownVariableNames))
        Update-CodeLineNumbers -Name $Name
        return
    }
    $known = @{}
    foreach ($variableName in @(Get-KnownVariableNames)) { $known[$variableName] = $true }
    $highlight.Inlines.Clear()
    $variables = New-Object System.Collections.Generic.List[object]
    $position = 0
    foreach ($match in [regex]::Matches($text, $script:syntaxPatterns[$language])) {
        if ($match.Index -gt $position) { [void]$highlight.Inlines.Add((New-Object System.Windows.Documents.Run($text.Substring($position, $match.Index - $position)))) }
        $kind = 'punctuation'
        foreach ($candidate in @('variable', 'comment', 'key', 'string', 'number', 'literal', 'tag', 'attribute', 'punctuation')) { if ($match.Groups[$candidate].Success) { $kind = $candidate; break } }
        $run = New-Object System.Windows.Documents.Run($match.Value)
        if ($kind -eq 'variable') {
            $variableName = $match.Value.Substring(2, $match.Value.Length - 4).Trim()
            $run.Foreground = $script:syntaxBrushes[$(if ($known.ContainsKey($variableName)) { 'variable' } else { 'missing' })]
            $run.FontWeight = [System.Windows.FontWeights]::SemiBold
            $variables.Add(@{ Start = $match.Index; End = $match.Index + $match.Length; Name = $variableName })
        } else { $run.Foreground = $script:syntaxBrushes[$kind] }
        [void]$highlight.Inlines.Add($run)
        $position = $match.Index + $match.Length
    }
    if ($position -lt $text.Length) { [void]$highlight.Inlines.Add((New-Object System.Windows.Documents.Run($text.Substring($position)))) }
    if ($text.EndsWith("`n")) { [void]$highlight.Inlines.Add((New-Object System.Windows.Documents.Run(' '))) }
    $editor.Variables = $variables
    Update-CodeLineNumbers -Name $Name
}

function Update-CodeLineNumbers {
    param([string]$Name)
    $editor = $script:codeEditors[$Name]
    if (-not $editor -or -not $editor.Gutter) { return }
    $lineCount = ([string]$editor.Box.Text).Split("`n").Count
    if ($lineCount -ne $editor.LineCount) {
        $editor.LineCount = $lineCount
        $editor.Gutter.Text = (1..$lineCount) -join "`n"
    }
}

# Wires a code editor. Controls: <Name>Box (TextBox), <Name>Highlight (TextBlock), <Name>Scroll (ScrollViewer),
# optional <Name>Gutter (TextBlock) + <Name>GutterScroll (ScrollViewer).
function Register-CodeEditor {
    param([string]$Name, $LanguageHint = $null)
    $controls = $script:ui
    $editor = @{
        Name = $Name; Box = $controls["${Name}Box"]; Highlight = $controls["${Name}Highlight"]; Scroll = $controls["${Name}Scroll"]
        Gutter = $controls["${Name}Gutter"]; GutterScroll = $controls["${Name}GutterScroll"]; LanguageHint = $LanguageHint; Variables = @(); LineCount = -1; Disabled = $false
    }
    $script:codeEditors[$Name] = $editor
    $editor.Box.SetResourceReference([System.Windows.Controls.Primitives.TextBoxBase]::CaretBrushProperty, 'Text')
    $editor.Box.Tag = $Name
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    $timer.Tag = $Name
    $timer.Add_Tick({ param($sender) $sender.Stop(); Invoke-UiGuard { Update-CodeHighlight -Name ([string]$sender.Tag) } 'Highlight' })
    $editor.Timer = $timer
    $editor.Box.Add_TextChanged({ param($sender) $target = $script:codeEditors[[string]$sender.Tag]; if ($target) { $target.Timer.Stop(); $target.Timer.Start() } })
    # Keep the caret visible: the outer ScrollViewer does the scrolling, so it is brought into view explicitly.
    $editor.Box.Add_SelectionChanged({
        param($sender)
        try { $caretRect = $sender.GetRectFromCharacterIndex($sender.CaretIndex); if (-not $caretRect.IsEmpty) { $sender.BringIntoView($caretRect) } } catch { }
    })
    if ($editor.GutterScroll) {
        $editor.Scroll.Tag = $Name
        $editor.Scroll.Add_ScrollChanged({ param($sender, $scrollArgs) $target = $script:codeEditors[[string]$sender.Tag]; if ($target.GutterScroll) { $target.GutterScroll.ScrollToVerticalOffset($scrollArgs.VerticalOffset) } })
    }
    $editor.Box.Add_MouseMove({ param($sender, $mouseArgs) Invoke-UiGuard { Update-VariableToolTip -Box $sender -Position ($mouseArgs.GetPosition($sender)) } 'Variable hover' })
    Update-CodeHighlight -Name $Name
}

# Shows the resolved value of the {{variable}} under the mouse (secret values masked).
function Update-VariableToolTip {
    param($Box, $Position)
    $editor = $script:codeEditors[[string]$Box.Tag]
    if (-not $editor) { return }
    $index = $Box.GetCharacterIndexFromPoint($Position, $false)
    $hit = $null
    if ($index -ge 0) { foreach ($variable in $editor.Variables) { if ($index -ge $variable.Start -and $index -lt $variable.End) { $hit = $variable; break } } }
    if (-not $hit) { if ($Box.ToolTip) { $Box.ToolTip = $null }; return }
    $source = Resolve-VariableSource -Name $hit.Name
    $text = if (-not $source.Found) { "{{$($hit.Name)}} is not defined in the active environment, the collection or the global variables." }
            elseif ($source.Secret) { "{{$($hit.Name)}} = $($script:SecretMask)  (secret)`nFrom: $($source.Source)" }
            else { "{{$($hit.Name)}} = $($source.Value)`nFrom: $($source.Source)" }
    if ([string]$Box.ToolTip -ne $text) { $Box.ToolTip = $text }
}

# Re-highlights the editors (for example after the environment changed, so known / unknown variables are recoloured).
function Update-AllCodeHighlights {
    param([string[]]$Except = @())
    foreach ($name in @($script:codeEditors.Keys)) { if ($Except -notcontains $name) { Invoke-UiGuard { Update-CodeHighlight -Name $name } 'Highlight' } }
}

# Scrolls an editor so the given character index is visible (code editors scroll through their outer ScrollViewer).
function Show-TextBoxIndex {
    param($Box, [int]$Index)
    try {
        if ($script:codeEditors[[string]$Box.Tag]) {
            $rect = $Box.GetRectFromCharacterIndex([Math]::Min($Index, $Box.Text.Length))
            if (-not $rect.IsEmpty) { $Box.BringIntoView([System.Windows.Rect]::new($rect.X, [Math]::Max(0, $rect.Y - 40), [Math]::Max(1, $rect.Width), $rect.Height + 80)) }
        } else { $Box.ScrollToLine($Box.GetLineIndexFromCharacterIndex($Index)) }
    } catch { }
}

function Set-CodeEditorWrap {
    param([string]$Name, [bool]$Wrap)
    $editor = $script:codeEditors[$Name]
    if (-not $editor) { return }
    $mode = if ($Wrap) { 'Wrap' } else { 'NoWrap' }
    $editor.Box.TextWrapping = $mode; $editor.Highlight.TextWrapping = $mode
    $editor.Scroll.HorizontalScrollBarVisibility = if ($Wrap) { 'Disabled' } else { 'Auto' }
    if ($editor.GutterScroll) { $editor.GutterScroll.Visibility = if ($Wrap) { 'Collapsed' } else { 'Visible' } }
}

function Set-CodeEditorFontSize {
    param([string]$Name, [double]$Size)
    $editor = $script:codeEditors[$Name]
    if (-not $editor) { return }
    $editor.Box.FontSize = $Size; $editor.Highlight.FontSize = $Size
    if ($editor.Gutter) { $editor.Gutter.FontSize = $Size }
}

# ------------------------------------------------------------------------------------------------
# Params tab (URL query string as key/value rows)
# ------------------------------------------------------------------------------------------------

function Split-UrlQuery {
    param([string]$Url)
    $fragment = ''
    $hashIndex = $Url.IndexOf('#')
    if ($hashIndex -ge 0) { $fragment = $Url.Substring($hashIndex); $Url = $Url.Substring(0, $hashIndex) }
    $questionIndex = $Url.IndexOf('?')
    if ($questionIndex -lt 0) { return @{ Base = $Url; Pairs = @(); Fragment = $fragment } }
    $pairs = foreach ($segment in ($Url.Substring($questionIndex + 1) -split '&')) {
        if ($segment -eq '') { continue }
        $equalsIndex = $segment.IndexOf('=')
        if ($equalsIndex -ge 0) { @{ Key = $segment.Substring(0, $equalsIndex); Value = $segment.Substring($equalsIndex + 1) } } else { @{ Key = $segment; Value = '' } }
    }
    return @{ Base = $Url.Substring(0, $questionIndex); Pairs = @($pairs); Fragment = $fragment }
}

function Update-ParamsFromUrl {
    if ($script:isSyncingParams) { return }
    $script:isSyncingParams = $true
    try {
        $parts = Split-UrlQuery -Url $script:ui.UrlBox.Text
        $script:paramRows.Clear()
        foreach ($pair in $parts.Pairs) {
            $row = New-Object ParamRow
            $row.Key = $pair.Key; $row.Value = $pair.Value
            $row.Add_PropertyChanged({ Request-UrlFromParams })
            $script:paramRows.Add($row)
        }
        $script:ui.TabParams.Header = if ($script:paramRows.Count -gt 0) { "Params ($($script:paramRows.Count))" } else { 'Params' }
    } finally { $script:isSyncingParams = $false }
}

function Request-UrlFromParams {
    if ($script:isSyncingParams) { return }
    if (-not $script:paramsTimer) {
        $script:paramsTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:paramsTimer.Interval = [TimeSpan]::FromMilliseconds(120)
        $script:paramsTimer.Add_Tick({ $script:paramsTimer.Stop(); Invoke-UiGuard { Update-UrlFromParams } 'Params' })
    }
    $script:paramsTimer.Stop(); $script:paramsTimer.Start()
}

function Update-UrlFromParams {
    $parts = Split-UrlQuery -Url $script:ui.UrlBox.Text
    $query = @($script:paramRows | Where-Object { $_.Key } | ForEach-Object { if ($_.Value -ne $null -and $_.Value -ne '') { "$($_.Key)=$($_.Value)" } else { [string]$_.Key } }) -join '&'
    $newUrl = $parts.Base + $(if ($query) { "?$query" } else { '' }) + $parts.Fragment
    if ($newUrl -ne $script:ui.UrlBox.Text) {
        $script:isSyncingParams = $true
        try { $script:ui.UrlBox.Text = $newUrl } finally { $script:isSyncingParams = $false }
    }
    $script:ui.TabParams.Header = if ($script:paramRows.Count -gt 0) { "Params ($($script:paramRows.Count))" } else { 'Params' }
}

function Add-ParamRow {
    $row = New-Object ParamRow
    $row.Key = 'key'; $row.Value = ''
    $row.Add_PropertyChanged({ Request-UrlFromParams })
    $script:paramRows.Add($row)
    $script:ui.ParamsGrid.SelectedItem = $row
    Request-UrlFromParams
}

function Remove-ParamRows {
    foreach ($row in @($script:ui.ParamsGrid.SelectedItems)) { [void]$script:paramRows.Remove($row) }
    Request-UrlFromParams
}

# ------------------------------------------------------------------------------------------------
# Test snippet library
# ------------------------------------------------------------------------------------------------

$script:testSnippets = [ordered]@{
    'Status code is 200'                    = 'Assert-StatusIs $statusCode 200'
    'Status code is 2xx'                    = 'Assert-True ($statusCode -ge 200 -and $statusCode -lt 300) "Status code $statusCode is 2xx"'
    'Response time is below 500 ms'         = 'Assert-True ($responseTimeMs -lt 500) "Response time $responseTimeMs ms is below 500 ms"'
    'JSON value equals'                     = "Assert-Equal (Get-JsonPathValue -JsonObject `$jsonBody -Path 'data.id') 123 'data.id equals 123'"
    'JSON value exists'                     = "Assert-True (`$null -ne (Get-JsonPathValue -JsonObject `$jsonBody -Path 'data.id')) 'data.id exists'"
    'JSON array is not empty'               = "Assert-True (@(Get-JsonPathValue -JsonObject `$jsonBody -Path 'items').Count -gt 0) 'items is not empty'"
    'Header is present'                     = "Assert-True (`$headers.ContainsKey('Content-Type')) 'Content-Type header is present'"
    'Header contains value'                 = "Assert-Contains `$headers['Content-Type'] 'application/json' 'Content-Type is JSON'"
    'Body contains text'                    = "Assert-Contains `$body 'expected text' 'Body contains the expected text'"
    'Save a JSON value as a global variable' = "`$script:globals['token'] = Get-JsonPathValue -JsonObject `$jsonBody -Path 'access_token'`r`nSave-Globals"
}

function New-TestSnippetMenu {
    $menu = New-Object System.Windows.Controls.ContextMenu
    foreach ($title in $script:testSnippets.Keys) {
        $menuItem = New-Object System.Windows.Controls.MenuItem
        $menuItem.Header = $title; $menuItem.Tag = $script:testSnippets[$title]
        $menuItem.Add_Click({ param($sender) Invoke-UiGuard { Add-TestSnippet -Code ([string]$sender.Tag) } 'Insert snippet' })
        [void]$menu.Items.Add($menuItem)
    }
    return $menu
}

function Add-TestSnippet {
    param([string]$Code)
    $box = $script:ui.TestsBox
    $text = [string]$box.Text
    $insertAt = [Math]::Min($box.CaretIndex, $text.Length)
    $prefix = if ($insertAt -gt 0 -and $text[$insertAt - 1] -ne "`n") { "`r`n" } else { '' }
    $insertion = "$prefix$Code`r`n"
    $box.Text = $text.Insert($insertAt, $insertion)
    $box.CaretIndex = $insertAt + $insertion.Length
    [void]$box.Focus()
    $script:editorDirty = $true
}

# ------------------------------------------------------------------------------------------------
# Request tabs: drag to reorder, open in a new window
# ------------------------------------------------------------------------------------------------

function Register-RequestTabDragDrop {
    param($Item)
    $Item.AllowDrop = $true
    $Item.Add_PreviewMouseLeftButtonDown({ param($sender, $mouseArgs) $script:tabDragStart = $mouseArgs.GetPosition($null); $script:tabDragItem = $sender })
    $Item.Add_PreviewMouseMove({
        param($sender, $mouseArgs)
        if ($mouseArgs.LeftButton -ne [System.Windows.Input.MouseButtonState]::Pressed -or $script:tabDragItem -ne $sender -or -not $script:tabDragStart) { return }
        $offset = $mouseArgs.GetPosition($null) - $script:tabDragStart
        if ([Math]::Abs($offset.X) -lt [System.Windows.SystemParameters]::MinimumHorizontalDragDistance -and [Math]::Abs($offset.Y) -lt [System.Windows.SystemParameters]::MinimumVerticalDragDistance) { return }
        $script:tabDragStart = $null
        try { [void][System.Windows.DragDrop]::DoDragDrop($sender, [string]$sender.Tag, [System.Windows.DragDropEffects]::Move) } catch { }
    })
    $Item.Add_DragOver({ param($sender, $dragArgs) $dragArgs.Effects = if ($dragArgs.Data.GetDataPresent([string])) { [System.Windows.DragDropEffects]::Move } else { [System.Windows.DragDropEffects]::None }; $dragArgs.Handled = $true })
    $Item.Add_Drop({
        param($sender, $dropArgs)
        $dropArgs.Handled = $true
        Invoke-UiGuard { Move-RequestTab -SourceId ([string]$dropArgs.Data.GetData([string])) -TargetId ([string]$sender.Tag) } 'Reorder tabs'
    })
}

function Move-RequestTab {
    param([string]$SourceId, [string]$TargetId)
    if (-not $SourceId -or $SourceId -eq $TargetId) { return }
    $ids = @($script:requestTabs | ForEach-Object { [string]$_.Id })
    $sourceIndex = [array]::IndexOf($ids, $SourceId); $targetIndex = [array]::IndexOf($ids, $TargetId)
    if ($sourceIndex -lt 0 -or $targetIndex -lt 0) { return }
    $tabs = New-Object System.Collections.ArrayList
    foreach ($tab in $script:requestTabs) { [void]$tabs.Add($tab) }
    $moving = $tabs[$sourceIndex]
    $tabs.RemoveAt($sourceIndex)
    # Dropped on a tab to its right -> place after it; dropped on a tab to its left -> place before it.
    $tabs.Insert($targetIndex, $moving)
    $script:requestTabs = @($tabs)
    Update-RequestTabsStrip
    Save-RequestTabs
}

# Opens a tab's request in its own window (a second API Tester window that holds just that request and does not
# run monitors or overwrite the main window's tabs).
function Open-RequestInNewWindow {
    param([string]$TabId)
    if ($TabId -eq [string]$script:activeRequestTabId) { Save-ActiveRequestTab }
    $tab = Get-RequestTabById -Id $TabId
    if (-not $tab) { return }
    $file = Join-Path ([System.IO.Path]::GetTempPath()) ("api-tester-request-{0}.json" -f [guid]::NewGuid().ToString('N'))
    ConvertTo-Json -InputObject $tab -Depth 20 | Set-Content -Path $file -Encoding UTF8
    $hostPath = (Get-Process -Id $PID).Path
    Start-Process -FilePath $hostPath -ArgumentList "-NoProfile -STA -ExecutionPolicy Bypass -File `"$PSCommandPath`" -OpenRequestFile `"$file`""
    Set-UiStatus "Opened '$($tab.Name)' in a new window."
}

# ------------------------------------------------------------------------------------------------
# Live theme switching
# ------------------------------------------------------------------------------------------------

function Set-AppThemeLive {
    param([string]$ThemeName)
    if (-not $script:Themes.ContainsKey($ThemeName)) { return }
    $script:settings.AppTheme = $ThemeName
    $script:Theme = $script:Themes[$ThemeName]
    foreach ($window in @($script:openWpfWindows)) {
        try { Set-WpfThemeResources -Window $window } catch { Write-Log "Theme could not be applied to '$($window.Title)': $($_.Exception.Message)" -Level Error }
    }
    Update-SyntaxPalette
    Update-ThemeToggleButton
    $script:themeAppliedLive = Test-ThemeApplied
    if ($script:themeAppliedLive) { Set-UiStatus "Theme changed to $ThemeName." }
    else { Write-Log "Theme '$ThemeName' did not reach the main window in place; it will be rebuilt." -Level Info }
}

# True when the main window really shows the active theme (window background and a primary button).
function Test-ThemeApplied {
    $window = Get-MainWindow
    if (-not $window -or -not $script:ui) { return $true }
    try {
        $colors = Get-ThemeBrushColors
        $form = [System.Windows.Media.ColorConverter]::ConvertFromString($colors.Form)
        $primary = [System.Windows.Media.ColorConverter]::ConvertFromString($colors.Primary)
        $background = $window.Background
        $sendBackground = $script:ui.SendButton.Background
        return (($background -is [System.Windows.Media.SolidColorBrush]) -and $background.Color -eq $form -and
                ($sendBackground -is [System.Windows.Media.SolidColorBrush]) -and $sendBackground.Color -eq $primary)
    } catch { return $false }
}

# ------------------------------------------------------------------------------------------------
# Theme switch (header button and shortcut)
# ------------------------------------------------------------------------------------------------

function Update-ThemeToggleButton {
    $controls = $script:ui
    if (-not $controls -or -not $controls.ThemeToggleButton) { return }
    $isDark = ($script:settings.AppTheme -eq 'Dark')
    # Sun when dark (click for light), moon when light (click for dark).
    $controls.ThemeToggleButton.Content = if ($isDark) { [string][char]0x2600 } else { [string][char]0x263E }
    $controls.ThemeToggleButton.ToolTip = if ($isDark) { 'Switch to the light theme' } else { 'Switch to the dark theme' }
}

function Switch-AppTheme {
    $next = if ($script:settings.AppTheme -eq 'Dark') { 'Light' } else { 'Dark' }
    Set-AppThemeLive -ThemeName $next
    Save-Settings
    Complete-ThemeSwitch
}

# ------------------------------------------------------------------------------------------------
# Keyboard shortcuts (customisable in Help -> Keyboard Shortcuts..., stored in Settings)
# ------------------------------------------------------------------------------------------------

$script:ShortcutDefinitions = [ordered]@{
    Send           = @{ Title = 'Send the request';               Default = 'Ctrl+Enter';       Action = { Invoke-SendRequest } }
    Cancel         = @{ Title = 'Cancel the running request';     Default = 'Ctrl+Shift+X';     Action = { Stop-SendRequest } }
    NewTab         = @{ Title = 'New request tab';                Default = 'Ctrl+T';           Action = { [void](Add-RequestTab) } }
    CloseTab       = @{ Title = 'Close the request tab';          Default = 'Ctrl+W';           Action = { Remove-ActiveRequestTab } }
    DuplicateTab   = @{ Title = 'Duplicate the request tab';      Default = 'Ctrl+D';           Action = { Copy-ActiveRequestTab } }
    NextTab        = @{ Title = 'Next request tab';               Default = 'Ctrl+Tab';         Action = { Select-AdjacentRequestTab -Offset 1 } }
    PreviousTab    = @{ Title = 'Previous request tab';           Default = 'Ctrl+Shift+Tab';   Action = { Select-AdjacentRequestTab -Offset -1 } }
    SaveRequest    = @{ Title = 'Save the request to a collection'; Default = 'Ctrl+S';         Action = { Save-CurrentRequest } }
    FocusUrl       = @{ Title = 'Go to the URL box';              Default = 'Ctrl+L';           Action = { [void]$script:ui.UrlBox.Focus(); $script:ui.UrlBox.SelectAll() } }
    Find           = @{ Title = 'Find in the response';           Default = 'Ctrl+F';           Action = { Show-FindBar } }
    Beautify       = @{ Title = 'Beautify the body';              Default = 'Ctrl+B';           Action = { Format-BodyEditor } }
    RunConsole     = @{ Title = 'Run the console command';        Default = 'Ctrl+Shift+Enter'; Action = { $script:ui.ResponseTabs.SelectedItem = $script:ui.TabConsole; Invoke-ConsoleRun } }
    ToggleTheme    = @{ Title = 'Switch light / dark theme';      Default = 'Ctrl+Shift+D';     Action = { Switch-AppTheme } }
    Environments   = @{ Title = 'Manage environments';            Default = 'Ctrl+E';           Action = { Show-EnvironmentManager } }
    ImportCurl     = @{ Title = 'Import a cURL command';          Default = 'Ctrl+I';           Action = { Invoke-MenuImportCurl } }
    MonitorManager = @{ Title = 'Monitor manager';                Default = 'Ctrl+M';           Action = { Show-MonitorManagerWindow } }
    Settings       = @{ Title = 'Settings';                       Default = 'Ctrl+Shift+O';     Action = { Invoke-MenuSettings } }
    Shortcuts      = @{ Title = 'Keyboard shortcuts';             Default = 'F1';               Action = { Show-ShortcutEditorDialog } }
}

# Shortcuts the text boxes need; they cannot be assigned.
$script:ReservedShortcuts = @('Ctrl+A', 'Ctrl+C', 'Ctrl+V', 'Ctrl+X', 'Ctrl+Z', 'Ctrl+Y', 'Alt+F4')

$script:ShortcutKeyNames = @{ 'Return' = 'Enter'; 'Escape' = 'Esc'; 'Back' = 'Backspace'; 'Next' = 'PageDown'; 'Prior' = 'PageUp'; 'OemComma' = ','; 'OemPeriod' = '.'; 'OemMinus' = '-'; 'OemPlus' = '='; 'Oem2' = '/'; 'OemQuestion' = '/' }

function Format-Shortcut {
    param([System.Windows.Input.Key]$Key, [System.Windows.Input.ModifierKeys]$Modifiers)
    $parts = New-Object System.Collections.Generic.List[string]
    if ($Modifiers -band [System.Windows.Input.ModifierKeys]::Control) { $parts.Add('Ctrl') }
    if ($Modifiers -band [System.Windows.Input.ModifierKeys]::Shift) { $parts.Add('Shift') }
    if ($Modifiers -band [System.Windows.Input.ModifierKeys]::Alt) { $parts.Add('Alt') }
    $name = [string]$Key
    if ($script:ShortcutKeyNames.ContainsKey($name)) { $name = $script:ShortcutKeyNames[$name] }
    elseif ($name -match '^D(\d)$') { $name = $Matches[1] }
    elseif ($name -match '^NumPad(\d)$') { $name = "Num$($Matches[1])" }
    $parts.Add($name)
    return ($parts -join '+')
}

function Get-ShortcutBindings {
    $custom = Get-ObjectProperty $script:settings 'KeyboardShortcuts' $null
    $bindings = [ordered]@{}
    foreach ($id in $script:ShortcutDefinitions.Keys) {
        $value = $script:ShortcutDefinitions[$id].Default
        if ($custom) {
            $hasCustom = if ($custom -is [System.Collections.IDictionary]) { $custom.Contains($id) } else { [bool]$custom.PSObject.Properties[$id] }
            if ($hasCustom) { $value = [string](Get-ObjectProperty $custom $id '') }
        }
        $bindings[$id] = $value
    }
    return $bindings
}

function Update-ShortcutLookup {
    $script:shortcutLookup = @{}
    $bindings = Get-ShortcutBindings
    foreach ($id in $bindings.Keys) { if ($bindings[$id]) { $script:shortcutLookup[$bindings[$id].ToLowerInvariant()] = $id } }
}

# Window-level key handling: runs the action bound to the pressed combination.
function Invoke-ShortcutKey {
    param($KeyArgs)
    if (-not $script:shortcutLookup) { Update-ShortcutLookup }
    $key = if ($KeyArgs.Key -eq [System.Windows.Input.Key]::System) { $KeyArgs.SystemKey } else { $KeyArgs.Key }
    if ($key -in @([System.Windows.Input.Key]::LeftCtrl, [System.Windows.Input.Key]::RightCtrl, [System.Windows.Input.Key]::LeftShift, [System.Windows.Input.Key]::RightShift,
                   [System.Windows.Input.Key]::LeftAlt, [System.Windows.Input.Key]::RightAlt, [System.Windows.Input.Key]::LWin, [System.Windows.Input.Key]::RWin)) { return }
    $gesture = (Format-Shortcut -Key $key -Modifiers ([System.Windows.Input.Keyboard]::Modifiers)).ToLowerInvariant()
    if (-not $script:shortcutLookup.ContainsKey($gesture)) { return }
    $id = $script:shortcutLookup[$gesture]
    # The console input runs its own command on Ctrl+Enter.
    if ($id -eq 'Send' -and $KeyArgs.OriginalSource -eq $script:ui.ConsoleInputBox) { return }
    $KeyArgs.Handled = $true
    Invoke-UiGuard $script:ShortcutDefinitions[$id].Action $script:ShortcutDefinitions[$id].Title
}

function Select-AdjacentRequestTab {
    param([int]$Offset)
    $ids = @($script:requestTabs | ForEach-Object { [string]$_.Id })
    if ($ids.Count -lt 2) { return }
    $index = [array]::IndexOf($ids, [string]$script:activeRequestTabId)
    $next = ($index + $Offset + $ids.Count) % $ids.Count
    Switch-RequestTab -Id $ids[$next]
}

function Show-ShortcutEditorDialog {
    $body = @'
  <Grid Margin="22,18,22,18">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <StackPanel Margin="0,0,0,12">
      <TextBlock Text="Keyboard shortcuts" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
      <TextBlock Margin="0,4,0,0" TextWrapping="Wrap" Foreground="{StaticResource Muted}" Text="Click a shortcut box and press the new key combination. Backspace or Delete removes a shortcut. Letters, digits and Enter need Ctrl or Alt; F1-F12 work on their own."/>
    </StackPanel>
    <Border Grid.Row="1" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="6">
      <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel x:Name="ShortcutRows"/></ScrollViewer>
    </Border>
    <DockPanel Grid.Row="2" Margin="0,14,0,0">
      <Button x:Name="ResetAllButton" DockPanel.Dock="Left" Width="150" Content="Reset all to defaults"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <TextBlock x:Name="ShortcutStatus" VerticalAlignment="Center" Margin="0,0,12,0" TextWrapping="Wrap" MaxWidth="360"/>
        <Button x:Name="SaveButton" Style="{StaticResource PrimaryButton}" Width="100" Content="Save"/>
        <Button x:Name="CancelButton" IsCancel="True" Width="100" Margin="10,0,0,0" Content="Cancel"/>
      </StackPanel>
    </DockPanel>
  </Grid>
'@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'ShortcutRows', 'ResetAllButton', 'ShortcutStatus', 'SaveButton', 'CancelButton' -Title 'Keyboard shortcuts' -Width 760 -Height 720
    $window = $dialog.Window; $controls = $dialog.Controls
    $bindings = Get-ShortcutBindings
    $script:shortcutEditorBoxes = [ordered]@{}
    foreach ($id in $script:ShortcutDefinitions.Keys) {
        $definition = $script:ShortcutDefinitions[$id]
        $row = New-Object System.Windows.Controls.Grid
        $row.Margin = [System.Windows.Thickness]::new(8, 4, 8, 4)
        foreach ($width in @('*', '190', 'Auto')) {
            $column = New-Object System.Windows.Controls.ColumnDefinition
            $column.Width = if ($width -eq '*') { [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) } elseif ($width -eq 'Auto') { [System.Windows.GridLength]::Auto } else { [System.Windows.GridLength]::new([double]$width) }
            $row.ColumnDefinitions.Add($column)
        }
        $label = New-Object System.Windows.Controls.TextBlock
        $label.Text = $definition.Title; $label.VerticalAlignment = 'Center'
        $label.ToolTip = "Default: $($definition.Default)"
        $box = New-Object System.Windows.Controls.TextBox
        $box.Text = [string]$bindings[$id]; $box.IsReadOnly = $true; $box.Height = 30; $box.VerticalContentAlignment = 'Center'; $box.HorizontalContentAlignment = 'Center'
        $box.Tag = $id; $box.Cursor = [System.Windows.Input.Cursors]::Hand; $box.ToolTip = 'Click, then press the key combination'
        $box.Add_PreviewKeyDown({
            param($sender, $keyArgs)
            $key = if ($keyArgs.Key -eq [System.Windows.Input.Key]::System) { $keyArgs.SystemKey } else { $keyArgs.Key }
            $modifiers = [System.Windows.Input.Keyboard]::Modifiers
            if ($key -eq [System.Windows.Input.Key]::Tab -and $modifiers -eq [System.Windows.Input.ModifierKeys]::None) { return }   # keep Tab for moving between boxes
            $keyArgs.Handled = $true
            if ($key -in @([System.Windows.Input.Key]::LeftCtrl, [System.Windows.Input.Key]::RightCtrl, [System.Windows.Input.Key]::LeftShift, [System.Windows.Input.Key]::RightShift, [System.Windows.Input.Key]::LeftAlt, [System.Windows.Input.Key]::RightAlt, [System.Windows.Input.Key]::LWin, [System.Windows.Input.Key]::RWin)) { return }
            if (($key -eq [System.Windows.Input.Key]::Back -or $key -eq [System.Windows.Input.Key]::Delete) -and $modifiers -eq [System.Windows.Input.ModifierKeys]::None) { $sender.Text = ''; return }
            $isFunctionKey = ([string]$key) -match '^F([1-9]|1[0-2])$'
            if (-not $isFunctionKey -and -not ($modifiers -band ([System.Windows.Input.ModifierKeys]::Control -bor [System.Windows.Input.ModifierKeys]::Alt))) {
                $script:shortcutStatusText.Text = 'Use Ctrl or Alt with this key (F1-F12 work on their own).'; return
            }
            $gesture = Format-Shortcut -Key $key -Modifiers $modifiers
            if ($script:ReservedShortcuts -contains $gesture) { $script:shortcutStatusText.Text = "$gesture is used for editing text and cannot be assigned."; return }
            $sender.Text = $gesture
            $script:shortcutStatusText.Text = ''
        })
        $resetButton = New-Object System.Windows.Controls.Button
        $resetButton.Content = 'Default'; $resetButton.Width = 80; $resetButton.Height = 30; $resetButton.Margin = [System.Windows.Thickness]::new(8, 0, 0, 0)
        $resetButton.Tag = $box
        $resetButton.ToolTip = "Reset to $($definition.Default)"
        $resetButton.Add_Click({ param($sender) $sender.Tag.Text = $script:ShortcutDefinitions[[string]$sender.Tag.Tag].Default })
        [System.Windows.Controls.Grid]::SetColumn($box, 1); [System.Windows.Controls.Grid]::SetColumn($resetButton, 2)
        [void]$row.Children.Add($label); [void]$row.Children.Add($box); [void]$row.Children.Add($resetButton)
        [void]$controls['ShortcutRows'].Children.Add($row)
        $script:shortcutEditorBoxes[$id] = $box
    }
    $script:shortcutStatusText = $controls['ShortcutStatus']
    $script:shortcutStatusText.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Primary')
    $controls['ResetAllButton'].Add_Click({ foreach ($id in $script:shortcutEditorBoxes.Keys) { $script:shortcutEditorBoxes[$id].Text = $script:ShortcutDefinitions[$id].Default } })
    $controls['SaveButton'].Add_Click({
        $seen = @{}
        foreach ($id in $script:shortcutEditorBoxes.Keys) {
            $gesture = $script:shortcutEditorBoxes[$id].Text.Trim()
            if (-not $gesture) { continue }
            $lookupKey = $gesture.ToLowerInvariant()
            if ($seen.ContainsKey($lookupKey)) {
                $script:shortcutStatusText.Text = "$gesture is used twice: '$($script:ShortcutDefinitions[$seen[$lookupKey]].Title)' and '$($script:ShortcutDefinitions[$id].Title)'."
                return
            }
            $seen[$lookupKey] = $id
        }
        $custom = @{}
        foreach ($id in $script:shortcutEditorBoxes.Keys) { $custom[$id] = $script:shortcutEditorBoxes[$id].Text.Trim() }
        $script:settings.KeyboardShortcuts = $custom
        Save-Settings
        Update-ShortcutLookup
        $window.DialogResult = $true
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}
#endregion
