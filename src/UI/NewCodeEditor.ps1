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

function Update-CodeHighlight {
    param([string]$Name)
    $editor = $script:codeEditors[$Name]
    if (-not $editor) { return }
    $box = $editor.Box; $highlight = $editor.Highlight
    $text = [string]$box.Text
    $limit = 300000
    $editor.Variables = @()
    if ($text.Length -gt $limit -or $editor.Disabled) {
        $highlight.Inlines.Clear(); $highlight.Text = ''
        $box.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, 'Text')
        Update-CodeLineNumbers -Name $Name
        return
    }
    $box.Foreground = [System.Windows.Media.Brushes]::Transparent
    $language = Get-CodeLanguage -Text $text -Hint $(if ($editor.LanguageHint) { & $editor.LanguageHint } else { '' })
    $palette = Get-SyntaxPalette
    $brushes = @{}
    foreach ($kind in $palette.Keys) { $brushes[$kind] = ConvertTo-WpfBrush $palette[$kind] }
    $highlight.Inlines.Clear()
    $position = 0
    foreach ($match in [regex]::Matches($text, $script:syntaxPatterns[$language])) {
        if ($match.Index -gt $position) { [void]$highlight.Inlines.Add((New-Object System.Windows.Documents.Run($text.Substring($position, $match.Index - $position)))) }
        $kind = 'punctuation'
        foreach ($candidate in @('variable', 'comment', 'key', 'string', 'number', 'literal', 'tag', 'attribute', 'punctuation')) { if ($match.Groups[$candidate].Success) { $kind = $candidate; break } }
        $run = New-Object System.Windows.Documents.Run($match.Value)
        if ($kind -eq 'variable') {
            $variableName = $match.Value.Substring(2, $match.Value.Length - 4).Trim()
            $source = Resolve-VariableSource -Name $variableName
            $run.Foreground = if ($source.Found) { $brushes['variable'] } else { $brushes['missing'] }
            $run.FontWeight = [System.Windows.FontWeights]::SemiBold
            $editor.Variables += @{ Start = $match.Index; End = $match.Index + $match.Length; Name = $variableName }
        } else { $run.Foreground = $brushes[$kind] }
        [void]$highlight.Inlines.Add($run)
        $position = $match.Index + $match.Length
    }
    if ($position -lt $text.Length) { [void]$highlight.Inlines.Add((New-Object System.Windows.Documents.Run($text.Substring($position)))) }
    # A trailing newline needs an extra line so the overlay keeps the same height as the TextBox.
    if ($text.EndsWith("`n")) { [void]$highlight.Inlines.Add((New-Object System.Windows.Documents.Run(' '))) }
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

function Update-AllCodeHighlights { foreach ($name in @($script:codeEditors.Keys)) { Invoke-UiGuard { Update-CodeHighlight -Name $name } 'Highlight' } }

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
    foreach ($window in @($script:openWpfWindows)) { try { Set-WpfThemeResources -Window $window } catch { } }
    Update-AllCodeHighlights
    Set-UiStatus "Theme changed to $ThemeName."
}
#endregion
