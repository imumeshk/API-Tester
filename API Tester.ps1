#region Initialization

# Determine the script's root directory to locate configuration and log files.
# This approach works for both standard execution and in the PowerShell ISE.
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Path $MyInvocation.MyCommand.Path -Parent }

# Define directories for organization
$configDir = Join-Path -Path $scriptRoot -ChildPath "Configuration"
$historyDir = Join-Path -Path $scriptRoot -ChildPath "History"
$logsDir = Join-Path -Path $scriptRoot -ChildPath "Logs"

# Auto-create directories if they don't exist
if (-not (Test-Path -Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
if (-not (Test-Path -Path $historyDir)) { New-Item -ItemType Directory -Path $historyDir -Force | Out-Null }
if (-not (Test-Path -Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }

# Migration: Move existing files to new locations if they exist in root
$filesToMoveToConfig = @("api_tester_settings.json", "api_tester_settings.json.bak", "api_tester_environments.json", "api_tester_globals.json", "api_tester_collections.json", "api_tester_monitors.json", "api_tester_workspace.apw")
foreach ($file in $filesToMoveToConfig) {
    $sourcePath = Join-Path -Path $scriptRoot -ChildPath $file
    $destPath = Join-Path -Path $configDir -ChildPath $file
    if ((Test-Path -Path $sourcePath) -and -not (Test-Path -Path $destPath)) {
        Move-Item -Path $sourcePath -Destination $destPath -Force
    }
}

$filesToMoveToHistory = @("api_tester_history.json", "api_tester_grpc_history.json", "api_tester_monitor_log.csv")
foreach ($file in $filesToMoveToHistory) {
    $sourcePath = Join-Path -Path $scriptRoot -ChildPath $file
    $destPath = Join-Path -Path $historyDir -ChildPath $file
    if ((Test-Path -Path $sourcePath) -and -not (Test-Path -Path $destPath)) {
        Move-Item -Path $sourcePath -Destination $destPath -Force
    }
}

# Migration: Move log files to Logs folder
$filesToMoveToLogs = @("api_tester.log")
foreach ($file in $filesToMoveToLogs) {
    $sourcePath = Join-Path -Path $scriptRoot -ChildPath $file
    $destPath = Join-Path -Path $logsDir -ChildPath $file
    if ((Test-Path -Path $sourcePath) -and -not (Test-Path -Path $destPath)) {
        Move-Item -Path $sourcePath -Destination $destPath -Force
    }
    # Check History folder (migration from previous version)
    $historySourcePath = Join-Path -Path $historyDir -ChildPath $file
    if ((Test-Path -Path $historySourcePath) -and -not (Test-Path -Path $destPath)) {
        Move-Item -Path $historySourcePath -Destination $destPath -Force
    }
}

# Define paths for log, history, settings, and environment configuration files.
$logFilePath = Join-Path -Path $logsDir -ChildPath "api_tester.csv"
$historyFilePath = Join-Path -Path $historyDir -ChildPath "api_tester_history.json"
$settingsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_settings.json"
$environmentsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_environments.json"
$globalsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_globals.json"
$collectionsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_collections.json"
$monitorsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_monitors.json"
$monitorLogFilePath = Join-Path -Path $historyDir -ChildPath "api_tester_monitor_log.csv"
$grpcHistoryFilePath = Join-Path -Path $historyDir -ChildPath "api_tester_grpc_history.json"

try {
    # Load required .NET assemblies for creating the Windows Forms GUI.
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms.DataVisualization -ErrorAction SilentlyContinue

    # High DPI Awareness & Visual Styles (Pro Enhancement)
    if ([Environment]::OSVersion.Version.Major -ge 6) {
        if (-not ([System.Management.Automation.PSTypeName]'Win32.NativeMethods').Type) {
            Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();' -Name "NativeMethods" -Namespace Win32 | Out-Null
        }
        [Win32.NativeMethods]::SetProcessDPIAware() | Out-Null
    }
    [System.Windows.Forms.Application]::EnableVisualStyles()
}
catch {
    # If assemblies fail to load, display an error and exit, as the GUI cannot be rendered.
    Write-Error "Failed to load Windows Forms assemblies. This script requires a graphical environment."
    Write-Host "Failed to load assemblies: $($_.Exception.Message)"
    exit
}

#endregion

#region UI Theme & Icons

$script:Theme = @{
    FormBackground      = [System.Drawing.ColorTranslator]::FromHtml("#f0f2f5")
    GroupBackground     = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
    TextColor           = [System.Drawing.ColorTranslator]::FromHtml("#1f1f1f")
    PrimaryButton       = [System.Drawing.ColorTranslator]::FromHtml("#0078d4")
    PrimaryButtonText   = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
    SecondaryButton     = [System.Drawing.ColorTranslator]::FromHtml("#e1e1e1")
    SecondaryButtonText = [System.Drawing.ColorTranslator]::FromHtml("#1f1f1f")
    DangerButton        = [System.Drawing.ColorTranslator]::FromHtml("#d93025")
    DangerButtonText    = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
}

#endregion

#region Core Helper Functions

# Writes a timestamped message to the log file if logging is enabled in settings.
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('Info', 'Debug')][string]$Level = 'Debug' # Default to Debug for existing calls
    )
    if ($script:settings.EnableLogs) {
        # Log Rotation: Check if file exceeds 5MB and rotate if necessary
        if (Test-Path $logFilePath) {
            try {
                if ((Get-Item $logFilePath).Length -gt 5MB) {
                    $timestamp = (Get-Date).ToString('yyyyMMddHHmmss')
                    $logName = [System.IO.Path]::GetFileName($logFilePath)
                    Rename-Item -Path $logFilePath -NewName "$logName.$timestamp.bak" -ErrorAction SilentlyContinue

                    # Cleanup old logs (keep last 5)
                    $logDir = [System.IO.Path]::GetDirectoryName($logFilePath)
                    Get-ChildItem -Path $logDir -Filter "$logName.*.bak" | Sort-Object CreationTime -Descending | Select-Object -Skip 5 | Remove-Item -Force -ErrorAction SilentlyContinue
                }
            } catch { }
        }
        # Only log if the level is 'Info' or if the configured level is 'Debug'
        if ($Level -eq 'Info' -or $script:settings.LogLevel -eq 'Debug') {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            if (-not (Test-Path $logFilePath)) {
                Add-Content -Path $logFilePath -Value "Timestamp,Level,Message"
            }
            $safeMessage = '"' + $Message.Replace('"', '""') + '"'
            $logEntry = "$timestamp,$Level,$safeMessage"
            Add-Content -Path $logFilePath -Value $logEntry
        }
    }
}

# Factory function to create a System.Windows.Forms.Label control.
function New-Label {
    param (
        [string]$Text,
        [Parameter(Mandatory=$false)][System.Drawing.Point]$Location,
        [Parameter(Mandatory=$false)][System.Drawing.Size]$Size,
        [Parameter(Mandatory=$false)][hashtable]$Property
    )
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    if ($Location) { $label.Location = $Location }
    if ($Size) { $label.Size = $Size }
    if ($Property) {
        foreach ($p in $Property.Keys) {
            try { $label.$p = $Property[$p] } catch { }
        }
    }
    return $label
}

# Factory function to create a System.Windows.Forms.TextBox control.
function New-TextBox {
    param (
        [Parameter(Mandatory=$false)][System.Drawing.Point]$Location,
        [Parameter(Mandatory=$false)][System.Drawing.Size]$Size,
        [Parameter(Mandatory=$false)][bool]$Multiline,
        [Parameter(Mandatory=$false)][hashtable]$Property
    )
    $textBox = New-Object System.Windows.Forms.TextBox
    if ($Location) { $textBox.Location = $Location }
    if ($Size) { $textBox.Size = $Size }
    if ($PSBoundParameters.ContainsKey('Multiline')) { $textBox.Multiline = $Multiline }
    if ($Property) {
        foreach ($p in $Property.Keys) {
            try { $textBox.$p = $Property[$p] } catch { }
        }
    }
    return $textBox
}

# Factory function to create a System.Windows.Forms.Button control.
function New-Button {
    param (
        [string]$Text,
        [Parameter(Mandatory=$false)][System.Drawing.Point]$Location,
        [Parameter(Mandatory=$false)][System.Drawing.Size]$Size,
        [scriptblock]$OnClick,
        [Parameter(Mandatory=$false)][hashtable]$Property,
        [Parameter(Mandatory=$false)][ValidateSet('Primary', 'Secondary', 'Danger')][string]$Style = 'Secondary'
    )
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    if ($Location) { $button.Location = $Location }
    if ($Size) { $button.Size = $Size }

    # Apply modern styling
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderSize = 0
    $button.Font = New-Object System.Drawing.Font($button.Font.FontFamily, 9, [System.Drawing.FontStyle]::Bold)

    switch ($Style) {
        'Primary' {
            $button.BackColor = $script:Theme.PrimaryButton
            $button.ForeColor = $script:Theme.PrimaryButtonText
        }
        'Danger' {
            $button.BackColor = $script:Theme.DangerButton
            $button.ForeColor = $script:Theme.DangerButtonText
        }
        default { # Secondary
            $button.BackColor = $script:Theme.SecondaryButton
            $button.ForeColor = $script:Theme.SecondaryButtonText
        }
    }

    if ($Property) {
        foreach ($p in $Property.Keys) {
            try { $button.$p = $Property[$p] } catch { }
        }
    }
    $button.Add_Click($OnClick)
    return $button
}

# Factory function to create a System.Windows.Forms.RichTextBox control.
function New-RichTextBox {
    param (
        [Parameter(Mandatory=$false)][System.Drawing.Point]$Location,
        [Parameter(Mandatory=$false)][System.Drawing.Size]$Size,
        [Parameter(Mandatory=$false)][bool]$ReadOnly,
        [Parameter(Mandatory=$false)][hashtable]$Property
    )
    $richTextBox = New-Object System.Windows.Forms.RichTextBox
    if ($Location) { $richTextBox.Location = $Location }
    if ($Size) { $richTextBox.Size = $Size }
    $richTextBox.ReadOnly = $ReadOnly
    if ($Property) {
        foreach ($p in $Property.Keys) {
            try { $richTextBox.$p = $Property[$p] } catch { }
        }
    }
    $richTextBox.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Both
    $richTextBox.WordWrap = $false
    return $richTextBox
}

# Creates a context menu with a "Copy" item for a given text-based control.
function New-CopyContextMenu {
    param([System.Windows.Forms.TextBoxBase]$ParentControl)

    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

    $copyMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Copy")
    $copyMenuItem.Tag = $ParentControl # Store the control reference
    $copyMenuItem.Add_Click({
        $controlToCopy = $this.Tag # Retrieve the correct text box
        if ($controlToCopy.SelectionLength -gt 0) {
            # If there's a selection, copy just the selection
            $controlToCopy.Copy()
        } elseif (-not [string]::IsNullOrEmpty($controlToCopy.Text)) {
            # Otherwise, if there's any text at all, copy all of it
            [System.Windows.Forms.Clipboard]::SetText($controlToCopy.Text)
        }
    })

    [void]$contextMenu.Add_Opening({
        param($sender, $e)
        # Enable the "Copy" item only if the associated control contains text or has a selection.
        # The 'sender' is the context menu. We retrieve the copyMenuItem from its Items collection.
        $menuItem = $sender.Items[0]
        $menuItem.Enabled = (-not [string]::IsNullOrEmpty($menuItem.Tag.Text) -or $menuItem.Tag.SelectionLength -gt 0)
    })

    [void]$contextMenu.Items.Add($copyMenuItem)
    return $contextMenu
}

# Simple JSON path evaluator (e.g. $.data.token or data.items[0].id)
function Get-JsonPathValue {
    param(
        [object]$JsonObject,
        [string]$Path
    )
    if (-not $JsonObject -or [string]::IsNullOrWhiteSpace($Path)) { return $null }

    $clean = $Path.Trim()
    if ($clean.StartsWith('$')) { $clean = $clean.TrimStart('$') }
    if ($clean.StartsWith('.')) { $clean = $clean.Substring(1) }
    if ([string]::IsNullOrWhiteSpace($clean)) { return $JsonObject }

    function Get-PropertyValue {
        param([object]$Obj, [string]$Name)
        if ($Obj -is [hashtable]) {
            if ($Obj.ContainsKey($Name)) { return $Obj[$Name] }
            return $null
        }
        if ($Obj -and $Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
        return $null
    }

    function Get-ByPathSimple {
        param([object]$Obj, [string]$NamePath)
        $cur = $Obj
        foreach ($part in ($NamePath -split '\.')) {
            if ([string]::IsNullOrWhiteSpace($part)) { continue }
            $cur = Get-PropertyValue -Obj $cur -Name $part
            if ($null -eq $cur) { return $null }
        }
        return $cur
    }

    function Split-JsonPathSegments {
        param([string]$p)
        $segments = New-Object System.Collections.Generic.List[string]
        $sb = New-Object System.Text.StringBuilder
        $depth = 0
        foreach ($ch in $p.ToCharArray()) {
            if ($ch -eq '[') { $depth++ }
            if ($ch -eq ']') { $depth-- }
            if ($ch -eq '.' -and $depth -eq 0) {
                if ($sb.Length -gt 0) { $segments.Add($sb.ToString()); $sb.Clear() | Out-Null }
            } else {
                [void]$sb.Append($ch)
            }
        }
        if ($sb.Length -gt 0) { $segments.Add($sb.ToString()) }
        return $segments
    }

    $nodes = @($JsonObject)
    $segments = Split-JsonPathSegments -p $clean

    foreach ($seg in $segments) {
        if ($seg -eq '*') {
            $expanded = @()
            foreach ($n in $nodes) {
                if ($n -is [array] -or $n -is [System.Collections.IList]) {
                    $expanded += @($n)
                } elseif ($n -is [hashtable]) {
                    $expanded += $n.Values
                } elseif ($n) {
                    $expanded += $n.PSObject.Properties.Value
                }
            }
            $nodes = $expanded
            continue
        }

        $name = $seg
        $brackets = ""
        if ($seg -match '^([^\[]+)(.*)$') {
            $name = $matches[1]
            $brackets = $matches[2]
        }

        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $nextNodes = @()
            foreach ($n in $nodes) {
                $val = Get-PropertyValue -Obj $n -Name $name
                if ($null -ne $val) { $nextNodes += $val }
            }
            $nodes = $nextNodes
        }

        if ($brackets) {
            $bracketMatches = [regex]::Matches($brackets, "\[(.*?)\]")
            foreach ($bm in $bracketMatches) {
                $inner = $bm.Groups[1].Value.Trim()
                if ($inner -eq "*") {
                    $expanded = @()
                    foreach ($n in $nodes) {
                        if ($n -is [array] -or $n -is [System.Collections.IList]) { $expanded += @($n) }
                    }
                    $nodes = $expanded
                    continue
                }
                if ($inner -match '^\d+$') {
                    $idx = [int]$inner
                    $indexed = @()
                    foreach ($n in $nodes) {
                        if ($n -is [array] -or $n -is [System.Collections.IList]) {
                            if ($idx -lt $n.Count) { $indexed += $n[$idx] }
                        }
                    }
                    $nodes = $indexed
                    continue
                }
                if ($inner -match '^\?\((.+)\)$') {
                    $expr = $matches[1].Trim()
                    $filterMatch = [regex]::Match($expr, '@\.([A-Za-z0-9_\.]+)\s*(==|!=)\s*(.+)')
                    if ($filterMatch.Success) {
                        $propPath = $filterMatch.Groups[1].Value
                        $op = $filterMatch.Groups[2].Value
                        $rawVal = $filterMatch.Groups[3].Value.Trim()
                        $cmpVal = $rawVal
                        if (($rawVal.StartsWith('"') -and $rawVal.EndsWith('"')) -or ($rawVal.StartsWith("'") -and $rawVal.EndsWith("'"))) {
                            $cmpVal = $rawVal.Substring(1, $rawVal.Length - 2)
                        } elseif ($rawVal -match '^(true|false)$') {
                            $cmpVal = [bool]::Parse($rawVal)
                        } elseif ($rawVal -match '^-?\d+(\.\d+)?$') {
                            $cmpVal = [double]$rawVal
                        }

                        $filtered = @()
                        foreach ($n in $nodes) {
                            if ($n -is [array] -or $n -is [System.Collections.IList]) {
                                foreach ($item in $n) {
                                    $val = Get-ByPathSimple -Obj $item -NamePath $propPath
                                    $match = $false
                                    if ($op -eq "==") { $match = ($val -eq $cmpVal) }
                                    else { $match = ($val -ne $cmpVal) }
                                    if ($match) { $filtered += $item }
                                }
                            }
                        }
                        $nodes = $filtered
                    }
                }
            }
        }
    }

    if ($nodes.Count -eq 1) { return $nodes[0] }
    return $nodes
}

# Converts a JSON string into Rich Text Format (RTF) with syntax highlighting.
function Format-JsonAsRtf {
    param(
        [string]$JsonString,
        [int]$FontSize = 9
    )    

    # Performance Check: If JSON is too large (>100KB), skip highlighting to prevent UI freeze.
    if ($JsonString.Length -gt 100000) {
        $halfPoints = $FontSize * 2
        $escaped = $JsonString.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}')
        return "{\rtf1\ansi\deff0{\fonttbl{\f0 Courier New;}}\fs$halfPoints $escaped}"
    }

    # Define RTF color table. \cf1=Key, \cf2=String, \cf3=Number, \cf4=Boolean, \cf5=Null
    $halfPoints = $FontSize * 2
    $rtfHeader = "{\rtf1\ansi\deff0{\fonttbl{\f0 Courier New;}}\fs$halfPoints"
    $colorTable = '{\colortbl;\red0\green0\blue0;\red163\green21\blue21;\red0\green0\blue205;\red0\green128\blue0;\red128\green0\blue128;\red128\green128\blue128;}'
    $rtfBuilder = New-Object System.Text.StringBuilder
    $rtfBuilder.Append($rtfHeader).Append($colorTable)

    # This regex tokenizes the JSON string, capturing strings, numbers, keywords, and punctuation.
    $jsonTokenRegex = '("(\\"|[^"])*")|(-?\d+(\.\d+)?([eE][+-]?\d+)?)|(true|false|null)|([\{\}\[\]:,])'
    $matches = [regex]::Matches($JsonString, $jsonTokenRegex)
    $indentationLevel = 0
    $isKey = $false

    foreach ($match in $matches) {
        $value = $match.Value
        $colorIndex = 1 # Default to black text color.

        if ($match.Groups[1].Success) { # String            
            $colorIndex = if ($isKey) { 2 } else { 3 } # Use key color or string color.
            $isKey = $false
        }
        elseif ($match.Groups[3].Success) { $colorIndex = 3 } # Number
        elseif ($match.Groups[6].Success) { $colorIndex = 4 } # Boolean or Null.
        elseif ($match.Groups[7].Success) { # Punctuation
            $isKey = $false
            if ($value -eq '{' -or $value -eq '[') {
                $indentationLevel++
                $rtfBuilder.Append("\cf$colorIndex $value\par ").Append((' ' * 4 * $indentationLevel)) | Out-Null
                $isKey = ($value -eq '{')
                continue
            }
            elseif ($value -eq '}' -or $value -eq ']') {
                $indentationLevel--
                $rtfBuilder.Append("\par ").Append((' ' * 4 * $indentationLevel)).Append("\cf$colorIndex $value") | Out-Null
                continue
            }
            elseif ($value -eq ':') {
                $isKey = $false
                $rtfBuilder.Append("\cf1 $value ") | Out-Null
                continue
            }
            elseif ($value -eq ',') {
                $rtfBuilder.Append("\cf1 $value\par ").Append((' ' * 4 * $indentationLevel)) | Out-Null
                $isKey = ($matches[$matches.IndexOf($match) - 1].Value -eq '{')
                continue
            }
        }

        # Escape special RTF characters and append the colored, formatted text.
        $escapedValue = $value.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}')
        $rtfBuilder.Append("\cf$colorIndex $escapedValue") | Out-Null
    }

    $rtfBuilder.Append('}') | Out-Null
    return $rtfBuilder.ToString()
}

# Converts a "redlinedocument" JSON object into a visually formatted RTF string.
function Format-RedlineAsRtf {
    param(
        [PSCustomObject]$RedlineJson,
        [int]$FontSize = 9
    )

    $rtfBuilder = New-Object System.Text.StringBuilder
    # Define RTF header with a color table for changes.
    # \cf1=Black, \cf2=Red (Deletions), \cf3=Blue (Insertions)
    $halfPoints = $FontSize * 2
    $rtfBuilder.Append("{\rtf1\ansi\deff0{\fonttbl{\f0 Times New Roman;}}\fs$halfPoints")
    $rtfBuilder.Append('{\colortbl;\red0\green0\blue0;\red255\green0\blue0;\red0\green0\blue255;}') | Out-Null

    # Helper function to recursively process content nodes
    function Process-Node {
        param($node)

        switch ($node._type) {
            "section" {
                foreach ($child in $node.content) { Process-Node -node $child }
            }
            "paragraph" {
                if ($node.isdeleted) {
                    # Skip rendering deleted paragraphs entirely for clarity
                } else {
                    foreach ($child in $node.content) { Process-Node -node $child }
                    $script:rtfBuilder.Append('\par ') | Out-Null # End of paragraph
                }
            }
            "change" {
                if ($node.type -eq "deletion") {
                    $script:rtfBuilder.Append('\cf2\strike ') | Out-Null # Red, strikethrough
                    foreach ($child in $node.content) { Process-Node -node $child }
                    $script:rtfBuilder.Append('\strike0\cf1 ') | Out-Null # Reset format
                }
                # Note: Insertions are handled by their text content having a different color/decoration
                # in a more complex implementation. For now, we just render the text.
            }
            default { # This will handle text runs
                if ($node.text) {
                    # Escape special RTF characters
                    $escapedText = $node.text.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}')
                    $script:rtfBuilder.Append($escapedText) | Out-Null
                }
            }
        }
    }

    # Set the builder in a script scope so the helper function can access it
    $script:rtfBuilder = $rtfBuilder
    Process-Node -node $RedlineJson
    $script:rtfBuilder = $null # Clean up

    $rtfBuilder.Append('}') | Out-Null
    return $rtfBuilder.ToString()
}

# Determines the MIME type of a file based on its extension.
function Get-MimeType {
    param([string]$filePath)
    $extension = [System.IO.Path]::GetExtension($filePath).ToLower()
    switch ($extension) {
        '.pdf'  { return 'application/pdf' }
        '.json' { return 'application/json' }
        '.xml'  { return 'application/xml' }
        '.txt'  { return 'text/plain' }
        '.jpg'  { return 'image/jpeg' }
        '.jpeg' { return 'image/jpeg' }
        '.png'  { return 'image/png' }
        '.gif'  { return 'image/gif' }
        '.doc'  { return 'application/msword' }
        '.docx' { return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }
        '.xls'  { return 'application/vnd.ms-excel' }
        '.xlsx' { return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }
        '.ppt'  { return 'application/vnd.ms-powerpoint' }
        '.pptx' { return 'application/vnd.openxmlformats-officedocument.presentationml.presentation' }
        '.zip'  { return 'application/zip' }
        default { return 'application/octet-stream' } # Default for unknown or binary files.
    }
}

# Formats test results into Rich Text Format (RTF) with color coding for pass/fail.
function Format-TestResultsAsRtf {
    param(
        [array]$Results,
        [int]$FontSize = 9
    )
    $rtfBuilder = New-Object System.Text.StringBuilder
    $halfPoints = $FontSize * 2
    $rtfBuilder.Append("{\rtf1\ansi\deff0{\fonttbl{\f0 Courier New;}}\fs$halfPoints")
    # Define colors: \cf1=Black, \cf2=Green, \cf3=Red, \cf4=Orange (Warning)
    $rtfBuilder.Append('{\colortbl;\red0\green0\blue0;\red0\green128\blue0;\red255\green0\blue0;\red255\green165\blue0;}') | Out-Null

    if (-not $Results -or $Results.Count -eq 0) {
        $rtfBuilder.Append("\cf1 No tests were executed or no results were reported.") | Out-Null
    } else {
        foreach ($result in $Results) {
            $colorIndex = 1 # Default to black
            switch ($result.Status) {
                "PASS"   { $colorIndex = 2 } # Green
                "FAIL"   { $colorIndex = 3 } # Red
                "WARN"   { $colorIndex = 4 } # Orange
                "ERROR"  { $colorIndex = 3 } # Red
            }
            $message = $result.Message.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}')
            $rtfBuilder.Append("\cf$colorIndex [$($result.Status)] $message\par")
        }
    }
    $rtfBuilder.Append('}')
    return $rtfBuilder.ToString()
}

$script:testResults = @() # Initialize global test results array

# --- Test Assertion Library ---
function Assert-Equal {
    param($Value, $Expected, $Message)
    if ($Value -eq $Expected) {
        $script:testResults.Add([PSCustomObject]@{ Status = 'PASS'; Message = "Value '$Value' equals expected '$Expected'." }) | Out-Null
    } else {
        $script:testResults.Add([PSCustomObject]@{ Status = 'FAIL'; Message = "Assertion Failed: Expected '$Expected', but got '$Value'. $Message" }) | Out-Null
    }
}

function Assert-Contains {
    param([string]$String, [string]$Substring, $Message)
    if ($String -like "*$Substring*") {
        $script:testResults.Add([PSCustomObject]@{ Status = 'PASS'; Message = "Value contains expected substring." }) | Out-Null
    } else {
        $script:testResults.Add([PSCustomObject]@{ Status = 'FAIL'; Message = "Assertion Failed: Value does not contain expected substring. $Message" }) | Out-Null
    }
}

function Assert-StatusIs {
    param([int]$StatusCode, [int]$ExpectedStatus)
    if ($StatusCode -eq $ExpectedStatus) {
        $script:testResults.Add([PSCustomObject]@{ Status = 'PASS'; Message = "Status code is $ExpectedStatus." }) | Out-Null
    } else {
        $script:testResults.Add([PSCustomObject]@{ Status = 'FAIL'; Message = "Assertion Failed: Expected status code $ExpectedStatus, but got $StatusCode." }) | Out-Null
    }
}
#endregion

#region Data Management (History, Environments, Settings)

$script:history = @()
$script:isRepeating = $false
$script:repeatCount = 0
$script:currentRepeatIteration = 0
$script:repeatSuccessCount = 0
$script:repeatFailCount = 0

function Load-History {
    if (Test-Path $historyFilePath) {
        try {
            $jsonContent = Get-Content -Path $historyFilePath -Raw
            # Filter out any null entries that might be in the JSON array
            $script:history = ($jsonContent | ConvertFrom-Json -ErrorAction SilentlyContinue) | Where-Object { $_ -ne $null }
            Write-Log "History loaded from $historyFilePath"
        } catch { # Catch block for Load-History
            Write-Log "Could not load or parse history file: $($_.Exception.Message)" -Level Info
            $script:history = @()
        }
    }
}

function Save-History {
    try { # Try block for Save-History
        $script:history | ConvertTo-Json -Depth 5 | Set-Content -Path $historyFilePath
    } catch {
        Write-Log "Failed to save history: $($_.Exception.Message)" -Level Debug
    }
}

$script:globals = @{}

function Load-Globals {
    if (Test-Path $globalsFilePath) {
        try {
            $json = Get-Content -Path $globalsFilePath -Raw
            $script:globals = $json | ConvertFrom-Json -AsHashtable -ErrorAction SilentlyContinue
            if (-not $script:globals) { $script:globals = @{} }
            Write-Log "Globals loaded from $globalsFilePath" -Level Debug
        } catch {
            Write-Log "Could not load or parse globals file: $($_.Exception.Message)" -Level Info
            $script:globals = @{}
        }
    }
}

function Save-Globals {
    try {
        $script:globals | ConvertTo-Json -Depth 10 | Out-File -FilePath $globalsFilePath -Encoding utf8 -NoNewline -ErrorAction Stop
    } catch {
        Write-Log "Failed to save globals: $($_.Exception.Message)" -Level Debug
    }
}

$script:environments = @{}
$script:activeEnvironment = "No Environment"

function Load-Environments {
    if (Test-Path $environmentsFilePath) {
        try {
            $json = Get-Content -Path $environmentsFilePath -Raw
            $script:environments = $json | ConvertFrom-Json -AsHashtable -ErrorAction SilentlyContinue
            # Decrypt sensitive fields
            foreach ($env in $script:environments.Values) {
                if ($env.Authentication) {
                    foreach ($k in @('Value','Token','Password','ClientSecret','AccessToken','RefreshToken')) {
                        if ($env.Authentication[$k]) { $env.Authentication[$k] = Unprotect-String $env.Authentication[$k] }
                    }
                }
            }
            Write-Log "Environments loaded from $environmentsFilePath" -Level Debug
        } catch { # Catch block for Load-Environments
            Write-Log "Could not load or parse environments file: $($_.Exception.Message)" -Level Info
            $script:environments = @{}
        }
    }
}

function Save-Environments {
    try {
        # Clone and Encrypt
        $jsonRaw = $script:environments | ConvertTo-Json -Depth 10
        $envCopy = $jsonRaw | ConvertFrom-Json -AsHashtable
        foreach ($env in $envCopy.Values) {
            if ($env.Authentication) {
                foreach ($k in @('Value','Token','Password','ClientSecret','AccessToken','RefreshToken')) {
                    if ($env.Authentication[$k]) { $env.Authentication[$k] = Protect-String $env.Authentication[$k] }
                }
            }
        }
        $json = $envCopy | ConvertTo-Json -Depth 10
        # Use Out-File with a specific encoding to prevent BOM (Byte Order Mark) issues.
        $json | Out-File -FilePath $environmentsFilePath -Encoding utf8 -NoNewline -ErrorAction Stop
    } catch { # Catch block for Save-Environments
        Write-Log "Failed to save environments: $($_.Exception.Message)" -Level Debug
    }
}

$script:collections = @()
$script:activeCollectionName = $null
$script:activeCollectionNode = $null
$script:activeCollectionVariables = @{}

function Ensure-CollectionVariables {
    param([array]$Items)
    foreach ($item in ($Items | Where-Object { $_ -ne $null })) {
        if ($item.Type -eq "Collection") {
            if (-not ($item.PSObject.Properties.Name -contains 'Variables')) {
                $item | Add-Member -MemberType NoteProperty -Name 'Variables' -Value @{}
            } elseif ($null -eq $item.Variables) {
                $item.Variables = @{}
            }
        }
        if ($item.Items) { Ensure-CollectionVariables -Items $item.Items }
    }
}

function Load-Collections {
    if (Test-Path $collectionsFilePath) {
        try {
            $jsonContent = Get-Content -Path $collectionsFilePath -Raw
            if (-not [string]::IsNullOrWhiteSpace($jsonContent)) {
                $script:collections = $jsonContent | ConvertFrom-Json -ErrorAction SilentlyContinue
            }
            if ($script:collections -and $script:collections -isnot [array]) { $script:collections = @($script:collections) }
            Ensure-CollectionVariables -Items $script:collections
            Write-Log "Collections loaded from $collectionsFilePath" -Level Debug
        } catch { # Catch block for Load-Collections
            Write-Log "Could not load or parse collections file: $($_.Exception.Message)" -Level Info
            $script:collections = @()
        }
    }
}

function Save-Collections {
    try {
        $json = $script:collections | ConvertTo-Json -Depth 10
        $json | Out-File -FilePath $collectionsFilePath -Encoding utf8 -NoNewline -ErrorAction Stop
    } catch {
        Write-Log "Failed to save collections: $($_.Exception.Message)" -Level Debug
        Write-Log "Failed to save collections: $($_.Exception.Message)" -Level Info
    }
}

$script:monitors = @()

function Load-Monitors {
    if (Test-Path $monitorsFilePath) {
        try {
            $json = Get-Content -Path $monitorsFilePath -Raw
            $script:monitors = $json | ConvertFrom-Json
            if ($script:monitors -isnot [array]) { $script:monitors = @($script:monitors) }
            # Migration for monitors saved without BodyType or RequestTimeoutSeconds
            foreach ($monitor in ($script:monitors | Where-Object { $_ -ne $null })) {
                if ($monitor.Request) {
                    if (-not ($monitor.Request.PSObject.Properties.Name -contains 'BodyType')) {
                        $monitor.Request | Add-Member -MemberType NoteProperty -Name 'BodyType' -Value 'multipart/form-data'
                    }
                    if (-not ($monitor.Request.PSObject.Properties.Name -contains 'RequestTimeoutSeconds')) {
                        $monitor.Request | Add-Member -MemberType NoteProperty -Name 'RequestTimeoutSeconds' -Value 30
                    }
                    if (-not ($monitor.Request.PSObject.Properties.Name -contains 'Authentication')) {
                        $monitor.Request | Add-Member -MemberType NoteProperty -Name 'Authentication' -Value @{ Type = "No Auth" }
                    }
                }
                # Migration for monitors missing the Alerts object or its properties
                if (-not ($monitor.PSObject.Properties.Name -contains 'Alerts')) {
                    $monitor | Add-Member -MemberType NoteProperty -Name 'Alerts' -Value @{ OnFailure=$true; OnSlow=$false; ThresholdMs=1000; SendEmail=$false; EmailTo="" }
                } else {
                    # Ensure all sub-properties exist
                    if (-not ($monitor.Alerts.PSObject.Properties.Name -contains 'OnFailure'))   { $monitor.Alerts | Add-Member -MemberType NoteProperty -Name 'OnFailure' -Value $true }
                    if (-not ($monitor.Alerts.PSObject.Properties.Name -contains 'OnSlow'))      { $monitor.Alerts | Add-Member -MemberType NoteProperty -Name 'OnSlow' -Value $false }
                    if (-not ($monitor.Alerts.PSObject.Properties.Name -contains 'ThresholdMs')) { $monitor.Alerts | Add-Member -MemberType NoteProperty -Name 'ThresholdMs' -Value 1000 }
                    if (-not ($monitor.Alerts.PSObject.Properties.Name -contains 'SendEmail'))   { $monitor.Alerts | Add-Member -MemberType NoteProperty -Name 'SendEmail' -Value $false }
                    if (-not ($monitor.Alerts.PSObject.Properties.Name -contains 'EmailTo'))     { $monitor.Alerts | Add-Member -MemberType NoteProperty -Name 'EmailTo' -Value "" }
                }
            }
        } catch {
            $script:monitors = @()
        }
    }
}

function Save-Monitors {
    $script:monitors | ConvertTo-Json -Depth 10 | Set-Content -Path $monitorsFilePath
}

$script:grpcHistory = @()

function Load-GrpcHistory {
    if (Test-Path $grpcHistoryFilePath) {
        try {
            $json = Get-Content -Path $grpcHistoryFilePath -Raw
            $script:grpcHistory = $json | ConvertFrom-Json
            if ($script:grpcHistory -isnot [array]) { $script:grpcHistory = @($script:grpcHistory) }
        } catch {
            $script:grpcHistory = @()
        }
    }
}

function Save-GrpcHistory {
    $script:grpcHistory | ConvertTo-Json -Depth 5 | Set-Content -Path $grpcHistoryFilePath
}
$script:defaultSettings = @{
    ShowResponse = $true
    ShowJsonTreeTab = $false
    ShowCurl = $true
    ShowHistory = $true
    ShowResponseHeaders = $true
    AutoSaveToFile = $false
    AutoSavePath = ""
    ShowConsoleTab = $true
    DefaultConsoleLanguage = "PowerShell"
    AutoRenameFile = $false
    EnableAutoRenamePrefix = $false
    AutoRenamePrefix = ""
    AutoRunHistory = $true
    EnableHistory = $true
    IncludeFilename = $true
    EnableLogs = $true
    EnableAllMethods = $false
    IncludeContentType = $true
    LogLevel = 'Info'
    ShowEnvironmentPanel = $true
    ShowRequestHeadersTab = $true
    ShowAuthTab = $true
    ShowPreRequestTab = $false
    ShowTestsTab = $false
    ShowTestResultsTab = $false
    LastActiveEnvironment = "No Environment"
    ResponseDockState = "Right"
    IgnoreSslErrors = $false
    RequestTimeoutSeconds = 60
    ResponseFontSize = 8
    EnablePostmanImport = $false
    EnableCurlImport = $false
    EnableRepeatRequest = $false
    MaxRepeatCount = 5
    MonitorSmtpServer = ""
    MonitorSmtpPort = 587
    MonitorSmtpUseSsl = $true
    MonitorSmtpFrom = ""
    MonitorSmtpUser = ""
    MonitorSmtpPass = ""
    MonitorSmtpAuthMethod = "Basic"
    MonitorSmtpClientId = ""
    MonitorSmtpClientSecret = ""
    MonitorSmtpRefreshToken = ""
    MonitorSmtpTokenEndpoint = ""
    MonitorSmtpTokenExpiry = ""
    MonitorAlertSubjectTemplate = "API Alert: {MonitorName}"
    MonitorAlertBodyTemplate = "Monitor: {MonitorName}`r`nStatus: {Status}`r`nStatus Code: {StatusCode}`r`nURL: {Url}`r`nTime (ms): {TimeMs}`r`nMessage: {Message}`r`nTimestamp: {Timestamp}"
    MonitorAlertBodyForceHtml = $false
    ProxyMode = "System" # System, Custom, None
    ProxyAddress = ""
    ProxyPort = 8080
    ProxyUser = ""
    ProxyPass = ""
}

$script:settings = $script:defaultSettings.Clone()


function Load-Settings {
    if (Test-Path $settingsFilePath) {
        try {
            Copy-Item -Path $settingsFilePath -Destination "$settingsFilePath.bak" -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Failed to backup settings: $($_.Exception.Message)" -Level Info
        }

        try {
            $loadedSettings = Get-Content -Path $settingsFilePath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue

            # Merge settings from file, adding new keys if they exist in the file but not in the defaults.
            foreach ($key in $loadedSettings.PSObject.Properties.Name) {
                if (-not $script:settings.ContainsKey($key)) {
                    $script:settings[$key] = $loadedSettings.$key
                }
            }
            foreach ($key in $loadedSettings.PSObject.Properties.Name) {
                if ($script:settings.ContainsKey($key)) { $script:settings[$key] = $loadedSettings.$key }
            }            
            Write-Log "Settings loaded from $settingsFilePath"
        } catch { # Catch block for Load-Settings
            Write-Log "Could not load or parse settings file: $($_.Exception.Message)" -Level Info
        }
    }
    # Ensure all default settings are present in the loaded settings
    foreach ($key in $script:defaultSettings.Keys) {
        if (-not $script:settings.ContainsKey($key)) { $script:settings[$key] = $script:defaultSettings[$key] }
    }
    # Validate critical settings to prevent crashes
    if ([int]$script:settings.ResponseFontSize -le 0) { $script:settings.ResponseFontSize = $script:defaultSettings.ResponseFontSize }
    if ([int]$script:settings.RequestTimeoutSeconds -le 0) { $script:settings.RequestTimeoutSeconds = $script:defaultSettings.RequestTimeoutSeconds }

    # Decrypt SMTP Password if present
    if ($script:settings.MonitorSmtpPass) { $script:settings.MonitorSmtpPass = Unprotect-String $script:settings.MonitorSmtpPass }
    if ($script:settings.MonitorSmtpClientSecret) { $script:settings.MonitorSmtpClientSecret = Unprotect-String $script:settings.MonitorSmtpClientSecret }
    if ($script:settings.MonitorSmtpRefreshToken) { $script:settings.MonitorSmtpRefreshToken = Unprotect-String $script:settings.MonitorSmtpRefreshToken }
}

function Save-Settings {
    $settingsToSave = $script:settings.Clone()
    if ($settingsToSave.MonitorSmtpPass) { $settingsToSave.MonitorSmtpPass = Protect-String $settingsToSave.MonitorSmtpPass }
    if ($settingsToSave.MonitorSmtpClientSecret) { $settingsToSave.MonitorSmtpClientSecret = Protect-String $settingsToSave.MonitorSmtpClientSecret }
    if ($settingsToSave.MonitorSmtpRefreshToken) { $settingsToSave.MonitorSmtpRefreshToken = Protect-String $settingsToSave.MonitorSmtpRefreshToken }
    if ($settingsToSave.ProxyPass) { $settingsToSave.ProxyPass = Protect-String $settingsToSave.ProxyPass }
    $settingsToSave | ConvertTo-Json | Set-Content -Path $settingsFilePath
}

# Formats a byte count into a human-readable string (e.g., KB, MB, GB).
function Format-Bytes {
    param([long]$bytes)
    if ($bytes -lt 0) { return "N/A" }
    $units = @("B", "KB", "MB", "GB", "TB")
    $i = 0
    $size = [double]$bytes
    while ($size -ge 1024 -and $i -lt ($units.Length - 1)) {
        $size /= 1024
        $i++
    }
    return "{0:N2} {1}" -f $size, $units[$i]
}

# Replaces placeholders like {{variableName}} in a string with values from the active environment.
function Substitute-Variables {
    param ([string]$InputString)
    
    $activeEnvVars = $null
    if ($script:activeEnvironment -ne "No Environment" -and $script:environments.ContainsKey($script:activeEnvironment)) {
        $envData = $script:environments[$script:activeEnvironment]
        if ($envData -is [hashtable] -and $envData.ContainsKey('Variables')) { $activeEnvVars = $envData.Variables }
        elseif ($envData.PSObject.Properties.Name -contains 'Variables') { $activeEnvVars = $envData.Variables }
        else { $activeEnvVars = $envData }
    }

    $maxDepth = 5
    $currentString = $InputString

    for ($i = 0; $i -lt $maxDepth; $i++) {
        $previousString = $currentString
        $evaluator = {
            param($match)
            $varName = $match.Groups[1].Value
            if ($activeEnvVars -and $activeEnvVars.ContainsKey($varName)) { return $activeEnvVars[$varName] }
            if ($script:activeCollectionVariables -and $script:activeCollectionVariables.ContainsKey($varName)) { return $script:activeCollectionVariables[$varName] }
            if ($script:globals -and $script:globals.ContainsKey($varName)) { return $script:globals[$varName] }
            
            switch ($varName) {
                '$guid'      { return [Guid]::NewGuid().ToString() }
                '$timestamp' { return [int64](Get-Date -UFormat %s) }
                '$randomInt' { return (Get-Random -Minimum 1 -Maximum 10000).ToString() }
                default      { return $match.Value }
            }
        }
        $currentString = [regex]::Replace($currentString, '\{\{([^{}]+?)\}\}', $evaluator)
        if ($currentString -eq $previousString) { break }
    }
    return $currentString
}

# Replaces {Placeholders} in alert templates with actual values.
function Format-AlertTemplate {
    param(
        [string]$Template,
        [hashtable]$Data
    )
    if ([string]::IsNullOrWhiteSpace($Template)) { return "" }
    $result = $Template
    foreach ($key in $Data.Keys) {
        $token = "\{$key\}"
        $result = $result -replace $token, [string]$Data[$key]
    }
    return $result
}

# Simple heuristic to detect HTML content in email body.
function Test-IsHtmlBody {
    param([string]$Body)
    if ([string]::IsNullOrWhiteSpace($Body)) { return $false }
    return ($Body -match '<\s*(html|body|div|span|p|br|table|tr|td|a|b|i|strong|em|ul|ol|li)\b')
}

# Factory function to create a standardized TableLayoutPanel for authentication details.
function New-AuthDetailTable {
    $table = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Top'; ColumnCount = 2; AutoSize = $true; AutoSizeMode = 'GrowAndShrink' }
    $table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    return $table
}

# --- Encryption Helpers (DPAPI) ---
function Protect-String {
    param([string]$String)
    if ([string]::IsNullOrEmpty($String)) { return $String }
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Convert]::ToBase64String($encrypted)
    } catch { return $String }
}

function Unprotect-String {
    param([string]$String)
    if ([string]::IsNullOrEmpty($String)) { return $String }
    try {
        $bytes = [Convert]::FromBase64String($String)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    } catch { return $String } # Return original if decryption fails (e.g. plain text)
}

# Sends an email using SMTP XOAUTH2 (required for Gmail/Outlook Modern Auth).
function Send-SmtpOAuth2 {
    param($Server, $Port, $UseSsl, $From, $To, $Subject, $Body, $User, $AccessToken, [bool]$IsHtml = $false)
    
    try {
        $client = New-Object System.Net.Sockets.TcpClient($Server, $Port)
        $stream = $client.GetStream()
        if ($UseSsl) {
            $sslStream = New-Object System.Net.Security.SslStream($stream)
            $sslStream.AuthenticateAsClient($Server)
            $stream = $sslStream
        }
        
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true
        
        function Read-Response { return $reader.ReadLine() }
        function Send-Command { param($cmd) $writer.WriteLine($cmd) }
        
        Read-Response | Out-Null # Banner
        Send-Command "EHLO localhost"
        while($line = Read-Response) { if($line -match "^\d+ ") { break } }
        
        # Auth XOAUTH2 construction: user=EMAIL^Aauth=Bearer TOKEN^A^A
        $authStr = "user=$User`x01auth=Bearer $AccessToken`x01`x01"
        $authBytes = [System.Text.Encoding]::ASCII.GetBytes($authStr)
        $authBase64 = [Convert]::ToBase64String($authBytes)
        
        Send-Command "AUTH XOAUTH2 $authBase64"
        $res = Read-Response
        if ($res -notmatch "^235") { throw "SMTP Auth Failed: $res" }
        
        Send-Command "MAIL FROM: <$From>"; Read-Response | Out-Null
        Send-Command "RCPT TO: <$To>"; Read-Response | Out-Null
        Send-Command "DATA"; Read-Response | Out-Null
        
        $contentType = if ($IsHtml) { "text/html; charset=utf-8" } else { "text/plain; charset=utf-8" }
        $headers = "Subject: $Subject`r`nFrom: $From`r`nTo: $To`r`nMIME-Version: 1.0`r`nContent-Type: $contentType`r`n"
        Send-Command "$headers`r`n$Body`r`n."
        Read-Response | Out-Null
        Send-Command "QUIT"
        $client.Close()
    } catch { throw $_ }
}

function Refresh-SmtpToken {
    if (-not $script:settings.MonitorSmtpRefreshToken -or -not $script:settings.MonitorSmtpTokenEndpoint) { return }
    try {
        Write-Log "Refreshing SMTP OAuth2 Token..." -Level Info
        $body = @{
            grant_type    = "refresh_token"
            refresh_token = $script:settings.MonitorSmtpRefreshToken
            client_id     = $script:settings.MonitorSmtpClientId
            client_secret = $script:settings.MonitorSmtpClientSecret
        }
        $response = Invoke-RestMethod -Uri $script:settings.MonitorSmtpTokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        
        $script:settings.MonitorSmtpPass = $response.access_token
        if ($response.refresh_token) { $script:settings.MonitorSmtpRefreshToken = $response.refresh_token }
        if ($response.expires_in) { $script:settings.MonitorSmtpTokenExpiry = ([DateTime]::UtcNow).AddSeconds([int]$response.expires_in).ToString("o") }
        Save-Settings
        Write-Log "SMTP Token Refreshed." -Level Info
    } catch {
        Write-Log "SMTP Token Refresh Failed: $($_.Exception.Message)" -Level Info
        throw $_
    }
}

#endregion

#region UI Windows (Settings, Main Form)

# --- Simple Variables Editor (key=value) ---
function Show-VariablesEditor {
    param(
        [System.Windows.Forms.Form]$parentForm,
        [string]$Title,
        [hashtable]$Variables
    )

    $form = New-Object System.Windows.Forms.Form -Property @{
        Text          = $Title
        Size          = New-Object System.Drawing.Size(600, 500)
        StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
        BackColor     = $script:Theme.FormBackground
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        MinimumSize   = New-Object System.Drawing.Size(500, 400)
    }

    $layout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock        = 'Fill'
        ColumnCount = 1
        RowCount    = 3
        Padding     = [System.Windows.Forms.Padding]::new(10)
    }
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $lblHint = New-Label -Text "Enter variables as key=value (one per line)." -Property @{ AutoSize = $true }
    $txtVars = New-TextBox -Multiline $true -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Courier New", 9); ScrollBars = 'Vertical' }

    if ($Variables) {
        $lines = $Variables.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $txtVars.Text = $lines -join [System.Environment]::NewLine
    }

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ FlowDirection = 'RightToLeft'; Dock = 'Fill'; AutoSize = $true }
    $btnSave = New-Button -Text "Save" -Style 'Primary' -Property @{ Width = 100; Height = 32 } -OnClick {
        $newVars = @{}
        foreach ($line in $txtVars.Lines) {
            if ($line -match '^\s*([^=]+?)\s*=(.*)$') {
                $newVars[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        $form.Tag = $newVars
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    }
    $btnCancel = New-Button -Text "Cancel" -Style 'Secondary' -Property @{ Width = 100; Height = 32 } -OnClick {
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    }
    $buttons.Controls.AddRange(@($btnSave, $btnCancel))

    $layout.Controls.Add($lblHint, 0, 0)
    $layout.Controls.Add($txtVars, 0, 1)
    $layout.Controls.Add($buttons, 0, 2)

    $form.Controls.Add($layout)
    $result = $form.ShowDialog($parentForm)
    return [PSCustomObject]@{
        Result    = $result
        Variables = $form.Tag
    }
}

# --- REFACTORED: Environment Editor Window ---
function Show-EnvironmentEditor {
    param(
        [System.Windows.Forms.Form]$parentForm,
        [string]$EnvironmentName,
        [hashtable]$EnvironmentData
    )

    $editorForm = New-Object System.Windows.Forms.Form -Property @{
        Text          = "Edit Environment: $EnvironmentName"
        Size          = New-Object System.Drawing.Size(700, 600)
        StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        MinimumSize   = New-Object System.Drawing.Size(550, 500)
        BackColor     = $script:Theme.FormBackground
    }

    # --- Main Layout: Tab Control ---
    $editorTabControl = New-Object System.Windows.Forms.TabControl -Property @{ Dock = 'Fill' }
    $editorTabControl.Font = New-Object System.Drawing.Font($editorTabControl.Font.FontFamily, 10)

    # --- URL Panel (at the top, outside tabs) ---
    $panelUrl = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Top'; AutoSize = $true; ColumnCount = 2; Padding = [System.Windows.Forms.Padding]::new(5) }
    $panelUrl.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelUrl.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $labelUrl = New-Label -Text "Base URL:" -Property @{ AutoSize = $true; Anchor = 'Left'; Margin = [System.Windows.Forms.Padding]::new(0, 5, 0, 0) }
    $textUrl = New-TextBox -Property @{ Dock = 'Fill'; Text = $EnvironmentData.Url }
    $panelUrl.BackColor = $script:Theme.GroupBackground
    $panelUrl.Controls.Add($labelUrl, 0, 0); $panelUrl.Controls.Add($textUrl, 1, 0)

    # --- Headers Tab ---
    $tabHeaders = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Headers"; Padding = [System.Windows.Forms.Padding]::new(5) }
    $textHeaders = New-TextBox -Multiline $true -Property @{ Dock = 'Fill'; Text = $EnvironmentData.Headers; Font = New-Object System.Drawing.Font("Courier New", 9) }
    $tabHeaders.Controls.Add($textHeaders)

    # --- Variables Tab ---
    $tabVars = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Variables (key=value)"; Padding = [System.Windows.Forms.Padding]::new(5) }
    $textVars = New-TextBox -Multiline $true -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Courier New", 9) }
    $varStrings = $EnvironmentData.Variables.GetEnumerator() | ForEach-Object { "$($_.Name)=$($_.Value)" }
    $textVars.Text = $varStrings -join [System.Environment]::NewLine
    $tabVars.Controls.Add($textVars)

    # --- Authentication Tab ---
    $authResult = New-AuthPanel -AuthData $EnvironmentData.Authentication
    $tabAuth = $authResult.Tab

    $editorTabControl.TabPages.AddRange(@($tabHeaders, $tabAuth, $tabVars))

    # --- Bottom Panel for Save/Cancel ---
    $panelBottom = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Bottom'; Height = 40; Padding = [System.Windows.Forms.Padding]::new(5) }
    $btnSave = New-Button -Text "Save" -Style 'Primary' -Property @{ Dock = 'Right'; Width = 100 } -OnClick {
        # Collect data from controls and update the original hashtable
        $EnvironmentData.Url = $textUrl.Text
        $EnvironmentData.Headers = $textHeaders.Text
        
        # Collect Authentication details by calling the helper on the auth panel
        $EnvironmentData.Authentication = & $authResult.GetAuthData
        
        # Parse variables back into a hashtable
        $newVars = @{}
        $textVars.Lines | ForEach-Object {
            if ($_ -match '^\s*([^=]+?)\s*=(.*)$') {
                $newVars[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        $EnvironmentData.Variables = $newVars

        $editorForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $editorForm.Close()
    }
    $btnCancel = New-Button -Text "Cancel" -Style 'Secondary' -Property @{ Dock = 'Right'; Width = 100 } -OnClick {
        $editorForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $editorForm.Close()
    }
    $panelBottom.Controls.AddRange(@($btnCancel, $btnSave)) # Add in reverse for right-docking

    $editorForm.Controls.AddRange(@($editorTabControl, $panelUrl, $panelBottom))
    return $editorForm.ShowDialog($parentForm)
}

# --- Reusable function to create a complete, self-contained Authentication Panel ---
function New-AuthPanel {
    param (
        [object]$AuthData # Pre-populate with this data
    )

    $tabAuth = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Authentication"; Padding = [System.Windows.Forms.Padding]::new(5) }

    # Main Layout: Changed Column 0 to Fixed 140px to match inner tables
    $authLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; ColumnCount = 2; RowCount = 2 }
    [void]$authLayout.ColumnStyles.Add( (New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)) )
    [void]$authLayout.ColumnStyles.Add( (New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)) )
    [void]$authLayout.RowStyles.Add(    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)) )
    [void]$authLayout.RowStyles.Add(    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)) )

    # Updated Label Properties for better vertical alignment (Top Margin 5)
    $lblProp = @{ AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'; Margin=[System.Windows.Forms.Padding]::new(3,5,5,0) }

    $labelAuthType = New-Label -Text "Type:" -Property $lblProp
    
    # Panel to hold ComboBox and Clear button
    $panelAuthType = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; FlowDirection = 'LeftToRight'; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0); Padding = [System.Windows.Forms.Padding]::new(0) }

    $script:comboAuthType = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; Width = 200 }
    $script:comboAuthType.Items.AddRange(@("No Auth", "API Key", "Bearer Token", "Basic Auth", "Auth2", "Client Certificate"))

    # Clear Button
    $btnClearAuth = New-Button -Text "Clear" -Style 'Secondary' -Property @{ Width = 80; Height = $script:comboAuthType.Height + 4; Margin = [System.Windows.Forms.Padding]::new(5,0,0,0) } -OnClick {
        switch ($script:comboAuthType.SelectedItem) {
            "API Key"      { $script:textApiKeyName.Text = ""; $script:textApiKeyValue.Text = "" }
            "Bearer Token" { $script:textBearerToken.Text = "" }
            "Basic Auth"   { $script:textBasicUser.Text = ""; $script:textBasicPass.Text = "" }
            "Auth2"        {
                $script:textAuth2ClientId.Text = ""
                $script:textAuth2ClientSecret.Text = ""
                $script:textAuth2AuthEndpoint.Text = ""
                $script:textAuth2RedirectUri.Text = ""
                $script:textAuth2TokenEndpoint.Text = ""
                $script:textAuth2Scope.Text = ""
                $script:textAuth2AccessToken.Text = ""
                $script:textAuth2RefreshToken.Text = ""
                $script:textAuth2ExpiresIn.Text = ""
                $script:textAuth2AccessToken.Tag = $null
            }
            "Client Certificate" {
                $script:textCertPath.Text = ""
                $script:textCertPass.Text = ""
                $script:textCertThumb.Text = ""
            }
        }
    }
    $panelAuthType.Controls.AddRange(@($script:comboAuthType, $btnClearAuth))

    $script:panelAuthDetails = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Fill'; AutoScroll = $true; Padding = [System.Windows.Forms.Padding]::new(0, 5, 0, 0) }

    $authLayout.Controls.AddRange(@($labelAuthType, $panelAuthType))
    $authLayout.Controls.Add($script:panelAuthDetails, 0, 1); $authLayout.SetColumnSpan($script:panelAuthDetails, 2)

    # --- Bearer Token Panel ---
    $script:bearerTable = New-AuthDetailTable
    $script:textBearerToken = New-TextBox -Property @{ Dock = 'Fill' }
    
    [void]$script:bearerTable.Controls.Add((New-Label -Text "Token:" -Property $lblProp), 0, 0)
    [void]$script:bearerTable.Controls.Add($script:textBearerToken, 1, 0)

    # --- Basic Auth Panel ---
    $script:basicTable = New-AuthDetailTable
    $script:textBasicUser = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textBasicPass = New-TextBox -Property @{ Dock = 'Fill'; UseSystemPasswordChar = $true }
    
    [void]$script:basicTable.Controls.Add((New-Label -Text "Username:" -Property $lblProp), 0, 0)
    [void]$script:basicTable.Controls.Add($script:textBasicUser, 1, 0)
    [void]$script:basicTable.Controls.Add((New-Label -Text "Password:" -Property $lblProp), 0, 1)
    [void]$script:basicTable.Controls.Add($script:textBasicPass, 1, 1)

    # --- API Key Panel ---
    $script:apiKeyTable = New-AuthDetailTable
    $script:textApiKeyName  = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textApiKeyValue = New-TextBox -Property @{ Dock = 'Fill' }
    $script:comboApiKeyAddTo = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; Dock = 'Fill' }
    $script:comboApiKeyAddTo.Items.AddRange(@("Header", "Query Parameter"))
    
    [void]$script:apiKeyTable.Controls.Add((New-Label -Text "Key Name:" -Property $lblProp), 0, 0)
    [void]$script:apiKeyTable.Controls.Add($script:textApiKeyName, 1, 0)
    [void]$script:apiKeyTable.Controls.Add((New-Label -Text "Key Value:" -Property $lblProp), 0, 1)
    [void]$script:apiKeyTable.Controls.Add($script:textApiKeyValue, 1, 1)
    [void]$script:apiKeyTable.Controls.Add((New-Label -Text "Add to:" -Property $lblProp), 0, 2)
    [void]$script:apiKeyTable.Controls.Add($script:comboApiKeyAddTo, 1, 2)

    # --- Auth2 Panel ---
    $script:auth2Table = New-AuthDetailTable
    $script:textAuth2ClientId = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textAuth2ClientSecret = New-TextBox -Property @{ Dock = 'Fill'; UseSystemPasswordChar = $true }
    $script:textAuth2AuthEndpoint = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textAuth2RedirectUri = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textAuth2TokenEndpoint = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textAuth2Scope = New-TextBox -Property @{ Dock = 'Fill' }
    
    $script:btnGetAuth2Token = New-Button -Text "Get Token" -Property @{ Dock = 'Fill'; Height = 25 } -OnClick {
        $clientId = $script:textAuth2ClientId.Text
        $clientSecret = $script:textAuth2ClientSecret.Text
        $tokenEndpoint = $script:textAuth2TokenEndpoint.Text
        $scope = $script:textAuth2Scope.Text

        if ([string]::IsNullOrWhiteSpace($clientId) -or [string]::IsNullOrWhiteSpace($clientSecret) -or [string]::IsNullOrWhiteSpace($tokenEndpoint)) {
            [System.Windows.Forms.MessageBox]::Show("Client ID, Client Secret, and Token Endpoint are required.", "Missing Info", "OK", "Warning")
            return
        }

        try {
            Write-Log "Attempting to get Auth2 token from $tokenEndpoint" -Level Info
            $body = @{ grant_type="client_credentials"; client_id=$clientId; client_secret=$clientSecret }
            if ($scope) { $body.scope = $scope }

            $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

            $script:textAuth2AccessToken.Text = $tokenResponse.access_token
            $script:textAuth2RefreshToken.Text = $tokenResponse.refresh_token
            $script:textAuth2ExpiresIn.Text = if ($tokenResponse.expires_in) { "$($tokenResponse.expires_in) seconds" } else { "N/A" }
            if ($tokenResponse.expires_in) { $script:textAuth2AccessToken.Tag = ([DateTime]::UtcNow).AddSeconds([int]$tokenResponse.expires_in) }
            [System.Windows.Forms.MessageBox]::Show("Access Token obtained!", "Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to get token: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }

    $script:btnGetAuth2CodeToken = New-Button -Text "Get Token (Browser)" -Property @{ Dock = 'Fill'; Height = 25 } -OnClick {
        $authEndpoint = $script:textAuth2AuthEndpoint.Text
        $clientId = $script:textAuth2ClientId.Text
        $redirectUri = $script:textAuth2RedirectUri.Text
        $scope = $script:textAuth2Scope.Text
        $state = [Guid]::NewGuid().ToString()

        if (-not $authEndpoint -or -not $clientId -or -not $redirectUri) {
             [System.Windows.Forms.MessageBox]::Show("Auth Endpoint, Client ID, and Redirect URI required.", "Missing Info", "OK", "Warning")
             return
        }
        $sep = if ($authEndpoint -match '\?') { '&' } else { '?' }
        $authUrl = "$authEndpoint${sep}response_type=code&client_id=$clientId&redirect_uri=$redirectUri&scope=$scope&state=$state"

        $browserForm = New-Object System.Windows.Forms.Form -Property @{ Width=1000; Height=700; Text="Authenticate"; StartPosition="CenterParent" }
        $wb = New-Object System.Windows.Forms.WebBrowser -Property @{ Dock='Fill'; ScriptErrorsSuppressed=$true }
        $browserForm.Controls.Add($wb)
        
        $wb.Add_Navigated({
            if ($wb.Url.AbsoluteUri.StartsWith($redirectUri)) {
                if ($wb.Url.Query -match 'code=([^&]+)') {
                    $code = $matches[1]
                    $browserForm.Close()
                    try {
                        $tokenEndpoint = $script:textAuth2TokenEndpoint.Text
                        $clientSecret = $script:textAuth2ClientSecret.Text
                        $body = @{ grant_type="authorization_code"; code=$code; redirect_uri=$redirectUri; client_id=$clientId; client_secret=$clientSecret }
                        $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                        
                        $script:textAuth2AccessToken.Text = $tokenResponse.access_token
                        $script:textAuth2RefreshToken.Text = $tokenResponse.refresh_token
                        $script:textAuth2ExpiresIn.Text = if ($tokenResponse.expires_in) { "$($tokenResponse.expires_in) seconds" } else { "N/A" }
                        if ($tokenResponse.expires_in) { $script:textAuth2AccessToken.Tag = ([DateTime]::UtcNow).AddSeconds([int]$tokenResponse.expires_in) }
                        [System.Windows.Forms.MessageBox]::Show("Access Token obtained!", "Success", "OK", "Information")
                    } catch { [System.Windows.Forms.MessageBox]::Show("Failed to exchange code: $($_.Exception.Message)", "Error", "OK", "Error") }
                }
            }
        })
        $wb.Navigate($authUrl)
        $browserForm.ShowDialog()
    }

    $script:textAuth2AccessToken = New-TextBox -Property @{ Dock = 'Fill'; ReadOnly = $true }
    $script:textAuth2RefreshToken = New-TextBox -Property @{ Dock = 'Fill'; ReadOnly = $true }
    $script:textAuth2ExpiresIn = New-TextBox -Property @{ Dock = 'Fill'; ReadOnly = $true }
    
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Client ID:" -Property $lblProp), 0, 0)
    [void]$script:auth2Table.Controls.Add($script:textAuth2ClientId, 1, 0)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Client Secret:" -Property $lblProp), 0, 1)
    [void]$script:auth2Table.Controls.Add($script:textAuth2ClientSecret, 1, 1)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Auth Endpoint:" -Property $lblProp), 0, 2)
    [void]$script:auth2Table.Controls.Add($script:textAuth2AuthEndpoint, 1, 2)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Token Endpoint:" -Property $lblProp), 0, 3)
    [void]$script:auth2Table.Controls.Add($script:textAuth2TokenEndpoint, 1, 3)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Redirect URI:" -Property $lblProp), 0, 4)
    [void]$script:auth2Table.Controls.Add($script:textAuth2RedirectUri, 1, 4)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Scope:" -Property $lblProp), 0, 5)
    [void]$script:auth2Table.Controls.Add($script:textAuth2Scope, 1, 5)
    
    $btnPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; AutoSize=$true }
    $script:btnGetAuth2Token.Width = 100; $script:btnGetAuth2CodeToken.Width = 140
    $btnPanel.Controls.Add($script:btnGetAuth2Token); $btnPanel.Controls.Add($script:btnGetAuth2CodeToken)
    [void]$script:auth2Table.Controls.Add($btnPanel, 1, 6)

    [void]$script:auth2Table.Controls.Add((New-Label -Text "Access Token:" -Property $lblProp), 0, 7)
    [void]$script:auth2Table.Controls.Add($script:textAuth2AccessToken, 1, 7)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Refresh Token:" -Property $lblProp), 0, 8)
    [void]$script:auth2Table.Controls.Add($script:textAuth2RefreshToken, 1, 8)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Expires In:" -Property $lblProp), 0, 9)
    [void]$script:auth2Table.Controls.Add($script:textAuth2ExpiresIn, 1, 9)

    # --- Client Certificate Panel ---
    $script:certTable = New-AuthDetailTable
    $script:comboCertSource = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Dock = 'Fill' }
    $script:comboCertSource.Items.AddRange(@("PFX File", "User Store"))
    $script:comboCertSource.SelectedIndex = 0
    
    $script:panelCertFile = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; AutoSize=$true; FlowDirection='LeftToRight'; Margin=[System.Windows.Forms.Padding]::new(0) }
    $script:textCertPath = New-TextBox -Property @{ Width=200 }
    $script:btnBrowseCert = New-Button -Text "..." -Style 'Secondary' -Property @{ Width=30; Height=23; Margin=[System.Windows.Forms.Padding]::new(3,0,0,0) } -OnClick {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter="PFX Files (*.pfx;*.p12)|*.pfx;*.p12|All Files (*.*)|*.*" }
        if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $script:textCertPath.Text = $ofd.FileName }
    }
    $script:panelCertFile.Controls.AddRange(@($script:textCertPath, $script:btnBrowseCert))
    
    $script:textCertPass = New-TextBox -Property @{ Dock='Fill'; UseSystemPasswordChar=$true }
    
    $script:panelCertStore = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; AutoSize=$true; FlowDirection='LeftToRight'; Margin=[System.Windows.Forms.Padding]::new(0) }
    $script:textCertThumb = New-TextBox -Property @{ Width=200; ReadOnly=$false; PlaceholderText="Thumbprint" }
    $script:btnSelectCert = New-Button -Text "Select" -Style 'Secondary' -Property @{ Width=60; Height=23; Margin=[System.Windows.Forms.Padding]::new(3,0,0,0) } -OnClick {
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
            $store.Open("ReadOnly")
            $certs = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection($store.Certificates, "Select Certificate", "Choose a client certificate for mTLS", "SingleSelection")
            if ($certs.Count -gt 0) { $script:textCertThumb.Text = $certs[0].Thumbprint }
            $store.Close()
        } catch { [System.Windows.Forms.MessageBox]::Show("Error accessing certificate store: $($_.Exception.Message)", "Error", "OK", "Error") }
    }
    $script:panelCertStore.Controls.AddRange(@($script:textCertThumb, $script:btnSelectCert))

    [void]$script:certTable.Controls.Add((New-Label -Text "Source:" -Property $lblProp), 0, 0)
    [void]$script:certTable.Controls.Add($script:comboCertSource, 1, 0)
    
    $script:lblCertPath = New-Label -Text "Path:" -Property $lblProp
    $script:lblCertPass = New-Label -Text "Password:" -Property $lblProp
    $script:lblCertThumb = New-Label -Text "Thumbprint:" -Property $lblProp

    [void]$script:certTable.Controls.Add($script:lblCertPath, 0, 1); [void]$script:certTable.Controls.Add($script:panelCertFile, 1, 1)
    [void]$script:certTable.Controls.Add($script:lblCertPass, 0, 2); [void]$script:certTable.Controls.Add($script:textCertPass, 1, 2)
    [void]$script:certTable.Controls.Add($script:lblCertThumb, 0, 3); [void]$script:certTable.Controls.Add($script:panelCertStore, 1, 3)

    $script:comboCertSource.Add_SelectedIndexChanged({
        $isPfx = ($script:comboCertSource.SelectedItem -eq "PFX File")
        $script:lblCertPath.Visible = $isPfx; $script:panelCertFile.Visible = $isPfx; $script:lblCertPass.Visible = $isPfx; $script:textCertPass.Visible = $isPfx
        $script:lblCertThumb.Visible = (-not $isPfx); $script:panelCertStore.Visible = (-not $isPfx)
    })
    # Trigger initial visibility
    $script:comboCertSource.SelectedIndex = 0; $script:lblCertThumb.Visible = $false; $script:panelCertStore.Visible = $false

    # Populate Data if Exists
    if ($AuthData) {
        $script:comboAuthType.SelectedItem = $AuthData.Type
        switch ($AuthData.Type) {
            "API Key"      { $script:textApiKeyName.Text = $AuthData.Key; $script:textApiKeyValue.Text = $AuthData.Value; $script:comboApiKeyAddTo.SelectedItem = $AuthData.AddTo }
            "Bearer Token" { $script:textBearerToken.Text = $AuthData.Token }
            "Basic Auth"   { $script:textBasicUser.Text = $AuthData.Username; $script:textBasicPass.Text = $AuthData.Password }
            "Auth2"        {
                $script:textAuth2ClientId.Text = $AuthData.ClientId
                $script:textAuth2ClientSecret.Text = $AuthData.ClientSecret
                $script:textAuth2AuthEndpoint.Text = $AuthData.AuthEndpoint
                $script:textAuth2RedirectUri.Text = $AuthData.RedirectUri
                $script:textAuth2TokenEndpoint.Text = $AuthData.TokenEndpoint
                $script:textAuth2Scope.Text = $AuthData.Scope
                $script:textAuth2AccessToken.Text = $AuthData.AccessToken
                $script:textAuth2RefreshToken.Text = $AuthData.RefreshToken
                $script:textAuth2ExpiresIn.Text = $AuthData.ExpiresIn
                $script:textAuth2AccessToken.Tag = $AuthData.TokenExpiryTimestamp
            }
            "Client Certificate" {
                $script:comboCertSource.SelectedItem = $AuthData.Source
                $script:textCertPath.Text = $AuthData.Path
                $script:textCertPass.Text = $AuthData.Password
                $script:textCertThumb.Text = $AuthData.Thumbprint
            }
        }
    } else {
        $script:comboAuthType.SelectedIndex = 0
    }

    # Switch Logic
    $switchPanel = {
        $script:panelAuthDetails.Controls.Clear()
        switch ($script:comboAuthType.SelectedItem) {
            "API Key"      { $script:panelAuthDetails.Controls.Add($script:apiKeyTable) }
            "Bearer Token" { $script:panelAuthDetails.Controls.Add($script:bearerTable) }
            "Basic Auth"   { $script:panelAuthDetails.Controls.Add($script:basicTable) }
            "Auth2"        { $script:panelAuthDetails.Controls.Add($script:auth2Table) }
            "Client Certificate" { $script:panelAuthDetails.Controls.Add($script:certTable) }
        }
    }
    $script:comboAuthType.Add_SelectedIndexChanged($switchPanel)
    $tabAuth.Controls.Add($authLayout)

    & $switchPanel # Initial render

    $getAuthData = {
        $details = @{ Type = $script:comboAuthType.SelectedItem }
        switch ($details.Type) {
            "API Key"      { $details.Key = $script:textApiKeyName.Text; $details.Value = $script:textApiKeyValue.Text; $details.AddTo = $script:comboApiKeyAddTo.SelectedItem }
            "Bearer Token" { $details.Token = $script:textBearerToken.Text }
            "Basic Auth"   { $details.Username = $script:textBasicUser.Text; $details.Password = $script:textBasicPass.Text }
            "Auth2"        {
                $details.ClientId = $script:textAuth2ClientId.Text; $details.ClientSecret = $script:textAuth2ClientSecret.Text
                $details.AuthEndpoint = $script:textAuth2AuthEndpoint.Text; $details.RedirectUri = $script:textAuth2RedirectUri.Text
                $details.TokenEndpoint = $script:textAuth2TokenEndpoint.Text; $details.Scope = $script:textAuth2Scope.Text
                $details.AccessToken = $script:textAuth2AccessToken.Text; $details.RefreshToken = $script:textAuth2RefreshToken.Text; $details.ExpiresIn = $script:textAuth2ExpiresIn.Text; $details.TokenExpiryTimestamp = $script:textAuth2AccessToken.Tag
            }
            "Client Certificate" {
                $details.Source = $script:comboCertSource.SelectedItem; $details.Path = $script:textCertPath.Text; $details.Password = $script:textCertPass.Text; $details.Thumbprint = $script:textCertThumb.Text
            }
        }
        return $details
    }

    [PSCustomObject]@{
        Tab              = $tabAuth
        GetAuthData      = $getAuthData
        SwitchPanel      = $switchPanel
        ComboAuthType    = $script:comboAuthType
        TextApiKeyName   = $script:textApiKeyName
        TextApiKeyValue  = $script:textApiKeyValue
        ComboApiKeyAddTo = $script:comboApiKeyAddTo
        TextBearerToken  = $script:textBearerToken
        TextBasicUser    = $script:textBasicUser
        TextBasicPass    = $script:textBasicPass
        TextAuth2TokenEndpoint = $script:textAuth2TokenEndpoint
        TextAuth2AuthEndpoint = $script:textAuth2AuthEndpoint
        TextAuth2RedirectUri = $script:textAuth2RedirectUri
        TextAuth2Scope = $script:textAuth2Scope
        TextAuth2AccessToken = $script:textAuth2AccessToken
        TextAuth2RefreshToken = $script:textAuth2RefreshToken
        TextAuth2ExpiresIn = $script:textAuth2ExpiresIn
        TextAuth2ClientId = $script:textAuth2ClientId
        TextAuth2ClientSecret = $script:textAuth2ClientSecret
        TextCertPath = $script:textCertPath
        TextCertPass = $script:textCertPass
        TextCertThumb = $script:textCertThumb
        ComboCertSource = $script:comboCertSource
    }
}
# --- Monitor Email Settings Window ---
function Show-MonitorEmailSettings {
    param($parentForm)
    $form = New-Object System.Windows.Forms.Form -Property @{ Text="Email Alert Configuration"; Size=New-Object System.Drawing.Size(700, 750); StartPosition="CenterParent" }
    $layout = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; FlowDirection='TopDown'; Padding=[System.Windows.Forms.Padding]::new(15); WrapContents=$false; AutoScroll=$true }
    
    $layout.Controls.Add((New-Label -Text "SMTP Server:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,5,0,0) }))
    $txtServer = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpServer; Width=500; Height=25 }
    $layout.Controls.Add($txtServer)

    $layout.Controls.Add((New-Label -Text "SMTP Port:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtPort = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpPort; Width=150; Height=25 }
    $layout.Controls.Add($txtPort)

    $layout.Controls.Add((New-Label -Text "Auth Method:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $comboAuth = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle='DropDownList'; Width=200; Height=25 }
    $comboAuth.Items.AddRange(@("Basic", "OAuth2"))
    $comboAuth.SelectedItem = if ($script:settings.MonitorSmtpAuthMethod) { $script:settings.MonitorSmtpAuthMethod } else { "Basic" }
    $layout.Controls.Add($comboAuth)

    $chkSsl = New-Object System.Windows.Forms.CheckBox -Property @{ Text="Use SSL"; Checked=$script:settings.MonitorSmtpUseSsl; AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }
    $layout.Controls.Add($chkSsl)

    $layout.Controls.Add((New-Label -Text "From Address:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtFrom = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpFrom; Width=500; Height=25 }
    $layout.Controls.Add($txtFrom)

    $layout.Controls.Add((New-Label -Text "Username (Optional):" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtUser = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpUser; Width=500; Height=25 }
    $layout.Controls.Add($txtUser)

    $lblPass = New-Label -Text "Password:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }
    $layout.Controls.Add($lblPass)
    $txtPass = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpPass; Width=500; Height=25; UseSystemPasswordChar=$true }
    $layout.Controls.Add($txtPass)

    # OAuth2 Specific Fields
    $panelOAuth = New-Object System.Windows.Forms.Panel -Property @{ AutoSize=$true; Visible=$false }
    $layoutOAuth = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; FlowDirection='TopDown'; AutoSize=$true; WrapContents=$false; Padding=[System.Windows.Forms.Padding]::new(0,10,0,0) }
    
    $layoutOAuth.Controls.Add((New-Label -Text "Client ID:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,5,0,0) }))
    $txtClientId = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpClientId; Width=500; Height=25 }
    $layoutOAuth.Controls.Add($txtClientId)

    $layoutOAuth.Controls.Add((New-Label -Text "Client Secret:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtClientSecret = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpClientSecret; Width=500; Height=25; UseSystemPasswordChar=$true }
    $layoutOAuth.Controls.Add($txtClientSecret)

    $layoutOAuth.Controls.Add((New-Label -Text "Token Endpoint:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtTokenEndpoint = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpTokenEndpoint; Width=500; Height=25 }
    $layoutOAuth.Controls.Add($txtTokenEndpoint)

    $layoutOAuth.Controls.Add((New-Label -Text "Refresh Token:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtRefreshToken = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpRefreshToken; Width=500; Height=25; UseSystemPasswordChar=$true }
    $layoutOAuth.Controls.Add($txtRefreshToken)
    
    $btnRefresh = New-Button -Text "Refresh Token Now" -Property @{ Width=180; Height=30; Margin=[System.Windows.Forms.Padding]::new(0,10,0,5) } -OnClick {
        $script:settings.MonitorSmtpClientId = $txtClientId.Text
        $script:settings.MonitorSmtpClientSecret = $txtClientSecret.Text
        $script:settings.MonitorSmtpRefreshToken = $txtRefreshToken.Text
        $script:settings.MonitorSmtpTokenEndpoint = $txtTokenEndpoint.Text
        
        try {
            Refresh-SmtpToken
            $txtPass.Text = $script:settings.MonitorSmtpPass
            [System.Windows.Forms.MessageBox]::Show("Token refreshed successfully!", "Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to refresh token:`n$($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
    $layoutOAuth.Controls.Add($btnRefresh)

    $panelOAuth.Controls.Add($layoutOAuth)
    $layout.Controls.Add($panelOAuth)

    $comboAuth.Add_SelectedIndexChanged({
        if ($comboAuth.SelectedItem -eq "OAuth2") { $lblPass.Text = "Access Token:"; $panelOAuth.Visible = $true } else { $lblPass.Text = "Password:"; $panelOAuth.Visible = $false }
    })
    if ($comboAuth.SelectedItem -eq "OAuth2") { $lblPass.Text = "Access Token:"; $panelOAuth.Visible = $true }

    # Alert Email Template
    $grpTemplate = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Alert Email Template"; AutoSize=$true; Width=600; Margin=[System.Windows.Forms.Padding]::new(0,15,0,0) }
    $tmplLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=2; AutoSize=$true; Padding=[System.Windows.Forms.Padding]::new(5) }
    $tmplLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $tmplLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $lblAlertSubject = New-Label -Text "Subject:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,8,0) }
    $txtAlertSubject = New-TextBox -Property @{ Text=$script:settings.MonitorAlertSubjectTemplate; Dock='Fill'; Height=25 }

    $lblAlertBody = New-Label -Text "Body:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,8,0) }
    $txtAlertBody = New-TextBox -Multiline $true -Property @{ Text=$script:settings.MonitorAlertBodyTemplate; Dock='Fill'; Height=120; ScrollBars='Vertical' }

    $checkForceHtml = New-Object System.Windows.Forms.CheckBox -Property @{
        Text = "Force HTML email body"
        Checked = $script:settings.MonitorAlertBodyForceHtml
        AutoSize = $true
        Margin = [System.Windows.Forms.Padding]::new(0,6,0,0)
    }
    $lblAlertHint = New-Label -Text "Placeholders: {MonitorName} {Status} {StatusCode} {Url} {TimeMs} {Message} {Timestamp}" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,8,0,0) }

    $tmplLayout.Controls.Add($lblAlertSubject, 0, 0); $tmplLayout.Controls.Add($txtAlertSubject, 1, 0)
    $tmplLayout.Controls.Add($lblAlertBody, 0, 1); $tmplLayout.Controls.Add($txtAlertBody, 1, 1)
    $tmplLayout.Controls.Add($checkForceHtml, 0, 2); $tmplLayout.SetColumnSpan($checkForceHtml, 2)
    $tmplLayout.Controls.Add($lblAlertHint, 0, 3); $tmplLayout.SetColumnSpan($lblAlertHint, 2)

    $grpTemplate.Controls.Add($tmplLayout)
    $layout.Controls.Add($grpTemplate)

    $grpActions = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Actions"; AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,15,0,0); Width=600 }
    $btnPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ AutoSize=$true; FlowDirection='LeftToRight'; Padding=[System.Windows.Forms.Padding]::new(5); WrapContents=$false }

    $btnSave = New-Button -Text "Save Settings" -Property @{ Width=140; Height=35; Margin=[System.Windows.Forms.Padding]::new(0,0,10,0) } -OnClick {
        # ... (keep existing save logic) ...
        $script:settings.MonitorSmtpServer = $txtServer.Text
        $script:settings.MonitorSmtpPort = [int]$txtPort.Text
        $script:settings.MonitorSmtpUseSsl = $chkSsl.Checked
        $script:settings.MonitorSmtpFrom = $txtFrom.Text
        $script:settings.MonitorSmtpUser = $txtUser.Text
        $script:settings.MonitorSmtpPass = $txtPass.Text
        $script:settings.MonitorSmtpAuthMethod = $comboAuth.SelectedItem
        $script:settings.MonitorSmtpClientId = $txtClientId.Text
        $script:settings.MonitorSmtpClientSecret = $txtClientSecret.Text
        $script:settings.MonitorSmtpTokenEndpoint = $txtTokenEndpoint.Text
        $script:settings.MonitorSmtpRefreshToken = $txtRefreshToken.Text
        $script:settings.MonitorAlertSubjectTemplate = $txtAlertSubject.Text
        $script:settings.MonitorAlertBodyTemplate = $txtAlertBody.Text
        $script:settings.MonitorAlertBodyForceHtml = $checkForceHtml.Checked
        Save-Settings
        $form.Close()
    }

    # FIX: Increased width to 160 to show full text
    $btnTest = New-Button -Text "Test Connection" -Property @{ Width=160; Height=35; Margin=[System.Windows.Forms.Padding]::new(10,0,0,0) } -OnClick {
        # ... (keep existing test logic) ...
         $server = $txtServer.Text
        $port = [int]$txtPort.Text
        $ssl = $chkSsl.Checked
        $from = $txtFrom.Text
        $user = $txtUser.Text
        $pass = $txtPass.Text
        $authMethod = $comboAuth.SelectedItem

        if (-not $server -or -not $from) {
            [System.Windows.Forms.MessageBox]::Show("Please enter SMTP Server and From Address.", "Missing Info", "OK", "Warning")
            return
        }

        $to = [Microsoft.VisualBasic.Interaction]::InputBox("Enter recipient email address for test:", "Test Email", $from)
        if (-not $to) { return }

        try {
            if ($authMethod -eq "OAuth2") {
                Send-SmtpOAuth2 -Server $server -Port $port -UseSsl $ssl -From $from -To $to -Subject "API Tester SMTP Test" -Body "This is a test email (OAuth2)." -User $user -AccessToken $pass -IsHtml:$false
            } else {
                $smtpParams = @{ SmtpServer=$server; Port=$port; UseSsl=$ssl; From=$from; To=$to; Subject="API Tester SMTP Test"; Body="This is a test email (Basic)."; IsBodyHtml = $false }
                if ($user) {
                    $securePass = $pass | ConvertTo-SecureString -AsPlainText -Force
                    $smtpParams.Credential = New-Object System.Management.Automation.PSCredential($user, $securePass)
                }
                Send-MailMessage @smtpParams -ErrorAction Stop
            }
            [System.Windows.Forms.MessageBox]::Show("Test email sent successfully to $to!", "Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to send test email:`n$($_.Exception.Message)", "Test Failed", "OK", "Error")
        }
    }

    $btnPanel.Controls.AddRange(@($btnSave, $btnTest))
    $grpActions.Controls.Add($btnPanel)
    $layout.Controls.Add($grpActions)
    $form.Controls.Add($layout)
    $form.ShowDialog($parentForm)
}

# --- Monitor Chart Window ---
function Show-MonitorChartWindow {
    param($parentForm)
    
    if (-not (Test-Path $monitorLogFilePath)) {
        [System.Windows.Forms.MessageBox]::Show("No monitor log file found.", "Info", "OK", "Information")
        return
    }

    try {
        $chartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Charting assemblies not found. Please ensure .NET Framework 4.x is installed.", "Error", "OK", "Error")
        return
    }

    $form = New-Object System.Windows.Forms.Form -Property @{ Text="Monitor Analytics"; Size=New-Object System.Drawing.Size(1000, 700); StartPosition="CenterParent" }
    
    # Load Data
    $data = Import-Csv $monitorLogFilePath | Select-Object @{N='Time';E={[DateTime]$_.Timestamp}}, MonitorName, @{N='Ms';E={[int]$_.TimeMs}}
    $monitors = $data | Select-Object -ExpandProperty MonitorName -Unique

    # Controls
    $panelTop = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Top'; AutoSize=$true; Padding=[System.Windows.Forms.Padding]::new(5) }
    $lblSel = New-Label -Text "Select Monitor:" -Property @{ AutoSize=$true; TextAlign='MiddleLeft'; Margin=[System.Windows.Forms.Padding]::new(0,6,0,0) }
    $comboMon = New-Object System.Windows.Forms.ComboBox -Property @{ Width=200; DropDownStyle='DropDownList'; Margin=[System.Windows.Forms.Padding]::new(3,3,10,3) }
    $comboMon.Items.AddRange($monitors)
    
    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart -Property @{ Dock='Fill' }
    $chartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
    $chart.ChartAreas.Add($chartArea)
    $series = New-Object System.Windows.Forms.DataVisualization.Charting.Series
    $series.ChartType = $chartType
    $series.BorderWidth = 2
    $chart.Series.Add($series)
    $title = New-Object System.Windows.Forms.DataVisualization.Charting.Title
    $title.Text = "Response Time (ms)"
    $chart.Titles.Add($title)

    $comboMon.Add_SelectedIndexChanged({
        $selected = $comboMon.SelectedItem
        $subset = $data | Where-Object { $_.MonitorName -eq $selected }
        $series.Points.Clear()
        foreach ($row in $subset) {
            $series.Points.AddXY($row.Time.ToString("HH:mm:ss"), $row.Ms) | Out-Null
        }
        $title.Text = "$selected - Response Time (ms)"
    })

    if ($comboMon.Items.Count -gt 0) { $comboMon.SelectedIndex = 0 }

    $btnSaveImage = New-Button -Text "Save Image" -Property @{ AutoSize=$true } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = "PNG Image|*.png|JPEG Image|*.jpg|Bitmap Image|*.bmp"
        $sfd.Title = "Save Chart Image"
        $sfd.FileName = "MonitorChart.png"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Png
                if ($sfd.FileName.EndsWith(".jpg")) { $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Jpeg }
                elseif ($sfd.FileName.EndsWith(".bmp")) { $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Bmp }
                
                $chart.SaveImage($sfd.FileName, $format)
                [System.Windows.Forms.MessageBox]::Show("Chart saved successfully.", "Success", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to save chart: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    }

    $panelTop.Controls.AddRange(@($lblSel, $comboMon, $btnSaveImage))
    $form.Controls.AddRange(@($chart, $panelTop))
    $form.ShowDialog($parentForm)
}

# --- WebSocket Client Window ---
function Show-WebSocketClient {
    param($parentForm)
    $wsForm = New-Object System.Windows.Forms.Form -Property @{ Text="WebSocket Client"; Size=New-Object System.Drawing.Size(750, 600); StartPosition="CenterParent"; BackColor = $script:Theme.FormBackground }
    
    $topPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Top'; AutoSize=$true; Padding=[System.Windows.Forms.Padding]::new(8); WrapContents=$false }
    $lblUrl = New-Label -Text "URL:" -Property @{ AutoSize=$true; TextAlign='MiddleLeft'; Margin=[System.Windows.Forms.Padding]::new(0,6,0,0) }
    $txtUrl = New-TextBox -Property @{ Width=320; Text="wss://echo.websocket.org" }
    $btnConnect = New-Button -Text "Connect" -Style 'Primary' -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(6,3,3,3) }
    $btnDisconnect = New-Button -Text "Disconnect" -Property @{ AutoSize=$true; Enabled=$false; Margin=[System.Windows.Forms.Padding]::new(3) }
    
    $btnSaveLog = New-Button -Text "Save Log" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(12,3,3,3) } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog -Property @{ Filter="Text Files (*.txt)|*.txt"; FileName="websocket_log.txt" }
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $logBox.Text | Set-Content -Path $sfd.FileName }
    }
    $btnLoadLog = New-Button -Text "Load Log" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(3) } -OnClick {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter="Text Files (*.txt)|*.txt" }
        if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $logBox.Text = Get-Content -Path $ofd.FileName -Raw }
    }
    $btnClearLog = New-Button -Text "Clear Log" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(3) } -OnClick {
        if ([System.Windows.Forms.MessageBox]::Show("Clear WebSocket log?", "Confirm", "YesNo") -eq "Yes") {
            $logBox.Clear()
        }
    }

    $lblStatus = New-Label -Text "Status: Disconnected" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(10,6,0,0); ForeColor = [System.Drawing.Color]::DarkRed }
    $topPanel.Controls.AddRange(@($lblUrl, $txtUrl, $btnConnect, $btnDisconnect, $btnSaveLog, $btnLoadLog, $btnClearLog, $lblStatus))

    $logBox = New-RichTextBox -ReadOnly $true -Property @{ Dock='Fill'; BackColor='White'; Font=New-Object System.Drawing.Font("Consolas", 9); BorderStyle='None' }
    
    $bottomPanel = New-Object System.Windows.Forms.Panel -Property @{ Dock='Bottom'; Height=40; Padding=[System.Windows.Forms.Padding]::new(5) }
    $txtMsg = New-TextBox -Property @{ Dock='Fill' }
    $btnSend = New-Button -Text "Send" -Style 'Primary' -Property @{ Dock='Right'; Width=90; Enabled=$false }
    $bottomPanel.Controls.AddRange(@($btnSend, $txtMsg))

    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    $buffer = New-Object byte[] 4096
    $timer = New-Object System.Windows.Forms.Timer -Property @{ Interval=100 }
    $script:wsTask = $null

    $btnConnect.Add_Click({
        try {
            if ($ws.State -ne 'None' -and $ws.State -ne 'Closed') { $ws = New-Object System.Net.WebSockets.ClientWebSocket }
            $uri = New-Object System.Uri($txtUrl.Text)
            $task = $ws.ConnectAsync($uri, [System.Threading.CancellationToken]::None)
            $task.Wait()
            if ($ws.State -eq 'Open') {
                $logBox.AppendText("[$([DateTime]::Now.ToString('HH:mm:ss'))] Connected to $($uri)`n")
                $btnConnect.Enabled = $false; $btnDisconnect.Enabled = $true; $btnSend.Enabled = $true
                $lblStatus.Text = "Status: Connected"
                $lblStatus.ForeColor = [System.Drawing.Color]::DarkGreen
                $timer.Start()
            }
        } catch { $logBox.AppendText("Error connecting: $($_.Exception.Message)`n") }
    })

    $btnDisconnect.Add_Click({
        if ($ws.State -eq 'Open') {
            $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "User Disconnect", [System.Threading.CancellationToken]::None) | Out-Null
            $logBox.AppendText("[$([DateTime]::Now.ToString('HH:mm:ss'))] Disconnected`n")
            $btnConnect.Enabled = $true; $btnDisconnect.Enabled = $false; $btnSend.Enabled = $false
            $lblStatus.Text = "Status: Disconnected"
            $lblStatus.ForeColor = [System.Drawing.Color]::DarkRed
            $timer.Stop()
        }
    })

    $btnSend.Add_Click({
        if ($ws.State -eq 'Open' -and $txtMsg.Text) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($txtMsg.Text)
            $segment = New-Object System.ArraySegment[byte] -ArgumentList $bytes
            $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [System.Threading.CancellationToken]::None) | Out-Null
            $logBox.SelectionColor = 'Blue'
            $logBox.AppendText("[$([DateTime]::Now.ToString('HH:mm:ss'))] Sent: $($txtMsg.Text)`n")
            $txtMsg.Text = ""
        }
    })

    $timer.Add_Tick({
        if ($ws.State -eq 'Open') {
            if ($script:wsTask -eq $null) {
                $seg = New-Object System.ArraySegment[byte] -ArgumentList $buffer
                $script:wsTask = $ws.ReceiveAsync($seg, [System.Threading.CancellationToken]::None)
            } elseif ($script:wsTask.IsCompleted) {
                try {
                    $res = $script:wsTask.Result
                    if ($res.MessageType -eq 'Close') { 
                        $btnDisconnect.PerformClick() 
                    } else {
                        $msg = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $res.Count)
                        $logBox.SelectionColor = 'Green'
                        $logBox.AppendText("[$([DateTime]::Now.ToString('HH:mm:ss'))] Received: $msg`n")
                    }
                } catch { $logBox.AppendText("Error receiving: $($_.Exception.Message)`n") }
                $script:wsTask = $null
            }
        }
    })

    $wsForm.Controls.AddRange(@($logBox, $bottomPanel, $topPanel))
    $wsForm.ShowDialog($parentForm)
    if ($ws) { $ws.Dispose() }
}

# --- gRPC Client Window (Wrapper for grpcurl) ---
function Show-GrpcClient {
    param($parentForm)
    Load-GrpcHistory

    $grpcForm = New-Object System.Windows.Forms.Form -Property @{ Text="gRPC Client (via grpcurl)"; Size=New-Object System.Drawing.Size(1100, 750); StartPosition="CenterParent"; BackColor=$script:Theme.FormBackground }
    
    $mainSplit = New-Object System.Windows.Forms.SplitContainer -Property @{ Dock='Fill'; Orientation='Vertical'; SplitterDistance=280; BackColor=$script:Theme.FormBackground }

    # --- History Panel (Left) ---
    $historyGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text="History"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor=$script:Theme.GroupBackground }
    $historyLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=1; RowCount=2 }
    $historyLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $historyLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $listHistory = New-Object System.Windows.Forms.ListBox -Property @{ Dock='Fill' }
    $btnClearHistory = New-Button -Text "Clear History" -Style 'Secondary' -Property @{ Dock='Fill'; Height=32; Margin=[System.Windows.Forms.Padding]::new(0,8,0,0) } -OnClick {
        if ([System.Windows.Forms.MessageBox]::Show("Clear gRPC history?", "Confirm", "YesNo") -eq "Yes") {
            $script:grpcHistory = @()
            $listHistory.Items.Clear()
            Save-GrpcHistory
        }
    }
    $historyLayout.Controls.Add($listHistory, 0, 0)
    $historyLayout.Controls.Add($btnClearHistory, 0, 1)
    $historyGroup.Controls.Add($historyLayout)
    $mainSplit.Panel1.Controls.Add($historyGroup)

    # Populate History List
    foreach ($item in $script:grpcHistory) {
        $ts = Get-Date
        if ($item.Timestamp) {
            $tsStr = if ($item.Timestamp -is [PSCustomObject]) { $item.Timestamp.DateTime } else { $item.Timestamp }
            if (-not [DateTime]::TryParse($tsStr, [ref]$ts)) {
                 [void][DateTime]::TryParse($tsStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$ts)
            }
        }
        $listHistory.Items.Add("$($ts.ToString('HH:mm:ss')) | $($item.Method)")
    }

    # --- Client Panel (Right) ---
    $split = New-Object System.Windows.Forms.SplitContainer -Property @{ Dock='Fill'; Orientation='Horizontal'; SplitterDistance=330; BackColor=$script:Theme.FormBackground }
    
    # Input Panel
    $inputPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=2; RowCount=6; Padding=[System.Windows.Forms.Padding]::new(8) }
    $inputPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $inputPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 30)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 70)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    
    $txtHost = New-TextBox -Property @{ Dock='Fill'; Text='localhost:50051' }
    $txtMethod = New-TextBox -Property @{ Dock='Fill'; Text='MyService/SayHello' }
    $txtHeaders = New-TextBox -Multiline $true -Property @{ Dock='Fill'; Text=''; Font=New-Object System.Drawing.Font("Courier New", 9); ScrollBars='Vertical' }
    $txtBody = New-TextBox -Multiline $true -Property @{ Dock='Fill'; Height=150; Text='{ "name": "World" }'; Font=New-Object System.Drawing.Font("Courier New", 9); ScrollBars='Vertical' }
    $chkPlaintext = New-Object System.Windows.Forms.CheckBox -Property @{ Text="Plaintext (-plaintext)"; AutoSize=$true; Checked=$true; Margin=[System.Windows.Forms.Padding]::new(0,8,0,0) }
    
    $inputPanel.Controls.Add((New-Label -Text "Host:" -Property @{AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'}), 0, 0); $inputPanel.Controls.Add($txtHost, 1, 0)
    $inputPanel.Controls.Add((New-Label -Text "Method:" -Property @{AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'}), 0, 1); $inputPanel.Controls.Add($txtMethod, 1, 1)
    $inputPanel.Controls.Add((New-Label -Text "Headers:" -Property @{AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'}), 0, 2); $inputPanel.Controls.Add($txtHeaders, 1, 2)
    $inputPanel.Controls.Add((New-Label -Text "JSON Body:" -Property @{AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'}), 0, 3); $inputPanel.Controls.Add($txtBody, 1, 3)
    $inputPanel.Controls.Add($chkPlaintext, 0, 4); $inputPanel.SetColumnSpan($chkPlaintext, 2)
    
    $btnExecute = New-Button -Text "Execute gRPC" -Style 'Primary' -Property @{ Height=38; Dock='Fill'; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) } -OnClick {
        $txtOutput.Text = "Executing..."
        $hostAddr = $txtHost.Text
        $method = $txtMethod.Text
        $json = $txtBody.Text.Replace('"', '\"') # Simple escape for cmd line
        
        # Save to History
        $historyItem = [PSCustomObject]@{
            Timestamp = Get-Date
            Host = $hostAddr
            Method = $method
            Headers = $txtHeaders.Text
            Body = $txtBody.Text
            Plaintext = $chkPlaintext.Checked
        }
        $script:grpcHistory = @($historyItem) + $script:grpcHistory
        if ($script:grpcHistory.Count -gt 50) { $script:grpcHistory = $script:grpcHistory[0..49] }
        Save-GrpcHistory
        
        $listHistory.Items.Insert(0, "$($historyItem.Timestamp.ToString('HH:mm:ss')) | $($historyItem.Method)")
        if ($listHistory.Items.Count -gt 50) { $listHistory.Items.RemoveAt(50) }

        $argsList = @()
        if ($chkPlaintext.Checked) { $argsList += "-plaintext" }
        
        # Add Headers
        if (-not [string]::IsNullOrWhiteSpace($txtHeaders.Text)) {
            foreach ($line in $txtHeaders.Text -split "`n") {
                if ($line -match "^\s*(.+?):\s*(.+)$") {
                    $argsList += "-H", "`"$($matches[1]): $($matches[2])`""
                }
            }
        }

        $argsList += "-d", "`"$json`"", $hostAddr, $method
        
        # Resolve grpcurl path (check script dir first, then PATH)
        $grpCurlPath = "grpcurl"
        $localPath = Join-Path $scriptRoot "grpcurl.exe"
        if (Test-Path $localPath) {
            $grpCurlPath = $localPath
        } elseif (-not (Get-Command "grpcurl" -ErrorAction SilentlyContinue -CommandType Application)) {
            $txtOutput.Text = "Error: 'grpcurl' executable not found.`r`nPlease download it and place 'grpcurl.exe' in:`r`n$scriptRoot`r`nOr add it to your system PATH."
            return
        }

        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $grpCurlPath
            $psi.Arguments = $argsList -join " "
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.WaitForExit()
            $out = $p.StandardOutput.ReadToEnd()
            $err = $p.StandardError.ReadToEnd()
            $txtOutput.Text = if ($err) { "STDERR:`r`n$err`r`nSTDOUT:`r`n$out" } else { $out }
        } catch {
            $txtOutput.Text = "Error executing grpcurl. Ensure 'grpcurl' is installed and in your PATH.`r`nError: $($_.Exception.Message)"
        }
    }
    $inputPanel.Controls.Add($btnExecute, 0, 5)
    $inputPanel.SetColumnSpan($btnExecute, 2)
    
    $outputTools = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Top'; AutoSize=$true; Padding=[System.Windows.Forms.Padding]::new(0); Margin=[System.Windows.Forms.Padding]::new(0); FlowDirection='LeftToRight'; WrapContents=$false }
    $btnBeautify = New-Button -Text "Beautify JSON" -Style 'Secondary' -Property @{ Width=140; Height=32; Margin=[System.Windows.Forms.Padding]::new(0,0,8,0) } -OnClick {
        if ([string]::IsNullOrWhiteSpace($txtOutput.Text)) { return }
        try {
            $json = $txtOutput.Text | ConvertFrom-Json
            $txtOutput.Text = $json | ConvertTo-Json -Depth 10
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Invalid JSON: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
    $btnDownload = New-Button -Text "Download grpcurl" -Style 'Secondary' -Property @{ Width=160; Height=32; Margin=[System.Windows.Forms.Padding]::new(0,0,8,0) } -OnClick {
        try {
            $txtOutput.Text = "Checking for latest grpcurl release..."
            [System.Windows.Forms.Application]::DoEvents()
            
            $latest = Invoke-RestMethod "https://api.github.com/repos/fullstorydev/grpcurl/releases/latest"
            $asset = $latest.assets | Where-Object { $_.name -match "windows_x86_64.zip" } | Select-Object -First 1
            
            if (-not $asset) { throw "Could not find Windows x64 asset in latest release." }
            
            $zipPath = Join-Path $env:TEMP $asset.name
            $txtOutput.Text += "`r`nDownloading $($asset.browser_download_url)..."
            [System.Windows.Forms.Application]::DoEvents()
            
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
            
            $txtOutput.Text += "`r`nExtracting..."
            [System.Windows.Forms.Application]::DoEvents()
            
            Expand-Archive -Path $zipPath -DestinationPath $scriptRoot -Force
            
            $txtOutput.Text += "`r`nDone! 'grpcurl.exe' installed to $scriptRoot."
            Remove-Item $zipPath -ErrorAction SilentlyContinue
        } catch {
            $txtOutput.Text += "`r`nError: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show("Failed to download grpcurl: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
    $outputTools.Controls.Add($btnBeautify)
    $outputTools.Controls.Add($btnDownload)

    $txtOutput = New-RichTextBox -ReadOnly $true -Property @{ Dock='Fill'; Font=New-Object System.Drawing.Font("Courier New", 9); BackColor='White'; BorderStyle='FixedSingle' }
    
    $inputGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Request"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor=$script:Theme.GroupBackground }
    $inputGroup.Controls.Add($inputPanel)

    $outputGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Response"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor=$script:Theme.GroupBackground }
    $outputLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=1; RowCount=2 }
    $outputLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $outputLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $outputLayout.Controls.Add($outputTools, 0, 0)
    $outputLayout.Controls.Add($txtOutput, 0, 1)
    $outputGroup.Controls.Add($outputLayout)
    
    $split.Panel1.Controls.Add($inputGroup)
    $split.Panel2.Controls.Add($outputGroup)
    
    $mainSplit.Panel2.Controls.Add($split)

    # History Selection Event
    $listHistory.Add_SelectedIndexChanged({
        if ($listHistory.SelectedIndex -ne -1) {
            $item = $script:grpcHistory[$listHistory.SelectedIndex]
            $txtHost.Text = $item.Host
            $txtMethod.Text = $item.Method
            $txtHeaders.Text = $item.Headers
            $txtBody.Text = $item.Body
            $chkPlaintext.Checked = $item.Plaintext
        }
    })

    $grpcForm.Controls.Add($mainSplit)
    $grpcForm.ShowDialog($parentForm)
}

# --- Monitoring Dashboard Window ---
function Show-MonitoringDashboard {
    param($parentForm)

    # Check for charting assemblies
    try {
        $chartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Charting assemblies not found. Please ensure .NET Framework 4.x is installed.", "Error", "OK", "Error")
        return
    }

    $dashboardForm = New-Object System.Windows.Forms.Form -Property @{
        Text = "Monitoring Dashboard"
        Size = New-Object System.Drawing.Size(1000, 700)
        StartPosition = "CenterParent"
        BackColor = $script:Theme.FormBackground
    }

    # --- Main Layout ---
    $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        RowCount = 3
        Padding = [System.Windows.Forms.Padding]::new(10)
    }
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    
    # --- Toolbar ---
    $toolbar = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; AutoSize = $true; WrapContents = $true }
    $lblMonitorFilter = New-Label -Text "Monitor:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,5,0) }
    $comboMonitorFilter = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle='DropDownList'; Width=200; Margin=[System.Windows.Forms.Padding]::new(0,3,10,0) }
    $lblFrom = New-Label -Text "From:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(10,6,5,0) }
    $dtpFrom = New-Object System.Windows.Forms.DateTimePicker -Property @{ Format='Short'; Width=100; ShowCheckBox=$true; Checked=$false; Margin=[System.Windows.Forms.Padding]::new(0,3,10,0) }
    $lblTo = New-Label -Text "To:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,5,0) }
    $dtpTo = New-Object System.Windows.Forms.DateTimePicker -Property @{ Format='Short'; Width=100; ShowCheckBox=$true; Checked=$false; Margin=[System.Windows.Forms.Padding]::new(0,3,10,0) }
    $btnRefresh = New-Button -Text "Refresh" -Style 'Primary' -Property @{ Width=100; Height=32; Margin=[System.Windows.Forms.Padding]::new(10,0,0,0) }
    $btnExportData = New-Button -Text "Export Data" -Style 'Secondary' -Property @{ Width=120; Height=32; Margin=[System.Windows.Forms.Padding]::new(10,0,0,0) }
    $btnSaveChart = New-Button -Text "Save Chart" -Style 'Secondary' -Property @{ Width=120; Height=32; Margin=[System.Windows.Forms.Padding]::new(5,0,0,0) }
    $toolbar.Controls.AddRange(@($lblMonitorFilter, $comboMonitorFilter, $lblFrom, $dtpFrom, $lblTo, $dtpTo, $btnRefresh, $btnExportData, $btnSaveChart))

    # --- Dashboard Cards ---
    $dashboardCardsLayout = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; AutoScroll = $true; AutoSize=$true }

    function New-DashboardCard {
        param([string]$Title, [string]$InitialValue = "...")
        $card = New-Object System.Windows.Forms.Panel -Property @{ Size = New-Object System.Drawing.Size(180, 100); BackColor = $script:Theme.GroupBackground; Margin = [System.Windows.Forms.Padding]::new(10) }
        $lblTitle = New-Label -Text $Title -Property @{ Dock = 'Top'; Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold); ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#6c757d"); TextAlign = 'MiddleCenter'; Height = 30 }
        $lblValue = New-Label -Text $InitialValue -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Segoe UI", 22, [System.Drawing.FontStyle]::Bold); TextAlign = 'MiddleCenter' }
        $card.Controls.AddRange(@($lblValue, $lblTitle))
        return [PSCustomObject]@{ Panel = $card; ValueLabel = $lblValue }
    }

    $uptimeCard = New-DashboardCard -Title "Uptime"
    $latencyCard = New-DashboardCard -Title "Avg. Latency"
    $totalRunsCard = New-DashboardCard -Title "Total Runs"
    $passedCard = New-DashboardCard -Title "Passed"
    $failedCard = New-DashboardCard -Title "Failed"

    $dashboardCardsLayout.Controls.AddRange(@($uptimeCard.Panel, $latencyCard.Panel, $totalRunsCard.Panel, $passedCard.Panel, $failedCard.Panel))

    # --- Chart ---
    $chartGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Latency Over Time"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor=$script:Theme.GroupBackground }
    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart -Property @{ Dock='Fill' }
    $chartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
    $chartArea.AxisX.LabelStyle.Format = "HH:mm"
    $chartArea.AxisY.Title = "Latency (ms)"
    $chart.ChartAreas.Add($chartArea)
    
    $latencySeries = New-Object System.Windows.Forms.DataVisualization.Charting.Series("Latency")
    $latencySeries.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
    $latencySeries.BorderWidth = 2
    $latencySeries.Color = [System.Drawing.ColorTranslator]::FromHtml("#0078d4")
    $chart.Series.Add($latencySeries)
    $chartGroup.Controls.Add($chart)

    # --- Update Logic ---
    $script:filteredDashboardData = $null
    function Update-DashboardData {
        if (-not (Test-Path $monitorLogFilePath)) {
            $uptimeCard.ValueLabel.Text = "N/A"; $latencyCard.ValueLabel.Text = "N/A"; $totalRunsCard.ValueLabel.Text = "N/A"; $passedCard.ValueLabel.Text = "N/A"; $failedCard.ValueLabel.Text = "N/A"
            $latencySeries.Points.Clear()
            return
        }
        try {
            $allData = Import-Csv $monitorLogFilePath
            
            # Populate filter dropdown
            $currentFilter = $comboMonitorFilter.SelectedItem
            $monitors = $allData | Select-Object -ExpandProperty MonitorName -Unique | Sort-Object
            $comboMonitorFilter.Items.Clear()
            $comboMonitorFilter.Items.Add("All Monitors")
            $comboMonitorFilter.Items.AddRange($monitors)
            if ($currentFilter -and $comboMonitorFilter.Items.Contains($currentFilter)) { $comboMonitorFilter.SelectedItem = $currentFilter } else { $comboMonitorFilter.SelectedIndex = 0 }

            # Filter data based on selection
            $data = $allData
            if ($comboMonitorFilter.SelectedItem -ne "All Monitors") {
                $data = $allData | Where-Object { $_.MonitorName -eq $comboMonitorFilter.SelectedItem }
            }

            # Date filtering
            if ($dtpFrom.Checked) {
                $data = $data | Where-Object { ([DateTime]$_.Timestamp) -ge $dtpFrom.Value.Date }
            }
            if ($dtpTo.Checked) {
                $data = $data | Where-Object { ([DateTime]$_.Timestamp) -le $dtpTo.Value.Date.AddDays(1).AddTicks(-1) }
            }

            $script:filteredDashboardData = $data

            if ($data.Count -eq 0) { throw "No data for selected monitor and date range." }

            $totalRuns = $data.Count
            $passed = ($data | Where-Object { $_.Success -eq 'True' }).Count
            $failed = $totalRuns - $passed
            $uptime = if ($totalRuns -gt 0) { ($passed / $totalRuns) } else { 0 }
            $avgLatency = ($data | Measure-Object -Property TimeMs -Average).Average

            $uptimeCard.ValueLabel.Text = "{0:P2}" -f $uptime
            $latencyCard.ValueLabel.Text = "{0:N0} ms" -f $avgLatency
            $totalRunsCard.ValueLabel.Text = $totalRuns
            $passedCard.ValueLabel.Text = $passed
            $failedCard.ValueLabel.Text = $failed

            if ($uptime -ge 0.99) { $uptimeCard.ValueLabel.ForeColor = [System.Drawing.Color]::DarkGreen }
            elseif ($uptime -ge 0.95) { $uptimeCard.ValueLabel.ForeColor = [System.Drawing.Color]::Orange }
            else { $uptimeCard.ValueLabel.ForeColor = [System.Drawing.Color]::DarkRed }

            # Update Chart
            $latencySeries.Points.Clear()
            $data | ForEach-Object {
                $ts = [DateTime]$_.Timestamp
                $latencySeries.Points.AddXY($ts, [int]$_.TimeMs) | Out-Null
            }
            $chartArea.AxisX.LabelStyle.Format = if (($data[-1].Timestamp -as [datetime]) - ($data[0].Timestamp -as [datetime]).TotalDays -gt 1) { "MM-dd HH:mm" } else { "HH:mm:ss" }
            $chart.DataManipulator.Sort("X", $latencySeries)

        } catch {
            $uptimeCard.ValueLabel.Text = "N/A"; $latencyCard.ValueLabel.Text = "N/A"; $totalRunsCard.ValueLabel.Text = "N/A"; $passedCard.ValueLabel.Text = "N/A"; $failedCard.ValueLabel.Text = "N/A"
            $latencySeries.Points.Clear()
        }
    }

    $dtpFrom.Add_ValueChanged({ Update-DashboardData })
    $dtpTo.Add_ValueChanged({ Update-DashboardData })
    $btnRefresh.Add_Click({ Update-DashboardData })
    $comboMonitorFilter.Add_SelectedIndexChanged({ Update-DashboardData })

    $btnExportData.Add_Click({
        if (-not $script:filteredDashboardData -or $script:filteredDashboardData.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("There is no data to export.", "Info", "OK", "Information")
            return
        }
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = "CSV File (*.csv)|*.csv"
        $sfd.FileName = "monitor_data_export_$((Get-Date).ToString('yyyyMMdd')).csv"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $script:filteredDashboardData | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
                [System.Windows.Forms.MessageBox]::Show("Data exported successfully.", "Success", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to export data: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    })

    $btnSaveChart.Add_Click({
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = "PNG Image|*.png|JPEG Image|*.jpg|Bitmap Image|*.bmp"
        $sfd.Title = "Save Chart Image"
        $sfd.FileName = "MonitorChart.png"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Png
                if ($sfd.FileName.EndsWith(".jpg", [System.StringComparison]::OrdinalIgnoreCase)) { $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Jpeg }
                elseif ($sfd.FileName.EndsWith(".bmp", [System.StringComparison]::OrdinalIgnoreCase)) { $format = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Bmp }
                
                $chart.SaveImage($sfd.FileName, $format)
                [System.Windows.Forms.MessageBox]::Show("Chart saved successfully.", "Success", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to save chart: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    })

    # --- Assemble Form ---
    $mainLayout.Controls.Add($toolbar, 0, 0)
    $mainLayout.Controls.Add($dashboardCardsLayout, 0, 1)
    $mainLayout.Controls.Add($chartGroup, 0, 2)
    $dashboardForm.Controls.Add($mainLayout)

    $dashboardForm.Add_Load({ Update-DashboardData })
    $dashboardForm.ShowDialog($parentForm)
}

# --- Report Customization Dialog ---
function Show-ReportCustomizationDialog {
    param($parentForm)

    $dialog = New-Object System.Windows.Forms.Form -Property @{
        Text = "Customize Report"
        Size = New-Object System.Drawing.Size(400, 500)
        StartPosition = "CenterParent"
        FormBorderStyle = "FixedDialog"
        MaximizeBox = $false
        MinimizeBox = $false
    }

    $layout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; Padding = [System.Windows.Forms.Padding]::new(10); ColumnCount = 1 }
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $chkSummaryCards = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Include Summary Cards"; Checked = $true; AutoSize = $true }
    $chkMonitorStats = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Include Monitor Statistics Table"; Checked = $true; AutoSize = $true }
    
    $groupDetailedLog = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Detailed Log Columns"; Dock = 'Fill' }
    $clbColumns = New-Object System.Windows.Forms.CheckedListBox -Property @{ Dock = 'Fill'; CheckOnClick = $true; BorderStyle = 'None' }
    
    $availableColumns = @("Timestamp", "MonitorName", "URL", "Success", "StatusCode", "TimeMs", "Message")
    $clbColumns.Items.AddRange($availableColumns)
    for ($i = 0; $i -lt $clbColumns.Items.Count; $i++) {
        $clbColumns.SetItemChecked($i, $true)
    }
    $groupDetailedLog.Controls.Add($clbColumns)

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ FlowDirection = 'RightToLeft'; Dock = 'Fill'; AutoSize = $true }
    $btnGenerate = New-Button -Text "Generate" -Style 'Primary' -Property @{ Width = 100; Height = 32 } -OnClick {
        $selectedColumns = @()
        foreach ($item in $clbColumns.CheckedItems) {
            $selectedColumns += $item
        }
        $dialog.Tag = [PSCustomObject]@{
            IncludeSummaryCards = $chkSummaryCards.Checked
            IncludeMonitorStats = $chkMonitorStats.Checked
            DetailedLogColumns = $selectedColumns
        }
        $dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $dialog.Close()
    }
    $btnCancel = New-Button -Text "Cancel" -Style 'Secondary' -Property @{ Width = 100; Height = 32 } -OnClick {
        $dialog.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $dialog.Close()
    }
    $buttons.Controls.AddRange(@($btnGenerate, $btnCancel))

    $layout.Controls.Add($chkSummaryCards, 0, 0)
    $layout.Controls.Add($chkMonitorStats, 0, 1)
    $layout.Controls.Add($groupDetailedLog, 0, 2)
    $layout.Controls.Add($buttons, 0, 3)

    $dialog.Controls.Add($layout)
    $result = $dialog.ShowDialog($parentForm)

    return [PSCustomObject]@{
        Result = $result
        Options = $dialog.Tag
    }
}

# --- Report Generator Window ---
function Show-ReportGenerator {
    param($parentForm)
    
    if (-not (Test-Path $monitorLogFilePath)) {
        [System.Windows.Forms.MessageBox]::Show("No monitor log file found to generate report.", "Info", "OK", "Information")
        return
    }

    # Show customization dialog
    $customization = Show-ReportCustomizationDialog -parentForm $parentForm
    if ($customization.Result -ne [System.Windows.Forms.DialogResult]::OK) {
        return # User cancelled
    }
    $options = $customization.Options

    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "HTML Report (*.html)|*.html"
    $sfd.FileName = "API_Test_Report_$((Get-Date).ToString('yyyyMMdd')).html"
    
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $data = Import-Csv $monitorLogFilePath
            if ($data.Count -eq 0) { throw "Log file is empty." }

            $html = @"
<!DOCTYPE html>
<html>
<head>
<title>API Test Report</title>
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f4f4; }
h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
.summary { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
.card { border: 1px solid #ddd; padding: 20px; border-radius: 8px; background: white; min-width: 150px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.card h3 { margin: 0 0 10px 0; font-size: 1em; color: #666; text-transform: uppercase; letter-spacing: 1px; }
.card .value { font-size: 2em; font-weight: bold; color: #333; }
.pass { color: #28a745; }
.fail { color: #dc3545; }
table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
th { background-color: #0078d4; color: white; font-weight: 600; }
tr:last-child td { border-bottom: none; }
tr:hover { background-color: #f9f9f9; }
</style>
</head>
<body>
<h1>API Test Execution Report</h1>
<p>Generated on $(Get-Date)</p>
"@
            if ($options.IncludeSummaryCards) {
                $totalRuns = $data.Count
                $passed = ($data | Where-Object { $_.Success -eq 'True' }).Count
                $failed = $totalRuns - $passed
                $passRate = if ($totalRuns -gt 0) { "{0:N2}" -f (($passed / $totalRuns) * 100) } else { 0 }
                $html += @"
<div class="summary">
    <div class="card"><h3>Total Runs</h3><div class="value">$totalRuns</div></div>
    <div class="card"><h3>Pass Rate</h3><div class="value $(if([double]$passRate -ge 90){'pass'}else{'fail'})">$passRate%</div></div>
    <div class="card"><h3>Passed</h3><div class="value pass">$passed</div></div>
    <div class="card"><h3>Failed</h3><div class="value fail">$failed</div></div>
</div>
"@
            }

            if ($options.IncludeMonitorStats) {
                $monitors = $data | Group-Object MonitorName
                $html += @"
<h2>Detailed Statistics</h2>
<table>
<thead><tr><th>Monitor Name</th><th>Runs</th><th>Pass %</th><th>Avg Time (ms)</th><th>Max Time (ms)</th><th>Last Status</th></tr></thead>
<tbody>
"@
                foreach ($m in $monitors) {
                    $mRuns = $m.Group.Count
                    $mPassed = ($m.Group | Where-Object { $_.Success -eq 'True' }).Count
                    $mPassRate = "{0:N2}" -f (($mPassed / $mRuns) * 100)
                    $times = $m.Group | ForEach-Object { [int]$_.TimeMs }
                    $avgTime = "{0:N0}" -f ($times | Measure-Object -Average).Average
                    $maxTime = ($times | Measure-Object -Maximum).Maximum
                    $lastStatus = $m.Group[$m.Group.Count - 1].Message
                    
                    $html += "<tr><td>$($m.Name)</td><td>$mRuns</td><td>$mPassRate%</td><td>$avgTime</td><td>$maxTime</td><td>$lastStatus</td></tr>"
                }
                $html += @"
</tbody>
</table>
"@
            }

            if ($options.DetailedLogColumns.Count -gt 0) {
                $html += @"
<h2>Detailed Log</h2>
<table>
<thead><tr>
"@
                foreach ($col in $options.DetailedLogColumns) {
                    $html += "<th>$col</th>"
                }
                $html += "</tr></thead><tbody>"

                foreach ($row in $data) {
                    $html += "<tr>"
                    foreach ($col in $options.DetailedLogColumns) {
                        $html += "<td>$($row.$col)</td>"
                    }
                    $html += "</tr>"
                }

                $html += "</tbody></table>"
            }

            $html += @"
</body>
</html>
"@
            $html | Set-Content -Path $sfd.FileName -Encoding UTF8
            Start-Process $sfd.FileName
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to generate report: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
}

# --- Monitor Editor Window ---
function Show-MonitorEditor {
    param($Monitor)
    $form = New-Object System.Windows.Forms.Form -Property @{
        Text          = "Edit Monitor"
        Size          = New-Object System.Drawing.Size(800, 850)
        MinimumSize   = New-Object System.Drawing.Size(750, 800)
        StartPosition = "CenterParent"
        BackColor     = $script:Theme.FormBackground
        Padding       = [System.Windows.Forms.Padding]::new(10)
        AutoScroll    = $false
    }

    # Main layout
    $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock        = 'Top'
        ColumnCount = 1
        AutoScroll  = $false
        AutoSize    = $true
    }
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    # --- General Settings Group ---
    $grpGeneral = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "General"; Dock = 'Fill'; AutoSize = $true; Padding = [System.Windows.Forms.Padding]::new(10); Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
    $tblGeneral = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; ColumnCount = 2; AutoSize = $true }
    $tblGeneral.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $tblGeneral.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $lblName = New-Label -Text "Monitor Name:" -Property @{ AutoSize = $true; Anchor = 'Left'; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(0, 3, 10, 3) }
    $txtName = New-TextBox -Property @{ Text = $Monitor.Name; Dock = 'Fill' }

    $lblInterval = New-Label -Text "Interval (seconds):" -Property @{ AutoSize = $true; Anchor = 'Left'; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(0, 3, 10, 3) }
    $numInterval = New-Object System.Windows.Forms.NumericUpDown -Property @{ Width = 100; Minimum = 10; Maximum = 86400; Value = $Monitor.IntervalSeconds; Anchor = 'Left' }

    $tblGeneral.Controls.Add($lblName, 0, 0); $tblGeneral.Controls.Add($txtName, 1, 0)
    $tblGeneral.Controls.Add($lblInterval, 0, 1); $tblGeneral.Controls.Add($numInterval, 1, 1)
    $grpGeneral.Controls.Add($tblGeneral)

    # --- Request Details Group (Refactored) ---
    $grpReq = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Request Details"; Dock = 'Fill'; AutoSize = $false; Height = 320; Padding = [System.Windows.Forms.Padding]::new(10); Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
    $requestTabControl = New-Object System.Windows.Forms.TabControl -Property @{ Dock = 'Fill'; Height = 300; MinimumSize = New-Object System.Drawing.Size(200, 280); Margin = [System.Windows.Forms.Padding]::new(0) }

    # Request > General Tab
    $tabReqGeneral = New-Object System.Windows.Forms.TabPage -Property @{ Text = "General" }
    $tblReqGeneral = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; ColumnCount = 2; AutoSize = $true }
    $tblReqGeneral.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $tblReqGeneral.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $lblReqMethod = New-Label -Text "Method:" -Property @{ Anchor = 'Left'; TextAlign = 'MiddleLeft' }
    $comboReqMethod = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Dock = 'Fill' }
    $comboReqMethod.Items.AddRange(@("GET", "POST", "PUT", "DELETE", "PATCH"))
    $comboReqMethod.SelectedItem = $Monitor.Request.Method
    $lblReqUrl = New-Label -Text "URL:" -Property @{ Anchor = 'Left'; TextAlign = 'MiddleLeft' }
    $txtReqUrl = New-TextBox -Property @{ Text = $Monitor.Request.Url; Dock = 'Fill' }
    $lblReqTimeout = New-Label -Text "Timeout (seconds):" -Property @{ Anchor = 'Left'; TextAlign = 'MiddleLeft' }
    $numReqTimeout = New-Object System.Windows.Forms.NumericUpDown -Property @{ Width = 100; Minimum = 1; Maximum = 300; Value = $Monitor.Request.RequestTimeoutSeconds }
    $btnImport = New-Button -Text "Import from Main Window" -Property @{ AutoSize = $true; MinimumSize = New-Object System.Drawing.Size(180, 26); Anchor = 'Left'; Margin = [System.Windows.Forms.Padding]::new(0, 6, 0, 0) } -OnClick {
        $comboReqMethod.SelectedItem = $script:comboMethod.SelectedItem
        $txtReqUrl.Text = $script:textUrl.Text
        $txtReqHeaders.Text = $script:textHeaders.Text
        $txtReqBody.Text = $script:textBody.Text
        $comboReqBodyType.SelectedItem = $script:comboBodyType.SelectedItem

        # Import Authentication settings
        $mainFormAuthData = (& $script:authPanel.GetAuthData)
        $editorAuthPanel = $authPanel
        $editorAuthPanel.ComboAuthType.SelectedItem = $mainFormAuthData.Type
        & $editorAuthPanel.SwitchPanel
        switch ($mainFormAuthData.Type) {
            "API Key"      { $editorAuthPanel.TextApiKeyName.Text = $mainFormAuthData.Key; $editorAuthPanel.TextApiKeyValue.Text = $mainFormAuthData.Value; $editorAuthPanel.ComboApiKeyAddTo.SelectedItem = $mainFormAuthData.AddTo }
            "Bearer Token" { $editorAuthPanel.TextBearerToken.Text = $mainFormAuthData.Token }
            "Basic Auth"   { $editorAuthPanel.TextBasicUser.Text = $mainFormAuthData.Username; $editorAuthPanel.TextBasicPass.Text = $mainFormAuthData.Password }
            "Auth2"        {
                $editorAuthPanel.TextAuth2ClientId.Text = $mainFormAuthData.ClientId; $editorAuthPanel.TextAuth2ClientSecret.Text = $mainFormAuthData.ClientSecret; $editorAuthPanel.TextAuth2AuthEndpoint.Text = $mainFormAuthData.AuthEndpoint; $editorAuthPanel.TextAuth2RedirectUri.Text = $mainFormAuthData.RedirectUri; $editorAuthPanel.TextAuth2TokenEndpoint.Text = $mainFormAuthData.TokenEndpoint; $editorAuthPanel.TextAuth2Scope.Text = $mainFormAuthData.Scope; $editorAuthPanel.TextAuth2AccessToken.Text = $mainFormAuthData.AccessToken; $editorAuthPanel.TextAuth2RefreshToken.Text = $mainFormAuthData.RefreshToken; $editorAuthPanel.TextAuth2ExpiresIn.Text = $mainFormAuthData.ExpiresIn; $editorAuthPanel.TextAuth2AccessToken.Tag = $mainFormAuthData.TokenExpiryTimestamp
            }
        }
        [System.Windows.Forms.MessageBox]::Show("Request details imported from main window.", "Import Complete", "OK", "Information")
    }
    $tblReqGeneral.Controls.Add($lblReqMethod, 0, 0); $tblReqGeneral.Controls.Add($comboReqMethod, 1, 0)
    $tblReqGeneral.Controls.Add($lblReqUrl, 0, 1); $tblReqGeneral.Controls.Add($txtReqUrl, 1, 1)
    $tblReqGeneral.Controls.Add($lblReqTimeout, 0, 2); $tblReqGeneral.Controls.Add($numReqTimeout, 1, 2)
    $tblReqGeneral.Controls.Add($btnImport, 0, 3); $tblReqGeneral.SetColumnSpan($btnImport, 2)
    $tabReqGeneral.Controls.Add($tblReqGeneral)

    # Request > Headers Tab
    $tabReqHeaders = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Headers" }
    $txtReqHeaders = New-TextBox -Multiline $true -Property @{ Text = $Monitor.Request.Headers; Dock = 'Fill'; Font = New-Object System.Drawing.Font("Courier New", 9) }
    $tabReqHeaders.Controls.Add($txtReqHeaders)

    # Request > Body Tab
    $tabReqBody = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Body" }
    $panelReqBodyType = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Top'; AutoSize = $true }
    $lblReqBodyType = New-Label -Text "Body Type:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 3, 0, 0) }
    $comboReqBodyType = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 200 }
    $comboReqBodyType.Items.AddRange(@("multipart/form-data", "application/json", "application/xml", "text/plain", "application/x-www-form-urlencoded", "GraphQL"))
    $comboReqBodyType.SelectedItem = $Monitor.Request.BodyType
    $panelReqBodyType.Controls.AddRange(@($lblReqBodyType, $comboReqBodyType))
    $txtReqBody = New-TextBox -Multiline $true -Property @{ Text = $Monitor.Request.Body; Dock = 'Fill'; Font = New-Object System.Drawing.Font("Courier New", 9) }
    $tabReqBody.Controls.AddRange(@($txtReqBody, $panelReqBodyType))

    # Request > Auth Tab
    $authPanel = New-AuthPanel -AuthData $Monitor.Request.Authentication
    $tabReqAuth = $authPanel.Tab

    $requestTabControl.TabPages.AddRange(@($tabReqGeneral, $tabReqHeaders, $tabReqBody, $tabReqAuth))
    $grpReq.Controls.Add($requestTabControl)

    # --- Alerting Group ---
    $grpAlert = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Alerting"; Dock = 'Fill'; AutoSize = $true; Padding = [System.Windows.Forms.Padding]::new(10); Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
    $tblAlert = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; ColumnCount = 2; AutoSize = $true }
    $tblAlert.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $tblAlert.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $chkFail = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Alert on HTTP Failure (Status != 2xx)"; Checked = $Monitor.Alerts.OnFailure; AutoSize = $true }
    $chkSlow = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Alert on Slow Response"; Checked = $Monitor.Alerts.OnSlow; AutoSize = $true }
    $lblThresh = New-Label -Text "Threshold (ms):" -Property @{ AutoSize = $true; Anchor = 'Left'; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 0) }
    $numThresh = New-Object System.Windows.Forms.NumericUpDown -Property @{ Width = 80; Minimum = 1; Maximum = 60000; Anchor = 'Left' }
    try { $numThresh.Value = $Monitor.Alerts.ThresholdMs } catch { $numThresh.Value = 1000 }
    $chkEmail = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Send Email Alert"; Checked = $Monitor.Alerts.SendEmail; AutoSize = $true }
    $lblEmail = New-Label -Text "To:" -Property @{ AutoSize = $true; Anchor = 'Left'; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 0) }
    $txtEmail = New-TextBox -Property @{ Text = $Monitor.Alerts.EmailTo; Dock = 'Fill' }
    $btnSmtpConfig = New-Button -Text "Configure Email (Global)" -Property @{ Width = 250; Height = 35; Anchor = 'Left'; Margin = [System.Windows.Forms.Padding]::new(0, 5, 0, 0) } -OnClick { Show-MonitorEmailSettings -parentForm $form }

    $tblAlert.Controls.Add($chkFail, 0, 0); $tblAlert.SetColumnSpan($chkFail, 2)
    $tblAlert.Controls.Add($chkSlow, 0, 1); $tblAlert.SetColumnSpan($chkSlow, 2)
    $tblAlert.Controls.Add($lblThresh, 0, 2); $tblAlert.Controls.Add($numThresh, 1, 2)
    $tblAlert.Controls.Add($chkEmail, 0, 3); $tblAlert.SetColumnSpan($chkEmail, 2)
    $tblAlert.Controls.Add($lblEmail, 0, 4); $tblAlert.Controls.Add($txtEmail, 1, 4)
    $tblAlert.Controls.Add($btnSmtpConfig, 0, 5); $tblAlert.SetColumnSpan($btnSmtpConfig, 2)
    $grpAlert.Controls.Add($tblAlert)

    # --- Analytics Group ---
    $grpAnalytics = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Analytics Integration (Webhook URL)"; Dock = 'Fill'; AutoSize = $false; Height = 70; Padding = [System.Windows.Forms.Padding]::new(10); Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
    $txtWebhook = New-TextBox -Property @{ Text = $Monitor.AnalyticsUrl; Dock = 'Top'; Height = 25 }
    $grpAnalytics.Controls.Add($txtWebhook)

    $mainLayout.Controls.Add($grpGeneral, 0, 0)
    $mainLayout.Controls.Add($grpReq, 0, 1)
    $mainLayout.Controls.Add($grpAlert, 0, 2)
    $mainLayout.Controls.Add($grpAnalytics, 0, 3)

    # --- Bottom Button Panel ---
    $btnPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Bottom'; Height = 55; ColumnCount = 4; Padding = [System.Windows.Forms.Padding]::new(5) }
    $btnPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) # Spacer
    $btnPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) # Test
    $btnPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) # Save
    $btnPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) # Cancel

    $btnSave = New-Button -Text "Save" -Style 'Primary' -Property @{ Width = 100; Height = 35; Anchor = 'None' } -OnClick {
        # Validation
        if ([string]::IsNullOrWhiteSpace($txtName.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Monitor Name cannot be empty.", "Validation Error", "OK", "Warning")
            return
        }
        if ([string]::IsNullOrWhiteSpace($txtReqUrl.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Request URL cannot be empty.", "Validation Error", "OK", "Warning")
            return
        }

        $Monitor.Name = $txtName.Text
        $Monitor.IntervalSeconds = $numInterval.Value
        $Monitor.Request.Method = $comboReqMethod.SelectedItem
        $Monitor.Request.Url = $txtReqUrl.Text
        $Monitor.Request.RequestTimeoutSeconds = $numReqTimeout.Value
        $Monitor.Request.Headers = $txtReqHeaders.Text
        $Monitor.Request.BodyType = $comboReqBodyType.SelectedItem
        $Monitor.Request.Body = $txtReqBody.Text
        $Monitor.Request.Authentication = & $authPanel.GetAuthData
        $Monitor.Alerts.OnFailure = $chkFail.Checked
        $Monitor.Alerts.OnSlow = $chkSlow.Checked
        $Monitor.Alerts.ThresholdMs = $numThresh.Value
        $Monitor.Alerts.SendEmail = $chkEmail.Checked
        $Monitor.Alerts.EmailTo = $txtEmail.Text
        $Monitor.AnalyticsUrl = $txtWebhook.Text
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    }
    $btnCancel = New-Button -Text "Cancel" -Property @{ Width = 100; Height = 35; Anchor = 'None' } -OnClick { $form.Close() }
    $btnTest = New-Button -Text "Test Request" -Property @{ Width = 140; Height = 35; Anchor = 'None' } -OnClick {
        try {
            $req = [System.Net.HttpWebRequest]::Create($txtReqUrl.Text)
            $req.Method = $comboReqMethod.SelectedItem
            $req.Timeout = $numReqTimeout.Value * 1000
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $resp = $req.GetResponse()
            $sw.Stop()
            [System.Windows.Forms.MessageBox]::Show("Success!`nStatus: $([int]$resp.StatusCode)`nTime: $($sw.ElapsedMilliseconds)ms", "Test Result", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed!`nError: $($_.Exception.Message)", "Test Result", "OK", "Error")
        }
    }

    $btnPanel.Controls.Add($btnTest, 1, 0)
    $btnPanel.Controls.Add($btnSave, 2, 0)
    $btnPanel.Controls.Add($btnCancel, 3, 0)

    $scrollPanel = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Fill'; AutoScroll = $true }
    $scrollPanel.Controls.Add($mainLayout)

    $form.Controls.AddRange(@($scrollPanel, $btnPanel))
    return $form.ShowDialog()
}

# --- Monitor Manager Window ---
function Show-MonitorManager {
    param([System.Windows.Forms.Form]$parentForm)

    $monitorForm = New-Object System.Windows.Forms.Form -Property @{
        Text = "API Monitor Manager"
        Size = New-Object System.Drawing.Size(1280, 650)
        MinimumSize = New-Object System.Drawing.Size(1280, 500)
        StartPosition = "CenterParent"
    }
    
    $listMonitors = New-Object System.Windows.Forms.ListView -Property @{ Dock = 'Fill'; View = 'Details'; FullRowSelect = $true; GridLines = $true }
    $listMonitors.Columns.Add("Name", 150) | Out-Null
    $listMonitors.Columns.Add("URL", 250) | Out-Null
    $listMonitors.Columns.Add("Interval (s)", 80) | Out-Null
    $listMonitors.Columns.Add("Status", 80) | Out-Null
    $listMonitors.Columns.Add("Last Run", 120) | Out-Null

    function Refresh-List {
        $listMonitors.Items.Clear()
        foreach ($m in $script:monitors) {
            $item = New-Object System.Windows.Forms.ListViewItem($m.Name)
            $item.SubItems.Add($m.Request.Url) | Out-Null
            $item.SubItems.Add($m.IntervalSeconds) | Out-Null
            $item.SubItems.Add($m.Status) | Out-Null
            $lastRun = if ($m.LastRun) { [DateTime]$m.LastRun } else { "Never" }
            $item.SubItems.Add($lastRun.ToString()) | Out-Null
            $item.Tag = $m
            $listMonitors.Items.Add($item) | Out-Null
        }
    }
    Refresh-List

    $panelBtn = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Bottom'; AutoSize = $true; ColumnCount = 3; Padding = [System.Windows.Forms.Padding]::new(0, 5, 0, 5) }
    $panelBtn.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null
    $panelBtn.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $panelBtn.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null
    
    $btnAdd = New-Button -Text "Add Monitor..." -Property @{ Width = 130; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        $newMonitor = @{
            Id = [Guid]::NewGuid().ToString()
            Name = "New Monitor"
            Status = "Stopped"
            IntervalSeconds = 60
            Request = @{ Method="GET"; Url="http://"; Headers=""; Body=""; BodyType="multipart/form-data"; RequestTimeoutSeconds=30; Authentication = @{ Type = "No Auth" } }
            Alerts = @{ OnFailure=$true; OnSlow=$false; ThresholdMs=1000; SendEmail=$false; EmailTo="" }
            AnalyticsUrl = ""
            LastRun = $null
        }
        if ((Show-MonitorEditor -Monitor $newMonitor) -eq [System.Windows.Forms.DialogResult]::OK) {
            $script:monitors += $newMonitor
            Save-Monitors
            Refresh-List
        }
    }

    $btnEdit = New-Button -Text "Edit" -Property @{ Width = 100; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if ($listMonitors.SelectedItems.Count -gt 0) {
            $m = $listMonitors.SelectedItems[0].Tag
            # Deep clone the monitor object to prevent auto-saving on cancel
            $monitorToEdit = $m | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            if ((Show-MonitorEditor -Monitor $monitorToEdit) -eq [System.Windows.Forms.DialogResult]::OK) {
                # Find the original monitor by its ID and replace it with the edited version
                $originalMonitorIndex = -1
                for ($i = 0; $i -lt $script:monitors.Count; $i++) {
                    if ($script:monitors[$i].Id -eq $m.Id) {
                        $originalMonitorIndex = $i
                        break
                    }
                }
                if ($originalMonitorIndex -ne -1) { $script:monitors[$originalMonitorIndex] = $monitorToEdit }
                Save-Monitors # Save the entire updated array
                Refresh-List
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please select a monitor to edit.", "Selection Required", "OK", "Warning")
        }
    }

    $btnToggle = New-Button -Text "Start/Stop" -Property @{ Width = 110; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if ($listMonitors.SelectedItems.Count -gt 0) {
            $m = $listMonitors.SelectedItems[0].Tag
            if ($m.Status -eq "Running") { $m.Status = "Stopped" } else { $m.Status = "Running"; $m.LastRun = $null }
            Save-Monitors
            Refresh-List
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please select a monitor to start or stop.", "Selection Required", "OK", "Warning")
        }
    }

    $btnDelete = New-Button -Text "Delete" -Property @{ Width = 100; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if ($listMonitors.SelectedItems.Count -gt 0) {
            $m = $listMonitors.SelectedItems[0].Tag
            if ([System.Windows.Forms.MessageBox]::Show("Are you sure you want to delete monitor '$($m.Name)'?", "Confirm Delete", "YesNo", "Warning") -eq "Yes") {
                $script:monitors = $script:monitors | Where-Object { $_.Id -ne $m.Id }
                Save-Monitors
                Refresh-List
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please select a monitor to delete.", "Selection Required", "OK", "Warning")
        }
    }

    $btnOpenLog = New-Button -Text "Open Log" -Property @{ Width = 180; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if (Test-Path $monitorLogFilePath) {
            try {
                Start-Process $monitorLogFilePath
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to open log file: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Log file not found yet.", "Info", "OK", "Information")
        }
    }

    $btnCharts = New-Button -Text "Visualize" -Property @{ Width = 110; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        Show-MonitorChartWindow -parentForm $monitorForm
    }

    $btnEmailConfig = New-Button -Text "Email Config" -Property @{ Width = 130; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        Show-MonitorEmailSettings -parentForm $monitorForm
    }

    $btnClearLog = New-Button -Text "Clear Log" -Property @{ Width = 180; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if ([System.Windows.Forms.MessageBox]::Show("Clear the monitor log file?", "Confirm", "YesNo", "Warning") -eq "Yes") {
            Clear-Content $monitorLogFilePath -ErrorAction SilentlyContinue
            [System.Windows.Forms.MessageBox]::Show("Log cleared.", "Info", "OK", "Information")
        }
    }

    $btnArchiveLog = New-Button -Text "Archive Log" -Property @{ Width = 120; Height = 35; Margin = [System.Windows.Forms.Padding]::new(5) } -OnClick {
        if (Test-Path $monitorLogFilePath) {
            $archiveName = "$monitorLogFilePath.$((Get-Date).ToString('yyyyMMdd-HHmmss')).csv"
            Rename-Item $monitorLogFilePath $archiveName
            [System.Windows.Forms.MessageBox]::Show("Log archived to:`n$archiveName", "Info", "OK", "Information")
        }
    }

    $buttonsFlow = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ AutoSize = $true; FlowDirection = 'LeftToRight'; WrapContents = $false; Margin = [System.Windows.Forms.Padding]::new(0); Padding = [System.Windows.Forms.Padding]::new(5,0,5,0) }
    $buttonsFlow.Controls.AddRange(@($btnCharts, $btnOpenLog, $btnAdd, $btnEdit, $btnToggle, $btnDelete, $btnEmailConfig, $btnClearLog, $btnArchiveLog))
    $panelBtn.Controls.Add($buttonsFlow, 1, 0)
    $monitorForm.Controls.AddRange(@($listMonitors, $panelBtn))
    $monitorForm.ShowDialog($parentForm)
}

# --- JWT Tool Window ---
function Show-JwtTool {
    $jwtForm = New-Object System.Windows.Forms.Form -Property @{ Text = "JWT Utility"; Size = New-Object System.Drawing.Size(950, 700); StartPosition = "CenterParent"; BackColor = $script:Theme.FormBackground }
    $tabs = New-Object System.Windows.Forms.TabControl -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Segoe UI", 10) }
    
    # Decoder Tab
    $tabDecode = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Decoder"; Padding = [System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.FormBackground }
    $split = New-Object System.Windows.Forms.SplitContainer -Property @{ Dock = 'Fill'; Orientation = 'Horizontal'; SplitterDistance = 280; BackColor = $script:Theme.FormBackground }
    
    $inputGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "JWT Input"; Dock = 'Fill'; Padding = [System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.GroupBackground }
    $inputLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=1; RowCount=2 }
    $inputLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $inputLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $txtJwtInput = New-RichTextBox -Property @{ Dock = 'Fill'; Text = "Paste JWT here..."; BorderStyle = 'FixedSingle'; BackColor = 'White'; Font = New-Object System.Drawing.Font("Consolas", 9) }
    $txtJwtOutput = New-RichTextBox -ReadOnly $true -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Consolas", 9); BorderStyle = 'FixedSingle'; BackColor = 'White' }

    $actionRow = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=3; AutoSize=$true }
    $actionRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $actionRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $actionRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $lblVerifySecret = New-Label -Text "Secret:" -Property @{ AutoSize=$true; Anchor='Left'; Margin=[System.Windows.Forms.Padding]::new(0,6,6,0) }
    $txtVerifySecret = New-TextBox -Property @{ Dock='Fill'; Margin=[System.Windows.Forms.Padding]::new(0,3,8,0); UseSystemPasswordChar = $true }

    $actionButtons = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ AutoSize=$true; FlowDirection='LeftToRight'; WrapContents=$false; Margin=[System.Windows.Forms.Padding]::new(0); Padding=[System.Windows.Forms.Padding]::new(0) }

    $btnClear = New-Button -Text "Clear" -Style 'Secondary' -Property @{ Width=90; Height=32; Margin=[System.Windows.Forms.Padding]::new(0) } -OnClick {
        $txtJwtInput.Clear()
        $txtJwtOutput.Clear()
    }

    $btnDecode = New-Button -Text "Decode" -Style 'Primary' -Property @{ Width=100; Height=32; Margin=[System.Windows.Forms.Padding]::new(0,0,6,0) } -OnClick {
        $token = $txtJwtInput.Text.Trim()
        if ($token -match '^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$') {
            $parts = $token.Split('.')
            try {
                function FromB64Url($s) { 
                    $s=$s.Replace('-','+').Replace('_','/'); switch($s.Length%4){2{$s+='=='}3{$s+='='}}; 
                    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) 
                }
                $header = FromB64Url $parts[0] | ConvertFrom-Json | ConvertTo-Json
                $payload = FromB64Url $parts[1] | ConvertFrom-Json | ConvertTo-Json
                $txtJwtOutput.Text = "HEADER:`n$header`n`nPAYLOAD:`n$payload`n`nSIGNATURE:`n$($parts[2])"
            } catch { $txtJwtOutput.Text = "Error decoding JWT: $($_.Exception.Message)" }
        } else { $txtJwtOutput.Text = "Invalid JWT format." }
    }

    $btnVerify = New-Button -Text "Verify Sig" -Style 'Secondary' -Property @{ Width=110; Height=32; Margin=[System.Windows.Forms.Padding]::new(0,0,6,0) } -OnClick {
        $token = $txtJwtInput.Text.Trim()
        $secret = $txtVerifySecret.Text
        if (-not $token -or -not $secret) { [System.Windows.Forms.MessageBox]::Show("Please enter JWT and Secret.", "Info", "OK", "Warning"); return }
        if ($token -match '^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$') {
            $parts = $token.Split('.')
            try {
                $hStr = $parts[0].Replace('-','+').Replace('_','/'); switch($hStr.Length%4){2{$hStr+='=='}3{$hStr+='='}}
                $headerJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($hStr))
                if (($headerJson | ConvertFrom-Json).alg -ne 'HS256') { [System.Windows.Forms.MessageBox]::Show("Only HS256 supported.", "Info", "OK", "Warning"); return }

                $hmac = New-Object System.Security.Cryptography.HMACSHA256(,[System.Text.Encoding]::UTF8.GetBytes($secret))
                $calcSig = [Convert]::ToBase64String($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])"))).Replace('+','-').Replace('/','_').TrimEnd('=')

                if ($calcSig -eq $parts[2]) { [System.Windows.Forms.MessageBox]::Show("Signature Verified!", "Success", "OK", "Information") }
                else { [System.Windows.Forms.MessageBox]::Show("Verification Failed!", "Error", "OK", "Error") }
            } catch { [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", "OK", "Error") }
        }
    }

    $actionButtons.Controls.AddRange(@($btnVerify, $btnDecode, $btnClear))
    $actionRow.Controls.Add($lblVerifySecret, 0, 0)
    $actionRow.Controls.Add($txtVerifySecret, 1, 0)
    $actionRow.Controls.Add($actionButtons, 2, 0)

    $inputLayout.Controls.Add($txtJwtInput, 0, 0)
    $inputLayout.Controls.Add($actionRow, 0, 1)
    $inputGroup.Controls.Add($inputLayout)

    $outputGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Decoded Output"; Dock = 'Fill'; Padding = [System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.GroupBackground }
    $outputGroup.Controls.Add($txtJwtOutput)

    $split.Panel1.Controls.Add($inputGroup)
    $split.Panel2.Controls.Add($outputGroup)
    $tabDecode.Controls.Add($split)
    
    # Generator Tab (Simple HMAC)
    $tabGen = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Generator (HS256)"; Padding = [System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.FormBackground }
    $genLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=1; RowCount=4 }
    $genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 55))) | Out-Null
    $genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 45))) | Out-Null

    $txtPayload = New-TextBox -Multiline $true -Property @{ Dock='Fill'; Height=150; Text='{ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 }'; Font=New-Object System.Drawing.Font("Consolas", 9); ScrollBars='Vertical' }
    $txtSecret = New-TextBox -Property @{ Dock='Fill'; Text='secret'; Height=25; Margin=[System.Windows.Forms.Padding]::new(0,4,0,0) }
    $txtJwtResult = New-TextBox -Multiline $true -Property @{ Dock='Fill'; ReadOnly=$true; Font=New-Object System.Drawing.Font("Consolas", 9); ScrollBars='Vertical' }

    $payloadGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Payload (JSON)"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.GroupBackground }
    $payloadGroup.Controls.Add($txtPayload)

    $secretRow = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Top'; ColumnCount=2; AutoSize=$true }
    $secretRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $secretRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $secretRow.Controls.Add((New-Label -Text "Secret:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,6,0) }), 0, 0)
    $secretRow.Controls.Add($txtSecret, 1, 0)

    $btnGen = New-Button -Text "Generate JWT" -Style 'Primary' -Property @{ Height=35; Width=140; Margin=[System.Windows.Forms.Padding]::new(0,8,0,8) } -OnClick {
        try {
            $header = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}')).Replace('+','-').Replace('/','_').TrimEnd('=')
            $payloadJson = $txtPayload.Text; $null = $payloadJson | ConvertFrom-Json # Validate
            $payload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)).Replace('+','-').Replace('/','_').TrimEnd('=')
            $secret = [System.Text.Encoding]::UTF8.GetBytes($txtSecret.Text)
            $toSign = [System.Text.Encoding]::UTF8.GetBytes("$header.$payload")
            $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$secret); $sigBytes = $hmac.ComputeHash($toSign)
            $sig = [Convert]::ToBase64String($sigBytes).Replace('+','-').Replace('/','_').TrimEnd('=')
            $txtJwtResult.Text = "$header.$payload.$sig"
        } catch { $txtJwtResult.Text = "Error: $($_.Exception.Message)" }
    }
    $resultGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Generated JWT"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.GroupBackground }
    $resultGroup.Controls.Add($txtJwtResult)

    $genLayout.Controls.Add($payloadGroup, 0, 0)
    $genLayout.Controls.Add($secretRow, 0, 1)
    $genLayout.Controls.Add($btnGen, 0, 2)
    $genLayout.Controls.Add($resultGroup, 0, 3)
    $tabGen.Controls.Add($genLayout)

    $tabs.TabPages.AddRange(@($tabDecode, $tabGen))
    $jwtForm.Controls.Add($tabs)
    $jwtForm.ShowDialog()
}

# --- REFACTORED: Environment Manager Window (now uses the top-level editor) ---
function Show-EnvironmentManagerWindow {
    param (
        [System.Windows.Forms.Form]$parentForm
    )

    $envManagerForm = New-Object System.Windows.Forms.Form -Property @{
        Text          = "Manage Environments"
        Size          = New-Object System.Drawing.Size(550, 550)
        StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        MinimumSize   = New-Object System.Drawing.Size(400, 450)
        BackColor     = $script:Theme.FormBackground
    }

    $listEnvironments = New-Object System.Windows.Forms.ListBox -Property @{ Dock = 'Fill' }
    $script:environments.Keys | Sort-Object | ForEach-Object { $listEnvironments.Items.Add($_) }

    # --- Button Panel ---
    $panelButtons = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Right'; Width = 180; Padding = [System.Windows.Forms.Padding]::new(10); FlowDirection = 'TopDown' }
    $btnAdd = New-Button -Text "Add..." -Style 'Secondary' -Property @{ Width = 150; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,0,8) } -OnClick {
        $newEnvName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter new environment name:", "Add Environment", "New Environment")
        if ($newEnvName -and -not $script:environments.ContainsKey($newEnvName)) {
            # Create a new, empty data structure for the environment
            $newEnvData = @{ Url = ""; Headers = ""; Authentication = @{ Type = "No Auth" }; Variables = @{} }
            # Open the editor with the new data
            $result = Show-EnvironmentEditor -parentForm $envManagerForm -EnvironmentName $newEnvName -EnvironmentData $newEnvData
            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                $script:environments[$newEnvName] = $newEnvData
                $listEnvironments.Items.Add($newEnvName)
                $listEnvironments.SelectedItem = $newEnvName
                Save-Environments
            }
        }
    }
    $btnEdit = New-Button -Text "Edit..." -Style 'Secondary' -Property @{ Width = 150; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,0,8) } -OnClick {
        $selected = $listEnvironments.SelectedItem
        if ($selected) {
            # Get a clone of the data to edit, so changes are only saved on "OK"
            $envData = $script:environments[$selected].Clone()
            $result = Show-EnvironmentEditor -parentForm $envManagerForm -EnvironmentName $selected -EnvironmentData $envData
            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                $script:environments[$selected] = $envData # Update with changes
                Save-Environments
            }
        }
    }
    $btnRemove = New-Button -Text "Remove" -Style 'Danger' -Property @{ Width = 150; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,0,8) } -OnClick {
        $selected = $listEnvironments.SelectedItem
        if ($selected) {
            $confirm = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to remove the '$selected' environment?", "Confirm Removal", "YesNo", "Warning")
            if ($confirm -eq 'Yes') {
                $script:environments.Remove($selected)
                $listEnvironments.Items.Remove($selected)
                Save-Environments
            }
        }
    }
    $btnSaveCurrent = New-Button -Text "Save Current..." -Style 'Secondary' -Property @{ Width = 150; Margin = [System.Windows.Forms.Padding]::new(0,15,0,8); Height = 45 } -OnClick {
        $newEnvName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter name for new environment:", "Save Current Configuration", "My Saved Request")
        if ($newEnvName -and -not $script:environments.ContainsKey($newEnvName)) {
            $newEnvData = @{
                Url       = $script:textUrl.Text
                Headers   = $script:textHeaders.Text
                Variables = @{} # Start with empty variables
                Authentication = (& $script:authPanel.GetAuthData) # Get auth data from main form's panel
            }

            $script:environments[$newEnvName] = $newEnvData
            $listEnvironments.Items.Add($newEnvName)
            $listEnvironments.SelectedItem = $newEnvName
            Save-Environments
            [System.Windows.Forms.MessageBox]::Show("Current configuration saved as new environment '$newEnvName'.", "Success", "OK", "Information")
        } elseif ($newEnvName) {
            [System.Windows.Forms.MessageBox]::Show("An environment with that name already exists.", "Error", "OK", "Error")
        }
    }
    $toolTip.SetToolTip($btnSaveCurrent, "Saves the URL, Headers, and Authentication settings from the main window as a new environment.")

    $btnClose = New-Button -Text "Close" -Style 'Primary' -Property @{ Width = 150; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,50,0,0) } -OnClick {
        Save-Environments
        $envManagerForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $envManagerForm.Close()
    }
    $panelButtons.Controls.AddRange(@($btnAdd, $btnEdit, $btnRemove, $btnSaveCurrent, $btnClose))
    
    $envManagerForm.Controls.AddRange(@($listEnvironments, $panelButtons))
    $envManagerForm.ShowDialog($parentForm)
}

# --- Log Viewer Window ---
function Show-LogViewer {
    param($parentForm)
    if (-not (Test-Path $logFilePath)) { [System.Windows.Forms.MessageBox]::Show("Log file not found.", "Info", "OK", "Information"); return } #FIX: Added check for log file
    
    $logForm = New-Object System.Windows.Forms.Form -Property @{ Text="Log Viewer"; Size=New-Object System.Drawing.Size(1000, 600); StartPosition="CenterParent" }
    $grid = New-Object System.Windows.Forms.DataGridView -Property @{ Dock="Fill"; ReadOnly=$true; AllowUserToAddRows=$false; SelectionMode="FullRowSelect"; AutoSizeColumnsMode="Fill"; RowHeadersVisible=$false }
    
    try {
        # Read with FileShare to avoid locking issues if logging happens simultaneously
        $fs = New-Object System.IO.FileStream($logFilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs)
        $content = $sr.ReadToEnd()
        $sr.Close(); $fs.Close()
        
        $data = $content | ConvertFrom-Csv
        $table = New-Object System.Data.DataTable
        $table.Columns.Add("Timestamp", [DateTime]); $table.Columns.Add("Level"); $table.Columns.Add("Message")
        
        foreach ($row in $data) { 
            $dt = [DateTime]::MinValue
            if ([DateTime]::TryParse($row.Timestamp, [ref]$dt)) {
                $table.Rows.Add($dt, $row.Level, $row.Message) | Out-Null 
            }
        }
        $grid.DataSource = $table
        
        if ($grid.Columns["Timestamp"]) { 
            $grid.Columns["Timestamp"].FillWeight = 20 
            $grid.Columns["Timestamp"].DefaultCellStyle.Format = "yyyy-MM-dd HH:mm:ss"
        }
        if ($grid.Columns["Level"]) { $grid.Columns["Level"].FillWeight = 10 }
        if ($grid.Columns["Message"]) { $grid.Columns["Message"].FillWeight = 70 }
    } catch { [System.Windows.Forms.MessageBox]::Show("Failed to load logs: $($_.Exception.Message)", "Error", "OK", "Error") }
    
    $panel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock="Top"; AutoSize=$true; Padding=[System.Windows.Forms.Padding]::new(5) }
    
    $lblSearch = New-Label -Text "Search:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,5,0,0) }
    $txtFilter = New-TextBox -Property @{ Width=200 }
    
    $lblFrom = New-Label -Text "From:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(10,5,0,0) }
    $dtpFrom = New-Object System.Windows.Forms.DateTimePicker -Property @{ Format="Short"; Width=100; ShowCheckBox=$true; Checked=$false }
    
    $lblTo = New-Label -Text "To:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,5,0,0) }
    $dtpTo = New-Object System.Windows.Forms.DateTimePicker -Property @{ Format="Short"; Width=100; ShowCheckBox=$true; Checked=$false }

    $updateFilter = { 
        $dv = $grid.DataSource.DefaultView
        $parts = @()
        
        # Text Filter
        $f = $txtFilter.Text
        if ($f) { $parts += "(Message LIKE '%$f%' OR Level LIKE '%$f%')" }
        
        # Date Filter
        if ($dtpFrom.Checked) {
            $d = $dtpFrom.Value.Date.ToString("MM/dd/yyyy")
            $parts += "Timestamp >= #$d#"
        }
        if ($dtpTo.Checked) {
            # End of day
            $d = $dtpTo.Value.Date.AddDays(1).AddTicks(-1).ToString("MM/dd/yyyy HH:mm:ss")
            $parts += "Timestamp <= #$d#"
        }
        
        if ($parts.Count -gt 0) { $dv.RowFilter = $parts -join " AND " } else { $dv.RowFilter = "" }
    }

    $txtFilter.Add_TextChanged($updateFilter) #FIX: Corrected event handler
    $dtpFrom.Add_ValueChanged($updateFilter)
    $dtpTo.Add_ValueChanged($updateFilter)

    $btnExport = New-Button -Text "Export" -Property @{ Width=100; Height=30; Margin=[System.Windows.Forms.Padding]::new(10,5,0,0) } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = "CSV Files (*.csv)|*.csv"
        $sfd.FileName = "filtered_logs.csv"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $dv = $grid.DataSource.DefaultView
                $exportData = @()
                foreach ($rowView in $dv) {
                    $exportData += [PSCustomObject]@{
                        Timestamp = $rowView["Timestamp"].ToString("yyyy-MM-dd HH:mm:ss")
                        Level     = $rowView["Level"]
                        Message   = $rowView["Message"]
                    }
                }
                $exportData | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
                [System.Windows.Forms.MessageBox]::Show("Export successful.", "Info", "OK", "Information")
            } catch { [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error") }
        }
    }

    $panel.Controls.AddRange(@($lblSearch, $txtFilter, $lblFrom, $dtpFrom, $lblTo, $dtpTo, $btnExport))
    $logForm.Controls.AddRange(@($grid, $panel))
    $logForm.ShowDialog($parentForm)
}

# Displays the main settings window, allowing users to configure application behavior.
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

    $panelsTable.Controls.AddRange(@($checkShowEnvironment, $checkShowHistory, $checkShowRequestHeaders, $checkShowAuth, $checkShowPreRequest, $checkShowTests, $checkShowTestResults, $checkShowResponse, $checkShowJsonTree, $checkShowResponseHeaders, $checkShowCurl, $checkShowConsole))
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
        Save-Settings
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
function Show-ProxySettings {
    param($parentForm)
    $form = New-Object System.Windows.Forms.Form -Property @{ Text="Proxy Configuration"; Size=New-Object System.Drawing.Size(500, 450); StartPosition="CenterParent"; BackColor=$script:Theme.FormBackground; FormBorderStyle='FixedDialog'; MaximizeBox=$false; MinimizeBox=$false }
    $layout = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; FlowDirection='TopDown'; Padding=[System.Windows.Forms.Padding]::new(15) }

    $lblMode = New-Label -Text "Proxy Mode:" -Property @{ AutoSize=$true }
    $comboMode = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle='DropDownList'; Width=200; Margin=[System.Windows.Forms.Padding]::new(0,0,0,10) }
    $comboMode.Items.AddRange(@("System", "Custom", "None"))
    $comboMode.SelectedItem = if ($script:settings.ProxyMode) { $script:settings.ProxyMode } else { "System" }

    $grpCustom = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Custom Proxy Settings"; Width=450; Height=220; Enabled=($comboMode.SelectedItem -eq "Custom") }
    $customLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=2; Padding=[System.Windows.Forms.Padding]::new(10) }
    $customLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $customLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $txtAddr = New-TextBox -Property @{ Text=$script:settings.ProxyAddress; Dock='Fill' }
    $txtPort = New-TextBox -Property @{ Text=$script:settings.ProxyPort; Width=60 }
    $txtUser = New-TextBox -Property @{ Text=$script:settings.ProxyUser; Dock='Fill' }
    $txtPass = New-TextBox -Property @{ Text=$script:settings.ProxyPass; Dock='Fill'; UseSystemPasswordChar=$true }

    $customLayout.Controls.Add((New-Label -Text "Address:" -Property @{AutoSize=$true; Anchor='Left'}), 0, 0); $customLayout.Controls.Add($txtAddr, 1, 0)
    $customLayout.Controls.Add((New-Label -Text "Port:" -Property @{AutoSize=$true; Anchor='Left'}), 0, 1); $customLayout.Controls.Add($txtPort, 1, 1)
    $customLayout.Controls.Add((New-Label -Text "Username:" -Property @{AutoSize=$true; Anchor='Left'}), 0, 2); $customLayout.Controls.Add($txtUser, 1, 2)
    $customLayout.Controls.Add((New-Label -Text "Password:" -Property @{AutoSize=$true; Anchor='Left'}), 0, 3); $customLayout.Controls.Add($txtPass, 1, 3)
    $grpCustom.Controls.Add($customLayout)

    $comboMode.Add_SelectedIndexChanged({ $grpCustom.Enabled = ($comboMode.SelectedItem -eq "Custom") })

    $btnPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ AutoSize=$true; FlowDirection='LeftToRight'; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }

    $btnSave = New-Button -Text "Save" -Style 'Primary' -Property @{ Width=180; Height=35; Margin=[System.Windows.Forms.Padding]::new(0,0,10,0) } -OnClick {
        $script:settings.ProxyMode = $comboMode.SelectedItem
        $script:settings.ProxyAddress = $txtAddr.Text
        $script:settings.ProxyPort = [int]$txtPort.Text
        $script:settings.ProxyUser = $txtUser.Text
        $script:settings.ProxyPass = $txtPass.Text
        Save-Settings
        $form.Close()
    }

    $btnTest = New-Button -Text "Test Connection" -Style 'Secondary' -Property @{ Width=180; Height=35 } -OnClick {
        if ($comboMode.SelectedItem -ne "Custom") {
             [System.Windows.Forms.MessageBox]::Show("Please select 'Custom' mode to test custom proxy settings.", "Info", "OK", "Information")
             return
        }
        $addr = $txtAddr.Text
        $port = $txtPort.Text
        if (-not $addr -or -not $port) {
             [System.Windows.Forms.MessageBox]::Show("Address and Port are required.", "Missing Info", "OK", "Warning")
             return
        }
        
        try {
            $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
            $proxy = New-Object System.Net.WebProxy($addr, [int]$port)
            if ($txtUser.Text) {
                $proxy.Credentials = New-Object System.Net.NetworkCredential($txtUser.Text, $txtPass.Text)
            }
            
            $req = [System.Net.WebRequest]::Create("http://www.google.com")
            $req.Proxy = $proxy
            $req.Timeout = 5000 # 5 seconds timeout
            $resp = $req.GetResponse()
            $resp.Close()
            
            [System.Windows.Forms.MessageBox]::Show("Connection successful!", "Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Connection failed: $($_.Exception.Message)", "Error", "OK", "Error")
        } finally {
            $form.Cursor = [System.Windows.Forms.Cursors]::Default
        }
    }

    $btnPanel.Controls.AddRange(@($btnSave, $btnTest))
    $layout.Controls.AddRange(@($lblMode, $comboMode, $grpCustom, $btnPanel))
    $form.Controls.Add($layout)
    $form.ShowDialog($parentForm)
}

# --- Cookie Jar Window ---
function Show-CookieJar {
    param($parentForm)
    $form = New-Object System.Windows.Forms.Form -Property @{ Text="Cookie Jar"; Size=New-Object System.Drawing.Size(600, 400); StartPosition="CenterParent"; BackColor=$script:Theme.FormBackground }
    
    $grid = New-Object System.Windows.Forms.DataGridView -Property @{ Dock='Fill'; ReadOnly=$true; AllowUserToAddRows=$false; RowHeadersVisible=$false; AutoSizeColumnsMode='Fill'; BackgroundColor='White' }
    $grid.Columns.Add("Domain", "Domain") | Out-Null
    $grid.Columns.Add("Name", "Name") | Out-Null
    $grid.Columns.Add("Value", "Value") | Out-Null
    $grid.Columns.Add("Path", "Path") | Out-Null
    $grid.Columns.Add("Expires", "Expires") | Out-Null

    function Refresh-Grid {
        $grid.Rows.Clear()
        if ($script:cookieJar) {
            foreach ($cookie in $script:cookieJar) {
                $grid.Rows.Add($cookie.Domain, $cookie.Name, $cookie.Value, $cookie.Path, $cookie.Expires) | Out-Null
            }
        }
    }
    Refresh-Grid

    $panelBtn = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Bottom'; AutoSize=$true; FlowDirection='RightToLeft'; Padding=[System.Windows.Forms.Padding]::new(5) }
    $btnClose = New-Button -Text "Close" -Style 'Secondary' -Property @{ Width=80; Height=30 } -OnClick { $form.Close() }
    $btnClear = New-Button -Text "Clear All" -Style 'Danger' -Property @{ Width=100; Height=30; Margin=[System.Windows.Forms.Padding]::new(0,0,5,0) } -OnClick {
        if ($script:cookieJar) { $script:cookieJar.Clear() }
        Refresh-Grid
    }
    $panelBtn.Controls.AddRange(@($btnClose, $btnClear))

    $btnExport = New-Button -Text "Export..." -Style 'Secondary' -Property @{ Width=80; Height=30; Margin=[System.Windows.Forms.Padding]::new(0,0,5,0) } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog -Property @{ Filter="JSON Files (*.json)|*.json"; FileName="cookies.json" }
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $script:cookieJar | ConvertTo-Json -Depth 5 | Set-Content -Path $sfd.FileName
                [System.Windows.Forms.MessageBox]::Show("Cookies exported successfully.", "Success", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to export cookies: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    }

    $btnImport = New-Button -Text "Import..." -Style 'Secondary' -Property @{ Width=80; Height=30; Margin=[System.Windows.Forms.Padding]::new(0,0,5,0) } -OnClick {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter="JSON Files (*.json)|*.json" }
        if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $importedCookies = Get-Content -Path $ofd.FileName -Raw | ConvertFrom-Json
                if ($importedCookies) {
                    if ($importedCookies -isnot [array]) { $importedCookies = @($importedCookies) }
                    $script:cookieJar.Clear()
                    foreach ($c in $importedCookies) {
                        try {
                            $cookie = New-Object System.Net.Cookie
                            $cookie.Name = $c.Name
                            $cookie.Value = $c.Value
                            $cookie.Domain = $c.Domain
                            $cookie.Path = if ($c.Path) { $c.Path } else { "/" }
                            if ($c.Expires) { 
                                if ($c.Expires -is [string]) { $cookie.Expires = [DateTime]::Parse($c.Expires) }
                                elseif ($c.Expires -is [DateTime]) { $cookie.Expires = $c.Expires }
                            }
                            $cookie.HttpOnly = if ($c.HttpOnly) { $c.HttpOnly } else { $false }
                            $cookie.Secure = if ($c.Secure) { $c.Secure } else { $false }
                            [void]$script:cookieJar.Add($cookie)
                        } catch {}
                    }
                    Refresh-Grid
                    [System.Windows.Forms.MessageBox]::Show("Cookies imported successfully.", "Success", "OK", "Information")
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to import cookies: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    }

    $panelBtn.Controls.AddRange(@($btnClose, $btnClear, $btnExport, $btnImport))

    $form.Controls.AddRange(@($grid, $panelBtn))
    $form.ShowDialog($parentForm)
}

# The main function that constructs and displays the primary application window.
function New-APIForm {

    $script:lastResponseContentType = $null # Store the content type of the last response
    $script:lastResponseText = ""
    $script:lastResponseHeadersText = ""
    $script:lastResponseHeadersNormalized = @{}
    $script:currentPowerShell = $null
    $script:currentAsyncResult = $null
    
    $script:isCollectionRunning = $false
    $script:collectionRunQueue = New-Object System.Collections.Queue
    $script:collectionRunnerForm = $null
    $script:collectionRunnerGrid = $null
    $script:collectionRunnerProgress = $null
    $script:collectionRunnerSummaryLabel = $null
    $script:collectionRunTotal = 0
    $script:collectionRunCompleted = 0
    $script:collectionRunDelay = 0
    $script:collectionRunStopOnFail = $false
    $script:collectionRunnerCurrentRow = $null
    $script:cookieJar = New-Object System.Collections.ArrayList

    # Create the single, persistent timer for polling request status.
    $script:requestTimer = New-Object System.Windows.Forms.Timer
    $script:requestTimer.Interval = 100 # Check every 100ms

    $script:requestTimer.Add_Tick({
        if ($script:currentAsyncResult -and $script:currentAsyncResult.IsCompleted) {
            $script:requestTimer.Stop()
            
            $jobResult = $null
            try {
                $output = $script:currentPowerShell.EndInvoke($script:currentAsyncResult)
                # Extract the result hashtable.
                $jobResult = $output | Where-Object { $_ -is [hashtable] -and $_.ContainsKey('Success') } | Select-Object -First 1
            } catch {
                 $jobResult = @{ Success = $false; ErrorMessage = "Runspace Error: $($_.Exception.Message)" }
                 $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#dc3545") # Red
            }

            # Check if it was stopped/cancelled (InvocationStateInfo might be Stopping/Stopped)
            if ($script:currentPowerShell.InvocationStateInfo.State -eq 'Stopped') {
                 $statusLabelStatus.Text = "Request Cancelled"
                 $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#ffc107") # Yellow/Orange
                 $richTextResponse.Text = "The request was cancelled by the user."
            }
            elseif ($jobResult) {
                if ($jobResult.Success) {
                    $res = $jobResult.Data
                    if ($script:isRepeating) { $script:repeatSuccessCount++ }
                    # Color code the status bar based on the response code
                    $statusCode = $res.StatusCode
                    if ($statusCode -ge 200 -and $statusCode -le 299) {
                        $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#28a745") # Green
                    }
                    elseif ($statusCode -ge 300 -and $statusCode -le 399) {
                        $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#ffc107") # Yellow
                    }
                    else { # 4xx, 5xx, etc.
                        $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#dc3545") # Red
                    }
                    $statusLabelStatus.Text = "$($res.StatusCode) $($res.StatusDescription)"
                    $statusLabelTime.Text = "Time: $($res.ElapsedTime) ms"
                    $statusLabelSize.Text = "Size: $(if ($res.RawContentLength -gt 0) { Format-Bytes -bytes $res.RawContentLength } else { (if ($res.Content) { Format-Bytes -bytes $res.Content.Length } else { '0 bytes' }) })"
                    Write-Log "Response: $($res.StatusCode) $($res.StatusDescription)"

                    $headersBuilder = New-Object System.Text.StringBuilder
                    foreach ($key in $res.Headers.Keys) { $headersBuilder.AppendLine("${key}: $($res.Headers[$key])") | Out-Null }
                    $responseHeadersText = $headersBuilder.ToString()
                    $richTextResponseHeaders.Text = $responseHeadersText
                    $script:lastResponseHeadersText = $responseHeadersText

                    # Normalize response headers to lowercase keys for consistent lookups.
                    $headersNormalized = @{}
                    foreach ($k in $res.Headers.Keys) { $headersNormalized[$k.ToLower()] = $res.Headers[$k] }
                    $script:lastResponseHeadersNormalized = $headersNormalized

                    $contentType = ""
                    $script:lastResponseContentType = $null # Reset content type
                    if ($headersNormalized.ContainsKey('content-type')) { $contentType = $headersNormalized['content-type'].Split(';')[0].Trim() }
                    $script:lastResponseContentType = $contentType

                    if ($script:settings.LogLevel -eq 'Debug') {
                        # Log Cookies
                        if ($jobResult.Cookies) {
                            $cookieLog = "Received Cookies:`r`n"
                            foreach ($c in $jobResult.Cookies) {
                                $cookieLog += "$($c.Name)=$($c.Value) (Domain: $($c.Domain))`r`n"
                            }
                            Write-Log $cookieLog
                        }

                        Write-Log "Response Headers:`r`n$responseHeadersText"
                        $shouldLogBody = $true
                        if ($contentType -match 'text|rtf|json|html|xml') { $shouldLogBody = $false }
                        if ($shouldLogBody -and $res.Content) {
                            $debugBody = [System.Text.Encoding]::UTF8.GetString($res.Content)
                            if ($debugBody.Length -gt 10000) { $debugBody = $debugBody.Substring(0, 10000) + "... (truncated)" }
                            Write-Log "Response Body:`r`n$debugBody"
                        }
                    }

                    # Update Cookie Jar
                    if ($jobResult.Cookies) {
                        foreach ($newCookie in $jobResult.Cookies) {
                            # Remove existing cookie with same name/domain/path
                            $existing = $null
                            foreach ($c in $script:cookieJar) {
                                if ($c.Name -eq $newCookie.Name -and $c.Domain -eq $newCookie.Domain -and $c.Path -eq $newCookie.Path) {
                                    $existing = $c
                                    break
                                }
                            }
                            if ($existing) { $script:cookieJar.Remove($existing) }
                            
                            # Add if not expired
                            if (-not $newCookie.Expired) {
                                [void]$script:cookieJar.Add($newCookie)
                            }
                        }
                    }

                    $isAttachmentHeader = $headersNormalized.ContainsKey('content-disposition') -and $headersNormalized['content-disposition'] -like 'attachment*'
                    
                    # Determine if the content is something we can render as text.
                    $isRenderable = $contentType -like 'text/*' -or 
                                    $contentType -like 'application/json*' -or 
                                    $contentType -like 'application/xml*' -or
                                    $contentType -like 'application/xml*' -or 
                                    $contentType -like 'application/rtf*' -or
                                    $contentType -like 'image/*' -or
                                    $contentType -like 'text/html*'

                    # Store the content type for the prettify button
                    $script:lastResponseContentType = $contentType
                    $script:btnExportResponse.Enabled = $isRenderable
                    $script:btnPrettifyResponse.Enabled = $isRenderable

                    $finalSavePath = $null

                    $isBinaryResponse = (-not $isRenderable -and $res.Content.Length -gt 0)
                    if ($isBinaryResponse -or $isAttachmentHeader) { # Check if we should try to save the file
                        if ($script:settings.AutoSaveToFile -and [System.IO.Directory]::Exists($script:settings.AutoSavePath)) { # Auto-save is enabled
                            # Auto-Save is enabled.
                            $targetFolder = $script:settings.AutoSavePath
                            $fileNameFromHeader = $null
                            if ($headersNormalized.ContainsKey('content-disposition') -and $headersNormalized['content-disposition'] -match 'filename="?([^"]+)"?') {
                                $fileNameFromHeader = $matches[1] # Extract filename from header
                            }
                            
                            if ($fileNameFromHeader) {
                                $outputFileName = $fileNameFromHeader # Start with filename from header
                                # Apply auto-rename logic if enabled.
                                if ($script:settings.AutoRenameFile) {
                                    # Find all keys in the form body that correspond to file uploads.
                                    $fileUploads = @($script:formBody.GetEnumerator() | Where-Object { $_.Value -is [hashtable] -and $_.Value.ContainsKey('_Path') })

                                    $prefix = if ($script:settings.EnableAutoRenamePrefix) { $script:settings.AutoRenamePrefix } else { "" }
                                    $ext = [System.IO.Path]::GetExtension($outputFileName)

                                    if ($fileUploads.Count -eq 1) {
                                        $file = $fileUploads[0].Value
                                        $name = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                                        $outputFileName = "$prefix$name$ext"
                                    } elseif ($fileUploads.Count -ge 2) {
                                        $file1 = $fileUploads[0].Value
                                        $file2 = $fileUploads[1].Value
                                        $name1 = [System.IO.Path]::GetFileNameWithoutExtension($file1.Name)
                                        $name2 = [System.IO.Path]::GetFileNameWithoutExtension($file2.Name)
                                        $outputFileName = "$prefix$name1 and $name2$ext"
                                    }
                                }
                                $finalSavePath = Join-Path -Path $targetFolder -ChildPath $outputFileName
                            } else {
                                $richTextResponse.Text = "Auto-save is enabled, but the server response did not include a 'filename' in the Content-Disposition header. Cannot save the file."
                            }
                        } elseif (-not [string]::IsNullOrWhiteSpace($script:textOutputFile.Text)) {
                            # Manual output file is specified.
                            $finalSavePath = $script:textOutputFile.Text
                        }
                    }
                    if ($finalSavePath) { # If a save path was determined, write the file
                        try {
                            $parentDir = [System.IO.Path]::GetDirectoryName($finalSavePath)
                            if (-not (Test-Path $parentDir)) { [System.IO.Directory]::CreateDirectory($parentDir) | Out-Null }
                            [System.IO.File]::WriteAllBytes($finalSavePath, $res.Content)
                            Write-Log "Saved file to $finalSavePath"
                            $uri = New-Object System.Uri $finalSavePath
                            $richTextResponse.Text = "Binary response successfully saved to:`n$($uri.AbsoluteUri)"
                            $script:lastResponseText = ""
                        } catch {
                            $richTextResponse.Text = "Error saving file to '$finalSavePath':`n$($_.Exception.Message)"
                            Write-Log "Error saving file: $($_.Exception.Message)" -Level Info
                            $script:lastResponseText = ""
                        }
                    } elseif ($isRenderable -or $res.Content.Length -eq 0) { # If not saving, try to render it
                        $responseContent = if ($res.Content) { [System.Text.Encoding]::UTF8.GetString($res.Content) } else { "" }
                        $script:lastResponseText = $responseContent
                        $tabControlResponse.TabPages.Remove($tabPreview) # Remove preview tab by default
                        $webBrowserPreview.Visible = $false
                        $pictureBoxPreview.Visible = $false

                        try {
                        if ($contentType -like 'application/rtf*') {
                            $richTextResponse.Rtf = $responseContent
                            Write-Log "Rendering response as RTF."
                        } elseif ($contentType -like 'application/json*') {
                            $jsonObj = $responseContent | ConvertFrom-Json # Validate JSON
                            Populate-JsonTree -JsonData $jsonObj -NodesCollection $treeViewJson.Nodes
                            $richTextResponse.Rtf = Format-JsonAsRtf -JsonString $responseContent -FontSize $script:settings.ResponseFontSize
                            Write-Log "Rendering response as formatted JSON."
                        } elseif ($contentType -like 'application/xml*' -or $contentType -like 'text/xml*') {
                        # Check if the JSON is a redline document
                        if ($jsonBodyForTest -and $jsonBodyForTest._type -eq 'redlinedocument') {
                            $richTextResponse.Rtf = Format-RedlineAsRtf -RedlineJson $jsonBodyForTest -FontSize $script:settings.ResponseFontSize
                            Write-Log "Rendering response as a formatted Redline Document."
                        }
                            $richTextResponse.Text = ([xml]$responseContent).OuterXml # Format XML
                            Write-Log "Rendering response as formatted XML."
                        } elseif ($contentType -like 'text/html*') {
                                $webBrowserPreview.Visible = $true
                                $webBrowserPreview.DocumentText = $responseContent
                                $tabControlResponse.TabPages.Add($tabPreview) # Add preview tab
                                $richTextResponse.Text = $responseContent # Also show raw text
                                Write-Log "Rendering response as HTML."
                            } elseif ($contentType -like 'image/*') {
                                $ms = New-Object System.IO.MemoryStream(,$res.Content)
                                $pictureBoxPreview.Image = [System.Drawing.Image]::FromStream($ms)
                                $pictureBoxPreview.Visible = $true
                                $tabControlResponse.TabPages.Add($tabPreview)
                                $richTextResponse.Text = "[Binary Image Data: $contentType]"
                                Write-Log "Rendering response as Image."
                            } else {
                                # Fallback for other text-based types
                                $richTextResponse.Text = $responseContent
                            }
                        }
                        catch { 
                            $richTextResponse.Text = $responseContent 
                            Write-Log "Failed to render rich content, showing as plain text."
                        }
                        # Execute user-defined tests against the response.
                        if (-not [string]::IsNullOrWhiteSpace($testsRaw)) {
                            $script:testResults.Clear()
                            $testScriptBlock = [scriptblock]::Create($testsRaw)

                            $jsonBodyForTest = $null
                            try {
                                if (-not $finalSavePath) {
                                    $jsonBodyForTest = [System.Text.Encoding]::UTF8.GetString($res.Content) | ConvertFrom-Json -ErrorAction Stop
                                }
                            } catch {
                                # If JSON parsing fails, $jsonBodyForTest will remain $null.
                            }

                            $testScopeVars = @{
                                statusCode = $res.StatusCode
                                headers    = $res.Headers
                                body       = if ($finalSavePath) { "[Binary content saved to file]" } else { [System.Text.Encoding]::UTF8.GetString($res.Content) }
                                jsonBody   = $jsonBodyForTest
                            }

                            try {
                            # Define the functions within the scope of the Invoke-Command
                            $fullTestScript = @"
                            $(Get-Command Assert-Equal | Select-Object -ExpandProperty Definition)
                            $(Get-Command Assert-Contains | Select-Object -ExpandProperty Definition)
                            $(Get-Command Assert-StatusIs | Select-Object -ExpandProperty Definition)
                            $testsRaw
"@
                            Invoke-Command -ScriptBlock ([scriptblock]::Create($fullTestScript)) -ArgumentList $testScopeVars -NoNewScope -ErrorAction Stop
                            } catch {
                                $script:testResults.Add([PSCustomObject]@{ Status = 'ERROR'; Message = "Test script failed to execute: $($_.Exception.Message)"}) | Out-Null
                            }

                            $richTextTestResults.Rtf = Format-TestResultsAsRtf -Results $script:testResults -FontSize $script:settings.ResponseFontSize
                            $tabControlResponse.SelectedTab = $tabTestResults
                        }
                    } else { # This is now the case for unrenderable binary content with no save path
                        $richTextResponse.Text = "Cannot render binary response in the UI.`n`nContent-Type: $contentType`nSize: $(Format-Bytes -bytes $res.Content.Length)`n`nTo save this response, specify an 'Output File' or enable 'Auto-Save' and send the request again."
                        $script:lastResponseText = ""
                    }
                }
                elseif ($jobResult) { # This handles the case where the job did not succeed
                    # Job failed but we might still have error data
                    if ($script:isRepeating) { $script:repeatFailCount++ }
                    $res = $jobResult.Data
                    if ($res -and $res.errorBody) {
                        $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#dc3545") # Red
                        $statusLabelStatus.Text = "Request Failed"
                        $statusLabelTime.Text = "Time: $($res.ElapsedTime) ms" # Display elapsed time even on error
                        $statusLabelSize.Text = "Size: N/A"
                        try {
                            $null = $res.errorBody | ConvertFrom-Json
                            $richTextResponse.Rtf = Format-JsonAsRtf -JsonString $res.errorBody -FontSize $script:settings.ResponseFontSize
                        } catch {
                            $richTextResponse.Text = $res.errorBody
                        }
                        $script:lastResponseText = $res.errorBody
                    } else {
                        $statusStrip.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#dc3545") # Red
                        $statusLabelStatus.Text = "Request Failed"
                        $richTextResponse.Text = $jobResult.ErrorMessage # Display generic job error message
                        $script:lastResponseText = $jobResult.ErrorMessage
                    }
                }

            }
            
            # Cleanup Runspace
            if ($script:currentPowerShell) { $script:currentPowerShell.Dispose() }
            $script:currentPowerShell = $null
            $script:currentAsyncResult = $null
            
            # --- Collection Runner Logic ---
            if ($script:isCollectionRunning) {
                $script:collectionRunCompleted++
                if ($script:collectionRunnerProgress) { $script:collectionRunnerProgress.Value = $script:collectionRunCompleted }
                if ($script:collectionRunnerSummaryLabel) { $script:collectionRunnerSummaryLabel.Text = "Progress: $($script:collectionRunCompleted)/$($script:collectionRunTotal)" }

                # Update Grid Status
                if ($script:collectionRunnerCurrentRow) {
                    $row = $script:collectionRunnerCurrentRow
                    if ($jobResult.Success) {
                        $row.Cells["Status"].Value = "PASS"
                        $row.Cells["Result"].Value = "$($jobResult.Data.StatusCode) $($jobResult.Data.StatusDescription)"
                        $row.Cells["Time"].Value = $jobResult.Data.ElapsedTime
                        $row.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#d4edda")
                    } else {
                        $row.Cells["Status"].Value = "FAIL"
                        $row.Cells["Result"].Value = if ($jobResult.Data) { "$($jobResult.Data.StatusCode) $($jobResult.Data.StatusDescription)" } else { $jobResult.ErrorMessage }
                        $row.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#f8d7da")
                    }
                    # Test Summary
                    if ($script:testResults) {
                        $passCount = ($script:testResults | Where-Object { $_.Status -eq 'PASS' }).Count
                        $failCount = ($script:testResults | Where-Object { $_.Status -ne 'PASS' }).Count
                        $row.Cells["Tests"].Value = "$passCount passed, $failCount failed"
                    }
                }

                # Stop on Failure Check
                $isFailure = (-not $jobResult.Success) -or ($jobResult.Data.StatusCode -ge 400)
                if ($script:collectionRunStopOnFail -and $isFailure) {
                    $script:isCollectionRunning = $false
                    if ($script:collectionRunnerSummaryLabel) { $script:collectionRunnerSummaryLabel.Text = "Stopped due to failure." }
                    if ($script:collectionRunnerForm) { $script:collectionRunnerForm.Tag.btnStart.Enabled = $true; $script:collectionRunnerForm.Tag.btnStart.Text = "Start Run" }
                    return
                }

                if ($script:collectionRunQueue.Count -gt 0) {
                    $nextRow = $script:collectionRunQueue.Dequeue()
                    $script:collectionRunnerCurrentRow = $nextRow
                    $nextRow.Cells["Status"].Value = "Running..."
                    
                    # Delay Logic
                    $delay = [Math]::Max(50, $script:collectionRunDelay)
                    $delayTimer = New-Object System.Windows.Forms.Timer
                    $delayTimer.Interval = $delay
                    $delayTimer.Add_Tick({
                        param($s, $ev)
                        $s.Stop(); $s.Dispose()
                        Load-Request-From-Object -RequestObject $nextRow.Tag.RequestData
                        Invoke-RequestExecution
                    })
                    $delayTimer.Start()
                    return # Exit tick to wait for delay
                } else {
                    $script:isCollectionRunning = $false
                    if ($script:collectionRunnerSummaryLabel) { $script:collectionRunnerSummaryLabel.Text = "Run Complete." }
                    if ($script:collectionRunnerForm) { $script:collectionRunnerForm.Tag.btnStart.Enabled = $true; $script:collectionRunnerForm.Tag.btnStart.Text = "Start Run" }
                }
            }

            # Handle repeat requests *after* cleaning up the completed runspace.
            if ($script:isRepeating -eq $true) {
                $script:currentRepeatIteration++
                if ($script:currentRepeatIteration -lt $script:repeatCount) {
                    Write-Log "Repeat Request: Iteration $($script:currentRepeatIteration) of $($script:repeatCount) completed. Sending next request..." -Level Debug
                    $statusLabelStatus.Text = "Repeating Request ($($script:currentRepeatIteration + 1)/$($script:repeatCount))... (Success: $($script:repeatSuccessCount), Fail: $($script:repeatFailCount))"
                    
                    $repeatDelayTimer = New-Object System.Windows.Forms.Timer
                    $repeatDelayTimer.Interval = 200 # A small delay to allow UI to update
                    $repeatDelayBlock = { 
                        param($sender, $e) # Use param block to get the timer object that fired the event
                        Invoke-RequestExecution # Call the core logic directly, bypassing the button click
                        $sender.Stop() # Stop and dispose the timer using the sender parameter
                        $sender.Dispose()
                    }
                    $repeatDelayTimer.Add_Tick($repeatDelayBlock)
                    $repeatDelayTimer.Start()
                    return # Exit the main timer tick; the delay timer will fire the next request.
                } else {
                    # All repeats are done
                    $finalStatus = "Repeat Request Completed ($($script:repeatCount) iterations). Success: $($script:repeatSuccessCount), Fail: $($script:repeatFailCount)."
                    Write-Log $finalStatus -Level Info
                    $statusLabelStatus.Text = $finalStatus
                    $script:isRepeating = $false
                }
            }
            
            # This code runs if not repeating, or if the last repeat has just finished.
            if (-not $script:isCollectionRunning) {
                $btnSubmit.Enabled = $true; $btnSubmit.BackColor = $script:Theme.PrimaryButton
                $btnCancel.Enabled = $false
                $btnRepeat.Enabled = $true
            }
        }
    })

# This function contains the core logic for preparing and executing an API request.
# It's separated from the UI button's click event to allow for programmatic re-triggering (e.g., for repeating requests).
function Invoke-RequestExecution {
    # Clear previous response and test results.
    $richTextResponse.Text = ""
    $richTextResponseHeaders.Text = ""
    $richTextCode.Text = ""
    $treeViewJson.Nodes.Clear()
    $script:btnExportResponse.Enabled = $false # Disable export button for new request
    $script:btnPrettifyResponse.Enabled = $false # Disable prettify button for new request
    $richTextTestResults.Text = ""
    $script:lastResponseText = ""
    $script:lastResponseHeadersText = ""
    $script:lastResponseHeadersNormalized = @{}

    # Reset the status bar for the new request.
    if (-not $script:isCollectionRunning) {
        $statusStrip.BackColor = $script:Theme.PrimaryButton
    }
    $statusLabelStatus.Text = "Sending request..."
    $statusLabelTime.Text = "Time: ..."
    $statusLabelSize.Text = "Size: ..."
    $form.Refresh() # Force UI update
    Write-Log "Request execution started."
    
    # Substitute environment variables into all relevant fields.
    $script:activeEnvironment = $script:comboEnvironment.SelectedItem

    # --- Pre-request Script Execution ---
    if (-not [string]::IsNullOrWhiteSpace($script:textPreRequest.Text)) {
        try {
            Write-Log "Executing Pre-request script..."
            if ($script:activeEnvironment -ne "No Environment" -and $script:environments.ContainsKey($script:activeEnvironment)) {
                $Environment = $script:environments[$script:activeEnvironment]
            } else { $Environment = @{} }
            
            Invoke-Command -ScriptBlock ([scriptblock]::Create($script:textPreRequest.Text)) -NoNewScope
            Write-Log "Pre-request script executed successfully."
        } catch {
            Write-Log "Pre-request script failed: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show("Pre-request script failed:`n$($_.Exception.Message)", "Error", "OK", "Error")
            # Re-enable buttons on script failure
            $btnSubmit.Enabled = $true; $btnCancel.Enabled = $false; $btnRepeat.Enabled = $true; return
        }
    }

    $method = (Substitute-Variables -InputString $script:comboMethod.SelectedItem.ToString())
    $url = (Substitute-Variables -InputString $script:textUrl.Text)
    $headersRaw = (Substitute-Variables -InputString $script:textHeaders.Text)
    $bodyRaw = (Substitute-Variables -InputString $script:textBody.Text)
    $testsRaw = $script:textTests.Text

    # --- GraphQL Logic ---
    if ($script:comboBodyType.SelectedItem -eq "GraphQL") {
        $gqlQuery = (Substitute-Variables -InputString $script:txtGqlQuery.Text)
        $gqlVars = (Substitute-Variables -InputString $script:txtGqlVars.Text)
        $payload = @{ query = $gqlQuery }
        if (-not [string]::IsNullOrWhiteSpace($gqlVars)) {
            try { $payload['variables'] = $gqlVars | ConvertFrom-Json } catch { Write-Log "Invalid GraphQL Variables JSON" }
        }
        $bodyRaw = $payload | ConvertTo-Json -Depth 10
        $bodyType = "application/json" # Send as JSON
        $method = "POST" # GraphQL is typically POST
    }

    $outputFormat = $script:textOutputFormat.Text
    if ($script:comboBodyType.SelectedItem -ne "GraphQL") { $bodyType = $script:comboBodyType.SelectedItem.ToString() }
    # Determine the correct output path based on whether Auto-Save is enabled.
    if ($script:settings.AutoSaveToFile) {
        $outputFile = $script:settings.AutoSavePath # Use the path from settings
    } else {
        $outputFile = $script:activeRequestTab.TextOutputFile.Text # Use the path from the visible text box
    }
    
    $includeFilename = $checkIncludeFilename.Checked
    $includeContentType = $checkIncludeContentType.Checked
    
    $ignoreSsl = $script:settings.IgnoreSslErrors
    $timeoutSeconds = $script:settings.RequestTimeoutSeconds
    
    # Store request state for code generation
    $script:lastRequestState = [PSCustomObject]@{
        Method = $method
        Url = $url
        Headers = $headersRaw
        Body = $bodyRaw
        BodyType = $bodyType
    }

    Write-Log "URL: $url"
    Write-Log "Headers: $headersRaw"
    Write-Log "Method: $method"
    Write-Log "Request Body: $bodyRaw" -Level Info
    Write-Log "Output Format: $outputFormat"

    if ($outputFile) {
        if ($script:settings.AutoSaveToFile) { Write-Log "Auto-Save Folder specified: $outputFile" }
        else { Write-Log "Output File specified: $outputFile" }
    }

    if (-not $url) {
    Write-Log "URL is empty. Showing message box."
    [System.Windows.Forms.MessageBox]::Show("Please enter a valid URL.")
    return
    }

    # Only add to history on the first request of a repeat sequence, or for a normal request.
    if ($script:settings.EnableHistory -and -not $script:isRepeating -and -not $script:isCollectionRunning) {
        # Create and save a history entry for the current request.
        $historyEntry = [PSCustomObject]@{
            Timestamp = Get-Date
            Method    = $method
            Url       = $url
            Headers   = $headersRaw
            Body      = $bodyRaw
            BodyType  = $bodyType
            OutputFormat = $outputFormat
            Tests     = $testsRaw
            PreRequestScript = $script:textPreRequest.Text
            Environment = $script:comboEnvironment.SelectedItem
            Authentication = (& $script:authPanel.GetAuthData) # Use the helper to get auth data
        }
        $script:history = @($historyEntry) + $script:history
        if ($script:history.Count -gt 50) { $script:history = $script:history[0..49] }
        
        $listHistory.Items.Insert(0, "$($historyEntry.Timestamp.ToString('HH:mm:ss')) | $($historyEntry.Method) | $($historyEntry.Url)")
        if ($listHistory.Items.Count -gt 50) { $listHistory.Items.RemoveAt(50) }

        Save-History
    }

    # Parse user-provided headers from the textbox into a hashtable.
    $headers = @{}
    foreach ($line in $headersRaw -split "`n") {
    if ($line -match "^\s*(.+?):\s*(.+)$") {
        $headers[$matches[1]] = $matches[2]
    }
    }

    # Apply authentication details to the request headers or URL.
    $authHeader = $null
    $currentAuth = & $script:authPanel.GetAuthData
    switch ($currentAuth.Type) {
        "Auth2" {
            # Pre-flight check for token expiry
            $tokenIsExpired = $false
            if ($currentAuth.TokenExpiryTimestamp) {
                try {
                    $expiryTime = [datetime]$currentAuth.TokenExpiryTimestamp
                    if ([DateTime]::UtcNow -ge $expiryTime) {
                        $tokenIsExpired = $true
                    }
                } catch {
                    Write-Log "Could not parse Auth2 TokenExpiryTimestamp: $($currentAuth.TokenExpiryTimestamp)" -Level Info
                }
            }

            if ($tokenIsExpired -and -not [string]::IsNullOrWhiteSpace($currentAuth.RefreshToken)) {
                Write-Log "Auth2 access token expired. Attempting to refresh..." -Level Info
                try {
                    $refreshBody = @{
                        grant_type    = 'refresh_token'
                        refresh_token = $currentAuth.RefreshToken
                        client_id     = $currentAuth.ClientId
                        client_secret = $currentAuth.ClientSecret # Some providers require this
                    }
                    $tokenResponse = Invoke-RestMethod -Uri $currentAuth.TokenEndpoint -Method Post -Body $refreshBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                    
                    # Update UI and current auth data with the new token
                    $currentAuth.AccessToken = $tokenResponse.access_token
                    $script:authPanel.TextAuth2AccessToken.Text = $tokenResponse.access_token
                    
                    if ($tokenResponse.PSObject.Properties.Name -contains 'refresh_token') {
                        $currentAuth.RefreshToken = $tokenResponse.refresh_token
                        $script:authPanel.TextAuth2RefreshToken.Text = $tokenResponse.refresh_token
                    }
                    
                    $currentAuth.TokenExpiryTimestamp = ([DateTime]::UtcNow).AddSeconds([int]$tokenResponse.expires_in)
                    $script:authPanel.TextAuth2AccessToken.Tag = $currentAuth.TokenExpiryTimestamp
                    
                    Write-Log "Auth2 token successfully refreshed." -Level Info
                } catch {
                    [System.Windows.Forms.MessageBox]::Show("Failed to automatically refresh access token. Please get a new token manually.`n`nError: $($_.Exception.Message)", "Token Refresh Failed", "OK", "Error")
                    # Stop the request by re-enabling the submit button and returning
                  $btnSubmit.Enabled = $true; $btnCancel.Enabled = $false; $btnRepeat.Enabled = $true; return
                }
            }
        }
        "API Key" {
            if (-not ([string]::IsNullOrWhiteSpace($currentAuth.Key) -or [string]::IsNullOrWhiteSpace($currentAuth.Value))) {
                if ($currentAuth.AddTo -eq "Header") {
                    $headers[$currentAuth.Key] = $currentAuth.Value
                } else { # Query Params
                    $separator = if ($url -like '*?*') { '&' } else { '?' }
                    $url += "$separator$([uri]::EscapeDataString($currentAuth.Key))=$([uri]::EscapeDataString($currentAuth.Value))"
                }
            }
        }
        "Bearer Token" {
            if (-not [string]::IsNullOrWhiteSpace($currentAuth.Token)) { # Only add if token is not empty
                $authHeader = "Bearer $($currentAuth.Token)"
            }
        }
        "Basic Auth" {
            if (-not ([string]::IsNullOrWhiteSpace($currentAuth.Username))) { # Only add if username is not empty
                $credentials = [System.Text.Encoding]::UTF8.GetBytes("$($currentAuth.Username):$($currentAuth.Password)")
                $authHeader = "Basic $([System.Convert]::ToBase64String($credentials))"
            }
        }
    } # End of switch ($currentAuth.Type)
    
    # Client Certificate Logic (Prepare data for job)
    $clientCertData = $null
    if ($currentAuth.Type -eq "Client Certificate") {
        $clientCertData = @{
            Source = $currentAuth.Source
            Path = $currentAuth.Path
            Password = $currentAuth.Password
            Thumbprint = $currentAuth.Thumbprint
        }
    }

    if ($authHeader) { $headers["Authorization"] = $authHeader }
    
    # Construct the request body
    $script:formBody = @{}
    $script:formBody.Clear() # Clear any data from a previous request
    if ($bodyType -eq "multipart/form-data") {
        Write-Log "Parsing Body as multipart/form-data..."
        foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) { # Process non-empty lines
            if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                $key = $matches[1].Trim()
                $filePath = if ($matches[3]) { $matches[3] } else { $matches[4] } # Correctly get path if quoted (group 3) or not (group 4)
                $attributesRaw = $matches[5]

                if (Test-Path $filePath) {
                    # Pass a simple hashtable with path/name/metadata so it serializes safely across Start-Job.
                    $fileObject = @{
                        _Path = $filePath
                        Name  = ([System.IO.Path]::GetFileName($filePath))
                        IncludeFilename = $false # Default to false, check attributes
                        IncludeContentType = $false # Default to false, check attributes
                    }
                    if ($attributesRaw -match 'filename=([^;`\r`n]+)') {
                        $fileObject.Name = $matches[1].Trim() # Override filename from attribute
                        $fileObject.IncludeFilename = $true
                    }
                    if ($attributesRaw -match 'type=([^;`\r`n]+)') {
                        $fileObject.ContentType = $matches[1].Trim() # Override content type from attribute
                        $fileObject.IncludeContentType = $true
                    }
                    # If the global checkbox is checked but no type attribute was specified, get it now.
                    if ($includeContentType -and -not $fileObject.ContainsKey('ContentType')) {
                        $fileObject.ContentType = Get-MimeType -filePath $filePath
                    }
                    
                    $script:formBody[$key] = $fileObject
                    Write-Log "Adding file to form: '$filePath' as key '$key'"
                } else {
                    Write-Log "File not found, skipping: '$filePath'"
                }
            } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') { # Regular key-value (allow empty values)
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                $script:formBody[$key] = $value
                Write-Log "Adding form value: '$key' = '$value'"
            }
        }
        if ($outputFormat) { $script:formBody["outputFormat"] = $outputFormat }
    }

    # Generate Code Snippet
    $selectedLang = if ($script:comboCodeLanguage.SelectedItem) { $script:comboCodeLanguage.SelectedItem } else { "cURL" }
    $richTextCode.Text = Generate-CodeSnippet -RequestItem $script:lastRequestState -Language $selectedLang

    if ($script:settings.LogLevel -eq 'Debug') {
        $debugCurl = Generate-CodeSnippet -RequestItem $script:lastRequestState -Language "cURL"
        Write-Log "Generated cURL:`r`n$debugCurl"
    }

    # --- Build multipart body bytes on the main thread to avoid Start-Job serialization issues ---
    $multipartBytes = $null # Initialize
    $multipartContentType = $null # Initialize
    if ($bodyType -eq "multipart/form-data") {
        $boundary = "---------------------------" + [System.Guid]::NewGuid().ToString("N")
        $encoding = [System.Text.Encoding]::GetEncoding("iso-8859-1")
        function Write-To-StreamLocal { param([System.IO.MemoryStream]$s, [string]$t) $b = $encoding.GetBytes($t); $s.Write($b,0,$b.Length) }
        $ms = New-Object System.IO.MemoryStream
        foreach ($key in $script:formBody.Keys) {
            $val = $script:formBody[$key]
            Write-To-StreamLocal -s $ms -t "--$boundary`r`n"
            if ($val -is [hashtable] -and $val.ContainsKey('_Path')) {
                $fp = $val._Path
                $fn = if ($val.ContainsKey('Name')) { $val.Name } else { [System.IO.Path]::GetFileName($fp) }
                $ctype = if ($val.ContainsKey('ContentType')) { $val.ContentType } else { 'application/octet-stream' }
                $disp = "Content-Disposition: form-data; name=`"$key`"; filename=`"$fn`"`r`n"
                Write-To-StreamLocal -s $ms -t $disp
                Write-To-StreamLocal -s $ms -t "Content-Type: $ctype`r`n`r`n"
                $fb = [System.IO.File]::ReadAllBytes($fp)
                $ms.Write($fb,0,$fb.Length)
                Write-To-StreamLocal -s $ms -t "`r`n"
            } else {
                $field = [string]$val
                Write-To-StreamLocal -s $ms -t "Content-Disposition: form-data; name=`"$key`"`r`n`r`n$field`r`n"
            }
        } # End of foreach ($key in $script:formBody.Keys)
        Write-To-StreamLocal -s $ms -t "--$boundary--`r`n"
        $ms.Seek(0,'Begin') | Out-Null
        $multipartBytes = $ms.ToArray()
        $multipartContentType = "multipart/form-data; boundary=$boundary"
        $ms.Close()
    }

    # Prepare Cookies for Job
    $inputCookies = @()
    if ($script:cookieJar.Count -gt 0) {
        $uri = New-Object System.Uri($url)
        foreach ($c in $script:cookieJar) {
            # Simple domain matching
            if ($uri.Host.EndsWith($c.Domain.TrimStart('.')) -or $c.Domain.TrimStart('.') -eq $uri.Host) {
                $inputCookies += $c
            }
        }
    }
    $proxySettings = @{ Mode=$script:settings.ProxyMode; Address=$script:settings.ProxyAddress; Port=$script:settings.ProxyPort; User=$script:settings.ProxyUser; Pass=$script:settings.ProxyPass }
    
    # This script block is executed in a background job to keep the UI responsive.
    $scriptBlock = { #region Start-Job ScriptBlock 
        param($url, $method, $headers, $bodyRaw, $bodyType, $formBody, $outputFile, $includeFilename, $includeContentType, $outputFormat, $multipartBytes, $multipartContentType, $ignoreSsl, $timeoutSeconds, $proxySettings, $clientCertData, $inputCookies)

        function Format-Bytes {
            param([long]$bytes)
            if ($bytes -lt 0) { return "N/A" }
            $units = @("B", "KB", "MB", "GB", "TB")
            $i = 0
            $size = [double]$bytes
            while ($size -ge 1024 -and $i -lt ($units.Length - 1)) {
                $size /= 1024
                $i++
            }
            return "{0:N2} {1}" -f $size, $units[$i]
        }
        $result = @{ Success = $false; Data = $null; ErrorMessage = "" }
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            function Job-Log { param([string]$Message) Write-Verbose "JOB: $Message" } # Use Verbose to avoid polluting output
            Job-Log "Starting request to $url"

            if ($ignoreSsl) {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }

            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Method = $method
            $req.Timeout = $timeoutSeconds * 1000
            
            # Proxy Configuration
            if ($proxySettings.Mode -eq 'Custom') {
                $proxy = New-Object System.Net.WebProxy($proxySettings.Address, $proxySettings.Port)
                if ($proxySettings.User) {
                    $proxy.Credentials = New-Object System.Net.NetworkCredential($proxySettings.User, $proxySettings.Pass)
                }
                $req.Proxy = $proxy
            } elseif ($proxySettings.Mode -eq 'None') {
                $req.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
            } else {
                $req.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
                $req.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            }

            # Client Certificates
            if ($clientCertData) {
                if ($clientCertData.Source -eq "PFX File" -and (Test-Path $clientCertData.Path)) {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($clientCertData.Path, $clientCertData.Password)
                    [void]$req.ClientCertificates.Add($cert)
                } elseif ($clientCertData.Source -eq "User Store") {
                    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
                    $store.Open("ReadOnly")
                    $certs = $store.Certificates.Find("FindByThumbprint", $clientCertData.Thumbprint, $false)
                    if ($certs.Count -gt 0) { [void]$req.ClientCertificates.Add($certs[0]) }
                    $store.Close()
                }
            }

            # Cookies
            $req.CookieContainer = New-Object System.Net.CookieContainer
            if ($inputCookies) {
                foreach ($c in $inputCookies) {
                    # Reconstruct cookie to ensure it attaches to container
                    $req.CookieContainer.Add($c)
                }
            }

            foreach ($key in $headers.Keys) { 
                if ($key -ne 'Content-Type') { # Content-Type is set automatically for body, avoid double-setting
                    $req.Headers.Add($key, $headers[$key]) 
                }
            }

            # Only attempt to write a request body for methods that support it.
            if ($method -in @('POST', 'PUT', 'PATCH')) {
                if ($bodyType -eq "multipart/form-data" -and $multipartBytes) {
                    $req.ContentType = $multipartContentType
                    $req.ContentLength = $multipartBytes.Length
                    Job-Log "Writing prebuilt multipart body, $($multipartBytes.Length) bytes"
                    $rs = $req.GetRequestStream()
                    $rs.Write($multipartBytes, 0, $multipartBytes.Length)
                    $rs.Close()
                } elseif ($bodyType -eq "multipart/form-data") {
                    Job-Log "Multipart Form-Data Logic: No bytes"
                } else {
                    if (-not [string]::IsNullOrEmpty($bodyRaw)) {
                        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyRaw)
                        $req.ContentLength = $bodyBytes.Length
                        $req.ContentType = if ($headers.ContainsKey('Content-Type')) { $headers['Content-Type'] } else { $bodyType }
                        Job-Log "Request ContentLength (raw) = $($req.ContentLength) bytes"
                        $requestStream = $req.GetRequestStream()
                        $requestStream.Write($bodyBytes, 0, $bodyBytes.Length)
                        $requestStream.Close()
                    }
                } # End of if (-not [string]::IsNullOrEmpty($bodyRaw))
            } # End of body-writing logic

            $response = $req.GetResponse()
            $stopwatch.Stop()

            $responseStream = $response.GetResponseStream()
            $memStream = New-Object System.IO.MemoryStream
            $responseStream.CopyTo($memStream)
            $responseBytes = $memStream.ToArray()
            $responseStream.Close()
            $memStream.Close()
            $responseHeaders = @{}
            foreach ($key in $response.Headers.AllKeys) { $responseHeaders[$key] = $response.Headers[$key] }
            
            $resCookies = $req.CookieContainer.GetCookies($req.RequestUri)
            $result.Success = $true
            $result.Data = @{
                StatusCode        = [int]$response.StatusCode
                StatusDescription = $response.StatusDescription
                ElapsedTime       = $stopwatch.ElapsedMilliseconds
                Headers           = $responseHeaders
                Content           = $responseBytes
                Cookies           = $resCookies
                RawContentLength  = $response.ContentLength
            }
        } # End of try
        catch {
            $stopwatch.Stop()
            $result.ErrorMessage = $_.Exception.Message
            if ($_.Exception.Response) {
                $errorBody = ""
                if ($errorStream = $_.Exception.Response.GetResponseStream()) {
                    $reader = New-Object System.IO.StreamReader($errorStream)
                    $errorBody = $reader.ReadToEnd()
                    $reader.Close()
                    $errorStream.Close()
                }
                $result.Data = @{
                    StatusCode        = [int]$_.Exception.Response.StatusCode
                    StatusDescription = $_.Exception.Response.StatusDescription
                    ElapsedTime       = $stopwatch.ElapsedMilliseconds
                    errorBody         = $errorBody
                }
            } else {
                $result.Data = @{ ElapsedTime = $stopwatch.ElapsedMilliseconds }
            }
        } # End of catch
        return $result
    } #endregion

    # Use Runspace (PowerShell instance) instead of Start-Job for better performance
    if ($script:currentPowerShell) { $script:currentPowerShell.Dispose(); $script:currentPowerShell = $null }
    $script:currentPowerShell = [PowerShell]::Create()
    $script:currentPowerShell.AddScript($scriptBlock).AddArgument($url).AddArgument($method).AddArgument($headers).AddArgument($bodyRaw).AddArgument($bodyType).AddArgument($formBody).AddArgument($outputFile).AddArgument($includeFilename).AddArgument($includeContentType).AddArgument($outputFormat).AddArgument($multipartBytes).AddArgument($multipartContentType).AddArgument($ignoreSsl).AddArgument($timeoutSeconds).AddArgument($proxySettings).AddArgument($clientCertData).AddArgument($inputCookies) | Out-Null
    
    $script:currentAsyncResult = $script:currentPowerShell.BeginInvoke()

    $script:requestTimer.Start()
}

    # --- Collection Runner Window ---
    function Show-CollectionRunnerWindow {
        param(
            [PSCustomObject]$Item,
            [System.Windows.Forms.Form]$parentForm
        )

        $runnerForm = New-Object System.Windows.Forms.Form -Property @{
            Text          = "Collection Runner: $($Item.Name)"
            Size          = New-Object System.Drawing.Size(900, 700)
            StartPosition = "CenterParent"
            BackColor     = $script:Theme.FormBackground
        }

        # --- Layout ---
        $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
            Dock        = 'Fill'
            ColumnCount = 1
            RowCount    = 3
            Padding     = [System.Windows.Forms.Padding]::new(10)
        }
        $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
        $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
        $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

        # --- Top Panel (Summary & Progress) ---
        $topPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; AutoSize = $true; ColumnCount = 2; RowCount = 2 }
        $topPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
        $topPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

        $summaryLabel = New-Label -Text "Ready to run." -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Segoe UI", 10); TextAlign = 'MiddleLeft' }
        $progress = New-Object System.Windows.Forms.ProgressBar -Property @{ Dock = 'Fill'; Margin = [System.Windows.Forms.Padding]::new(0, 5, 0, 5) }
        
        # Settings Panel
        $settingsPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; AutoSize = $true; FlowDirection = 'LeftToRight'; WrapContents = $false }
        $lblDelay = New-Label -Text "Delay (ms):" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 5, 5, 0) }
        $numDelay = New-Object System.Windows.Forms.NumericUpDown -Property @{ Minimum = 0; Maximum = 60000; Value = 0; Width = 60 }
        if ($script:settings.CollectionRunnerDelay) { $numDelay.Value = $script:settings.CollectionRunnerDelay }
        $chkStopOnFail = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Stop on Failure"; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(15, 3, 0, 0) }
        if ($script:settings.CollectionRunnerStopOnFail) { $chkStopOnFail.Checked = $script:settings.CollectionRunnerStopOnFail }
        $chkSelectAll = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Select All"; Checked = $true; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(15, 3, 0, 0) }
        
        $settingsPanel.Controls.AddRange(@($lblDelay, $numDelay, $chkStopOnFail, $chkSelectAll))

        $topPanel.Controls.Add($summaryLabel, 0, 0)
        $topPanel.Controls.Add($settingsPanel, 1, 0)
        $topPanel.Controls.Add($progress, 0, 1); $topPanel.SetColumnSpan($progress, 2)

        # --- Grid ---
        $grid = New-Object System.Windows.Forms.DataGridView -Property @{
            Dock               = 'Fill'
            ReadOnly           = $true
            AllowUserToAddRows = $false
            RowHeadersVisible  = $false
            SelectionMode      = 'FullRowSelect'
            BackgroundColor    = $script:Theme.GroupBackground
            BorderStyle        = 'None'
        }
        $colCheck = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
        $colCheck.HeaderText = ""
        $colCheck.Name = "Run"
        $colCheck.Width = 30
        $grid.Columns.Add($colCheck) | Out-Null
        
        $grid.Columns.Add("Name", "Request") | Out-Null
        $grid.Columns.Add("Status", "Status") | Out-Null
        $grid.Columns.Add("Result", "Result") | Out-Null
        $grid.Columns.Add("Time", "Time (ms)") | Out-Null
        $grid.Columns.Add("Tests", "Tests") | Out-Null
        $grid.Columns["Name"].AutoSizeMode = 'Fill'
        $grid.Columns["Result"].Width = 200

        # --- Bottom Panel (Buttons) ---
        $bottomPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ FlowDirection = 'RightToLeft'; Dock = 'Fill'; AutoSize = $true }
        $btnStart = New-Button -Text "Start Run" -Style 'Primary' -Property @{ Width = 120; Height = 35 }
        $btnClose = New-Button -Text "Close" -Style 'Secondary' -Property @{ Width = 100; Height = 35 } -OnClick { $runnerForm.Close() }
        $btnRetry = New-Button -Text "Retry Failed" -Style 'Secondary' -Property @{ Width = 120; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,5,0); Enabled = $false } -OnClick {
            $failedRows = @()
            foreach ($row in $grid.Rows) {
                if ($row.Cells["Status"].Value -in @("FAIL", "ERROR")) { $failedRows += $row }
            }

            if ($failedRows.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("No failed requests to retry.", "Info", "OK", "Information")
                return
            }

            $script:collectionRunQueue.Clear()
            foreach ($row in $failedRows) {
                $script:collectionRunQueue.Enqueue($row)
                $row.Cells["Status"].Value = "Queued"
                $row.Cells["Result"].Value = ""
                $row.Cells["Time"].Value = ""
                $row.Cells["Tests"].Value = ""
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::Empty
            }

            $script:collectionRunTotal = $script:collectionRunQueue.Count
            $script:collectionRunCompleted = 0
            $script:collectionRunPassed = 0
            $script:collectionRunFailed = 0
            
            $script:settings.CollectionRunnerDelay = [int]$numDelay.Value
            $script:settings.CollectionRunnerStopOnFail = $chkStopOnFail.Checked
            Save-Settings

            $script:isCollectionRunning = $true
            $script:collectionRunDelay = [int]$numDelay.Value
            $script:collectionRunStopOnFail = $chkStopOnFail.Checked
            
            $script:collectionRunnerForm = $runnerForm
            $script:collectionRunnerGrid = $grid
            $script:collectionRunnerProgress = $progress
            $script:collectionRunnerSummaryLabel = $summaryLabel
            
            $progress.Maximum = $script:collectionRunTotal
            $progress.Value = 0
            $summaryLabel.Text = "Retrying $($script:collectionRunTotal) failed requests..."

            $btnStart.Enabled = $false
            $btnRetry.Enabled = $false
            
            if ($script:collectionRunQueue.Count -gt 0) {
                $firstRow = $script:collectionRunQueue.Dequeue()
                $script:collectionRunnerCurrentRow = $firstRow
                $firstRow.Cells["Status"].Value = "Running..."
                Load-Request-From-Object -RequestObject $firstRow.Tag.RequestData
                
                $parentForm.Tag.btnSubmit.Enabled = $false
                $parentForm.Tag.btnCancel.Enabled = $true
                $parentForm.Tag.btnRepeat.Enabled = $false
                
                Invoke-RequestExecution
            }
        }
        $btnExport = New-Button -Text "Export CSV" -Style 'Secondary' -Property @{ Width = 100; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,5,0) } -OnClick {
            $sfd = New-Object System.Windows.Forms.SaveFileDialog
            $sfd.Filter = "CSV Files (*.csv)|*.csv"
            $sfd.FileName = "collection_run_results.csv"
            if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $results = @()
                foreach ($row in $grid.Rows) {
                    $results += [PSCustomObject]@{
                        Request = $row.Cells["Name"].Value
                        Status  = $row.Cells["Status"].Value
                        Result  = $row.Cells["Result"].Value
                        TimeMs  = $row.Cells["Time"].Value
                        Tests   = $row.Cells["Tests"].Value
                    }
                }
                $results | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
                [System.Windows.Forms.MessageBox]::Show("Export successful.", "Export", "OK", "Information")
            }
        }
        $bottomPanel.Controls.AddRange(@($btnStart, $btnClose, $btnExport, $btnRetry))

        $chkSelectAll.Add_CheckedChanged({
            foreach ($row in $grid.Rows) { $row.Cells["Run"].Value = $chkSelectAll.Checked }
        })

        # --- Logic ---
        function Get-RequestsRecursive {
            param($NodeItem)
            $requests = @()
            if ($NodeItem.Type -eq "Request") {
                $requests += $NodeItem
            } elseif ($NodeItem.Items) {
                foreach ($child in $NodeItem.Items) {
                    $requests += Get-RequestsRecursive -NodeItem $child
                }
            }
            return $requests
        }
        $allRequests = Get-RequestsRecursive -NodeItem $Item

        # Populate Grid
        $grid.Rows.Clear()
        foreach ($req in $allRequests) {
            $rowIndex = $grid.Rows.Add(@($true, $req.Name, "Queued", "", "", ""))
            $grid.Rows[$rowIndex].Tag = $req
        }

        $btnStart.Add_Click({
            # Reset state
            $script:collectionRunQueue.Clear()
            
            foreach ($row in $grid.Rows) {
                if ($row.Cells["Run"].Value) {
                    $script:collectionRunQueue.Enqueue($row)
                    $row.Cells["Status"].Value = "Queued"
                    $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::Empty
                } else {
                    $row.Cells["Status"].Value = "Skipped"
                    $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightGray
                }
                $row.Cells["Result"].Value = ""
                $row.Cells["Time"].Value = ""
                $row.Cells["Tests"].Value = ""
            }

            $script:settings.CollectionRunnerDelay = [int]$numDelay.Value
            $script:settings.CollectionRunnerStopOnFail = $chkStopOnFail.Checked
            Save-Settings

            $script:isCollectionRunning = $true
            $script:collectionRunDelay = [int]$numDelay.Value
            $script:collectionRunStopOnFail = $chkStopOnFail.Checked
            
            $script:collectionRunnerForm = $runnerForm
            $script:collectionRunnerGrid = $grid
            $script:collectionRunnerProgress = $progress
            $script:collectionRunnerSummaryLabel = $summaryLabel
            $script:collectionRunTotal = $script:collectionRunQueue.Count
            $script:collectionRunCompleted = 0
            $script:collectionRunPassed = 0
            $script:collectionRunFailed = 0

            # Reset UI
            $progress.Maximum = $script:collectionRunTotal
            $progress.Value = 0
            $summaryLabel.Text = "Starting run..."

            # Disable button
            $this.Enabled = $false
            $btnRetry.Enabled = $false
            $this.Text = "Running..."

            # Dequeue and run the first request
            if ($script:collectionRunQueue.Count -gt 0) {
                $firstRow = $script:collectionRunQueue.Dequeue()
                $script:collectionRunnerCurrentRow = $firstRow
                $firstRow.Cells["Status"].Value = "Running..."
                Load-Request-From-Object -RequestObject $firstRow.Tag.RequestData
                
                # Control main form buttons
                $parentForm.Tag.btnSubmit.Enabled = $false
                $parentForm.Tag.btnCancel.Enabled = $true
                $parentForm.Tag.btnRepeat.Enabled = $false
                
                Invoke-RequestExecution
            } else {
                # No requests to run
                $summaryLabel.Text = "No requests found in this collection/folder."
                $script:isCollectionRunning = $false
                $this.Enabled = $true
                $this.Text = "Start Run"
            }
        })

        # Store controls in the form's Tag so the main form can access them
        $runnerForm.Tag = [PSCustomObject]@{
            btnStart = $btnStart
            btnRetry = $btnRetry
        }

        # Assemble form
        $mainLayout.Controls.Add($topPanel, 0, 0)
        $mainLayout.Controls.Add($grid, 0, 1)
        $mainLayout.Controls.Add($bottomPanel, 0, 2)
        $runnerForm.Controls.Add($mainLayout)

        $runnerForm.Show($parentForm) # Show non-modally
    }

    $script:monitorPool = $null
    $script:isHistoryUndocked = $false
    $script:lastDockState = 'Bottom' # Initialize the last known dock state
    $script:responseForm = $null # Initialize the undocked response form variable
    $script:isMainFormClosing = $false # New flag to indicate if the main form is closing
    if ($script:settings.EnableHistory) {
        Load-History
    }
    Load-Settings
    Load-Globals
    Load-Environments
    Load-Monitors
    Load-Collections

    # Initialize dock state from loaded settings, ensuring it's a valid state
    $script:responseDockState = $script:settings.ResponseDockState

    # Create Form
    $form = New-Object System.Windows.Forms.Form -Property @{
        Text               = "PowerShell API Tester"
        Size               = New-Object System.Drawing.Size(1200, 1000)
        StartPosition      = "CenterScreen"
        MinimumSize        = New-Object System.Drawing.Size(900, 800)
        FormBorderStyle    = [System.Windows.Forms.FormBorderStyle]::Sizable
        KeyPreview         = $true
        BackColor          = $script:Theme.FormBackground
    }

    $toolTip = New-Object System.Windows.Forms.ToolTip
    $script:monitorJobs = @{} # Hash to store running monitor jobs

    $statusStrip = New-Object System.Windows.Forms.StatusStrip
    $statusLabelStatus = New-Object System.Windows.Forms.ToolStripStatusLabel -Property @{
        Spring      = $true
        Text        = "Ready"
        TextAlign   = [System.Drawing.ContentAlignment]::MiddleLeft
    }
    $statusLabelTime = New-Object System.Windows.Forms.ToolStripStatusLabel -Property @{
        Text = "Time: N/A"
    }
    $statusLabelSize = New-Object System.Windows.Forms.ToolStripStatusLabel -Property @{
        Text = "Size: N/A"
    }
    $statusStrip.BackColor = $script:Theme.PrimaryButton
    $statusLabelStatus.ForeColor = $statusLabelTime.ForeColor = $statusLabelSize.ForeColor = $script:Theme.PrimaryButtonText

    $statusStrip.Items.AddRange(@($statusLabelStatus, $statusLabelTime, $statusLabelSize))

    # --- Menu Strip and File Menu ---
    $menuStrip = New-Object System.Windows.Forms.MenuStrip
    $fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Menu")
    $toolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Tools")
    $monitorMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Monitor")
    $menuStrip.BackColor = $script:Theme.GroupBackground
    $menuStrip.ForeColor = $script:Theme.TextColor


    # Initialize RunspacePool for background monitoring (Min 1, Max 5 concurrent tasks)
    $script:monitorPool = [runspacefactory]::CreateRunspacePool(1, 5)
    $script:monitorPool.Open()

    # --- Monitoring System ---
    $notifyIcon = New-Object System.Windows.Forms.NotifyIcon
    $notifyIcon.Icon = [System.Drawing.SystemIcons]::Application
    $notifyIcon.Visible = $true
    $notifyIcon.Text = "API Tester Monitor"

    $monitorTimer = New-Object System.Windows.Forms.Timer
    $monitorTimer.Interval = 1000 # Tick every second
    $monitorTimer.Add_Tick({
        $now = Get-Date
        foreach ($m in $script:monitors) {
            if ($m.Status -eq 'Running') {
                $lastRun = if ($m.LastRun) { [DateTime]$m.LastRun } else { [DateTime]::MinValue }
                
                # Check if it's time to run (and not currently running)
                if (($now - $lastRun).TotalSeconds -ge $m.IntervalSeconds -and -not $script:monitorJobs.ContainsKey($m.Id)) {
                    
                    # Start Monitor Job
                    $m.LastRun = $now
                    
                    # Simplified job script block for monitoring
                    $jobBlock = {
                        param($url, $method, $headers, $body, $bodyType)
                        param($url, $method, $headers, $body, $bodyType, $timeout)
                        try {
                            $sw = [System.Diagnostics.Stopwatch]::StartNew()
                            $req = [System.Net.HttpWebRequest]::Create($url)
                            $req.Method = $method
                            $req.Timeout = 30000
                            $req.Timeout = $timeout * 1000
                            # Add headers/body logic here (simplified for brevity)
                            $resp = $req.GetResponse()
                            $sw.Stop()
                            return @{ Success=$true; StatusCode=[int]$resp.StatusCode; Time=$sw.ElapsedMilliseconds; Msg="OK" }
                        } catch {
                            return @{ Success=$false; StatusCode=0; Time=0; Msg=$_.Exception.Message }
                        }
                    }
                    
                    $ps = [PowerShell]::Create()
                    $ps.RunspacePool = $script:monitorPool
                    $ps.AddScript($jobBlock).AddArgument($m.Request.Url).AddArgument($m.Request.Method).AddArgument($m.Request.Headers).AddArgument($m.Request.Body).AddArgument($m.Request.BodyType) | Out-Null
                    $ps.AddScript($jobBlock).AddArgument($m.Request.Url).AddArgument($m.Request.Method).AddArgument($m.Request.Headers).AddArgument($m.Request.Body).AddArgument($m.Request.BodyType).AddArgument($m.Request.RequestTimeoutSeconds) | Out-Null
                    $script:monitorJobs[$m.Id] = @{ PS = $ps; AR = $ps.BeginInvoke() }
                }
            }
        }

        # Check running jobs
        $ids = @($script:monitorJobs.Keys)
        foreach ($id in $ids) {
            $entry = $script:monitorJobs[$id]
            if ($entry.AR.IsCompleted) {
                $res = $entry.PS.EndInvoke($entry.AR) | Select-Object -First 1
                $entry.PS.Dispose()
                $script:monitorJobs.Remove($id)
                
                # Alerting Logic
                $mon = ($script:monitors | Where-Object {$_.Id -eq $id})
                if ($mon) {
                    # Log to CSV
                    try {
                        $logEntry = [PSCustomObject]@{
                            Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            MonitorName = $mon.Name
                            URL         = $mon.Request.Url
                            Success     = $res.Success
                            StatusCode  = $res.StatusCode
                            TimeMs      = $res.Time
                            Message     = $res.Msg
                        }
                        $logEntry | Export-Csv -Path $monitorLogFilePath -Append -NoTypeInformation -Force
                    } catch { Write-Log "Failed to write to monitor log: $($_.Exception.Message)" -Level Info }

                    $alertMsg = $null
                    $alertType = $null
                    if ($mon.Alerts.OnFailure -and (-not $res.Success -or $res.StatusCode -ne 200)) {
                        $alertMsg = "$($mon.Name) Failed: $($res.Msg)"
                        $alertType = "Failure"
                        $notifyIcon.ShowBalloonTip(5000, "API Monitor Alert", $alertMsg, [System.Windows.Forms.ToolTipIcon]::Error)
                    } elseif ($mon.Alerts.OnSlow -and $res.Time -gt $mon.Alerts.ThresholdMs) {
                        $alertMsg = "$($mon.Name) Slow: $($res.Time)ms"
                        $alertType = "Slow"
                        $notifyIcon.ShowBalloonTip(5000, "API Monitor Warning", $alertMsg, [System.Windows.Forms.ToolTipIcon]::Warning)
                    }

                    # Email Alert
                    if ($alertMsg -and $mon.Alerts.SendEmail -and $mon.Alerts.EmailTo -and $script:settings.MonitorSmtpServer) {
                        try {
                            $alertData = @{
                                MonitorName = $mon.Name
                                Status = $alertType
                                StatusCode = $res.StatusCode
                                Url = $mon.Request.Url
                                TimeMs = $res.Time
                                Message = $res.Msg
                                Timestamp = $logEntry.Timestamp
                            }
                            $subjectTemplate = if ($script:settings.MonitorAlertSubjectTemplate) { $script:settings.MonitorAlertSubjectTemplate } else { "API Alert: {MonitorName}" }
                            $bodyTemplate = if ($script:settings.MonitorAlertBodyTemplate) { $script:settings.MonitorAlertBodyTemplate } else { $alertMsg }
                            $emailSubject = Format-AlertTemplate -Template $subjectTemplate -Data $alertData
                            $emailBody = Format-AlertTemplate -Template $bodyTemplate -Data $alertData
                            if ([string]::IsNullOrWhiteSpace($emailSubject)) { $emailSubject = "API Alert: $($mon.Name)" }
                            if ([string]::IsNullOrWhiteSpace($emailBody)) { $emailBody = $alertMsg }

                            if ($script:settings.MonitorSmtpAuthMethod -eq "OAuth2") {
                                # Check for refresh
                                if ($script:settings.MonitorSmtpRefreshToken -and $script:settings.MonitorSmtpTokenEndpoint) {
                                     $shouldRefresh = $false
                                     if ($script:settings.MonitorSmtpTokenExpiry) {
                                         if ([DateTime]::UtcNow -ge [DateTime]$script:settings.MonitorSmtpTokenExpiry) { $shouldRefresh = $true }
                                     } elseif (-not $script:settings.MonitorSmtpPass) { $shouldRefresh = $true }
                                     if ($shouldRefresh) { Refresh-SmtpToken }
                                }
                                $isHtml = $script:settings.MonitorAlertBodyForceHtml -or (Test-IsHtmlBody -Body $emailBody)
                                Send-SmtpOAuth2 -Server $script:settings.MonitorSmtpServer -Port $script:settings.MonitorSmtpPort -UseSsl $script:settings.MonitorSmtpUseSsl -From $script:settings.MonitorSmtpFrom -To $mon.Alerts.EmailTo -Subject $emailSubject -Body $emailBody -User $script:settings.MonitorSmtpUser -AccessToken $script:settings.MonitorSmtpPass -IsHtml:$isHtml
                            } else {
                                $smtpParams = @{
                                    SmtpServer = $script:settings.MonitorSmtpServer
                                    Port = $script:settings.MonitorSmtpPort
                                    UseSsl = $script:settings.MonitorSmtpUseSsl
                                    From = $script:settings.MonitorSmtpFrom
                                    To = $mon.Alerts.EmailTo
                                    Subject = $emailSubject
                                    Body = $emailBody
                                    IsBodyHtml = ($script:settings.MonitorAlertBodyForceHtml -or (Test-IsHtmlBody -Body $emailBody))
                                }
                                if ($script:settings.MonitorSmtpUser) {
                                    $pass = $script:settings.MonitorSmtpPass | ConvertTo-SecureString -AsPlainText -Force
                                    $smtpParams.Credential = New-Object System.Management.Automation.PSCredential($script:settings.MonitorSmtpUser, $pass)
                                }
                                Send-MailMessage @smtpParams -ErrorAction Stop
                            }
                        } catch { Write-Log "Failed to send email alert: $($_.Exception.Message)" -Level Info }
                    }

                    # Analytics Webhook
                    if ($mon.AnalyticsUrl) {
                        try {
                            $payload = @{
                                monitorName = $mon.Name
                                timestamp = $logEntry.Timestamp
                                success = $res.Success
                                statusCode = $res.StatusCode
                                timeMs = $res.Time
                                message = $res.Msg
                            } | ConvertTo-Json -Compress
                            Invoke-RestMethod -Uri $mon.AnalyticsUrl -Method Post -Body $payload -ContentType "application/json" -ErrorAction Stop
                        } catch { Write-Log "Failed to send analytics for $($mon.Name): $($_.Exception.Message)" -Level Info }
                    }
                }
            }
        }
    })
    $monitorTimer.Start()

    # --- Import/Export Workspace ---
    $importCurlMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Import cURL...", $null, {
        $curlForm = New-Object System.Windows.Forms.Form -Property @{
            Text = "Import cURL"
            Size = New-Object System.Drawing.Size(600, 450)
            StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
        }
        $labelCurl = New-Label -Text "Paste cURL command here:" -Property @{ Dock = "Top"; Height = 25; Padding = [System.Windows.Forms.Padding]::new(5) }
        $txtCurl = New-TextBox -Multiline $true -Property @{ Dock = "Fill"; ScrollBars = "Vertical"; Font = New-Object System.Drawing.Font("Courier New", 9) }
        
        $panelBtn = New-Object System.Windows.Forms.Panel -Property @{ Dock = "Bottom"; Height = 40; Padding = [System.Windows.Forms.Padding]::new(5) }
        $btnImport = New-Button -Text "Import" -Property @{ Dock = "Right"; Width = 100 } -OnClick {
            $raw = $txtCurl.Text
            if ([string]::IsNullOrWhiteSpace($raw)) { return }

            # Basic parsing logic for standard cURL commands
            $url = ""
            $method = "GET"
            $headers = @{}
            $body = ""

            # Regex to find URL (http/https) inside quotes or whitespace
            if ($raw -match "['`"](https?://[^'`"]+)['`"]") { $url = $matches[1] }
            elseif ($raw -match "(https?://\S+)") { $url = $matches[1] }

            # Method
            if ($raw -match "-X\s+([A-Z]+)") { $method = $matches[1] }
            
            # Headers (-H "Key: Value")
            # Regex matches -H, space, quote (group 1), content (group 2), matching quote (backreference 1)
            $hMatches = [regex]::Matches($raw, '-H\s+([''"])(.*?)\1')
            foreach ($m in $hMatches) {
                $headerContent = $m.Groups[2].Value
                if ($headerContent -match "^(.*?):\s*(.*)$") {
                    $k = $matches[1]; $v = $matches[2]
                    if ($k -ne "Content-Type") { $headers[$k] = $v }
                }
            }

            # Body (--data, -d, --data-raw)
            if ($raw -match "(?:--data|--data-raw|-d)\s+(['`"])(.*?)\1") {
                $body = $matches[2]
                if ($method -eq "GET") { $method = "POST" }
            }

            # Apply to UI
            if ($url) { $script:textUrl.Text = $url }
            $script:comboMethod.SelectedItem = $method
            
            $headerText = ""
            foreach ($k in $headers.Keys) { $headerText += "${k}: $($headers[$k])`r`n" }
            $script:textHeaders.Text = $headerText
            
            $script:textBody.Text = $body
            if ($body.Trim().StartsWith("{") -or $body.Trim().StartsWith("[")) { $script:comboBodyType.SelectedItem = "application/json" }

            $curlForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $curlForm.Close()
        }
        $btnCancel = New-Button -Text "Cancel" -Property @{ Dock = "Right"; Width = 100 } -OnClick { $curlForm.Close() }
        
        $panelBtn.Controls.AddRange(@($btnCancel, $btnImport))
        $curlForm.Controls.AddRange(@($txtCurl, $labelCurl, $panelBtn))
        $curlForm.ShowDialog($form)
    })    
    $importCurlMenuItem.Visible = $script:settings.EnableCurlImport

    $importPostmanMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Import Postman Collection...", $null, {
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Filter = "Postman Collection (*.json)|*.json"
            Title  = "Import Postman Collection"
        }
        if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $jsonContent = Get-Content -Path $openFileDialog.FileName -Raw | ConvertFrom-Json
                
                if (-not $jsonContent.info -or -not $jsonContent.item) {
                    throw "Invalid Postman Collection format. Only v2.1 is supported."
                }

                function Convert-PostmanItems {
                    param($Items)
                    $converted = @()
                    foreach ($item in $Items) {
                        if ($item.item) {
                            $folder = [PSCustomObject]@{
                                Name = $item.name
                                Type = "Folder"
                                Items = (Convert-PostmanItems -Items $item.item)
                            }
                            $converted += $folder
                        } elseif ($item.request) {
                            $req = $item.request
                            if ($req.url -is [string]) { $url = $req.url } elseif ($req.url.raw) { $url = $req.url.raw } else { $url = "" }
                            $method = $req.method
                            
                            $headers = ""
                            if ($req.header -is [array]) {
                                $headers = ($req.header | ForEach-Object { "$($_.key): $($_.value)" }) -join "`r`n"
                            }

                            $body = ""
                            $bodyType = "text/plain"
                            if ($req.body) {
                                if ($req.body.mode -eq "raw") {
                                    $body = $req.body.raw
                                    if ($req.body.options.raw.language -eq "json") { $bodyType = "application/json" }
                                    elseif ($req.body.options.raw.language -eq "xml") { $bodyType = "application/xml" }
                                } elseif ($req.body.mode -eq "formdata") {
                                    $bodyType = "multipart/form-data"
                                    $lines = @()
                                    foreach ($fd in $req.body.formdata) {
                                        if ($fd.type -eq "file") { $lines += "$($fd.key)=@`"$($fd.src)`"" }
                                        else { $lines += "$($fd.key)=$($fd.value)" }
                                    }
                                    $body = $lines -join "`r`n"
                                } elseif ($req.body.mode -eq "urlencoded") {
                                    $bodyType = "application/x-www-form-urlencoded"
                                    $pairs = @()
                                    foreach ($ue in $req.body.urlencoded) {
                                        $pairs += "$([uri]::EscapeDataString($ue.key))=$([uri]::EscapeDataString($ue.value))"
                                    }
                                    $body = $pairs -join "&"
                                }
                            }

                            $authData = @{ Type = "No Auth" }
                            if ($req.auth) {
                                if ($req.auth.type -eq "basic") {
                                    $u = ($req.auth.basic | Where-Object { $_.key -eq "username" }).value
                                    $p = ($req.auth.basic | Where-Object { $_.key -eq "password" }).value
                                    $authData = @{ Type = "Basic Auth"; Username = $u; Password = $p }
                                } elseif ($req.auth.type -eq "bearer") {
                                    $t = ($req.auth.bearer | Where-Object { $_.key -eq "token" }).value
                                    $authData = @{ Type = "Bearer Token"; Token = $t }
                                }
                            }

                            $converted += [PSCustomObject]@{ Name = $item.name; Type = "Request"; RequestData = [PSCustomObject]@{ Timestamp = Get-Date; Method = $method; Url = $url; Headers = $headers; Body = $body; BodyType = $bodyType; OutputFormat = ""; Tests = ""; PreRequestScript = ""; Authentication = $authData } }
                        }
                    }
                    return $converted
                }

                $importedItems = Convert-PostmanItems -Items $jsonContent.item
                $script:collections += [PSCustomObject]@{ Name = $jsonContent.info.name; Type = "Collection"; Items = $importedItems; Variables = @{} }
                Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
                Save-Collections
                [System.Windows.Forms.MessageBox]::Show("Postman collection imported successfully.", "Import Complete", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to import Postman collection: $($_.Exception.Message)", "Import Error", "OK", "Error")
            }
        }
    })
    $importPostmanMenuItem.Visible = $script:settings.EnablePostmanImport

    $importWorkspaceMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Import Workspace...", $null, {
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Filter = "API Tester Workspace (*.apw)|*.apw"
            Title  = "Import Workspace"
            InitialDirectory = $configDir
        }
        if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $workspace = Get-Content -Path $openFileDialog.FileName -Raw | ConvertFrom-Json
                if ($workspace.PSObject.Properties.Name -contains 'Settings') {
                    # Create an import options form
                    $importOptionsForm = New-Object System.Windows.Forms.Form -Property @{
                        Text = "Import Options"
                        Size = New-Object System.Drawing.Size(320, 260)
                        StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
                        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
                        MaximizeBox = $false; MinimizeBox = $false
                    }
                    $labelInfo = New-Label -Text "Select components to import from workspace." -Location (New-Object System.Drawing.Point(15, 15)) -Size (New-Object System.Drawing.Size(280, 20))
                    $checkImportEnvironments = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Import Environments"; Location = (New-Object System.Drawing.Point(18, 45)); AutoSize = $true }
                    $checkImportHistory = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Import History"; Location = (New-Object System.Drawing.Point(18, 75)); AutoSize = $true }
                    $checkImportGlobals = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Import Globals"; Location = (New-Object System.Drawing.Point(18, 105)); AutoSize = $true }
                    $checkImportCollections = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Import Collections"; Location = (New-Object System.Drawing.Point(18, 135)); AutoSize = $true }

                    # Enable/disable checkboxes based on what's in the file
                    $checkImportEnvironments.Enabled = $workspace.PSObject.Properties.Name -contains 'Environments'
                    $checkImportHistory.Enabled = $workspace.PSObject.Properties.Name -contains 'History'
                    $checkImportGlobals.Enabled = $workspace.PSObject.Properties.Name -contains 'Globals'
                    $checkImportCollections.Enabled = $workspace.PSObject.Properties.Name -contains 'Collections'
                    $checkImportEnvironments.Checked = $checkImportEnvironments.Enabled
                    $checkImportHistory.Checked = $checkImportHistory.Enabled
                    $checkImportGlobals.Checked = $checkImportGlobals.Enabled
                    $checkImportCollections.Checked = $checkImportCollections.Enabled

                    $btnContinueImport = New-Button -Text "Import" -Location (New-Object System.Drawing.Point(190, 180)) -Size (New-Object System.Drawing.Size(100, 30)) -OnClick {
                        # Always import settings
                        $workspace.Settings | ConvertTo-Json -Depth 5 | Set-Content -Path $settingsFilePath
                        Write-Log "Imported Settings from workspace." -Level Debug

                        if ($checkImportEnvironments.Checked) {
                            $workspace.Environments | ConvertTo-Json -Depth 5 | Set-Content -Path $environmentsFilePath -ErrorAction Stop
                            Write-Log "Imported Environments from workspace." -Level Debug
                        }
                        if ($checkImportHistory.Checked) {
                            $workspace.History | ConvertTo-Json -Depth 5 | Set-Content -Path $historyFilePath -ErrorAction Stop
                            Write-Log "Imported History from workspace." -Level Debug
                        }
                        if ($checkImportGlobals.Checked) {
                            $workspace.Globals | ConvertTo-Json -Depth 5 | Set-Content -Path $globalsFilePath -ErrorAction Stop
                            Write-Log "Imported Globals from workspace." -Level Debug
                        }
                        if ($checkImportCollections.Checked) {
                            $workspace.Collections | ConvertTo-Json -Depth 10 | Set-Content -Path $collectionsFilePath -ErrorAction Stop
                            Write-Log "Imported Collections from workspace." -Level Debug
                        }

                        # Reload everything into the current session
                        Write-Log "Workspace import complete. Reloading UI."
                        Load-Settings
                        Load-Globals
                        Load-Environments
                        Load-Collections
                        if ($script:settings.EnableHistory) { Load-History }
                        Populate-EnvironmentDropdown
                        Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
                        $script:activeCollectionNode = $null
                        $script:activeCollectionVariables = @{}
                        Update-Layout
                        Populate-HistoryList
                        [System.Windows.Forms.MessageBox]::Show("Workspace components successfully imported. The application will now reflect the changes.", "Import Successful", "OK", "Information")
                        $importOptionsForm.Close()
                    }
                    $btnCancelImport = New-Button -Text "Cancel" -Location (New-Object System.Drawing.Point(80, 180)) -Size (New-Object System.Drawing.Size(100, 30)) -OnClick { $importOptionsForm.Close() }
                    
                    $importOptionsForm.Controls.AddRange(@($labelInfo, $checkImportEnvironments, $checkImportHistory, $checkImportGlobals, $checkImportCollections, $btnContinueImport, $btnCancelImport))
                    $importOptionsForm.ShowDialog($form)
                } else {
                    [System.Windows.Forms.MessageBox]::Show("The selected file is not a valid workspace file.", "Import Error", "OK", "Error")
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to import workspace: $($_.Exception.Message)", "Import Error", "OK", "Error")
                Write-Log "Error importing workspace file '$($openFileDialog.FileName)': $($_.Exception.Message)" -Level Info
            }
        }
    })
    $exportWorkspaceMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Export Workspace...", $null, {
        # Create a small form to ask about including history
        $exportOptionsForm = New-Object System.Windows.Forms.Form -Property @{
            Text = "Export Options"
            Size = New-Object System.Drawing.Size(450, 340) # Increased height for better button spacing
            StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
            FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
            MaximizeBox = $false
            MinimizeBox = $false
        }
        $labelInfo = New-Label -Text "Select options for your workspace export." -Location (New-Object System.Drawing.Point(15, 15)) -Size (New-Object System.Drawing.Size(410, 25))
        $checkIncludeEnvironments = New-Object System.Windows.Forms.CheckBox -Property @{
            Text = "Include environments in export"
            Location = New-Object System.Drawing.Point(18, 50)
            AutoSize = $true
        }
        $checkIncludeHistory = New-Object System.Windows.Forms.CheckBox -Property @{
            Text = "Include request history in export"
            Location = New-Object System.Drawing.Point(18, 85) # Moved down
            AutoSize = $true
        }
        $checkIncludeGlobals = New-Object System.Windows.Forms.CheckBox -Property @{
            Text = "Include global variables in export"
            Location = New-Object System.Drawing.Point(18, 120)
            AutoSize = $true
        }
        $checkIncludeCollections = New-Object System.Windows.Forms.CheckBox -Property @{
            Text = "Include collections in export"
            Location = New-Object System.Drawing.Point(18, 155)
            AutoSize = $true
        }
        # Disable checkboxes if there is no data to export
        $checkIncludeEnvironments.Enabled = ($null -ne $script:environments -and $script:environments.Count -gt 0)
        $checkIncludeHistory.Enabled = ($null -ne $script:history -and $script:history.Count -gt 0)
        $checkIncludeGlobals.Enabled = ($null -ne $script:globals -and $script:globals.Count -gt 0)
        $checkIncludeCollections.Enabled = ($null -ne $script:collections -and $script:collections.Count -gt 0)
        $checkIncludeEnvironments.Checked = $checkIncludeEnvironments.Enabled
        $checkIncludeHistory.Checked = $checkIncludeHistory.Enabled
        $checkIncludeGlobals.Checked = $checkIncludeGlobals.Enabled
        $checkIncludeCollections.Checked = $checkIncludeCollections.Enabled

        $btnContinueExport = New-Button -Text "Export..." -Location (New-Object System.Drawing.Point(310, 300)) -Size (New-Object System.Drawing.Size(110, 40)) -OnClick {
            $exportOptionsForm.Close() # Close the options form first
            $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog -Property @{
                Filter = "API Tester Workspace (*.apw)|*.apw"
                DefaultExt = "apw"
                FileName = "api_tester_workspace.apw"
                Title = "Export Workspace"
                InitialDirectory = $configDir
            }
            if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $workspace = [PSCustomObject]@{
                    # Settings are always included in a workspace export.
                    Settings = $script:settings
                }
                if ($checkIncludeEnvironments.Checked) {
                    $workspace | Add-Member -MemberType NoteProperty -Name "Environments" -Value $script:environments
                }
                if ($checkIncludeHistory.Checked) {
                    $workspace | Add-Member -MemberType NoteProperty -Name "History" -Value $script:history
                }
                if ($checkIncludeGlobals.Checked) {
                    $workspace | Add-Member -MemberType NoteProperty -Name "Globals" -Value $script:globals
                }
                if ($checkIncludeCollections.Checked) {
                    $workspace | Add-Member -MemberType NoteProperty -Name "Collections" -Value $script:collections
                }
                try {
                    $workspace | ConvertTo-Json -Depth 10 | Set-Content -Path $saveFileDialog.FileName -ErrorAction Stop
                    [System.Windows.Forms.MessageBox]::Show("Workspace successfully exported.", "Export Complete", "OK", "Information")
                } catch {
                    Write-Log "Error exporting workspace: $($_.Exception.Message)" -Level Info
                    [System.Windows.Forms.MessageBox]::Show("Failed to export workspace: $($_.Exception.Message)", "Export Error", "OK", "Error")
                }
            }
        }
        $btnCancelExport = New-Button -Text "Cancel" -Location (New-Object System.Drawing.Point(200, 300)) -Size (New-Object System.Drawing.Size(100, 40)) -OnClick {
            $exportOptionsForm.Close()
        }
        $exportOptionsForm.Controls.AddRange(@($labelInfo, $checkIncludeEnvironments, $checkIncludeHistory, $checkIncludeGlobals, $checkIncludeCollections, $btnContinueExport, $btnCancelExport))
        $exportOptionsForm.ShowDialog($form)
    })

    $settingsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("&Settings...", $null, { 
        # Directly call the function to show the settings window.
        $result = Show-SettingsWindow -parentForm $form

        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            Write-Log "Settings saved and applied."
            Update-Layout
            $importCurlMenuItem.Visible = $script:settings.EnableCurlImport
            $importPostmanMenuItem.Visible = $script:settings.EnablePostmanImport

            # Update Console Welcome Message if it is currently displayed (and no other history exists)
            if ($script:consoleOutput -and $script:consoleOutput.Text -match "(?s)^Welcome to API Tester Console.*?Example: python: print\('Hello'\)\s+$") {
                $defaultLang = if ($script:settings.DefaultConsoleLanguage) { $script:settings.DefaultConsoleLanguage } else { "PowerShell" }
                $script:consoleOutput.Text = "Welcome to API Tester Console.`nDefault language: $defaultLang.`nPrefix commands with 'python:', 'js:', 'php:', 'ruby:', 'go:', 'bat:', 'bash:' to switch languages.`nExample: python: print('Hello')`n`n"
            }
        } else {
            Write-Log "Settings dialog cancelled."
        }
    })
    
    $exitMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("E&xit", $null, { $form.Close() })

    $resetLayoutMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Reset Layout", $null, {
        $script:responseDockState = 'Right'
        $script:settings.ResponseDockState = 'Right'
        $script:isHistoryUndocked = $false
        # Calculate optimal splitter distances based on form width
        $formWidth = $form.ClientSize.Width
        $splitContainer.SplitterDistance = [int]($formWidth * 0.7)  # 70% for Body+Response, 30% for History
        $mainContentSplitter.SplitterDistance = [int](($formWidth * 0.7) * 0.45)  # 45% of left panel for Body, 55% for Response
        Save-Settings
        Update-Layout
        [System.Windows.Forms.MessageBox]::Show("Layout has been reset to defaults.", "Reset Layout", "OK", "Information")
    })

    $fileMenu.DropDownItems.AddRange(@(
        $importCurlMenuItem, $importPostmanMenuItem, $importWorkspaceMenuItem, $exportWorkspaceMenuItem, 
        (New-Object System.Windows.Forms.ToolStripSeparator), 
        $resetLayoutMenuItem,
        $settingsMenuItem, 
        (New-Object System.Windows.Forms.ToolStripSeparator), 
        $exitMenuItem
    ))
    $menuStrip.Items.Add($fileMenu)

    $globalVarsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Global Variables...", $null, {
        $result = Show-VariablesEditor -parentForm $form -Title "Global Variables" -Variables $script:globals
        if ($result.Result -eq [System.Windows.Forms.DialogResult]::OK) {
            $script:globals = if ($result.Variables) { $result.Variables } else { @{} }
            Save-Globals
            Write-Log "Global variables updated."
        }
    })
    $toolsMenu.DropDownItems.Add($globalVarsMenuItem)
    $toolsMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))

    $proxyMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Proxy Configuration...", $null, { Show-ProxySettings -parentForm $form })
    $toolsMenu.DropDownItems.Add($proxyMenuItem)

    $cookieJarMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Cookie Jar...", $null, { Show-CookieJar -parentForm $form })
    $toolsMenu.DropDownItems.Add($cookieJarMenuItem)

    $jwtMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("JWT Utility...", $null, { Show-JwtTool })
    $toolsMenu.DropDownItems.Add($jwtMenuItem)

    $reportMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Generate Report...", $null, { Show-ReportGenerator -parentForm $form })
    $toolsMenu.DropDownItems.Add($reportMenuItem)

    $wsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("WebSocket Client...", $null, { Show-WebSocketClient -parentForm $form })
    $toolsMenu.DropDownItems.Add($wsMenuItem)

    $grpcMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("gRPC Client...", $null, { Show-GrpcClient -parentForm $form })
    $toolsMenu.DropDownItems.Add($grpcMenuItem)

    $menuStrip.Items.Add($toolsMenu)

    $monitorManagerItem = New-Object System.Windows.Forms.ToolStripMenuItem("Monitor Manager...", $null, { Show-MonitorManager -parentForm $form })
    $monitorDashboardItem = New-Object System.Windows.Forms.ToolStripMenuItem("Monitoring Dashboard...", $null, { Show-MonitoringDashboard -parentForm $form })

    $monitorMenu.DropDownItems.AddRange(@($monitorManagerItem, $monitorDashboardItem))
    $menuStrip.Items.Add($monitorMenu)

    $form.MainMenuStrip = $menuStrip

    # GroupBox for selecting the active environment.
    $groupEnvironment = New-Object System.Windows.Forms.GroupBox -Property @{
        Height   = 110
        Dock     = 'Top'
        Text     = "Environment"
        Padding  = [System.Windows.Forms.Padding]::new(5)
        BackColor = $script:Theme.GroupBackground
    }
    # Use TableLayoutPanel for perfect alignment and to prevent cutoff
    $panelEnvInner = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ 
        Dock = 'Fill'
        ColumnCount = 3
        RowCount = 1
        Padding = [System.Windows.Forms.Padding]::new(5, 10, 5, 5)
    }
    $panelEnvInner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelEnvInner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $panelEnvInner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelEnvInner.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 35)))

    $labelEnvironment = New-Label -Text "Active Environment:" -Property @{ 
        AutoSize = $true
        Anchor = 'Left, Right'
        TextAlign = 'MiddleLeft'
        Margin = [System.Windows.Forms.Padding]::new(0, 5, 10, 0)
    }

    $script:comboEnvironment = New-Object System.Windows.Forms.ComboBox -Property @{
        Name          = 'comboEnvironment'
        Anchor        = 'Left, Right'
        DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        Height        = 28
        Margin        = [System.Windows.Forms.Padding]::new(0, 3, 0, 0)
    }

    $btnManageEnvs = New-Button -Text "Manage..." -OnClick {
        Show-EnvironmentManagerWindow -parentForm $form
        Populate-EnvironmentDropdown
    } -Property @{
        Width = 100
        Height = 35
        Anchor = 'Right'
        Margin = [System.Windows.Forms.Padding]::new(10, 3, 0, 0)
    }

    $panelEnvInner.Controls.Add($labelEnvironment, 0, 0)
    $panelEnvInner.Controls.Add($script:comboEnvironment, 1, 0)
    $panelEnvInner.Controls.Add($btnManageEnvs, 2, 0)

    $groupEnvironment.Controls.Add($panelEnvInner)

    # Populates the environment dropdown, preserving the current selection if possible.
    function Populate-EnvironmentDropdown {
        $currentSelection = $script:comboEnvironment.SelectedItem
        $script:comboEnvironment.Items.Clear()
        $script:comboEnvironment.Items.Add("No Environment") # Always include this option
        $script:environments.Keys | Sort-Object | ForEach-Object { $script:comboEnvironment.Items.Add($_) }
        if ($currentSelection -and $script:comboEnvironment.Items.Contains($currentSelection)) { $script:comboEnvironment.SelectedItem = $currentSelection } else { $script:comboEnvironment.SelectedItem = "No Environment" }
    }

    # When an environment is selected, populate the main form's fields.
    $script:comboEnvironment.Add_SelectedIndexChanged({
        $selectedEnvName = $script:comboEnvironment.SelectedItem
        if ($selectedEnvName -ne "No Environment" -and $script:environments.ContainsKey($selectedEnvName)) {
            $script:settings.LastActiveEnvironment = $selectedEnvName
            Save-Settings

            $envData = $script:environments[$selectedEnvName] # Retrieve the environment data

            # Populate URL and Headers
            $script:textUrl.Text = $envData.Url
            $script:textHeaders.Text = $envData.Headers

            # Populate Authentication
            if ($envData.Authentication) {
                $auth = $envData.Authentication
                $script:authPanel.ComboAuthType.SelectedItem = $auth.Type
                & $script:authPanel.SwitchPanel # Update the visible auth panel
                switch ($auth.Type) {
                    "API Key"      { $script:authPanel.TextApiKeyName.Text = $auth.Key; $script:authPanel.TextApiKeyValue.Text = $auth.Value; $script:authPanel.ComboApiKeyAddTo.SelectedItem = $auth.AddTo }
                    "Bearer Token" { $script:authPanel.TextBearerToken.Text = $auth.Token }
                    "Basic Auth"   { $script:authPanel.TextBasicUser.Text = $auth.Username; $script:authPanel.TextBasicPass.Text = $auth.Password }
                    "Auth2"        {
                        $script:authPanel.TextAuth2ClientId.Text = $auth.ClientId
                        $script:authPanel.TextAuth2ClientSecret.Text = $auth.ClientSecret
                        $script:authPanel.TextAuth2AuthEndpoint.Text = $auth.AuthEndpoint
                        $script:authPanel.TextAuth2RedirectUri.Text = $auth.RedirectUri
                        $script:authPanel.TextAuth2TokenEndpoint.Text = $auth.TokenEndpoint
                        $script:authPanel.TextAuth2Scope.Text = $auth.Scope
                        $script:authPanel.TextAuth2AccessToken.Text = $auth.AccessToken
                        $script:authPanel.TextAuth2RefreshToken.Text = $auth.RefreshToken
                        $script:authPanel.TextAuth2ExpiresIn.Text = $auth.ExpiresIn
                        $script:authPanel.TextAuth2AccessToken.Tag = $auth.TokenExpiryTimestamp
                    }
                    "Client Certificate" {
                        $script:authPanel.ComboCertSource.SelectedItem = $auth.Source
                        $script:authPanel.TextCertPath.Text = $auth.Path
                        $script:authPanel.TextCertPass.Text = $auth.Password
                        $script:authPanel.TextCertThumb.Text = $auth.Thumbprint
                    }
                }
            }
            Write-Log "Applied environment '$selectedEnvName' to the current request." -Level Info
        }
        if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Environment" -and $null -ne $updateExtractVarList) {
            & $updateExtractVarList
        }
    })

    $form.Add_Resize({
        $form.SuspendLayout()
        Update-Layout
        $form.ResumeLayout()
    })

    # Main layout container, splitting the request/response view from the history panel.
    $splitContainer = New-Object System.Windows.Forms.SplitContainer -Property @{ # This is the main splitter for Request/Response vs History
        Name             = 'splitContainer'
        Dock             = [System.Windows.Forms.DockStyle]::Fill
        BorderStyle      = [System.Windows.Forms.BorderStyle]::FixedSingle
        SplitterDistance = 590 # Initial width of the left panel (request/response)
    }

    # This splitter is for handling Left/Right docking of the Response panel
    $mainContentSplitter = New-Object System.Windows.Forms.SplitContainer -Property @{
        Name        = 'mainContentSplitter'
        Dock        = [System.Windows.Forms.DockStyle]::Fill
        Orientation = [System.Windows.Forms.Orientation]::Vertical
        BorderStyle = [System.Windows.Forms.BorderStyle]::None # No double border
        SplitterDistance = 590
    }
    # This panel will hold the Request and Output controls when the Response is side-docked
    $mainContentPanel = New-Object System.Windows.Forms.Panel -Property @{
        Name = 'mainContentPanel'
        Dock = [System.Windows.Forms.DockStyle]::Fill
        Padding = [System.Windows.Forms.Padding]::new(10)
    }

    # Add the new splitter to the original split container's Panel1
    $splitContainer.Panel1.Controls.Add($mainContentSplitter)
    
    # GroupBox for manual output file settings and the main Send/Cancel buttons.
    $groupOutput = New-Object System.Windows.Forms.GroupBox -Property @{
        Height   = 180
        Dock     = 'Top'
        Text     = "Output & Submission"
        Padding  = [System.Windows.Forms.Padding]::new(5)
        BackColor = $script:Theme.GroupBackground
    }

    # Refactored: Use Panels with Docking strategy consistent with Request/Environment panels
    $panelOutputFormat = New-Object System.Windows.Forms.Panel -Property @{
        Dock = 'Top'
        Height = 50
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5)
    }
    $labelOutputFormat = New-Label -Text "Output Format:" -Property @{ 
        Dock = 'Left'
        AutoSize = $false
        Width = 160
        TextAlign = 'MiddleLeft'
    }
    $script:textOutputFormat = New-TextBox -Multiline $false -Property @{
        Name     = 'textOutputFormat'
        Dock     = 'Fill'
    }
    $panelOutputFormat.Controls.AddRange(@($labelOutputFormat, $script:textOutputFormat))

    $panelOutputFile = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Top'
        Height = 40
        ColumnCount = 3
        RowCount = 1
        Padding = [System.Windows.Forms.Padding]::new(5, 0, 5, 0)
    }
    $panelOutputFile.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 160)))
    $panelOutputFile.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $panelOutputFile.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelOutputFile.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $panelOutputFile.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $labelOutputFile = New-Label -Text "Output File:" -Property @{ 
        Anchor = 'Left, Right'
        TextAlign = 'MiddleLeft'
        Margin = [System.Windows.Forms.Padding]::new(0, 5, 5, 0)
    }
    $script:textOutputFile = New-TextBox -Multiline $false -Property @{
        Anchor = 'Left, Right'
        Margin = [System.Windows.Forms.Padding]::new(0, 3, 0, 0)
    }
    $btnBrowseOutputFile = New-Button -Text "Browse..." -Property @{
        Dock = 'Fill'
        Height = 35
        Width = 100
        Margin = [System.Windows.Forms.Padding]::new(5, 0, 0, 0)
    } -OnClick {
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "All files (*.*)|*.*"
        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $script:textOutputFile.Text = $saveFileDialog.FileName
        }
    }

    $panelOutputFile.Controls.Add($labelOutputFile, 0, 0)
    $panelOutputFile.Controls.Add($script:textOutputFile, 1, 0)
    $panelOutputFile.Controls.Add($btnBrowseOutputFile, 2, 0)

    $panelOutputActions = New-Object System.Windows.Forms.Panel -Property @{
        Dock = 'Bottom'
        Height = 60
        Padding = [System.Windows.Forms.Padding]::new(5, 10, 5, 5)
    }

    $groupOutput.Controls.AddRange(@($panelOutputActions, $panelOutputFile, $panelOutputFormat))
    $panelOutputActions.BringToFront()
    $panelOutputFile.BringToFront()
    $panelOutputFormat.BringToFront()

    # Updates UI elements based on current settings, such as toggling control visibility.
    function Update-UI-Mode {
        $showOutputFileControls = -not $script:settings.AutoSaveToFile
        
        $labelOutputFile.Visible = $showOutputFileControls
        $script:textOutputFile.Visible = $showOutputFileControls
        $btnBrowseOutputFile.Visible = $showOutputFileControls
        # OutputFormat controls are always visible, so no need to toggle here.

        if (-not $showOutputFileControls) { $script:textOutputFile.Text = "" }

        if ($script:settings.EnableAllMethods) {
            $script:comboMethod.Enabled = $true
        } else {
            $script:comboMethod.Enabled = $false
            $script:comboMethod.SelectedItem = "POST"
        }

        # Show/Hide Repeat button based on settings
        $btnRepeat.Visible = $script:settings.EnableRepeatRequest
    }

    # Creates the separate, undockable window for the request history panel.
    function New-HistoryWindow {
        if ($script:historyForm -and -not $script:historyForm.IsDisposed) { return } # Don't create if it already exists and is not disposed

        $script:historyForm = New-Object System.Windows.Forms.Form -Property @{ # Initialize the form
            Text          = "History"
            Size          = New-Object System.Drawing.Size(300, 600)
            StartPosition = [System.Windows.Forms.FormStartPosition]::WindowsDefaultLocation # Start with a default location
            FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
            ShowInTaskbar = $false
            Owner         = $form
        }

        $historyFormShownHandler = {
            # Position the history window next to the main form, then remove this event handler.
            $script:historyForm.Location = New-Object System.Drawing.Point(([int]$form.Location.X + [int]$form.Width), [int]$form.Location.Y)
            $script:historyForm.Remove_Shown($historyFormShownHandler)
        }
        $script:historyForm.Add_Shown($historyFormShownHandler)

        # Handle the 'X' button click: hide the window and re-dock the panel instead of closing.
        $script:historyForm.Add_FormClosing({
            param($sender, $e)
            if (-not $script:isMainFormClosing) { # Only re-dock if main form is not closing
                $e.Cancel = $true # Prevent the form from being disposed.
                $script:isHistoryUndocked = $false
                Update-Layout # Re-dock the panel.
                Write-Log "Undocked history window closed, re-docking." -Level Debug
            } else {
                Write-Log "Undocked history window closing due to main form closure." -Level Debug
            }
        })
        Write-Log "Created undocked history window."
    }

    # Creates the separate, undockable window for the response panel.
    function New-ResponseWindow {
        if ($script:responseForm -and -not $script:responseForm.IsDisposed) { return } # Don't create if it already exists
        Write-Log "Creating undocked response window." -Level Debug


        $script:responseForm = New-Object System.Windows.Forms.Form -Property @{
            Text          = "Response"
            Size          = New-Object System.Drawing.Size(600, 700)
            StartPosition = [System.Windows.Forms.FormStartPosition]::WindowsDefaultLocation
            FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
            ShowInTaskbar = $true # Show in taskbar as it's a primary content window
            Owner         = $form
            MaximizeBox   = $true
            MinimizeBox   = $true
        }

        # Handle the 'X' button click: hide the window and re-dock the panel.
        $script:responseForm.Add_FormClosing({
            param($sender, $e)
            if (-not $script:isMainFormClosing) { # Only re-dock if main form is not closing
                $e.Cancel = $true # Prevent the form from being disposed.
                $script:responseDockState = 'Bottom' # Default back to bottom docking
                # Use the last known dock state instead of defaulting to Bottom
                & $setDockState $script:lastDockState
                Write-Log "Undocked response window closed, re-docking." -Level Debug
            } else {
                Write-Log "Undocked response window closing due to main form closure." -Level Debug
            }
        })
        Write-Log "Undocked response window created." -Level Debug
    }


    # Recalculates and applies the positions and sizes of all major UI panels.
    # This function is called on form resize and when settings change.
    function Update-Layout {
        if (-not $tabRequestBody) { return } # Guard clause to prevent execution before UI tabs are initialized
        # Suspend layout logic to prevent flickering during updates
        $form.SuspendLayout()
        $mainContentSplitter.SuspendLayout()
        Update-UI-Mode

        # Update checkmarks on the docking context menu
        $dockBottomMenuItem.Checked = ($script:responseDockState -eq 'Bottom')
        $dockLeftMenuItem.Checked = ($script:responseDockState -eq 'Left')
        $dockRightMenuItem.Checked = ($script:responseDockState -eq 'Right')
        $undockMenuItem.Checked = ($script:responseDockState -eq 'Undocked')

        if ($script:isHistoryUndocked -and $script:settings.EnableHistory) {
            $splitContainer.Panel2Collapsed = $true
            
            if (-not $script:historyForm -or $script:historyForm.IsDisposed) {
                New-HistoryWindow # This will create/recreate $script:historyForm
            }
            if (-not $script:historyForm.Controls.Contains($groupHistory)) {
                $groupHistory.Parent = $script:historyForm
            }
            if (-not $script:historyForm.Visible) {
                $script:historyForm.Show($form) # Show() will make it visible.
            }
        } else {
            if ($script:historyForm -and -not $script:historyForm.IsDisposed -and $script:historyForm.Visible) { $script:historyForm.Hide() }
            if (-not $splitContainer.Panel2.Controls.Contains($groupHistory)) {
                $groupHistory.Parent = $splitContainer.Panel2
            }
            $splitContainer.Panel2Collapsed = (-not $script:settings.ShowHistory) -or (-not $script:settings.EnableHistory)
        }

        # 1. Detach groupResponse and mainContentPanel from any parent, and clear splitter panels.
        $groupResponse.Parent = $null # Detach groupResponse from any parent
        $mainContentPanel.Parent = $null # Detach mainContentPanel from any parent
        $mainContentSplitter.Panel1.Controls.Clear()
        $mainContentSplitter.Panel2.Controls.Clear()
        if ($script:responseForm -and -not $script:responseForm.IsDisposed) { $script:responseForm.Controls.Clear() }

        if ($script:responseDockState -eq 'Undocked') {
            $groupResponse.Dock = 'Fill' # Make it fill the new window
            if (-not $script:responseForm -or $script:responseForm.IsDisposed) {
                New-ResponseWindow
            }
            if (-not $script:responseForm.Controls.Contains($groupResponse)) {
                $groupResponse.Parent = $script:responseForm
            }
            if (-not $script:responseForm.Visible) { $script:responseForm.Show() }
            $mainContentSplitter.Panel2Collapsed = $true
            $mainContentSplitter.Panel1.Controls.Add($mainContentPanel) # mainContentPanel gets request/output
            $tabControlResponse.Alignment = [System.Windows.Forms.TabAlignment]::Top
            $mainContentPanel.Controls.AddRange(@($groupEnvironment, $groupRequest, $groupOutput))
            $groupResponse.Visible = $true
        } elseif ($script:responseDockState -eq 'Left' -or $script:responseDockState -eq 'Right') {
            if ($script:responseForm -and -not $script:responseForm.IsDisposed -and $script:responseForm.Visible) { $script:responseForm.Hide() }

            $mainContentSplitter.Panel2Collapsed = $false
            $groupResponse.Dock = 'Fill'
            $mainContentSplitter.Orientation = [System.Windows.Forms.Orientation]::Vertical # Use Vertical for a side-by-side split

            if ($script:responseDockState -eq 'Left') {
                $groupResponse.Parent = $mainContentSplitter.Panel1 # Reparent to splitter panel 1
                $mainContentPanel.Parent = $mainContentSplitter.Panel2 # Reparent mainContentPanel to splitter panel 2
                $tabControlResponse.Alignment = [System.Windows.Forms.TabAlignment]::Left
                $mainContentSplitter.SplitterDistance = [int]($mainContentSplitter.ClientSize.Width * 0.4) # 40% for response
            } else { # Right
                $mainContentPanel.Parent = $mainContentSplitter.Panel1 # Reparent mainContentPanel to splitter panel 1
                $groupResponse.Parent = $mainContentSplitter.Panel2 # Reparent to splitter panel 2
                $tabControlResponse.Alignment = [System.Windows.Forms.TabAlignment]::Right
                $mainContentSplitter.SplitterDistance = [int]($mainContentSplitter.ClientSize.Width * 0.6) # 60% for request/output
            }
            $mainContentPanel.Controls.AddRange(@($groupEnvironment, $groupRequest, $groupOutput))
            $groupResponse.Visible = $true
        } else {
            # Default 'Bottom' docking
            $groupResponse.Dock = 'Fill'
            if ($script:responseForm -and -not $script:responseForm.IsDisposed -and $script:responseForm.Visible) { $script:responseForm.Hide() }
            $mainContentSplitter.Orientation = [System.Windows.Forms.Orientation]::Vertical
            $mainContentSplitter.Panel1.Controls.Add($mainContentPanel) # mainContentPanel gets request/output
            $mainContentSplitter.Panel2Collapsed = $true
            $tabControlResponse.Alignment = [System.Windows.Forms.TabAlignment]::Top
            
            $groupResponse.Parent = $mainContentPanel # Reparent to mainContentPanel
            $mainContentPanel.Controls.AddRange(@($groupEnvironment, $groupRequest, $groupOutput, $groupResponse))
            $groupResponse.Visible = $true
        } # End of Response Panel Docking State

        # Re-populate the request tabs based on visibility settings.
        $selectedRequestTab = $requestTabControl.SelectedTab
        $requestTabControl.TabPages.Clear()
        $requestTabControl.TabPages.Add($tabRequestBody)
        if ($script:settings.ShowRequestHeadersTab) { $requestTabControl.TabPages.Add($tabRequestHeaders) }
        if ($script:settings.ShowAuthTab) { $requestTabControl.TabPages.Add($tabAuth) }
        if ($script:settings.ShowPreRequestTab) { $requestTabControl.TabPages.Add($tabPreRequest) }
        if ($script:settings.ShowTestsTab) { $requestTabControl.TabPages.Add($tabRequestTests) }
        if ($selectedRequestTab -and $requestTabControl.TabPages.Contains($selectedRequestTab)) {
            $requestTabControl.SelectedTab = $selectedRequestTab
        }

        # Re-populate the response tabs based on visibility settings. This must be done
        # AFTER the parent control is set and visibility is determined.
        $selectedResponseTab = $tabControlResponse.SelectedTab
        $tabControlResponse.TabPages.Clear()
        # Only add tabs if the response group is visible in its current context
        # This ensures that if groupResponse.Visible is false, no tabs are added.
        if ($groupResponse.Visible) {
            if ($script:settings.ShowResponse) { $tabControlResponse.TabPages.Add($tabResponse) }
            if ($script:settings.ShowJsonTreeTab) { $tabControlResponse.TabPages.Add($tabJsonTree) }
            if ($script:settings.ShowResponseHeaders) { $tabControlResponse.TabPages.Add($tabHeaders) }
            if ($script:settings.ShowTestResultsTab) { $tabControlResponse.TabPages.Add($tabTestResults) }
            if ($script:settings.ShowCurl) { $tabControlResponse.TabPages.Add($tabCode) }
            if ($script:settings.ShowConsoleTab) { $tabControlResponse.TabPages.Add($tabConsole) }
        }
        # Restore the selected tab if it still exists
        if ($selectedResponseTab -and $tabControlResponse.TabPages.Contains($selectedResponseTab)) {
            $tabControlResponse.SelectedTab = $selectedResponseTab
        }

        # Determine if the entire response group box should be visible. This applies to its content.
        $isAnyResponseTabVisible = ($script:settings.ShowResponse -or 
                                    $script:settings.ShowResponseHeaders -or 
                                    $script:settings.ShowTestResultsTab -or 
                                    $script:settings.ShowCurl -or
                                    $script:settings.ShowConsoleTab)
        # If no tabs are visible, hide the groupResponse itself.
        if (-not $isAnyResponseTabVisible) { $groupResponse.Visible = $false }

        $groupEnvironment.Visible = $script:settings.ShowEnvironmentPanel

        # Apply Stacking Strategy
        $groupEnvironment.Dock = 'Top'
        $groupEnvironment.Height = 110

        if ($groupResponse.Visible -and ($script:responseDockState -eq 'Bottom')) {
            $groupRequest.Dock = 'Top'
            $groupRequest.Height = 500
            $groupOutput.Dock = 'Top'
            $groupOutput.Height = 180
            $groupResponse.Dock = 'Fill'
        } else {
            $groupOutput.Dock = 'Bottom'
            $groupOutput.Height = 180
            $groupRequest.Dock = 'Fill'
        }

        # Ensure correct visual order (Env -> Request -> Output -> Response)
        $groupEnvironment.BringToFront()
        
        if ($groupRequest.Dock -eq 'Top') {
            $groupRequest.BringToFront()
            $groupOutput.BringToFront()
            if ($groupResponse.Parent -eq $mainContentPanel) { $groupResponse.BringToFront() }
        } else {
            $groupOutput.BringToFront()
            $groupRequest.BringToFront()
        }
        
        # Update fonts
        if ($script:settings.ResponseFontSize -le 0) { $script:settings.ResponseFontSize = 9 }
        $responseFont = New-Object System.Drawing.Font("Courier New", $script:settings.ResponseFontSize)
        if ($richTextResponse) { $richTextResponse.Font = $responseFont }
        if ($richTextResponseHeaders) { $richTextResponseHeaders.Font = $responseFont }
        if ($richTextCode) { $richTextCode.Font = $responseFont }
        if ($script:richTextTestResults) { $script:richTextTestResults.Font = $responseFont }
        if ($script:consoleOutput) { $script:consoleOutput.Font = $responseFont; $script:consoleInput.Font = $responseFont }

        $mainContentSplitter.ResumeLayout()
        $form.ResumeLayout()
    }

    # --- GroupBox for Request Details ---
    $groupRequest = New-Object System.Windows.Forms.GroupBox -Property @{
        Height   = 500
        Dock     = 'Top'
        Text     = "Request"
        Padding  = [System.Windows.Forms.Padding]::new(5)
        BackColor = $script:Theme.GroupBackground
    }

    # Use TableLayoutPanel for perfect alignment
    $panelRequestTop = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Top'
        Height = 60
        ColumnCount = 4
        RowCount = 1
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5)
    }
    $panelRequestTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelRequestTop.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $panelRequestTop.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $labelMethod = New-Label -Text "Method:" -Property @{ 
        AutoSize = $true
        Anchor = 'Left'
        TextAlign = 'MiddleLeft'
        Margin = [System.Windows.Forms.Padding]::new(5, 5, 10, 0)
    }

    $script:comboMethod = New-Object System.Windows.Forms.ComboBox -Property @{
        Name          = 'comboMethod'
        Width         = 100
        Anchor        = 'Left, Right'
        DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        Margin        = [System.Windows.Forms.Padding]::new(0, 0, 10, 0)
    }
    $script:comboMethod.Items.AddRange(@("POST", "GET", "PUT", "DELETE", "PATCH"))
    $script:comboMethod.SelectedIndex = 0

    $labelUrl = New-Label -Text "URL:" -Property @{ 
        AutoSize = $true
        Anchor = 'Left'
        TextAlign = 'MiddleLeft'
        Margin = [System.Windows.Forms.Padding]::new(0, 5, 10, 0)
    }

    $script:textUrl = New-TextBox -Multiline $false -Property @{
        Name     = 'textUrl'
        Anchor   = 'Left, Right'
    }

    $panelRequestTop.Controls.Add($labelMethod, 0, 0)
    $panelRequestTop.Controls.Add($script:comboMethod, 1, 0)
    $panelRequestTop.Controls.Add($labelUrl, 2, 0)
    $panelRequestTop.Controls.Add($script:textUrl, 3, 0)

    # --- NEW: TabControl for Body, Headers, Auth ---
    # --- TabControl for Body, Headers, Auth ---
    $requestTabControl = New-Object System.Windows.Forms.TabControl -Property @{
        Dock = 'Fill'
        Margin = [System.Windows.Forms.Padding]::new(0, 10, 0, 0)
    }

    $tabRequestBody = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Body"; BorderStyle = 'None' }

    $bodyTopPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Top'; AutoSize = $true}

    # Body Type Selection
    $labelBodyType = New-Label -Text "Body Type:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 0) }
    $script:comboBodyType = New-Object System.Windows.Forms.ComboBox -Property @{
        Name          = 'comboBodyType'
        Width         = 160
        DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    }
    $script:comboBodyType.Items.AddRange(@("multipart/form-data", "application/json", "application/xml", "text/plain", "application/x-www-form-urlencoded", "GraphQL"))
    $script:comboBodyType.SelectedIndex = 0 # Default to form-data

    $checkIncludeFilename = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Include 'filename'"; AutoSize = $true; Checked = $script:settings.IncludeFilename; Margin = [System.Windows.Forms.Padding]::new(10, 3, 0, 0) }
    $toolTip.SetToolTip($checkIncludeFilename, "If checked, includes the 'filename' attribute in the multipart request part, which is standard for file uploads.")

    $checkIncludeContentType = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Include 'type'"; AutoSize = $true; Checked = $script:settings.IncludeContentType; Margin = [System.Windows.Forms.Padding]::new(10, 3, 0, 0) }
    $toolTip.SetToolTip($checkIncludeContentType, "If checked, automatically determines and includes the Content-Type for the file part (e.g., 'application/pdf').")
    
    $bodyTopPanel.Controls.AddRange(@($labelBodyType, $script:comboBodyType, $checkIncludeFilename, $checkIncludeContentType))

    $panelBodyLabel = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Top'; Height = 35; Padding = [System.Windows.Forms.Padding]::new(5, 0, 5, 0) }

    $labelBody = New-Label -Text "Body (key=value per line. Press 'Alt + @' to add a file):" -Property @{ Dock = 'Fill'; TextAlign = 'MiddleLeft' }
    
    $panelBodyLabel.Controls.Add($labelBody)

    $script:textBody = New-TextBox -Multiline $true -Property @{
        Name       = 'textBody'
        Dock       = 'Fill'
        ScrollBars = "Both"
        BorderStyle = 'None'
    }

    # Helper function to re-evaluate and update all file lines in the body text
    function Apply-Attributes-To-AllFileLines {
        $lines = $script:textBody.Text.Split([string[]]@("`r`n", "`n"), [StringSplitOptions]::None)
        $updatedLines = foreach ($line in $lines) {
            $trimmedLine = $line.Trim()
            # Regex to capture key, file path (quoted or not), and then optional attributes
            if ($trimmedLine -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                $key = $matches[1].Trim()
                $filePath = if ($matches[3]) { $matches[3] } else { $matches[4] } # Correctly get path if quoted (group 3) or not (group 4)
                $fileString = "@`"$filePath`""

                if ($checkIncludeFilename.Checked) {
                    $fileName = [System.IO.Path]::GetFileName($filePath)
                    $fileString += ";filename=$fileName"
                }
                if ($checkIncludeContentType.Checked) {
                    $mimeType = Get-MimeType -filePath $filePath
                    $fileString += ";type=$mimeType"
                }
                "$key=$fileString"
            } else { $line } # Return non-file lines unchanged
        } # End of foreach ($line in $lines)
        $script:textBody.Text = $updatedLines -join [System.Environment]::NewLine
    }
    # Add KeyDown event to Body textbox to handle file selection with Alt+@
    $script:textBody.Add_KeyDown({
        param($sender, $e)
        if ($e.Alt -and $e.KeyCode -eq [System.Windows.Forms.Keys]::D2 -and $script:comboBodyType.SelectedItem -eq "multipart/form-data") {
            # Alt+Shift+2 produces @ character
            $e.SuppressKeyPress = $true
            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $openFileDialog.Filter = "All files (*.*)|*.*"
            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                # Find the start of the current line to get the key
                $lineStart = $sender.Text.LastIndexOf("`n", [Math]::Max(0, $sender.SelectionStart - 1)) + 1
                $currentLine = $sender.Text.Substring($lineStart, $sender.SelectionStart - $lineStart)
                $key = ($currentLine -split '=')[0].Trim()

                # Format the file path string, including optional attributes
                $fullPath = $openFileDialog.FileName
                $fileString = "@`"$fullPath`""

                if ($checkIncludeFilename.Checked) {
                    $fileName = [System.IO.Path]::GetFileName($fullPath)
                    $fileString += ";filename=$fileName"
                }
                if ($checkIncludeContentType.Checked) {
                    $mimeType = Get-MimeType -filePath $fullPath
                    $fileString += ";type=$mimeType"
                }

                $currentPos = $sender.SelectionStart
                $sender.Text = $sender.Text.Insert($currentPos, $fileString)
                $sender.SelectionStart = $currentPos + $fileString.Length
                Write-Log "File string inserted: $fileString"
            }
        }
    })

    # --- GraphQL Controls ---
    $script:panelGraphQL = New-Object System.Windows.Forms.Panel -Property @{ Dock='Fill'; Visible=$false }
    $splitGraphQL = New-Object System.Windows.Forms.SplitContainer -Property @{ Dock='Fill'; Orientation='Vertical'; SplitterDistance=260 }
    
    $lblGqlQuery = New-Label -Text "Query:" -Property @{ Dock='Top' }
    $script:txtGqlQuery = New-TextBox -Multiline $true -Property @{ Dock='Fill'; ScrollBars='Vertical'; Font=New-Object System.Drawing.Font("Courier New", 9) }
    
    $lblGqlVars = New-Label -Text "Variables (JSON):" -Property @{ Dock='Top' }
    $script:txtGqlVars = New-TextBox -Multiline $true -Property @{ Dock='Fill'; ScrollBars='Vertical'; Font=New-Object System.Drawing.Font("Courier New", 9) }
    
    $splitGraphQL.Panel1.Controls.Add($script:txtGqlQuery)
    $splitGraphQL.Panel1.Controls.Add($lblGqlQuery)
    $splitGraphQL.Panel2.Controls.Add($script:txtGqlVars)
    $splitGraphQL.Panel2.Controls.Add($lblGqlVars)
    $script:panelGraphQL.Controls.Add($splitGraphQL)

    $tabRequestBody.Controls.AddRange(@($script:textBody, $script:panelGraphQL, $panelBodyLabel, $bodyTopPanel))

    $tabRequestHeaders = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Headers"; Padding = [System.Windows.Forms.Padding]::new(5) }

    $labelHeaders = New-Label -Text "Headers (key:value per line):" -Property @{ Dock = 'Top'; Height = 25; TextAlign = 'MiddleLeft' }
    $script:textHeaders = New-TextBox -Multiline $true -Property @{
        Name       = 'textHeaders'
        Dock       = 'Fill'
        ScrollBars = "Both"
    }
    $tabRequestHeaders.Controls.AddRange(@($script:textHeaders, $labelHeaders))

    $tabPreRequest = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Pre-request"; Padding = [System.Windows.Forms.Padding]::new(5) }
    $labelPreRequest = New-Label -Text "PowerShell script to run before request. Access environment via `$Environment." -Property @{ Dock = 'Top'; Height = 25; TextAlign = 'MiddleLeft' }
    $script:textPreRequest = New-TextBox -Multiline $true -Property @{
        Name       = 'textPreRequest'
        Dock       = 'Fill'
        Font       = New-Object System.Drawing.Font("Courier New", 9)
        ScrollBars = "Both"
    }
    $tabPreRequest.Controls.AddRange(@($script:textPreRequest, $labelPreRequest))

    $tabRequestTests = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Tests"; Padding = [System.Windows.Forms.Padding]::new(5) }

    # --- Tests Snippets Library (Sidebar) ---
    $script:testSnippets = @(
        [PSCustomObject]@{ Name = "Check Status 200"; Code = "Assert-StatusIs -StatusCode `$statusCode -ExpectedStatus 200" }
        [PSCustomObject]@{ Name = "Check Status 201"; Code = "Assert-StatusIs -StatusCode `$statusCode -ExpectedStatus 201" }
        [PSCustomObject]@{ Name = "Check JSON Value"; Code = "Assert-Equal -Value `$jsonBody.path.to.value -Expected `"expected`"" }
        [PSCustomObject]@{ Name = "Check Body Contains"; Code = "Assert-Contains -String `$body -Substring `"expected substring`"" }
        [PSCustomObject]@{ Name = "Header Exists"; Code = "Assert-Contains -String (`$headers.Keys -join `",`") -Substring `"Header-Name`"" }
        [PSCustomObject]@{ Name = "Check JSON Exists"; Code = "if (-not `$jsonBody) { `$script:testResults.Add([PSCustomObject]@{ Status='FAIL'; Message='Response body is not valid JSON.' }) }" }
    )

    $testsSplit = New-Object System.Windows.Forms.SplitContainer
    $testsSplit.Dock = 'Fill'
    $testsSplit.Orientation = 'Vertical'
    $testsSplit.SplitterDistance = 220
    $testsSplit.Panel1MinSize = 160
    $testsSplit.BackColor = $script:Theme.FormBackground

    $snippetsGroup = New-Object System.Windows.Forms.GroupBox -Property @{
        Text = "Snippets"
        Dock = 'Fill'
        Padding = [System.Windows.Forms.Padding]::new(8)
        BackColor = $script:Theme.GroupBackground
    }

    $snippetsLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        RowCount = 2
    }
    $snippetsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $snippetsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $listSnippets = New-Object System.Windows.Forms.ListBox -Property @{
        Dock = 'Fill'
    }
    $listSnippets.Items.AddRange($script:testSnippets.Name)

    $btnInsertSnippet = New-Button -Text "Insert" -Style 'Secondary' -Property @{
        Dock = 'Fill'
        Height = 30
        Margin = [System.Windows.Forms.Padding]::new(0, 6, 0, 0)
    } -OnClick {
        if ($listSnippets.SelectedIndex -lt 0) { return }
        $code = $script:testSnippets[$listSnippets.SelectedIndex].Code
        $pos = $script:textTests.SelectionStart
        $prefix = ""
        if ($pos -gt 0 -and $script:textTests.Text[$pos - 1] -ne "`n") { $prefix = "`r`n" }
        $insertText = "$prefix$code"
        $script:textTests.Text = $script:textTests.Text.Insert($pos, $insertText)
        $script:textTests.SelectionStart = $pos + $insertText.Length
        $script:textTests.Focus()
    }

    $listSnippets.Add_DoubleClick({ $btnInsertSnippet.PerformClick() })

    $snippetsLayout.Controls.Add($listSnippets, 0, 0)
    $snippetsLayout.Controls.Add($btnInsertSnippet, 0, 1)
    $snippetsGroup.Controls.Add($snippetsLayout)
    $testsSplit.Panel1.Controls.Add($snippetsGroup)

    # --- Tests Editor (Right Panel) ---
    $testsEditorLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        RowCount = 2
    }
    $testsEditorLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $testsEditorLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $labelTests = New-Label -Text "PowerShell tests to run against the response. Use variables like `$statusCode, `$body, `$jsonBody." -Property @{ Dock = 'Top'; Height = 25; TextAlign = 'MiddleLeft' }
    $script:textTests = New-TextBox -Multiline $true -Property @{
        Name       = 'textTests'
        Dock       = 'Fill'
        Font       = New-Object System.Drawing.Font("Courier New", 9)
        ScrollBars = "Both"
    }
    $toolTip.SetToolTip($script:textTests, "Example: Assert-Equal -Value `$statusCode -Expected 200")

    $testsEditorLayout.Controls.Add($labelTests, 0, 0)
    $testsEditorLayout.Controls.Add($script:textTests, 0, 1)
    $testsSplit.Panel2.Controls.Add($testsEditorLayout)

    $tabRequestTests.Controls.Add($testsSplit)

    # Create the main authentication panel for the request and get the tab page from it
    $script:authPanel = New-AuthPanel #FIX: Corrected function call
    $tabAuth = $script:authPanel.Tab

    # The main "Send Request" button. Its click handler orchestrates the entire API call process.
    $btnSubmit = New-Button -Text "Send Request" -Style 'Primary' -OnClick { #FIX: Corrected button creation
        $btnSubmit.Enabled = $false
        $btnCancel.Enabled = $true
        $btnRepeat.Enabled = $false
        Invoke-RequestExecution
    } -Property @{ Size = New-Object System.Drawing.Size(165, 40); Margin = [System.Windows.Forms.Padding]::new(0,0,10,0) }

    # Button to repeat the request after receiving response
    $btnRepeat = New-Button -Text "Repeat" -OnClick {
        if ($script:settings.EnableRepeatRequest -eq $false) {
            [System.Windows.Forms.MessageBox]::Show("Repeat Request is not enabled. Enable it in Settings > Configuration > Enable Repeat Request.", "Feature Disabled", "OK", "Information")
            return
        }
        
        $repeatCount = [int][Microsoft.VisualBasic.Interaction]::InputBox("Enter number of times to repeat the request:`n(Max: $($script:settings.MaxRepeatCount))", "Repeat Request", "1")
        
        if ($repeatCount -le 0) { 
            [System.Windows.Forms.MessageBox]::Show("Please enter a positive number.", "Invalid Input", "OK", "Warning")
            return 
        }
        
        if ($repeatCount -gt $script:settings.MaxRepeatCount) {
            [System.Windows.Forms.MessageBox]::Show("Number of repeats exceeds maximum allowed ($($script:settings.MaxRepeatCount)).", "Limit Exceeded", "OK", "Warning")
            return
        }
        
        $script:repeatCount = $repeatCount
        $script:currentRepeatIteration = 0
        $script:repeatSuccessCount = 0
        $script:repeatFailCount = 0
        $script:isRepeating = $true
        
        Write-Log "Starting repeat request: $repeatCount iterations" -Level Debug
        
        # Manually trigger the request execution instead of clicking the button
        # This avoids UI race conditions where the button might be disabled.
        $btnSubmit.Enabled = $false
        $btnCancel.Enabled = $true
        $btnRepeat.Enabled = $false
        Invoke-RequestExecution
    } -Property @{ Size = New-Object System.Drawing.Size(165, 40); Margin = [System.Windows.Forms.Padding]::new(0,0,10,0) }

    # Button to stop the currently running background job.
    $btnCancel = New-Button -Text "Cancel" -OnClick {
        if ($script:currentPowerShell) {
            Write-Log "Cancel button clicked. Stopping pipeline."
            try { $script:currentPowerShell.Stop() } catch {}
        }
        $script:isRepeating = $false
    } -Property @{ Size = New-Object System.Drawing.Size(165, 40); Enabled = $false; Margin = [System.Windows.Forms.Padding]::new(0,0,10,0) }

    $panelOutputButtons = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
        Dock = 'Fill'
        FlowDirection = 'LeftToRight'
    }
    $panelOutputButtons.Controls.AddRange(@($btnSubmit, $btnRepeat, $btnCancel))
    
    $panelOutputActions.Controls.Add($panelOutputButtons)

    $form.Tag = [PSCustomObject]@{
        btnSubmit = $btnSubmit
        btnCancel = $btnCancel
        btnRepeat = $btnRepeat
    }

    # GroupBox that contains all the response-related tabs.
    $groupResponse = New-Object System.Windows.Forms.GroupBox -Property @{ #FIX: Corrected GroupBox creation
        Anchor    = "Top, Bottom, Left, Right"
        Text      = "Response"
        Padding   = [System.Windows.Forms.Padding]::new(5)
        BackColor = $script:Theme.GroupBackground
    }

    # Context menu for the response panel to allow undocking
    $responsePanelContextMenu = New-Object System.Windows.Forms.ContextMenuStrip    
    $dockingMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Docking Options")

    # Helper function to set and save the dock state
    $setDockState = {
        param([string]$newState)
        # If the new state is different, or if we are toggling off the 'Undocked' state
        if ($script:responseDockState -ne $newState -or ($script:responseDockState -eq 'Undocked' -and $newState -eq 'Undocked')) {
            # If currently docked, save the state before undocking
            if ($script:responseDockState -ne 'Undocked') {
                $script:lastDockState = $script:responseDockState
            }
 
            # If we are clicking 'Undocked' while already undocked, re-dock to the last state
            if ($script:responseDockState -eq 'Undocked' -and $newState -eq 'Undocked') {
                $newState = $script:lastDockState
            }
 
            $script:responseDockState = $newState
            $script:settings.ResponseDockState = $newState
            Save-Settings
            Update-Layout
        }
    }
    $dockBottomMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Dock to Bottom", $null, { & $setDockState 'Bottom' })
    $dockLeftMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Dock to Left", $null, { & $setDockState 'Left' })
    $dockRightMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Dock to Right", $null, { & $setDockState 'Right' })
    $undockMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Undock Panel", $null, { & $setDockState 'Undocked' })

    $dockingMenuItem.DropDownItems.AddRange(@($dockBottomMenuItem, $dockLeftMenuItem, $dockRightMenuItem, (New-Object System.Windows.Forms.ToolStripSeparator), $undockMenuItem))
    $responsePanelContextMenu.Items.Add($dockingMenuItem)
    $groupResponse.ContextMenuStrip = $responsePanelContextMenu

    # Generates a code snippet string based on a request object.
    function Generate-CodeSnippet {
        param(
            [PSCustomObject]$RequestItem,
            [string]$Language = "cURL"
        )
        if (-not $RequestItem) { return "" }

        $method = $RequestItem.Method
        $url = $RequestItem.Url
        $headersRaw = $RequestItem.Headers
        $bodyRaw = $RequestItem.Body
        $bodyType = $RequestItem.BodyType

        # Parse headers
        $headers = @{}
        foreach ($line in $headersRaw -split "`n") {
            if ($line -match "^\s*(.+?):\s*(.+)$") {
                $headers[$matches[1]] = $matches[2]
            }
        }

        $sb = New-Object System.Text.StringBuilder

        switch ($Language) {
            "cURL" {
                $curlParts = @("curl -X '$method' \")
                foreach ($key in $headers.Keys) {
                    $curlParts += "  -H '$($key): $($headers[$key])' \"
                }

                if ($bodyType -eq "multipart/form-data") {
                    if (-not $headers.ContainsKey("Content-Type")) {
                        $curlParts += "  -H 'Content-Type: multipart/form-data' \"
                    }
                    foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                        if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                            $key = $matches[1].Trim()
                            if ($matches[3]) { $filePath = $matches[3] } else { $filePath = $matches[4] }
                            $attributes = $matches[5]
                            $curlParts += "  -F '$key=@$filePath$attributes' \"
                        } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                            $key = $matches[1].Trim()
                            $value = $matches[2].Trim()
                            $curlParts += "  -F '$key=$value' \"
                        }
                    }
                } else {
                if (-not $headers.ContainsKey("Content-Type")) { 
                    if ($bodyRaw) { $rawContentType = $bodyType } else { $rawContentType = 'text/plain' }
                    $curlParts += "  -H 'Content-Type: $rawContentType' \" 
                }
                    if ($bodyRaw) { $curlParts += "  -d '$($bodyRaw -replace "'", "'\''")' \" }
                }
                $curlParts += "  '$url'"
                return ($curlParts -join "`n").TrimEnd(' \')
            }
            "PowerShell" {
                $sb.AppendLine("`$headers = @{") | Out-Null
                foreach ($key in $headers.Keys) {
                    $sb.AppendLine("    '$key' = '$($headers[$key])'") | Out-Null
                }
                $sb.AppendLine("}") | Out-Null
                $sb.AppendLine("") | Out-Null
                
                $params = "-Method $method -Uri '$url' -Headers `$headers"
                
                if ($bodyRaw) {
                    $sb.AppendLine("`$body = @'") | Out-Null
                    $sb.AppendLine($bodyRaw) | Out-Null
                    $sb.AppendLine("'@") | Out-Null
                    $params += " -Body `$body"
                    if (-not $headers.ContainsKey("Content-Type") -and $bodyType -ne 'multipart/form-data') {
                         $params += " -ContentType '$bodyType'"
                    }
                }
                $sb.AppendLine("Invoke-RestMethod $params") | Out-Null
                return $sb.ToString()
            }
            "Python" {
                $sb.AppendLine("import requests") | Out-Null
                $sb.AppendLine("") | Out-Null
                $sb.AppendLine("url = '$url'") | Out-Null
                $sb.AppendLine("headers = {") | Out-Null
                foreach ($key in $headers.Keys) {
                    if ($key -ne "Content-Type") {
                        $sb.AppendLine("    '$key': '$($headers[$key])',") | Out-Null
                    }
                }
                $sb.AppendLine("}") | Out-Null
                
                if ($bodyType -eq "multipart/form-data") {
                    $sb.AppendLine("files = [") | Out-Null
                    foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                        if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                            $key = $matches[1].Trim()
                            $path = if ($matches[3]) { $matches[3] } else { $matches[4] }
                            $attrs = $matches[5]
                            $fn = [System.IO.Path]::GetFileName($path)
                            $ct = $null
                            if ($attrs -match 'filename=([^;]+)') { $fn = $matches[1] }
                            if ($attrs -match 'type=([^;]+)') { $ct = $matches[1] }
                            $tuple = "('$key', ('$fn', open(r'$path', 'rb')"
                            if ($ct) { $tuple += ", '$ct'" }
                            $tuple += "))"
                            $sb.AppendLine("  $tuple,") | Out-Null
                        } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                            $key = $matches[1].Trim()
                            $val = $matches[2].Trim()
                            $sb.AppendLine("  ('$key', (None, '$val')),") | Out-Null
                        }
                    }
                    $sb.AppendLine("]") | Out-Null
                    $sb.AppendLine("response = requests.request('$method', url, headers=headers, files=files)") | Out-Null
                } else {
                    if ($bodyRaw) {
                        $sb.AppendLine("payload = '''$bodyRaw'''") | Out-Null
                        $sb.AppendLine("response = requests.request('$method', url, headers=headers, data=payload)") | Out-Null
                    } else {
                        $sb.AppendLine("response = requests.request('$method', url, headers=headers)") | Out-Null
                    }
                }
                $sb.AppendLine("print(response.text)") | Out-Null
                return $sb.ToString()
            }
            "JavaScript" {
                $sb.AppendLine("const myHeaders = new Headers();") | Out-Null
                foreach ($key in $headers.Keys) {
                    if ($key -ne "Content-Type") {
                        $sb.AppendLine("myHeaders.append('$key', '$($headers[$key])');") | Out-Null
                    }
                }
                $sb.AppendLine("") | Out-Null
                
                if ($bodyType -eq "multipart/form-data") {
                    $sb.AppendLine("const formdata = new FormData();") | Out-Null
                    foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                        if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                            $key = $matches[1].Trim()
                            $path = if ($matches[3]) { $matches[3] } else { $matches[4] }
                            $attrs = $matches[5]
                            $fn = [System.IO.Path]::GetFileName($path)
                            if ($attrs -match 'filename=([^;]+)') { $fn = $matches[1] }
                            $sb.AppendLine("formdata.append('$key', fileInput.files[0], '$fn');") | Out-Null
                        } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                            $key = $matches[1].Trim()
                            $val = $matches[2].Trim()
                            $sb.AppendLine("formdata.append('$key', '$val');") | Out-Null
                        }
                    }
                    $sb.AppendLine("") | Out-Null
                    $sb.AppendLine("const requestOptions = {") | Out-Null
                    $sb.AppendLine("  method: '$method',") | Out-Null
                    $sb.AppendLine("  headers: myHeaders,") | Out-Null
                    $sb.AppendLine("  body: formdata,") | Out-Null
                    $sb.AppendLine("  redirect: 'follow'") | Out-Null
                    $sb.AppendLine("};") | Out-Null
                } else {
                    $sb.AppendLine("const requestOptions = {") | Out-Null
                    $sb.AppendLine("  method: '$method',") | Out-Null
                    $sb.AppendLine("  headers: myHeaders,") | Out-Null
                    if ($bodyRaw) {
                        $sb.AppendLine("  body: `$(`"$bodyRaw`"),") | Out-Null
                    }
                    $sb.AppendLine("  redirect: 'follow'") | Out-Null
                    $sb.AppendLine("};") | Out-Null
                }
                $sb.AppendLine("") | Out-Null
                $sb.AppendLine("fetch('$url', requestOptions)") | Out-Null
                $sb.AppendLine("  .then(response => response.text())") | Out-Null
                $sb.AppendLine("  .then(result => console.log(result))") | Out-Null
                $sb.AppendLine("  .catch(error => console.error('error', error));") | Out-Null
                return $sb.ToString()
            }
            "C#" {
                $sb.AppendLine("var client = new HttpClient();") | Out-Null
                $sb.AppendLine("var request = new HttpRequestMessage(new HttpMethod(`"$method`"), `"$url`");") | Out-Null
                foreach ($key in $headers.Keys) {
                    if ($key -ne "Content-Type") {
                        $sb.AppendLine("request.Headers.Add(`"$key`", `"$($headers[$key])`");") | Out-Null
                    }
                }
                if ($bodyType -eq "multipart/form-data") {
                    $sb.AppendLine("var content = new MultipartFormDataContent();") | Out-Null
                    foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                        if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                            $key = $matches[1].Trim(); $path = if ($matches[3]) { $matches[3] } else { $matches[4] }; $fn = [System.IO.Path]::GetFileName($path); $safePath = $path.Replace('\', '\\')
                            $sb.AppendLine("content.Add(new StreamContent(File.OpenRead(`"$safePath`")), `"$key`", `"$fn`");") | Out-Null
                        } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                            $key = $matches[1].Trim(); $val = $matches[2].Trim()
                            $sb.AppendLine("content.Add(new StringContent(`"$val`"), `"$key`");") | Out-Null
                        }
                    }
                    $sb.AppendLine("request.Content = content;") | Out-Null
                } elseif ($bodyRaw) {
                    $mediaType = if ($headers.ContainsKey("Content-Type")) { $headers["Content-Type"] } elseif ($bodyType) { $bodyType } else { "text/plain" }
                    $safeBody = $bodyRaw.Replace('\', '\\').Replace('"', '\"')
                    $sb.AppendLine("var content = new StringContent(`"$safeBody`", null, `"$mediaType`");") | Out-Null
                    $sb.AppendLine("request.Content = content;") | Out-Null
                }
                $sb.AppendLine("var response = await client.SendAsync(request);") | Out-Null
                $sb.AppendLine("response.EnsureSuccessStatusCode();") | Out-Null
                $sb.AppendLine("Console.WriteLine(await response.Content.ReadAsStringAsync());") | Out-Null
                return $sb.ToString()
            }
        }
        return ""
    }

    # Helper to populate JSON TreeView
    function Populate-JsonTree {
        param($JsonData, $NodesCollection)
        $NodesCollection.Clear()
        $NodesCollection.Owner.BeginUpdate()
        
        function Add-Node {
            param($ParentNodes, $Obj, $Name)
            $nodeText = if ($Name) { "$Name" } else { "Item" }
            $tag = [PSCustomObject]@{ Key = $Name; Value = $Obj }
            
            if ($Obj -eq $null) {
                $newNode = New-Object System.Windows.Forms.TreeNode("${nodeText}: null")
                $newNode.Tag = $tag
                $ParentNodes.Add($newNode) | Out-Null
            } elseif ($Obj -is [PSCustomObject] -or $Obj -is [hashtable]) {
                $newNode = New-Object System.Windows.Forms.TreeNode($nodeText)
                $newNode.Tag = $tag
                $ParentNodes.Add($newNode) | Out-Null
                $props = if ($Obj -is [hashtable]) { $Obj.Keys } else { $Obj.PSObject.Properties.Name }
                foreach ($prop in $props) { Add-Node -ParentNodes $newNode.Nodes -Obj $Obj.$prop -Name $prop }
            } elseif ($Obj -is [array] -or $Obj -is [System.Collections.ICollection]) {
                $newNode = New-Object System.Windows.Forms.TreeNode("$nodeText [$($Obj.Count)]")
                $newNode.Tag = $tag
                $ParentNodes.Add($newNode) | Out-Null
                for ($i=0; $i -lt $Obj.Count; $i++) { Add-Node -ParentNodes $newNode.Nodes -Obj $Obj[$i] -Name "[$i]" }
            } else {
                $newNode = New-Object System.Windows.Forms.TreeNode("${nodeText}: $Obj")
                $newNode.Tag = $tag
                $ParentNodes.Add($newNode) | Out-Null
            }
        }

        try { Add-Node -ParentNodes $NodesCollection -Obj $JsonData -Name "Root" } catch {}
        if ($NodesCollection.Count -gt 0) { $NodesCollection[0].Expand() }
        $NodesCollection.Owner.EndUpdate()
    }

    $tabControlResponse = New-Object System.Windows.Forms.TabControl -Property @{
        Dock = [System.Windows.Forms.DockStyle]::Fill
    }

    $tabResponse = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Response"; BorderStyle = 'None' }
    
    # Refactored: Use a FlowLayoutPanel to match Body layout
    $responseToolsPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ 
        Dock = 'Top'
        Padding = [System.Windows.Forms.Padding]::new(2, 2, 2, 2)
        AutoSize = $true #FIX: Corrected property name
        AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        WrapContents = $false
    }

    $script:btnPrettifyResponse = New-Button -Text "Prettify" -Property @{ 
        Width = 100
        Height = 35
        Enabled = $false
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0) #FIX: Corrected margin
    } -OnClick {
        try {
            if ($script:lastResponseContentType -like 'application/json*') {
                $jsonObj = $richTextResponse.Text | ConvertFrom-Json -ErrorAction Stop
                $richTextResponse.Rtf = Format-JsonAsRtf -JsonString ($jsonObj | ConvertTo-Json -Depth 10 -ErrorAction Stop) -FontSize $script:settings.ResponseFontSize
            } elseif ($script:lastResponseContentType -like 'application/xml*' -or $script:lastResponseContentType -like 'text/xml*') {
                # Use XmlWriter to properly indent the XML
                $xmlDoc = New-Object System.Xml.XmlDocument
                $xmlDoc.LoadXml($richTextResponse.Text)
                $stringWriter = New-Object System.IO.StringWriter
                $xmlWriterSettings = New-Object System.Xml.XmlWriterSettings
                $xmlWriterSettings.Indent = $true
                $xmlWriter = [System.Xml.XmlWriter]::Create($stringWriter, $xmlWriterSettings)
                $xmlDoc.Save($xmlWriter)
                $xmlWriter.Close()
                $richTextResponse.Text = $stringWriter.ToString()
            } elseif ($script:lastResponseContentType -like 'text/html*') {
                # Use the MSHTML COM object to tidy up the HTML
                $html = New-Object -ComObject "HTMLFile"
                $html.IHTMLDocument2_write($richTextResponse.Text)
                $html.Close() # Close the document stream
                $prettyHtml = $html.documentElement.outerHTML
                $richTextResponse.Text = $prettyHtml
                # Also update the preview tab with the tidied HTML
                $webBrowserPreview.DocumentText = $prettyHtml
            }
        } catch { Write-Log "Could not prettify response content: $($_.Exception.Message)" -Level Info }
    }

    $script:btnExportResponse = New-Button -Text "Export" -Property @{ 
        Width = 100
        Height = 35
        Enabled = $false
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0) #FIX: Corrected margin
    } -OnClick {
        if ([string]::IsNullOrWhiteSpace($richTextResponse.Text)) { return }

        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Title = "Export Response Body"

        # Suggest a file extension based on the content type
        $extension = "txt"
        $filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
        if ($script:lastResponseContentType -like 'application/json*') {
            $extension = "json"; $filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
        } elseif ($script:lastResponseContentType -like '*xml*') {
            $extension = "xml"; $filter = "XML files (*.xml)|*.xml|All files (*.*)|*.*"
        } elseif ($script:lastResponseContentType -like '*html*') {
            $extension = "html"; $filter = "HTML files (*.html)|*.html|All files (*.*)|*.*"
        }
        $saveFileDialog.DefaultExt = $extension
        $saveFileDialog.Filter = $filter
        $saveFileDialog.FileName = "response.$extension"

        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $richTextResponse.Text | Set-Content -Path $saveFileDialog.FileName -Encoding UTF8 -ErrorAction Stop
                Write-Log "Response body exported to $($saveFileDialog.FileName)" -Level Info
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to export response body: $($_.Exception.Message)", "Export Error", "OK", "Error")
                Write-Log "Failed to export response body: $($_.Exception.Message)" -Level Info
            }
        }
    }

    $script:btnGoToLine = New-Button -Text "Go To" -Property @{ 
        Width = 100
        Height = 35
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0) #FIX: Corrected margin
    } -OnClick {
        $lineStr = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Line Number:", "Go To Line", "1")
        if ([int]::TryParse($lineStr, [ref]$null)) {
            $line = [int]$lineStr
            if ($line -gt 0 -and $line -le $richTextResponse.Lines.Length) {
                $index = $richTextResponse.GetFirstCharIndexFromLine($line - 1)
                $richTextResponse.Select($index, 0)
                $richTextResponse.ScrollToCaret()
            }
        }
    }

    $script:btnToggleWordWrap = New-Button -Text "Wrap" -Property @{ 
        Width = 100
        Height = 35
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0) #FIX: Corrected margin
    } -OnClick {
        $richTextResponse.WordWrap = -not $richTextResponse.WordWrap
    }
    $toolTip.SetToolTip($script:btnToggleWordWrap, "Toggle Word Wrap")

    $script:btnFind = New-Button -Text "Find" -Property @{ 
        Width = 100
        Height = 35
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0)
    } -OnClick {
        $responseSearchPanel.Visible = -not $responseSearchPanel.Visible
        if ($responseSearchPanel.Visible) { $script:textSearchResponse.Focus() }
    }
    $toolTip.SetToolTip($script:btnFind, "Find text in response (Ctrl+F)")

    $script:btnExtractVariable = New-Button -Text "Extract" -Property @{
        Width = 100
        Height = 35
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0)
    } -OnClick {
        $responseExtractPanel.Visible = -not $responseExtractPanel.Visible
    }
    $toolTip.SetToolTip($script:btnExtractVariable, "Extract a value from the response into a variable")

    $toolTip.SetToolTip($script:btnPrettifyResponse, "Format the response content (JSON, XML, HTML).")
    $toolTip.SetToolTip($script:btnExportResponse, "Save the content of the response body to a file.")

    # Add controls to panel - Left-docked buttons first, then Right-docked
    # Add controls to panel
    $responseToolsPanel.Controls.AddRange(@($script:btnPrettifyResponse, $script:btnExportResponse, $script:btnToggleWordWrap, $script:btnGoToLine, $script:btnFind, $script:btnExtractVariable))
    
    # Refactored: Use a Panel with Docking strategy consistent with main layout
    $responseSearchPanel = New-Object System.Windows.Forms.Panel -Property @{ 
        Dock = 'Top'
        Height = 45
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5)
        Visible = $false
        BackColor = $script:Theme.GroupBackground
    }

    $script:textSearchResponse = New-TextBox -Property @{ 
        Dock = 'Fill'
        Text = "Find..." 
        ForeColor = [System.Drawing.Color]::Gray 
    }
    
    $script:textSearchResponse.Add_Enter({ 
        if ($script:textSearchResponse.Text -eq "Find...") { 
            $script:textSearchResponse.Text = ""; 
            $script:textSearchResponse.ForeColor = [System.Drawing.Color]::Black 
        } 
    })
    
    $script:textSearchResponse.Add_Leave({ 
        if ([string]::IsNullOrWhiteSpace($script:textSearchResponse.Text)) { 
            $script:textSearchResponse.Text = "Find..."; 
            $script:textSearchResponse.ForeColor = [System.Drawing.Color]::Gray 
            $script:labelSearchStatus.Text = ""
        } 
    })

    $script:btnSearchPrev = New-Button -Text "<" -Property @{ 
        Dock = 'Right'
        Width = 35 
        FlatStyle = 'Flat'
        TextAlign = 'MiddleCenter'
        Margin = [System.Windows.Forms.Padding]::new(5, 0, 0, 0) 
    }
    $toolTip.SetToolTip($script:btnSearchPrev, "Find Previous")
    $script:btnSearchNext = New-Button -Text ">" -Property @{ 
        Dock = 'Right'
        Width = 35 
        FlatStyle = 'Flat'
        TextAlign = 'MiddleCenter'
        Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0) 
    }
    $toolTip.SetToolTip($script:btnSearchNext, "Find Next")
    $script:checkSearchMatchCase = New-Object System.Windows.Forms.CheckBox -Property @{ 
        Text = "Aa"
        Dock = 'Right'
        Appearance = 'Button'
        AutoSize = $false 
        Width = 35 
        FlatStyle = 'Flat'
        TextAlign = 'MiddleCenter'
        Margin = [System.Windows.Forms.Padding]::new(5, 0, 0, 0)
    }
    $toolTip.SetToolTip($script:checkSearchMatchCase, "Match Case")

    $script:checkSearchWholeWord = New-Object System.Windows.Forms.CheckBox -Property @{ 
        Text = "WW"
        Dock = 'Right'
        Appearance = 'Button'
        AutoSize = $false 
        Width = 35 
        FlatStyle = 'Flat'
        TextAlign = 'MiddleCenter'
        Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0)
    }
    $toolTip.SetToolTip($script:checkSearchWholeWord, "Match Whole Word Only")

    $script:labelSearchStatus = New-Label -Text "" -Property @{ 
        Dock = 'Right'
        AutoSize = $true 
        TextAlign = 'MiddleLeft'
        Margin = [System.Windows.Forms.Padding]::new(10, 0, 10, 0)
    }

    function Get-ResponseSearchMatches {
        param([string]$SearchText)
        if ([string]::IsNullOrWhiteSpace($SearchText) -or $SearchText -eq "Find...") { return @() }

        $escaped = [regex]::Escape($SearchText)
        if ($script:checkSearchWholeWord.Checked) {
            $wordChars = "A-Za-z0-9_-"
            $pattern = "(?<![$wordChars])$escaped(?![$wordChars])"
        } else {
            $pattern = $escaped
        }

        $options = [System.Text.RegularExpressions.RegexOptions]::None
        if (-not $script:checkSearchMatchCase.Checked) {
            $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        }

        return @([regex]::Matches($richTextResponse.Text, $pattern, $options))
    }

    function Apply-ResponseSearchHighlights {
        param(
            [array]$Matches,
            [int]$CurrentIndex
        )
        # Preserve current selection
        $currentSelStart = $richTextResponse.SelectionStart
        $currentSelLength = $richTextResponse.SelectionLength

        $richTextResponse.SuspendLayout()
        # Clear previous highlights
        $richTextResponse.SelectAll()
        $richTextResponse.SelectionBackColor = [System.Drawing.Color]::Empty
        $richTextResponse.DeselectAll()

        if ($Matches -and $Matches.Count -gt 0) {
            for ($i = 0; $i -lt $Matches.Count; $i++) {
                $m = $Matches[$i]
                $richTextResponse.Select($m.Index, $m.Length)
                $richTextResponse.SelectionBackColor = if ($i -eq $CurrentIndex) { [System.Drawing.Color]::Orange } else { [System.Drawing.Color]::Yellow }
            }
        }

        # Restore selection
        $richTextResponse.Select($currentSelStart, $currentSelLength)
        $richTextResponse.ResumeLayout()
    }

    $searchHandler = {
        $searchText = $script:textSearchResponse.Text

        if ($searchText -ne "Find..." -and -not [string]::IsNullOrEmpty($searchText)) {
            $matches = Get-ResponseSearchMatches -SearchText $searchText
            $script:responseSearchMatches = $matches
            $script:responseSearchCurrentIndex = if ($matches.Count -gt 0) { 0 } else { -1 }

            if ($matches.Count -gt 0) {
                Apply-ResponseSearchHighlights -Matches $matches -CurrentIndex $script:responseSearchCurrentIndex

                $script:labelSearchStatus.Text = "$($matches.Count) Found"
                $script:labelSearchStatus.ForeColor = [System.Drawing.Color]::Green
                # Scroll to the first match
                $richTextResponse.Select($matches[0].Index, 0)
                $richTextResponse.ScrollToCaret()
            } else {
                $script:labelSearchStatus.Text = "0 Found"
                $script:labelSearchStatus.ForeColor = [System.Drawing.Color]::Red
                Apply-ResponseSearchHighlights -Matches @() -CurrentIndex -1
            }
        } else {
            $script:labelSearchStatus.Text = ""
            Apply-ResponseSearchHighlights -Matches @() -CurrentIndex -1
        }
        $script:textSearchResponse.Focus()
    }

    $script:textSearchResponse.Add_TextChanged($searchHandler)
    $script:checkSearchWholeWord.Add_CheckedChanged($searchHandler)
    $script:checkSearchMatchCase.Add_CheckedChanged($searchHandler)

    # Next/Prev Logic
    $findNextPrev = {
        param($direction) # 1 for Next, -1 for Prev
        $searchText = $script:textSearchResponse.Text
        if ($searchText -eq "Find..." -or [string]::IsNullOrEmpty($searchText)) { return }

        if (-not $script:responseSearchMatches -or $script:responseSearchMatches.Count -eq 0) {
            $script:responseSearchMatches = Get-ResponseSearchMatches -SearchText $searchText
        }

        $matches = $script:responseSearchMatches
        if ($matches.Count -eq 0) { return }

        $cursor = $richTextResponse.SelectionStart
        if ($direction -eq 1) {
            $cursor += [Math]::Max(1, $richTextResponse.SelectionLength)
        }

        if ($direction -eq 1) {
            $nextMatch = $matches | Where-Object { $_.Index -ge $cursor } | Select-Object -First 1
            if (-not $nextMatch) { $nextMatch = $matches[0] }
            $richTextResponse.Select($nextMatch.Index, $nextMatch.Length)
            $script:responseSearchCurrentIndex = [array]::IndexOf($matches, $nextMatch)
        } else {
            $prevMatch = $matches | Where-Object { $_.Index -lt $cursor } | Select-Object -Last 1
            if (-not $prevMatch) { $prevMatch = $matches[$matches.Count - 1] }
            $richTextResponse.Select($prevMatch.Index, $prevMatch.Length)
            $script:responseSearchCurrentIndex = [array]::IndexOf($matches, $prevMatch)
        }

        Apply-ResponseSearchHighlights -Matches $matches -CurrentIndex $script:responseSearchCurrentIndex
        $richTextResponse.ScrollToCaret()
        $richTextResponse.Focus() # Focus RTB to show selection
    }
    $script:btnSearchNext.Add_Click({ & $findNextPrev 1 })
    $script:btnSearchPrev.Add_Click({ & $findNextPrev -1 })

    $script:btnCloseSearch = New-Button -Text "X" -Property @{ 
        Dock = 'Right'
        Width = 35 
        FlatStyle = [System.Windows.Forms.FlatStyle]::Flat 
        ForeColor = [System.Drawing.Color]::Red 
        Margin = [System.Windows.Forms.Padding]::new(5, 0, 0, 0)
    } -OnClick {
        $responseSearchPanel.Visible = $false
        Apply-ResponseSearchHighlights -Matches @() -CurrentIndex -1
    }
    $toolTip.SetToolTip($script:btnCloseSearch, "Close Find Bar")

    # Add controls to panel - Fill first, then Right-docked controls in order
    $responseSearchPanel.Controls.AddRange(@($script:textSearchResponse, $script:labelSearchStatus, $script:checkSearchWholeWord, $script:checkSearchMatchCase, $script:btnSearchNext, $script:btnSearchPrev, $script:btnCloseSearch))

    # --- Response Extract Panel ---
    $responseExtractPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{
        Dock = 'Top'
        AutoSize = $true
        AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5)
        Visible = $false
        BackColor = $script:Theme.GroupBackground
        WrapContents = $true
    }

    $lblVarName = New-Label -Text "Var:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:textExtractVarName = New-TextBox -Property @{ Width = 120; Margin = [System.Windows.Forms.Padding]::new(0,3,10,0) }
    $lblVarBrowse = New-Label -Text "Pick:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:comboExtractVarBrowser = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 140; Margin = [System.Windows.Forms.Padding]::new(0,3,5,0) }
    $script:btnRefreshVarBrowser = New-Button -Text "Refresh" -Style 'Secondary' -Property @{ Width = 70; Height = 26; Margin = [System.Windows.Forms.Padding]::new(0,2,10,0) } -OnClick {
        if ($null -ne $updateExtractVarList) { & $updateExtractVarList }
    }
    $toolTip.SetToolTip($script:btnRefreshVarBrowser, "Refresh variable list")

    $lblScope = New-Label -Text "Scope:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:comboExtractScope = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 120; Margin = [System.Windows.Forms.Padding]::new(0,3,10,0) }
    $script:comboExtractScope.Items.AddRange(@("Global", "Collection", "Environment"))
    $script:comboExtractScope.SelectedIndex = 0

    $lblSource = New-Label -Text "Source:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:comboExtractSource = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 90; Margin = [System.Windows.Forms.Padding]::new(0,3,10,0) }
    $script:comboExtractSource.Items.AddRange(@("Body", "Headers"))
    $script:comboExtractSource.SelectedIndex = 0

    $lblMode = New-Label -Text "Mode:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:comboExtractMode = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 110; Margin = [System.Windows.Forms.Padding]::new(0,3,10,0) }
    $script:comboExtractMode.Items.AddRange(@("JSON Path", "Regex"))
    $script:comboExtractMode.SelectedIndex = 0

    $lblPath = New-Label -Text "Path/Regex:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,5,0) }
    $script:textExtractPath = New-TextBox -Property @{ Width = 220; Margin = [System.Windows.Forms.Padding]::new(0,3,10,0) }

    $updateExtractVarList = {
        $vars = @()
        switch ($script:comboExtractScope.SelectedItem) {
            "Global" {
                if ($script:globals) { $vars = $script:globals.Keys }
            }
            "Collection" {
                if ($script:activeCollectionNode -and $script:activeCollectionNode.Tag.Type -eq "Collection") {
                    if (-not ($script:activeCollectionNode.Tag.PSObject.Properties.Name -contains 'Variables')) {
                        $script:activeCollectionNode.Tag | Add-Member -MemberType NoteProperty -Name 'Variables' -Value @{}
                    }
                    if ($null -ne $script:activeCollectionNode.Tag.Variables) { $vars = $script:activeCollectionNode.Tag.Variables.Keys }
                }
            }
            "Environment" {
                if ($script:activeEnvironment -ne "No Environment" -and $script:environments.ContainsKey($script:activeEnvironment)) {
                    $envData = $script:environments[$script:activeEnvironment]
                    if ($envData -is [hashtable] -and $envData.ContainsKey('Variables')) { $vars = $envData['Variables'].Keys }
                    elseif ($envData.PSObject.Properties.Name -contains 'Variables') { $vars = $envData.Variables.Keys }
                }
            }
        }
        $script:comboExtractVarBrowser.Items.Clear()
        [void]$script:comboExtractVarBrowser.Items.Add("")
        foreach ($k in ($vars | Sort-Object)) { [void]$script:comboExtractVarBrowser.Items.Add($k) }
        $script:comboExtractVarBrowser.SelectedIndex = 0
        $script:comboExtractVarBrowser.Enabled = ($vars.Count -gt 0)
    }

    $script:comboExtractScope.Add_SelectedIndexChanged($updateExtractVarList)
    $script:comboExtractVarBrowser.Add_SelectedIndexChanged({
        $selected = $script:comboExtractVarBrowser.SelectedItem
        if ($selected -and $selected -ne "") { $script:textExtractVarName.Text = $selected }
    })
    & $updateExtractVarList

    $script:btnExtractSave = New-Button -Text "Extract & Save" -Style 'Primary' -Property @{ Width = 140; Height = 30; Margin = [System.Windows.Forms.Padding]::new(0,2,10,0) } -OnClick {
        $varName = $script:textExtractVarName.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($varName)) {
            $script:labelExtractStatus.Text = "Variable name is required."
            $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
            return
        }

        $source = $script:comboExtractSource.SelectedItem
        $mode = $script:comboExtractMode.SelectedItem
        $rawText = if ($source -eq "Headers") { $script:lastResponseHeadersText } else { $script:lastResponseText }
        if ([string]::IsNullOrWhiteSpace($rawText)) {
            $script:labelExtractStatus.Text = "No response content to extract."
            $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
            return
        }

        $extracted = $null
        if ($mode -eq "JSON Path") {
            if ($source -ne "Body") {
                $script:labelExtractStatus.Text = "JSON Path only supports Body source."
                $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                return
            }
            $path = $script:textExtractPath.Text.Trim()
            if ([string]::IsNullOrWhiteSpace($path)) {
                $script:labelExtractStatus.Text = "JSON path is required."
                $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                return
            }
            try {
                $jsonObj = $rawText | ConvertFrom-Json -ErrorAction Stop
                $value = Get-JsonPathValue -JsonObject $jsonObj -Path $path
                if ($null -eq $value) {
                    $script:labelExtractStatus.Text = "Path not found."
                    $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                    return
                }
                $extracted = if ($value -is [string]) { $value } else { $value | ConvertTo-Json -Depth 10 }
            } catch {
                $script:labelExtractStatus.Text = "Invalid JSON or path."
                $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                return
            }
        } else {
            $pattern = $script:textExtractPath.Text
            if ([string]::IsNullOrWhiteSpace($pattern)) {
                $script:labelExtractStatus.Text = "Regex pattern is required."
                $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                return
            }
            try {
                $m = [regex]::Match($rawText, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                if (-not $m.Success) {
                    $script:labelExtractStatus.Text = "No regex match."
                    $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                    return
                }
                if ($m.Groups.Count -gt 1 -and $m.Groups[1].Value) { $extracted = $m.Groups[1].Value } else { $extracted = $m.Value }
            } catch {
                $script:labelExtractStatus.Text = "Invalid regex."
                $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                return
            }
        }

        switch ($script:comboExtractScope.SelectedItem) {
            "Global" {
                $script:globals[$varName] = $extracted
                Save-Globals
            }
            "Collection" {
                if (-not $script:activeCollectionNode -or $script:activeCollectionNode.Tag.Type -ne "Collection") {
                    $script:labelExtractStatus.Text = "No active collection selected."
                    $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                    return
                }
                if (-not ($script:activeCollectionNode.Tag.PSObject.Properties.Name -contains 'Variables')) {
                    $script:activeCollectionNode.Tag | Add-Member -MemberType NoteProperty -Name 'Variables' -Value @{}
                }
                if ($null -eq $script:activeCollectionNode.Tag.Variables) { $script:activeCollectionNode.Tag.Variables = @{} }
                $script:activeCollectionNode.Tag.Variables[$varName] = $extracted
                $script:activeCollectionVariables = $script:activeCollectionNode.Tag.Variables
                Save-Collections
            }
            "Environment" {
                if ($script:activeEnvironment -eq "No Environment" -or -not $script:environments.ContainsKey($script:activeEnvironment)) {
                    $script:labelExtractStatus.Text = "No active environment selected."
                    $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Red
                    return
                }
                $envData = $script:environments[$script:activeEnvironment]
                if ($envData -is [hashtable]) {
                    if (-not $envData.ContainsKey('Variables')) { $envData['Variables'] = @{} }
                    if ($null -eq $envData['Variables']) { $envData['Variables'] = @{} }
                    $envData['Variables'][$varName] = $extracted
                    Save-Environments
                    $script:labelExtractStatus.Text = "Saved '$varName' to Environment."
                    $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Green
                    return
                } else {
                    if (-not ($envData.PSObject.Properties.Name -contains 'Variables')) { $envData | Add-Member -MemberType NoteProperty -Name 'Variables' -Value @{} }
                    if ($null -eq $envData.Variables) { $envData.Variables = @{} }
                    $envData.Variables[$varName] = $extracted
                }
                Save-Environments
            }
        }

        $script:labelExtractStatus.Text = "Saved '$varName' to $($script:comboExtractScope.SelectedItem)."
        $script:labelExtractStatus.ForeColor = [System.Drawing.Color]::Green
        & $updateExtractVarList
        if ($script:comboExtractVarBrowser.Items.Contains($varName)) { $script:comboExtractVarBrowser.SelectedItem = $varName }
    }

    $script:labelExtractStatus = New-Label -Text "" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0,6,0,0) }

    $responseExtractPanel.Controls.AddRange(@(
        $lblVarName, $script:textExtractVarName,
        $lblVarBrowse, $script:comboExtractVarBrowser, $script:btnRefreshVarBrowser,
        $lblScope, $script:comboExtractScope,
        $lblSource, $script:comboExtractSource,
        $lblMode, $script:comboExtractMode,
        $lblPath, $script:textExtractPath,
        $script:btnExtractSave, $script:labelExtractStatus
    ))

    $richTextResponse = New-RichTextBox -ReadOnly $true -Property @{ Dock = [System.Windows.Forms.DockStyle]::Fill; HideSelection = $false; DetectUrls = $true; BorderStyle = 'None' }
    $richTextResponse.Add_KeyDown({
        param($sender, $e)
        if ($e.Control -and $e.KeyCode -eq 'F') {
            $script:btnFind.PerformClick()
            $e.SuppressKeyPress = $true
        }
    })
    $richTextResponse.Add_LinkClicked({
        param($sender, $e)
        $linkText = $e.LinkText
        if ($linkText -match "^file:") {
            try {
                $uri = New-Object System.Uri $linkText
                $localPath = $uri.LocalPath
                if (Test-Path $localPath) {
                    Start-Process "explorer.exe" -ArgumentList "/select,`"$localPath`""
                }
            } catch { Write-Log "Failed to open file link: $($_.Exception.Message)" -Level Info }
        } else {
            try { Start-Process $linkText } catch { }
        }
    })
    $richTextResponse.ContextMenuStrip = New-CopyContextMenu -ParentControl $richTextResponse

    # Add Fill control last to prevent overlap from Top-docked panels.
    $tabResponse.Controls.AddRange(@($responseToolsPanel, $responseSearchPanel, $responseExtractPanel, $richTextResponse))

    $tabHeaders = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Response Headers" }
    $richTextResponseHeaders = New-RichTextBox -ReadOnly $true -Property @{ Dock = [System.Windows.Forms.DockStyle]::Fill; DetectUrls = $true; BorderStyle = 'None' }
    $richTextResponseHeaders.ContextMenuStrip = New-CopyContextMenu -ParentControl $richTextResponseHeaders
    $richTextResponseHeaders.Dock = [System.Windows.Forms.DockStyle]::Fill
    $tabHeaders.Controls.Add($richTextResponseHeaders)

    $tabJsonTree = New-Object System.Windows.Forms.TabPage -Property @{ Text = "JSON Tree" }
    
    # --- JSON Tree Search Panel ---
    $jsonTreeSearchPanel = New-Object System.Windows.Forms.Panel -Property @{ 
        Dock = 'Top'
        Height = 30
        Padding = [System.Windows.Forms.Padding]::new(2)
        BackColor = $script:Theme.GroupBackground
    }

    $textSearchJsonTree = New-TextBox -Property @{ 
        Dock = 'Fill'
        Text = "Search JSON..." 
        ForeColor = [System.Drawing.Color]::Gray 
    }
    
    $textSearchJsonTree.Add_Enter({ 
        if ($textSearchJsonTree.Text -eq "Search JSON...") { 
            $textSearchJsonTree.Text = ""; 
            $textSearchJsonTree.ForeColor = [System.Drawing.Color]::Black 
        } 
    })
    
    $textSearchJsonTree.Add_Leave({ 
        if ([string]::IsNullOrWhiteSpace($textSearchJsonTree.Text)) { 
            $textSearchJsonTree.Text = "Search JSON..."; 
            $textSearchJsonTree.ForeColor = [System.Drawing.Color]::Gray 
            $lblJsonTreeStatus.Text = ""
        } 
    })

    $lblJsonTreeStatus = New-Label -Text "" -Property @{ Dock = 'Right'; AutoSize = $true; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(5, 0, 5, 0) }

    $script:jsonTreeMatches = @()
    $script:jsonTreeCurrentIndex = -1

    $navigateJsonTreeSearch = {
        param($direction)
        if ($script:jsonTreeMatches.Count -eq 0) { return }
        $script:jsonTreeCurrentIndex += $direction
        if ($script:jsonTreeCurrentIndex -ge $script:jsonTreeMatches.Count) { $script:jsonTreeCurrentIndex = 0 }
        if ($script:jsonTreeCurrentIndex -lt 0) { $script:jsonTreeCurrentIndex = $script:jsonTreeMatches.Count - 1 }
        $node = $script:jsonTreeMatches[$script:jsonTreeCurrentIndex]
        $treeViewJson.SelectedNode = $node
        $node.EnsureVisible()
        $treeViewJson.Focus()
        $lblJsonTreeStatus.Text = "$($script:jsonTreeCurrentIndex + 1)/$($script:jsonTreeMatches.Count)"
    }

    $btnJsonTreeNext = New-Button -Text ">" -Property @{ Dock = 'Right'; Width = 30; FlatStyle = 'Flat'; TextAlign = 'MiddleCenter'; Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0) } -OnClick { & $navigateJsonTreeSearch 1 }
    $btnJsonTreePrev = New-Button -Text "<" -Property @{ Dock = 'Right'; Width = 30; FlatStyle = 'Flat'; TextAlign = 'MiddleCenter'; Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0) } -OnClick { & $navigateJsonTreeSearch -1 }

    $btnJsonTreeCollapse = New-Button -Text "-" -Property @{ Dock = 'Right'; Width = 30; FlatStyle = 'Flat'; TextAlign = 'MiddleCenter'; Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0) } -OnClick { $treeViewJson.CollapseAll() }
    $toolTip.SetToolTip($btnJsonTreeCollapse, "Collapse All")
    
    $btnJsonTreeExpand = New-Button -Text "+" -Property @{ Dock = 'Right'; Width = 30; FlatStyle = 'Flat'; TextAlign = 'MiddleCenter'; Margin = [System.Windows.Forms.Padding]::new(2, 0, 0, 0) } -OnClick { $treeViewJson.ExpandAll() }
    $toolTip.SetToolTip($btnJsonTreeExpand, "Expand All")

    $performJsonTreeSearch = {
        $term = $textSearchJsonTree.Text
        if ($term -eq "Search JSON..." -or [string]::IsNullOrWhiteSpace($term)) { return }
        $matches = New-Object System.Collections.ArrayList
        $recurse = {
            param($nodes)
            foreach ($node in $nodes) {
                if ($node.Text -like "*$term*") { [void]$matches.Add($node) }
                if ($node.Nodes.Count -gt 0) { & $recurse -nodes $node.Nodes }
            }
        }
        & $recurse -nodes $treeViewJson.Nodes
        $script:jsonTreeMatches = $matches
        $script:jsonTreeCurrentIndex = -1
        if ($matches.Count -gt 0) {
            $script:jsonTreeCurrentIndex = 0
            $node = $matches[0]
            $treeViewJson.SelectedNode = $node
            $node.EnsureVisible()
            $treeViewJson.Focus()
            $lblJsonTreeStatus.Text = "1/$($matches.Count)"; $lblJsonTreeStatus.ForeColor = [System.Drawing.Color]::Green
        } else { $lblJsonTreeStatus.Text = "0 found"; $lblJsonTreeStatus.ForeColor = [System.Drawing.Color]::Red }
    }

    $textSearchJsonTree.Add_KeyDown({ param($sender, $e) if ($e.KeyCode -eq 'Enter') { & $performJsonTreeSearch; $e.SuppressKeyPress = $true } })
    $jsonTreeSearchPanel.Controls.AddRange(@($textSearchJsonTree, $lblJsonTreeStatus, $btnJsonTreeNext, $btnJsonTreePrev, $btnJsonTreeExpand, $btnJsonTreeCollapse))

    $treeViewJson = New-Object System.Windows.Forms.TreeView -Property @{ Dock = 'Fill'; BorderStyle = 'None'; HideSelection = $false }
    
    $jsonContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $itemCopyKey = $jsonContextMenu.Items.Add("Copy Key")
    $itemCopyKey.Add_Click({
        if ($treeViewJson.SelectedNode -and $treeViewJson.SelectedNode.Tag) {
            [System.Windows.Forms.Clipboard]::SetText([string]$treeViewJson.SelectedNode.Tag.Key)
        }
    })
    $itemCopyValue = $jsonContextMenu.Items.Add("Copy Value")
    $itemCopyValue.Add_Click({
        if ($treeViewJson.SelectedNode -and $treeViewJson.SelectedNode.Tag) {
            $val = $treeViewJson.SelectedNode.Tag.Value
            $text = if ($val -is [string] -or $val -is [ValueType]) { "$val" } else { $val | ConvertTo-Json -Depth 10 -Compress }
            if ($text) { [System.Windows.Forms.Clipboard]::SetText($text) }
        }
    })
    $treeViewJson.ContextMenuStrip = $jsonContextMenu
    $treeViewJson.Add_NodeMouseClick({ param($s,$e) if ($e.Button -eq 'Right') { $treeViewJson.SelectedNode = $e.Node } })
    
    $tabJsonTree.Controls.Add($treeViewJson)
    $tabJsonTree.Controls.Add($jsonTreeSearchPanel)

    $tabCode = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Code Snippets" }
    $panelCodeTools = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Top'; AutoSize = $true; AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink; Padding = [System.Windows.Forms.Padding]::new(3) }
    $script:comboCodeLanguage = New-Object System.Windows.Forms.ComboBox -Property @{ Width = 120; DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; Margin = [System.Windows.Forms.Padding]::new(3) }
    $script:comboCodeLanguage.Items.AddRange(@("cURL", "PowerShell", "Python", "JavaScript", "C#"))
    $script:comboCodeLanguage.SelectedIndex = 0
    $panelCodeTools.Controls.Add($script:comboCodeLanguage)
    
    $richTextCode = New-RichTextBox -ReadOnly $true -Property @{ Dock = [System.Windows.Forms.DockStyle]::Fill; BorderStyle = 'None' }
    $richTextCode.ContextMenuStrip = New-CopyContextMenu -ParentControl $richTextCode
    # Add the Top-docked panel first, then the Fill-docked text box to ensure correct layout.
    $tabCode.Controls.AddRange(@($panelCodeTools, $richTextCode))
    # --- Console Tab ---
    $tabConsole = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Console" }
    
    $consoleSplit = New-Object System.Windows.Forms.SplitContainer -Property @{ Dock = 'Fill'; Orientation = 'Horizontal'; SplitterDistance = 200 }
    
    # Console Output (Top)
    $defaultLang = if ($script:settings.DefaultConsoleLanguage) { $script:settings.DefaultConsoleLanguage } else { "PowerShell" }
    $script:consoleOutput = New-RichTextBox -ReadOnly $true -Property @{ Dock = 'Fill'; BackColor = 'Black'; ForeColor = 'White'; Font = New-Object System.Drawing.Font("Courier New", 9); Text = "Welcome to API Tester Console.`nDefault language: $defaultLang.`nPrefix commands with 'python:', 'js:', 'php:', 'ruby:', 'go:', 'bat:', 'bash:' to switch languages.`nExample: python: print('Hello')`n`n"; BorderStyle = 'None' }
    $script:consoleOutput.ContextMenuStrip = New-CopyContextMenu -ParentControl $script:consoleOutput
    
    # Console Input (Bottom)
    $consoleInputPanel = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Fill' }
    $consoleToolbar = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Top'; AutoSize = $true; AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink; Padding = [System.Windows.Forms.Padding]::new(3) }
    
    $script:consolePlaceholder = "Enter command here... (Ctrl+Enter or Shift+Enter to run)"

    $btnRunConsole = New-Button -Text "Run" -Property @{ Dock = 'Left'; Width = 60; Margin = [System.Windows.Forms.Padding]::new(5,0,0,0) } -OnClick {
        $code = $script:consoleInput.Text
        if ([string]::IsNullOrWhiteSpace($code) -or $code -eq $script:consolePlaceholder) { return }
        
        # Language Detection and Parsing
        $lang = if ($script:settings.DefaultConsoleLanguage) { $script:settings.DefaultConsoleLanguage } else { "PowerShell" }
        $scriptToRun = $code
        
        if ($code -match '^(python|py):\s*(.*)') { $lang = "Python"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(js|node|javascript):\s*(.*)') { $lang = "JavaScript (Node.js)"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(php):\s*(.*)') { $lang = "PHP"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(ruby|rb):\s*(.*)') { $lang = "Ruby"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(go):\s*(.*)') { $lang = "Go"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(bat|cmd|batch):\s*(.*)') { $lang = "Batch"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(bash|sh):\s*(.*)') { $lang = "Bash"; $scriptToRun = $matches[2] }
        elseif ($code -match '^(ps|pwsh|powershell):\s*(.*)') { $lang = "PowerShell"; $scriptToRun = $matches[2] }

        # Echo Input
        $script:consoleOutput.SelectionColor = [System.Drawing.Color]::LightGray
        $script:consoleOutput.AppendText("> $code`n")
        $script:consoleOutput.SelectionColor = [System.Drawing.Color]::White
        $script:consoleOutput.ScrollToCaret()
        
        try {
            if ($lang -eq "PowerShell") {
                # Run in the current session to allow manipulation of form variables
                $output = Invoke-Expression $scriptToRun | Out-String
                $script:consoleOutput.AppendText($output)
            } else {
                # External execution
                $fileName = [System.IO.Path]::GetTempFileName()
                $argsList = @()
                $exe = ""
                
                switch ($lang) {
                    "JavaScript (Node.js)" { $exe = "node"; $fileName += ".js"; $argsList = @($fileName) }
                    "Python"  { $exe = "python"; $fileName += ".py"; $argsList = @($fileName) }
                    "PHP"     { $exe = "php"; $fileName += ".php"; $argsList = @($fileName) }
                    "Ruby"    { $exe = "ruby"; $fileName += ".rb"; $argsList = @($fileName) }
                    "Go"      { $exe = "go"; $fileName += ".go"; $argsList = @("run", $fileName) }
                    "Batch"   { $exe = "cmd"; $fileName += ".bat"; $argsList = @("/c", $fileName) }
                    "Bash"    { $exe = "bash"; $fileName += ".sh"; $argsList = @($fileName) }
                }
                
                $scriptToRun | Set-Content -Path $fileName -Encoding UTF8
                
                $processInfo = New-Object System.Diagnostics.ProcessStartInfo
                $processInfo.FileName = $exe
                $processInfo.Arguments = $argsList -join " "
                $processInfo.RedirectStandardOutput = $true
                $processInfo.RedirectStandardError = $true
                $processInfo.UseShellExecute = $false
                $processInfo.CreateNoWindow = $true
                
                $process = [System.Diagnostics.Process]::Start($processInfo)
                $process.WaitForExit()
                
                $stdOut = $process.StandardOutput.ReadToEnd()
                $stdErr = $process.StandardError.ReadToEnd()
                
                if ($stdOut) { $script:consoleOutput.AppendText($stdOut) }
                if ($stdErr) { $script:consoleOutput.SelectionColor = [System.Drawing.Color]::Red; $script:consoleOutput.AppendText($stdErr); $script:consoleOutput.SelectionColor = [System.Drawing.Color]::White }
                
                Remove-Item $fileName -ErrorAction SilentlyContinue
            }
        } catch {
            $script:consoleOutput.SelectionColor = [System.Drawing.Color]::Red
            $script:consoleOutput.AppendText("Error: $($_.Exception.Message)`n")
            $script:consoleOutput.SelectionColor = [System.Drawing.Color]::White
        }
        $script:consoleOutput.AppendText("`n")
        $script:consoleOutput.ScrollToCaret()
    }
    
    $btnClearConsole = New-Button -Text "Clear" -Property @{ Dock = 'Left'; Width = 60; Margin = [System.Windows.Forms.Padding]::new(5,0,0,0) } -OnClick { $script:consoleOutput.Clear() }
    
    $consoleToolbar.Controls.AddRange(@($btnClearConsole, $btnRunConsole))
    
    $script:consoleInput = New-RichTextBox -Property @{ Dock = 'Fill'; BackColor = 'Black'; ForeColor = 'Gray'; Font = New-Object System.Drawing.Font("Courier New", 9); AcceptsTab = $true; Text = $script:consolePlaceholder; BorderStyle = 'None' }
    
    $script:consoleInput.Add_Enter({
        if ($script:consoleInput.Text -eq $script:consolePlaceholder) {
            $script:consoleInput.Text = ""
            $script:consoleInput.ForeColor = [System.Drawing.Color]::White
        }
    })
    
    $script:consoleInput.Add_Leave({
        if ([string]::IsNullOrWhiteSpace($script:consoleInput.Text)) {
            $script:consoleInput.Text = $script:consolePlaceholder
            $script:consoleInput.ForeColor = [System.Drawing.Color]::Gray
        }
    })

    $script:consoleInput.Add_KeyDown({
        param($sender, $e)
        if (($e.Control -or $e.Shift) -and $e.KeyCode -eq 'Enter') {
            $btnRunConsole.PerformClick()
            $e.SuppressKeyPress = $true
        }
    })

    # Basic Syntax Highlighting for Console Input
    $script:isHighlighting = $false
    $script:consoleInput.Add_TextChanged({
        if ($script:isHighlighting) { return }
        if ($script:consoleInput.Text -eq $script:consolePlaceholder) { return }
        $script:isHighlighting = $true
        $rtb = $script:consoleInput
        $rtb.SuspendLayout()
        $selStart = $rtb.SelectionStart
        $selLength = $rtb.SelectionLength
        
        $rtb.SelectAll()
        $rtb.SelectionColor = [System.Drawing.Color]::White
        
        $text = $rtb.Text
        # Keywords (Blue)
        $keywords = "\b(if|else|elseif|for|foreach|return|function|var|let|const|try|catch|switch|case|while|do|class|import|from|def|end|param|in|echo|print|write-host)\b"
        [regex]::Matches($text, $keywords, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) | ForEach-Object {
            $rtb.Select($_.Index, $_.Length); $rtb.SelectionColor = [System.Drawing.Color]::LightSkyBlue
        }
        # Strings (Orange)
        [regex]::Matches($text, "(['`"])(?:\\\1|.)*?\1") | ForEach-Object {
            $rtb.Select($_.Index, $_.Length); $rtb.SelectionColor = [System.Drawing.Color]::LightSalmon
        }

        $rtb.Select($selStart, $selLength)
        $rtb.SelectionColor = [System.Drawing.Color]::White
        $rtb.ResumeLayout()
        $script:isHighlighting = $false
    })
    
    $consoleInputPanel.Controls.Add($consoleToolbar)
    $consoleInputPanel.Controls.Add($script:consoleInput)
    
    $consoleSplit.Panel1.Controls.Add($script:consoleOutput)
    $consoleSplit.Panel2.Controls.Add($consoleInputPanel)
    $tabConsole.Controls.Add($consoleSplit)

    $script:comboCodeLanguage.Add_SelectedIndexChanged({
        if ($script:lastRequestState) {
            $richTextCode.Text = Generate-CodeSnippet -RequestItem $script:lastRequestState -Language $script:comboCodeLanguage.SelectedItem
        }
    })

    $tabPreview = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Preview" }
    $webBrowserPreview = New-Object System.Windows.Forms.WebBrowser -Property @{ Dock = 'Fill'; Visible = $false }
    $pictureBoxPreview = New-Object System.Windows.Forms.PictureBox -Property @{ Dock = 'Fill'; SizeMode = 'Zoom'; Visible = $false }
    $tabPreview.Controls.AddRange(@($webBrowserPreview, $pictureBoxPreview))
    # Visibility is managed during response processing

    $tabTestResults = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Test Results" }
    $script:richTextTestResults = New-RichTextBox -ReadOnly $true -Property @{ Dock = [System.Windows.Forms.DockStyle]::Fill; BorderStyle = 'None' }
    $script:richTextTestResults.ContextMenuStrip = New-CopyContextMenu -ParentControl $script:richTextTestResults
    $tabTestResults.Controls.Add($script:richTextTestResults)

    $groupResponse.Controls.Add($tabControlResponse)

    # GroupBox for the request history list.
    $groupHistory = New-Object System.Windows.Forms.GroupBox -Property @{
        Dock     = [System.Windows.Forms.DockStyle]::Fill
        Padding  = [System.Windows.Forms.Padding]::new(3, 3, 3, 3) # Add padding
        Text     = "Collections & History"
        BackColor = $script:Theme.GroupBackground
    }

    # Populates the history listbox from the $script:history array.
    function Populate-HistoryList { # Renamed from Populate-HistoryTab
        param(
            [string]$TextFilter,
            [string]$EnvironmentFilter
        )

        $listHistory.Items.Clear()
        $listHistory.DisplayMember = "Display" # Use the 'Display' property for the text
        $itemsToShow = $script:history | Where-Object { $_ -ne $null }

        if (-not [string]::IsNullOrWhiteSpace($TextFilter)) {
            $itemsToShow = $itemsToShow | Where-Object { $_.Method -like "*$TextFilter*" -or $_.Url -like "*$TextFilter*" }
        }

        if ($EnvironmentFilter -and $EnvironmentFilter -ne "All Environments") {
            $itemsToShow = $itemsToShow | Where-Object { $_.Environment -eq $EnvironmentFilter }
        }

        foreach ($item in $itemsToShow) {
            if ($item.Timestamp -and $item.Method -and $item.Url) {
                $tsStr = if ($item.Timestamp -is [PSCustomObject]) { $item.Timestamp.DateTime } else { $item.Timestamp }
                $ts = [DateTime]::MinValue
                $parsed = [DateTime]::TryParse($tsStr, [ref]$ts)
                if (-not $parsed) {
                    $parsed = [DateTime]::TryParse($tsStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$ts)
                }
                if (-not $parsed) {
                    $parsed = [DateTime]::TryParse($tsStr, [System.Globalization.CultureInfo]::GetCultureInfo("en-US"), [System.Globalization.DateTimeStyles]::None, [ref]$ts)
                }

                if ($parsed) {
                    $displayString = "$($ts.ToString('HH:mm:ss')) | $($item.Method) | $($item.Url)"
                    $listItem = [PSCustomObject]@{ Display = $displayString; Value = $item }
                    $listHistory.Items.Add($listItem)
                } else {
                    $displayString = "??:??:?? | $($item.Method) | $($item.Url)"
                    $listItem = [PSCustomObject]@{ Display = $displayString; Value = $item }
                    $listHistory.Items.Add($listItem)
                }
            }
        }
    }

    function Populate-HistoryEnvironmentFilter {
        $currentSelection = $comboHistoryEnvFilter.SelectedItem
        $comboHistoryEnvFilter.Items.Clear()
        $comboHistoryEnvFilter.Items.Add("All Environments")
        $script:environments.Keys | Sort-Object | ForEach-Object { $comboHistoryEnvFilter.Items.Add($_) }
        if ($currentSelection -and $comboHistoryEnvFilter.Items.Contains($currentSelection)) { $comboHistoryEnvFilter.SelectedItem = $currentSelection } else { $comboHistoryEnvFilter.SelectedItem = "All Environments" }
    }

    # Recursively populates the TreeView with collections, folders, and requests.
    function Populate-CollectionsTreeView {
        param ([System.Windows.Forms.TreeNodeCollection]$nodes, [array]$items)

        $nodes.Clear()
        foreach ($item in $items) {
            $newNode = New-Object System.Windows.Forms.TreeNode($item.Name)
            $newNode.Tag = $item # Store the full object
            if ($item.Type -eq "Collection") {
                $newNode.ImageIndex = 0
                $newNode.SelectedImageIndex = 0
            } elseif ($item.Type -eq "Folder") {
                $newNode.ImageIndex = 1
                $newNode.SelectedImageIndex = 1
            } else { # Request
                $newNode.ImageIndex = 2
                $newNode.SelectedImageIndex = 2
            }
        $nodes.Add($newNode) | Out-Null # Add node to TreeView
            if ($item.Items) { Populate-CollectionsTreeView -nodes $newNode.Nodes -items $item.Items }
        }
    }

    function Get-CollectionNodeFromChild {
        param([System.Windows.Forms.TreeNode]$node)
        $current = $node
        while ($current -and $current.Tag -and $current.Tag.Type -ne "Collection") {
            $current = $current.Parent
        }
        return $current
    }
    $historyPanelContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $dockUndockMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Undock Panel", $null, {
        $script:isHistoryUndocked = -not $script:isHistoryUndocked
        if ($script:isHistoryUndocked) {
            $dockUndockMenuItem.Text = "Dock Panel"
        } else {
            $dockUndockMenuItem.Text = "Undock Panel"
        }
        Update-Layout
    })
    $historyPanelContextMenu.Items.Add($dockUndockMenuItem)
    $groupHistory.ContextMenuStrip = $historyPanelContextMenu
    
    # --- NEW: TabControl for Collections and History ---
    $collectionsTabControl = New-Object System.Windows.Forms.TabControl -Property @{
        Dock = [System.Windows.Forms.DockStyle]::Fill
    }

    # --- Collections Tab ---
    $tabCollections = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Collections" }
    $treeViewCollections = New-Object System.Windows.Forms.TreeView -Property @{
        Dock = [System.Windows.Forms.DockStyle]::Fill
        ShowNodeToolTips = $true
    }
    # Add an ImageList for icons
    $imageList = New-Object System.Windows.Forms.ImageList
    # Simple icons for Collection (folder), Folder (subfolder), and Request (file)
    $imageList.Images.Add([System.Drawing.SystemIcons]::Application) # Collection
    $imageList.Images.Add([System.Drawing.SystemIcons]::Information) # Folder
    $imageList.Images.Add([System.Drawing.SystemIcons]::Question)    # Request
    $treeViewCollections.ImageList = $imageList

    # --- Collections Context Menu ---
    $collectionsContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $addCollectionMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("New Collection", $null, {
        $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter new collection name:", "New Collection")
        if ($name) {
            $newCollection = [PSCustomObject]@{ Name = $name; Type = "Collection"; Items = @(); Variables = @{} } # Create new collection object
            $script:collections += $newCollection
            Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
            Save-Collections #FIX: Corrected function call
        }
    })
    $addFolderMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("New Folder", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter new folder name:", "New Folder") # Prompt for folder name
            if ($name) {
                $newFolder = [PSCustomObject]@{ Name = $name; Type = "Folder"; Items = @() }
                $selectedNode.Tag.Items += $newFolder
                Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
                $selectedNode.Expand()
                Save-Collections
            }
        }
    })
    $saveRequestMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Save Current Request", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter request name:", "Save Request", "$($script:comboMethod.SelectedItem) $($script:textUrl.Text)") # Prompt for request name
            if ($name) {
                $newRequest = [PSCustomObject]@{
                    Name = $name
                    Type = "Request"
                    RequestData = [PSCustomObject]@{
                        Timestamp = Get-Date
                        Method    = $script:comboMethod.SelectedItem
                        Url       = $script:textUrl.Text
                        Headers   = $script:textHeaders.Text
                        Body      = $script:textBody.Text
                        BodyType  = $script:comboBodyType.SelectedItem
                        OutputFormat = $script:textOutputFormat.Text
                        Tests     = $script:textTests.Text                        
                        PreRequestScript = $script:textPreRequest.Text
                        Authentication = (& $script:authPanel.GetAuthData)
                    }
                }
                $selectedNode.Tag.Items += $newRequest
                Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
                $selectedNode.Expand()
                Save-Collections
            }
        }
    })
    $editCollectionVarsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Edit Variables...", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode -and $selectedNode.Tag.Type -eq "Collection") {
            $col = $selectedNode.Tag
            $currentVars = if ($col.PSObject.Properties.Name -contains 'Variables' -and $col.Variables) { $col.Variables } else { @{} }
            $result = Show-VariablesEditor -parentForm $form -Title "Collection Variables: $($col.Name)" -Variables $currentVars
            if ($result.Result -eq [System.Windows.Forms.DialogResult]::OK) {
                $col.Variables = if ($result.Variables) { $result.Variables } else { @{} }
                Save-Collections
                if ($script:activeCollectionNode -and $script:activeCollectionNode -eq $selectedNode) {
                    $script:activeCollectionVariables = $col.Variables
                    if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Collection" -and $null -ne $updateExtractVarList) {
                        & $updateExtractVarList
                    }
                }
                Write-Log "Collection variables updated for '$($col.Name)'."
            }
        }
    })
    $renameMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Rename", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            $newName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter new name:", "Rename", $selectedNode.Text) # Prompt for new name
            if ($newName) {
                $selectedNode.Tag.Name = $newName
                $selectedNode.Text = $newName
                Save-Collections
            }
        }
    })
    $deleteMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Delete", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            $confirm = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to delete '$($selectedNode.Text)'?", "Confirm Delete", "YesNo", "Warning") # Confirmation dialog
            if ($confirm -eq 'Yes') {
                $parent = $selectedNode.Parent
                if ($parent) {
                    $parent.Tag.Items = @($parent.Tag.Items | Where-Object { $_ -ne $selectedNode.Tag })
                } else { # Top-level collection
                    $script:collections = @($script:collections | Where-Object { $_ -ne $selectedNode.Tag })
                }
                $selectedNode.Remove()
                Save-Collections
            }
        }
    })
    $exportFolderMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Export Folder...", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            $sfd = New-Object System.Windows.Forms.SaveFileDialog -Property @{ 
                Filter = "JSON Files (*.json)|*.json"; 
                FileName = "$($selectedNode.Text)_export.json"; 
                Title = "Export Folder" 
            }
            if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                try {
                    $selectedNode.Tag | ConvertTo-Json -Depth 10 | Set-Content -Path $sfd.FileName -ErrorAction Stop
                    [System.Windows.Forms.MessageBox]::Show("Folder exported successfully.", "Export", "OK", "Information")
                } catch { [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error") }
            }
        }
    })
    $runCollectionMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Run...", $null, {
        $selectedNode = $treeViewCollections.SelectedNode
        if ($selectedNode) {
            Show-CollectionRunnerWindow -Item $selectedNode.Tag -parentForm $form
        }
    })

    $collectionsContextMenu.Items.AddRange(@($addCollectionMenuItem, $addFolderMenuItem, $saveRequestMenuItem, $editCollectionVarsMenuItem, (New-Object System.Windows.Forms.ToolStripSeparator), $runCollectionMenuItem, $renameMenuItem, $deleteMenuItem, $exportFolderMenuItem))
    $treeViewCollections.ContextMenuStrip = $collectionsContextMenu

    $collectionsContextMenu.Add_Opening({
        $selectedNode = $treeViewCollections.SelectedNode
        $addFolderMenuItem.Enabled = $false
        $saveRequestMenuItem.Enabled = $false
        $editCollectionVarsMenuItem.Enabled = $false
        $renameMenuItem.Enabled = $false
        $deleteMenuItem.Enabled = $false
        $runCollectionMenuItem.Enabled = $false
        $exportFolderMenuItem.Enabled = $false

        if ($selectedNode) {
            $itemType = $selectedNode.Tag.Type
            $renameMenuItem.Enabled = $true
            $deleteMenuItem.Enabled = $true
            if ($itemType -eq "Collection" -or $itemType -eq "Folder") {
                $addFolderMenuItem.Enabled = $true
                $saveRequestMenuItem.Enabled = $true
                $runCollectionMenuItem.Enabled = $true
                $exportFolderMenuItem.Enabled = $true
            }
            if ($itemType -eq "Collection") {
                $editCollectionVarsMenuItem.Enabled = $true
            }
        }
    })

    $treeViewCollections.Add_NodeMouseClick({
        param($sender, $e)
        # Select node on right-click to make context menu work intuitively
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) {
            $treeViewCollections.SelectedNode = $e.Node
        }
    })

    $treeViewCollections.Add_AfterSelect({
        param($sender, $e)
        $selectedNode = $e.Node
        if ($selectedNode) {
            if ($selectedNode.Tag.Type -eq "Collection") {
                $script:activeCollectionNode = $selectedNode
                $script:activeCollectionName = $selectedNode.Tag.Name
                $script:activeCollectionVariables = if ($selectedNode.Tag.Variables) { $selectedNode.Tag.Variables } else { @{} }
                if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Collection" -and $null -ne $updateExtractVarList) {
                    & $updateExtractVarList
                }
            } elseif ($selectedNode.Tag.Type -eq "Request") {
                # Load the request data into the form
                $selectedHistoryItem = $selectedNode.Tag.RequestData
                # This reuses the existing history loading logic
                Load-Request-From-Object -RequestObject $selectedHistoryItem
                Write-Log "Loaded request '$($selectedNode.Tag.Name)' from collection."

                $collectionNode = Get-CollectionNodeFromChild -node $selectedNode
                if ($collectionNode) {
                    $script:activeCollectionNode = $collectionNode
                    $script:activeCollectionName = $collectionNode.Tag.Name
                    $script:activeCollectionVariables = if ($collectionNode.Tag.Variables) { $collectionNode.Tag.Variables } else { @{} }
                    if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Collection" -and $null -ne $updateExtractVarList) {
                        & $updateExtractVarList
                    }
                }
            } else {
                $collectionNode = Get-CollectionNodeFromChild -node $selectedNode
                if ($collectionNode) {
                    $script:activeCollectionNode = $collectionNode
                    $script:activeCollectionName = $collectionNode.Tag.Name
                    $script:activeCollectionVariables = if ($collectionNode.Tag.Variables) { $collectionNode.Tag.Variables } else { @{} }
                    if ($script:comboExtractScope -and $script:comboExtractScope.SelectedItem -eq "Collection" -and $null -ne $updateExtractVarList) {
                        & $updateExtractVarList
                    }
                }
            }
        }
    })

    # Refactored: Use a Panel with Docking strategy consistent with History tab
    $panelCollectionsBottom = New-Object System.Windows.Forms.Panel -Property @{ 
        Dock = 'Bottom'
        Height = 60 
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5) 
    }

    $btnImportCollections = New-Button -Text "Import" -Property @{ 
        Dock = 'Left'
        Width = 180 
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 10, 0) 
    } -OnClick {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter = "JSON Files (*.json)|*.json"; Title = "Import Collections" }
        if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $confirm = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to import collections? This will append the imported items to your current list.", "Confirm Import", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
            if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
                try {
                    $imported = Get-Content -Path $ofd.FileName -Raw | ConvertFrom-Json
                        if ($imported) {
                            if ($imported -is [array]) {
                                $script:collections += $imported
                            } else {
                                $script:collections += @($imported)
                            }
                            Ensure-CollectionVariables -Items $script:collections
                            Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections
                            Save-Collections
                            [System.Windows.Forms.MessageBox]::Show("Collections imported successfully.", "Import", "OK", "Information")
                        }
                } catch { [System.Windows.Forms.MessageBox]::Show("Import failed: $($_.Exception.Message)", "Error", "OK", "Error") }
            }
        }
    }

    $btnExportCollections = New-Button -Text "Export" -Property @{ 
        Dock = 'Left'
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 3, 0)
        Width = 180
    } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog -Property @{ Filter = "JSON Files (*.json)|*.json"; FileName = "api_tester_collections_export.json"; Title = "Export Collections" }
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $script:collections | ConvertTo-Json -Depth 10 | Set-Content -Path $sfd.FileName -ErrorAction Stop
                [System.Windows.Forms.MessageBox]::Show("Collections exported successfully.", "Export", "OK", "Information")
            } catch { [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error") }
        }
    }

    # Add controls in docking order (Left, then Left)
    $panelCollectionsBottom.Controls.AddRange(@($btnImportCollections, $btnExportCollections))

    $tabCollections.Controls.AddRange(@($treeViewCollections, $panelCollectionsBottom))

    # --- History Tab ---
    $tabHistory = New-Object System.Windows.Forms.TabPage -Property @{ Text = "History" }
    
    # Refactored: Use a Panel with Docking strategy consistent with main layout
    $searchHistoryPanel = New-Object System.Windows.Forms.Panel -Property @{ 
        Dock = 'Top'
        Height = 45
        Padding = [System.Windows.Forms.Padding]::new(5, 10, 5, 5)
    }

    $comboHistoryEnvFilter = New-Object System.Windows.Forms.ComboBox -Property @{ 
        Dock = 'Right'
        Width = 180 
        DropDownWidth = 240 
        DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        Margin = [System.Windows.Forms.Padding]::new(10, 0, 0, 0) 
    }
    $toolTip.SetToolTip($comboHistoryEnvFilter, "Filter history by environment")
    
    $textSearchHistory = New-TextBox -Property @{ 
        Dock = 'Fill'
        Text = "Search by Method/URL..." 
        ForeColor = [System.Drawing.Color]::Gray 
    }
    $toolTip.SetToolTip($textSearchHistory, "Search by method or URL")

    # Add placeholder text functionality
    $textSearchHistory.Add_Enter({ 
        if ($textSearchHistory.Text -eq "Search by Method/URL...") { 
            $textSearchHistory.Text = ""; 
            $textSearchHistory.ForeColor = [System.Drawing.Color]::Black 
        } 
    })
    $textSearchHistory.Add_Leave({ 
        if ([string]::IsNullOrWhiteSpace($textSearchHistory.Text)) { 
            $textSearchHistory.Text = "Search by Method/URL..."; 
            $textSearchHistory.ForeColor = [System.Drawing.Color]::Gray 
        } 
    })

    # Add the event handler to filter the list as the user types
    $textSearchHistory.Add_TextChanged({
        param($sender, $e)
        # Avoid filtering when the placeholder text is present
        if ($sender.Text -ne "Search by Method/URL...") {
            Populate-HistoryList -TextFilter $sender.Text -EnvironmentFilter $comboHistoryEnvFilter.SelectedItem
        }
    })

    $comboHistoryEnvFilter.Add_SelectedIndexChanged({
        if ($textSearchHistory.Text -eq "Search by Method/URL...") { $textFilter = "" } else { $textFilter = $textSearchHistory.Text }
        Populate-HistoryList -TextFilter $textFilter -EnvironmentFilter $comboHistoryEnvFilter.SelectedItem
    })

    # Add controls to panel and apply docking precedence
    # Note: Search field (Fill) first, then dropdown (Right) to ensure proper layout
    $searchHistoryPanel.Controls.AddRange(@($textSearchHistory, $comboHistoryEnvFilter))

    $listHistory = New-Object System.Windows.Forms.ListBox -Property @{
        Dock = [System.Windows.Forms.DockStyle]::Fill
    }
    
    # Refactored: Use a Panel with Docking strategy consistent with Collections tab
    $panelHistoryBottom = New-Object System.Windows.Forms.Panel -Property @{ 
        Dock = 'Bottom'
        Height = 60 
        Padding = [System.Windows.Forms.Padding]::new(5, 5, 5, 5) 
    }
    
    $btnClearHistory = New-Button -Text "Clear History" -Style 'Danger' -Property @{ 
        Dock = 'Left'
        Width = 180
        Margin = [System.Windows.Forms.Padding]::new(0, 0, 10, 0) 
    } -OnClick {
        $result = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to clear all history? This cannot be undone.", "Confirm Clear", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            $script:history = @()
            $listHistory.Items.Clear()
            Save-History
        }
    }
    
    $btnExportHistory = New-Button -Text "Export History" -Property @{ 
        Dock = 'Left'
        Width = 180
    } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog -Property @{ Filter = "JSON Files (*.json)|*.json"; FileName = "api_tester_history_export.json"; Title = "Export History" }
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $script:history | ConvertTo-Json -Depth 10 | Set-Content -Path $sfd.FileName -ErrorAction Stop
                [System.Windows.Forms.MessageBox]::Show("History exported successfully.", "Export", "OK", "Information")
            } catch { [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error") }
        }
    }
    $panelHistoryBottom.Controls.AddRange(@($btnClearHistory, $btnExportHistory))
    $tabHistory.Controls.AddRange(@($listHistory, $searchHistoryPanel, $panelHistoryBottom))

    $historyContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $duplicateHistoryItem = New-Object System.Windows.Forms.ToolStripMenuItem("Duplicate", $null, {
        $selectedItem = $listHistory.SelectedItem
        if ($selectedItem) {
            $historyObject = $selectedItem.Value
            $script:activeCollectionName = $null
            $script:activeCollectionNode = $null
            $script:activeCollectionVariables = @{}
            Load-Request-From-Object -RequestObject $historyObject
            Write-Log "Duplicated request from history: $($historyObject.Url)"
        }
    })
    $deleteHistoryItem = New-Object System.Windows.Forms.ToolStripMenuItem("Delete", $null, {
        $selectedItem = $listHistory.SelectedItem
        if ($selectedItem) {
            $historyObjectToRemove = $selectedItem.Value
            $listHistory.Items.Remove($selectedItem)
            $script:history = $script:history | Where-Object { $_ -ne $historyObjectToRemove }
            Save-History
            Write-Log "Deleted history item: $($historyObjectToRemove.Url)"
        }
    })    
    $copyAsCurlMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Copy as cURL", $null, {
        $selectedItem = $listHistory.SelectedItem
        if ($selectedItem) {
            $selectedHistoryItem = $selectedItem.Value
            $curlCommand = Generate-CodeSnippet -RequestItem $selectedHistoryItem -Language "cURL"
            [System.Windows.Forms.Clipboard]::SetText($curlCommand) # Copy to clipboard
            Write-Log "Copied history item as cURL command to clipboard."
        }
    })
    $copyAsPSMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Copy as PowerShell", $null, {
        $selectedItem = $listHistory.SelectedItem
        if ($selectedItem) {
            $selectedHistoryItem = $selectedItem.Value
            $psCommand = Generate-CodeSnippet -RequestItem $selectedHistoryItem -Language "PowerShell"
            [System.Windows.Forms.Clipboard]::SetText($psCommand)
            Write-Log "Copied history item as PowerShell command to clipboard."
        }
    })

    $historyContextMenu.Items.AddRange(@($duplicateHistoryItem, $copyAsCurlMenuItem, $copyAsPSMenuItem, $deleteHistoryItem))
    $listHistory.ContextMenuStrip = $historyContextMenu

    $listHistory.Add_MouseDown({
        param($sender, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) {
            $index = $listHistory.IndexFromPoint($e.Location)
            if ($index -ne [System.Windows.Forms.ListBox]::NoMatches) {
                $listHistory.SelectedIndex = $index
            }
        }
    })
    $historyContextMenu.Add_Opening({
        $_.Cancel = ($listHistory.SelectedIndex -eq -1)
    })

    # Central function to load a request object into the UI fields
    function Load-Request-From-Object {
        param(
            # Accept the named parameter used elsewhere (-RequestObject) and positional calls.
            [Parameter(Mandatory=$true, Position=0)]
            [PSCustomObject]$RequestObject
        )

        # If caller used the old variable name internally, normalize to $selectedHistoryItem for the rest of the function.
        $selectedHistoryItem = $RequestObject
        if (-not $selectedHistoryItem) { return }

        $script:textUrl.Text = $selectedHistoryItem.Url
        $script:comboMethod.SelectedItem = $selectedHistoryItem.Method
        $script:comboBodyType.SelectedItem = $selectedHistoryItem.BodyType
        
        # Directly apply the logic that would normally be in SelectedIndexChanged
        if ($script:comboBodyType.SelectedItem -eq "multipart/form-data") { # Update UI based on body type
            $checkIncludeFilename.Visible = $true
            $checkIncludeContentType.Visible = $true
            $labelBody.Text = "Body (key=value per line. Press '@' to add a file):"
            $script:textBody.Visible = $true
            $script:panelGraphQL.Visible = $false
        } elseif ($script:comboBodyType.SelectedItem -eq "GraphQL") {
            $script:textBody.Visible = $false
            $script:panelGraphQL.Visible = $true
        }
        else {
            $checkIncludeFilename.Visible = $false
            $checkIncludeContentType.Visible = $false
            $labelBody.Text = "Body (raw content):"
            $script:textBody.Visible = $true
            $script:panelGraphQL.Visible = $false
        }

        $script:textHeaders.Text = $selectedHistoryItem.Headers
        $script:textBody.Text = $selectedHistoryItem.Body

        if ($selectedHistoryItem.PSObject.Properties.Name -contains 'OutputFormat') {
            $script:textOutputFormat.Text = $selectedHistoryItem.OutputFormat
        } else {
            $script:textOutputFormat.Text = ""
        }

        if ($selectedHistoryItem.PSObject.Properties.Name -contains 'Tests') {
            $script:textTests.Text = $selectedHistoryItem.Tests
        } else {
            $script:textTests.Text = ""
        }

        if ($selectedHistoryItem.PSObject.Properties.Name -contains 'PreRequestScript') {
            $script:textPreRequest.Text = $selectedHistoryItem.PreRequestScript
        } else {
            $script:textPreRequest.Text = ""
        }

        if ($selectedHistoryItem.PSObject.Properties.Name -contains 'Environment') {
            if ($script:comboEnvironment.Items.Contains($selectedHistoryItem.Environment)) {
                $script:comboEnvironment.SelectedItem = $selectedHistoryItem.Environment
            }
        }

        if ($selectedHistoryItem.PSObject.Properties.Name -contains 'Authentication') {
            # Temporarily remove the event handler to prevent it from firing and clearing the panel
            $authTypeChangedHandler = $script:authPanel.ComboAuthType.SelectedIndexChanged # Store event handler
            $script:authPanel.ComboAuthType.remove_SelectedIndexChanged($authTypeChangedHandler)

            $auth = $selectedHistoryItem.Authentication
            $script:authPanel.ComboAuthType.SelectedItem = $auth.Type
            & $script:authPanel.SwitchPanel # Manually trigger the panel switch
            switch ($auth.Type) {
                "API Key"      { $script:authPanel.TextApiKeyName.Text = $auth.Key; $script:authPanel.TextApiKeyValue.Text = $auth.Value; $script:authPanel.ComboApiKeyAddTo.SelectedItem = $auth.AddTo }
                "Bearer Token" { $script:authPanel.TextBearerToken.Text = $auth.Token }
                "Basic Auth"   { $script:authPanel.TextBasicUser.Text = $auth.Username; $script:authPanel.TextBasicPass.Text = $auth.Password }
                "Auth2"        {
                    $script:authPanel.TextAuth2ClientId.Text = $auth.ClientId
                    $script:authPanel.TextAuth2ClientSecret.Text = $auth.ClientSecret
                    $script:authPanel.TextAuth2TokenEndpoint.Text = $auth.TokenEndpoint
                    $script:authPanel.TextAuth2Scope.Text = $auth.Scope
                    $script:authPanel.TextAuth2AccessToken.Text = $auth.AccessToken
                    $script:authPanel.TextAuth2RefreshToken.Text = $auth.RefreshToken
                    $script:authPanel.TextAuth2ExpiresIn.Text = $auth.ExpiresIn
                    $script:authPanel.TextAuth2AccessToken.Tag = $auth.TokenExpiryTimestamp
                }
                "Client Certificate" {
                    $script:authPanel.ComboCertSource.SelectedItem = $auth.Source
                    $script:authPanel.TextCertPath.Text = $auth.Path
                    $script:authPanel.TextCertPass.Text = $auth.Password
                    $script:authPanel.TextCertThumb.Text = $auth.Thumbprint
                }
            }

            # Re-add the event handler
            $script:authPanel.ComboAuthType.add_SelectedIndexChanged($authTypeChangedHandler) # Re-add event handler
        } else {
            $script:authPanel.ComboAuthType.SelectedItem = "No Auth"
        }

        $checkIncludeFilename.Checked = $script:settings.IncludeFilename
        $checkIncludeContentType.Checked = $script:settings.IncludeContentType
        # After loading the body and setting the checkboxes, re-apply the attributes
        # to ensure the file lines are correctly formatted for the current settings.
        Apply-Attributes-To-AllFileLines

        # Update Code Snippet
        $currentUiRequest = [PSCustomObject]@{
            Method = $script:comboMethod.SelectedItem
            Url = $script:textUrl.Text
            Headers = $script:textHeaders.Text
            Body = $script:textBody.Text
            BodyType = $script:comboBodyType.SelectedItem
        }
        $script:lastRequestState = $currentUiRequest
        $richTextCode.Text = Generate-CodeSnippet -RequestItem $currentUiRequest -Language $script:comboCodeLanguage.SelectedItem
    }

    $script:comboBodyType.Add_SelectedIndexChanged({
        if ($script:comboBodyType.SelectedItem -eq "multipart/form-data") {
            $checkIncludeFilename.Visible = $true
            $checkIncludeContentType.Visible = $true
            $labelBody.Text = "Body (key=value per line. Press '@' to add a file):"
            $script:textBody.Visible = $true
            $script:panelGraphQL.Visible = $false
        } elseif ($script:comboBodyType.SelectedItem -eq "GraphQL") {
            $script:textBody.Visible = $false
            $script:panelGraphQL.Visible = $true
        } else {
            $checkIncludeFilename.Visible = $false
            $checkIncludeContentType.Visible = $false
            $labelBody.Text = "Body (raw content):"
            $script:textBody.Visible = $true
            $script:panelGraphQL.Visible = $false
        }
    })

    if ($script:settings.EnableHistory) {
        Load-History
    }    
    Populate-HistoryList -TextFilter "" -EnvironmentFilter "All Environments" 
    Populate-CollectionsTreeView -nodes $treeViewCollections.Nodes -items $script:collections

    $listHistory.Add_SelectedIndexChanged({
        # This event is intentionally left empty to prevent a race condition with the DoubleClick event.
    })

    $checkIncludeFilename.Add_CheckedChanged({
        $script:settings.IncludeFilename = $checkIncludeFilename.Checked
        Save-Settings
        Apply-Attributes-To-AllFileLines
    })
    $checkIncludeContentType.Add_CheckedChanged({
        $script:settings.IncludeContentType = $checkIncludeContentType.Checked
        Save-Settings
        Apply-Attributes-To-AllFileLines
    })
    $listHistory.Add_DoubleClick({
        if ($listHistory.SelectedIndex -ne -1) {
            $selectedListItem = $listHistory.SelectedItem
            $selectedHistoryItem = $selectedListItem.Value
            $script:activeCollectionName = $null
            $script:activeCollectionNode = $null
            $script:activeCollectionVariables = @{}
            Load-Request-From-Object -RequestObject $selectedHistoryItem
            Write-Log "Loaded request from history via double-click (URL: $($selectedHistoryItem.Url))"

            # Force the message queue to process all pending UI updates from Load-Request-From-Object
            # before checking the body content for auto-run.
            [System.Windows.Forms.Application]::DoEvents()
            
            # Now that the data is loaded and the UI is updated, check if we should auto-run.
            if ($script:settings.AutoRunHistory) {
                $method = $script:comboMethod.Text
                # Check if the method requires a body and if the body is actually empty.
                # This check now happens *after* DoEvents() ensures the textbox is populated.
                if (($method -in @('POST', 'PUT', 'PATCH')) -and ([string]::IsNullOrWhiteSpace($script:textBody.Text))) {
                    [System.Windows.Forms.MessageBox]::Show("Cannot auto-run a $method request with an empty body. Please provide a body or run the request manually.", "Missing Request Data", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                } else {
                    $btnSubmit.PerformClick()
                }
            }
        }
    })

    $groupRequest.Controls.Add($panelRequestTop)
    $groupRequest.Controls.Add($requestTabControl)
    # Ensure correct Z-order: TabControl (Fill) at index 0 (Front), Panel (Top) at index 1 (Back)
    $groupRequest.Controls.SetChildIndex($requestTabControl, 0)
    $groupRequest.Controls.SetChildIndex($panelRequestTop, 1)
    $groupHistory.Controls.Add($collectionsTabControl)

    # Add controls to the SplitContainer panels
    $mainContentPanel.Controls.AddRange(@(
        $groupEnvironment,
        $groupRequest,        $groupOutput    ))
    $splitContainer.Panel2.Controls.Add($groupHistory)
    $collectionsTabControl.TabPages.AddRange(@($tabCollections, $tabHistory))

    $form.Controls.AddRange(@(
        $splitContainer,
        $menuStrip,
        $statusStrip
    ))

    Populate-EnvironmentDropdown
    Populate-HistoryEnvironmentFilter
    # Restore the last used environment if it exists
    if ($script:settings.LastActiveEnvironment -and $script:comboEnvironment.Items.Contains($script:settings.LastActiveEnvironment)) {
        $script:comboEnvironment.SelectedItem = $script:settings.LastActiveEnvironment
    }

    if ($script:settings.AutoSaveToFile) {
        $script:textOutputFile.Text = $script:settings.AutoSavePath
    }
    
    Update-Layout

    $form.Add_Shown({
        # A second call to Update-Layout after the form is shown ensures all control
        # dimensions are correctly calculated for the final layout.
        Update-Layout # Initial layout update
    })

    # Add global keyboard shortcuts
    $form.Add_KeyDown({
        param($sender, $e)
        # Ctrl+Enter to Send Request
        if ($e.Control -and $e.KeyCode -eq 'Enter') {
            if ($btnSubmit.Enabled) {
                $btnSubmit.PerformClick()
                $e.SuppressKeyPress = $true
            }
        }
    })

    # Add a FormClosing handler to the main form for proper cleanup of undocked windows
    $form.Add_FormClosing({
        param($sender, $e)
        Write-Log "Main form closing event triggered."
        # Set flag to indicate main form is closing
        $script:isMainFormClosing = $true
        # Explicitly dispose of undocked forms if they exist and are not disposed
        # This ensures they are cleaned up and don't prevent the main form from closing.
        if ($script:historyForm -and -not $script:historyForm.IsDisposed) {
            Write-Log "Disposing undocked history form."
            $script:historyForm.Dispose()
            $script:historyForm = $null # Clear reference
        }
        if ($script:responseForm -and -not $script:responseForm.IsDisposed) {
            Write-Log "Disposing undocked response form."
            $script:responseForm.Dispose() # Dispose undocked response form
            $script:responseForm = $null
        }
        # Cleanup RunspacePool
        if ($script:monitorPool) {
            $script:monitorPool.Close()
            $script:monitorPool.Dispose()
            $script:monitorPool = $null
        }
        # Perform cleanup for background jobs and timers
        # (The cleanup after Application::Run is still there, but this is more robust)
        # Allow the main form to close
        $e.Cancel = $false
        Write-Log "Main form allowed to close."
    })
    $form.Add_Shown({$form.Activate()}) # Activate the form when shown
    [System.Windows.Forms.Application]::Run($form) # Run the Windows Forms application
    # Perform cleanup after the main form is closed.
    if ($script:currentPowerShell) { $script:currentPowerShell.Dispose() }
    foreach ($mId in $script:monitorJobs.Keys) {
        $entry = $script:monitorJobs[$mId]
        if ($entry.PS) { $entry.PS.Dispose() }
    }
    if ($script:monitorPool) { $script:monitorPool.Close(); $script:monitorPool.Dispose() }
    if ($script:requestTimer) { $script:requestTimer.Stop(); $script:requestTimer.Dispose() }
    if ($script:historyForm -and -not $script:historyForm.IsDisposed) { $script:historyForm.Dispose() }
    if ($script:responseForm -and -not $script:responseForm.IsDisposed) { $script:responseForm.Dispose() } # Ensure response form is disposed
    if ($notifyIcon) { $notifyIcon.Dispose() }
    $form.Dispose() # Release main form resources
}

#endregion


function Invoke-ApiRequest {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [string]$Method = 'GET',
        [string]$Headers = '',
        [string]$Body = '',
        [string]$BodyType = 'raw',
        [string[]]$Files = @(),
        [int]$TimeoutSeconds = 30
    )
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $client = New-Object System.Net.Http.HttpClient
        $methodObj = [System.Net.Http.HttpMethod]::new($Method)
        $req = New-Object System.Net.Http.HttpRequestMessage($methodObj, $Url)

        if ($Headers) {
            $lines = $Headers -split "`r?`n" | Where-Object { $_ -match '\S' }
            foreach ($l in $lines) { if ($l -match '^\s*([^:]+)\s*:\s*(.+)$') { $req.Headers.TryAddWithoutValidation($matches[1], $matches[2]) | Out-Null } }
        }

        if ($Files.Count -gt 0 -or $BodyType -eq 'multipart/form-data') {
            $multi = New-Object System.Net.Http.MultipartFormDataContent
            if ($Body) { $lines = $Body -split "`r?`n" | Where-Object { $_ -match '\S' }; foreach ($l in $lines) { if ($l -match '=') { $p=$l.Split('=',2); $multi.Add((New-Object System.Net.Http.StringContent($p[1])),$p[0]) } else { $multi.Add((New-Object System.Net.Http.StringContent($l)),'body') } } }
            foreach ($f in $Files) { if (Test-Path $f) { $bytes = [System.IO.File]::ReadAllBytes($f); $content = New-Object System.Net.Http.ByteArrayContent($bytes); $content.Headers.ContentDisposition = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue('form-data'); $content.Headers.ContentDisposition.Name = 'file'; $content.Headers.ContentDisposition.FileName = [System.IO.Path]::GetFileName($f); $multi.Add($content,'file',[System.IO.Path]::GetFileName($f)) } }
            $req.Content = $multi
        }
        elseif ($BodyType -eq 'application/x-www-form-urlencoded') {
            $pairs = @()
            if ($Body) { foreach ($l in $Body -split "`r?`n") { if ($l -match '=') { $p = $l.Split('=',2); $pairs += [System.Collections.Generic.KeyValuePair[string,string]]::new($p[0],$p[1]) } } }
            $req.Content = New-Object System.Net.Http.FormUrlEncodedContent($pairs)
        }
        elseif ($BodyType -match 'graphql') {
            $payload = "{`"query`":`"$($Body -replace '"','\"')`"}"
            $req.Content = New-Object System.Net.Http.StringContent($payload,[System.Text.Encoding]::UTF8, 'application/json')
        }
        elseif ($Body) { $contentType = 'application/json'; $req.Content = New-Object System.Net.Http.StringContent($Body,[System.Text.Encoding]::UTF8,$contentType) }

        $respTask = $client.SendAsync($req)
        $respTask.Wait()
        $resp = $respTask.Result
        $sw.Stop()
        $text = $resp.Content.ReadAsStringAsync().Result
        $hdrs = @{}
        foreach ($h in $resp.Headers) { $hdrs[$h.Key] = ($h.Value -join ',') }
        foreach ($h in $resp.Content.Headers) { $hdrs[$h.Key] = ($h.Value -join ',') }
        return @{ Success = $resp.IsSuccessStatusCode; Data = @{ StatusCode = [int]$resp.StatusCode; StatusDescription = $resp.ReasonPhrase; ElapsedTime = $sw.ElapsedMilliseconds; Headers = $hdrs; Content = $text; RawContentLength = ($resp.Content.Headers.ContentLength -as [int64]) } }
    } catch { return @{ Success = $false; ErrorMessage = $_.Exception.Message } }
}

function Invoke-RunTests {
    param([string]$Response, [string]$Tests)
    $out = New-Object System.Text.StringBuilder
    $lines = $Tests -split "`r?`n" | Where-Object { $_ -match '\S' }
    foreach ($l in $lines) {
        if ($l -match '^contains\s+"?(.+)"?$') {
            if ($Response -like "*$($matches[1])*") { $out.AppendLine("PASS: contains '$($matches[1])'") } else { $out.AppendLine("FAIL: does not contain '$($matches[1])'") }
        }
        elseif ($l -match '^matches\s+/(.+)/$') {
            if ($Response -match $matches[1]) { $out.AppendLine("PASS: matches /$($matches[1])/") } else { $out.AppendLine("FAIL: does not match /$($matches[1])/") }
        }
        else { $out.AppendLine("UNKNOWN: $l") }
    }
    return $out.ToString()
}

Write-Log "Script finished"

# Create and run the form
$apiForm = New-APIForm