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
