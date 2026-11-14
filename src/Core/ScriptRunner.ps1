#region Script Runner
# UI-independent implementations of: pre-request scripts, test scripts, the console, and "extract variable".

function Get-ActiveEnvironmentData {
    if ($script:activeEnvironment -and $script:activeEnvironment -ne 'No Environment' -and $script:environments.ContainsKey($script:activeEnvironment)) {
        return $script:environments[$script:activeEnvironment]
    }
    return @{}
}

# Runs a pre-request script. The script sees $ApiRequest (Method, Url, Headers, Body) and $Environment and may change
# the request. Returns the (possibly modified) request object.
function Invoke-PreRequestScript {
    param([string]$ScriptText, [Parameter(Mandatory = $true)]$Request)

    if ([string]::IsNullOrWhiteSpace($ScriptText)) { return $Request }
    $ApiRequest = [PSCustomObject]@{ Method = $Request.Method; Url = $Request.Url; Headers = $Request.Headers; Body = $Request.Body }
    $Environment = Get-ActiveEnvironmentData
    Invoke-Command -ScriptBlock ([scriptblock]::Create($ScriptText)) -NoNewScope
    return $ApiRequest
}

# Runs a test script against a finished response. Variables available to the script: $statusCode, $headers, $body,
# $jsonBody, plus Assert-Equal / Assert-Contains / Assert-StatusIs. Returns a list of @{ Status; Message }.
function Invoke-TestScript {
    param([string]$ScriptText, [Parameter(Mandatory = $true)]$Result)

    $script:testResults = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($ScriptText)) { return @() }

    $statusCode = [int]$Result.StatusCode
    $headers = @{}
    foreach ($headerLine in @($Result.HeaderLines)) {
        $separator = ([string]$headerLine).IndexOf(':')
        if ($separator -gt 0) { $headers[$headerLine.Substring(0, $separator).Trim()] = $headerLine.Substring($separator + 1).Trim() }
    }
    $body = if ($Result.IsBinary) { '[Binary content]' } else { [string]$Result.Body }
    $jsonBody = $null
    try { if (-not $Result.IsBinary) { $jsonBody = $body | ConvertFrom-Json -ErrorAction Stop } } catch { }
    $responseTimeMs = [int]$Result.ElapsedMs
    $testScope = @{ statusCode = $statusCode; headers = $headers; body = $body; jsonBody = $jsonBody; responseTimeMs = $responseTimeMs }

    try {
        Invoke-Command -ScriptBlock ([scriptblock]::Create($ScriptText)) -ArgumentList $testScope -NoNewScope -ErrorAction Stop
    } catch {
        [void]$script:testResults.Add([PSCustomObject]@{ Status = 'ERROR'; Message = "Test script failed to execute: $($_.Exception.Message)" })
    }
    return @($script:testResults)
}

# Extracts a value from a response. Source: Body | Headers. Mode: 'JSON Path' | 'Regex'.
# Returns @{ Success; Value; Error }.
function Get-ExtractedValue {
    param([string]$Source, [string]$Mode, [string]$Path, [string]$BodyText, [string]$HeadersText)

    $rawText = if ($Source -eq 'Headers') { $HeadersText } else { $BodyText }
    if ([string]::IsNullOrWhiteSpace($rawText)) { return @{ Success = $false; Error = 'No response content to extract.' } }
    if ([string]::IsNullOrWhiteSpace($Path)) { return @{ Success = $false; Error = if ($Mode -eq 'JSON Path') { 'JSON path is required.' } else { 'Regex pattern is required.' } } }

    if ($Mode -eq 'JSON Path') {
        if ($Source -ne 'Body') { return @{ Success = $false; Error = 'JSON Path only supports the Body source.' } }
        try {
            $jsonObject = $rawText | ConvertFrom-Json -ErrorAction Stop
            $value = Get-JsonPathValue -JsonObject $jsonObject -Path $Path.Trim()
            if ($null -eq $value) { return @{ Success = $false; Error = 'Path not found.' } }
            return @{ Success = $true; Value = $(if ($value -is [string]) { $value } else { $value | ConvertTo-Json -Depth 10 }) }
        } catch { return @{ Success = $false; Error = 'Invalid JSON or path.' } }
    }

    try {
        $match = [regex]::Match($rawText, $Path, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if (-not $match.Success) { return @{ Success = $false; Error = 'No regex match.' } }
        $value = if ($match.Groups.Count -gt 1 -and $match.Groups[1].Value) { $match.Groups[1].Value } else { $match.Value }
        return @{ Success = $true; Value = $value }
    } catch { return @{ Success = $false; Error = 'Invalid regex.' } }
}

# Stores an extracted value in the Global / Collection / Environment scope. Returns @{ Success; Message }.
function Save-ExtractedVariable {
    param([string]$Scope, [string]$Name, [string]$Value)

    switch ($Scope) {
        'Global' {
            $script:globals[$Name] = $Value
            Save-Globals
        }
        'Collection' {
            $collection = $script:activeCollection
            if (-not $collection) { return @{ Success = $false; Message = 'No active collection. Load a request from a collection first.' } }
            if (-not ($collection.PSObject.Properties.Name -contains 'Variables') -or $null -eq $collection.Variables) {
                $collection | Add-Member -MemberType NoteProperty -Name 'Variables' -Value @{} -Force
            }
            if ($collection.Variables -is [System.Management.Automation.PSCustomObject]) {
                $converted = @{}
                foreach ($property in $collection.Variables.PSObject.Properties) { $converted[$property.Name] = $property.Value }
                $collection.Variables = $converted
            }
            $collection.Variables[$Name] = $Value
            $script:activeCollectionVariables = $collection.Variables
            Save-Collections
        }
        'Environment' {
            if ($script:activeEnvironment -eq 'No Environment' -or -not $script:environments.ContainsKey($script:activeEnvironment)) {
                return @{ Success = $false; Message = 'No active environment selected.' }
            }
            $environmentData = $script:environments[$script:activeEnvironment]
            if ($environmentData -is [hashtable]) {
                if ($null -eq $environmentData['Variables']) { $environmentData['Variables'] = @{} }
                $environmentData['Variables'][$Name] = $Value
            } else {
                if (-not ($environmentData.PSObject.Properties.Name -contains 'Variables') -or $null -eq $environmentData.Variables) {
                    $environmentData | Add-Member -MemberType NoteProperty -Name 'Variables' -Value @{} -Force
                }
                $environmentData.Variables[$Name] = $Value
            }
            Save-Environments
        }
        default { return @{ Success = $false; Message = "Unknown scope '$Scope'." } }
    }
    return @{ Success = $true; Message = "Saved '$Name' to $Scope." }
}

# Lists the variable names that already exist in a scope (for the "browse" drop-down).
function Get-VariableNames {
    param([string]$Scope)
    $names = @()
    switch ($Scope) {
        'Global' { if ($script:globals) { $names = @($script:globals.Keys) } }
        'Collection' {
            $variables = if ($script:activeCollection) { $script:activeCollection.Variables } else { $null }
            if ($variables -is [hashtable]) { $names = @($variables.Keys) }
            elseif ($variables) { $names = @($variables.PSObject.Properties.Name) }
        }
        'Environment' {
            $environmentData = Get-ActiveEnvironmentData
            $variables = if ($environmentData -is [hashtable]) { $environmentData['Variables'] } else { $environmentData.Variables }
            if ($variables -is [hashtable]) { $names = @($variables.Keys) }
            elseif ($variables) { $names = @($variables.PSObject.Properties.Name) }
        }
    }
    return @($names | Sort-Object)
}

# Console: runs one command. A language prefix switches the interpreter ("python: print(1)", "js: ...", "bash: ...").
# PowerShell runs inside this session so scripts can use $script:globals etc. Returns @{ Output; Error; Language }.
function Invoke-ConsoleCommand {
    param([string]$Code, [string]$DefaultLanguage = 'PowerShell')

    $language = $DefaultLanguage
    $scriptToRun = $Code
    if     ($Code -match '^(python|py):\s*(.*)')              { $language = 'Python'; $scriptToRun = $Matches[2] }
    elseif ($Code -match '^(js|node|javascript):\s*(.*)')     { $language = 'JavaScript (Node.js)'; $scriptToRun = $Matches[2] }
    elseif ($Code -match '^(php):\s*(.*)')                    { $language = 'PHP'; $scriptToRun = $Matches[2] }
    elseif ($Code -match '^(ruby|rb):\s*(.*)')                { $language = 'Ruby'; $scriptToRun = $Matches[2] }
    elseif ($Code -match '^(go):\s*(.*)')                     { $language = 'Go'; $scriptToRun = $Matches[2] }
    elseif ($Code -match '^(bat|cmd|batch):\s*(.*)')          { $language = 'Batch'; $scriptToRun = $Matches[2] }
    elseif ($Code -match '^(bash|sh):\s*(.*)')                { $language = 'Bash'; $scriptToRun = $Matches[2] }
    elseif ($Code -match '^(ps|pwsh|powershell):\s*(.*)')     { $language = 'PowerShell'; $scriptToRun = $Matches[2] }

    try {
        if ($language -eq 'PowerShell') {
            return @{ Language = $language; Output = (Invoke-Expression $scriptToRun | Out-String); Error = '' }
        }
        $interpreters = @{
            'JavaScript (Node.js)' = @{ Exe = 'node';   Ext = '.js';  Args = { param($f) @($f) } }
            'Python'               = @{ Exe = 'python'; Ext = '.py';  Args = { param($f) @($f) } }
            'PHP'                  = @{ Exe = 'php';    Ext = '.php'; Args = { param($f) @($f) } }
            'Ruby'                 = @{ Exe = 'ruby';   Ext = '.rb';  Args = { param($f) @($f) } }
            'Go'                   = @{ Exe = 'go';     Ext = '.go';  Args = { param($f) @('run', $f) } }
            'Batch'                = @{ Exe = 'cmd';    Ext = '.bat'; Args = { param($f) @('/c', $f) } }
            'Bash'                 = @{ Exe = 'bash';   Ext = '.sh';  Args = { param($f) @($f) } }
        }
        $interpreter = $interpreters[$language]
        $scriptFile = [System.IO.Path]::GetTempFileName() + $interpreter.Ext
        try {
            Set-Content -Path $scriptFile -Value $scriptToRun -Encoding UTF8
            $processInfo = New-Object System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = $interpreter.Exe
            $processInfo.Arguments = (& $interpreter.Args $scriptFile | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
            $processInfo.RedirectStandardOutput = $true
            $processInfo.RedirectStandardError = $true
            $processInfo.UseShellExecute = $false
            $processInfo.CreateNoWindow = $true
            $process = [System.Diagnostics.Process]::Start($processInfo)
            $standardOutput = $process.StandardOutput.ReadToEnd()
            $standardError = $process.StandardError.ReadToEnd()
            $process.WaitForExit()
            return @{ Language = $language; Output = $standardOutput; Error = $standardError }
        } finally { Remove-Item $scriptFile -ErrorAction SilentlyContinue }
    } catch {
        return @{ Language = $language; Output = ''; Error = $_.Exception.Message }
    }
}
#endregion
