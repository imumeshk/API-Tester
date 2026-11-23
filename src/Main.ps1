
# -----------------------------------------------------------------------------
# Execute Application
# -----------------------------------------------------------------------------

function Invoke-HeadlessCollection {
    param([string]$CollectionName, [string]$EnvName, [string]$DataFilePath, [string]$OutFormat)
    $Retries = [Math]::Max(0, [int]$script:Retries)
    Write-Host "Running in Headless Mode..." -ForegroundColor Cyan

    Import-Settings
    Import-Globals
    Import-Environments
    Import-Collections

    $collection = $script:collections | Where-Object { $_.Name -eq $CollectionName -and $_.Type -eq "Collection" } | Select-Object -First 1
    if (-not $collection) {
        Write-Error "Collection '$CollectionName' not found."
        exit 1
    }
    $script:activeEnvironment = if ($EnvName -and $script:environments.ContainsKey($EnvName)) { $EnvName } else { "No Environment" }
    # Collection variables keep working; data-file columns are layered on top for each iteration.
    $script:activeCollection = $collection
    $script:activeCollectionVariables = if ($collection.Variables) { $collection.Variables } else { @{} }

    $requests = @(Get-RequestsFromItem -Item $collection)
    if ($requests.Count -eq 0) {
        Write-Warning "No requests found in collection '$CollectionName'."
        exit 0
    }

    $iterations = @(@{})
    if ($DataFilePath -and (Test-Path $DataFilePath)) {
        $dataRows = @(Import-RunnerDataFile -Path $DataFilePath)
        if ($dataRows.Count -gt 0) {
            $iterations = @(foreach ($dataRow in $dataRows) { $variables = @{}; foreach ($property in $dataRow.PSObject.Properties) { $variables[$property.Name] = [string]$property.Value }; $variables })
        }
    }

    $timeout = if ($script:settings.RequestTimeoutSeconds -gt 0) { [int]$script:settings.RequestTimeoutSeconds } else { 60 }
    $results = New-Object System.Collections.Generic.List[object]
    $iterationNumber = 0
    foreach ($iterationVariables in $iterations) {
        $iterationNumber++
        $script:iterationVariables = $iterationVariables
        foreach ($entry in $requests) {
            $name = "$($entry.Path)$($entry.Item.Name)"
            $request = Copy-RequestData (Get-RequestObjectFromItem -Item $entry.Item)
            if (-not $request) { $results.Add([PSCustomObject]@{ Iteration = $iterationNumber; Name = $name; Method = ''; Url = ''; Status = 'ERROR'; StatusCode = 0; TimeMs = 0; Message = 'Missing request data'; Tests = '' }); continue }
            Initialize-RequestTabDefaults -TabState $request
            $request = Resolve-InheritedRequest -Request $request -Root $collection -Item $entry.Item
            $status = 'PASS'; $message = ''; $testSummary = ''
            for ($attempt = 0; $attempt -le [Math]::Max(0, $Retries); $attempt++) {
            if ($attempt -gt 0) { Write-Host "  -> retry $attempt of $Retries" -ForegroundColor DarkYellow; Start-Sleep -Seconds 1 }
            $status = 'PASS'; $message = ''; $testSummary = ''
            try {
                if ($request.PreRequestScript -match '\S') {
                    $modified = Invoke-PreRequestScript -ScriptText $request.PreRequestScript -Request $request
                    $request.Method = [string]$modified.Method; $request.Url = [string]$modified.Url; $request.Headers = [string]$modified.Headers; $request.Body = [string]$modified.Body
                }
                Write-Host "Executing: [$($request.Method)] $(Expand-Variables -InputString $request.Url)" -ForegroundColor Yellow
                $result = Invoke-HttpRequestSync -Request $request -TimeoutSeconds $timeout
                if (-not $result.Success) { $status = 'ERROR'; $message = [string]$result.ErrorMessage }
                else {
                    $message = "$($result.StatusCode) $($result.ReasonPhrase)".Trim()
                    if ($result.StatusCode -ge 400) { $status = 'FAIL' }
                    if ($request.Tests -match '\S') {
                        $testResults = @(Invoke-TestScript -ScriptText $request.Tests -Result $result)
                        $failedTests = @($testResults | Where-Object { $_.Status -ne 'PASS' })
                        $testSummary = "$($testResults.Count - $failedTests.Count)/$($testResults.Count) passed"
                        if ($failedTests.Count -gt 0) { $status = 'FAIL'; foreach ($failure in $failedTests) { Write-Host "    [$($failure.Status)] $($failure.Message)" -ForegroundColor Red } }
                    }
                }
            } catch { $status = 'ERROR'; $message = $_.Exception.Message; $result = @{ StatusCode = 0; ElapsedMs = 0 } }
            if ($status -eq 'PASS') { break }
            }
            $color = if ($status -eq 'PASS') { 'Green' } else { 'Red' }
            Write-Host "  -> $status $message ($($result.ElapsedMs) ms)$(if ($testSummary) { " - tests $testSummary" })" -ForegroundColor $color
            $results.Add([PSCustomObject]@{ Iteration = $iterationNumber; Name = $name; Method = $request.Method; Url = $request.Url; Status = $status; StatusCode = [int]$result.StatusCode; TimeMs = [int]$result.ElapsedMs; Message = $message; Tests = $testSummary })
        }
    }
    $script:iterationVariables = $null

    $passed = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    $failed = $results.Count - $passed
    switch -Regex ($OutFormat) {
        '^(?i)json$'  { [PSCustomObject]@{ Collection = $CollectionName; Passed = $passed; Failed = $failed; Results = $results } | ConvertTo-Json -Depth 5 | Write-Output }
        '^(?i)html$'  { Write-Output (New-RunnerReportHtml -Title "Collection run: $CollectionName" -Rows @($results | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Method = $_.Method; Url = $_.Url; Status = $_.Status; Result = $_.Message; TimeMs = $_.TimeMs; Tests = $_.Tests } })) }
        '^(?i)junit$' {
            $xml = New-Object System.Text.StringBuilder
            [void]$xml.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
            [void]$xml.AppendLine("<testsuite name=`"$([System.Security.SecurityElement]::Escape($CollectionName))`" tests=`"$($results.Count)`" failures=`"$failed`">")
            foreach ($row in $results) {
                [void]$xml.Append("  <testcase name=`"$([System.Security.SecurityElement]::Escape("$($row.Name) #$($row.Iteration)"))`" time=`"$([Math]::Round($row.TimeMs / 1000, 3))`">")
                if ($row.Status -ne 'PASS') { [void]$xml.Append("<failure message=`"$([System.Security.SecurityElement]::Escape($row.Message))`"/>") }
                [void]$xml.AppendLine('</testcase>')
            }
            [void]$xml.AppendLine('</testsuite>')
            Write-Output $xml.ToString()
        }
        default {
            Write-Host "`n--- Run Complete ---" -ForegroundColor Cyan
            Write-Host "Passed: $passed" -ForegroundColor Green
            Write-Host "Failed: $failed" -ForegroundColor Red
        }
    }
    if ($failed -gt 0) { exit 1 } else { exit 0 }
}

try {
    if ($Headless) {
        Invoke-HeadlessCollection -CollectionName $RunCollection -EnvName $Environment -DataFilePath $DataFile -OutFormat $OutputFormat
    } else {
        Write-Log "Starting PowerShell API Tester v$($script:AppVersion)..."
        if ($RunMonitors) { Invoke-MonitorService }
        elseif ($ClassicUi) { New-ApiForm }
        else {
            # The window is shown again when it asked to be rebuilt (theme change that could not be applied in place).
            do { $script:reopenMainWindow = $false; Show-MainWindow } while ($script:reopenMainWindow)
        }
    }
} catch {
    $fatalDetails = "$($_.Exception.Message)`r`n`r`n$($_.InvocationInfo.PositionMessage)`r`n`r`n$($_.ScriptStackTrace)"
    try { Write-Log "FATAL ERROR: $fatalDetails" -Level Error } catch { }
    Write-Host "FATAL ERROR: $fatalDetails" -ForegroundColor Red
    if (-not $Headless) {
        try { [System.Windows.Forms.MessageBox]::Show("A fatal error occurred:`r`n`r`n$fatalDetails", "Fatal Error", 'OK', 'Error') | Out-Null } catch { }
    } else {
        Write-Error "Fatal Error: $fatalDetails"
        exit 1
    }
}
