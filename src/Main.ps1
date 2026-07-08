
# -----------------------------------------------------------------------------
# Execute Application
# -----------------------------------------------------------------------------

function Run-HeadlessCollection {
    param([string]$CollectionName, [string]$EnvName, [string]$DataFilePath, [string]$OutFormat)
    Write-Host "Running in Headless Mode..." -ForegroundColor Cyan
    
    Load-Settings
    Load-Globals
    Load-Environments
    Load-Collections

    # Find the collection
    $collection = $script:collections | Where-Object { $_.Name -eq $CollectionName -and $_.Type -eq "Collection" }
    if (-not $collection) {
        Write-Error "Collection '$CollectionName' not found."
        exit 1
    }

    # Setup Environment
    if ($EnvName -and $script:environments.ContainsKey($EnvName)) {
        $script:activeEnvironment = $EnvName
    } else {
        $script:activeEnvironment = "No Environment"
    }

    $requests = @()
    # Flatten the tree to get all requests
    function Get-RequestsRecursive($node) {
        if ($node.Type -eq "Request") { $requests += $node }
        elseif ($node.Children) { foreach ($child in $node.Children) { Get-RequestsRecursive $child } }
    }
    Get-RequestsRecursive $collection

    if ($requests.Count -eq 0) {
        Write-Warning "No requests found in collection '$CollectionName'."
        exit 0
    }

    $dataRows = @(@{}) # Default to 1 empty row
    if ($DataFilePath -and (Test-Path $DataFilePath)) {
        if ($DataFilePath -match '\.json$') {
            $dataRows = Get-Content $DataFilePath -Raw | ConvertFrom-Json
        } elseif ($DataFilePath -match '\.csv$') {
            $dataRows = Import-Csv $DataFilePath
        }
    }

    $totalPassed = 0
    $totalFailed = 0

    foreach ($row in $dataRows) {
        $script:activeCollectionVariables = @{}
        foreach ($prop in $row.PSObject.Properties) {
            $script:activeCollectionVariables[$prop.Name] = $prop.Value
        }

        foreach ($reqNode in $requests) {
            $req = $reqNode.RequestData
            $method = Substitute-Variables -InputString $req.Method
            $url = Substitute-Variables -InputString $req.Url
            $headersRaw = Substitute-Variables -InputString $req.Headers
            $bodyRaw = Substitute-Variables -InputString $req.Body
            $tests = $req.Tests

            Write-Host "Executing: [$method] $url" -ForegroundColor Yellow

            $headers = @{}
            if (-not [string]::IsNullOrWhiteSpace($headersRaw)) {
                $headersRaw -split "`n" | Where-Object { $_ -match ":" } | ForEach-Object {
                    $idx = $_.IndexOf(":")
                    if ($idx -gt 0) {
                        $key = $_.Substring(0, $idx).Trim()
                        $val = $_.Substring($idx + 1).Trim()
                        if ($key) { $headers[$key] = $val }
                    }
                }
            }

            try {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                if ($method -in @('POST', 'PUT', 'PATCH') -and $bodyRaw) {
                    $response = Invoke-WebRequest -Uri $url -Method $method -Headers $headers -Body $bodyRaw -UseBasicParsing -ErrorAction Stop
                } else {
                    $response = Invoke-WebRequest -Uri $url -Method $method -Headers $headers -UseBasicParsing -ErrorAction Stop
                }
                $sw.Stop()
                
                $status = $response.StatusCode
                $resBody = $response.Content
                Write-Host "  -> $status OK ($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Green

                if ($tests) {
                    $testResults = Invoke-RunTests -Response $resBody -Tests $tests
                    if ($testResults -match "FAIL:") {
                        Write-Host "  [TESTS FAILED]`n$testResults" -ForegroundColor Red
                        $totalFailed++
                    } else {
                        Write-Host "  [TESTS PASSED]" -ForegroundColor Green
                        $totalPassed++
                    }
                }
            } catch {
                Write-Host "  -> Request Failed: $($_.Exception.Message)" -ForegroundColor Red
                $totalFailed++
            }
        }
    }

    Write-Host "`n--- Run Complete ---" -ForegroundColor Cyan
    Write-Host "Passed: $totalPassed" -ForegroundColor Green
    Write-Host "Failed: $totalFailed" -ForegroundColor Red

    if ($totalFailed -gt 0) { exit 1 } else { exit 0 }
}

try {
    if ($Headless) {
        Run-HeadlessCollection -CollectionName $RunCollection -EnvName $Environment -DataFilePath $DataFile -OutFormat $OutputFormat
    } else {
        Write-Log "Starting PowerShell API Tester v$($script:AppVersion)..."
        New-APIForm
    }
} catch {
    Write-Log "FATAL ERROR: $_" -Level Error
    if (-not $Headless) {
        [System.Windows.Forms.MessageBox]::Show("A fatal error occurred: $_", "Fatal Error", 'OK', 'Error')
    } else {
        Write-Error "Fatal Error: $_"
        exit 1
    }
}
