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
