function ConvertFrom-OpenApiSpec {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }
    
    $content = Get-Content $FilePath -Raw
    $spec = $null
    $isYamlFile = $FilePath -match '\.(ya?ml)$'

    # ConvertFrom-Json -Depth only exists in PowerShell 6.2+; Windows PowerShell 5.1 has no such parameter.
    $fromJson = {
        param($text)
        if ($PSVersionTable.PSVersion.Major -ge 6) { $text | ConvertFrom-Json -Depth 100 -ErrorAction Stop }
        else { $text | ConvertFrom-Json -ErrorAction Stop }
    }

    if (-not $isYamlFile) {
        try { $spec = & $fromJson $content } catch { $spec = $null }
    }

    if (-not $spec) {
        # Not JSON (or a .yaml/.yml file): attempt YAML via the optional 'powershell-yaml' module.
        $yamlAvailable = [bool](Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue)
        if (-not $yamlAvailable) {
            try { Import-Module powershell-yaml -ErrorAction Stop; $yamlAvailable = $true } catch { }
        }
        if (-not $yamlAvailable) {
            throw "This file is not valid JSON, and YAML support requires the 'powershell-yaml' module. Install it with: Install-Module powershell-yaml -Scope CurrentUser   (or convert the spec to JSON first)."
        }
        try {
            $yamlObj = ConvertFrom-Yaml $content
            # Round-trip through JSON so the rest of the code sees PSCustomObjects, not hashtables.
            $spec = & $fromJson ($yamlObj | ConvertTo-Json -Depth 100)
        } catch {
            throw "Failed to parse the OpenAPI spec as JSON or YAML: $($_.Exception.Message)"
        }
    }

    if (-not $spec.paths) {
        throw "Invalid OpenAPI Spec: No paths found."
    }

    $folderName = if ($spec.info -and $spec.info.title) { $spec.info.title } else { "OpenAPI Import" }
    
    $folderId = [guid]::NewGuid().ToString()
    $folderNode = [PSCustomObject]@{
        Id = $folderId
        Type = "Folder"
        Name = $folderName
        Items = @()
    }

    $baseUrl = ""
    if ($spec.servers -and $spec.servers.Count -gt 0) {
        $baseUrl = $spec.servers[0].url
    } elseif ($spec.host) {
        $scheme = if ($spec.schemes) { $spec.schemes[0] } else { "http" }
        $baseUrl = $scheme + "://" + $spec.host + $spec.basePath
    }

    foreach ($path in $spec.paths.PSObject.Properties) {
        $pathUrl = $path.Name
        foreach ($method in $path.Value.PSObject.Properties) {
            $methodName = $method.Name.ToUpper()
            if ($methodName -notin @("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")) {
                continue
            }

            $op = $method.Value
            $reqName = if ($op.summary) { $op.summary } elseif ($op.operationId) { $op.operationId } else { "$methodName $pathUrl" }

            $fullUrl = $baseUrl + $pathUrl

            # Parse parameters to build query string or replace path params with {{vars}}
            $headers = ""
            $queryString = @()
            if ($op.parameters) {
                foreach ($p in $op.parameters) {
                    if ($p.in -eq "query") {
                        $queryString += "$($p.name)={{$($p.name)}}"
                    } elseif ($p.in -eq "header") {
                        $headers += ($p.name + ": `n")
                    } elseif ($p.in -eq "path") {
                        $fullUrl = $fullUrl -replace "\{$($p.name)\}", "{{$($p.name)}}"
                    }
                }
            }
            if ($queryString.Count -gt 0) {
                $fullUrl += "?" + ($queryString -join "&")
            }

            $body = ""
            $bodyType = "text/plain"
            if ($op.requestBody -and $op.requestBody.content) {
                if ($op.requestBody.content.'application/json') {
                    $bodyType = "application/json"
                    $body = "{`n  `n}"
                }
            }

            $reqId = [guid]::NewGuid().ToString()
            $requestObj = [PSCustomObject]@{
                Id = $reqId
                Type = "Request"
                Name = $reqName
                ParentId = $folderId
                RequestData = [PSCustomObject]@{
                    Method = $methodName
                    Url = $fullUrl
                    Headers = $headers
                    Body = $body
                    BodyType = $bodyType
                    AuthType = "None"
                    Tests = ""
                }
            }

            $folderNode.Items += $requestObj
        }
    }

    return $folderNode
}
