function Parse-OpenApiSpec {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }
    
    $content = Get-Content $FilePath -Raw
    $spec = $null
    
    # Try parsing as JSON
    try {
        $spec = $content | ConvertFrom-Json -Depth 100 -ErrorAction Stop
    } catch {
        throw "Failed to parse OpenAPI spec as JSON. (YAML parsing is not yet natively supported without additional modules.)"
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
        Children = @()
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

            $folderNode.Children += $requestObj
        }
    }

    return $folderNode
}
