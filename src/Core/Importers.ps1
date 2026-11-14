#region Collection Importers
# Top-level (script-scope) importer functions shared by every import entry point in the UI.

# Maps a Postman auth block to this app's authentication object. Returns $null when the block is absent.
function Convert-PostmanAuth {
    param($PostmanAuth)
    if (-not $PostmanAuth) { return $null }
    $getAuthValue = {
        param($entries, $name)
        $match = @($entries) | Where-Object { $_.key -eq $name } | Select-Object -First 1
        if ($match) { $match.value } else { $null }
    }
    switch ($PostmanAuth.type) {
        "noauth" { return @{ Type = "No Auth" } }
        "basic" {
            return @{ Type = "Basic Auth"; Username = (& $getAuthValue $PostmanAuth.basic "username"); Password = (& $getAuthValue $PostmanAuth.basic "password") }
        }
        "bearer" {
            return @{ Type = "Bearer Token"; Token = (& $getAuthValue $PostmanAuth.bearer "token") }
        }
        "apikey" {
            $location = & $getAuthValue $PostmanAuth.apikey "in"
            $addTo = if ($location -eq "query") { "Query Parameter" } else { "Header" }
            return @{ Type = "API Key"; Key = (& $getAuthValue $PostmanAuth.apikey "key"); Value = (& $getAuthValue $PostmanAuth.apikey "value"); AddTo = $addTo }
        }
        default { return @{ Type = "No Auth" } }
    }
}

function Convert-PostmanItems {
    param($Items, $InheritedAuth = $null)
    $converted = @()
    foreach ($item in $Items) {
        if ($item.item) {
            # A folder's own auth overrides the inherited one for everything below it.
            $folderAuth = Convert-PostmanAuth -PostmanAuth $item.auth
            if (-not $folderAuth) { $folderAuth = $InheritedAuth }
            $folder = [PSCustomObject]@{
                Name = $item.name
                Type = "Folder"
                Items = @(Convert-PostmanItems -Items $item.item -InheritedAuth $folderAuth)
            }
            $converted += $folder
        } elseif ($item.request) {
            $req = $item.request
            if ($req.url -is [string]) { $url = $req.url } elseif ($req.url.raw) { $url = $req.url.raw } else { $url = "" }
            $method = $req.method
            
            $headers = ""
            if ($req.header) {
                $headers = (@($req.header) | Where-Object { $_.disabled -ne $true } | ForEach-Object { "$($_.key): $($_.value)" }) -join "`r`n"
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

            # Only fall back to inherited auth when the request has no auth block at all.
            $authData = Convert-PostmanAuth -PostmanAuth $req.auth
            if (-not $authData) { $authData = if ($InheritedAuth) { $InheritedAuth } else { @{ Type = "No Auth" } } }

            $converted += [PSCustomObject]@{ Name = $item.name; Type = "Request"; RequestData = [PSCustomObject]@{ Timestamp = Get-Date; Method = $method; Url = $url; Headers = $headers; Body = $body; BodyType = $bodyType; OutputFormat = ""; Tests = ""; PreRequestScript = ""; Authentication = $authData } }
        }
    }
    return $converted
}

# Builds a native collection node from a parsed Postman v2.x collection object.
function Convert-PostmanCollection {
    param($PostmanJson)
    if (-not $PostmanJson.info -or -not $PostmanJson.item) {
        throw "Invalid Postman Collection format. Only v2.x is supported."
    }
    $collectionAuth = Convert-PostmanAuth -PostmanAuth $PostmanJson.auth
    $importedItems  = @(Convert-PostmanItems -Items $PostmanJson.item -InheritedAuth $collectionAuth)
    # Collection-level variables ({{baseUrl}} etc.); disabled ones are skipped.
    $collectionVariables = @{}
    foreach ($variable in @($PostmanJson.variable)) {
        if ($variable -and $variable.key -and $variable.disabled -ne $true) { $collectionVariables[[string]$variable.key] = [string]$variable.value }
    }
    return [PSCustomObject]@{ Name = $PostmanJson.info.name; Type = "Collection"; Items = $importedItems; Variables = $collectionVariables }
}

# Detects what kind of collection file a parsed JSON document is: Postman, OpenApi, Native or Unknown.
function Get-ImportFileKind {
    param($ParsedJson)
    if ($null -eq $ParsedJson) { return "Unknown" }
    $propertyNames = @($ParsedJson.PSObject.Properties.Name)
    if ($propertyNames -contains "info" -and $propertyNames -contains "item") { return "Postman" }
    if ($propertyNames -contains "openapi" -or $propertyNames -contains "swagger") { return "OpenApi" }
    if ($propertyNames -contains "log" -and $ParsedJson.log.PSObject.Properties.Name -contains "entries") { return "Har" }
    if ($propertyNames -contains "resources" -and ([string]$ParsedJson._type -eq "export" -or $propertyNames -contains "__export_format")) { return "Insomnia" }
    $first = @($ParsedJson)[0]
    if ($first -and ($first.PSObject.Properties.Name -contains "Type") -and ($first.PSObject.Properties.Name -contains "Name")) { return "Native" }
    return "Unknown"
}

# Reads any supported collection file and returns an array of native collection nodes.
function Import-CollectionFile {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { throw "File not found: $FilePath" }

    if ($FilePath -match '\.(ya?ml)$') { return @(ConvertFrom-OpenApiSpec -FilePath $FilePath) }

    $parsed = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
    switch (Get-ImportFileKind -ParsedJson $parsed) {
        "Postman" { return @(Convert-PostmanCollection -PostmanJson $parsed) }
        "OpenApi" { return @(ConvertFrom-OpenApiSpec -FilePath $FilePath) }
        "Native"  { return @($parsed) }
        "Har"     { return @(ConvertFrom-HarLog -HarJson $parsed -Name ([System.IO.Path]::GetFileNameWithoutExtension($FilePath))) }
        "Insomnia" { return @(ConvertFrom-InsomniaExport -Export $parsed) }
        default   { throw "Unrecognized file format. Expected a Postman collection, an OpenAPI spec, a HAR file, an Insomnia export, or an API Tester collections export." }
    }
}

# Splits a command line into arguments the way a POSIX shell would (single/double quotes, backslash escapes,
# and line continuations with "\" or "^").
function Split-ShellArguments {
    param([string]$Text)

    $arguments = New-Object System.Collections.Generic.List[string]
    $current = New-Object System.Text.StringBuilder
    $hasToken = $false
    $quote = ''
    $characters = ($Text -replace '\\\r?\n', ' ' -replace '\^\r?\n', ' ').ToCharArray()

    for ($index = 0; $index -lt $characters.Length; $index++) {
        $character = $characters[$index]
        if ($quote -eq "'") {
            if ($character -eq "'") { $quote = '' } else { [void]$current.Append($character) }
            continue
        }
        if ($quote -eq '"') {
            if ($character -eq '\' -and ($index + 1) -lt $characters.Length -and '"\$`'.Contains([string]$characters[$index + 1])) {
                $index++
                [void]$current.Append($characters[$index])
            } elseif ($character -eq '"') { $quote = '' }
            else { [void]$current.Append($character) }
            continue
        }
        if ($character -eq "'" -or $character -eq '"') { $quote = [string]$character; $hasToken = $true; continue }
        if ([char]::IsWhiteSpace($character)) {
            if ($hasToken) { $arguments.Add($current.ToString()); [void]$current.Clear(); $hasToken = $false }
            continue
        }
        if ($character -eq '\' -and ($index + 1) -lt $characters.Length) {
            $index++
            [void]$current.Append($characters[$index]); $hasToken = $true
            continue
        }
        [void]$current.Append($character); $hasToken = $true
    }
    if ($hasToken) { $arguments.Add($current.ToString()) }
    return ,$arguments.ToArray()
}

# Parses a cURL command into a request description:
# @{ Method; Url; HeaderText; Body; BodyType (MIME-style: application/json ...); Authentication; Warnings }
function ConvertFrom-CurlCommand {
    param([Parameter(Mandatory = $true)][string]$CommandText)

    $tokens = Split-ShellArguments -Text $CommandText.Trim()
    $url = ''
    $explicitMethod = ''
    $useHeadMethod = $false
    $dataParts = New-Object System.Collections.Generic.List[string]
    $headerLines = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $authentication = @{ Type = 'No Auth' }
    $optionsWithValueToSkip = '^(-o|--output|-m|--max-time|--connect-timeout|-x|--proxy|--cacert|--cert|--key|-w|--write-out|--retry|-K|--config|-c|--cookie-jar|-T|--upload-file|-E)$'

    $index = 0
    if ($tokens.Count -gt 0 -and $tokens[0] -match '^(?i)curl(\.exe)?$') { $index = 1 }

    while ($index -lt $tokens.Count) {
        $token = $tokens[$index]; $index++
        $nextValue = if ($index -lt $tokens.Count) { $tokens[$index] } else { '' }

        if ($token -cmatch '^(-X|--request)$')                      { $explicitMethod = $nextValue.ToUpperInvariant(); $index++ }
        elseif ($token -cmatch '^-X.+')                             { $explicitMethod = $token.Substring(2).ToUpperInvariant() }
        elseif ($token -cmatch '^(-H|--header)$')                   { $headerLines.Add($nextValue); $index++ }
        elseif ($token -cmatch '^(-d|--data|--data-raw|--data-binary|--data-ascii|--data-urlencode)$') {
            if ($nextValue.StartsWith('@')) { $warnings.Add("Body from file '$nextValue' was not loaded; paste its content into the Body tab.") }
            else { $dataParts.Add($nextValue) }
            $index++
        }
        elseif ($token -cmatch '^(-u|--user)$') {
            $separator = $nextValue.IndexOf(':')
            if ($separator -ge 0) { $authentication = @{ Type = 'Basic Auth'; Username = $nextValue.Substring(0, $separator); Password = $nextValue.Substring($separator + 1) } }
            else { $authentication = @{ Type = 'Basic Auth'; Username = $nextValue; Password = '' } }
            $index++
        }
        elseif ($token -cmatch '^--url$')                           { $url = $nextValue; $index++ }
        elseif ($token -cmatch '^(-A|--user-agent)$')               { $headerLines.Add("User-Agent: $nextValue"); $index++ }
        elseif ($token -cmatch '^(-e|--referer)$')                  { $headerLines.Add("Referer: $nextValue"); $index++ }
        elseif ($token -cmatch '^(-b|--cookie)$')                   { $headerLines.Add("Cookie: $nextValue"); $index++ }
        elseif ($token -cmatch '^(-I|--head)$')                     { $useHeadMethod = $true }
        elseif ($token -cmatch '^(-F|--form|--form-string)$')       { $warnings.Add("Multipart form field '$nextValue' is not supported yet and was skipped."); $index++ }
        elseif ($token -cmatch $optionsWithValueToSkip)             { $index++ }
        elseif ($token -cmatch '^(-k|--insecure)$')                 { $warnings.Add("The command used --insecure; enable 'Ignore SSL errors' in Settings if you need that.") }
        elseif ($token -cmatch '^-')                                { } # --compressed, -L, -s, -v, -i ... have no effect here
        elseif (-not $url)                                          { $url = $token }
    }

    # Pull Content-Type / Authorization out of the header list so the dedicated controls can represent them.
    $contentType = ''
    $remainingHeaders = New-Object System.Collections.Generic.List[string]
    foreach ($line in $headerLines) {
        if ($line -match '^\s*Content-Type\s*:\s*(.+)$') { $contentType = $Matches[1].Trim(); continue }
        if ($line -match '^\s*Authorization\s*:\s*Bearer\s+(.+)$' -and $authentication.Type -eq 'No Auth') {
            $authentication = @{ Type = 'Bearer Token'; Token = $Matches[1].Trim() }; continue
        }
        $remainingHeaders.Add($line.Trim())
    }

    $body = $dataParts -join '&'
    $bodyType = 'application/json'
    if ($body) {
        if ($contentType -match 'json') { $bodyType = 'application/json' }
        elseif ($contentType -match 'xml') { $bodyType = 'application/xml' }
        elseif ($contentType -match 'x-www-form-urlencoded') { $bodyType = 'application/x-www-form-urlencoded' }
        elseif ($contentType -match 'text/plain') { $bodyType = 'text/plain' }
        elseif ($body.TrimStart() -match '^[\{\[]') { $bodyType = 'application/json' }
        elseif ($body -match '^[^=\s&]+=') { $bodyType = 'application/x-www-form-urlencoded' }
        else { $bodyType = 'text/plain' }
        if ($contentType -and $bodyType -eq 'text/plain' -and $contentType -notmatch 'text/plain') { $remainingHeaders.Add("Content-Type: $contentType") }
    }

    $method = if ($explicitMethod) { $explicitMethod } elseif ($useHeadMethod) { 'HEAD' } elseif ($body) { 'POST' } else { 'GET' }

    return [PSCustomObject]@{
        Method = $method; Url = $url; HeaderText = ($remainingHeaders -join "`r`n"); Body = $body
        BodyType = $bodyType; Authentication = $authentication; Warnings = @($warnings)
    }
}


# --- HAR (browser "Save all as HAR") ----------------------------------------------------------------
function ConvertTo-BodyTypeFromMime {
    param([string]$MimeType)
    switch -Regex ($MimeType) {
        'json' { return 'application/json' } 'xml' { return 'application/xml' } 'x-www-form-urlencoded' { return 'application/x-www-form-urlencoded' }
        'multipart' { return 'multipart/form-data' } 'graphql' { return 'GraphQL' } default { return 'text/plain' }
    }
}

function ConvertFrom-HarLog {
    param([Parameter(Mandatory = $true)]$HarJson, [string]$Name = 'HAR import')
    $skipHeaders = @('content-length', 'host', 'connection', 'accept-encoding')
    $items = foreach ($entry in @($HarJson.log.entries)) {
        $request = $entry.request
        if (-not $request) { continue }
        $headerLines = @($request.headers | Where-Object { $_.name -and -not $_.name.StartsWith(':') -and $_.name.ToLowerInvariant() -notin $skipHeaders } | ForEach-Object { "$($_.name): $($_.value)" })
        $body = ''; $bodyType = 'application/json'
        if ($request.postData) {
            $bodyType = ConvertTo-BodyTypeFromMime -MimeType ([string]$request.postData.mimeType)
            if (@($request.postData.params).Count -gt 0 -and $bodyType -in @('application/x-www-form-urlencoded', 'multipart/form-data')) {
                $body = (@($request.postData.params | ForEach-Object { if ($_.fileName) { "$($_.name)=@`"$($_.fileName)`"" } else { "$($_.name)=$($_.value)" } }) -join "`r`n")
            } else { $body = [string]$request.postData.text }
        }
        $path = try { ([uri]$request.url).AbsolutePath } catch { [string]$request.url }
        [PSCustomObject]@{
            Name = "$($request.method) $path"; Type = 'Request'
            RequestData = [PSCustomObject]@{ Method = [string]$request.method; Url = [string]$request.url; Headers = ($headerLines -join "`r`n"); Body = $body; BodyType = $bodyType
                Authentication = @{ Type = 'No Auth' }; Tests = ''; PreRequestScript = ''; OutputFormat = '' }
        }
    }
    return [PSCustomObject]@{ Name = $Name; Type = 'Collection'; Items = @($items); Variables = @{} }
}

# --- Insomnia (Application -> Export Data, v4 JSON) ----------------------------------------------------
function ConvertFrom-InsomniaExport {
    param([Parameter(Mandatory = $true)]$Export)
    $resources = @($Export.resources | Where-Object { $_ })
    $toVariable = { param([string]$text) [regex]::Replace([string]$text, '\{\{\s*_\.([\w.\-]+)\s*\}\}', '{{$1}}') }
    $convertRequest = {
        param($resource)
        $headers = @($resource.headers | Where-Object { $_.name -and -not $_.disabled } | ForEach-Object { "$($_.name): $(& $toVariable $_.value)" })
        $bodyType = 'application/json'; $body = ''
        if ($resource.body) {
            $bodyType = ConvertTo-BodyTypeFromMime -MimeType ([string]$resource.body.mimeType)
            if (@($resource.body.params).Count -gt 0) {
                $body = (@($resource.body.params | Where-Object { -not $_.disabled } | ForEach-Object { if ($_.type -eq 'file') { "$($_.name)=@`"$($_.fileName)`"" } else { "$($_.name)=$(& $toVariable $_.value)" } }) -join "`r`n")
            } else { $body = & $toVariable $resource.body.text }
        }
        $auth = @{ Type = 'No Auth' }
        $sourceAuth = $resource.authentication
        if ($sourceAuth -and -not $sourceAuth.disabled) {
            switch ([string]$sourceAuth.type) {
                'bearer' { $auth = @{ Type = 'Bearer Token'; Token = (& $toVariable $sourceAuth.token) } }
                'basic'  { $auth = @{ Type = 'Basic Auth'; Username = (& $toVariable $sourceAuth.username); Password = (& $toVariable $sourceAuth.password) } }
                'apikey' { $auth = @{ Type = 'API Key'; Key = [string]$sourceAuth.key; Value = (& $toVariable $sourceAuth.value); AddTo = $(if ($sourceAuth.addTo -eq 'queryParams') { 'Query Parameter' } else { 'Header' }) } }
            }
        }
        [PSCustomObject]@{
            Name = [string]$resource.name; Type = 'Request'
            RequestData = [PSCustomObject]@{ Method = [string]$resource.method; Url = (& $toVariable $resource.url); Headers = ($headers -join "`r`n"); Body = $body; BodyType = $bodyType
                Authentication = $auth; Tests = ''; PreRequestScript = ''; OutputFormat = '' }
        }
    }
    $buildChildren = {
        param([string]$parentId)
        $children = @($resources | Where-Object { $_.parentId -eq $parentId -and $_._type -in @('request_group', 'request') } | Sort-Object { [double]$(if ($_.metaSortKey) { $_.metaSortKey } else { 0 }) })
        foreach ($child in $children) {
            if ($child._type -eq 'request_group') { [PSCustomObject]@{ Name = [string]$child.name; Type = 'Folder'; Items = @(& $buildChildren $child._id) } }
            else { & $convertRequest $child }
        }
    }
    $collections = @()
    foreach ($workspace in @($resources | Where-Object { $_._type -eq 'workspace' })) {
        $variables = @{}
        foreach ($environment in @($resources | Where-Object { $_._type -eq 'environment' -and $_.parentId -eq $workspace._id })) {
            if ($environment.data) { foreach ($property in $environment.data.PSObject.Properties) { $variables[$property.Name] = [string]$property.Value } }
        }
        $collections += [PSCustomObject]@{ Name = [string]$workspace.name; Type = 'Collection'; Items = @(& $buildChildren $workspace._id); Variables = $variables }
    }
    if ($collections.Count -eq 0) {
        $roots = @($resources | Where-Object { $_._type -eq 'request' })
        $collections += [PSCustomObject]@{ Name = 'Insomnia import'; Type = 'Collection'; Items = @($roots | ForEach-Object { & $convertRequest $_ }); Variables = @{} }
    }
    return ,$collections
}

#endregion
