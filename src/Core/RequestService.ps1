#region Request Service
# UI-independent HTTP sending used by the XAML main window. Nothing here touches WinForms or WPF controls,
# so the same functions can be reused by the headless runner, the collection runner and the monitors later.

# Pretty-prints JSON text without re-serialising it (keeps numbers, key order and escapes exactly as received).
function Format-JsonText {
    param([string]$Text, [int]$IndentSize = 2)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $builder = New-Object System.Text.StringBuilder
    $indentLevel = 0
    $insideString = $false
    $escapeNext = $false
    $characters = $Text.ToCharArray()

    for ($index = 0; $index -lt $characters.Length; $index++) {
        $character = $characters[$index]
        if ($insideString) {
            [void]$builder.Append($character)
            if ($escapeNext) { $escapeNext = $false }
            elseif ($character -eq '\') { $escapeNext = $true }
            elseif ($character -eq '"') { $insideString = $false }
            continue
        }
        switch ($character) {
            '"' { $insideString = $true; [void]$builder.Append($character) }
            { $_ -eq '{' -or $_ -eq '[' } {
                [void]$builder.Append($character)
                $lookahead = $index + 1
                while ($lookahead -lt $characters.Length -and [char]::IsWhiteSpace($characters[$lookahead])) { $lookahead++ }
                $isEmptyContainer = ($lookahead -lt $characters.Length) -and ($characters[$lookahead] -eq '}' -or $characters[$lookahead] -eq ']')
                if ($isEmptyContainer) {
                    [void]$builder.Append($characters[$lookahead])
                    $index = $lookahead
                } else {
                    $indentLevel++
                    [void]$builder.Append("`n").Append(' ' * ($indentLevel * $IndentSize))
                }
            }
            { $_ -eq '}' -or $_ -eq ']' } {
                $indentLevel = [Math]::Max(0, $indentLevel - 1)
                [void]$builder.Append("`n").Append(' ' * ($indentLevel * $IndentSize)).Append($character)
            }
            ',' { [void]$builder.Append(',').Append("`n").Append(' ' * ($indentLevel * $IndentSize)) }
            ':' { [void]$builder.Append(': ') }
            default { if (-not [char]::IsWhiteSpace($character)) { [void]$builder.Append($character) } }
        }
    }
    return $builder.ToString()
}

# Makes the process accept any TLS certificate (used only when the "Ignore SSL errors" setting is on).
function Enable-TrustAllCertificates {
    if (-not ('AppTrustAllCertificates' -as [type])) {
        Add-Type -ReferencedAssemblies 'System.dll' -TypeDefinition @'
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class AppTrustAllCertificates
{
    public static bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) { return true; }
    public static void Enable() { ServicePointManager.ServerCertificateValidationCallback = Validate; }
}
'@
    }
    [AppTrustAllCertificates]::Enable()
}

# Parses "Key: Value" lines into an ordered list of @{ Name; Value } entries (blank lines and // comments skipped).
function ConvertFrom-HeaderText {
    param([string]$HeaderText)
    $entries = @()
    foreach ($line in ($HeaderText -split "`r?`n")) {
        if ($line -match '^\s*(//|#)' -or $line -notmatch '\S') { continue }
        $separator = $line.IndexOf(':')
        if ($separator -lt 1) { continue }
        $entries += @{ Name = $line.Substring(0, $separator).Trim(); Value = $line.Substring($separator + 1).Trim() }
    }
    return $entries
}

# Maps friendly/legacy body type names to the MIME-style names the whole app stores in collections and history.
function ConvertTo-MimeBodyType {
    param([string]$Name)
    switch -Regex ($Name) {
        '^(?i)json$'                    { return 'application/json' }
        '^(?i)xml$'                     { return 'application/xml' }
        '^(?i)text$'                    { return 'text/plain' }
        '^(?i)form url-encoded$'        { return 'application/x-www-form-urlencoded' }
        '^(?i)(form-?data|multipart.*)$' { return 'multipart/form-data' }
        '^(?i)graphql$'                 { return 'GraphQL' }
        '^\s*$'                         { return 'application/json' }
        default                         { return $Name }
    }
}

# --- multipart body text <-> items ---------------------------------------------------------------------------
# One field per line:   name=value      or      name=@"C:\path\file.pdf";filename=x.pdf;type=application/pdf
function Convert-MultipartBodyToItems {
    param([string]$BodyText)
    $items = @()
    foreach ($line in ($BodyText -split "`r?`n" | Where-Object { $_ -match '\S' })) {
        if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;\r\n]+))((?:;[^=]+=[^;]+)*)\s*$') {
            $filePath = if ($Matches[3]) { $Matches[3] } else { $Matches[4] }
            $attributes = $Matches[5]
            $fileName = ''; $contentType = ''
            if ($attributes -match 'filename=([^;\r\n]+)') { $fileName = $Matches[1].Trim() }
            if ($attributes -match 'type=([^;\r\n]+)') { $contentType = $Matches[1].Trim() }
            $items += [PSCustomObject]@{ Key = $line.Split('=')[0].Trim(); Kind = 'File'; Value = $filePath; FileName = $fileName; ContentType = $contentType }
        } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)$') {
            $items += [PSCustomObject]@{ Key = $Matches[1].Trim(); Kind = 'Value'; Value = $Matches[2]; FileName = ''; ContentType = '' }
        }
    }
    return $items
}

function ConvertTo-MultipartBodyText {
    param($Items, [bool]$IncludeFilename = $true, [bool]$IncludeContentType = $true)
    $lines = foreach ($item in @($Items)) {
        if ([string]::IsNullOrWhiteSpace($item.Key) -and [string]::IsNullOrWhiteSpace($item.Value)) { continue }
        if ($item.Kind -eq 'File') {
            $fileText = "@`"$($item.Value)`""
            if (-not [string]::IsNullOrWhiteSpace($item.FileName)) { $fileText += ";filename=$($item.FileName)" }
            elseif ($IncludeFilename -and $item.Value) { $fileText += ";filename=$([System.IO.Path]::GetFileName($item.Value))" }
            if (-not [string]::IsNullOrWhiteSpace($item.ContentType)) { $fileText += ";type=$($item.ContentType)" }
            elseif ($IncludeContentType -and $item.Value) { $fileText += ";type=$(Get-MimeType -filePath $item.Value)" }
            "$($item.Key)=$fileText"
        } else { "$($item.Key)=$($item.Value)" }
    }
    return ($lines -join "`r`n")
}

function New-MultipartRequestContent {
    param([string]$BodyText, [bool]$IncludeFilename, [bool]$IncludeContentType, [string]$OutputFormat)

    $multipart = New-Object System.Net.Http.MultipartFormDataContent
    foreach ($item in (Convert-MultipartBodyToItems -BodyText $BodyText)) {
        $fieldName = Expand-Variables -InputString $item.Key
        if ($item.Kind -eq 'File') {
            $filePath = Expand-Variables -InputString $item.Value
            if (-not (Test-Path -LiteralPath $filePath)) { throw "Attachment not found: $filePath" }
            $fileContent = New-Object System.Net.Http.StreamContent([System.IO.File]::OpenRead($filePath))
            $contentType = if ($item.ContentType) { $item.ContentType } elseif ($IncludeContentType) { Get-MimeType -filePath $filePath } else { 'application/octet-stream' }
            try { $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($contentType) } catch { }
            $fileName = if ($item.FileName) { $item.FileName } elseif ($IncludeFilename) { [System.IO.Path]::GetFileName($filePath) } else { '' }
            if ($fileName) { $multipart.Add($fileContent, $fieldName, $fileName) } else { $multipart.Add($fileContent, $fieldName) }
        } else {
            $multipart.Add((New-Object System.Net.Http.StringContent((Expand-Variables -InputString $item.Value), [System.Text.Encoding]::UTF8)), $fieldName)
        }
    }
    if ($OutputFormat -match '^\s*([^=\s]+)\s*=\s*(.*)$') {
        $multipart.Add((New-Object System.Net.Http.StringContent($Matches[2].Trim(), [System.Text.Encoding]::UTF8)), $Matches[1])
    }
    return $multipart
}

# --- cookie jar ---------------------------------------------------------------------------------------------
function Get-CookieHeaderForUrl {
    param([string]$Url)
    if (-not $script:cookieJar -or $script:cookieJar.Count -eq 0) { return '' }
    try { $uri = [uri]$Url } catch { return '' }
    $pairs = foreach ($cookie in $script:cookieJar) {
        $cookieDomain = ([string]$cookie.Domain).TrimStart('.')
        if (-not $cookieDomain) { continue }
        $domainMatches = ($uri.Host -eq $cookieDomain) -or $uri.Host.EndsWith(".$cookieDomain")
        $pathMatches = (-not $cookie.Path) -or $uri.AbsolutePath.StartsWith([string]$cookie.Path)
        $notExpired = $true
        if ($cookie.Expires) { $expires = [datetime]::MinValue; if ([datetime]::TryParse([string]$cookie.Expires, [ref]$expires) -and $expires -gt [datetime]::MinValue -and $expires -lt [datetime]::Now) { $notExpired = $false } }
        if ($domainMatches -and $pathMatches -and $notExpired) { "$($cookie.Name)=$($cookie.Value)" }
    }
    return (@($pairs) -join '; ')
}

function Update-CookieJarFromResponse {
    param([string]$Url, [string[]]$SetCookieValues)
    if (-not $script:cookieJar) { $script:cookieJar = New-Object System.Collections.ArrayList }
    try { $uri = [uri]$Url } catch { return }
    foreach ($setCookie in @($SetCookieValues)) {
        if ([string]::IsNullOrWhiteSpace($setCookie)) { continue }
        $parts = $setCookie -split ';\s*'
        $nameValue = $parts[0]
        $separator = $nameValue.IndexOf('=')
        if ($separator -lt 1) { continue }
        $cookie = [PSCustomObject]@{ Name = $nameValue.Substring(0, $separator).Trim(); Value = $nameValue.Substring($separator + 1); Domain = $uri.Host; Path = '/'; Expires = '' }
        foreach ($attribute in ($parts | Select-Object -Skip 1)) {
            if ($attribute -match '^(?i)domain=(.+)$') { $cookie.Domain = $Matches[1] }
            elseif ($attribute -match '^(?i)path=(.+)$') { $cookie.Path = $Matches[1] }
            elseif ($attribute -match '^(?i)expires=(.+)$') { $cookie.Expires = $Matches[1] }
        }
        for ($index = $script:cookieJar.Count - 1; $index -ge 0; $index--) {
            $existing = $script:cookieJar[$index]
            if ($existing.Name -eq $cookie.Name -and $existing.Domain -eq $cookie.Domain -and $existing.Path -eq $cookie.Path) { $script:cookieJar.RemoveAt($index) }
        }
        [void]$script:cookieJar.Add($cookie)
    }
}

# --- OAuth 2.0 ---------------------------------------------------------------------------------------------
# Calls a token endpoint (form POST) and returns @{ AccessToken; RefreshToken; ExpiresIn; TokenExpiryTimestamp }.
function Invoke-OAuth2TokenRequest {
    param([Parameter(Mandatory = $true)][string]$TokenEndpoint, [Parameter(Mandatory = $true)][hashtable]$Form)

    Add-Type -AssemblyName System.Net.Http
    Enable-ModernTls
    $client = New-Object System.Net.Http.HttpClient
    try {
        $pairs = New-Object 'System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string,string]]'
        foreach ($key in $Form.Keys) { if ($Form[$key]) { $pairs.Add([System.Collections.Generic.KeyValuePair[string,string]]::new([string]$key, [string]$Form[$key])) } }
        $response = $client.PostAsync($TokenEndpoint, (New-Object System.Net.Http.FormUrlEncodedContent($pairs))).GetAwaiter().GetResult()
        $responseText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) { throw "Token endpoint returned $([int]$response.StatusCode): $responseText" }
        $tokenJson = $responseText | ConvertFrom-Json
        if (-not $tokenJson.access_token) { throw "The token response did not contain an access_token." }
        $expiresIn = if ($tokenJson.expires_in) { [int]$tokenJson.expires_in } else { 0 }
        return @{
            AccessToken = [string]$tokenJson.access_token; RefreshToken = [string]$tokenJson.refresh_token; ExpiresIn = [string]$expiresIn
            TokenExpiryTimestamp = $(if ($expiresIn -gt 0) { [DateTime]::UtcNow.AddSeconds($expiresIn).ToString('o') } else { '' })
        }
    } finally { $client.Dispose() }
}

# Refreshes an expired OAuth 2.0 access token when a refresh token + token endpoint are available.
# Returns the (possibly updated) authentication hashtable.
function Update-OAuth2TokenIfExpired {
    param([hashtable]$Authentication)

    if ($Authentication.Type -ne 'Auth2' -or -not $Authentication.TokenExpiryTimestamp -or -not $Authentication.RefreshToken -or -not $Authentication.TokenEndpoint) { return $Authentication }
    try { $expiry = [datetime]$Authentication.TokenExpiryTimestamp } catch { return $Authentication }
    if ([DateTime]::UtcNow -lt $expiry.ToUniversalTime()) { return $Authentication }

    $refreshed = Invoke-OAuth2TokenRequest -TokenEndpoint $Authentication.TokenEndpoint -Form @{
        grant_type = 'refresh_token'; refresh_token = $Authentication.RefreshToken; client_id = $Authentication.ClientId; client_secret = $Authentication.ClientSecret
    }
    $updated = $Authentication.Clone()
    $updated.AccessToken = $refreshed.AccessToken
    if ($refreshed.RefreshToken) { $updated.RefreshToken = $refreshed.RefreshToken }
    $updated.ExpiresIn = $refreshed.ExpiresIn
    $updated.TokenExpiryTimestamp = $refreshed.TokenExpiryTimestamp
    return $updated
}

# --- sending ----------------------------------------------------------------------------------------------
# Builds the message and starts sending it. Returns a state object; poll $state.Task.IsCompleted, then call
# Get-HttpRequestResult. BodyType uses the MIME-style names (application/json, multipart/form-data, GraphQL ...).
function Start-HttpRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$HeaderText = '',
        [string]$Body = '',
        [string]$BodyType = 'application/json',
        [hashtable]$Authentication = @{ Type = 'No Auth' },
        [int]$TimeoutSeconds = 60,
        [string]$GqlQuery = '',
        [string]$GqlVars = '',
        [string]$OutputFormat = '',
        [bool]$IncludeFilename = $true,
        [bool]$IncludeContentType = $true
    )

    Add-Type -AssemblyName System.Net.Http
    Enable-ModernTls
    $BodyType = ConvertTo-MimeBodyType -Name $BodyType
    $Authentication = Update-OAuth2TokenIfExpired -Authentication $Authentication
    $httpMethod = $Method.ToUpperInvariant()
    if ($BodyType -eq 'GraphQL') { $httpMethod = 'POST' }

    $resolvedUrl = (Expand-Variables -InputString $Url).Trim()
    $headerEntries = ConvertFrom-HeaderText -HeaderText (Expand-Variables -InputString $HeaderText)

    if ($Authentication.Type -eq 'API Key' -and $Authentication.AddTo -eq 'Query Parameter' -and $Authentication.Key) {
        $separator = if ($resolvedUrl.Contains('?')) { '&' } else { '?' }
        $resolvedUrl += $separator + [uri]::EscapeDataString((Expand-Variables -InputString $Authentication.Key)) + '=' + [uri]::EscapeDataString((Expand-Variables -InputString ([string]$Authentication.Value)))
    }
    if ($resolvedUrl -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $resolvedUrl = "https://$resolvedUrl" }

    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $true
    $handler.UseCookies = $false
    $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
    switch ($script:settings.ProxyMode) {
        'None'   { $handler.UseProxy = $false }
        'Custom' {
            if ($script:settings.ProxyAddress -and $script:settings.ProxyPort) {
                $proxy = New-Object System.Net.WebProxy($script:settings.ProxyAddress, [int]$script:settings.ProxyPort)
                if ($script:settings.ProxyUser) { $proxy.Credentials = New-Object System.Net.NetworkCredential($script:settings.ProxyUser, $script:settings.ProxyPass) }
                $handler.Proxy = $proxy; $handler.UseProxy = $true
            }
        }
    }
    if ($script:settings.IgnoreSslErrors) { Enable-TrustAllCertificates }

    if ($Authentication.Type -eq 'Client Certificate') {
        $certificate = $null
        if ($Authentication.Source -eq 'User Store') {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
            $store.Open('ReadOnly')
            $certificate = $store.Certificates | Where-Object { $_.Thumbprint -eq (([string]$Authentication.Thumbprint) -replace '\s', '').ToUpperInvariant() } | Select-Object -First 1
            $store.Close()
            if (-not $certificate) { throw "No certificate with thumbprint '$($Authentication.Thumbprint)' was found in the current user's store." }
        } else {
            if (-not (Test-Path -LiteralPath $Authentication.Path)) { throw "Certificate file not found: $($Authentication.Path)" }
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Authentication.Path, [string]$Authentication.Password)
        }
        $handler.ClientCertificateOptions = [System.Net.Http.ClientCertificateOption]::Manual
        [void]$handler.ClientCertificates.Add($certificate)
    }

    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds([Math]::Max(1, $TimeoutSeconds))
    $message = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::new($httpMethod), $resolvedUrl)

    # Body
    $methodAllowsBody = $httpMethod -notin @('GET', 'HEAD')
    if ($BodyType -eq 'GraphQL') {
        $payload = [ordered]@{ query = (Expand-Variables -InputString $GqlQuery) }
        $variablesText = Expand-Variables -InputString $GqlVars
        if (-not [string]::IsNullOrWhiteSpace($variablesText)) { try { $payload['variables'] = $variablesText | ConvertFrom-Json } catch { throw 'The GraphQL variables are not valid JSON.' } }
        $message.Content = New-Object System.Net.Http.StringContent(($payload | ConvertTo-Json -Depth 20 -Compress), [System.Text.Encoding]::UTF8, 'application/json')
    } elseif ($methodAllowsBody -and $BodyType -eq 'multipart/form-data') {
        if ($Body -match '\S' -or $OutputFormat) { $message.Content = New-MultipartRequestContent -BodyText $Body -IncludeFilename $IncludeFilename -IncludeContentType $IncludeContentType -OutputFormat $OutputFormat }
    } elseif ($methodAllowsBody -and $Body) {
        $resolvedBody = Expand-Variables -InputString $Body
        if ($BodyType -eq 'application/x-www-form-urlencoded') {
            $pairs = New-Object 'System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string,string]]'
            foreach ($line in ($resolvedBody -split "`r?`n|&")) {
                if ($line -notmatch '=') { continue }
                $parts = $line.Split('=', 2)
                $pairs.Add([System.Collections.Generic.KeyValuePair[string,string]]::new([uri]::UnescapeDataString($parts[0].Trim()), [uri]::UnescapeDataString($parts[1].Trim())))
            }
            $message.Content = New-Object System.Net.Http.FormUrlEncodedContent($pairs)
        } else {
            $message.Content = New-Object System.Net.Http.StringContent($resolvedBody, [System.Text.Encoding]::UTF8, $BodyType)
        }
    }

    # Headers: user Content-Type wins (except multipart, which needs its boundary); content headers go on the content.
    foreach ($entry in $headerEntries) {
        switch -Regex ($entry.Name) {
            '^(?i)content-length$' { continue }
            '^(?i)content-type$' {
                if ($message.Content -and $BodyType -ne 'multipart/form-data') { try { $message.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($entry.Value) } catch { } }
                continue
            }
            default {
                if (-not $message.Headers.TryAddWithoutValidation($entry.Name, $entry.Value) -and $message.Content) {
                    [void]$message.Content.Headers.TryAddWithoutValidation($entry.Name, $entry.Value)
                }
            }
        }
    }

    if (-not ($headerEntries | Where-Object { $_.Name -ieq 'User-Agent' })) { [void]$message.Headers.TryAddWithoutValidation('User-Agent', "PowerShell-API-Tester/$($script:AppVersion)") }
    if (-not ($headerEntries | Where-Object { $_.Name -ieq 'Accept' })) { [void]$message.Headers.TryAddWithoutValidation('Accept', '*/*') }
    if (-not ($headerEntries | Where-Object { $_.Name -ieq 'Cookie' })) {
        $cookieHeader = Get-CookieHeaderForUrl -Url $resolvedUrl
        if ($cookieHeader) { [void]$message.Headers.TryAddWithoutValidation('Cookie', $cookieHeader) }
    }

    # Authentication (never overrides an Authorization header the user typed)
    $hasAuthorizationHeader = [bool]($headerEntries | Where-Object { $_.Name -ieq 'Authorization' })
    switch ($Authentication.Type) {
        'Bearer Token' {
            if (-not $hasAuthorizationHeader -and $Authentication.Token) { [void]$message.Headers.TryAddWithoutValidation('Authorization', 'Bearer ' + (Expand-Variables -InputString ([string]$Authentication.Token))) }
        }
        'Auth2' {
            if (-not $hasAuthorizationHeader -and $Authentication.AccessToken) { [void]$message.Headers.TryAddWithoutValidation('Authorization', 'Bearer ' + (Expand-Variables -InputString ([string]$Authentication.AccessToken))) }
        }
        'Basic Auth' {
            if (-not $hasAuthorizationHeader -and $Authentication.Username) {
                $credentialText = (Expand-Variables -InputString ([string]$Authentication.Username)) + ':' + (Expand-Variables -InputString ([string]$Authentication.Password))
                [void]$message.Headers.TryAddWithoutValidation('Authorization', 'Basic ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credentialText)))
            }
        }
        'API Key' {
            if ($Authentication.AddTo -ne 'Query Parameter' -and $Authentication.Key) {
                [void]$message.Headers.TryAddWithoutValidation((Expand-Variables -InputString $Authentication.Key), (Expand-Variables -InputString ([string]$Authentication.Value)))
            }
        }
    }

    $cancellation = New-Object System.Threading.CancellationTokenSource
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $task = $client.SendAsync($message, $cancellation.Token)
    return @{ Task = $task; Client = $client; Message = $message; Cancellation = $cancellation; Stopwatch = $stopwatch; Url = $resolvedUrl; Method = $httpMethod; Authentication = $Authentication }
}

# Starts a request described by a classic request-state object (Method, Url, Headers, Body, BodyType, Authentication ...).
function Start-HttpRequestFromObject {
    param([Parameter(Mandatory = $true)]$Request, [int]$TimeoutSeconds = 60)

    $authentication = @{ Type = 'No Auth' }
    if ($Request.Authentication) {
        if ($Request.Authentication -is [hashtable]) { $authentication = $Request.Authentication }
        else { $authentication = @{}; foreach ($property in $Request.Authentication.PSObject.Properties) { $authentication[$property.Name] = $property.Value } }
    }
    $arguments = @{
        Method = [string]$Request.Method; Url = [string]$Request.Url; HeaderText = [string]$Request.Headers; Body = [string]$Request.Body
        BodyType = [string]$Request.BodyType; Authentication = $authentication; TimeoutSeconds = $TimeoutSeconds
        GqlQuery = [string]$Request.GqlQuery; GqlVars = [string]$Request.GqlVars; OutputFormat = [string]$Request.OutputFormat
        IncludeFilename = $(if ($null -ne $Request.IncludeFilename) { [bool]$Request.IncludeFilename } else { $true })
        IncludeContentType = $(if ($null -ne $Request.IncludeContentType) { [bool]$Request.IncludeContentType } else { $true })
    }
    return Start-HttpRequest @arguments
}

# Converts a finished request state into a plain result object (never throws). Text bodies are decoded using the
# response charset; images, PDFs and other binary payloads are returned as BodyBytes with IsBinary = $true.
function Get-HttpRequestResult {
    param([Parameter(Mandatory = $true)]$RequestState)

    $RequestState.Stopwatch.Stop()
    try {
        if ($RequestState.Task.IsCanceled) { return @{ Success = $false; Canceled = $true; ErrorMessage = 'Request canceled.'; ElapsedMs = $RequestState.Stopwatch.ElapsedMilliseconds } }
        if ($RequestState.Task.IsFaulted) {
            $innerError = $RequestState.Task.Exception.GetBaseException()
            $errorMessage = $innerError.Message
            if ($innerError -is [System.Threading.Tasks.TaskCanceledException]) { $errorMessage = 'The request timed out.' }
            return @{ Success = $false; ErrorMessage = $errorMessage; ElapsedMs = $RequestState.Stopwatch.ElapsedMilliseconds }
        }
        $response = $RequestState.Task.Result
        $bodyBytes = $response.Content.ReadAsByteArrayAsync().Result
        $contentType = ''
        $charset = ''
        if ($response.Content.Headers.ContentType) {
            $contentType = [string]$response.Content.Headers.ContentType.MediaType
            $charset = [string]$response.Content.Headers.ContentType.CharSet
        }
        $isText = (-not $contentType) -or ($contentType -match '^text/|json|xml|javascript|html|csv|yaml|urlencoded|graphql|svg|x-www-form')
        $bodyText = ''
        if ($isText) {
            $encoding = [System.Text.Encoding]::UTF8
            if ($charset) { try { $encoding = [System.Text.Encoding]::GetEncoding($charset.Trim('"')) } catch { } }
            $bodyText = $encoding.GetString($bodyBytes)
        }

        $headerLines = New-Object System.Collections.Generic.List[string]
        foreach ($header in $response.Headers) { $headerLines.Add("$($header.Key): $($header.Value -join ', ')") }
        foreach ($header in $response.Content.Headers) { $headerLines.Add("$($header.Key): $($header.Value -join ', ')") }

        $setCookieValues = @()
        $cookieHeaderValues = $null
        if ($response.Headers.TryGetValues('Set-Cookie', [ref]$cookieHeaderValues)) { $setCookieValues = @($cookieHeaderValues) }
        if ($setCookieValues.Count -gt 0) { Update-CookieJarFromResponse -Url $RequestState.Url -SetCookieValues $setCookieValues }

        return @{
            Success = $true; StatusCode = [int]$response.StatusCode; ReasonPhrase = [string]$response.ReasonPhrase
            ElapsedMs = $RequestState.Stopwatch.ElapsedMilliseconds; SizeBytes = $bodyBytes.Length
            Body = $bodyText; BodyBytes = $bodyBytes; IsBinary = (-not $isText); HeaderLines = @($headerLines); ContentType = $contentType
            ContentDispositionName = $(if ($response.Content.Headers.ContentDisposition) { [string]$response.Content.Headers.ContentDisposition.FileName } else { '' })
            Authentication = $RequestState.Authentication; Url = $RequestState.Url
        }
    } catch {
        return @{ Success = $false; ErrorMessage = $_.Exception.Message; ElapsedMs = $RequestState.Stopwatch.ElapsedMilliseconds }
    } finally {
        try { $RequestState.Client.Dispose() } catch { }
        try { if ($RequestState.Message) { $RequestState.Message.Dispose() } } catch { }
    }
}

# Sends a request and waits for it (used by the collection runner). Returns the same result object.
function Invoke-HttpRequestSync {
    param([Parameter(Mandatory = $true)]$Request, [int]$TimeoutSeconds = 60)
    try { $state = Start-HttpRequestFromObject -Request $Request -TimeoutSeconds $TimeoutSeconds }
    catch { return @{ Success = $false; ErrorMessage = $_.Exception.Message; ElapsedMs = 0 } }
    try { [void]$state.Task.Wait() } catch { }
    return (Get-HttpRequestResult -RequestState $state)
}
#endregion
