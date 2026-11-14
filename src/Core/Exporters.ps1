#region Exporters (Postman v2.1)

function ConvertTo-PostmanAuthBlock {
    param($Auth)
    $type = [string](Get-ObjectProperty $Auth 'Type' 'No Auth')
    $pair = { param($key, $value) [ordered]@{ key = $key; value = [string]$value; type = 'string' } }
    switch ($type) {
        'Inherit'      { return $null }
        'Bearer Token' { return [ordered]@{ type = 'bearer'; bearer = @(& $pair 'token' (Get-ObjectProperty $Auth 'Token' '')) } }
        'Basic Auth'   { return [ordered]@{ type = 'basic'; basic = @((& $pair 'username' (Get-ObjectProperty $Auth 'Username' '')), (& $pair 'password' (Get-ObjectProperty $Auth 'Password' ''))) } }
        'API Key'      { return [ordered]@{ type = 'apikey'; apikey = @((& $pair 'key' (Get-ObjectProperty $Auth 'Key' '')), (& $pair 'value' (Get-ObjectProperty $Auth 'Value' '')), (& $pair 'in' $(if ((Get-ObjectProperty $Auth 'AddTo' 'Header') -eq 'Query Parameter') { 'query' } else { 'header' }))) } }
        'Auth2'        { return [ordered]@{ type = 'oauth2'; oauth2 = @((& $pair 'accessToken' (Get-ObjectProperty $Auth 'AccessToken' '')), (& $pair 'accessTokenUrl' (Get-ObjectProperty $Auth 'TokenEndpoint' '')), (& $pair 'clientId' (Get-ObjectProperty $Auth 'ClientId' '')), (& $pair 'scope' (Get-ObjectProperty $Auth 'Scope' ''))) } }
        default        { return [ordered]@{ type = 'noauth' } }
    }
}

function ConvertTo-PostmanItem {
    param($Item)
    if ([string]$Item.Type -eq 'Request') {
        $data = Get-RequestObjectFromItem -Item $Item
        $request = [ordered]@{
            method = [string](Get-ObjectProperty $data 'Method' 'GET')
            header = @(ConvertFrom-HeaderText -HeaderText ([string](Get-ObjectProperty $data 'Headers' '')) | ForEach-Object { [ordered]@{ key = $_.Name; value = $_.Value } })
            url    = [ordered]@{ raw = [string](Get-ObjectProperty $data 'Url' '') }
        }
        $bodyType = ConvertTo-MimeBodyType -Name ([string](Get-ObjectProperty $data 'BodyType' 'application/json'))
        $bodyText = [string](Get-ObjectProperty $data 'Body' '')
        switch ($bodyType) {
            'GraphQL' { $request.body = [ordered]@{ mode = 'graphql'; graphql = [ordered]@{ query = [string](Get-ObjectProperty $data 'GqlQuery' ''); variables = [string](Get-ObjectProperty $data 'GqlVars' '') } } }
            'multipart/form-data' {
                if ($bodyText -match '\S') {
                    $request.body = [ordered]@{ mode = 'formdata'; formdata = @(Convert-MultipartBodyToItems -BodyText $bodyText | ForEach-Object {
                        if ($_.Kind -eq 'File') { [ordered]@{ key = $_.Key; type = 'file'; src = $_.Value } } else { [ordered]@{ key = $_.Key; type = 'text'; value = $_.Value } } }) }
                }
            }
            'application/x-www-form-urlencoded' {
                $request.body = [ordered]@{ mode = 'urlencoded'; urlencoded = @(($bodyText -split "`r?`n|&") | Where-Object { $_ -match '=' } | ForEach-Object { $parts = $_.Split('=', 2); [ordered]@{ key = $parts[0].Trim(); value = $parts[1].Trim() } }) }
            }
            default {
                if ($bodyText) { $request.body = [ordered]@{ mode = 'raw'; raw = $bodyText; options = [ordered]@{ raw = [ordered]@{ language = $(if ($bodyType -match 'json') { 'json' } elseif ($bodyType -match 'xml') { 'xml' } else { 'text' }) } } } }
            }
        }
        $auth = ConvertTo-PostmanAuthBlock (Get-ObjectProperty $data 'Authentication' $null)
        if ($auth) { $request.auth = $auth }
        return [ordered]@{ name = [string]$Item.Name; request = $request }
    }
    $folder = [ordered]@{ name = [string]$Item.Name; item = @(@($Item.Items) | Where-Object { $_ } | ForEach-Object { ConvertTo-PostmanItem -Item $_ }) }
    $folderAuth = Get-ObjectProperty $Item 'Auth' $null
    if ($folderAuth) { $block = ConvertTo-PostmanAuthBlock $folderAuth; if ($block) { $folder.auth = $block } }
    return $folder
}

# Converts a collection (or a folder, exported as its own collection) to Postman Collection v2.1 JSON.
# Secret collection variables are exported empty. PowerShell scripts are not exported (Postman runs JavaScript).
function ConvertTo-PostmanCollectionJson {
    param([Parameter(Mandatory = $true)]$Item)
    $safe = $Item
    if ([string]$Item.Type -eq 'Collection') { $safeCollections = Get-CollectionsForStorage -Collections @($Item) -ForExport; $safe = $safeCollections[0] }
    $collection = [ordered]@{
        info = [ordered]@{ _postman_id = [guid]::NewGuid().ToString(); name = [string]$safe.Name; schema = 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' }
        item = @(@($safe.Items) | Where-Object { $_ } | ForEach-Object { ConvertTo-PostmanItem -Item $_ })
    }
    $variables = Get-ObjectProperty $safe 'Variables' $null
    if ($variables) {
        $pairs = if ($variables -is [System.Collections.IDictionary]) { $variables.GetEnumerator() | ForEach-Object { [ordered]@{ key = [string]$_.Key; value = [string]$_.Value } } } else { $variables.PSObject.Properties | ForEach-Object { [ordered]@{ key = $_.Name; value = [string]$_.Value } } }
        $collection.variable = @($pairs)
    }
    $rootAuth = Get-ObjectProperty $safe 'Auth' $null
    if ($rootAuth) { $block = ConvertTo-PostmanAuthBlock $rootAuth; if ($block) { $collection.auth = $block } }
    return (ConvertTo-Json -InputObject $collection -Depth 50)
}
#endregion
