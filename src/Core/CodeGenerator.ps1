#region Code Generator
# Turns a request description (Method, Url, Headers, Body, BodyType) into a code snippet.
# Languages: cURL, PowerShell, Python, C#, JavaScript. Extracted unchanged from the classic window so both UIs
# produce identical output.

function New-CodeSnippet {
    param(
        [PSCustomObject]$RequestItem,
        [string]$Language = "cURL"
    )
    if (-not $RequestItem) { return "" }

    $method = $RequestItem.Method
    $url = $RequestItem.Url
    $headersRaw = $RequestItem.Headers
    $bodyRaw = $RequestItem.Body
    $bodyType = $RequestItem.BodyType

    # Parse headers
    $headers = @{}
    foreach ($line in $headersRaw -split "`n") {
        if ($line -match "^\s*(.+?):\s*(.+)$") {
            $headers[$matches[1]] = $matches[2]
        }
    }

    $sb = New-Object System.Text.StringBuilder
    if ($Language -in @('Go', 'Java', 'JavaScript (axios)')) { return (New-ExtraCodeSnippet -Language $Language -Method $method -Url $url -Headers $headers -Body $bodyRaw -BodyType $bodyType) }

    switch ($Language) {
        "cURL" {
            $curlParts = @("curl -X '$method' \")
            foreach ($key in $headers.Keys) {
                $curlParts += "  -H '$($key): $($headers[$key])' \"
            }

            if ($bodyType -eq "multipart/form-data") {
                if (-not $headers.ContainsKey("Content-Type")) {
                    $curlParts += "  -H 'Content-Type: multipart/form-data' \"
                }
                foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                    if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                        $key = $matches[1].Trim()
                        if ($matches[3]) { $filePath = $matches[3] } else { $filePath = $matches[4] }
                        $attributes = $matches[5]
                        $curlParts += "  -F '$key=@$filePath$attributes' \"
                    } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                        $key = $matches[1].Trim()
                        $value = $matches[2].Trim()
                        $curlParts += "  -F '$key=$value' \"
                    }
                }
            } else {
            if (-not $headers.ContainsKey("Content-Type")) { 
                if ($bodyRaw) { $rawContentType = $bodyType } else { $rawContentType = 'text/plain' }
                $curlParts += "  -H 'Content-Type: $rawContentType' \" 
            }
                if ($bodyRaw) { $curlParts += "  -d '$($bodyRaw -replace "'", "'\''")' \" }
            }
            $curlParts += "  '$url'"
            return ($curlParts -join "`n").TrimEnd(' \')
        }
        "PowerShell" {
            $sb.AppendLine("`$headers = @{") | Out-Null
            foreach ($key in $headers.Keys) {
                $sb.AppendLine("    '$key' = '$($headers[$key])'") | Out-Null
            }
            $sb.AppendLine("}") | Out-Null
            $sb.AppendLine("") | Out-Null
            
            $params = "-Method $method -Uri '$url' -Headers `$headers"
            
            if ($bodyRaw) {
                $sb.AppendLine("`$body = @'") | Out-Null
                $sb.AppendLine($bodyRaw) | Out-Null
                $sb.AppendLine("'@") | Out-Null
                $params += " -Body `$body"
                if (-not $headers.ContainsKey("Content-Type") -and $bodyType -ne 'multipart/form-data') {
                     $params += " -ContentType '$bodyType'"
                }
            }
            $sb.AppendLine("Invoke-RestMethod $params") | Out-Null
            return $sb.ToString()
        }
        "Python" {
            $sb.AppendLine("import requests") | Out-Null
            $sb.AppendLine("") | Out-Null
            $sb.AppendLine("url = '$url'") | Out-Null
            $sb.AppendLine("headers = {") | Out-Null
            foreach ($key in $headers.Keys) {
                if ($key -ne "Content-Type") {
                    $sb.AppendLine("    '$key': '$($headers[$key])',") | Out-Null
                }
            }
            $sb.AppendLine("}") | Out-Null
            
            if ($bodyType -eq "multipart/form-data") {
                $sb.AppendLine("files = [") | Out-Null
                foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                    if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                        $key = $matches[1].Trim()
                        $path = if ($matches[3]) { $matches[3] } else { $matches[4] }
                        $attrs = $matches[5]
                        $fn = [System.IO.Path]::GetFileName($path)
                        $ct = $null
                        if ($attrs -match 'filename=([^;]+)') { $fn = $matches[1] }
                        if ($attrs -match 'type=([^;]+)') { $ct = $matches[1] }
                        $tuple = "('$key', ('$fn', open(r'$path', 'rb')"
                        if ($ct) { $tuple += ", '$ct'" }
                        $tuple += "))"
                        $sb.AppendLine("  $tuple,") | Out-Null
                    } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                        $key = $matches[1].Trim()
                        $val = $matches[2].Trim()
                        $sb.AppendLine("  ('$key', (None, '$val')),") | Out-Null
                    }
                }
                $sb.AppendLine("]") | Out-Null
                $sb.AppendLine("response = requests.request('$method', url, headers=headers, files=files)") | Out-Null
            } else {
                if ($bodyRaw) {
                    $sb.AppendLine("payload = '''$bodyRaw'''") | Out-Null
                    $sb.AppendLine("response = requests.request('$method', url, headers=headers, data=payload)") | Out-Null
                } else {
                    $sb.AppendLine("response = requests.request('$method', url, headers=headers)") | Out-Null
                }
            }
            $sb.AppendLine("print(response.text)") | Out-Null
            return $sb.ToString()
        }
        "C#" {
            $sb.AppendLine("var client = new HttpClient();") | Out-Null
            $sb.AppendLine("var request = new HttpRequestMessage(HttpMethod.$([cultureinfo]::CurrentCulture.TextInfo.ToTitleCase($method.ToLower())), `"$url`");") | Out-Null
            
            foreach ($key in $headers.Keys) {
                if ($key -ne "Content-Type") {
                    $sb.AppendLine("request.Headers.Add(`"$key`", `"$($headers[$key])`");") | Out-Null
                }
            }
            
            if ($bodyRaw) {
                if ($bodyType -eq "multipart/form-data") {
                    $sb.AppendLine("var content = new MultipartFormDataContent();") | Out-Null
                    foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                        if ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                            $key = $matches[1].Trim()
                            $val = $matches[2].Trim()
                            if ($val -match '^@') {
                                $sb.AppendLine("content.Add(new StreamContent(File.OpenRead(`"$($val.Substring(1))`")), `"$key`", `"$($val.Substring(1))`");") | Out-Null
                            } else {
                                $sb.AppendLine("content.Add(new StringContent(`"$val`"), `"$key`");") | Out-Null
                            }
                        }
                    }
                } else {
                    $sb.AppendLine("var content = new StringContent(`"$($bodyRaw -replace '"', '\"' -replace '`n', '\n' -replace '`r', '')`", null, `"$bodyType`");") | Out-Null
                }
                $sb.AppendLine("request.Content = content;") | Out-Null
            }
            
            $sb.AppendLine("var response = await client.SendAsync(request);") | Out-Null
            $sb.AppendLine("response.EnsureSuccessStatusCode();") | Out-Null
            $sb.AppendLine("Console.WriteLine(await response.Content.ReadAsStringAsync());") | Out-Null
            return $sb.ToString()
        }
        "JavaScript" {
            $sb.AppendLine("const myHeaders = new Headers();") | Out-Null
            foreach ($key in $headers.Keys) {
                if ($key -ne "Content-Type") {
                    $sb.AppendLine("myHeaders.append('$key', '$($headers[$key])');") | Out-Null
                }
            }
            $sb.AppendLine("") | Out-Null
            
            if ($bodyType -eq "multipart/form-data") {
                $sb.AppendLine("const formdata = new FormData();") | Out-Null
                foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                    if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                        $key = $matches[1].Trim()
                        $path = if ($matches[3]) { $matches[3] } else { $matches[4] }
                        $attrs = $matches[5]
                        $fn = [System.IO.Path]::GetFileName($path)
                        if ($attrs -match 'filename=([^;]+)') { $fn = $matches[1] }
                        $sb.AppendLine("formdata.append('$key', fileInput.files[0], '$fn');") | Out-Null
                    } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                        $key = $matches[1].Trim()
                        $val = $matches[2].Trim()
                        $sb.AppendLine("formdata.append('$key', '$val');") | Out-Null
                    }
                }
                $sb.AppendLine("") | Out-Null
                $sb.AppendLine("const requestOptions = {") | Out-Null
                $sb.AppendLine("  method: '$method',") | Out-Null
                $sb.AppendLine("  headers: myHeaders,") | Out-Null
                $sb.AppendLine("  body: formdata,") | Out-Null
                $sb.AppendLine("  redirect: 'follow'") | Out-Null
                $sb.AppendLine("};") | Out-Null
            } else {
                $sb.AppendLine("const requestOptions = {") | Out-Null
                $sb.AppendLine("  method: '$method',") | Out-Null
                $sb.AppendLine("  headers: myHeaders,") | Out-Null
                if ($bodyRaw) {
                    $sb.AppendLine("  body: `$(`"$bodyRaw`"),") | Out-Null
                }
                $sb.AppendLine("  redirect: 'follow'") | Out-Null
                $sb.AppendLine("};") | Out-Null
            }
            $sb.AppendLine("") | Out-Null
            $sb.AppendLine("fetch('$url', requestOptions)") | Out-Null
            $sb.AppendLine("  .then(response => response.text())") | Out-Null
            $sb.AppendLine("  .then(result => console.log(result))") | Out-Null
            $sb.AppendLine("  .catch(error => console.error('error', error));") | Out-Null
            return $sb.ToString()
        }
        "C#" {
            $sb.AppendLine("var client = new HttpClient();") | Out-Null
            $sb.AppendLine("var request = new HttpRequestMessage(new HttpMethod(`"$method`"), `"$url`");") | Out-Null
            foreach ($key in $headers.Keys) {
                if ($key -ne "Content-Type") {
                    $sb.AppendLine("request.Headers.Add(`"$key`", `"$($headers[$key])`");") | Out-Null
                }
            }
            if ($bodyType -eq "multipart/form-data") {
                $sb.AppendLine("var content = new MultipartFormDataContent();") | Out-Null
                foreach ($line in $bodyRaw -split "`n" | Where-Object { $_ -match '\S' }) {
                    if ($line -match '^\s*([^=]+?)\s*=\s*@("([^"]+)"|([^;`\r`n]+))((?:;[^=]+=[^;]+)*)\s*$') {
                        $key = $matches[1].Trim(); $path = if ($matches[3]) { $matches[3] } else { $matches[4] }; $fn = [System.IO.Path]::GetFileName($path); $safePath = $path.Replace('\', '\\')
                        $sb.AppendLine("content.Add(new StreamContent(File.OpenRead(`"$safePath`")), `"$key`", `"$fn`");") | Out-Null
                    } elseif ($line -match '^\s*([^=]+?)\s*=\s*(.*)') {
                        $key = $matches[1].Trim(); $val = $matches[2].Trim()
                        $sb.AppendLine("content.Add(new StringContent(`"$val`"), `"$key`");") | Out-Null
                    }
                }
                $sb.AppendLine("request.Content = content;") | Out-Null
            } elseif ($bodyRaw) {
                $mediaType = if ($headers.ContainsKey("Content-Type")) { $headers["Content-Type"] } elseif ($bodyType) { $bodyType } else { "text/plain" }
                $safeBody = $bodyRaw.Replace('\', '\\').Replace('"', '\"')
                $sb.AppendLine("var content = new StringContent(`"$safeBody`", null, `"$mediaType`");") | Out-Null
                $sb.AppendLine("request.Content = content;") | Out-Null
            }
            $sb.AppendLine("var response = await client.SendAsync(request);") | Out-Null
            $sb.AppendLine("response.EnsureSuccessStatusCode();") | Out-Null
            $sb.AppendLine("Console.WriteLine(await response.Content.ReadAsStringAsync());") | Out-Null
            return $sb.ToString()
        }
    }
    return ""
}

# Helper to populate JSON TreeView

# Extra snippet languages (Go, Java, JavaScript axios). Uses the same request description as New-CodeSnippet.
function ConvertTo-DoubleQuotedLiteral {
    param([string]$Text)
    return '"' + ([string]$Text).Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t') + '"'
}

function New-ExtraCodeSnippet {
    param([string]$Language, [string]$Method, [string]$Url, [hashtable]$Headers, [string]$Body, [string]$BodyType)
    $quote = { param($text) ConvertTo-DoubleQuotedLiteral $text }
    $isMultipart = $BodyType -eq 'multipart/form-data' -and $Body -match '\S'
    $parts = if ($isMultipart) { @(Convert-MultipartBodyToItems -BodyText $Body) } else { @() }
    $lines = New-Object System.Collections.Generic.List[string]
    switch ($Language) {
        'Go' {
            $lines.Add('package main'); $lines.Add(''); $lines.Add('import (')
            foreach ($package in @('"fmt"', '"io"', '"net/http"') + $(if ($isMultipart) { @('"bytes"', '"mime/multipart"', '"os"', '"path/filepath"') } elseif ($Body) { @('"strings"') } else { @() })) { $lines.Add("`t$package") }
            $lines.Add(')'); $lines.Add(''); $lines.Add('func main() {')
            if ($isMultipart) {
                $lines.Add("`tbody := &bytes.Buffer{}"); $lines.Add("`twriter := multipart.NewWriter(body)")
                foreach ($part in $parts) {
                    if ($part.Kind -eq 'File') {
                        $lines.Add("`tfile, _ := os.Open($(& $quote $part.Value))"); $lines.Add("`tpart, _ := writer.CreateFormFile($(& $quote $part.Key), filepath.Base($(& $quote $part.Value)))"); $lines.Add("`tio.Copy(part, file)"); $lines.Add("`tfile.Close()")
                    } else { $lines.Add("`twriter.WriteField($(& $quote $part.Key), $(& $quote $part.Value))") }
                }
                $lines.Add("`twriter.Close()")
                $lines.Add("`treq, _ := http.NewRequest($(& $quote $Method), $(& $quote $Url), body)")
                $lines.Add("`treq.Header.Set(""Content-Type"", writer.FormDataContentType())")
            } elseif ($Body) { $lines.Add("`treq, _ := http.NewRequest($(& $quote $Method), $(& $quote $Url), strings.NewReader($(& $quote $Body)))") }
            else { $lines.Add("`treq, _ := http.NewRequest($(& $quote $Method), $(& $quote $Url), nil)") }
            foreach ($key in $Headers.Keys) { if (-not ($isMultipart -and $key -ieq 'Content-Type')) { $lines.Add("`treq.Header.Set($(& $quote $key), $(& $quote $Headers[$key]))") } }
            if ($Body -and -not $isMultipart -and -not ($Headers.Keys | Where-Object { $_ -ieq 'Content-Type' })) { $lines.Add("`treq.Header.Set(""Content-Type"", $(& $quote $BodyType))") }
            $lines.Add(''); $lines.Add("`tres, err := http.DefaultClient.Do(req)"); $lines.Add("`tif err != nil {"); $lines.Add("`t`tpanic(err)"); $lines.Add("`t}"); $lines.Add("`tdefer res.Body.Close()")
            $lines.Add("`tdata, _ := io.ReadAll(res.Body)"); $lines.Add("`tfmt.Println(res.Status)"); $lines.Add("`tfmt.Println(string(data))"); $lines.Add('}')
        }
        'Java' {
            if ($isMultipart) {
                $lines.Add('// Uses OkHttp (com.squareup.okhttp3:okhttp) because java.net.http has no multipart support.')
                $lines.Add('OkHttpClient client = new OkHttpClient();'); $lines.Add('MultipartBody.Builder form = new MultipartBody.Builder().setType(MultipartBody.FORM);')
                foreach ($part in $parts) {
                    if ($part.Kind -eq 'File') { $lines.Add("File file = new File($(& $quote $part.Value));"); $lines.Add("form.addFormDataPart($(& $quote $part.Key), file.getName(), RequestBody.create(file, MediaType.parse($(& $quote $(if ($part.ContentType) { $part.ContentType } else { 'application/octet-stream' })))));") }
                    else { $lines.Add("form.addFormDataPart($(& $quote $part.Key), $(& $quote $part.Value));") }
                }
                $lines.Add("Request.Builder request = new Request.Builder().url($(& $quote $Url)).method($(& $quote $Method), form.build());")
                foreach ($key in $Headers.Keys) { if ($key -ine 'Content-Type') { $lines.Add("request.addHeader($(& $quote $key), $(& $quote $Headers[$key]));") } }
                $lines.Add('try (Response response = client.newCall(request.build()).execute()) {'); $lines.Add('    System.out.println(response.code());'); $lines.Add('    System.out.println(response.body().string());'); $lines.Add('}')
            } else {
                $lines.Add('import java.net.URI;'); $lines.Add('import java.net.http.HttpClient;'); $lines.Add('import java.net.http.HttpRequest;'); $lines.Add('import java.net.http.HttpResponse;'); $lines.Add('')
                $lines.Add('HttpClient client = HttpClient.newHttpClient();')
                $lines.Add("HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create($(& $quote $Url)))")
                $publisher = if ($Body) { "HttpRequest.BodyPublishers.ofString($(& $quote $Body))" } else { 'HttpRequest.BodyPublishers.noBody()' }
                $lines.Add("        .method($(& $quote $Method), $publisher);")
                foreach ($key in $Headers.Keys) { $lines.Add("builder.header($(& $quote $key), $(& $quote $Headers[$key]));") }
                if ($Body -and -not ($Headers.Keys | Where-Object { $_ -ieq 'Content-Type' })) { $lines.Add("builder.header(""Content-Type"", $(& $quote $BodyType));") }
                $lines.Add('HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());')
                $lines.Add('System.out.println(response.statusCode());'); $lines.Add('System.out.println(response.body());')
            }
        }
        'JavaScript (axios)' {
            $lines.Add("const axios = require('axios');")
            if ($isMultipart) {
                $lines.Add("const FormData = require('form-data');"); $lines.Add("const fs = require('fs');"); $lines.Add('const form = new FormData();')
                foreach ($part in $parts) { if ($part.Kind -eq 'File') { $lines.Add("form.append($(& $quote $part.Key), fs.createReadStream($(& $quote $part.Value)));") } else { $lines.Add("form.append($(& $quote $part.Key), $(& $quote $part.Value));") } }
            }
            $lines.Add(''); $lines.Add('axios({'); $lines.Add("  method: '$($Method.ToLowerInvariant())',"); $lines.Add("  url: $(& $quote $Url),")
            $headerEntries = @($Headers.Keys | Where-Object { -not ($isMultipart -and $_ -ieq 'Content-Type') } | ForEach-Object { "    $(& $quote $_): $(& $quote $Headers[$_])" })
            if ($isMultipart) { $headerEntries += '    ...form.getHeaders()' }
            if ($headerEntries.Count -gt 0) { $lines.Add('  headers: {'); $lines.Add(($headerEntries -join ",`n")); $lines.Add('  },') }
            if ($isMultipart) { $lines.Add('  data: form') }
            elseif ($Body) {
                $jsonBody = $null
                if ($BodyType -match 'json') { try { $jsonBody = $Body | ConvertFrom-Json -ErrorAction Stop } catch { $jsonBody = $null } }
                if ($null -ne $jsonBody) { $lines.Add("  data: $($Body.Trim())") } else { $lines.Add("  data: $(& $quote $Body)") }
            }
            $lines.Add('})'); $lines.Add('  .then(response => console.log(response.status, response.data))'); $lines.Add('  .catch(error => console.error(error.response ? error.response.status : error.message));')
        }
    }
    return ($lines -join "`r`n")
}

#endregion
