function Invoke-ApiRequest {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [string]$Method = 'GET',
        [string]$Headers = '',
        [string]$Body = '',
        [string]$BodyType = 'raw',
        [string[]]$Files = @(),
        [int]$TimeoutSeconds = 30
    )
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $client = New-Object System.Net.Http.HttpClient
        $methodObj = [System.Net.Http.HttpMethod]::new($Method)
        $req = New-Object System.Net.Http.HttpRequestMessage($methodObj, $Url)

        if ($Headers) {
            $lines = $Headers -split "`r?`n" | Where-Object { $_ -match '\S' }
            foreach ($l in $lines) { if ($l -match '^\s*([^:]+)\s*:\s*(.+)$') { $req.Headers.TryAddWithoutValidation($matches[1], $matches[2]) | Out-Null } }
        }

        if ($Files.Count -gt 0 -or $BodyType -eq 'multipart/form-data') {
            $multi = New-Object System.Net.Http.MultipartFormDataContent
            if ($Body) { $lines = $Body -split "`r?`n" | Where-Object { $_ -match '\S' }; foreach ($l in $lines) { if ($l -match '=') { $p=$l.Split('=',2); $multi.Add((New-Object System.Net.Http.StringContent($p[1])),$p[0]) } else { $multi.Add((New-Object System.Net.Http.StringContent($l)),'body') } } }
            foreach ($f in $Files) { if (Test-Path $f) { $bytes = [System.IO.File]::ReadAllBytes($f); $content = New-Object System.Net.Http.ByteArrayContent($bytes); $content.Headers.ContentDisposition = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue('form-data'); $content.Headers.ContentDisposition.Name = 'file'; $content.Headers.ContentDisposition.FileName = [System.IO.Path]::GetFileName($f); $multi.Add($content,'file',[System.IO.Path]::GetFileName($f)) } }
            $req.Content = $multi
        }
        elseif ($BodyType -eq 'application/x-www-form-urlencoded') {
            $pairs = @()
            if ($Body) { foreach ($l in $Body -split "`r?`n") { if ($l -match '=') { $p = $l.Split('=',2); $pairs += [System.Collections.Generic.KeyValuePair[string,string]]::new($p[0],$p[1]) } } }
            $req.Content = New-Object System.Net.Http.FormUrlEncodedContent($pairs)
        }
        elseif ($BodyType -match 'graphql') {
            $payload = "{`"query`":`"$($Body -replace '"','\"')`"}"
            $req.Content = New-Object System.Net.Http.StringContent($payload,[System.Text.Encoding]::UTF8, 'application/json')
        }
        elseif ($Body) { $contentType = 'application/json'; $req.Content = New-Object System.Net.Http.StringContent($Body,[System.Text.Encoding]::UTF8,$contentType) }

        $respTask = $client.SendAsync($req)
        $respTask.Wait()
        $resp = $respTask.Result
        $sw.Stop()
        $text = $resp.Content.ReadAsStringAsync().Result
        $hdrs = @{}
        foreach ($h in $resp.Headers) { $hdrs[$h.Key] = ($h.Value -join ',') }
        foreach ($h in $resp.Content.Headers) { $hdrs[$h.Key] = ($h.Value -join ',') }
        return @{ Success = $resp.IsSuccessStatusCode; Data = @{ StatusCode = [int]$resp.StatusCode; StatusDescription = $resp.ReasonPhrase; ElapsedTime = $sw.ElapsedMilliseconds; Headers = $hdrs; Content = $text; RawContentLength = ($resp.Content.Headers.ContentLength -as [int64]) } }
    } catch { return @{ Success = $false; ErrorMessage = $_.Exception.Message } }
}

