#region XAML monitor UI (engine, manager, editor, email settings, dashboard, chart)

function Set-ObjectProperty {
    param($Object, [string]$Name, $Value)
    if ($Object -is [System.Collections.IDictionary]) { $Object[$Name] = $Value }
    else { $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value -Force }
}

# ------------------------------------------------------------------------------------------------
# Background monitor service (-RunMonitors): runs the monitors with no window, only a tray icon.
# Only one runner is active at a time: while the service is running the app's own engine stays idle, and
# edits made in the Monitor Manager (start/stop/add/edit) are picked up by the service from the monitors file.
# ------------------------------------------------------------------------------------------------

$script:MonitorServiceMutexName = 'Global\APITester.MonitorService'
$script:MonitorServiceStopEventName = 'Global\APITester.MonitorService.Stop'
$script:monitorLastResult = @{}
$script:backgroundEmails = New-Object System.Collections.ArrayList

function Get-MonitorStatusFilePath { return (Join-Path $configDir 'api_tester_monitor_status.json') }

function Test-MonitorServiceRunning {
    param([switch]$NoCache)
    if ($script:isMonitorService) { return $false }
    $now = [datetime]::UtcNow
    if (-not $NoCache -and $script:serviceCheckTime -and ($now - $script:serviceCheckTime).TotalSeconds -lt 3) { return [bool]$script:serviceRunningCached }
    $script:serviceCheckTime = $now
    $mutex = $null
    $running = $false
    try { $running = [System.Threading.Mutex]::TryOpenExisting($script:MonitorServiceMutexName, [ref]$mutex) }
    catch [System.UnauthorizedAccessException] { $running = $true }   # exists but belongs to another account (scheduled task)
    catch { $running = $false }
    if ($mutex) { $mutex.Dispose() }
    $script:serviceRunningCached = $running
    return $running
}

function Get-MonitorServiceLaunch {
    $hostPath = (Get-Process -Id $PID).Path
    $arguments = "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`" -RunMonitors"
    return @{ HostPath = $hostPath; Arguments = $arguments }
}

function Start-MonitorService {
    if (Test-MonitorServiceRunning -NoCache) { return $true }
    $launch = Get-MonitorServiceLaunch
    Start-Process -FilePath $launch.HostPath -ArgumentList $launch.Arguments -WindowStyle Hidden
    # Hand over immediately: stop anything the app is running so nothing is sent twice.
    foreach ($run in @($script:monitorRuns.Values)) { try { $run.State.Cancellation.Cancel() } catch { } }
    $script:monitorRuns = @{}
    $script:serviceRunningCached = $true; $script:serviceCheckTime = [datetime]::UtcNow
    Write-Log 'Background monitor service started.' -Level Info
    return $true
}

function Stop-MonitorService {
    $task = Get-MonitorScheduledTask
    if ($task -and $task.State -eq 'Running') { try { Stop-ScheduledTask -TaskName $script:MonitorTaskName -ErrorAction Stop } catch { Write-Log "Could not stop the scheduled task: $($_.Exception.Message)" -Level Info } }
    try {
        $stopEvent = $null
        if ([System.Threading.EventWaitHandle]::TryOpenExisting($script:MonitorServiceStopEventName, [ref]$stopEvent)) { [void]$stopEvent.Set(); $stopEvent.Dispose() }
    } catch { }
    $script:serviceRunningCached = $false; $script:serviceCheckTime = $null
    Write-Log 'Background monitor service stop requested.' -Level Info
}

# Windows sign-in auto-start, through a shortcut in the user's Startup folder (no admin rights needed).
function Get-MonitorAutoStartPath { return (Join-Path ([Environment]::GetFolderPath('Startup')) 'API Tester Monitors.lnk') }
function Test-MonitorAutoStart { return (Test-Path (Get-MonitorAutoStartPath)) }
function Set-MonitorAutoStart {
    param([bool]$Enabled)
    $shortcutPath = Get-MonitorAutoStartPath
    if (-not $Enabled) { Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue; return }
    $launch = Get-MonitorServiceLaunch
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $launch.HostPath
    $shortcut.Arguments = $launch.Arguments
    $shortcut.WorkingDirectory = Split-Path $PSCommandPath
    $shortcut.WindowStyle = 7
    $shortcut.Description = 'Runs the API Tester monitors in the background'
    $shortcut.Save()
}

# Status written by the service so the Monitor Manager can show last run / last result.
function Save-MonitorStatus {
    param([switch]$Force)
    if (-not $Force -and $script:monitorStatusSaved -and ([datetime]::Now - $script:monitorStatusSaved).TotalSeconds -lt 5) { return }
    $script:monitorStatusSaved = [datetime]::Now
    try {
        $entries = @{}
        foreach ($monitor in @($script:monitors | Where-Object { $_ })) {
            $entries[[string]$monitor.Id] = @{ LastRun = $(if ($monitor.LastRun) { ([datetime]$monitor.LastRun).ToString('o') } else { '' }); LastResult = [string]$script:monitorLastResult[[string]$monitor.Id] }
        }
        @{ Updated = (Get-Date).ToString('o'); ProcessId = $PID; Monitors = $entries } | ConvertTo-Json -Depth 4 | Set-Content -Path (Get-MonitorStatusFilePath) -Encoding UTF8
    } catch { }
}

function Get-MonitorServiceStatus {
    try {
        $path = Get-MonitorStatusFilePath
        if (Test-Path $path) { return (ConvertFrom-JsonToHashtable -Json (Get-Content -Path $path -Raw)) }
    } catch { }
    return $null
}

# Reloads the monitors file (edited by the app) while keeping the in-memory last-run times.
function Update-MonitorsFromDisk {
    $lastRuns = @{}
    foreach ($monitor in @($script:monitors | Where-Object { $_ })) { $lastRuns[[string]$monitor.Id] = $monitor.LastRun }
    Import-Monitors
    foreach ($monitor in @($script:monitors | Where-Object { $_ })) {
        if ($lastRuns.ContainsKey([string]$monitor.Id) -and $lastRuns[[string]$monitor.Id]) { Set-ObjectProperty -Object $monitor -Name 'LastRun' -Value $lastRuns[[string]$monitor.Id] }
    }
}

function Invoke-MonitorService {
    $script:isMonitorService = $true
    Import-Settings; Import-Globals; Import-Environments; Import-Collections; Import-Monitors
    $createdNew = $false
    try { $mutex = New-Object System.Threading.Mutex($true, $script:MonitorServiceMutexName, [ref]$createdNew) }
    catch { $mutex = New-Object System.Threading.Mutex($true, ($script:MonitorServiceMutexName -replace '^Global', 'Local'), [ref]$createdNew) }
    if (-not $createdNew) { Write-Host 'The API Tester background monitor service is already running.'; $mutex.Dispose(); return }
    try { $stopEvent = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, $script:MonitorServiceStopEventName) }
    catch { $stopEvent = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, ($script:MonitorServiceStopEventName -replace '^Global', 'Local')) }
    $script:monitorRuns = @{}
    $script:monitorServiceStopRequested = $false

    Initialize-MonitorHistory
    Initialize-MonitorTray -Mode 'Service'
    $runningCount = @($script:monitors | Where-Object { $_ -and $_.Status -eq 'Running' }).Count
    Show-MonitorBalloon -Title 'API Tester monitors are running' -Message "$runningCount monitor(s) active in the background. Double-click the tray icon to open API Tester, right-click for monitors and options." -Kind 'Info'
    Write-Log "Background monitor service started ($runningCount active monitors)." -Level Info

    $monitorsStamp = if (Test-Path $monitorsFilePath) { (Get-Item $monitorsFilePath).LastWriteTimeUtc } else { $null }
    try {
        while (-not $script:monitorServiceStopRequested -and -not $stopEvent.WaitOne(0)) {
            [System.Windows.Forms.Application]::DoEvents()
            try {
                $stamp = if (Test-Path $monitorsFilePath) { (Get-Item $monitorsFilePath).LastWriteTimeUtc } else { $null }
                if ($stamp -ne $monitorsStamp) { $monitorsStamp = $stamp; Update-MonitorsFromDisk }
                Step-MonitorEngine
                Save-MonitorStatus
            } catch { Write-Log "Background monitor error: $($_.Exception.Message)" -Level Error }
            Start-Sleep -Milliseconds 250
        }
    } finally {
        foreach ($run in @($script:monitorRuns.Values)) { try { $run.State.Cancellation.Cancel() } catch { } }
        Save-MonitorStatus -Force
        Stop-MonitorWebServer
        try { $script:notifyIcon.Visible = $false; $script:notifyIcon.Dispose() } catch { }
        try { $stopEvent.Dispose() } catch { }
        try { $mutex.ReleaseMutex(); $mutex.Dispose() } catch { }
        Write-Log 'Background monitor service stopped.' -Level Info
    }
}

# Sends an alert email on a background runspace so a slow SMTP server never pauses the window or the service.
function Send-MonitorEmailInBackground {
    param([string]$To, [string]$Subject, [string]$Body)
    if ($script:settings.MonitorSmtpAuthMethod -eq 'OAuth2' -and $script:settings.MonitorSmtpRefreshToken -and $script:settings.MonitorSmtpTokenEndpoint) {
        $refresh = $false
        if ($script:settings.MonitorSmtpTokenExpiry) { if ([DateTime]::UtcNow -ge [DateTime]$script:settings.MonitorSmtpTokenExpiry) { $refresh = $true } }
        elseif (-not $script:settings.MonitorSmtpPass) { $refresh = $true }
        if ($refresh) { Update-SmtpToken }
    }
    $isHtml = [bool]($script:settings.MonitorAlertBodyForceHtml -or (Test-IsHtmlBody -Body $Body))
    $worker = [PowerShell]::Create()
    [void]$worker.AddScript({
        param($Settings, $To, $Subject, $Body, $IsHtml, $OAuthFunctionText)
        if ($Settings.MonitorSmtpAuthMethod -eq 'OAuth2') {
            . ([scriptblock]::Create("function Send-SmtpOAuth2 {`n$OAuthFunctionText`n}"))
            Send-SmtpOAuth2 -Server $Settings.MonitorSmtpServer -Port $Settings.MonitorSmtpPort -UseSsl $Settings.MonitorSmtpUseSsl -From $Settings.MonitorSmtpFrom -To $To -Subject $Subject -Body $Body -User $Settings.MonitorSmtpUser -AccessToken $Settings.MonitorSmtpPass -IsHtml:$IsHtml
        } else {
            $parameters = @{ SmtpServer = $Settings.MonitorSmtpServer; Port = $Settings.MonitorSmtpPort; UseSsl = [bool]$Settings.MonitorSmtpUseSsl; From = $Settings.MonitorSmtpFrom; To = $To; Subject = $Subject; Body = $Body; BodyAsHtml = $IsHtml }
            if ($Settings.MonitorSmtpUser) { $parameters.Credential = New-Object System.Management.Automation.PSCredential($Settings.MonitorSmtpUser, ($Settings.MonitorSmtpPass | ConvertTo-SecureString -AsPlainText -Force)) }
            Send-MailMessage @parameters -ErrorAction Stop
        }
    }).AddArgument($script:settings.Clone()).AddArgument($To).AddArgument($Subject).AddArgument($Body).AddArgument($isHtml).AddArgument([string]${function:Send-SmtpOAuth2})
    [void]$script:backgroundEmails.Add(@{ Worker = $worker; Handle = $worker.BeginInvoke(); To = $To })
}

function Update-BackgroundEmails {
    foreach ($job in @($script:backgroundEmails)) {
        if (-not $job.Handle.IsCompleted) { continue }
        try {
            [void]$job.Worker.EndInvoke($job.Handle)
            if ($job.Worker.HadErrors) { Write-Log "Failed to send email alert to $($job.To): $(@($job.Worker.Streams.Error)[0])" -Level Info }
        } catch { Write-Log "Failed to send email alert to $($job.To): $($_.Exception.Message)" -Level Info }
        finally { $job.Worker.Dispose(); [void]$script:backgroundEmails.Remove($job) }
    }
}

# ------------------------------------------------------------------------------------------------
# Live monitor dashboard in the browser (http://127.0.0.1:<port>/, loopback only)
# Served by whichever runner is active (the app or the background service). The HTTP server runs on its own
# runspace, so a slow or idle browser connection never blocks the window or the monitor loop; the runner only
# publishes a JSON snapshot into a synchronized table once per second.
# ------------------------------------------------------------------------------------------------

$script:monitorHistory = @{}

function Get-MonitorDashboardUrl {
    $port = if ([int]$script:settings.MonitorDashboardPort -gt 0) { [int]$script:settings.MonitorDashboardPort } else { 8765 }
    return "http://127.0.0.1:$port/"
}

function Add-MonitorHistorySample {
    param([string]$MonitorId, [datetime]$Time, [int]$TimeMs, [bool]$Ok)
    if (-not $script:monitorHistory.ContainsKey($MonitorId)) { $script:monitorHistory[$MonitorId] = New-Object System.Collections.ArrayList }
    $samples = $script:monitorHistory[$MonitorId]
    [void]$samples.Add(@{ t = $Time.ToString('o'); ms = $TimeMs; ok = $Ok })
    while ($samples.Count -gt 500) { $samples.RemoveAt(0) }
}

# Seeds the in-memory history from the end of the monitor log so the page has data straight away.
function Initialize-MonitorHistory {
    $script:monitorHistory = @{}
    if (-not (Test-Path $monitorLogFilePath)) { return }
    try {
        $header = Get-Content -Path $monitorLogFilePath -TotalCount 1
        $rows = @((@($header) + @(Get-Content -Path $monitorLogFilePath -Tail 3000)) | ConvertFrom-Csv | Where-Object { $_.Timestamp -and $_.Timestamp -ne 'Timestamp' })
        $idsByName = @{}
        foreach ($monitor in @($script:monitors | Where-Object { $_ })) { $idsByName[[string]$monitor.Name] = [string]$monitor.Id }
        foreach ($row in $rows) {
            if (-not $idsByName.ContainsKey([string]$row.MonitorName)) { continue }
            $time = [datetime]::MinValue
            if (-not [datetime]::TryParse([string]$row.Timestamp, [ref]$time)) { continue }
            Add-MonitorHistorySample -MonitorId $idsByName[[string]$row.MonitorName] -Time $time -TimeMs ([int]$row.TimeMs) -Ok ($row.Success -eq 'True')
        }
    } catch { Write-Log "Could not read the monitor log for the dashboard: $($_.Exception.Message)" -Level Info }
}

function Get-MonitorDashboardHtml {
    return @'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>API Tester - Monitors</title>
<style>
:root { --bg:#F4F7FC; --surface:#fff; --border:#D8E1EF; --text:#1F2937; --muted:#64748B; --primary:#3659C9; --ok:#107C10; --bad:#D93025; --warn:#B45309; }
@media (prefers-color-scheme: dark) { :root { --bg:#0F172A; --surface:#111B33; --border:#304264; --text:#DCE7FF; --muted:#94A3B8; --primary:#4C6FE0; } }
* { box-sizing:border-box } body { margin:0; font-family:"Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--text) }
header { background:linear-gradient(90deg,#3659C9,#243E9E); color:#fff; padding:18px 28px; display:flex; align-items:center; gap:18px; flex-wrap:wrap }
header h1 { margin:0; font-size:22px; font-weight:600 } header .meta { opacity:.85; font-size:13px } header .spacer { flex:1 }
main { padding:22px 28px; max-width:1400px; margin:0 auto }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin-bottom:20px }
.card { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:14px 16px }
.card .label { font-size:11px; font-weight:600; color:var(--muted); letter-spacing:.06em; text-transform:uppercase } .card .value { font-size:28px; font-weight:700; margin-top:6px }
table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); border-radius:10px; overflow:hidden }
th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); font-size:14px; vertical-align:middle }
th { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; font-weight:600 } tr:last-child td { border-bottom:none }
.pill { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600; color:#fff }
.ok { background:var(--ok) } .bad { background:var(--bad) } .idle { background:#9AA7BD } .url { color:var(--muted); font-size:12px; word-break:break-all }
.num { font-variant-numeric:tabular-nums } .empty { padding:40px; text-align:center; color:var(--muted) } .error { color:var(--bad); padding:10px 0 }
</style></head>
<body>
<header><div><h1>API Tester monitors</h1><div class="meta" id="meta">Loading...</div></div><div class="spacer"></div><div class="meta">Refreshes every 3 seconds</div></header>
<main>
<div class="cards">
  <div class="card"><div class="label">Monitors running</div><div class="value num" id="running">-</div></div>
  <div class="card"><div class="label">Healthy now</div><div class="value num" id="healthy">-</div></div>
  <div class="card"><div class="label">Failing now</div><div class="value num" id="failing">-</div></div>
  <div class="card"><div class="label">Uptime (last 24 h)</div><div class="value num" id="uptime">-</div></div>
</div>
<div id="error" class="error"></div>
<table><thead><tr><th>Monitor</th><th>State</th><th>Last result</th><th>Last run</th><th>Uptime 24 h</th><th>Avg / p50 / p95 / p99 (ms)</th><th>Latency (last 60)</th></tr></thead><tbody id="rows"></tbody></table>
</main>
<script>
function esc(s){ return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function spark(samples){
  if(!samples || !samples.length) return '<span class="url">no data</span>';
  const w=220,h=36,max=Math.max(...samples.map(s=>s.ms),1),step=samples.length>1?w/(samples.length-1):w;
  const pts=samples.map((s,i)=>`${(i*step).toFixed(1)},${(h-2-(s.ms/max)*(h-6)).toFixed(1)}`).join(' ');
  const dots=samples.map((s,i)=>s.ok?'':`<circle cx="${(i*step).toFixed(1)}" cy="${(h-2-(s.ms/max)*(h-6)).toFixed(1)}" r="2.6" fill="var(--bad)"/>`).join('');
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><polyline fill="none" stroke="var(--primary)" stroke-width="1.8" points="${pts}"/>${dots}</svg>`;
}
async function refresh(){
  try{
    const r = await fetch('/api/status', {cache:'no-store'}); const d = await r.json();
    document.getElementById('error').textContent='';
    document.getElementById('meta').textContent = `Served by: ${d.runner} - updated ${new Date(d.generated).toLocaleTimeString()}`;
    const running = d.monitors.filter(m=>m.status==='Running');
    document.getElementById('running').textContent = running.length + ' / ' + d.monitors.length;
    document.getElementById('healthy').textContent = running.filter(m=>m.lastOk===true).length;
    document.getElementById('failing').textContent = running.filter(m=>m.lastOk===false).length;
    const all = d.monitors.filter(m=>m.checks24h>0); const total = all.reduce((a,m)=>a+m.checks24h,0), passed = all.reduce((a,m)=>a+m.passed24h,0);
    document.getElementById('uptime').textContent = total ? (100*passed/total).toFixed(2)+'%' : '-';
    const rows = d.monitors.map(m => {
      const state = m.status==='Running' ? (m.lastOk===false ? '<span class="pill bad">Failing</span>' : m.lastOk===true ? '<span class="pill ok">Healthy</span>' : '<span class="pill idle">Waiting</span>') : '<span class="pill idle">Stopped</span>';
      return `<tr><td><b>${esc(m.name)}</b><div class="url">${esc(m.method)} ${esc(m.url)} - every ${m.intervalSeconds}s</div></td><td>${state}</td><td>${esc(m.lastResult||'-')}</td>
        <td class="num">${m.lastRun ? new Date(m.lastRun).toLocaleString() : 'never'}</td><td class="num">${m.checks24h ? (100*m.passed24h/m.checks24h).toFixed(2)+'%' : '-'}</td>
        <td class="num">${m.avgMs!=null ? m.avgMs+' / '+m.p50Ms+' / '+m.p95Ms+' / '+m.p99Ms : '-'}</td><td>${spark(m.samples)}</td></tr>`;
    }).join('');
    document.getElementById('rows').innerHTML = rows || '<tr><td colspan="7" class="empty">No monitors yet. Add one in API Tester -> Monitor -> Monitor Manager.</td></tr>';
  } catch(e) { document.getElementById('error').textContent = 'API Tester is not serving the dashboard right now (the app and the background monitors are both closed?). Retrying...'; }
}
refresh(); setInterval(refresh, 3000);
</script></body></html>
'@
}

# Builds the JSON snapshot published to the web server.
function Get-MonitorDashboardStatusJson {
    $cutoff = [datetime]::Now.AddHours(-24)
    $entries = foreach ($monitor in @($script:monitors | Where-Object { $_ })) {
        $id = [string]$monitor.Id
        $samples = if ($script:monitorHistory.ContainsKey($id)) { @($script:monitorHistory[$id]) } else { @() }
        $recent = @($samples | Where-Object { [datetime]$_.t -ge $cutoff })
        $times = @($recent | ForEach-Object { [int]$_.ms } | Sort-Object)
        $last = if ($samples.Count -gt 0) { $samples[$samples.Count - 1] } else { $null }
        [ordered]@{
            id = $id; name = [string]$monitor.Name; method = [string]$monitor.Request.Method; url = [string]$monitor.Request.Url
            status = [string]$monitor.Status; intervalSeconds = [int]$monitor.IntervalSeconds
            lastRun = $(if ($monitor.LastRun) { ([datetime]$monitor.LastRun).ToString('o') } elseif ($last) { $last.t } else { $null })
            lastResult = [string]$script:monitorLastResult[$id]; lastOk = $(if ($last) { [bool]$last.ok } else { $null })
            checks24h = $recent.Count; passed24h = @($recent | Where-Object { $_.ok }).Count
            avgMs = $(if ($times.Count) { [int]($times | Measure-Object -Average).Average } else { $null })
            p50Ms = (Get-LatencyPercentile -SortedValues ([int[]]$times) -Fraction 0.5)
            p95Ms = (Get-LatencyPercentile -SortedValues ([int[]]$times) -Fraction 0.95)
            p99Ms = (Get-LatencyPercentile -SortedValues ([int[]]$times) -Fraction 0.99)
            samples = @($samples | Select-Object -Last 60)
        }
    }
    $snapshot = [ordered]@{ generated = (Get-Date).ToString('o'); runner = $(if ($script:isMonitorService) { 'Background service' } else { 'API Tester app' }); monitors = @($entries) }
    return (ConvertTo-Json -InputObject $snapshot -Depth 6 -Compress)
}

function Start-MonitorWebServer {
    if ($script:settings.EnableMonitorWebDashboard -eq $false) { return }
    if ($script:monitorWebServer) {
        $server = $script:monitorWebServer
        if (-not $server.Handle.IsCompleted) { return }
        # The previous attempt ended (for example the port was still in use); retry every 5 seconds.
        if (([datetime]::Now - $server.Started).TotalSeconds -lt 5) { return }
        try { $server.Worker.Dispose() } catch { }
        $script:monitorWebServer = $null
    }
    $port = if ([int]$script:settings.MonitorDashboardPort -gt 0) { [int]$script:settings.MonitorDashboardPort } else { 8765 }
    $shared = [hashtable]::Synchronized(@{ StatusJson = '{"monitors":[]}'; Html = (Get-MonitorDashboardHtml); Stop = $false; Error = $null; Listening = $false })
    $worker = [PowerShell]::Create()
    [void]$worker.AddScript({
        param($Shared, $Port)
        try { $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port); $listener.Start(); $Shared.Listening = $true }
        catch { $Shared.Error = $_.Exception.Message; return }
        try {
            while (-not $Shared.Stop) {
                if (-not $listener.Pending()) { Start-Sleep -Milliseconds 100; continue }
                $client = $listener.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 3000; $client.SendTimeout = 3000
                    $stream = $client.GetStream()
                    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII, $false, 4096, $true)
                    $requestLine = $reader.ReadLine()
                    while ($line = $reader.ReadLine()) { }
                    $path = if ($requestLine) { (($requestLine -split ' ')[1] -split '\?')[0] } else { '' }
                    $status = '200 OK'
                    if ($path -eq '/api/status') { $type = 'application/json'; $body = [string]$Shared.StatusJson }
                    elseif ($path -eq '/' -or $path -eq '/index.html') { $type = 'text/html'; $body = [string]$Shared.Html }
                    else { $status = '404 Not Found'; $type = 'text/plain'; $body = 'Not found' }
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $status`r`nContent-Type: $type; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nCache-Control: no-store`r`nConnection: close`r`n`r`n")
                    $stream.Write($headerBytes, 0, $headerBytes.Length); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
                } catch { } finally { $client.Close() }
            }
        } finally { $listener.Stop(); $Shared.Listening = $false }
    }).AddArgument($shared).AddArgument($port)
    $script:monitorWebServer = @{ Worker = $worker; Handle = $worker.BeginInvoke(); Shared = $shared; Port = $port; Started = [datetime]::Now }
}

function Stop-MonitorWebServer {
    if (-not $script:monitorWebServer) { return }
    $script:monitorWebServer.Shared.Stop = $true
    $server = $script:monitorWebServer
    $script:monitorWebServer = $null
    try { if ($server.Handle.AsyncWaitHandle.WaitOne(1000)) { $server.Worker.Dispose() } } catch { }
}

# Called by the active runner: keeps the server running and publishes the snapshot once per second.
function Update-MonitorWebServer {
    Start-MonitorWebServer
    if (-not $script:monitorWebServer) { return }
    if ($script:monitorWebPublished -and ([datetime]::Now - $script:monitorWebPublished).TotalMilliseconds -lt 1000) { return }
    $script:monitorWebPublished = [datetime]::Now
    try { $script:monitorWebServer.Shared.StatusJson = Get-MonitorDashboardStatusJson } catch { }
}

function Open-MonitorDashboardInBrowser {
    if (-not $script:isMonitorService -and -not (Test-MonitorServiceRunning -NoCache)) { Update-MonitorWebServer; Start-Sleep -Milliseconds 300 }
    if ($script:monitorWebServer -and $script:monitorWebServer.Shared.Error) {
        $message = "The monitor dashboard could not listen on port $($script:monitorWebServer.Port): $($script:monitorWebServer.Shared.Error)`n`nChange 'MonitorDashboardPort' in the settings file if another program uses this port."
        if ($script:MainWindowContext) { [void][System.Windows.MessageBox]::Show((Get-MainWindow), $message, 'Monitor dashboard', 'OK', 'Warning') } else { Write-Log $message -Level Warning }
        return
    }
    Start-Process (Get-MonitorDashboardUrl)
}

# ------------------------------------------------------------------------------------------------
# Tray icon (background service and open app)
# The icon is drawn at run time and its colour shows the state: green = all running monitors healthy,
# red = at least one failing, blue = running but no result yet, grey = no monitor running.
# Tooltip and menu list every monitor; clicking a monitor starts or stops it; double-click opens API Tester.
# ------------------------------------------------------------------------------------------------

function New-MonitorTrayIcon {
    param([string]$State = 'Idle')
    if (-not $script:trayIcons) { $script:trayIcons = @{} }
    if ($script:trayIcons.ContainsKey($State)) { return $script:trayIcons[$State] }
    $fill = switch ($State) { 'Healthy' { '#107C10' } 'Failing' { '#D93025' } 'Waiting' { '#3659C9' } default { '#64748B' } }
    $bitmap = New-Object System.Drawing.Bitmap 32, 32
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $diameter = 14
    $shape = New-Object System.Drawing.Drawing2D.GraphicsPath
    $shape.AddArc(0, 0, $diameter, $diameter, 180, 90); $shape.AddArc(31 - $diameter, 0, $diameter, $diameter, 270, 90)
    $shape.AddArc(31 - $diameter, 31 - $diameter, $diameter, $diameter, 0, 90); $shape.AddArc(0, 31 - $diameter, $diameter, $diameter, 90, 90)
    $shape.CloseFigure()
    $brush = New-Object System.Drawing.SolidBrush ([System.Drawing.ColorTranslator]::FromHtml($fill))
    $graphics.FillPath($brush, $shape)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), 3
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round; $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pulse = [System.Drawing.Point[]]@((New-Object System.Drawing.Point 5, 17), (New-Object System.Drawing.Point 11, 17), (New-Object System.Drawing.Point 14, 8),
        (New-Object System.Drawing.Point 18, 24), (New-Object System.Drawing.Point 21, 15), (New-Object System.Drawing.Point 27, 15))
    $graphics.DrawLines($pen, $pulse)
    $icon = [System.Drawing.Icon]::FromHandle($bitmap.GetHicon())
    $pen.Dispose(); $brush.Dispose(); $shape.Dispose(); $graphics.Dispose()
    $script:trayIcons[$State] = $icon
    return $icon
}

function Get-MonitorTraySummary {
    $running = @($script:monitors | Where-Object { $_ -and $_.Status -eq 'Running' })
    $failing = New-Object System.Collections.Generic.List[string]
    $healthy = 0; $waiting = 0
    foreach ($monitor in $running) {
        $samples = $script:monitorHistory[[string]$monitor.Id]
        if ($samples -and $samples.Count -gt 0) { if ($samples[$samples.Count - 1].ok) { $healthy++ } else { $failing.Add([string]$monitor.Name) } } else { $waiting++ }
    }
    $state = if ($running.Count -eq 0) { 'Idle' } elseif ($failing.Count -gt 0) { 'Failing' } elseif ($healthy -gt 0) { 'Healthy' } else { 'Waiting' }
    $long = if ($running.Count -eq 0) { 'API Tester - no monitor running' }
            elseif ($failing.Count -gt 0) { "API Tester - $($running.Count) running, $($failing.Count) failing: $($failing -join ', ')" }
            else { "API Tester - $($running.Count) monitor(s) running, all healthy" }
    $short = if ($long.Length -gt 63) { $long.Substring(0, 60) + '...' } else { $long }   # NotifyIcon.Text is limited to 63 characters
    return @{ Running = $running.Count; Failing = $failing.Count; Healthy = $healthy; Waiting = $waiting; State = $state; Text = $short; LongText = $long }
}

function Initialize-MonitorTray {
    param([ValidateSet('App', 'Service')][string]$Mode)
    $script:trayMode = $Mode
    try {
        $trayIcon = New-Object System.Windows.Forms.NotifyIcon
        $trayIcon.Icon = New-MonitorTrayIcon -State 'Idle'
        $trayIcon.Text = 'API Tester monitors'
        $menu = New-Object System.Windows.Forms.ContextMenuStrip
        $header = $menu.Items.Add('API Tester monitors')
        $header.Enabled = $false
        $header.Font = New-Object System.Drawing.Font($menu.Font, [System.Drawing.FontStyle]::Bold)
        $script:trayHeaderItem = $header
        $script:trayMonitorsItem = New-Object System.Windows.Forms.ToolStripMenuItem('Monitors')
        [void]$menu.Items.Add($script:trayMonitorsItem)
        [void]$menu.Items.Add('-')
        [void]$menu.Items.Add('Open API Tester', $null, { Open-ApiTesterFromTray })
        [void]$menu.Items.Add('Open monitor dashboard (browser)', $null, { Open-MonitorDashboardInBrowser })
        [void]$menu.Items.Add('Open monitor log', $null, { if (Test-Path $monitorLogFilePath) { Start-Process $monitorLogFilePath } })
        [void]$menu.Items.Add('-')
        if ($Mode -eq 'Service') {
            [void]$menu.Items.Add('Stop background monitors', $null, { $script:monitorServiceStopRequested = $true })
        } else {
            [void]$menu.Items.Add('Monitor Manager...', $null, { Invoke-UiGuard { Open-ApiTesterFromTray; Show-MonitorManagerWindow } 'Monitor manager' })
            [void]$menu.Items.Add('Keep running in the background (tray only)', $null, { Invoke-UiGuard { Save-Monitors; [void](Start-MonitorService); Update-MonitorTray -Force } 'Background monitors' })
        }
        $menu.Add_Opening({ Invoke-UiGuard { Update-MonitorTrayMenu } 'Tray menu' })
        $trayIcon.ContextMenuStrip = $menu
        $trayIcon.Add_DoubleClick({ Open-ApiTesterFromTray })
        $trayIcon.Add_BalloonTipClicked({ Open-ApiTesterFromTray })
        $script:notifyIcon = $trayIcon
        $script:trayState = 'Idle'
        $trayIcon.Visible = ($Mode -eq 'Service')
        Update-MonitorTray -Force
    } catch {
        $script:notifyIcon = $null
        Write-Log "No tray icon (no interactive desktop): $($_.Exception.Message)" -Level Info
    }
}

# Refreshes colour, tooltip and (for the app) visibility: the app shows its icon only while it is the one running
# monitors, so there is never more than one icon.
function Update-MonitorTray {
    param([switch]$Force)
    if (-not $script:notifyIcon) { return }
    if (-not $Force -and $script:trayUpdated -and ([datetime]::Now - $script:trayUpdated).TotalMilliseconds -lt 1000) { return }
    $script:trayUpdated = [datetime]::Now
    try {
        $summary = Get-MonitorTraySummary
        if ($summary.State -ne $script:trayState) { $script:notifyIcon.Icon = New-MonitorTrayIcon -State $summary.State; $script:trayState = $summary.State }
        if ($script:notifyIcon.Text -ne $summary.Text) { $script:notifyIcon.Text = $summary.Text }
        if ($script:trayMode -eq 'App') {
            $visible = ($summary.Running -gt 0) -and -not (Test-MonitorServiceRunning)
            if ($script:notifyIcon.Visible -ne $visible) { $script:notifyIcon.Visible = $visible }
        }
    } catch { }
}

function Update-MonitorTrayMenu {
    $summary = Get-MonitorTraySummary
    $script:trayHeaderItem.Text = $summary.LongText
    $entries = $script:trayMonitorsItem.DropDownItems
    $entries.Clear()
    $all = @($script:monitors | Where-Object { $_ })
    if ($all.Count -eq 0) { $none = $entries.Add('No monitors yet - add one in Monitor Manager'); $none.Enabled = $false; return }
    foreach ($monitor in $all) {
        $state = if ($monitor.Status -ne 'Running') { 'stopped' } elseif ($script:monitorLastResult[[string]$monitor.Id]) { [string]$script:monitorLastResult[[string]$monitor.Id] } else { 'waiting for the first check' }
        $label = "$($monitor.Name)  -  $state"
        if ($label.Length -gt 100) { $label = $label.Substring(0, 97) + '...' }
        $entry = New-Object System.Windows.Forms.ToolStripMenuItem($label)
        $entry.Checked = ($monitor.Status -eq 'Running')
        $entry.Tag = [string]$monitor.Id
        $entry.ToolTipText = 'Click to start or stop this monitor'
        $entry.Add_Click({ param($sender) Invoke-UiGuard { Switch-MonitorFromTray -MonitorId ([string]$sender.Tag) } 'Start/stop monitor' })
        [void]$entries.Add($entry)
    }
    [void]$entries.Add('-')
    [void]$entries.Add('Start all', $null, { Invoke-UiGuard { Set-AllMonitorsStatus -Status 'Running' } 'Start all' })
    [void]$entries.Add('Stop all', $null, { Invoke-UiGuard { Set-AllMonitorsStatus -Status 'Stopped' } 'Stop all' })
}

function Switch-MonitorFromTray {
    param([string]$MonitorId)
    $monitor = @($script:monitors | Where-Object { $_ -and [string]$_.Id -eq $MonitorId })[0]
    if (-not $monitor) { return }
    if ($monitor.Status -eq 'Running') {
        Set-ObjectProperty -Object $monitor -Name 'Status' -Value 'Stopped'
        if ($script:monitorRuns.ContainsKey($MonitorId)) { try { $script:monitorRuns[$MonitorId].State.Cancellation.Cancel() } catch { }; $script:monitorRuns.Remove($MonitorId) }
    } else {
        Set-ObjectProperty -Object $monitor -Name 'Status' -Value 'Running'
        Set-ObjectProperty -Object $monitor -Name 'LastRun' -Value $null
    }
    Save-Monitors
    Update-MonitorTray -Force
}

function Set-AllMonitorsStatus {
    param([string]$Status)
    foreach ($monitor in @($script:monitors | Where-Object { $_ })) {
        if ($monitor.Status -eq $Status) { continue }
        Set-ObjectProperty -Object $monitor -Name 'Status' -Value $Status
        if ($Status -eq 'Running') { Set-ObjectProperty -Object $monitor -Name 'LastRun' -Value $null }
    }
    if ($Status -eq 'Stopped') { foreach ($run in @($script:monitorRuns.Values)) { try { $run.State.Cancellation.Cancel() } catch { } }; $script:monitorRuns = @{} }
    Save-Monitors
    Update-MonitorTray -Force
}

# Double-click / "Open API Tester": brings the open window to the front, or starts the app from the service.
function Open-ApiTesterFromTray {
    if ($script:trayMode -eq 'App' -and $script:MainWindowContext) {
        $window = Get-MainWindow
        if ($window.WindowState -eq [System.Windows.WindowState]::Minimized) { $window.WindowState = [System.Windows.WindowState]::Normal }
        [void]$window.Activate(); $window.Topmost = $true; $window.Topmost = $false
        return
    }
    try { Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList "-NoProfile -STA -ExecutionPolicy Bypass -File `"$PSCommandPath`"" } catch { }
}

# ------------------------------------------------------------------------------------------------
# Monitor engine: runs due monitors with async requests, logs to CSV, raises alerts
# ------------------------------------------------------------------------------------------------

function Start-MonitorEngine {
    if ($script:monitorEngineTimer) { return }
    $script:monitorRuns = @{}
    Initialize-MonitorHistory
    Initialize-MonitorTray -Mode 'App'
    $script:monitorEngineTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:monitorEngineTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:monitorEngineTimer.Add_Tick({ Invoke-UiGuard { Step-MonitorEngine } 'Monitors' })
    $script:monitorEngineTimer.Start()
}

function Stop-MonitorEngine {
    try { if ($script:monitorEngineTimer) { $script:monitorEngineTimer.Stop() } } catch { }
    Stop-MonitorWebServer
    $script:monitorEngineTimer = $null
    foreach ($run in @($script:monitorRuns.Values)) { try { $run.State.Cancellation.Cancel() } catch { } }
    $script:monitorRuns = @{}
    try { if ($script:notifyIcon) { $script:notifyIcon.Visible = $false; $script:notifyIcon.Dispose() } } catch { }
    $script:notifyIcon = $null
}

function Show-MonitorBalloon {
    param([string]$Title, [string]$Message, [string]$Kind = 'Error')
    try { if ($script:notifyIcon) { $script:notifyIcon.ShowBalloonTip(5000, $Title, $Message, [System.Windows.Forms.ToolTipIcon]::$Kind) } } catch { }
}

function Step-MonitorEngine {
    Update-BackgroundEmails
    Update-MonitorTray
    if (Test-MonitorServiceRunning) {
        if ($script:monitorRuns.Count -gt 0) { foreach ($run in @($script:monitorRuns.Values)) { try { $run.State.Cancellation.Cancel() } catch { } }; $script:monitorRuns = @{} }
        Stop-MonitorWebServer
        return
    }
    Update-MonitorWebServer
    $now = Get-Date
    foreach ($monitor in @($script:monitors)) {
        if (-not $monitor -or $monitor.Status -ne 'Running' -or $script:monitorRuns.ContainsKey($monitor.Id)) { continue }
        $lastRun = if ($monitor.LastRun) { [datetime]$monitor.LastRun } else { [datetime]::MinValue }
        if (($now - $lastRun).TotalSeconds -lt [int]$monitor.IntervalSeconds) { continue }
        Start-MonitorRun -Monitor $monitor
    }
    foreach ($id in @($script:monitorRuns.Keys)) {
        $run = $script:monitorRuns[$id]
        if (-not $run.State.Task.IsCompleted) { continue }
        $script:monitorRuns.Remove($id)
        $result = Get-HttpRequestResult -RequestState $run.State
        Complete-MonitorRun -Monitor $run.Monitor -Result $result
    }
}

function Start-MonitorRun {
    param($Monitor)
    Set-ObjectProperty -Object $Monitor -Name 'LastRun' -Value (Get-Date)
    $timeout = [int](Get-ObjectProperty $Monitor.Request 'RequestTimeoutSeconds' 30)
    try {
        $state = Start-HttpRequestFromObject -Request $Monitor.Request -TimeoutSeconds ([Math]::Max(1, $timeout))
        $script:monitorRuns[$Monitor.Id] = @{ State = $state; Monitor = $Monitor }
    } catch {
        Complete-MonitorRun -Monitor $Monitor -Result @{ Success = $false; ErrorMessage = $_.Exception.Message; ElapsedMs = 0 }
    }
}

function Complete-MonitorRun {
    param($Monitor, $Result)
    $id = [string]$Monitor.Id
    $alerts = $Monitor.Alerts
    $statusCode = if ($Result.Success) { [int]$Result.StatusCode } else { 0 }
    $succeeded = $Result.Success -and $statusCode -ge 200 -and $statusCode -lt 300
    $message = if (-not $Result.Success) { [string]$Result.ErrorMessage } elseif ($succeeded) { 'OK' } else { "HTTP $statusCode $($Result.ReasonPhrase)".Trim() }
    $timeMs = [int]$Result.ElapsedMs

    # Retry N times (5 seconds apart) before a failure is logged and alerted.
    if (-not $script:monitorRetryAttempts) { $script:monitorRetryAttempts = @{} }
    $retryLimit = [int](Get-ObjectProperty $alerts 'RetryCount' 0)
    if (-not $succeeded -and [int]$script:monitorRetryAttempts[$id] -lt $retryLimit) {
        $script:monitorRetryAttempts[$id] = [int]$script:monitorRetryAttempts[$id] + 1
        $script:monitorLastResult[$id] = "Retrying ($($script:monitorRetryAttempts[$id])/$retryLimit) - $message"
        Set-ObjectProperty -Object $Monitor -Name 'LastRun' -Value ((Get-Date).AddSeconds(5 - [int]$Monitor.IntervalSeconds))
        return
    }
    $retriesUsed = [int]$script:monitorRetryAttempts[$id]
    $script:monitorRetryAttempts[$id] = 0
    if ($retriesUsed -gt 0) { $message = "$message (after $retriesUsed retr$(if ($retriesUsed -eq 1) { 'y' } else { 'ies' }))" }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-MonitorHistorySample -MonitorId $id -Time (Get-Date) -TimeMs $timeMs -Ok $succeeded
    $script:monitorLastResult[$id] = "$(if ($succeeded) { 'OK' } else { 'FAIL' }) - $message ($timeMs ms)"
    try {
        [PSCustomObject]@{ Timestamp = $timestamp; MonitorName = $Monitor.Name; URL = $Monitor.Request.Url; Success = $succeeded; StatusCode = $statusCode; TimeMs = $timeMs; Message = $message } |
            Export-Csv -Path $monitorLogFilePath -Append -NoTypeInformation -Force
    } catch { Write-Log "Failed to write to monitor log: $($_.Exception.Message)" -Level Info }

    # Decide which alert (if any) this result raises.
    if (-not $script:monitorAlertState) { $script:monitorAlertState = @{} }
    $previous = if ($script:monitorAlertState.ContainsKey($id)) { $script:monitorAlertState[$id] } else { @{ Down = $false; Slow = $false } }
    $isSlow = $succeeded -and $alerts.OnSlow -and $timeMs -gt [int]$alerts.ThresholdMs
    $stateChangeOnly = [bool](Get-ObjectProperty $alerts 'OnStateChangeOnly' $false)
    $alertType = $null
    if ($alerts.OnFailure -and -not $succeeded) { if (-not $stateChangeOnly -or -not $previous.Down) { $alertType = 'Down' } }
    elseif ($alerts.OnFailure -and $succeeded -and $previous.Down) { $alertType = 'Recovered' }
    elseif ($isSlow) { if (-not $stateChangeOnly -or -not $previous.Slow) { $alertType = 'Slow' } }
    $script:monitorAlertState[$id] = @{ Down = (-not $succeeded); Slow = $isSlow }
    if (-not $alertType) { return }

    $alertMessage = switch ($alertType) { 'Down' { "$($Monitor.Name) failed: $message" } 'Recovered' { "$($Monitor.Name) recovered: $message ($timeMs ms)" } 'Slow' { "$($Monitor.Name) slow: $timeMs ms" } }
    if (Test-InQuietHours -Start (Get-ObjectProperty $alerts 'QuietHoursStart' '') -End (Get-ObjectProperty $alerts 'QuietHoursEnd' '')) {
        Write-Log "Alert suppressed (quiet hours): $alertMessage" -Level Info
        return
    }
    $kind = switch ($alertType) { 'Down' { 'Error' } 'Slow' { 'Warning' } default { 'Info' } }
    Show-MonitorBalloon -Title $(if ($alertType -eq 'Recovered') { 'API Monitor recovered' } elseif ($alertType -eq 'Slow') { 'API Monitor warning' } else { 'API Monitor alert' }) -Message $alertMessage -Kind $kind
    $alertData = @{ MonitorName = $Monitor.Name; Status = $(if ($alertType -eq 'Down') { 'Failure' } else { $alertType }); StatusCode = $statusCode; Url = $Monitor.Request.Url; TimeMs = $timeMs; Message = $message; Timestamp = $timestamp }
    if ($alerts.SendEmail -and $alerts.EmailTo -and $script:settings.MonitorSmtpServer) {
        try {
            $subjectTemplate = if ($script:settings.MonitorAlertSubjectTemplate) { $script:settings.MonitorAlertSubjectTemplate } else { 'API Alert: {MonitorName}' }
            $bodyTemplate = if ($script:settings.MonitorAlertBodyTemplate) { $script:settings.MonitorAlertBodyTemplate } else { $alertMessage }
            $emailSubject = Format-AlertTemplate -Template $subjectTemplate -Data $alertData
            $emailBody = Format-AlertTemplate -Template $bodyTemplate -Data $alertData
            if ([string]::IsNullOrWhiteSpace($emailSubject)) { $emailSubject = "API Alert: $($Monitor.Name)" }
            if ([string]::IsNullOrWhiteSpace($emailBody)) { $emailBody = $alertMessage }
            Send-MonitorEmailInBackground -To $alerts.EmailTo -Subject $emailSubject -Body $emailBody
        } catch { Write-Log "Failed to send email alert: $($_.Exception.Message)" -Level Info }
    }
    $webhookUrl = [string](Get-ObjectProperty $alerts 'WebhookUrl' '')
    if ($webhookUrl) { Send-MonitorWebhookAlert -Url $webhookUrl -Type ([string](Get-ObjectProperty $alerts 'WebhookType' 'Generic')) -Title "API Tester: $($Monitor.Name) $($alertType.ToLower())" -Data $alertData -Kind $alertType }
    if ($Monitor.AnalyticsUrl) {
        try {
            if (-not $script:analyticsClient) { Add-Type -AssemblyName System.Net.Http; $script:analyticsClient = New-Object System.Net.Http.HttpClient; $script:analyticsClient.Timeout = [TimeSpan]::FromSeconds(10) }
            $payload = @{ monitorName = $Monitor.Name; timestamp = $timestamp; success = $succeeded; statusCode = $statusCode; timeMs = $timeMs; message = $message } | ConvertTo-Json -Compress
            [void]$script:analyticsClient.PostAsync($Monitor.AnalyticsUrl, (New-Object System.Net.Http.StringContent($payload, [System.Text.Encoding]::UTF8, 'application/json')))
        } catch { Write-Log "Failed to send analytics for $($Monitor.Name): $($_.Exception.Message)" -Level Info }
    }
}

# Sends an email using the SMTP settings (Basic or OAuth2). Throws on failure.
function Send-MonitorEmail {
    param([string]$To, [string]$Subject, [string]$Body)
    $isHtml = $script:settings.MonitorAlertBodyForceHtml -or (Test-IsHtmlBody -Body $Body)
    if ($script:settings.MonitorSmtpAuthMethod -eq 'OAuth2') {
        if ($script:settings.MonitorSmtpRefreshToken -and $script:settings.MonitorSmtpTokenEndpoint) {
            $shouldRefresh = $false
            if ($script:settings.MonitorSmtpTokenExpiry) { if ([DateTime]::UtcNow -ge [DateTime]$script:settings.MonitorSmtpTokenExpiry) { $shouldRefresh = $true } }
            elseif (-not $script:settings.MonitorSmtpPass) { $shouldRefresh = $true }
            if ($shouldRefresh) { Update-SmtpToken }
        }
        Send-SmtpOAuth2 -Server $script:settings.MonitorSmtpServer -Port $script:settings.MonitorSmtpPort -UseSsl $script:settings.MonitorSmtpUseSsl -From $script:settings.MonitorSmtpFrom -To $To -Subject $Subject -Body $Body -User $script:settings.MonitorSmtpUser -AccessToken $script:settings.MonitorSmtpPass -IsHtml:$isHtml
        return
    }
    $parameters = @{ SmtpServer = $script:settings.MonitorSmtpServer; Port = $script:settings.MonitorSmtpPort; UseSsl = $script:settings.MonitorSmtpUseSsl; From = $script:settings.MonitorSmtpFrom; To = $To; Subject = $Subject; Body = $Body; BodyAsHtml = $isHtml }
    if ($script:settings.MonitorSmtpUser) {
        $parameters.Credential = New-Object System.Management.Automation.PSCredential($script:settings.MonitorSmtpUser, ($script:settings.MonitorSmtpPass | ConvertTo-SecureString -AsPlainText -Force))
    }
    Send-MailMessage @parameters -ErrorAction Stop
}

# ------------------------------------------------------------------------------------------------
# Scheduled task: runs the background monitors at system start-up under a chosen account, also while nobody is
# signed in. Registering a start-up task needs an elevated (Run as administrator) API Tester.
# ------------------------------------------------------------------------------------------------
$script:MonitorTaskName = 'API Tester Monitors'

function Get-MonitorScheduledTask {
    try { return (Get-ScheduledTask -TaskName $script:MonitorTaskName -ErrorAction Stop) } catch { return $null }
}

function Install-MonitorScheduledTask {
    param([Parameter(Mandatory = $true)][string]$UserName, [string]$Password)
    $hostPath = (Get-Process -Id $PID).Path
    $action = New-ScheduledTaskAction -Execute $hostPath -Argument "-NoProfile -NonInteractive -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`" -RunMonitors" -WorkingDirectory (Split-Path $PSCommandPath)
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $arguments = @{ TaskName = $script:MonitorTaskName; Action = $action; Trigger = $trigger; Settings = $taskSettings; Description = 'Runs the API Tester monitors in the background, also while nobody is signed in.'; Force = $true }
    if ($UserName -match '^(?i)(NT AUTHORITY\\)?(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') { $arguments.User = $UserName; $arguments.RunLevel = 'Highest' }
    else { $arguments.User = $UserName; $arguments.Password = $Password; $arguments.RunLevel = 'Limited' }
    Register-ScheduledTask @arguments | Out-Null
    Start-ScheduledTask -TaskName $script:MonitorTaskName
}

function Uninstall-MonitorScheduledTask {
    try { Stop-ScheduledTask -TaskName $script:MonitorTaskName -ErrorAction SilentlyContinue } catch { }
    Unregister-ScheduledTask -TaskName $script:MonitorTaskName -Confirm:$false -ErrorAction Stop
}

function Show-MonitorScheduledTaskDialog {
    param($Owner)
    $existing = Get-MonitorScheduledTask
    $body = @'
  <StackPanel Margin="22,18,22,18">
    <TextBlock Text="Run monitors as a scheduled task" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <TextBlock Margin="0,4,0,12" TextWrapping="Wrap" Foreground="{StaticResource Muted}" Text="The monitors start when Windows starts and keep running while nobody is signed in. Use an account that can read the API Tester folder. Installing needs API Tester to be run as administrator."/>
    <TextBlock x:Name="TaskStateText" Margin="0,0,0,10" FontWeight="SemiBold"/>
    <TextBlock Style="{StaticResource SectionLabel}" Text="ACCOUNT (DOMAIN\USER, OR SYSTEM)"/>
    <TextBox x:Name="TaskUserBox" Height="28" Margin="0,4,0,10" VerticalContentAlignment="Center"/>
    <TextBlock Style="{StaticResource SectionLabel}" Text="PASSWORD (NOT NEEDED FOR SYSTEM)"/>
    <PasswordBox x:Name="TaskPasswordBox" Height="28" Margin="0,4,0,10" VerticalContentAlignment="Center"/>
    <TextBlock x:Name="TaskMessageText" TextWrapping="Wrap" Margin="0,0,0,10"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="TaskRemoveButton" Width="120" Margin="0,0,8,0" Content="Remove task"/>
      <Button x:Name="TaskInstallButton" Style="{StaticResource PrimaryButton}" Width="140" Margin="0,0,8,0" Content="Install and start"/>
      <Button x:Name="TaskCloseButton" IsCancel="True" Width="90" Content="Close"/>
    </StackPanel>
  </StackPanel>
'@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'TaskStateText', 'TaskUserBox', 'TaskPasswordBox', 'TaskMessageText', 'TaskRemoveButton', 'TaskInstallButton', 'TaskCloseButton' -Title 'Scheduled task' -Width 560
    $window = $dialog.Window; $controls = $dialog.Controls
    $controls['TaskUserBox'].Text = "$env:USERDOMAIN\$env:USERNAME"
    $refreshState = {
        $task = Get-MonitorScheduledTask
        $controls['TaskStateText'].Text = if ($task) { "Installed - state: $($task.State) - runs as $($task.Principal.UserId)" } else { 'Not installed.' }
        $controls['TaskRemoveButton'].IsEnabled = [bool]$task
    }
    & $refreshState
    $controls['TaskInstallButton'].Add_Click({
        try {
            Save-Monitors
            Install-MonitorScheduledTask -UserName $controls['TaskUserBox'].Text.Trim() -Password $controls['TaskPasswordBox'].Password
            $controls['TaskMessageText'].Text = 'Installed and started. The monitors now run in the background at every start-up.'
            $controls['TaskMessageText'].Foreground = [System.Windows.Media.Brushes]::SeaGreen
        } catch {
            $controls['TaskMessageText'].Text = "Could not install the task: $($_.Exception.Message)`nRun API Tester as administrator and check the account and password."
            $controls['TaskMessageText'].Foreground = [System.Windows.Media.Brushes]::Firebrick
        }
        & $refreshState
    })
    $controls['TaskRemoveButton'].Add_Click({
        try { Uninstall-MonitorScheduledTask; $controls['TaskMessageText'].Text = 'The scheduled task was removed.'; $controls['TaskMessageText'].Foreground = [System.Windows.Media.Brushes]::SeaGreen }
        catch { $controls['TaskMessageText'].Text = "Could not remove the task: $($_.Exception.Message)"; $controls['TaskMessageText'].Foreground = [System.Windows.Media.Brushes]::Firebrick }
        & $refreshState
    })
    [void](Show-WpfDialog -Window $window -OwnerForm $Owner)
}

# ------------------------------------------------------------------------------------------------
# Monitor manager
# ------------------------------------------------------------------------------------------------

function Show-MonitorManagerWindow {
    $body = @'
  <Grid Margin="18,16,18,16">
    <Grid.Resources>
      <Style x:Key="BarButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
        <Setter Property="Height" Value="34"/><Setter Property="MinWidth" Value="108"/><Setter Property="Padding" Value="14,0"/><Setter Property="Margin" Value="0,0,8,8"/>
      </Style>
      <Style x:Key="BarPrimaryButton" TargetType="Button" BasedOn="{StaticResource PrimaryButton}">
        <Setter Property="Height" Value="34"/><Setter Property="MinWidth" Value="108"/><Setter Property="Padding" Value="14,0"/><Setter Property="Margin" Value="0,0,8,8"/>
      </Style>
    </Grid.Resources>
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="API monitors" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}" Margin="0,0,0,10"/>
    <Border Grid.Row="1" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="14,10,6,2" Margin="0,0,0,12">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <TextBlock x:Name="ServiceStatusText" VerticalAlignment="Center" TextWrapping="Wrap" Margin="0,0,16,8"/>
        <WrapPanel Grid.Column="1" VerticalAlignment="Center">
          <CheckBox x:Name="AutoStartBox" Content="Start when I sign in to Windows" VerticalAlignment="Center" Margin="0,0,14,8" ToolTip="Start the background monitors automatically after you sign in"/>
          <Button x:Name="StartServiceButton" Style="{StaticResource BarPrimaryButton}" Content="Run in background"/>
          <Button x:Name="StopServiceButton" Style="{StaticResource BarButton}" Content="Stop background"/>
          <Button x:Name="ScheduledTaskButton" Style="{StaticResource BarButton}" Content="Scheduled task..."/>
        </WrapPanel>
      </Grid>
    </Border>
    <DataGrid x:Name="MonitorGrid" Grid.Row="2" AutoGenerateColumns="False" IsReadOnly="True" HeadersVisibility="Column" SelectionMode="Single" GridLinesVisibility="Horizontal" Background="Transparent" RowBackground="Transparent">
      <DataGrid.Columns>
        <DataGridTextColumn Header="Name" Binding="{Binding C1}" Width="180"/><DataGridTextColumn Header="URL" Binding="{Binding C2}" Width="*"/>
        <DataGridTextColumn Header="Interval (s)" Binding="{Binding C3}" Width="90"/><DataGridTextColumn Header="Status" Binding="{Binding C4}" Width="90"/>
        <DataGridTextColumn Header="Last run / result" Binding="{Binding C5}" Width="300"/>
      </DataGrid.Columns>
    </DataGrid>
    <WrapPanel Grid.Row="3" Margin="0,12,0,0">
      <StackPanel Orientation="Horizontal" Margin="0,0,24,0">
        <Button x:Name="AddMonitorButton" Style="{StaticResource BarPrimaryButton}" Content="Add monitor..."/>
        <Button x:Name="EditMonitorButton" Style="{StaticResource BarButton}" Content="Edit"/>
        <Button x:Name="ToggleMonitorButton" Style="{StaticResource BarButton}" Content="Start / Stop"/>
        <Button x:Name="DeleteMonitorButton" Style="{StaticResource BarButton}" Content="Delete"/>
      </StackPanel>
      <StackPanel Orientation="Horizontal" Margin="0,0,24,0">
        <Button x:Name="BrowserButton" Style="{StaticResource BarButton}" Content="Open in browser"/>
        <Button x:Name="VisualizeButton" Style="{StaticResource BarButton}" Content="Visualize"/>
      </StackPanel>
      <StackPanel Orientation="Horizontal">
        <Button x:Name="OpenLogButton" Style="{StaticResource BarButton}" Content="Open log"/>
        <Button x:Name="ClearLogButton" Style="{StaticResource BarButton}" Content="Clear log"/>
        <Button x:Name="ArchiveLogButton" Style="{StaticResource BarButton}" Content="Archive log"/>
        <Button x:Name="EmailConfigButton" Style="{StaticResource BarButton}" Content="Email settings"/>
      </StackPanel>
    </WrapPanel>
  </Grid>
'@
    $names = 'AutoStartBox', 'StartServiceButton', 'StopServiceButton', 'ScheduledTaskButton', 'ServiceStatusText', 'MonitorGrid', 'BrowserButton', 'VisualizeButton', 'OpenLogButton', 'AddMonitorButton', 'EditMonitorButton', 'ToggleMonitorButton', 'DeleteMonitorButton', 'EmailConfigButton', 'ClearLogButton', 'ArchiveLogButton'
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title 'API monitor manager' -Width 1180 -Height 600
    $window = $dialog.Window; $controls = $dialog.Controls

    $refresh = {
        $serviceRunning = Test-MonitorServiceRunning
        $serviceStatus = if ($serviceRunning) { Get-MonitorServiceStatus } else { $null }
        $controls['ServiceStatusText'].Text = if ($serviceRunning) { 'Running in the background service (tray icon). Monitors keep running after you close API Tester; changes here are picked up within a second.' } else { 'Monitors run while API Tester is open. Use "Run in background" to keep them running after you close it.' }
        if ($serviceRunning) { $controls['ServiceStatusText'].Foreground = ConvertTo-WpfBrush (ConvertTo-ThemeColor '#15803D') } else { $controls['ServiceStatusText'].SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Muted') }
        $controls['StartServiceButton'].IsEnabled = -not $serviceRunning
        $controls['StopServiceButton'].IsEnabled = $serviceRunning
        $selectedId = if ($controls['MonitorGrid'].SelectedItem) { $controls['MonitorGrid'].SelectedItem.Item.Id } else { $null }
        $rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[SimpleRow]'
        foreach ($monitor in @($script:monitors | Where-Object { $_ })) {
            $row = New-Object SimpleRow
            $row.C1 = [string]$monitor.Name; $row.C2 = [string]$monitor.Request.Url; $row.C3 = [string]$monitor.IntervalSeconds; $row.C4 = [string]$monitor.Status
            $lastRun = $monitor.LastRun; $lastResult = $script:monitorLastResult[[string]$monitor.Id]
            if ($serviceStatus -and $serviceStatus.Monitors -and $serviceStatus.Monitors.ContainsKey([string]$monitor.Id)) {
                $entry = $serviceStatus.Monitors[[string]$monitor.Id]
                if ($entry.LastRun) { $lastRun = $entry.LastRun }
                $lastResult = $entry.LastResult
            }
            $row.C5 = if ($lastRun) { ([datetime]$lastRun).ToString() + $(if ($lastResult) { "  |  $lastResult" } else { '' }) } else { 'Never' }
            $row.Item = $monitor
            $rows.Add($row)
        }
        $controls['MonitorGrid'].ItemsSource = $rows
        if ($selectedId) { $match = $rows | Where-Object { $_.Item.Id -eq $selectedId } | Select-Object -First 1; if ($match) { $controls['MonitorGrid'].SelectedItem = $match } }
    }
    $selected = { if ($controls['MonitorGrid'].SelectedItem) { return $controls['MonitorGrid'].SelectedItem.Item } else { [void][System.Windows.MessageBox]::Show($window, 'Please select a monitor first.', 'Selection required', 'OK', 'Warning'); return $null } }
    & $refresh

    $liveTimer = New-Object System.Windows.Threading.DispatcherTimer
    $liveTimer.Interval = [TimeSpan]::FromSeconds(2)
    $liveTimer.Add_Tick({ & $refresh })
    $liveTimer.Start()
    $window.Add_Closing({ $liveTimer.Stop() })

    $controls['AddMonitorButton'].Add_Click({
        $newMonitor = @{
            Id = [Guid]::NewGuid().ToString(); Name = 'New Monitor'; Status = 'Stopped'; IntervalSeconds = 60
            Request = @{ Method = 'GET'; Url = 'http://'; Headers = ''; Body = ''; BodyType = 'application/json'; RequestTimeoutSeconds = 30; Authentication = @{ Type = 'No Auth' } }
            Alerts = @{ OnFailure = $true; OnSlow = $false; ThresholdMs = 1000; SendEmail = $false; EmailTo = '' }; AnalyticsUrl = ''; LastRun = $null
        }
        if (Show-MonitorEditorDialog -Monitor $newMonitor -Owner $window) { $script:monitors = @($script:monitors) + $newMonitor; Save-Monitors; & $refresh }
    })
    $controls['EditMonitorButton'].Add_Click({
        $monitor = & $selected
        if (-not $monitor) { return }
        $copy = $monitor | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        if (Show-MonitorEditorDialog -Monitor $copy -Owner $window) {
            for ($index = 0; $index -lt @($script:monitors).Count; $index++) { if ($script:monitors[$index].Id -eq $monitor.Id) { $script:monitors[$index] = $copy; break } }
            Save-Monitors; & $refresh
        }
    })
    $controls['ToggleMonitorButton'].Add_Click({
        $monitor = & $selected
        if (-not $monitor) { return }
        if ($monitor.Status -eq 'Running') { Set-ObjectProperty -Object $monitor -Name 'Status' -Value 'Stopped'; if ($script:monitorRuns.ContainsKey($monitor.Id)) { try { $script:monitorRuns[$monitor.Id].State.Cancellation.Cancel() } catch { }; $script:monitorRuns.Remove($monitor.Id) } }
        else { Set-ObjectProperty -Object $monitor -Name 'Status' -Value 'Running'; Set-ObjectProperty -Object $monitor -Name 'LastRun' -Value $null }
        Save-Monitors; & $refresh
    })
    $controls['DeleteMonitorButton'].Add_Click({
        $monitor = & $selected
        if (-not $monitor) { return }
        if ([System.Windows.MessageBox]::Show($window, "Delete monitor '$($monitor.Name)'?", 'Confirm delete', 'YesNo', 'Warning') -ne 'Yes') { return }
        if ($script:monitorRuns.ContainsKey($monitor.Id)) { try { $script:monitorRuns[$monitor.Id].State.Cancellation.Cancel() } catch { }; $script:monitorRuns.Remove($monitor.Id) }
        $script:monitors = @($script:monitors | Where-Object { $_.Id -ne $monitor.Id })
        Save-Monitors; & $refresh
    })
    $controls['OpenLogButton'].Add_Click({
        if (Test-Path $monitorLogFilePath) { try { Start-Process $monitorLogFilePath } catch { [void][System.Windows.MessageBox]::Show($window, "Failed to open the log: $($_.Exception.Message)", 'Error', 'OK', 'Error') } }
        else { [void][System.Windows.MessageBox]::Show($window, 'The log file does not exist yet.', 'Info', 'OK', 'Information') }
    })
    $controls['AutoStartBox'].IsChecked = Test-MonitorAutoStart
    $controls['AutoStartBox'].Add_Click({
        try { Set-MonitorAutoStart -Enabled ([bool]$controls['AutoStartBox'].IsChecked) }
        catch { [void][System.Windows.MessageBox]::Show($window, "Could not change the sign-in setting: $($_.Exception.Message)", 'Background monitors', 'OK', 'Error'); $controls['AutoStartBox'].IsChecked = Test-MonitorAutoStart }
    })
    $controls['StartServiceButton'].Add_Click({
        Save-Monitors
        [void](Start-MonitorService)
        & $refresh
    })
    $controls['StopServiceButton'].Add_Click({
        Stop-MonitorService
        Start-Sleep -Milliseconds 400
        & $refresh
    })
    $controls['BrowserButton'].Add_Click({ Open-MonitorDashboardInBrowser })
    $controls['ScheduledTaskButton'].Add_Click({ Show-MonitorScheduledTaskDialog -Owner $window; & $refresh })
    $controls['VisualizeButton'].Add_Click({ Show-MonitorChartDialog -Owner $window })
    $controls['EmailConfigButton'].Add_Click({ Show-MonitorEmailDialog -Owner $window })
    $controls['ClearLogButton'].Add_Click({
        if ([System.Windows.MessageBox]::Show($window, 'Clear the monitor log file?', 'Confirm', 'YesNo', 'Warning') -eq 'Yes') { Clear-Content $monitorLogFilePath -ErrorAction SilentlyContinue }
    })
    $controls['ArchiveLogButton'].Add_Click({
        if (-not (Test-Path $monitorLogFilePath)) { return }
        $archiveName = "$monitorLogFilePath.$((Get-Date).ToString('yyyyMMdd-HHmmss')).csv"
        Rename-Item $monitorLogFilePath $archiveName
        [void][System.Windows.MessageBox]::Show($window, "Log archived to:`n$archiveName", 'Archive log', 'OK', 'Information')
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}

# ------------------------------------------------------------------------------------------------
# Monitor editor. Returns $true when saved; $Monitor is modified in place.
# ------------------------------------------------------------------------------------------------

function Show-MonitorEditorDialog {
    param($Monitor, $Owner)
    $body = @'
  <Grid Margin="20,16,20,16">
    <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="0,0,10,0">
      <TextBlock Text="Edit monitor" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}" Margin="0,0,0,10"/>
      <WrapPanel>
        <StackPanel Margin="0,0,16,8"><TextBlock Style="{StaticResource SectionLabel}" Text="NAME"/><TextBox x:Name="MeNameBox" Width="320" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
        <StackPanel Margin="0,0,16,8"><TextBlock Style="{StaticResource SectionLabel}" Text="INTERVAL (SECONDS, 10-86400)"/><TextBox x:Name="MeIntervalBox" Width="120" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
      </WrapPanel>
      <TabControl Height="330" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}">
        <TabItem Header="General"><StackPanel Margin="12">
          <WrapPanel>
            <StackPanel Margin="0,0,16,8"><TextBlock Style="{StaticResource SectionLabel}" Text="METHOD"/><ComboBox x:Name="MeMethodBox" Width="120" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
            <StackPanel Margin="0,0,16,8"><TextBlock Style="{StaticResource SectionLabel}" Text="TIMEOUT (SECONDS, 1-300)"/><TextBox x:Name="MeTimeoutBox" Width="120" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
          </WrapPanel>
          <TextBlock Style="{StaticResource SectionLabel}" Text="URL"/><TextBox x:Name="MeUrlBox" Height="28" Margin="0,4,0,10" VerticalContentAlignment="Center"/>
          <Button x:Name="MeImportButton" HorizontalAlignment="Left" Padding="14,5" Content="Import from the current request"/>
        </StackPanel></TabItem>
        <TabItem Header="Headers"><TextBox x:Name="MeHeadersBox" Margin="10" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/></TabItem>
        <TabItem Header="Body"><Grid Margin="10"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <ComboBox x:Name="MeBodyTypeBox" Width="260" Height="28" HorizontalAlignment="Left" Margin="0,0,0,8" VerticalContentAlignment="Center"/>
          <TextBox x:Name="MeBodyBox" Grid.Row="1" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/></Grid></TabItem>
        <TabItem Header="Auth"><StackPanel Margin="12">
          <ComboBox x:Name="MeAuthTypeBox" Width="220" Height="28" HorizontalAlignment="Left" VerticalContentAlignment="Center" Margin="0,0,0,8"/>
          <WrapPanel>
            <StackPanel x:Name="MeAuth1Panel" Margin="0,0,12,8"><TextBlock x:Name="MeAuthLabel1" Style="{StaticResource SectionLabel}"/><TextBox x:Name="MeAuth1Box" Width="260" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
            <StackPanel x:Name="MeAuth2Panel" Margin="0,0,12,8"><TextBlock x:Name="MeAuthLabel2" Style="{StaticResource SectionLabel}"/><TextBox x:Name="MeAuth2Box" Width="260" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
            <StackPanel x:Name="MeAuth3Panel" Margin="0,0,12,8"><TextBlock x:Name="MeAuthLabel3" Style="{StaticResource SectionLabel}"/><ComboBox x:Name="MeAuthAddToBox" Width="170" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
          </WrapPanel>
          <TextBlock x:Name="MeAuthNote" Foreground="{StaticResource Muted}" TextWrapping="Wrap"/>
        </StackPanel></TabItem>
      </TabControl>
      <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="14,10" Margin="0,12,0,0"><StackPanel>
        <TextBlock Style="{StaticResource SectionLabel}" Text="ALERTING"/>
        <CheckBox x:Name="MeAlertFailBox" Content="Alert on HTTP failure (status is not 2xx)" Margin="0,8,0,3"/>
        <WrapPanel><CheckBox x:Name="MeAlertSlowBox" Content="Alert on slow response, threshold (ms):" VerticalAlignment="Center" Margin="0,3,8,3"/><TextBox x:Name="MeThresholdBox" Width="90" Height="26" VerticalContentAlignment="Center"/></WrapPanel>
        <CheckBox x:Name="MeStateChangeBox" Content="Only alert when the monitor goes down or recovers (not on every failed check)" Margin="0,3"/>
        <WrapPanel Margin="0,3">
          <TextBlock Text="Retry before alerting:" VerticalAlignment="Center" Margin="0,0,6,0"/><TextBox x:Name="MeRetryBox" Width="50" Height="26" VerticalContentAlignment="Center" ToolTip="Failed checks are retried this many times (5 seconds apart) before they count"/>
          <TextBlock Text="Quiet hours from" VerticalAlignment="Center" Margin="16,0,6,0"/><TextBox x:Name="MeQuietStartBox" Width="60" Height="26" VerticalContentAlignment="Center" ToolTip="HH:mm, e.g. 22:00 - alerts are suppressed (still logged)"/>
          <TextBlock Text="to" VerticalAlignment="Center" Margin="6,0,6,0"/><TextBox x:Name="MeQuietEndBox" Width="60" Height="26" VerticalContentAlignment="Center" ToolTip="HH:mm, e.g. 07:00"/>
        </WrapPanel>
        <WrapPanel Margin="0,3">
          <TextBlock Text="Webhook:" VerticalAlignment="Center" Margin="0,0,6,0"/><ComboBox x:Name="MeWebhookTypeBox" Width="110" Height="26" VerticalContentAlignment="Center" Margin="0,0,6,0"/>
          <TextBox x:Name="MeAlertWebhookBox" Width="420" Height="26" VerticalContentAlignment="Center" ToolTip="Microsoft Teams incoming webhook, Slack incoming webhook, or any URL that accepts JSON"/>
        </WrapPanel>
        <WrapPanel Margin="0,3"><CheckBox x:Name="MeAlertEmailBox" Content="Send email alert to:" VerticalAlignment="Center" Margin="0,3,8,3"/><TextBox x:Name="MeEmailToBox" Width="320" Height="26" VerticalContentAlignment="Center"/>
          <Button x:Name="MeSmtpButton" Style="{StaticResource SmallButton}" Margin="10,0,0,0" Content="SMTP settings..."/></WrapPanel>
      </StackPanel></Border>
      <TextBlock Style="{StaticResource SectionLabel}" Text="ANALYTICS WEBHOOK URL (OPTIONAL)" Margin="0,12,0,0"/><TextBox x:Name="MeWebhookBox" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/>
    </StackPanel></ScrollViewer>
    <DockPanel Grid.Row="1" Margin="0,12,0,0">
      <TextBlock x:Name="MeStatusText" DockPanel.Dock="Left" VerticalAlignment="Center" Foreground="#B91C1C" TextWrapping="Wrap" MaxWidth="460"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="MeTestButton" Width="130" Margin="0,0,8,0" Content="Test request"/>
        <Button x:Name="MeSaveButton" Style="{StaticResource PrimaryButton}" Width="100" Content="Save"/>
        <Button x:Name="MeCancelButton" IsCancel="True" Width="90" Margin="8,0,0,0" Content="Cancel"/>
      </StackPanel>
    </DockPanel>
  </Grid>
'@
    $names = 'MeNameBox', 'MeIntervalBox', 'MeMethodBox', 'MeTimeoutBox', 'MeUrlBox', 'MeImportButton', 'MeHeadersBox', 'MeBodyTypeBox', 'MeBodyBox', 'MeAuthTypeBox', 'MeAuth1Panel', 'MeAuthLabel1', 'MeAuth1Box',
        'MeAuth2Panel', 'MeAuthLabel2', 'MeAuth2Box', 'MeAuth3Panel', 'MeAuthLabel3', 'MeAuthAddToBox', 'MeAuthNote', 'MeAlertFailBox', 'MeAlertSlowBox', 'MeThresholdBox', 'MeStateChangeBox', 'MeRetryBox', 'MeQuietStartBox', 'MeQuietEndBox', 'MeWebhookTypeBox', 'MeAlertWebhookBox', 'MeAlertEmailBox', 'MeEmailToBox',
        'MeSmtpButton', 'MeWebhookBox', 'MeStatusText', 'MeTestButton', 'MeSaveButton', 'MeCancelButton'
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title 'Edit monitor' -Width 900 -Height 960
    $window = $dialog.Window; $controls = $dialog.Controls
    foreach ($method in @('GET', 'POST', 'PUT', 'DELETE', 'PATCH')) { [void]$controls['MeMethodBox'].Items.Add($method) }
    foreach ($type in @('multipart/form-data', 'application/json', 'application/xml', 'text/plain', 'application/x-www-form-urlencoded', 'GraphQL')) { [void]$controls['MeBodyTypeBox'].Items.Add($type) }
    foreach ($type in @('No Auth', 'API Key', 'Bearer Token', 'Basic Auth', 'Auth2', 'Client Certificate')) { [void]$controls['MeAuthTypeBox'].Items.Add($type) }
    foreach ($location in @('Header', 'Query Parameter')) { [void]$controls['MeAuthAddToBox'].Items.Add($location) }

    $request = $Monitor.Request; $alerts = $Monitor.Alerts
    $script:monitorAuthExtras = @{}
    $updateAuthFields = {
        $type = [string]$controls['MeAuthTypeBox'].SelectedItem
        $labels = switch ($type) { 'API Key' { @('KEY NAME', 'VALUE', 'ADD TO') } 'Bearer Token' { @('TOKEN', '', '') } 'Basic Auth' { @('USERNAME', 'PASSWORD', '') } default { @('', '', '') } }
        $controls['MeAuthLabel1'].Text = $labels[0]; $controls['MeAuthLabel2'].Text = $labels[1]; $controls['MeAuthLabel3'].Text = $labels[2]
        $controls['MeAuth1Panel'].Visibility = if ($labels[0]) { 'Visible' } else { 'Collapsed' }
        $controls['MeAuth2Panel'].Visibility = if ($labels[1]) { 'Visible' } else { 'Collapsed' }
        $controls['MeAuth3Panel'].Visibility = if ($labels[2]) { 'Visible' } else { 'Collapsed' }
        $controls['MeAuthNote'].Text = if ($type -in @('Auth2', 'Client Certificate')) { "$type settings are kept as they are. Use 'Import from the current request' to copy them from the request editor." } else { '' }
    }
    $loadAuth = {
        param($Auth)
        $script:monitorAuthExtras = @{}
        if ($Auth -is [System.Collections.IDictionary]) { foreach ($key in $Auth.Keys) { $script:monitorAuthExtras[$key] = $Auth[$key] } } elseif ($Auth) { foreach ($property in $Auth.PSObject.Properties) { $script:monitorAuthExtras[$property.Name] = $property.Value } }
        $type = [string](Get-ObjectProperty $Auth 'Type' 'No Auth')
        if (-not $controls['MeAuthTypeBox'].Items.Contains($type)) { $type = 'No Auth' }
        $controls['MeAuthTypeBox'].SelectedItem = $type
        & $updateAuthFields
        switch ($type) {
            'API Key'      { $controls['MeAuth1Box'].Text = [string]$script:monitorAuthExtras['Key']; $controls['MeAuth2Box'].Text = [string]$script:monitorAuthExtras['Value']; $controls['MeAuthAddToBox'].SelectedItem = if ($script:monitorAuthExtras['AddTo']) { [string]$script:monitorAuthExtras['AddTo'] } else { 'Header' } }
            'Bearer Token' { $controls['MeAuth1Box'].Text = [string]$script:monitorAuthExtras['Token']; $controls['MeAuth2Box'].Text = '' }
            'Basic Auth'   { $controls['MeAuth1Box'].Text = [string]$script:monitorAuthExtras['Username']; $controls['MeAuth2Box'].Text = [string]$script:monitorAuthExtras['Password'] }
            default        { $controls['MeAuth1Box'].Text = ''; $controls['MeAuth2Box'].Text = '' }
        }
    }
    $readAuth = {
        $type = [string]$controls['MeAuthTypeBox'].SelectedItem
        $auth = @{ Type = $type }
        switch ($type) {
            'API Key'      { $auth.Key = $controls['MeAuth1Box'].Text; $auth.Value = $controls['MeAuth2Box'].Text; $auth.AddTo = [string]$controls['MeAuthAddToBox'].SelectedItem }
            'Bearer Token' { $auth.Token = $controls['MeAuth1Box'].Text }
            'Basic Auth'   { $auth.Username = $controls['MeAuth1Box'].Text; $auth.Password = $controls['MeAuth2Box'].Text }
            { $_ -in @('Auth2', 'Client Certificate') } { foreach ($key in $script:monitorAuthExtras.Keys) { $auth[$key] = $script:monitorAuthExtras[$key] }; $auth.Type = $type }
        }
        return $auth
    }
    $controls['MeAuthTypeBox'].Add_SelectionChanged({ & $updateAuthFields })

    $controls['MeNameBox'].Text = [string]$Monitor.Name
    $controls['MeIntervalBox'].Text = [string]$Monitor.IntervalSeconds
    $controls['MeMethodBox'].SelectedItem = if ($request.Method -and $controls['MeMethodBox'].Items.Contains([string]$request.Method)) { [string]$request.Method } else { 'GET' }
    $controls['MeTimeoutBox'].Text = [string](Get-ObjectProperty $request 'RequestTimeoutSeconds' 30)
    $controls['MeUrlBox'].Text = [string]$request.Url
    $controls['MeHeadersBox'].Text = [string](Get-ObjectProperty $request 'Headers' '')
    $bodyType = ConvertTo-MimeBodyType -Name ([string](Get-ObjectProperty $request 'BodyType' 'application/json'))
    $controls['MeBodyTypeBox'].SelectedItem = if ($controls['MeBodyTypeBox'].Items.Contains($bodyType)) { $bodyType } else { 'application/json' }
    $controls['MeBodyBox'].Text = [string](Get-ObjectProperty $request 'Body' '')
    & $loadAuth (Get-ObjectProperty $request 'Authentication' @{ Type = 'No Auth' })
    $controls['MeAlertFailBox'].IsChecked = [bool](Get-ObjectProperty $alerts 'OnFailure' $true)
    $controls['MeAlertSlowBox'].IsChecked = [bool](Get-ObjectProperty $alerts 'OnSlow' $false)
    $controls['MeThresholdBox'].Text = [string](Get-ObjectProperty $alerts 'ThresholdMs' 1000)
    $controls['MeAlertEmailBox'].IsChecked = [bool](Get-ObjectProperty $alerts 'SendEmail' $false)
    $controls['MeEmailToBox'].Text = [string](Get-ObjectProperty $alerts 'EmailTo' '')
    $controls['MeWebhookBox'].Text = [string](Get-ObjectProperty $Monitor 'AnalyticsUrl' '')
    foreach ($type in @('Teams', 'Slack', 'Generic')) { [void]$controls['MeWebhookTypeBox'].Items.Add($type) }
    $controls['MeWebhookTypeBox'].SelectedItem = [string](Get-ObjectProperty $alerts 'WebhookType' 'Teams')
    if (-not $controls['MeWebhookTypeBox'].SelectedItem) { $controls['MeWebhookTypeBox'].SelectedIndex = 0 }
    $controls['MeAlertWebhookBox'].Text = [string](Get-ObjectProperty $alerts 'WebhookUrl' '')
    $controls['MeStateChangeBox'].IsChecked = [bool](Get-ObjectProperty $alerts 'OnStateChangeOnly' $false)
    $controls['MeRetryBox'].Text = [string][int](Get-ObjectProperty $alerts 'RetryCount' 0)
    $controls['MeQuietStartBox'].Text = [string](Get-ObjectProperty $alerts 'QuietHoursStart' '')
    $controls['MeQuietEndBox'].Text = [string](Get-ObjectProperty $alerts 'QuietHoursEnd' '')

    $controls['MeImportButton'].Add_Click({
        $state = Get-EditorState
        $controls['MeMethodBox'].SelectedItem = if ($controls['MeMethodBox'].Items.Contains($state.Method)) { $state.Method } else { 'GET' }
        $controls['MeUrlBox'].Text = $state.Url; $controls['MeHeadersBox'].Text = $state.Headers; $controls['MeBodyBox'].Text = $state.Body
        $controls['MeBodyTypeBox'].SelectedItem = $state.BodyType
        $authCopy = @{}
        foreach ($property in (Copy-RequestData $state.Authentication).PSObject.Properties) { $authCopy[$property.Name] = $property.Value }
        & $loadAuth $authCopy
        $controls['MeStatusText'].Text = ''
        [void][System.Windows.MessageBox]::Show($window, 'Request details imported from the main window.', 'Import complete', 'OK', 'Information')
    })
    $controls['MeSmtpButton'].Add_Click({ Show-MonitorEmailDialog -Owner $window })
    $controls['MeTestButton'].Add_Click({
        try {
            $testRequest = [PSCustomObject]@{ Method = [string]$controls['MeMethodBox'].SelectedItem; Url = $controls['MeUrlBox'].Text; Headers = $controls['MeHeadersBox'].Text; Body = $controls['MeBodyBox'].Text; BodyType = [string]$controls['MeBodyTypeBox'].SelectedItem; Authentication = (& $readAuth) }
            $timeout = 0; if (-not [int]::TryParse($controls['MeTimeoutBox'].Text, [ref]$timeout) -or $timeout -lt 1) { $timeout = 30 }
            $controls['MeStatusText'].Text = 'Testing...'; $controls['MeStatusText'].Foreground = [System.Windows.Media.Brushes]::DimGray; Update-UiNow
            $result = Invoke-HttpRequestSync -Request $testRequest -TimeoutSeconds $timeout
            if ($result.Success) { $controls['MeStatusText'].Text = "Success: HTTP $($result.StatusCode) in $($result.ElapsedMs) ms"; $controls['MeStatusText'].Foreground = if ($result.StatusCode -lt 400) { [System.Windows.Media.Brushes]::SeaGreen } else { [System.Windows.Media.Brushes]::DarkOrange } }
            else { $controls['MeStatusText'].Text = "Failed: $($result.ErrorMessage)"; $controls['MeStatusText'].Foreground = [System.Windows.Media.Brushes]::Firebrick }
        } catch { $controls['MeStatusText'].Text = "Failed: $($_.Exception.Message)"; $controls['MeStatusText'].Foreground = [System.Windows.Media.Brushes]::Firebrick }
    })
    $script:monitorEditorSaved = $false
    $controls['MeSaveButton'].Add_Click({
        $interval = 0; $timeout = 0; $threshold = 0
        $controls['MeStatusText'].Foreground = [System.Windows.Media.Brushes]::Firebrick
        if ([string]::IsNullOrWhiteSpace($controls['MeNameBox'].Text)) { $controls['MeStatusText'].Text = 'The monitor name cannot be empty.'; return }
        if ([string]::IsNullOrWhiteSpace($controls['MeUrlBox'].Text)) { $controls['MeStatusText'].Text = 'The request URL cannot be empty.'; return }
        if (-not [int]::TryParse($controls['MeIntervalBox'].Text, [ref]$interval) -or $interval -lt 10 -or $interval -gt 86400) { $controls['MeStatusText'].Text = 'The interval must be 10-86400 seconds.'; return }
        if (-not [int]::TryParse($controls['MeTimeoutBox'].Text, [ref]$timeout) -or $timeout -lt 1 -or $timeout -gt 300) { $controls['MeStatusText'].Text = 'The timeout must be 1-300 seconds.'; return }
        if (-not [int]::TryParse($controls['MeThresholdBox'].Text, [ref]$threshold) -or $threshold -lt 1) { $threshold = 1000 }
        Set-ObjectProperty -Object $Monitor -Name 'Name' -Value $controls['MeNameBox'].Text
        Set-ObjectProperty -Object $Monitor -Name 'IntervalSeconds' -Value $interval
        Set-ObjectProperty -Object $request -Name 'Method' -Value ([string]$controls['MeMethodBox'].SelectedItem)
        Set-ObjectProperty -Object $request -Name 'Url' -Value $controls['MeUrlBox'].Text
        Set-ObjectProperty -Object $request -Name 'RequestTimeoutSeconds' -Value $timeout
        Set-ObjectProperty -Object $request -Name 'Headers' -Value $controls['MeHeadersBox'].Text
        Set-ObjectProperty -Object $request -Name 'BodyType' -Value ([string]$controls['MeBodyTypeBox'].SelectedItem)
        Set-ObjectProperty -Object $request -Name 'Body' -Value $controls['MeBodyBox'].Text
        Set-ObjectProperty -Object $request -Name 'Authentication' -Value (& $readAuth)
        Set-ObjectProperty -Object $alerts -Name 'OnFailure' -Value ([bool]$controls['MeAlertFailBox'].IsChecked)
        Set-ObjectProperty -Object $alerts -Name 'OnSlow' -Value ([bool]$controls['MeAlertSlowBox'].IsChecked)
        Set-ObjectProperty -Object $alerts -Name 'ThresholdMs' -Value $threshold
        Set-ObjectProperty -Object $alerts -Name 'SendEmail' -Value ([bool]$controls['MeAlertEmailBox'].IsChecked)
        Set-ObjectProperty -Object $alerts -Name 'EmailTo' -Value $controls['MeEmailToBox'].Text
        Set-ObjectProperty -Object $Monitor -Name 'AnalyticsUrl' -Value $controls['MeWebhookBox'].Text
        $retryCount = 0; [void][int]::TryParse($controls['MeRetryBox'].Text, [ref]$retryCount)
        $quietStart = $controls['MeQuietStartBox'].Text.Trim(); $quietEnd = $controls['MeQuietEndBox'].Text.Trim(); $parsedTime = [TimeSpan]::Zero
        if (($quietStart -and -not [TimeSpan]::TryParse($quietStart, [ref]$parsedTime)) -or ($quietEnd -and -not [TimeSpan]::TryParse($quietEnd, [ref]$parsedTime))) { $controls['MeStatusText'].Text = 'Quiet hours must be HH:mm (for example 22:00).'; return }
        Set-ObjectProperty -Object $alerts -Name 'RetryCount' -Value ([Math]::Max(0, [Math]::Min(10, $retryCount)))
        Set-ObjectProperty -Object $alerts -Name 'OnStateChangeOnly' -Value ([bool]$controls['MeStateChangeBox'].IsChecked)
        Set-ObjectProperty -Object $alerts -Name 'QuietHoursStart' -Value $quietStart
        Set-ObjectProperty -Object $alerts -Name 'QuietHoursEnd' -Value $quietEnd
        Set-ObjectProperty -Object $alerts -Name 'WebhookType' -Value ([string]$controls['MeWebhookTypeBox'].SelectedItem)
        Set-ObjectProperty -Object $alerts -Name 'WebhookUrl' -Value $controls['MeAlertWebhookBox'].Text.Trim()
        $script:monitorEditorSaved = $true
        $window.DialogResult = $true
    })
    [void](Show-WpfDialog -Window $window -OwnerForm $Owner)
    return $script:monitorEditorSaved
}

# ------------------------------------------------------------------------------------------------
# SMTP / email alert settings
# ------------------------------------------------------------------------------------------------

function Show-MonitorEmailDialog {
    param($Owner)
    $body = @'
  <Grid Margin="20,16,20,16">
    <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="0,0,10,0">
      <TextBlock Text="Email alert configuration" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}" Margin="0,0,0,10"/>
      <WrapPanel>
        <StackPanel Margin="0,0,16,8"><TextBlock Style="{StaticResource SectionLabel}" Text="SMTP SERVER"/><TextBox x:Name="SmtpServerBox" Width="320" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
        <StackPanel Margin="0,0,16,8"><TextBlock Style="{StaticResource SectionLabel}" Text="PORT"/><TextBox x:Name="SmtpPortBox" Width="90" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
        <StackPanel Margin="0,0,16,8"><TextBlock Style="{StaticResource SectionLabel}" Text="AUTHENTICATION"/><ComboBox x:Name="SmtpAuthBox" Width="140" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
        <CheckBox x:Name="SmtpSslBox" Content="Use SSL/TLS" VerticalAlignment="Bottom" Margin="0,0,0,12"/>
      </WrapPanel>
      <WrapPanel>
        <StackPanel Margin="0,0,16,8"><TextBlock Style="{StaticResource SectionLabel}" Text="FROM ADDRESS"/><TextBox x:Name="SmtpFromBox" Width="320" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
        <StackPanel Margin="0,0,16,8"><TextBlock Style="{StaticResource SectionLabel}" Text="USERNAME"/><TextBox x:Name="SmtpUserBox" Width="300" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
      </WrapPanel>
      <StackPanel Margin="0,0,0,8"><TextBlock x:Name="SmtpPassLabel" Style="{StaticResource SectionLabel}" Text="PASSWORD"/><PasswordBox x:Name="SmtpPassBox" Width="640" HorizontalAlignment="Left" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
      <Border x:Name="OAuthSection" Visibility="Collapsed" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="14,10" Margin="0,0,0,8"><StackPanel>
        <TextBlock Style="{StaticResource SectionLabel}" Text="OAUTH 2.0"/>
        <WrapPanel Margin="0,6,0,0">
          <StackPanel Margin="0,0,16,8"><TextBlock Text="Client ID"/><TextBox x:Name="SmtpClientIdBox" Width="300" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
          <StackPanel Margin="0,0,16,8"><TextBlock Text="Client secret"/><PasswordBox x:Name="SmtpClientSecretBox" Width="300" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
          <StackPanel Margin="0,0,16,8"><TextBlock Text="Token endpoint"/><TextBox x:Name="SmtpTokenEndpointBox" Width="300" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
          <StackPanel Margin="0,0,16,8"><TextBlock Text="Refresh token"/><PasswordBox x:Name="SmtpRefreshTokenBox" Width="300" Height="28" Margin="0,4,0,0" VerticalContentAlignment="Center"/></StackPanel>
        </WrapPanel>
        <Button x:Name="SmtpRefreshButton" HorizontalAlignment="Left" Padding="14,5" Content="Refresh access token now"/>
      </StackPanel></Border>
      <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="14,10"><StackPanel>
        <TextBlock Style="{StaticResource SectionLabel}" Text="ALERT EMAIL TEMPLATE"/>
        <TextBlock Text="Subject" Margin="0,8,0,0"/><TextBox x:Name="AlertSubjectBox" Height="28" Margin="0,4,0,8" VerticalContentAlignment="Center"/>
        <TextBlock Text="Body"/><TextBox x:Name="AlertBodyBox" Height="120" Margin="0,4,0,8" AcceptsReturn="True" VerticalScrollBarVisibility="Auto"/>
        <CheckBox x:Name="ForceHtmlBox" Content="Force HTML email body"/>
        <TextBlock Margin="0,8,0,0" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Text="Placeholders: {MonitorName} {Status} {StatusCode} {Url} {TimeMs} {Message} {Timestamp}"/>
      </StackPanel></Border>
    </StackPanel></ScrollViewer>
    <DockPanel Grid.Row="1" Margin="0,12,0,0">
      <TextBlock x:Name="SmtpStatusText" VerticalAlignment="Center" TextWrapping="Wrap" MaxWidth="420"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="SmtpTestButton" Width="150" Margin="0,0,8,0" Content="Test connection"/>
        <Button x:Name="SmtpSaveButton" Style="{StaticResource PrimaryButton}" Width="100" Content="Save"/>
        <Button x:Name="SmtpCancelButton" IsCancel="True" Width="90" Margin="8,0,0,0" Content="Close"/>
      </StackPanel>
    </DockPanel>
  </Grid>
'@
    $names = 'SmtpServerBox', 'SmtpPortBox', 'SmtpAuthBox', 'SmtpSslBox', 'SmtpFromBox', 'SmtpUserBox', 'SmtpPassLabel', 'SmtpPassBox', 'OAuthSection', 'SmtpClientIdBox', 'SmtpClientSecretBox', 'SmtpTokenEndpointBox',
        'SmtpRefreshTokenBox', 'SmtpRefreshButton', 'AlertSubjectBox', 'AlertBodyBox', 'ForceHtmlBox', 'SmtpStatusText', 'SmtpTestButton', 'SmtpSaveButton', 'SmtpCancelButton'
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title 'Email alert configuration' -Width 760 -Height 840
    $window = $dialog.Window; $controls = $dialog.Controls
    foreach ($method in @('Basic', 'OAuth2')) { [void]$controls['SmtpAuthBox'].Items.Add($method) }
    $currentSettings = $script:settings
    $controls['SmtpServerBox'].Text = [string]$currentSettings.MonitorSmtpServer; $controls['SmtpPortBox'].Text = [string]$currentSettings.MonitorSmtpPort
    $controls['SmtpAuthBox'].SelectedItem = if ($currentSettings.MonitorSmtpAuthMethod) { [string]$currentSettings.MonitorSmtpAuthMethod } else { 'Basic' }
    $controls['SmtpSslBox'].IsChecked = [bool]$currentSettings.MonitorSmtpUseSsl; $controls['SmtpFromBox'].Text = [string]$currentSettings.MonitorSmtpFrom; $controls['SmtpUserBox'].Text = [string]$currentSettings.MonitorSmtpUser
    $controls['SmtpPassBox'].Password = [string]$currentSettings.MonitorSmtpPass
    $controls['SmtpClientIdBox'].Text = [string]$currentSettings.MonitorSmtpClientId; $controls['SmtpClientSecretBox'].Password = [string]$currentSettings.MonitorSmtpClientSecret
    $controls['SmtpTokenEndpointBox'].Text = [string]$currentSettings.MonitorSmtpTokenEndpoint; $controls['SmtpRefreshTokenBox'].Password = [string]$currentSettings.MonitorSmtpRefreshToken
    $controls['AlertSubjectBox'].Text = [string]$currentSettings.MonitorAlertSubjectTemplate; $controls['AlertBodyBox'].Text = [string]$currentSettings.MonitorAlertBodyTemplate; $controls['ForceHtmlBox'].IsChecked = [bool]$currentSettings.MonitorAlertBodyForceHtml

    $updateAuth = {
        $isOAuth = ([string]$controls['SmtpAuthBox'].SelectedItem -eq 'OAuth2')
        $controls['SmtpPassLabel'].Text = if ($isOAuth) { 'ACCESS TOKEN' } else { 'PASSWORD' }
        $controls['OAuthSection'].Visibility = if ($isOAuth) { 'Visible' } else { 'Collapsed' }
    }
    $controls['SmtpAuthBox'].Add_SelectionChanged($updateAuth)
    & $updateAuth

    $applyToSettings = {
        $port = 0; [void][int]::TryParse($controls['SmtpPortBox'].Text, [ref]$port)
        $script:settings.MonitorSmtpServer = $controls['SmtpServerBox'].Text; $script:settings.MonitorSmtpPort = $port; $script:settings.MonitorSmtpUseSsl = [bool]$controls['SmtpSslBox'].IsChecked
        $script:settings.MonitorSmtpFrom = $controls['SmtpFromBox'].Text; $script:settings.MonitorSmtpUser = $controls['SmtpUserBox'].Text; $script:settings.MonitorSmtpPass = $controls['SmtpPassBox'].Password
        $script:settings.MonitorSmtpAuthMethod = [string]$controls['SmtpAuthBox'].SelectedItem
        $script:settings.MonitorSmtpClientId = $controls['SmtpClientIdBox'].Text; $script:settings.MonitorSmtpClientSecret = $controls['SmtpClientSecretBox'].Password
        $script:settings.MonitorSmtpTokenEndpoint = $controls['SmtpTokenEndpointBox'].Text; $script:settings.MonitorSmtpRefreshToken = $controls['SmtpRefreshTokenBox'].Password
        $script:settings.MonitorAlertSubjectTemplate = $controls['AlertSubjectBox'].Text; $script:settings.MonitorAlertBodyTemplate = $controls['AlertBodyBox'].Text; $script:settings.MonitorAlertBodyForceHtml = [bool]$controls['ForceHtmlBox'].IsChecked
    }
    $controls['SmtpRefreshButton'].Add_Click({
        & $applyToSettings
        try { Update-SmtpToken; $controls['SmtpPassBox'].Password = [string]$script:settings.MonitorSmtpPass; $controls['SmtpStatusText'].Text = 'Token refreshed.'; $controls['SmtpStatusText'].Foreground = [System.Windows.Media.Brushes]::SeaGreen }
        catch { $controls['SmtpStatusText'].Text = "Failed to refresh the token: $($_.Exception.Message)"; $controls['SmtpStatusText'].Foreground = [System.Windows.Media.Brushes]::Firebrick }
    })
    $controls['SmtpSaveButton'].Add_Click({ & $applyToSettings; Save-Settings; $window.DialogResult = $true })
    $controls['SmtpTestButton'].Add_Click({
        if (-not $controls['SmtpServerBox'].Text -or -not $controls['SmtpFromBox'].Text) { $controls['SmtpStatusText'].Text = 'Enter the SMTP server and the From address.'; $controls['SmtpStatusText'].Foreground = [System.Windows.Media.Brushes]::DarkOrange; return }
        $recipient = Show-InputBox -Prompt 'Recipient for the test email:' -Title 'Test email' -DefaultText $controls['SmtpFromBox'].Text
        if (-not $recipient) { return }
        & $applyToSettings
        $controls['SmtpStatusText'].Text = 'Sending...'; $controls['SmtpStatusText'].Foreground = [System.Windows.Media.Brushes]::DimGray; Update-UiNow
        try {
            Send-MonitorEmail -To $recipient -Subject 'API Tester SMTP test' -Body "This is a test email ($($script:settings.MonitorSmtpAuthMethod))."
            $controls['SmtpStatusText'].Text = "Test email sent to $recipient."; $controls['SmtpStatusText'].Foreground = [System.Windows.Media.Brushes]::SeaGreen
        } catch { $controls['SmtpStatusText'].Text = "Failed to send: $($_.Exception.Message)"; $controls['SmtpStatusText'].Foreground = [System.Windows.Media.Brushes]::Firebrick }
    })
    [void](Show-WpfDialog -Window $window -OwnerForm $Owner)
}

# ------------------------------------------------------------------------------------------------
# Dashboard + chart window
# ------------------------------------------------------------------------------------------------

function Get-MonitorLogData {
    if (-not (Test-Path $monitorLogFilePath)) { return @() }
    try { return @(Import-Csv $monitorLogFilePath) } catch { return @() }
}

function Show-MonitoringDashboardWindow {
    $body = @'
  <Grid Margin="16,14,16,14">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
    <WrapPanel>
      <TextBlock Text="Monitor" VerticalAlignment="Center" Margin="0,0,6,0"/><ComboBox x:Name="DbMonitorBox" Width="200" Height="28" VerticalContentAlignment="Center" Margin="0,0,12,0"/>
      <TextBlock Text="From" VerticalAlignment="Center" Margin="0,0,6,0"/><DatePicker x:Name="DbFromPicker" Width="130" Margin="0,0,10,0"/>
      <TextBlock Text="To" VerticalAlignment="Center" Margin="0,0,6,0"/><DatePicker x:Name="DbToPicker" Width="130" Margin="0,0,12,0"/>
      <Button x:Name="DbRefreshButton" Style="{StaticResource PrimaryButton}" Padding="14,5" Margin="0,0,8,0" Content="Refresh"/>
      <Button x:Name="DbExportButton" Style="{StaticResource SmallButton}" Padding="12,5" Content="Export data"/>
      <Button x:Name="DbSaveChartButton" Style="{StaticResource SmallButton}" Padding="12,5" Content="Save chart"/>
      <Button x:Name="DbBrowserButton" Style="{StaticResource SmallButton}" Padding="12,5" Content="Open live view in browser"/>
    </WrapPanel>
    <WrapPanel Grid.Row="1" Margin="0,12,0,12">
      <Border Width="180" Height="92" Margin="0,0,12,0" CornerRadius="8" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" Padding="12,8"><StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="UPTIME"/><TextBlock x:Name="DbUptimeText" FontSize="26" FontWeight="Bold" Text="..."/></StackPanel></Border>
      <Border Width="180" Height="92" Margin="0,0,12,0" CornerRadius="8" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" Padding="12,8"><StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="AVG. LATENCY"/><TextBlock x:Name="DbLatencyText" FontSize="26" FontWeight="Bold" Text="..."/></StackPanel></Border>
      <Border Width="180" Height="92" Margin="0,0,12,0" CornerRadius="8" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" Padding="12,8"><StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="TOTAL RUNS"/><TextBlock x:Name="DbTotalText" FontSize="26" FontWeight="Bold" Text="..."/></StackPanel></Border>
      <Border Width="180" Height="92" Margin="0,0,12,0" CornerRadius="8" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" Padding="12,8"><StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="PASSED"/><TextBlock x:Name="DbPassedText" FontSize="26" FontWeight="Bold" Text="..."/></StackPanel></Border>
      <Border Width="180" Height="92" Margin="0,0,12,0" CornerRadius="8" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" Padding="12,8"><StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="FAILED"/><TextBlock x:Name="DbFailedText" FontSize="26" FontWeight="Bold" Text="..."/></StackPanel></Border>
      <Border Width="240" Height="92" CornerRadius="8" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" Padding="12,8"><StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="P50 / P95 / P99 (MS)"/><TextBlock x:Name="DbPercentileText" FontSize="22" FontWeight="Bold" Text="..."/></StackPanel></Border>
    </WrapPanel>
    <Border Grid.Row="2" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="6"><Canvas x:Name="DbChart" ClipToBounds="True"/></Border>
  </Grid>
'@
    $names = 'DbMonitorBox', 'DbFromPicker', 'DbToPicker', 'DbRefreshButton', 'DbExportButton', 'DbSaveChartButton', 'DbBrowserButton', 'DbUptimeText', 'DbLatencyText', 'DbTotalText', 'DbPassedText', 'DbFailedText', 'DbPercentileText', 'DbChart'
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title 'Monitoring dashboard' -Width 1060 -Height 720
    $window = $dialog.Window; $controls = $dialog.Controls
    $controls['DbChart'].SetResourceReference([System.Windows.Controls.Panel]::BackgroundProperty, 'Surface')
    $script:dashboardData = @()
    $script:dashboardRefreshing = $false

    $update = {
        if ($script:dashboardRefreshing) { return }
        $script:dashboardRefreshing = $true
        try {
            $all = @(Get-MonitorLogData)
            $current = [string]$controls['DbMonitorBox'].SelectedItem
            $controls['DbMonitorBox'].Items.Clear(); [void]$controls['DbMonitorBox'].Items.Add('All Monitors')
            foreach ($name in @($all | Select-Object -ExpandProperty MonitorName -Unique | Sort-Object)) { [void]$controls['DbMonitorBox'].Items.Add($name) }
            $controls['DbMonitorBox'].SelectedItem = if ($current -and $controls['DbMonitorBox'].Items.Contains($current)) { $current } else { 'All Monitors' }
            $data = $all
            if ($controls['DbMonitorBox'].SelectedItem -ne 'All Monitors') { $data = @($all | Where-Object { $_.MonitorName -eq $controls['DbMonitorBox'].SelectedItem }) }
            if ($controls['DbFromPicker'].SelectedDate) { $from = $controls['DbFromPicker'].SelectedDate.Value.Date; $data = @($data | Where-Object { ([datetime]$_.Timestamp) -ge $from }) }
            if ($controls['DbToPicker'].SelectedDate) { $to = $controls['DbToPicker'].SelectedDate.Value.Date.AddDays(1).AddTicks(-1); $data = @($data | Where-Object { ([datetime]$_.Timestamp) -le $to }) }
            $script:dashboardData = $data
            if ($data.Count -eq 0) {
                foreach ($key in @('DbUptimeText', 'DbLatencyText', 'DbTotalText', 'DbPassedText', 'DbFailedText', 'DbPercentileText')) { $controls[$key].Text = 'N/A' }
                Update-LineChart -Canvas $controls['DbChart'] -Series @() -EmptyText 'No data for the selected monitor and date range.'
                return
            }
            $passed = @($data | Where-Object { $_.Success -eq 'True' }).Count
            $uptime = $passed / $data.Count
            $controls['DbUptimeText'].Text = '{0:P2}' -f $uptime
            $controls['DbUptimeText'].Foreground = if ($uptime -ge 0.99) { [System.Windows.Media.Brushes]::SeaGreen } elseif ($uptime -ge 0.95) { [System.Windows.Media.Brushes]::DarkOrange } else { [System.Windows.Media.Brushes]::Firebrick }
            $controls['DbLatencyText'].Text = '{0:N0} ms' -f ($data | Measure-Object -Property TimeMs -Average).Average
            $controls['DbTotalText'].Text = [string]$data.Count; $controls['DbPassedText'].Text = [string]$passed; $controls['DbFailedText'].Text = [string]($data.Count - $passed)
            $sortedTimes = [int[]]@($data | ForEach-Object { [int]$_.TimeMs } | Sort-Object)
            $controls['DbPercentileText'].Text = "$(Get-LatencyPercentile -SortedValues $sortedTimes -Fraction 0.5) / $(Get-LatencyPercentile -SortedValues $sortedTimes -Fraction 0.95) / $(Get-LatencyPercentile -SortedValues $sortedTimes -Fraction 0.99)"
            $sorted = @($data | Sort-Object { [datetime]$_.Timestamp })
            $span = ([datetime]$sorted[-1].Timestamp) - ([datetime]$sorted[0].Timestamp)
            Update-LineChart -Canvas $controls['DbChart'] -Series @(@{ Name = 'Latency (ms)'; Color = '#3659C9'; X = @($sorted | ForEach-Object { [double]([datetime]$_.Timestamp).Ticks }); Y = @($sorted | ForEach-Object { [double]$_.TimeMs }); Axis = 'Left' }) `
                -LeftTitle 'Latency (ms)' -XAsTime -TimeFormat $(if ($span.TotalDays -gt 1) { 'MM-dd HH:mm' } else { 'HH:mm' })
        } catch {
            foreach ($key in @('DbUptimeText', 'DbLatencyText', 'DbTotalText', 'DbPassedText', 'DbFailedText', 'DbPercentileText')) { $controls[$key].Text = 'N/A' }
        } finally { $script:dashboardRefreshing = $false }
    }
    $controls['DbRefreshButton'].Add_Click({ & $update })
    $controls['DbBrowserButton'].Add_Click({ Open-MonitorDashboardInBrowser })
    $controls['DbMonitorBox'].Add_SelectionChanged({ & $update })
    $controls['DbFromPicker'].Add_SelectedDateChanged({ & $update })
    $controls['DbToPicker'].Add_SelectedDateChanged({ & $update })
    $controls['DbChart'].Add_SizeChanged({ & $update })
    $controls['DbExportButton'].Add_Click({
        if (@($script:dashboardData).Count -eq 0) { [void][System.Windows.MessageBox]::Show($window, 'There is no data to export.', 'Export', 'OK', 'Information'); return }
        $picker = New-Object Microsoft.Win32.SaveFileDialog; $picker.Filter = 'CSV file (*.csv)|*.csv'; $picker.FileName = "monitor_data_export_$((Get-Date).ToString('yyyyMMdd')).csv"
        if ($picker.ShowDialog($window) -eq $true) { $script:dashboardData | Export-Csv -Path $picker.FileName -NoTypeInformation -Encoding UTF8 }
    })
    $controls['DbSaveChartButton'].Add_Click({
        $picker = New-Object Microsoft.Win32.SaveFileDialog; $picker.Filter = 'PNG image (*.png)|*.png'; $picker.FileName = 'MonitorChart.png'
        if ($picker.ShowDialog($window) -eq $true) { try { Save-ElementAsPng -Element $controls['DbChart'] -Path $picker.FileName } catch { [void][System.Windows.MessageBox]::Show($window, "Failed to save the chart: $($_.Exception.Message)", 'Save chart', 'OK', 'Error') } }
    })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}

function Show-MonitorChartDialog {
    param($Owner)
    if (-not (Test-Path $monitorLogFilePath)) { [void][System.Windows.MessageBox]::Show($Owner, 'No monitor log file found.', 'Monitor analytics', 'OK', 'Information'); return }
    $body = @'
  <Grid Margin="16,14,16,14">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
    <WrapPanel Margin="0,0,0,10"><TextBlock Text="Monitor" VerticalAlignment="Center" Margin="0,0,8,0"/><ComboBox x:Name="McMonitorBox" Width="240" Height="28" VerticalContentAlignment="Center" Margin="0,0,10,0"/><Button x:Name="McSaveButton" Style="{StaticResource SmallButton}" Padding="12,5" Content="Save image"/></WrapPanel>
    <Border Grid.Row="1" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="6"><Canvas x:Name="McChart" ClipToBounds="True"/></Border>
  </Grid>
'@
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames 'McMonitorBox', 'McSaveButton', 'McChart' -Title 'Monitor analytics' -Width 1000 -Height 680
    $window = $dialog.Window; $controls = $dialog.Controls
    $controls['McChart'].SetResourceReference([System.Windows.Controls.Panel]::BackgroundProperty, 'Surface')
    $data = @(Get-MonitorLogData | Select-Object @{ N = 'Time'; E = { [datetime]$_.Timestamp } }, MonitorName, @{ N = 'Ms'; E = { [int]$_.TimeMs } })
    foreach ($name in @($data | Select-Object -ExpandProperty MonitorName -Unique)) { [void]$controls['McMonitorBox'].Items.Add($name) }
    $draw = {
        $selected = [string]$controls['McMonitorBox'].SelectedItem
        $subset = @($data | Where-Object { $_.MonitorName -eq $selected } | Sort-Object Time)
        Update-LineChart -Canvas $controls['McChart'] -Series @(@{ Name = "$selected - response time (ms)"; Color = '#3659C9'; X = @($subset | ForEach-Object { [double]$_.Time.Ticks }); Y = @($subset | ForEach-Object { [double]$_.Ms }); Axis = 'Left' }) -LeftTitle 'ms' -XAsTime -TimeFormat 'HH:mm:ss' -EmptyText 'Select a monitor.'
    }
    $controls['McMonitorBox'].Add_SelectionChanged({ & $draw })
    $controls['McChart'].Add_SizeChanged({ & $draw })
    $controls['McSaveButton'].Add_Click({
        $picker = New-Object Microsoft.Win32.SaveFileDialog; $picker.Filter = 'PNG image (*.png)|*.png'; $picker.FileName = 'MonitorChart.png'
        if ($picker.ShowDialog($window) -eq $true) { Save-ElementAsPng -Element $controls['McChart'] -Path $picker.FileName }
    })
    if ($controls['McMonitorBox'].Items.Count -gt 0) { $controls['McMonitorBox'].SelectedIndex = 0 }
    [void](Show-WpfDialog -Window $window -OwnerForm $Owner)
}
#endregion
