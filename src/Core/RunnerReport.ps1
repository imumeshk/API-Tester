#region Collection runner HTML report
function New-RunnerReportHtml {
    param([string]$Title, $Rows)
    $encode = { param($value) [System.Net.WebUtility]::HtmlEncode([string]$value) }
    $rows = @($Rows)
    $passed = @($rows | Where-Object { $_.Status -eq 'PASS' }).Count
    $failed = @($rows | Where-Object { $_.Status -in @('FAIL', 'ERROR') }).Count
    $times = @($rows | Where-Object { [string]$_.TimeMs -match '^\d+$' } | ForEach-Object { [int]$_.TimeMs } | Sort-Object)
    $percentile = { param([double]$fraction) if ($times.Count -eq 0) { '-' } else { $times[[Math]::Min($times.Count - 1, [Math]::Max(0, [int][Math]::Ceiling($times.Count * $fraction) - 1))] } }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append(@"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>$(& $encode $Title)</title>
<style>
body{font-family:'Segoe UI',sans-serif;margin:24px;background:#F4F7FC;color:#1F2937} h1{margin:0 0 4px;color:#243E9E} .meta{color:#64748B;margin-bottom:18px}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px} .card{background:#fff;border:1px solid #D8E1EF;border-radius:10px;padding:12px 18px;min-width:140px}
.card b{display:block;font-size:26px} table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #D8E1EF;border-radius:10px;overflow:hidden}
th,td{padding:9px 12px;border-bottom:1px solid #E5EAF3;text-align:left;font-size:14px} th{background:#3659C9;color:#fff;font-weight:600}
.PASS{color:#107C10;font-weight:600} .FAIL,.ERROR{color:#D93025;font-weight:600} .url{color:#64748B;font-size:12px}
</style></head><body><h1>$(& $encode $Title)</h1><div class="meta">Generated $(Get-Date)</div>
<div class="cards"><div class="card">Requests<b>$($rows.Count)</b></div><div class="card">Passed<b style="color:#107C10">$passed</b></div><div class="card">Failed<b style="color:#D93025">$failed</b></div>
<div class="card">p50 / p95 / p99 (ms)<b>$(& $percentile 0.5) / $(& $percentile 0.95) / $(& $percentile 0.99)</b></div></div>
<table><thead><tr><th>Request</th><th>Status</th><th>Result</th><th>Time (ms)</th><th>Tests</th></tr></thead><tbody>
"@)
    foreach ($row in $rows) {
        [void]$builder.Append("<tr><td>$(& $encode $row.Name)<div class=`"url`">$(& $encode $row.Method) $(& $encode $row.Url)</div></td><td class=`"$(& $encode $row.Status)`">$(& $encode $row.Status)</td><td>$(& $encode $row.Result)</td><td>$(& $encode $row.TimeMs)</td><td>$(& $encode $row.Tests)</td></tr>")
    }
    [void]$builder.Append('</tbody></table></body></html>')
    return $builder.ToString()
}
#endregion
