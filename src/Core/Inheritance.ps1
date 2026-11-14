#region Inheritance (Postman-style folder / collection settings)
# Collections and folders can carry: Auth (an auth object, Type 'Inherit' = use the parent's), Headers (text),
# PreRequestScript and Tests. A request whose auth Type is 'Inherit' uses the nearest ancestor's auth.
# Headers from ancestors are merged (the request wins on the same name); scripts run collection -> folder -> request.

function Get-ItemAncestors {
    param($Root, $Item)
    if (-not $Root -or -not $Item) { return @() }
    $path = New-Object System.Collections.ArrayList
    $search = {
        param($node)
        if ($node -eq $Item) { return $true }
        [void]$path.Add($node)
        foreach ($child in @($node.Items)) { if ($child -and (& $search $child)) { return $true } }
        $path.RemoveAt($path.Count - 1)
        return $false
    }
    if (& $search $Root) { return @($path) }
    return @()
}

function Resolve-InheritedRequest {
    param([Parameter(Mandatory = $true)]$Request, $Root = $null, $Item = $null)
    $resolved = Copy-RequestData $Request
    $ancestors = @(Get-ItemAncestors -Root $Root -Item $Item)

    $inheritedHeaders = @($ancestors | ForEach-Object { [string](Get-ObjectProperty $_ 'Headers' '') } | Where-Object { $_ -match '\S' })
    if ($inheritedHeaders.Count -gt 0) {
        $merged = [ordered]@{}
        foreach ($headerText in @($inheritedHeaders) + @([string]$resolved.Headers)) {
            foreach ($entry in (ConvertFrom-HeaderText -HeaderText $headerText)) { $merged[$entry.Name.ToLowerInvariant()] = "$($entry.Name): $($entry.Value)" }
        }
        $resolved.Headers = (@($merged.Values) -join "`r`n")
    }

    if ([string](Get-ObjectProperty $resolved.Authentication 'Type' 'No Auth') -eq 'Inherit') {
        $inherited = $null
        for ($index = $ancestors.Count - 1; $index -ge 0; $index--) {
            $nodeAuth = Get-ObjectProperty $ancestors[$index] 'Auth' $null
            if ($nodeAuth -and [string](Get-ObjectProperty $nodeAuth 'Type' 'Inherit') -ne 'Inherit') { $inherited = $nodeAuth; break }
        }
        $resolved.Authentication = if ($inherited) { Copy-RequestData $inherited } else { [PSCustomObject]@{ Type = 'No Auth' } }
    }

    foreach ($field in @('PreRequestScript', 'Tests')) {
        $scripts = @($ancestors | ForEach-Object { [string](Get-ObjectProperty $_ $field '') }) + @([string]$resolved.$field)
        $scripts = @($scripts | Where-Object { $_ -match '\S' })
        $resolved.$field = if ($scripts.Count -gt 0) { $scripts -join "`r`n`r`n" } else { '' }
    }
    $resolved | Add-Member -MemberType NoteProperty -Name 'HasInheritance' -Value ([bool]($ancestors | Where-Object { (Get-ObjectProperty $_ 'Auth' $null) -or ([string](Get-ObjectProperty $_ 'Headers' '') -match '\S') -or ([string](Get-ObjectProperty $_ 'PreRequestScript' '') -match '\S') -or ([string](Get-ObjectProperty $_ 'Tests' '') -match '\S') })) -Force
    return $resolved
}
#endregion
