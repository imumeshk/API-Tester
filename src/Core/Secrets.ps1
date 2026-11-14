#region Secret variables
# Variables can be marked secret per scope:
#   environments  -> environment data key 'SecretVariables' (array of names)
#   globals       -> $script:settings.SecretGlobalNames
#   collections   -> collection property 'SecretVariables'
# Secret values are encrypted (DPAPI) on disk, masked on screen and left out of exports.

$script:SecretMask = [string][char]0x2022 * 8

function Get-SecretNames {
    param($Container, [string]$Property = 'SecretVariables')
    return @(Get-ObjectProperty $Container $Property @() | Where-Object { $_ })
}

# Returns a copy of a variables table with the secret values encrypted (or blanked with -Blank).
function ConvertTo-ProtectedVariables {
    param($Variables, [string[]]$SecretNames, [switch]$Blank)
    $copy = @{}
    if ($Variables -is [System.Collections.IDictionary]) { foreach ($key in $Variables.Keys) { $copy[[string]$key] = $Variables[$key] } }
    elseif ($Variables) { foreach ($property in $Variables.PSObject.Properties) { $copy[$property.Name] = $property.Value } }
    foreach ($name in @($SecretNames)) {
        if (-not $copy.ContainsKey($name)) { continue }
        $copy[$name] = if ($Blank) { '' } elseif ($copy[$name]) { Protect-String ([string]$copy[$name]) } else { '' }
    }
    return $copy
}

# Decrypts the secret values of a variables table in place.
function Unprotect-SecretVariables {
    param($Variables, [string[]]$SecretNames)
    if (-not $Variables) { return }
    foreach ($name in @($SecretNames)) {
        if ($Variables -is [System.Collections.IDictionary]) { if ($Variables.Contains($name) -and $Variables[$name]) { $Variables[$name] = Unprotect-String ([string]$Variables[$name]) } }
        elseif ($Variables.PSObject.Properties[$name] -and $Variables.$name) { $Variables.$name = Unprotect-String ([string]$Variables.$name) }
    }
}

# Collections copy with secret variables blanked (for exports) or encrypted (for the collections file).
function Get-CollectionsForStorage {
    param($Collections, [switch]$ForExport)
    $copies = @()
    foreach ($collection in @($Collections | Where-Object { $_ })) {
        $secretNames = Get-SecretNames $collection
        if ($secretNames.Count -eq 0 -or -not $collection.Variables) { $copies += $collection; continue }
        # Only the collection object is copied; its items are shared, so deep folder trees are never truncated.
        $copy = $collection.PSObject.Copy()
        if ($copy.Variables) {
            $copy.Variables = ConvertTo-ProtectedVariables -Variables $copy.Variables -SecretNames $secretNames -Blank:$ForExport
        }
        $copies += $copy
    }
    return ,$copies
}

function Test-IsSecretVariable {
    param([string]$Name, [string]$Scope)
    switch ($Scope) {
        'Environment' {
            $environmentData = Get-ActiveEnvironmentData
            return ((Get-SecretNames $environmentData) -contains $Name)
        }
        'Collection' { return ($script:activeCollection -and ((Get-SecretNames $script:activeCollection) -contains $Name)) }
        'Global' { return (@($script:settings.SecretGlobalNames) -contains $Name) }
    }
    return $false
}

# Where a {{variable}} resolves from: @{ Found; Value; Source; Secret }. Same order as Expand-Variables.
function Resolve-VariableSource {
    param([string]$Name)
    if ($script:iterationVariables -and $script:iterationVariables.ContainsKey($Name)) { return @{ Found = $true; Value = [string]$script:iterationVariables[$Name]; Source = 'data file (current iteration)'; Secret = $false } }
    $environmentData = Get-ActiveEnvironmentData
    $environmentVariables = Get-ObjectProperty $environmentData 'Variables' $null
    if ($environmentVariables -and (($environmentVariables -is [System.Collections.IDictionary] -and $environmentVariables.Contains($Name)) -or ($environmentVariables -isnot [System.Collections.IDictionary] -and $environmentVariables.PSObject.Properties[$Name]))) {
        return @{ Found = $true; Value = [string](Get-ObjectProperty $environmentVariables $Name ''); Source = "environment '$($script:activeEnvironment)'"; Secret = (Test-IsSecretVariable -Name $Name -Scope 'Environment') }
    }
    $collectionVariables = $script:activeCollectionVariables
    if ($collectionVariables -and (($collectionVariables -is [System.Collections.IDictionary] -and $collectionVariables.Contains($Name)) -or ($collectionVariables -isnot [System.Collections.IDictionary] -and $collectionVariables.PSObject.Properties[$Name]))) {
        return @{ Found = $true; Value = [string](Get-ObjectProperty $collectionVariables $Name ''); Source = "collection '$(if ($script:activeCollection) { $script:activeCollection.Name })'"; Secret = (Test-IsSecretVariable -Name $Name -Scope 'Collection') }
    }
    if ($script:globals -and $script:globals.ContainsKey($Name)) { return @{ Found = $true; Value = [string]$script:globals[$Name]; Source = 'global variables'; Secret = (Test-IsSecretVariable -Name $Name -Scope 'Global') } }
    switch ($Name) {
        '$guid'      { return @{ Found = $true; Value = 'a new GUID for every request'; Source = 'dynamic variable'; Secret = $false } }
        '$timestamp' { return @{ Found = $true; Value = 'current Unix time in seconds'; Source = 'dynamic variable'; Secret = $false } }
        '$randomInt' { return @{ Found = $true; Value = 'random number 1-9999'; Source = 'dynamic variable'; Secret = $false } }
    }
    return @{ Found = $false; Value = ''; Source = ''; Secret = $false }
}
#endregion
