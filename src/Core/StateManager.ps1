function Import-History {
    if (Test-Path $historyFilePath) {
        try {
            $jsonContent = Get-Content -Path $historyFilePath -Raw
            # Filter out any null entries that might be in the JSON array
            $script:history = ($jsonContent | ConvertFrom-Json -ErrorAction SilentlyContinue) | Where-Object { $_ -ne $null }
            Write-Log "History loaded from $historyFilePath"
        } catch { # Catch block for Import-History
            Write-Log "Could not load or parse history file: $($_.Exception.Message)" -Level Info
            $script:history = @()
        }
    }
}

function Save-History {
    try { # Try block for Save-History
        $script:history | ConvertTo-Json -Depth 5 | Set-Content -Path $historyFilePath
    } catch {
        Write-Log "Failed to save history: $($_.Exception.Message)" -Level Debug
    }
}

function Save-Globals {
    try {
        ConvertTo-ProtectedVariables -Variables $script:globals -SecretNames @($script:settings.SecretGlobalNames) | ConvertTo-Json -Depth 10 | Out-File -FilePath $globalsFilePath -Encoding utf8 -NoNewline -ErrorAction Stop
    } catch {
        Write-Log "Failed to save globals: $($_.Exception.Message)" -Level Debug
    }
}

$script:globals = @{}

function Import-Globals {
    if (Test-Path $globalsFilePath) {
        try {
            $json = Get-Content -Path $globalsFilePath -Raw
            $script:globals = ConvertFrom-JsonToHashtable -Json $json
            if (-not $script:globals) { $script:globals = @{} }
            Unprotect-SecretVariables -Variables $script:globals -SecretNames @($script:settings.SecretGlobalNames)
            Write-Log "Globals loaded from $globalsFilePath" -Level Debug
        } catch {
            Write-Log "Could not load or parse globals file: $($_.Exception.Message)" -Level Info
            $script:globals = @{}
        }
    }
}

$script:environments = @{}
$script:activeEnvironment = "No Environment"

function Import-Environments {
    if (Test-Path $environmentsFilePath) {
        try {
            $json = Get-Content -Path $environmentsFilePath -Raw
            $script:environments = ConvertFrom-JsonToHashtable -Json $json
            if (-not $script:environments) { $script:environments = @{} }
            # Decrypt sensitive fields
            foreach ($env in $script:environments.Values) {
                if ($env.Variables) { Unprotect-SecretVariables -Variables $env.Variables -SecretNames (Get-SecretNames $env) }
                if ($env.Authentication) {
                    foreach ($k in @('Value','Token','Password','ClientSecret','AccessToken','RefreshToken')) {
                        if ($env.Authentication[$k]) { $env.Authentication[$k] = Unprotect-String $env.Authentication[$k] }
                    }
                }
            }
            Write-Log "Environments loaded from $environmentsFilePath" -Level Debug
        } catch { # Catch block for Import-Environments
            Write-Log "Could not load or parse environments file: $($_.Exception.Message)" -Level Info
            $script:environments = @{}
        }
    }
}

function Save-Environments {
    try {
        # Clone and Encrypt
        $jsonRaw = $script:environments | ConvertTo-Json -Depth 10
        $envCopy = ConvertFrom-JsonToHashtable -Json $jsonRaw
        if (-not $envCopy) { $envCopy = @{} }
        foreach ($env in $envCopy.Values) {
            if ($env.Variables) { $env.Variables = ConvertTo-ProtectedVariables -Variables $env.Variables -SecretNames (Get-SecretNames $env) }
            if ($env.Authentication) {
                foreach ($k in @('Value','Token','Password','ClientSecret','AccessToken','RefreshToken')) {
                    if ($env.Authentication[$k]) { $env.Authentication[$k] = Protect-String $env.Authentication[$k] }
                }
            }
        }
        $json = $envCopy | ConvertTo-Json -Depth 10
        # Use Out-File with a specific encoding to prevent BOM (Byte Order Mark) issues.
        $json | Out-File -FilePath $environmentsFilePath -Encoding utf8 -NoNewline -ErrorAction Stop
    } catch { # Catch block for Save-Environments
        Write-Log "Failed to save environments: $($_.Exception.Message)" -Level Debug
    }
}

$script:collections = @()
$script:activeCollectionName = $null
$script:activeCollectionNode = $null
$script:activeCollectionVariables = @{}
$script:requestTabs = @()
$script:requestTemplates = @()
$script:activeRequestTabId = $null
$script:isSwitchingRequestTab = $false

function Initialize-CollectionVariables {
    param([array]$Items)
    foreach ($item in ($Items | Where-Object { $_ -ne $null })) {
        if ($item.Type -eq "Collection") {
            if (-not ($item.PSObject.Properties.Name -contains 'Variables')) {
                $item | Add-Member -MemberType NoteProperty -Name 'Variables' -Value @{}
            } elseif ($null -eq $item.Variables) {
                $item.Variables = @{}
            }
        }
        if ($item.Items) { Initialize-CollectionVariables -Items $item.Items }
    }
}

function Import-Collections {
    if (Test-Path $collectionsFilePath) {
        try {
            $jsonContent = Get-Content -Path $collectionsFilePath -Raw
            if (-not [string]::IsNullOrWhiteSpace($jsonContent)) {
                $script:collections = $jsonContent | ConvertFrom-Json -ErrorAction SilentlyContinue
            }
            if ($script:collections -and $script:collections -isnot [array]) { $script:collections = @($script:collections) }
            foreach ($collection in @($script:collections | Where-Object { $_ })) { if ($collection.Variables) { Unprotect-SecretVariables -Variables $collection.Variables -SecretNames (Get-SecretNames $collection) } }
            Initialize-CollectionVariables -Items $script:collections
            Write-Log "Collections loaded from $collectionsFilePath" -Level Debug
        } catch { # Catch block for Import-Collections
            Write-Log "Could not load or parse collections file: $($_.Exception.Message)" -Level Info
            $script:collections = @()
        }
    }
}

function Save-Collections {
    try {
        # Depth 50: nested folders deeper than a few levels were silently truncated at depth 10.
        $json = ConvertTo-Json -InputObject (Get-CollectionsForStorage -Collections $script:collections) -Depth 50
        $json | Out-File -FilePath $collectionsFilePath -Encoding utf8 -NoNewline -ErrorAction Stop
    } catch {
        Write-Log "Failed to save collections: $($_.Exception.Message)" -Level Info
    }
}

function Copy-RequestData {
    param([object]$Data)
    if ($null -eq $Data) { return $null }
    return (($Data | ConvertTo-Json -Depth 20) | ConvertFrom-Json)
}

function New-RequestTabState {
    param(
        [string]$Name = "Request",
        [string]$Method = "POST",
        [string]$Url = "",
        [string]$Headers = "",
        [string]$Body = "",
        [string]$BodyType = "multipart/form-data",
        [string]$OutputFormat = "",
        [string]$Tests = "",
        [string]$PreRequestScript = "",
        [string]$Environment = "No Environment",
        [object]$Authentication = $null,
        [string]$GqlQuery = "",
        [string]$GqlVars = "",
        [bool]$IncludeFilename = $true,
        [bool]$IncludeContentType = $true
    )

    [PSCustomObject]@{
        Id = [guid]::NewGuid().ToString()
        Name = $Name
        Method = $Method
        Url = $Url
        Headers = $Headers
        Body = $Body
        BodyType = $BodyType
        OutputFormat = $OutputFormat
        Tests = $Tests
        PreRequestScript = $PreRequestScript
        Environment = $Environment
        Authentication = if ($Authentication) { Copy-RequestData $Authentication } else { @{ Type = "No Auth" } }
        GqlQuery = $GqlQuery
        GqlVars = $GqlVars
        IncludeFilename = $IncludeFilename
        IncludeContentType = $IncludeContentType
    }
}

function Initialize-RequestTabDefaults {
    param([object]$TabState)
    if (-not $TabState) { return }
    if (-not ($TabState.PSObject.Properties.Name -contains 'Id') -or [string]::IsNullOrWhiteSpace($TabState.Id)) {
        $TabState | Add-Member -MemberType NoteProperty -Name 'Id' -Value ([guid]::NewGuid().ToString()) -Force
    }
    foreach ($pair in @(
        @{ Name='Name'; Value='Request' },
        @{ Name='Method'; Value='POST' },
        @{ Name='Url'; Value='' },
        @{ Name='Headers'; Value='' },
        @{ Name='Body'; Value='' },
        @{ Name='BodyType'; Value='multipart/form-data' },
        @{ Name='OutputFormat'; Value='' },
        @{ Name='Tests'; Value='' },
        @{ Name='PreRequestScript'; Value='' },
        @{ Name='Environment'; Value='No Environment' },
        @{ Name='Authentication'; Value=@{ Type = "No Auth" } },
        @{ Name='GqlQuery'; Value='' },
        @{ Name='GqlVars'; Value='' },
        @{ Name='IncludeFilename'; Value=$true },
        @{ Name='IncludeContentType'; Value=$true }
    )) {
        if (-not ($TabState.PSObject.Properties.Name -contains $pair.Name)) {
            $TabState | Add-Member -MemberType NoteProperty -Name $pair.Name -Value $pair.Value -Force
        }
    }
}

function Import-RequestTabs {
    $script:requestTabs = @()
    if (Test-Path $requestTabsFilePath) {
        try {
            $json = Get-Content -Path $requestTabsFilePath -Raw
            if (-not [string]::IsNullOrWhiteSpace($json)) {
                $loadedTabs = $json | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($loadedTabs -and $loadedTabs -isnot [array]) { $loadedTabs = @($loadedTabs) }
                foreach ($tabState in @($loadedTabs)) {
                    if (-not $tabState) { continue }
                    Initialize-RequestTabDefaults -TabState $tabState
                    $script:requestTabs += $tabState
                }
            }
            Write-Log "Request tabs loaded from $requestTabsFilePath" -Level Debug
        } catch {
            Write-Log "Could not load request tabs: $($_.Exception.Message)" -Level Info
            $script:requestTabs = @()
        }
    }
    if (-not $script:requestTabs -or $script:requestTabs.Count -eq 0) {
        $script:requestTabs = @(New-RequestTabState -Name "Request 1" -IncludeFilename $script:settings.IncludeFilename -IncludeContentType $script:settings.IncludeContentType)
    }
    $script:activeRequestTabId = $script:requestTabs[0].Id
}

function Save-RequestTabs {
    if ($script:isSecondaryWindow) { return }
    try {
        if (-not $script:requestTabs) { return }
        $script:requestTabs | ConvertTo-Json -Depth 20 | Out-File -FilePath $requestTabsFilePath -Encoding utf8 -NoNewline -ErrorAction Stop
    } catch {
        Write-Log "Failed to save request tabs: $($_.Exception.Message)" -Level Debug
    }
}

function Import-RequestTemplates {
    $script:requestTemplates = @()
    if (Test-Path $requestTemplatesFilePath) {
        try {
            $json = Get-Content -Path $requestTemplatesFilePath -Raw
            if (-not [string]::IsNullOrWhiteSpace($json)) {
                $loadedTemplates = $json | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($loadedTemplates -and $loadedTemplates -isnot [array]) { $loadedTemplates = @($loadedTemplates) }
                foreach ($template in @($loadedTemplates)) {
                    if (-not $template) { continue }
                    Initialize-RequestTabDefaults -TabState $template
                    $script:requestTemplates += $template
                }
            }
            Write-Log "Request templates loaded from $requestTemplatesFilePath" -Level Debug
        } catch {
            Write-Log "Could not load request templates: $($_.Exception.Message)" -Level Info
            $script:requestTemplates = @()
        }
    }
}

function Save-RequestTemplates {
    try {
        $script:requestTemplates | ConvertTo-Json -Depth 20 | Out-File -FilePath $requestTemplatesFilePath -Encoding utf8 -NoNewline -ErrorAction Stop
    } catch {
        Write-Log "Failed to save request templates: $($_.Exception.Message)" -Level Debug
    }
}

$script:monitors = @()

function Import-Monitors {
    if (Test-Path $monitorsFilePath) {
        try {
            $json = Get-Content -Path $monitorsFilePath -Raw
            $script:monitors = $json | ConvertFrom-Json
            if ($script:monitors -isnot [array]) { $script:monitors = @($script:monitors) }
            # Migration for monitors saved without BodyType or RequestTimeoutSeconds
            foreach ($monitor in ($script:monitors | Where-Object { $_ -ne $null })) {
                if ($monitor.Request) {
                    if (-not ($monitor.Request.PSObject.Properties.Name -contains 'BodyType')) {
                        $monitor.Request | Add-Member -MemberType NoteProperty -Name 'BodyType' -Value 'multipart/form-data'
                    }
                    if (-not ($monitor.Request.PSObject.Properties.Name -contains 'RequestTimeoutSeconds')) {
                        $monitor.Request | Add-Member -MemberType NoteProperty -Name 'RequestTimeoutSeconds' -Value 30
                    }
                    if (-not ($monitor.Request.PSObject.Properties.Name -contains 'Authentication')) {
                        $monitor.Request | Add-Member -MemberType NoteProperty -Name 'Authentication' -Value @{ Type = "No Auth" }
                    }
                }
                # Migration for monitors missing the Alerts object or its properties
                if (-not ($monitor.PSObject.Properties.Name -contains 'Alerts')) {
                    $monitor | Add-Member -MemberType NoteProperty -Name 'Alerts' -Value @{ OnFailure=$true; OnSlow=$false; ThresholdMs=1000; SendEmail=$false; EmailTo="" }
                } else {
                    # Ensure all sub-properties exist
                    if (-not ($monitor.Alerts.PSObject.Properties.Name -contains 'OnFailure'))   { $monitor.Alerts | Add-Member -MemberType NoteProperty -Name 'OnFailure' -Value $true }
                    if (-not ($monitor.Alerts.PSObject.Properties.Name -contains 'OnSlow'))      { $monitor.Alerts | Add-Member -MemberType NoteProperty -Name 'OnSlow' -Value $false }
                    if (-not ($monitor.Alerts.PSObject.Properties.Name -contains 'ThresholdMs')) { $monitor.Alerts | Add-Member -MemberType NoteProperty -Name 'ThresholdMs' -Value 1000 }
                    if (-not ($monitor.Alerts.PSObject.Properties.Name -contains 'SendEmail'))   { $monitor.Alerts | Add-Member -MemberType NoteProperty -Name 'SendEmail' -Value $false }
                    if (-not ($monitor.Alerts.PSObject.Properties.Name -contains 'EmailTo'))     { $monitor.Alerts | Add-Member -MemberType NoteProperty -Name 'EmailTo' -Value "" }
                }
            }
        } catch {
            $script:monitors = @()
        }
    }
}

function Save-Monitors {
    $script:monitors | ConvertTo-Json -Depth 10 | Set-Content -Path $monitorsFilePath
}

$script:grpcHistory = @()

function Import-GrpcHistory {
    if (Test-Path $grpcHistoryFilePath) {
        try {
            $json = Get-Content -Path $grpcHistoryFilePath -Raw
            $script:grpcHistory = $json | ConvertFrom-Json
            if ($script:grpcHistory -isnot [array]) { $script:grpcHistory = @($script:grpcHistory) }
        } catch {
            $script:grpcHistory = @()
        }
    }
}

function Save-GrpcHistory {
    $script:grpcHistory | ConvertTo-Json -Depth 5 | Set-Content -Path $grpcHistoryFilePath
}
$script:defaultSettings = @{
    ShowResponse = $true
    ShowJsonTreeTab = $false
    ShowCurl = $true
    ShowHistory = $true
    ShowResponseHeaders = $true
    AutoSaveToFile = $false
    AutoSavePath = ""
    ShowConsoleTab = $true
    DefaultConsoleLanguage = "PowerShell"
    AutoRenameFile = $false
    EnableAutoRenamePrefix = $false
    AutoRenamePrefix = ""
    AutoRunHistory = $true
    EnableHistory = $true
    IncludeFilename = $true
    EnableAllMethods = $false
    IncludeContentType = $true
    LogLevel = 'Info'
    ShowEnvironmentPanel = $true
    ShowRequestHeadersTab = $true
    ShowAuthTab = $true
    ShowPreRequestTab = $false
    ShowTestsTab = $false
    ShowTestResultsTab = $false
    LastActiveEnvironment = "No Environment"
    ResponseDockState = "Right"
    EnableLogs = $true
    HistoryUndocked = $false
    RestoreRequestTabs = $false
    WindowBounds = $null
    EnableMonitorWebDashboard = $true
    MonitorDashboardPort = 8765
    HistorySaveResponses = $true
    HistoryResponseBodyLimitKB = 256
    SecretGlobalNames = @()
    CollectionRunnerParallel = 1
    CollectionRunnerRetries = 0
    CheckForUpdatesOnStartup = $true
    LastUpdateCheck = $null
    IgnoreSslErrors = $false
    RequestTimeoutSeconds = 60
    ResponseFontSize = 8
    EnablePostmanImport = $true
    EnableCurlImport = $true
    ImportDefaultsMigrated = $true
    EnableRepeatRequest = $false
    MaxRepeatCount = 5
    MonitorSmtpServer = ""
    MonitorSmtpPort = 587
    MonitorSmtpUseSsl = $true
    MonitorSmtpFrom = ""
    MonitorSmtpUser = ""
    MonitorSmtpPass = ""
    MonitorSmtpAuthMethod = "Basic"
    MonitorSmtpClientId = ""
    MonitorSmtpClientSecret = ""
    MonitorSmtpRefreshToken = ""
    MonitorSmtpTokenEndpoint = ""
    MonitorSmtpTokenExpiry = ""
    MonitorAlertSubjectTemplate = "API Alert: {MonitorName}"
    MonitorAlertBodyTemplate = "Monitor: {MonitorName}`r`nStatus: {Status}`r`nStatus Code: {StatusCode}`r`nURL: {Url}`r`nTime (ms): {TimeMs}`r`nMessage: {Message}`r`nTimestamp: {Timestamp}"
    MonitorAlertBodyForceHtml = $false
    ProxyMode = "System" # System, Custom, None
    ProxyAddress = ""
    ProxyPort = 8080
    ProxyUser = ""
    ProxyPass = ""
    CollectionRunnerDelay = 0
    CollectionRunnerStopOnFail = $false
    AppTheme = "Light"
}

function Get-RequestObjectFromItem {
    param($Item)

    if (-not $Item) { return $null }

    $itemProperties = @($Item.PSObject.Properties.Name)
    if ($itemProperties -contains 'RequestData' -and $Item.RequestData) {
        return $Item.RequestData
    }

    if (($itemProperties -contains 'Method') -and ($itemProperties -contains 'Url')) {
        return $Item
    }

    return $null
}

$script:collectionRunQueue = New-Object System.Collections.Queue

$script:settings = $script:defaultSettings.Clone()


# Settings keys that are stored encrypted (DPAPI) on disk. Used by BOTH Import-Settings and Save-Settings
# so the two can never get out of sync.
$script:encryptedSettingKeys = @('MonitorSmtpPass', 'MonitorSmtpClientSecret', 'MonitorSmtpRefreshToken', 'ProxyPass')

function Import-Settings {
    if (Test-Path $settingsFilePath) {
        try {
            Copy-Item -Path $settingsFilePath -Destination "$settingsFilePath.bak" -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Failed to backup settings: $($_.Exception.Message)" -Level Info
        }

        try {
            $loadedSettings = Get-Content -Path $settingsFilePath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue

            # Merge settings from file, adding new keys if they exist in the file but not in the defaults.
            foreach ($key in $loadedSettings.PSObject.Properties.Name) {
                if (-not $script:settings.ContainsKey($key)) {
                    $script:settings[$key] = $loadedSettings.$key
                }
            }
            foreach ($key in $loadedSettings.PSObject.Properties.Name) {
                if ($script:settings.ContainsKey($key)) { $script:settings[$key] = $loadedSettings.$key }
            }            
            Write-Log "Settings loaded from $settingsFilePath"
        } catch { # Catch block for Import-Settings
            Write-Log "Could not load or parse settings file: $($_.Exception.Message)" -Level Info
        }
    }
    # Ensure all default settings are present in the loaded settings
    foreach ($key in $script:defaultSettings.Keys) {
        if (-not $script:settings.ContainsKey($key)) { $script:settings[$key] = $script:defaultSettings[$key] }
    }
    # Validate critical settings to prevent crashes
    if ([int]$script:settings.ResponseFontSize -le 0) { $script:settings.ResponseFontSize = $script:defaultSettings.ResponseFontSize }
    if ([int]$script:settings.RequestTimeoutSeconds -le 0) { $script:settings.RequestTimeoutSeconds = $script:defaultSettings.RequestTimeoutSeconds }

    # One-time migration: Postman/cURL import used to default to off and stay hidden in saved settings files.
    if (-not $loadedSettings -or -not ($loadedSettings.PSObject.Properties.Name -contains 'ImportDefaultsMigrated')) {
        $script:settings.EnablePostmanImport = $true
        $script:settings.EnableCurlImport = $true
        $script:settings.ImportDefaultsMigrated = $true
    }

    # Decrypt sensitive values
    foreach ($key in $script:encryptedSettingKeys) {
        if ($script:settings[$key]) { $script:settings[$key] = Unprotect-String $script:settings[$key] }
    }
}

function Save-Settings {
    $settingsToSave = $script:settings.Clone()
    foreach ($key in $script:encryptedSettingKeys) {
        if ($settingsToSave[$key]) { $settingsToSave[$key] = Protect-String $settingsToSave[$key] }
    }
    $settingsToSave | ConvertTo-Json | Set-Content -Path $settingsFilePath
}

# Formats a byte count into a human-readable string (e.g., KB, MB, GB).

function Import-DraftState {
    if (Test-Path $draftsFilePath) {
        try {
            $json = Get-Content -Path $draftsFilePath -Raw
            if (-not [string]::IsNullOrWhiteSpace($json)) {
                $drafts = $json | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($drafts -and $drafts -isnot [array]) { $drafts = @($drafts) }
                return $drafts
            }
        } catch {
            Write-Log "Could not load drafts file: $($_.Exception.Message)" -Level Info
        }
    }
    return $null
}

function Save-DraftState {
    if ($script:isSecondaryWindow) { return }
    try {
        if (-not $script:requestTabs) { return }
        # Note: Do not overwrite the main file heavily to avoid I/O bottlenecks. 
        # This is a silent background save.
        $script:requestTabs | ConvertTo-Json -Depth 20 | Out-File -FilePath $draftsFilePath -Encoding utf8 -NoNewline -ErrorAction Stop
    } catch {
        Write-Log "Failed to save drafts: $($_.Exception.Message)" -Level Debug
    }
}
