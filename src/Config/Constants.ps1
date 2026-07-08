#region Initialization

# --- App Metadata ---
$script:AppVersion     = "2.0.0"
$script:AppGitHubRepo  = "imumeshk/API-Tester"
$script:AppGitHubAsset = "API-Tester.ps1"   # Name of the .ps1 asset attached to GitHub Releases

# Determine the script's root directory to locate configuration and log files.
# This approach works for both standard execution and in the PowerShell ISE.
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Path $MyInvocation.MyCommand.Path -Parent }

# Define directories for organization
$configDir = Join-Path -Path $scriptRoot -ChildPath "Configuration"
$historyDir = Join-Path -Path $scriptRoot -ChildPath "History"
$logsDir = Join-Path -Path $scriptRoot -ChildPath "Logs"

# Auto-create directories if they don't exist
if (-not (Test-Path -Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
if (-not (Test-Path -Path $historyDir)) { New-Item -ItemType Directory -Path $historyDir -Force | Out-Null }
if (-not (Test-Path -Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }

# Migration: Move existing files to new locations if they exist in root
$filesToMoveToConfig = @("api_tester_settings.json", "api_tester_settings.json.bak", "api_tester_environments.json", "api_tester_globals.json", "api_tester_collections.json", "api_tester_monitors.json", "api_tester_workspace.apw")
foreach ($file in $filesToMoveToConfig) {
    $sourcePath = Join-Path -Path $scriptRoot -ChildPath $file
    $destPath = Join-Path -Path $configDir -ChildPath $file
    if ((Test-Path -Path $sourcePath) -and -not (Test-Path -Path $destPath)) {
        Move-Item -Path $sourcePath -Destination $destPath -Force
    }
}

$filesToMoveToHistory = @("api_tester_history.json", "api_tester_grpc_history.json", "api_tester_monitor_log.csv")
foreach ($file in $filesToMoveToHistory) {
    $sourcePath = Join-Path -Path $scriptRoot -ChildPath $file
    $destPath = Join-Path -Path $historyDir -ChildPath $file
    if ((Test-Path -Path $sourcePath) -and -not (Test-Path -Path $destPath)) {
        Move-Item -Path $sourcePath -Destination $destPath -Force
    }
}

# Migration: Move log files to Logs folder
$filesToMoveToLogs = @("api_tester.log")
foreach ($file in $filesToMoveToLogs) {
    $sourcePath = Join-Path -Path $scriptRoot -ChildPath $file
    $destPath = Join-Path -Path $logsDir -ChildPath $file
    if ((Test-Path -Path $sourcePath) -and -not (Test-Path -Path $destPath)) {
        Move-Item -Path $sourcePath -Destination $destPath -Force
    }
    # Check History folder (migration from previous version)
    $historySourcePath = Join-Path -Path $historyDir -ChildPath $file
    if ((Test-Path -Path $historySourcePath) -and -not (Test-Path -Path $destPath)) {
        Move-Item -Path $historySourcePath -Destination $destPath -Force
    }
}

# Define paths for log, history, settings, and environment configuration files.
$logFilePath = Join-Path -Path $logsDir -ChildPath "api_tester.csv"
$historyFilePath = Join-Path -Path $historyDir -ChildPath "api_tester_history.json"
$settingsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_settings.json"
$environmentsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_environments.json"
$globalsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_globals.json"
$collectionsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_collections.json"
$requestTabsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_request_tabs.json"
$requestTemplatesFilePath = Join-Path -Path $configDir -ChildPath "api_tester_request_templates.json"
$monitorsFilePath = Join-Path -Path $configDir -ChildPath "api_tester_monitors.json"
$monitorLogFilePath = Join-Path -Path $historyDir -ChildPath "api_tester_monitor_log.csv"
$grpcHistoryFilePath = Join-Path -Path $historyDir -ChildPath "api_tester_grpc_history.json"

try {
    # Load required .NET assemblies for creating the Windows Forms GUI.
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms.DataVisualization -ErrorAction SilentlyContinue
}
catch {
    # If assemblies fail to load, display an error and exit, as the GUI cannot be rendered.
    Write-Error "Failed to load Windows Forms assemblies. This script requires a graphical environment."
    Write-Host "Failed to load assemblies: $($_.Exception.Message)"
    exit
}

try {
    # High DPI Awareness & Visual Styles (Pro Enhancement)
    if ([Environment]::OSVersion.Version.Major -ge 6) {
        if (-not ([System.Management.Automation.PSTypeName]'Win32.NativeMethods').Type) {
            Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();' -Name "NativeMethods" -Namespace Win32 | Out-Null
        }
        [Win32.NativeMethods]::SetProcessDPIAware() | Out-Null
    }
    [System.Windows.Forms.Application]::EnableVisualStyles()
}
catch {
    # If assemblies fail to load, display an error and exit, as the GUI cannot be rendered.
    Write-Error "Failed to load Windows Forms assemblies. This script requires a graphical environment."
    Write-Host "Failed to load assemblies: $($_.Exception.Message)"
    exit
}

#endregion

#region UI Theme & Icons

$script:Theme = @{
    FormBackground      = [System.Drawing.ColorTranslator]::FromHtml("#f0f2f5")
    GroupBackground     = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
    TextColor           = [System.Drawing.ColorTranslator]::FromHtml("#1f1f1f")
    PrimaryButton       = [System.Drawing.ColorTranslator]::FromHtml("#0078d4")
    PrimaryButtonText   = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
    SecondaryButton     = [System.Drawing.ColorTranslator]::FromHtml("#e1e1e1")
    SecondaryButtonText = [System.Drawing.ColorTranslator]::FromHtml("#1f1f1f")
    DangerButton        = [System.Drawing.ColorTranslator]::FromHtml("#d93025")
    DangerButtonText    = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
}

#endregion

#region Core Helper Functions

# Writes a timestamped message to the log file if logging is enabled in settings.
