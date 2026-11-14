[CmdletBinding()]
param(
    [string]$RunCollection = "",
    [string]$Environment = "",
    [switch]$Headless,
    [switch]$RunMonitors,       # runs the monitors in the background with only a tray icon (no window)
    [switch]$ClassicUi,         # opens the previous WinForms window instead of the default WPF window
    [switch]$NewUi,             # kept for compatibility; the WPF window is now the default
    [string]$DataFile = "",
    [string]$OutputFormat = "Console",   # headless: Console | Json | JUnit | Html
    [int]$Retries = 0,                    # headless: retry a failing request this many times
    [string]$OpenRequestFile = ""        # internal: opens one request in its own window
)
