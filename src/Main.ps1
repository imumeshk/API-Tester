
# -----------------------------------------------------------------------------
# Execute Application
# -----------------------------------------------------------------------------
try {
    Write-Log "Starting PowerShell API Tester v$($script:AppVersion)..."
    New-APIForm
} catch {
    Write-Log "FATAL ERROR: $_" -Level Error
    [System.Windows.Forms.MessageBox]::Show("A fatal error occurred: $_", "Fatal Error", 'OK', 'Error')
}
