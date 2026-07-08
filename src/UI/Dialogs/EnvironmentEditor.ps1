function Show-EnvironmentEditor {
    param(
        [System.Windows.Forms.Form]$parentForm,
        [string]$EnvironmentName,
        [hashtable]$EnvironmentData
    )

    $editorForm = New-Object System.Windows.Forms.Form -Property @{
        Text          = "Edit Environment: $EnvironmentName"
        Size          = New-Object System.Drawing.Size(700, 600)
        StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        MinimumSize   = New-Object System.Drawing.Size(550, 500)
        BackColor     = $script:Theme.FormBackground
    }

    # --- Main Layout: Tab Control ---
    $editorTabControl = New-Object System.Windows.Forms.TabControl -Property @{ Dock = 'Fill' }
    $editorTabControl.Font = New-Object System.Drawing.Font($editorTabControl.Font.FontFamily, 10)

    # --- URL Panel (at the top, outside tabs) ---
    $panelUrl = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Top'; AutoSize = $true; ColumnCount = 2; Padding = [System.Windows.Forms.Padding]::new(5) }
    $panelUrl.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $panelUrl.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $labelUrl = New-Label -Text "Base URL:" -Property @{ AutoSize = $true; Anchor = 'Left'; Margin = [System.Windows.Forms.Padding]::new(0, 5, 0, 0) }
    $textUrl = New-TextBox -Property @{ Dock = 'Fill'; Text = $EnvironmentData.Url }
    $panelUrl.BackColor = $script:Theme.GroupBackground
    $panelUrl.Controls.Add($labelUrl, 0, 0); $panelUrl.Controls.Add($textUrl, 1, 0)

    # --- Headers Tab ---
    $tabHeaders = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Headers"; Padding = [System.Windows.Forms.Padding]::new(5) }
    $textHeaders = New-TextBox -Multiline $true -Property @{ Dock = 'Fill'; Text = $EnvironmentData.Headers; Font = New-Object System.Drawing.Font("Courier New", 9) }
    $tabHeaders.Controls.Add($textHeaders)

    # --- Variables Tab ---
    $tabVars = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Variables (key=value)"; Padding = [System.Windows.Forms.Padding]::new(5) }
    $textVars = New-TextBox -Multiline $true -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Courier New", 9) }
    $varStrings = $EnvironmentData.Variables.GetEnumerator() | ForEach-Object { "$($_.Name)=$($_.Value)" }
    $textVars.Text = $varStrings -join [System.Environment]::NewLine
    $tabVars.Controls.Add($textVars)

    # --- Authentication Tab ---
    $authResult = New-AuthPanel -AuthData $EnvironmentData.Authentication
    $tabAuth = $authResult.Tab

    $editorTabControl.TabPages.AddRange(@($tabHeaders, $tabAuth, $tabVars))

    # --- Bottom Panel for Save/Cancel ---
    $panelBottom = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Bottom'; Height = 40; Padding = [System.Windows.Forms.Padding]::new(5) }
    $btnSave = New-Button -Text "Save" -Style 'Primary' -Property @{ Dock = 'Right'; Width = 100 } -OnClick {
        # Collect data from controls and update the original hashtable
        $EnvironmentData.Url = $textUrl.Text
        $EnvironmentData.Headers = $textHeaders.Text
        
        # Collect Authentication details by calling the helper on the auth panel
        $EnvironmentData.Authentication = & $authResult.GetAuthData
        
        # Parse variables back into a hashtable
        $newVars = @{}
        $textVars.Lines | ForEach-Object {
            if ($_ -match '^\s*([^=]+?)\s*=(.*)$') {
                $newVars[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        $EnvironmentData.Variables = $newVars

        $editorForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $editorForm.Close()
    }
    $btnCancel = New-Button -Text "Cancel" -Style 'Secondary' -Property @{ Dock = 'Right'; Width = 100 } -OnClick {
        $editorForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $editorForm.Close()
    }
    $panelBottom.Controls.AddRange(@($btnCancel, $btnSave)) # Add in reverse for right-docking

    $editorForm.Controls.AddRange(@($editorTabControl, $panelUrl, $panelBottom))
    return $editorForm.ShowDialog($parentForm)
}

# --- Reusable function to create a complete, self-contained Authentication Panel ---
