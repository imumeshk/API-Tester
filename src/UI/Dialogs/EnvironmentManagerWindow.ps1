function Show-EnvironmentManagerWindow {
    param (
        [System.Windows.Forms.Form]$parentForm
    )

    $envManagerForm = New-Object System.Windows.Forms.Form -Property @{
        Text          = "Manage Environments"
        Size          = New-Object System.Drawing.Size(550, 550)
        StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        MinimumSize   = New-Object System.Drawing.Size(400, 450)
        BackColor     = $script:Theme.FormBackground
    }

    $listEnvironments = New-Object System.Windows.Forms.ListBox -Property @{ Dock = 'Fill' }
    $script:environments.Keys | Sort-Object | ForEach-Object { $listEnvironments.Items.Add($_) }

    # --- Button Panel ---
    $panelButtons = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Right'; Width = 180; Padding = [System.Windows.Forms.Padding]::new(10); FlowDirection = 'TopDown' }
    $btnAdd = New-Button -Text "Add..." -Style 'Secondary' -Property @{ Width = 150; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,0,8) } -OnClick {
        $newEnvName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter new environment name:", "Add Environment", "New Environment")
        if ($newEnvName -and -not $script:environments.ContainsKey($newEnvName)) {
            # Create a new, empty data structure for the environment
            $newEnvData = @{ Url = ""; Headers = ""; Authentication = @{ Type = "No Auth" }; Variables = @{} }
            # Open the editor with the new data
            $result = Show-EnvironmentEditor -parentForm $envManagerForm -EnvironmentName $newEnvName -EnvironmentData $newEnvData
            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                $script:environments[$newEnvName] = $newEnvData
                $listEnvironments.Items.Add($newEnvName)
                $listEnvironments.SelectedItem = $newEnvName
                Save-Environments
            }
        }
    }
    $btnEdit = New-Button -Text "Edit..." -Style 'Secondary' -Property @{ Width = 150; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,0,8) } -OnClick {
        $selected = $listEnvironments.SelectedItem
        if ($selected) {
            # Get a clone of the data to edit, so changes are only saved on "OK"
            $envData = $script:environments[$selected].Clone()
            $result = Show-EnvironmentEditor -parentForm $envManagerForm -EnvironmentName $selected -EnvironmentData $envData
            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                $script:environments[$selected] = $envData # Update with changes
                Save-Environments
            }
        }
    }
    $btnRemove = New-Button -Text "Remove" -Style 'Danger' -Property @{ Width = 150; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,0,0,8) } -OnClick {
        $selected = $listEnvironments.SelectedItem
        if ($selected) {
            $confirm = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to remove the '$selected' environment?", "Confirm Removal", "YesNo", "Warning")
            if ($confirm -eq 'Yes') {
                $script:environments.Remove($selected)
                $listEnvironments.Items.Remove($selected)
                Save-Environments
            }
        }
    }
    $btnSaveCurrent = New-Button -Text "Save Current..." -Style 'Secondary' -Property @{ Width = 150; Margin = [System.Windows.Forms.Padding]::new(0,15,0,8); Height = 45 } -OnClick {
        $newEnvName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter name for new environment:", "Save Current Configuration", "My Saved Request")
        if ($newEnvName -and -not $script:environments.ContainsKey($newEnvName)) {
            $newEnvData = @{
                Url       = $script:textUrl.Text
                Headers   = $script:textHeaders.Text
                Variables = @{} # Start with empty variables
                Authentication = (& $script:authPanel.GetAuthData) # Get auth data from main form's panel
            }

            $script:environments[$newEnvName] = $newEnvData
            $listEnvironments.Items.Add($newEnvName)
            $listEnvironments.SelectedItem = $newEnvName
            Save-Environments
            [System.Windows.Forms.MessageBox]::Show("Current configuration saved as new environment '$newEnvName'.", "Success", "OK", "Information")
        } elseif ($newEnvName) {
            [System.Windows.Forms.MessageBox]::Show("An environment with that name already exists.", "Error", "OK", "Error")
        }
    }
    $toolTip.SetToolTip($btnSaveCurrent, "Saves the URL, Headers, and Authentication settings from the main window as a new environment.")

    $btnClose = New-Button -Text "Close" -Style 'Primary' -Property @{ Width = 150; Height = 35; Margin = [System.Windows.Forms.Padding]::new(0,50,0,0) } -OnClick {
        Save-Environments
        $envManagerForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $envManagerForm.Close()
    }
    $panelButtons.Controls.AddRange(@($btnAdd, $btnEdit, $btnRemove, $btnSaveCurrent, $btnClose))
    
    $envManagerForm.Controls.AddRange(@($listEnvironments, $panelButtons))
    $envManagerForm.ShowDialog($parentForm)
}

# --- Log Viewer Window ---
