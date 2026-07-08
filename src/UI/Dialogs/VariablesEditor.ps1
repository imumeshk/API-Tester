function Show-VariablesEditor {
    param(
        [System.Windows.Forms.Form]$parentForm,
        [string]$Title,
        [hashtable]$Variables
    )

    $form = New-Object System.Windows.Forms.Form -Property @{
        Text          = $Title
        Size          = New-Object System.Drawing.Size(600, 500)
        StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
        BackColor     = $script:Theme.FormBackground
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        MinimumSize   = New-Object System.Drawing.Size(500, 400)
    }

    $layout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock        = 'Fill'
        ColumnCount = 1
        RowCount    = 3
        Padding     = [System.Windows.Forms.Padding]::new(10)
    }
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $lblHint = New-Label -Text "Enter variables as key=value (one per line)." -Property @{ AutoSize = $true }
    $txtVars = New-TextBox -Multiline $true -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Courier New", 9); ScrollBars = 'Vertical' }

    if ($Variables) {
        $lines = $Variables.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $txtVars.Text = $lines -join [System.Environment]::NewLine
    }

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ FlowDirection = 'RightToLeft'; Dock = 'Fill'; AutoSize = $true }
    $btnSave = New-Button -Text "Save" -Style 'Primary' -Property @{ Width = 100; Height = 32 } -OnClick {
        $newVars = @{}
        foreach ($line in $txtVars.Lines) {
            if ($line -match '^\s*([^=]+?)\s*=(.*)$') {
                $newVars[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        $form.Tag = $newVars
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    }
    $btnCancel = New-Button -Text "Cancel" -Style 'Secondary' -Property @{ Width = 100; Height = 32 } -OnClick {
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    }
    $buttons.Controls.AddRange(@($btnSave, $btnCancel))

    $layout.Controls.Add($lblHint, 0, 0)
    $layout.Controls.Add($txtVars, 0, 1)
    $layout.Controls.Add($buttons, 0, 2)

    $form.Controls.Add($layout)
    $result = $form.ShowDialog($parentForm)
    return [PSCustomObject]@{
        Result    = $result
        Variables = $form.Tag
    }
}

# --- REFACTORED: Environment Editor Window ---
