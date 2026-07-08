function New-Label {
    param (
        [string]$Text,
        [Parameter(Mandatory=$false)][System.Drawing.Point]$Location,
        [Parameter(Mandatory=$false)][System.Drawing.Size]$Size,
        [Parameter(Mandatory=$false)][hashtable]$Property
    )
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    if ($Location) { $label.Location = $Location }
    if ($Size) { $label.Size = $Size }
    if ($Property) {
        foreach ($p in $Property.Keys) {
            try { $label.$p = $Property[$p] } catch { }
        }
    }
    return $label
}

# Factory function to create a System.Windows.Forms.TextBox control.
function New-TextBox {
    param (
        [Parameter(Mandatory=$false)][System.Drawing.Point]$Location,
        [Parameter(Mandatory=$false)][System.Drawing.Size]$Size,
        [Parameter(Mandatory=$false)][bool]$Multiline,
        [Parameter(Mandatory=$false)][hashtable]$Property
    )
    $textBox = New-Object System.Windows.Forms.TextBox
    if ($Location) { $textBox.Location = $Location }
    if ($Size) { $textBox.Size = $Size }
    if ($PSBoundParameters.ContainsKey('Multiline')) { $textBox.Multiline = $Multiline }
    if ($Property) {
        foreach ($p in $Property.Keys) {
            try { $textBox.$p = $Property[$p] } catch { }
        }
    }
    return $textBox
}

# Factory function to create a System.Windows.Forms.Button control.
function New-Button {
    param (
        [string]$Text,
        [Parameter(Mandatory=$false)][System.Drawing.Point]$Location,
        [Parameter(Mandatory=$false)][System.Drawing.Size]$Size,
        [scriptblock]$OnClick,
        [Parameter(Mandatory=$false)][hashtable]$Property,
        [Parameter(Mandatory=$false)][ValidateSet('Primary', 'Secondary', 'Danger')][string]$Style = 'Secondary'
    )
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    if ($Location) { $button.Location = $Location }
    if ($Size) { $button.Size = $Size }

    # Apply modern styling
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderSize = 0
    $button.Font = New-Object System.Drawing.Font($button.Font.FontFamily, 9, [System.Drawing.FontStyle]::Bold)

    switch ($Style) {
        'Primary' {
            $button.BackColor = $script:Theme.PrimaryButton
            $button.ForeColor = $script:Theme.PrimaryButtonText
        }
        'Danger' {
            $button.BackColor = $script:Theme.DangerButton
            $button.ForeColor = $script:Theme.DangerButtonText
        }
        default { # Secondary
            $button.BackColor = $script:Theme.SecondaryButton
            $button.ForeColor = $script:Theme.SecondaryButtonText
        }
    }

    if ($Property) {
        foreach ($p in $Property.Keys) {
            try { $button.$p = $Property[$p] } catch { }
        }
    }
    $button.Add_Click($OnClick)
    return $button
}

# Factory function to create a System.Windows.Forms.RichTextBox control.
function New-RichTextBox {
    param (
        [Parameter(Mandatory=$false)][System.Drawing.Point]$Location,
        [Parameter(Mandatory=$false)][System.Drawing.Size]$Size,
        [Parameter(Mandatory=$false)][bool]$ReadOnly,
        [Parameter(Mandatory=$false)][hashtable]$Property
    )
    $richTextBox = New-Object System.Windows.Forms.RichTextBox
    if ($Location) { $richTextBox.Location = $Location }
    if ($Size) { $richTextBox.Size = $Size }
    $richTextBox.ReadOnly = $ReadOnly
    if ($Property) {
        foreach ($p in $Property.Keys) {
            try { $richTextBox.$p = $Property[$p] } catch { }
        }
    }
    $richTextBox.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Both
    $richTextBox.WordWrap = $false
    return $richTextBox
}

# Creates a context menu with a "Copy" item for a given text-based control.
function New-CopyContextMenu {
    param([System.Windows.Forms.TextBoxBase]$ParentControl)

    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

    $copyMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Copy")
    $copyMenuItem.Tag = $ParentControl # Store the control reference
    $copyMenuItem.Add_Click({
        $controlToCopy = $this.Tag # Retrieve the correct text box
        if ($controlToCopy.SelectionLength -gt 0) {
            # If there's a selection, copy just the selection
            $controlToCopy.Copy()
        } elseif (-not [string]::IsNullOrEmpty($controlToCopy.Text)) {
            # Otherwise, if there's any text at all, copy all of it
            [System.Windows.Forms.Clipboard]::SetText($controlToCopy.Text)
        }
    })

    [void]$contextMenu.Add_Opening({
        param($sender, $e)
        # Enable the "Copy" item only if the associated control contains text or has a selection.
        # The 'sender' is the context menu. We retrieve the copyMenuItem from its Items collection.
        $menuItem = $sender.Items[0]
        $menuItem.Enabled = (-not [string]::IsNullOrEmpty($menuItem.Tag.Text) -or $menuItem.Tag.SelectionLength -gt 0)
    })

    [void]$contextMenu.Items.Add($copyMenuItem)
    return $contextMenu
}

# Simple JSON path evaluator (e.g. $.data.token or data.items[0].id)
