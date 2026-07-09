function Show-DiffViewer {
    param(
        [PSCustomObject]$Request1,
        [PSCustomObject]$Request2,
        [System.Windows.Forms.Form]$parentForm
    )

    $diffForm = New-Object System.Windows.Forms.Form -Property @{
        Text = "Diff Viewer - Compare Responses"
        Size = New-Object System.Drawing.Size(1000, 700)
        StartPosition = "CenterParent"
    }

    $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock = 'Fill'
        ColumnCount = 1
        RowCount = 2
        Padding = [System.Windows.Forms.Padding]::new(10)
    }
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 40))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $headerPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; ColumnCount = 2; RowCount = 1 }
    $headerPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null
    $headerPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null

    $lblReq1 = New-Label -Text "Old: [$($Request1.Method)] $($Request1.Url) ($($Request1.Timestamp))" -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold) }
    $lblReq2 = New-Label -Text "New: [$($Request2.Method)] $($Request2.Url) ($($Request2.Timestamp))" -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold) }
    
    $headerPanel.Controls.Add($lblReq1, 0, 0)
    $headerPanel.Controls.Add($lblReq2, 1, 0)

    $rtbDiff = New-Object System.Windows.Forms.RichTextBox -Property @{
        Dock = 'Fill'
        Font = New-Object System.Drawing.Font("Consolas", 10)
        ReadOnly = $true
        WordWrap = $false
        ScrollBars = 'Both'
    }

    $mainLayout.Controls.Add($headerPanel, 0, 0)
    $mainLayout.Controls.Add($rtbDiff, 0, 1)
    $diffForm.Controls.Add($mainLayout)

    # Theme
    if ($script:Theme) {
        $diffForm.BackColor = $script:Theme.FormBackground
        $rtbDiff.BackColor = $script:Theme.TextBoxBackground
        $rtbDiff.ForeColor = $script:Theme.TextColor
        $lblReq1.ForeColor = $script:Theme.TextColor
        $lblReq2.ForeColor = $script:Theme.TextColor
    }

    # Diff Logic
    function Format-ForDiff($body) {
        if (-not $body) { return @() }
        # Try JSON pretty print
        try {
            $json = $body | ConvertFrom-Json -ErrorAction Stop
            return ($json | ConvertTo-Json -Depth 10) -split "`r?`n"
        } catch {
            return $body -split "`r?`n"
        }
    }

    $lines1 = Format-ForDiff $Request1.ResponseBody
    $lines2 = Format-ForDiff $Request2.ResponseBody

    $diff = Compare-Object -ReferenceObject $lines1 -DifferenceObject $lines2 -IncludeEqual

    $diffForm.Add_Shown({
        $rtbDiff.SuspendLayout()
        foreach ($item in $diff) {
            $text = ""
            $color = [System.Drawing.Color]::Gray

            if ($item.SideIndicator -eq "==") {
                $text = "  " + $item.InputObject + "`n"
                $color = if ($script:Theme) { $script:Theme.TextColor } else { [System.Drawing.Color]::Black }
            } elseif ($item.SideIndicator -eq "<=") {
                $text = "- " + $item.InputObject + "`n"
                $color = [System.Drawing.Color]::IndianRed
            } elseif ($item.SideIndicator -eq "=>") {
                $text = "+ " + $item.InputObject + "`n"
                $color = [System.Drawing.Color]::MediumSeaGreen
            }

            $rtbDiff.SelectionStart = $rtbDiff.TextLength
            $rtbDiff.SelectionLength = 0
            $rtbDiff.SelectionColor = $color
            $rtbDiff.AppendText($text)
        }
        $rtbDiff.SelectionStart = 0
        $rtbDiff.ResumeLayout()
    })

    $diffForm.ShowDialog() | Out-Null
    $diffForm.Dispose()
}
