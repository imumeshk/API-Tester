#region Charts
# A small line-chart renderer for WPF canvases (no external charting assembly needed).

function ConvertTo-WpfBrush {
    param([string]$Color)
    return New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($Color))
}

function New-ChartLabel {
    param([string]$Text, [double]$Left, [double]$Top, [string]$Color, [double]$FontSize = 11, [string]$Align = 'Left')
    $label = New-Object System.Windows.Controls.TextBlock
    $label.Text = $Text; $label.FontSize = $FontSize; $label.Foreground = ConvertTo-WpfBrush $Color
    if ($Align -eq 'Right') { $label.Width = 50; $label.TextAlignment = 'Right'; $Left = $Left - 50 }
    [System.Windows.Controls.Canvas]::SetLeft($label, $Left); [System.Windows.Controls.Canvas]::SetTop($label, $Top)
    return $label
}

# Draws one or two series. Each series: @{ Name; Color; X = double[] (ticks or indexes); Y = double[]; Axis = 'Left'|'Right' }.
# XAsTime formats the X ticks as dates; otherwise X values are shown as plain numbers.
function Update-LineChart {
    param($Canvas, $Series, [string]$LeftTitle = '', [string]$RightTitle = '', [switch]$XAsTime, [string]$TimeFormat = 'HH:mm', [string]$EmptyText = 'No data to display.')

    $Canvas.Children.Clear()
    $width = $Canvas.ActualWidth; $height = $Canvas.ActualHeight
    if ($width -lt 140 -or $height -lt 110) { return }
    $textColor = ConvertTo-HexColor $script:Theme.TextColor
    $mutedColor = ConvertTo-HexColor $script:Theme.MutedText
    $gridColor = ConvertTo-HexColor $script:Theme.BorderColor
    $seriesList = @($Series | Where-Object { $_ -and @($_.Y).Count -gt 0 })
    if ($seriesList.Count -eq 0) { [void]$Canvas.Children.Add((New-ChartLabel -Text $EmptyText -Left 20 -Top 20 -Color $mutedColor -FontSize 13)); return }

    $hasRight = [bool]($seriesList | Where-Object { $_.Axis -eq 'Right' })
    $plotLeft = 58; $plotRight = $width - $(if ($hasRight) { 58 } else { 18 }); $plotTop = 26; $plotBottom = $height - 34
    $plotWidth = $plotRight - $plotLeft; $plotHeight = $plotBottom - $plotTop
    if ($plotWidth -lt 40 -or $plotHeight -lt 40) { return }

    $allX = @($seriesList | ForEach-Object { $_.X } | ForEach-Object { [double]$_ })
    $minX = ($allX | Measure-Object -Minimum).Minimum; $maxX = ($allX | Measure-Object -Maximum).Maximum
    if ($maxX -le $minX) { $maxX = $minX + 1 }
    $axisMax = @{}
    foreach ($axis in @('Left', 'Right')) {
        $values = @($seriesList | Where-Object { ($_.Axis -eq 'Right') -eq ($axis -eq 'Right') } | ForEach-Object { $_.Y } | ForEach-Object { [double]$_ })
        $maximum = if ($values.Count -gt 0) { ($values | Measure-Object -Maximum).Maximum } else { 1 }
        $axisMax[$axis] = if ($maximum -le 0) { 1 } else { $maximum * 1.1 }
    }

    for ($step = 0; $step -le 4; $step++) {
        $y = $plotBottom - ($plotHeight * $step / 4)
        $line = New-Object System.Windows.Shapes.Line
        $line.X1 = $plotLeft; $line.X2 = $plotRight; $line.Y1 = $y; $line.Y2 = $y; $line.Stroke = ConvertTo-WpfBrush $gridColor; $line.StrokeThickness = 1
        [void]$Canvas.Children.Add($line)
        [void]$Canvas.Children.Add((New-ChartLabel -Text ('{0:N0}' -f ($axisMax['Left'] * $step / 4)) -Left ($plotLeft - 6) -Top ($y - 8) -Color $mutedColor -Align 'Right'))
        if ($hasRight) { [void]$Canvas.Children.Add((New-ChartLabel -Text ('{0:N0}' -f ($axisMax['Right'] * $step / 4)) -Left ($plotRight + 8) -Top ($y - 8) -Color $mutedColor)) }
    }
    for ($tick = 0; $tick -le 5; $tick++) {
        $value = $minX + (($maxX - $minX) * $tick / 5)
        $x = $plotLeft + ($plotWidth * $tick / 5)
        $text = if ($XAsTime) { try { ([datetime][long]$value).ToString($TimeFormat) } catch { '' } } else { '{0:N0}' -f $value }
        [void]$Canvas.Children.Add((New-ChartLabel -Text $text -Left ($x - 22) -Top ($plotBottom + 6) -Color $mutedColor))
    }
    if ($LeftTitle) { [void]$Canvas.Children.Add((New-ChartLabel -Text $LeftTitle -Left 6 -Top 4 -Color $textColor -FontSize 11)) }
    if ($RightTitle -and $hasRight) { [void]$Canvas.Children.Add((New-ChartLabel -Text $RightTitle -Left ($plotRight - 40) -Top 4 -Color $textColor -FontSize 11)) }

    $legendLeft = $plotLeft + 120
    foreach ($entry in $seriesList) {
        $axis = if ($entry.Axis -eq 'Right') { 'Right' } else { 'Left' }
        $polyline = New-Object System.Windows.Shapes.Polyline
        $polyline.Stroke = ConvertTo-WpfBrush $entry.Color; $polyline.StrokeThickness = 2; $polyline.StrokeLineJoin = 'Round'
        $xs = @($entry.X); $ys = @($entry.Y)
        for ($index = 0; $index -lt $ys.Count; $index++) {
            $x = $plotLeft + $plotWidth * (([double]$xs[$index] - $minX) / ($maxX - $minX))
            $y = $plotBottom - $plotHeight * ([double]$ys[$index] / $axisMax[$axis])
            [void]$polyline.Points.Add([System.Windows.Point]::new($x, $y))
        }
        [void]$Canvas.Children.Add($polyline)
        [void]$Canvas.Children.Add((New-ChartLabel -Text ([string][char]0x25CF + ' ' + $entry.Name) -Left $legendLeft -Top 4 -Color $entry.Color -FontSize 11))
        $legendLeft += 130
    }
}

# Saves a WPF element (for example the chart canvas) as a PNG file.
function Save-ElementAsPng {
    param($Element, [string]$Path)
    $width = [int][Math]::Max(1, $Element.ActualWidth); $height = [int][Math]::Max(1, $Element.ActualHeight)
    $bitmap = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($width, $height, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($Element)
    $encoder = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $stream = [System.IO.File]::Create($Path)
    try { $encoder.Save($stream) } finally { $stream.Dispose() }
}

# Lets the UI repaint during a short blocking operation.
function Update-UiNow {
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
}
#endregion
