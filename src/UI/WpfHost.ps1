#region WPF Host
# XAML-based dialogs, in the same style as the Litera Compare tester: the view is an embedded XAML string,
# loaded with XamlReader, and controls are looked up by x:Name. The XAML shares one resource block that is
# generated from $script:Theme, so WPF dialogs always match the WinForms window and the Light/Dark setting.

function Initialize-WpfSupport {
    if ($script:WpfSupportLoaded) { return }
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    # Lets WinForms dialogs opened from a WPF window handle keyboard input (Tab, Enter, arrows) correctly.
    try { Add-Type -AssemblyName WindowsFormsIntegration; [System.Windows.Forms.Integration.WindowsFormsHost]::EnableWindowsFormsInterop() } catch { }
    $script:WpfSupportLoaded = $true
}

function ConvertTo-HexColor {
    param([System.Drawing.Color]$Color)
    return ('#{0:X2}{1:X2}{2:X2}' -f $Color.R, $Color.G, $Color.B)
}

# Returns the shared <Window.Resources> content (brushes + control styles) built from the active theme.
function Get-WpfResourcesXaml {
    $tokens = @{
        '@PRIMARY@'      = ConvertTo-HexColor $script:Theme.PrimaryButton
        '@PRIMARYTEXT@'  = ConvertTo-HexColor $script:Theme.PrimaryButtonText
        '@SOFT@'         = ConvertTo-HexColor $script:Theme.SecondaryButton
        '@SOFTTEXT@'     = ConvertTo-HexColor $script:Theme.SecondaryButtonText
        '@SURFACE@'      = ConvertTo-HexColor $script:Theme.GroupBackground
        '@INPUT@'        = ConvertTo-HexColor $script:Theme.TextBoxBackground
        '@BORDER@'       = ConvertTo-HexColor $script:Theme.BorderColor
        '@TEXT@'         = ConvertTo-HexColor $script:Theme.TextColor
        '@MUTED@'        = ConvertTo-HexColor $script:Theme.MutedText
        '@FORM@'         = ConvertTo-HexColor $script:Theme.FormBackground
        '@SCROLLTHUMB@'  = $(if ($script:settings.AppTheme -eq 'Dark') { '#3A4A6B' } else { '#C3CCDA' })
    }
    $xaml = @'
<SolidColorBrush x:Key="Primary" Color="@PRIMARY@"/>
<SolidColorBrush x:Key="Soft" Color="@SOFT@"/>
<SolidColorBrush x:Key="SoftText" Color="@SOFTTEXT@"/>
<SolidColorBrush x:Key="Surface" Color="@SURFACE@"/>
<SolidColorBrush x:Key="Border" Color="@BORDER@"/>
<SolidColorBrush x:Key="Muted" Color="@MUTED@"/>
<SolidColorBrush x:Key="Text" Color="@TEXT@"/>
<SolidColorBrush x:Key="Form" Color="@FORM@"/>
<SolidColorBrush x:Key="Input" Color="@INPUT@"/>
<SolidColorBrush x:Key="PrimaryText" Color="@PRIMARYTEXT@"/>
<SolidColorBrush x:Key="ScrollThumb" Color="@SCROLLTHUMB@"/>
<Style TargetType="Button">
  <Setter Property="Padding" Value="14,7"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/>
  <Setter Property="Background" Value="{StaticResource Soft}"/><Setter Property="Foreground" Value="{StaticResource SoftText}"/>
  <Setter Property="BorderThickness" Value="0"/><Setter Property="HorizontalContentAlignment" Value="Center"/><Setter Property="VerticalContentAlignment" Value="Center"/>
  <Setter Property="Template"><Setter.Value>
    <ControlTemplate TargetType="Button">
      <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
        <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}" RecognizesAccessKey="True"/>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.85"/></Trigger>
        <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.7"/></Trigger>
        <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{StaticResource Primary}"/><Setter TargetName="Bd" Property="BorderThickness" Value="1"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Bd" Property="Opacity" Value="0.45"/></Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>
  </Setter.Value></Setter>
</Style>
<Style x:Key="PrimaryButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
  <Setter Property="Background" Value="{StaticResource Primary}"/><Setter Property="Foreground" Value="{DynamicResource PrimaryText}"/>
</Style>
<Style x:Key="SmallButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}"><Setter Property="Padding" Value="10,4"/><Setter Property="Margin" Value="0,0,6,0"/></Style>
<Style TargetType="TextBox">
  <Setter Property="Padding" Value="8,5"/><Setter Property="Background" Value="{DynamicResource Input}"/>
  <Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/>
</Style>
<Style TargetType="PasswordBox">
  <Setter Property="Padding" Value="8,5"/><Setter Property="Background" Value="{DynamicResource Input}"/>
  <Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/>
</Style>
<Style TargetType="ComboBox">
  <Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Background" Value="{DynamicResource Input}"/>
  <Setter Property="BorderBrush" Value="{StaticResource Border}"/><Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding" Value="10,4,30,4"/><Setter Property="SnapsToDevicePixels" Value="True"/><Setter Property="Cursor" Value="Hand"/>
  <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Disabled"/><Setter Property="ScrollViewer.VerticalScrollBarVisibility" Value="Auto"/>
  <Setter Property="MaxDropDownHeight" Value="360"/>
  <Setter Property="Template"><Setter.Value>
    <ControlTemplate TargetType="ComboBox">
      <Grid>
        <ToggleButton x:Name="DropDownToggle" Focusable="False" ClickMode="Press" IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}">
          <ToggleButton.Template>
            <ControlTemplate TargetType="ToggleButton">
              <Border x:Name="Bd" CornerRadius="6" BorderThickness="1" SnapsToDevicePixels="True"
                      Background="{Binding Background, RelativeSource={RelativeSource AncestorType=ComboBox}}"
                      BorderBrush="{Binding BorderBrush, RelativeSource={RelativeSource AncestorType=ComboBox}}">
                <Path x:Name="Arrow" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,11,0" Data="M 0 0 L 4.5 4.5 L 9 0" Stroke="{StaticResource Muted}" StrokeThickness="1.6"/>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{StaticResource Primary}"/><Setter TargetName="Arrow" Property="Stroke" Value="{StaticResource Primary}"/></Trigger>
                <Trigger Property="IsChecked" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{StaticResource Primary}"/><Setter TargetName="Arrow" Property="Stroke" Value="{StaticResource Primary}"/></Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
          </ToggleButton.Template>
        </ToggleButton>
        <ContentPresenter x:Name="ContentSite" IsHitTestVisible="False" Margin="{TemplateBinding Padding}" HorizontalAlignment="Left"
                          VerticalAlignment="{TemplateBinding VerticalContentAlignment}" Content="{TemplateBinding SelectionBoxItem}"
                          ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}" ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"/>
        <Popup x:Name="PART_Popup" Placement="Bottom" IsOpen="{TemplateBinding IsDropDownOpen}" AllowsTransparency="True" Focusable="False" PopupAnimation="Fade">
          <Border x:Name="DropDownBorder" Margin="0,4,0,0" Padding="4" CornerRadius="6" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1"
                  MinWidth="{Binding ActualWidth, RelativeSource={RelativeSource TemplatedParent}}" MaxHeight="{TemplateBinding MaxDropDownHeight}">
            <ScrollViewer SnapsToDevicePixels="True"><StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Contained"/></ScrollViewer>
          </Border>
        </Popup>
      </Grid>
      <ControlTemplate.Triggers>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/></Trigger>
        <Trigger Property="HasItems" Value="False"><Setter TargetName="DropDownBorder" Property="MinHeight" Value="36"/></Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>
  </Setter.Value></Setter>
</Style>
<Style TargetType="ComboBoxItem">
  <Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Padding" Value="10,6"/><Setter Property="Cursor" Value="Hand"/>
  <Setter Property="Template"><Setter.Value>
    <ControlTemplate TargetType="ComboBoxItem">
      <Border x:Name="Bd" Background="Transparent" CornerRadius="4" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True"><ContentPresenter/></Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsHighlighted" Value="True"><Setter TargetName="Bd" Property="Background" Value="{StaticResource Soft}"/></Trigger>
        <Trigger Property="IsSelected" Value="True"><Setter TargetName="Bd" Property="Background" Value="{StaticResource Soft}"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Foreground" Value="{StaticResource Primary}"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/></Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>
  </Setter.Value></Setter>
</Style>
<Style TargetType="CheckBox"><Setter Property="Foreground" Value="{StaticResource Text}"/></Style>
<Style TargetType="TabControl">
  <Setter Property="Padding" Value="0"/><Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Template"><Setter.Value>
    <ControlTemplate TargetType="TabControl">
      <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" SnapsToDevicePixels="True">
        <Grid>
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border BorderBrush="{StaticResource Border}" BorderThickness="0,0,0,1" Padding="6,2,6,0"><TabPanel IsItemsHost="True" Background="Transparent"/></Border>
          <ContentPresenter x:Name="PART_SelectedContentHost" Grid.Row="1" ContentSource="SelectedContent" Margin="{TemplateBinding Padding}"/>
        </Grid>
      </Border>
    </ControlTemplate>
  </Setter.Value></Setter>
</Style>
<Style TargetType="TabItem">
  <Setter Property="Padding" Value="14,8"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/>
  <Setter Property="Template"><Setter.Value>
    <ControlTemplate TargetType="TabItem">
      <Border x:Name="Bd" Background="Transparent" BorderBrush="Transparent" BorderThickness="0,0,0,2" Padding="{TemplateBinding Padding}" Margin="0,0,2,0" CornerRadius="4,4,0,0">
        <ContentPresenter x:Name="Hd" ContentSource="Header" RecognizesAccessKey="True" HorizontalAlignment="Center" VerticalAlignment="Center" TextElement.Foreground="{StaticResource Muted}"/>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="{StaticResource Soft}"/></Trigger>
        <Trigger Property="IsSelected" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{StaticResource Primary}"/><Setter TargetName="Hd" Property="TextElement.Foreground" Value="{StaticResource Primary}"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Bd" Property="Opacity" Value="0.45"/></Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>
  </Setter.Value></Setter>
</Style>
<Style TargetType="Menu"><Setter Property="Background" Value="Transparent"/></Style>
<Style x:Key="{x:Static MenuItem.SeparatorStyleKey}" TargetType="Separator">
  <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Separator"><Border Height="1" Margin="8,4" Background="{StaticResource Border}"/></ControlTemplate></Setter.Value></Setter>
</Style>
<Style TargetType="MenuItem">
  <Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Cursor" Value="Hand"/>
  <Setter Property="Template"><Setter.Value>
    <ControlTemplate TargetType="MenuItem">
      <Border x:Name="Bd" Background="Transparent" CornerRadius="4" Padding="10,6" SnapsToDevicePixels="True">
        <Grid>
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <ContentPresenter ContentSource="Header" RecognizesAccessKey="True" VerticalAlignment="Center"/>
          <TextBlock x:Name="Gesture" Grid.Column="1" Text="{TemplateBinding InputGestureText}" Margin="28,0,0,0" Foreground="{StaticResource Muted}" VerticalAlignment="Center"/>
          <Popup x:Name="PART_Popup" Placement="Bottom" VerticalOffset="4" AllowsTransparency="True" Focusable="False" PopupAnimation="Fade"
                 IsOpen="{Binding IsSubmenuOpen, RelativeSource={RelativeSource TemplatedParent}}">
            <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="6" Padding="4" MinWidth="240">
              <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Cycle"/>
            </Border>
          </Popup>
        </Grid>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsHighlighted" Value="True"><Setter TargetName="Bd" Property="Background" Value="{StaticResource Soft}"/></Trigger>
        <Trigger Property="IsSubmenuOpen" Value="True"><Setter TargetName="Bd" Property="Background" Value="{StaticResource Soft}"/></Trigger>
        <Trigger Property="Role" Value="TopLevelHeader"><Setter TargetName="Gesture" Property="Visibility" Value="Collapsed"/><Setter TargetName="Bd" Property="Padding" Value="12,6"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Bd" Property="Opacity" Value="0.45"/></Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>
  </Setter.Value></Setter>
</Style>
<Style TargetType="ContextMenu">
  <Setter Property="Template"><Setter.Value>
    <ControlTemplate TargetType="ContextMenu">
      <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="6" Padding="4" MinWidth="200">
        <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Cycle"/>
      </Border>
    </ControlTemplate>
  </Setter.Value></Setter>
</Style>
<Style TargetType="DataGridCell">
  <Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="6,3"/><Setter Property="FocusVisualStyle" Value="{x:Null}"/>
  <Setter Property="Template"><Setter.Value>
    <ControlTemplate TargetType="DataGridCell">
      <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
        <ContentPresenter VerticalAlignment="Center" SnapsToDevicePixels="{TemplateBinding SnapsToDevicePixels}"/>
      </Border>
    </ControlTemplate>
  </Setter.Value></Setter>
  <Style.Triggers>
    <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource Soft}"/><Setter Property="Foreground" Value="{DynamicResource Text}"/></Trigger>
  </Style.Triggers>
</Style>
<Style TargetType="DataGridColumnHeader">
  <Setter Property="Background" Value="{StaticResource Surface}"/><Setter Property="Foreground" Value="{StaticResource Muted}"/>
  <Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Padding" Value="8,6"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/><Setter Property="BorderThickness" Value="0,0,1,1"/>
</Style>
<Style x:Key="ScrollThumbStyle" TargetType="Thumb">
  <Setter Property="Template"><Setter.Value>
    <ControlTemplate TargetType="Thumb">
      <Border x:Name="Bd" CornerRadius="4" Background="{DynamicResource ScrollThumb}"/>
      <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="{DynamicResource Muted}"/></Trigger>
        <Trigger Property="IsDragging" Value="True"><Setter TargetName="Bd" Property="Background" Value="{DynamicResource Primary}"/></Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>
  </Setter.Value></Setter>
</Style>
<Style x:Key="ScrollPageButton" TargetType="RepeatButton">
  <Setter Property="Focusable" Value="False"/><Setter Property="IsTabStop" Value="False"/>
  <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="RepeatButton"><Border Background="Transparent"/></ControlTemplate></Setter.Value></Setter>
</Style>
<Style TargetType="ScrollBar">
  <Setter Property="Background" Value="Transparent"/><Setter Property="Width" Value="10"/><Setter Property="MinWidth" Value="10"/>
  <Setter Property="Template"><Setter.Value>
    <ControlTemplate TargetType="ScrollBar">
      <Grid Background="{TemplateBinding Background}">
        <Track x:Name="PART_Track" IsDirectionReversed="True">
          <Track.DecreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPageButton}" Command="ScrollBar.PageUpCommand"/></Track.DecreaseRepeatButton>
          <Track.Thumb><Thumb Style="{StaticResource ScrollThumbStyle}" Margin="2"/></Track.Thumb>
          <Track.IncreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPageButton}" Command="ScrollBar.PageDownCommand"/></Track.IncreaseRepeatButton>
        </Track>
      </Grid>
    </ControlTemplate>
  </Setter.Value></Setter>
  <Style.Triggers>
    <Trigger Property="Orientation" Value="Horizontal">
      <Setter Property="Width" Value="Auto"/><Setter Property="MinWidth" Value="0"/><Setter Property="Height" Value="10"/><Setter Property="MinHeight" Value="10"/>
      <Setter Property="Template"><Setter.Value>
        <ControlTemplate TargetType="ScrollBar">
          <Grid Background="{TemplateBinding Background}">
            <Track x:Name="PART_Track" IsDirectionReversed="False">
              <Track.DecreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPageButton}" Command="ScrollBar.PageLeftCommand"/></Track.DecreaseRepeatButton>
              <Track.Thumb><Thumb Style="{StaticResource ScrollThumbStyle}" Margin="2"/></Track.Thumb>
              <Track.IncreaseRepeatButton><RepeatButton Style="{StaticResource ScrollPageButton}" Command="ScrollBar.PageRightCommand"/></Track.IncreaseRepeatButton>
            </Track>
          </Grid>
        </ControlTemplate>
      </Setter.Value></Setter>
    </Trigger>
  </Style.Triggers>
</Style>
<Style x:Key="SectionLabel" TargetType="TextBlock">
  <Setter Property="FontSize" Value="11"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Foreground" Value="{StaticResource Muted}"/>
</Style>
'@
    foreach ($token in $tokens.Keys) { $xaml = $xaml.Replace($token, $tokens[$token]) }
    return $xaml
}

# Loads a XAML window. Put <!--APP_RESOURCES--> inside <Window.Resources> to pull in the shared styles and
# use @FORM@ / @TEXT@ for the theme's window background and text colors.
# Returns @{ Window = <Window>; Controls = <x:Name -> element> }.
# Brush resource key -> colour for the active theme. Every colour in the XAML is a DynamicResource on one of these
# keys, so a theme change only has to replace the brushes (Set-WpfThemeResources) for every open window to repaint.
$script:ThemeBrushKeys = @('Primary', 'PrimaryText', 'Soft', 'SoftText', 'Surface', 'Border', 'Muted', 'Text', 'Form', 'Input', 'ScrollThumb')

function Get-ThemeBrushColors {
    return @{
        Primary = ConvertTo-HexColor $script:Theme.PrimaryButton; PrimaryText = ConvertTo-HexColor $script:Theme.PrimaryButtonText
        Soft = ConvertTo-HexColor $script:Theme.SecondaryButton; SoftText = ConvertTo-HexColor $script:Theme.SecondaryButtonText
        Surface = ConvertTo-HexColor $script:Theme.GroupBackground; Border = ConvertTo-HexColor $script:Theme.BorderColor
        Muted = ConvertTo-HexColor $script:Theme.MutedText; Text = ConvertTo-HexColor $script:Theme.TextColor
        Form = ConvertTo-HexColor $script:Theme.FormBackground; Input = ConvertTo-HexColor $script:Theme.TextBoxBackground
        ScrollThumb = $(if ($script:settings.AppTheme -eq 'Dark') { '#3A4A6B' } else { '#C3CCDA' })
    }
}

function Set-WpfThemeResources {
    param([Parameter(Mandatory = $true)]$Window)
    $colors = Get-ThemeBrushColors
    foreach ($key in $script:ThemeBrushKeys) {
        $brush = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($colors[$key]))
        $Window.Resources[$key] = $brush
    }
}

$script:openWpfWindows = New-Object System.Collections.ArrayList

function Register-WpfWindow {
    param($Window)
    [void]$script:openWpfWindows.Add($Window)
    $Window.Add_Closed({ param($sender) [void]$script:openWpfWindows.Remove($sender) })
}

# Loads a XAML window. Put <!--APP_RESOURCES--> inside <Window.Resources> to pull in the shared styles; @FORM@ and
# @TEXT@ (window background / text) and {StaticResource <brush>} become theme-aware dynamic resources.
# Returns @{ Window = <Window>; Controls = <x:Name -> element> }.
function New-WpfWindowFromXaml {
    param([Parameter(Mandatory = $true)][string]$Xaml, [string[]]$ControlNames = @())

    Initialize-WpfSupport
    $Xaml = $Xaml.Replace('<!--APP_RESOURCES-->', (Get-WpfResourcesXaml))
    $Xaml = $Xaml.Replace('"@FORM@"', '"{DynamicResource Form}"').Replace('"@TEXT@"', '"{DynamicResource Text}"')
    $Xaml = [regex]::Replace($Xaml, '\{StaticResource (' + ($script:ThemeBrushKeys -join '|') + ')\}', '{DynamicResource $1}')
    $window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$Xaml)))
    Register-WpfWindow -Window $window
    $controls = @{}
    foreach ($name in $ControlNames) { $controls[$name] = $window.FindName($name) }
    return @{ Window = $window; Controls = $controls }
}

# ---- Screen fitting ---------------------------------------------------------------------------------------------
# Returns the work area (WPF device-independent units) of the monitor showing $Reference, or the primary monitor.
function Get-WindowWorkArea {
    param($Reference = $null)
    try {
        if ($Reference -is [System.Windows.Window] -and $Reference.IsLoaded) {
            $handle = (New-Object System.Windows.Interop.WindowInteropHelper($Reference)).Handle
            $source = [System.Windows.PresentationSource]::FromVisual($Reference)
            if ($handle -ne [IntPtr]::Zero -and $source) {
                $working = [System.Windows.Forms.Screen]::FromHandle($handle).WorkingArea
                $toDips = $source.CompositionTarget.TransformFromDevice
                $topLeft = $toDips.Transform([System.Windows.Point]::new($working.Left, $working.Top))
                $bottomRight = $toDips.Transform([System.Windows.Point]::new($working.Right, $working.Bottom))
                return [System.Windows.Rect]::new($topLeft, $bottomRight)
            }
        }
    } catch { }
    return [System.Windows.SystemParameters]::WorkArea
}

# Moves a shown window so that it lies completely inside the work area of its monitor.
function Move-WindowIntoWorkArea {
    param($Window)
    try {
        if ($Window.WindowState -ne [System.Windows.WindowState]::Normal) { return }
        $area = Get-WindowWorkArea -Reference $Window
        $width = [Math]::Min($Window.ActualWidth, $area.Width); $height = [Math]::Min($Window.ActualHeight, $area.Height)
        if ($Window.ActualWidth -gt $area.Width) { $Window.Width = $area.Width }
        if ($Window.ActualHeight -gt $area.Height) { $Window.Height = $area.Height }
        $Window.Left = [Math]::Max($area.Left, [Math]::Min($Window.Left, $area.Right - $width))
        $Window.Top = [Math]::Max($area.Top, [Math]::Min($Window.Top, $area.Bottom - $height))
    } catch { }
}

# Caps a window (and its minimum size) to the screen before it is shown, and pulls it back on screen once loaded.
# Fixed-size dialogs shrink to fit (their content scrolls); size-to-content dialogs get a maximum size.
function Set-WindowFitToScreen {
    param([Parameter(Mandatory = $true)]$Window, $Reference = $null)
    $area = Get-WindowWorkArea -Reference $(if ($Reference) { $Reference } else { $Window.Owner })
    $maxWidth = [Math]::Max(320, $area.Width - 32)
    $maxHeight = [Math]::Max(240, $area.Height - 32)
    if ($Window.MinWidth -gt $maxWidth) { $Window.MinWidth = $maxWidth }
    if ($Window.MinHeight -gt $maxHeight) { $Window.MinHeight = $maxHeight }
    if ($Window.SizeToContent -ne [System.Windows.SizeToContent]::Manual) { $Window.MaxWidth = $maxWidth; $Window.MaxHeight = $maxHeight }
    if (-not [double]::IsNaN($Window.Width) -and $Window.Width -gt $maxWidth) { $Window.Width = $maxWidth }
    if (-not [double]::IsNaN($Window.Height) -and $Window.Height -gt $maxHeight) { $Window.Height = $maxHeight }
    $hasInteropOwner = $false
    try { $hasInteropOwner = (New-Object System.Windows.Interop.WindowInteropHelper($Window)).Owner -ne [IntPtr]::Zero } catch { }
    if (-not $Window.Owner -and -not $hasInteropOwner) { $Window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterScreen }
    $Window.Add_Loaded({ param($sender) Move-WindowIntoWorkArea -Window $sender })
}

# Shows a WPF window modally. OwnerForm may be a WPF Window, a WinForms Form, or omitted.
# Returns the DialogResult ($true/$false/$null).
function Show-WpfDialog {
    param([Parameter(Mandatory = $true)]$Window, $OwnerForm)

    if ($OwnerForm -is [System.Windows.Window]) {
        $Window.Owner = $OwnerForm
        $Window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterOwner
    } elseif ($OwnerForm -is [System.Windows.Forms.Form]) {
        $interopHelper = New-Object System.Windows.Interop.WindowInteropHelper($Window)
        $interopHelper.Owner = $OwnerForm.Handle
        $Window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterOwner
    }
    Set-WindowFitToScreen -Window $Window -Reference $(if ($OwnerForm -is [System.Windows.Window]) { $OwnerForm } else { $null })
    return $Window.ShowDialog()
}

#endregion
