#region XAML Main Window
# New WPF/XAML main window, started with:  .\API-Tester.ps1 -NewUi
# It reads and writes the same files as the classic window (collections, history, environments, request tabs,
# templates, settings), so both UIs always show the same data.
#
#   NewMainWindow.ps1   - the XAML, startup and event wiring (this file)
#   NewRequestEditor.ps1 - request editor, request tabs, sending, response viewer
#   NewSidebar.ps1      - collections tree and history list
#   NewDialogs.ps1      - environments, templates, variables, save-to-collection, collection runner
#   NewMenuBar.ps1      - Menu / Tools / Monitor / Help
#   NewToolDialogs.ps1  - Settings, log viewer, cookie jar, JWT, About, diff viewer, report
#   NewNetworkDialogs.ps1 - WebSocket, gRPC, load tester
#   NewMonitorUi.ps1    - monitor engine, manager, editor, email settings, dashboard, charts
#   NewCharts.ps1       - line-chart renderer
#
# All handlers call top-level functions that read the controls from $script:ui, because event handlers run after
# the function that registered them has returned.

function Show-MainWindow {
    Import-Settings
    Import-Globals
    Import-Environments
    Import-Collections
    Import-Monitors
    Import-RequestTemplates
    if ($script:settings.EnableHistory) { Import-History }
    $script:monitorJobs = @{}
    if (-not $script:cookieJar) { $script:cookieJar = New-Object System.Collections.ArrayList }

    $themeName = if ($script:settings.AppTheme -and $script:Themes.ContainsKey($script:settings.AppTheme)) { $script:settings.AppTheme } else { 'Light' }
    $script:Theme = $script:Themes[$themeName]
    Initialize-NewUiTypes

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="API Tester" Height="900" Width="1440" MinHeight="480" MinWidth="760"
        WindowStartupLocation="CenterScreen" Background="@FORM@" Foreground="@TEXT@" FontFamily="Segoe UI">
  <Window.Resources>
    <!--APP_RESOURCES-->
    <Style x:Key="CodeBox" TargetType="TextBox" BasedOn="{StaticResource {x:Type TextBox}}">
      <Setter Property="FontFamily" Value="Consolas"/><Setter Property="FontSize" Value="13"/>
      <Setter Property="AcceptsReturn" Value="True"/><Setter Property="AcceptsTab" Value="True"/>
      <Setter Property="VerticalScrollBarVisibility" Value="Auto"/><Setter Property="HorizontalScrollBarVisibility" Value="Auto"/>
    </Style>
    <Style x:Key="TabCloseButton" TargetType="Button">
      <Setter Property="Width" Value="18"/><Setter Property="Height" Value="18"/><Setter Property="Margin" Value="10,0,0,0"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Foreground" Value="{Binding Foreground, RelativeSource={RelativeSource AncestorType=ListBoxItem}}"/>
      <Setter Property="Template"><Setter.Value>
        <ControlTemplate TargetType="Button">
          <Border x:Name="Bd" Background="Transparent" CornerRadius="9"><TextBlock Text="&#x2715;" FontSize="10" HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="{TemplateBinding Foreground}"/></Border>
          <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#40808080"/></Trigger></ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value></Setter>
    </Style>
    <Style x:Key="RequestTabItem" TargetType="ListBoxItem">
      <Setter Property="Padding" Value="14,7"/><Setter Property="Margin" Value="0,0,4,0"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Foreground" Value="{StaticResource SoftText}"/><Setter Property="Background" Value="{StaticResource Soft}"/>
      <Setter Property="Template"><Setter.Value>
        <ControlTemplate TargetType="ListBoxItem">
          <Border x:Name="TabBorder" Background="{TemplateBinding Background}" CornerRadius="6,6,0,0" Padding="{TemplateBinding Padding}">
            <ContentPresenter TextElement.Foreground="{TemplateBinding Foreground}"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsSelected" Value="True"><Setter TargetName="TabBorder" Property="Background" Value="{StaticResource Primary}"/><Setter Property="Foreground" Value="White"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="72"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0">
      <Border.Background><LinearGradientBrush StartPoint="0,0" EndPoint="1,0"><GradientStop Color="#3659C9" Offset="0"/><GradientStop Color="#243E9E" Offset="1"/></LinearGradientBrush></Border.Background>
      <Grid Margin="24,0">
        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel VerticalAlignment="Center">
          <TextBlock Text="API Tester" FontSize="24" FontWeight="SemiBold" Foreground="White"/>
          <TextBlock Text="Request workspace" Margin="2,2,0,0" Foreground="#DCE7FF"/>
        </StackPanel>
        <Border Grid.Column="1" Height="34" Margin="30,0" Padding="16,0" HorizontalAlignment="Center" VerticalAlignment="Center" CornerRadius="17" Background="#22FFFFFF" MaxWidth="560">
          <TextBlock x:Name="StatusText" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" Foreground="#DCE7FF" Text="Ready"/>
        </Border>
        <StackPanel x:Name="EnvironmentPanel" Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
          <TextBlock Text="Environment" Foreground="#DCE7FF" VerticalAlignment="Center" Margin="0,0,8,0"/>
          <ComboBox x:Name="EnvironmentBox" Width="190" Height="34" VerticalContentAlignment="Center"/>
          <Button x:Name="ManageEnvironmentsButton" Height="34" Margin="8,0,0,0" Padding="14,0" Content="Manage..." ToolTip="Add, edit and remove environments"/>
          <Button x:Name="SettingsButton" Height="34" Margin="8,0,0,0" Padding="14,0" Content="&#x2699; Settings" ToolTip="Application settings"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- Menu bar -->
    <Border Grid.Row="1" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="0,0,0,1">
      <Menu x:Name="MainMenu" Background="Transparent" Padding="14,3" FontSize="13">
        <MenuItem Header="_Menu" Foreground="{StaticResource Text}">
          <MenuItem x:Name="MenuImportCurl" Header="Import _cURL..."/>
          <MenuItem x:Name="MenuImportPostman" Header="Import _Postman / Insomnia / HAR / OpenAPI..."/>
          <MenuItem x:Name="MenuImportWorkspace" Header="Import _Workspace..."/>
          <MenuItem x:Name="MenuExportWorkspace" Header="_Export Workspace..."/>
          <Separator/>
          <MenuItem x:Name="MenuResetLayout" Header="Reset _Layout"/>
          <MenuItem x:Name="MenuSettings" Header="_Settings..."/>
          <Separator/>
          <MenuItem x:Name="MenuExit" Header="E_xit" InputGestureText="Alt+F4"/>
        </MenuItem>
        <MenuItem Header="_Tools" Foreground="{StaticResource Text}">
          <MenuItem x:Name="MenuEnvironments" Header="Manage _Environments..."/>
          <MenuItem x:Name="MenuGlobalVariables" Header="_Global Variables..."/>
          <MenuItem x:Name="MenuTemplates" Header="Request _Templates..."/>
          <Separator/>
          <MenuItem x:Name="MenuProxy" Header="_Proxy Configuration..."/>
          <MenuItem x:Name="MenuCookieJar" Header="_Cookie Jar..."/>
          <MenuItem x:Name="MenuJwt" Header="_JWT Utility..."/>
          <MenuItem x:Name="MenuReport" Header="Generate _Report..."/>
          <MenuItem x:Name="MenuWebSocket" Header="_WebSocket Client..."/>
          <MenuItem x:Name="MenuGrpc" Header="g_RPC Client..."/>
          <MenuItem x:Name="MenuLoadTester" Header="_Load Tester..."/>
        </MenuItem>
        <MenuItem Header="_Monitor" Foreground="{StaticResource Text}">
          <MenuItem x:Name="MenuMonitorManager" Header="Monitor _Manager..."/>
          <MenuItem x:Name="MenuMonitorDashboard" Header="Monitoring _Dashboard..."/>
          <MenuItem x:Name="MenuMonitorBrowser" Header="Open Monitors in _Browser"/>
        </MenuItem>
        <MenuItem Header="_Help" Foreground="{StaticResource Text}">
          <MenuItem x:Name="MenuAbout" Header="_About API Tester..."/>
          <MenuItem x:Name="MenuShortcuts" Header="_Keyboard Shortcuts..."/>
        </MenuItem>
      </Menu>
    </Border>

    <!-- Request tabs strip -->
    <Border Grid.Row="2" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="0,0,0,1" Padding="14,8,14,0">
      <ScrollViewer HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Disabled">
        <StackPanel Orientation="Horizontal">
          <ListBox x:Name="RequestTabsStrip" BorderThickness="0" Background="Transparent" ItemContainerStyle="{StaticResource RequestTabItem}" ScrollViewer.HorizontalScrollBarVisibility="Disabled">
            <ListBox.ItemsPanel><ItemsPanelTemplate><StackPanel Orientation="Horizontal"/></ItemsPanelTemplate></ListBox.ItemsPanel>
          </ListBox>
          <Button x:Name="NewTabButton" Content="+" Width="34" Height="32" Padding="0" Margin="2,0,0,2" FontSize="17" VerticalAlignment="Bottom" ToolTip="New request tab (Ctrl+T)"/>
        </StackPanel>
      </ScrollViewer>
    </Border>

    <!-- Request bar -->
    <Border Grid.Row="3" Margin="14,12,14,0" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="12">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <ComboBox x:Name="MethodBox" Width="120" Height="36" VerticalContentAlignment="Center" FontWeight="SemiBold"/>
        <Border x:Name="UrlEditorHost" Grid.Column="1" Margin="10,0,10,0" Height="36" Background="{StaticResource Input}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="6">
          <ScrollViewer x:Name="UrlScroll" HorizontalScrollBarVisibility="Hidden" VerticalScrollBarVisibility="Disabled" Padding="8,0">
            <Grid MinWidth="{Binding ViewportWidth, ElementName=UrlScroll}" Background="Transparent"><TextBlock x:Name="UrlHighlight" FontFamily="Segoe UI" FontSize="14" Margin="2,0,0,0" TextWrapping="NoWrap" IsHitTestVisible="False" VerticalAlignment="Center"/><TextBox x:Name="UrlBox" FontFamily="Segoe UI" FontSize="14" Background="Transparent" BorderThickness="0" Padding="0" VerticalScrollBarVisibility="Disabled" HorizontalScrollBarVisibility="Disabled" TextWrapping="NoWrap" VerticalAlignment="Center"/></Grid>
          </ScrollViewer>
        </Border>
        <StackPanel Grid.Column="2" Orientation="Horizontal">
          <Button x:Name="SendButton" Style="{StaticResource PrimaryButton}" Width="100" Height="36" Content="Send"/>
          <Button x:Name="StopButton" Width="90" Height="36" Margin="8,0,0,0" Content="Cancel" IsEnabled="False"/>
          <Button x:Name="RepeatButton" Width="90" Height="36" Margin="8,0,0,0" Content="Repeat..." Visibility="Collapsed" ToolTip="Send the request several times"/>
          <Button x:Name="SaveRequestButton" Width="80" Height="36" Margin="8,0,0,0" Content="Save" ToolTip="Save to the selected collection (or update the request this tab was loaded from)"/>
          <Button x:Name="TemplatesButton" Width="100" Height="36" Margin="8,0,0,0" Content="Templates..."/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- Main area -->
    <Grid Grid.Row="4" Margin="14,10,14,12">
      <Grid.ColumnDefinitions><ColumnDefinition x:Name="SidebarColumn" Width="310"/><ColumnDefinition x:Name="SidebarSplitterColumn" Width="6"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>

      <!-- Sidebar -->
      <TabControl x:Name="SidebarTabs" Grid.Column="0" ToolTip="Right-click a tab header to undock this panel" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}">
        <TabItem x:Name="TabCollections" Header="Collections">
          <Grid>
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
            <TextBox x:Name="CollectionFilterBox" Margin="8,8,8,4" Height="28" VerticalContentAlignment="Center" ToolTip="Filter requests by name or URL"/>
            <TreeView x:Name="CollectionsTree" Grid.Row="1" BorderThickness="0" Background="Transparent" Margin="2"/>
            <WrapPanel Grid.Row="2" Margin="8,4,8,8">
              <Button x:Name="NewCollectionButton" Style="{StaticResource SmallButton}" Content="New"/>
              <Button x:Name="ImportCollectionsButton" Style="{StaticResource SmallButton}" Content="Import..."/>
              <Button x:Name="ExportCollectionsButton" Style="{StaticResource SmallButton}" Content="Export..."/>
            </WrapPanel>
          </Grid>
        </TabItem>
        <TabItem x:Name="TabHistory" Header="History">
          <Grid>
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
            <StackPanel Margin="8,8,8,4">
              <TextBox x:Name="HistoryFilterBox" Height="28" VerticalContentAlignment="Center" ToolTip="Search by method or URL"/>
              <ComboBox x:Name="HistoryEnvironmentBox" Margin="0,6,0,0" Height="28" VerticalContentAlignment="Center" ToolTip="Filter history by environment"/>
            </StackPanel>
            <ListBox x:Name="HistoryList" Grid.Row="1" BorderThickness="0" Background="Transparent" SelectionMode="Extended" Margin="2"/>
            <WrapPanel Grid.Row="2" Margin="8,4,8,8">
              <Button x:Name="ClearHistoryButton" Style="{StaticResource SmallButton}" Content="Clear"/>
              <Button x:Name="ExportHistoryButton" Style="{StaticResource SmallButton}" Content="Export..."/>
            </WrapPanel>
          </Grid>
        </TabItem>
      </TabControl>
      <GridSplitter x:Name="SidebarSplitter" Grid.Column="1" HorizontalAlignment="Stretch" Background="Transparent"/>

      <!-- Workspace: editor + response -->
      <Grid x:Name="WorkspaceGrid" Grid.Column="2">
        <Grid.RowDefinitions><RowDefinition Height="*" MinHeight="140"/><RowDefinition Height="6"/><RowDefinition Height="1.4*" MinHeight="160"/></Grid.RowDefinitions>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="0"/><ColumnDefinition Width="0"/></Grid.ColumnDefinitions>

        <!-- Request editor -->
        <TabControl x:Name="RequestTabs" Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="3" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}">
          <TabItem x:Name="TabParams" Header="Params">
            <Grid Margin="10"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
              <WrapPanel Margin="0,0,0,6">
                <Button x:Name="AddParamButton" Style="{StaticResource SmallButton}" Content="+ Add parameter"/>
                <Button x:Name="RemoveParamButton" Style="{StaticResource SmallButton}" Content="Remove selected"/>
                <TextBlock Style="{StaticResource SectionLabel}" VerticalAlignment="Center" Text="Query parameters - edits here update the URL, and the other way round."/>
              </WrapPanel>
              <DataGrid x:Name="ParamsGrid" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" HeadersVisibility="Column" SelectionMode="Extended" GridLinesVisibility="Horizontal" Background="Transparent" RowBackground="Transparent">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Key" Binding="{Binding Key, UpdateSourceTrigger=PropertyChanged}" Width="220"/>
                  <DataGridTextColumn Header="Value" Binding="{Binding Value, UpdateSourceTrigger=PropertyChanged}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>
          <TabItem x:Name="TabHeaders" Header="Headers">
            <Grid Margin="10"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
              <TextBlock Style="{StaticResource SectionLabel}" Text="ONE HEADER PER LINE  -  Name: value"/>
              <Border x:Name="HeadersEditorHost" Grid.Row="1" Margin="0,8,0,0" Background="{StaticResource Input}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="6">
                <ScrollViewer x:Name="HeadersScroll" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" Padding="4,4,6,4">
                  <Grid MinWidth="{Binding ViewportWidth, ElementName=HeadersScroll}" MinHeight="{Binding ViewportHeight, ElementName=HeadersScroll}" Background="Transparent"><TextBlock x:Name="HeadersHighlight" FontFamily="Consolas" FontSize="13" Margin="2,0,0,0" TextWrapping="NoWrap" IsHitTestVisible="False"/><TextBox x:Name="HeadersBox" FontFamily="Consolas" FontSize="13" Background="Transparent" BorderThickness="0" Padding="0" VerticalScrollBarVisibility="Disabled" HorizontalScrollBarVisibility="Disabled" TextWrapping="NoWrap" AcceptsReturn="True" AcceptsTab="True"/></Grid>
                </ScrollViewer>
              </Border>
            </Grid>
          </TabItem>
          <TabItem x:Name="TabBody" Header="Body">
            <Grid Margin="10">
              <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
              <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                <ComboBox x:Name="BodyTypeBox" Grid.Column="0" Width="250" Height="30" VerticalContentAlignment="Center" VerticalAlignment="Center"/>
                <Button x:Name="BeautifyButton" Grid.Column="1" Style="{StaticResource SmallButton}" Height="30" Margin="10,0,0,0" VerticalAlignment="Center" Content="Beautify" ToolTip="Pretty-print JSON or XML"/>
                <TextBlock x:Name="BodyOptionsHint" Grid.Column="2" Margin="14,0,0,0" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" Foreground="{StaticResource Muted}" Visibility="Collapsed"
                           Text="File name / content-type options and Save to file: Options tab" ToolTip="Options tab: multipart options, output format field and where to save the response"/>
              </Grid>
              <Grid Grid.Row="1" Margin="0,10,0,0">
                <Border x:Name="BodyEditorHost"  Background="{StaticResource Input}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="6">
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                    <ScrollViewer x:Name="BodyGutterScroll" VerticalScrollBarVisibility="Hidden" HorizontalScrollBarVisibility="Disabled" IsHitTestVisible="False" Padding="0,4,0,4" Background="{StaticResource Surface}"><TextBlock x:Name="BodyGutter" FontFamily="Consolas" FontSize="13" Foreground="{StaticResource Muted}" TextAlignment="Right" MinWidth="26" Margin="8,0,8,0"/></ScrollViewer>
                    <ScrollViewer x:Name="BodyScroll" Grid.Column="1" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" Padding="4,4,6,4">
                      <Grid MinWidth="{Binding ViewportWidth, ElementName=BodyScroll}" MinHeight="{Binding ViewportHeight, ElementName=BodyScroll}" Background="Transparent"><TextBlock x:Name="BodyHighlight" FontFamily="Consolas" FontSize="13" Margin="2,0,0,0" TextWrapping="NoWrap" IsHitTestVisible="False"/><TextBox x:Name="BodyBox" FontFamily="Consolas" FontSize="13" Background="Transparent" BorderThickness="0" Padding="0" VerticalScrollBarVisibility="Disabled" HorizontalScrollBarVisibility="Disabled" TextWrapping="NoWrap" AcceptsReturn="True" AcceptsTab="True"/></Grid>
                    </ScrollViewer>
                  </Grid>
                </Border>
                <Grid x:Name="MultipartPanel" Visibility="Collapsed" AllowDrop="True">
                  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                  <WrapPanel Margin="0,0,0,6">
                    <Button x:Name="AddFieldButton" Style="{StaticResource SmallButton}" Content="+ Text field"/>
                    <Button x:Name="AddFileButton" Style="{StaticResource SmallButton}" Content="+ Attach file(s)..."/>
                    <Button x:Name="RemoveRowButton" Style="{StaticResource SmallButton}" Content="Remove selected"/>
                    <Button x:Name="ClearRowsButton" Style="{StaticResource SmallButton}" Content="Clear all"/>
                    <TextBlock Style="{StaticResource SectionLabel}" VerticalAlignment="Center" TextWrapping="Wrap" Text="Set a row's Type to File to choose a file for that key (or use its Browse button). Files can also be dropped onto a row or onto the grid."/>
                  </WrapPanel>
                  <DataGrid x:Name="MultipartGrid" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" CanUserReorderColumns="False" CanUserSortColumns="False" HeadersVisibility="Column" SelectionMode="Extended" SelectionUnit="FullRow" GridLinesVisibility="Horizontal" Background="Transparent" RowBackground="Transparent" AllowDrop="True">
                    <DataGrid.Columns>
                      <DataGridTemplateColumn Header="Key" Width="150">
                        <DataGridTemplateColumn.CellTemplate><DataTemplate><TextBox Text="{Binding Key, UpdateSourceTrigger=PropertyChanged}" BorderThickness="0" Background="Transparent" Padding="2,0" VerticalContentAlignment="Center" MinHeight="24"/></DataTemplate></DataGridTemplateColumn.CellTemplate>
                      </DataGridTemplateColumn>
                      <DataGridTemplateColumn Header="Type" Width="100">
                        <DataGridTemplateColumn.CellTemplate><DataTemplate><ComboBox ItemsSource="{Binding KindChoices}" SelectedItem="{Binding Kind, UpdateSourceTrigger=PropertyChanged}" Height="26" Padding="8,2,26,2" VerticalContentAlignment="Center" ToolTip="Text value or file upload"/></DataTemplate></DataGridTemplateColumn.CellTemplate>
                      </DataGridTemplateColumn>
                      <DataGridTemplateColumn Header="Value" Width="*">
                        <DataGridTemplateColumn.CellTemplate>
                          <DataTemplate>
                            <Grid>
                              <TextBox x:Name="TextValueBox" Text="{Binding Value, UpdateSourceTrigger=PropertyChanged}" BorderThickness="0" Background="Transparent" Padding="2,0" VerticalContentAlignment="Center" MinHeight="24" ToolTip="Text value (supports {{variables}})"/>
                              <DockPanel x:Name="FileValuePanel" Visibility="Collapsed">
                                <Button DockPanel.Dock="Right" Tag="BrowseFile" Content="Browse..." Padding="10,1" Margin="6,1,2,1" ToolTip="Choose the file to upload"/>
                                <TextBlock x:Name="FileLabelText" Text="{Binding FileLabel}" ToolTip="{Binding Value}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis" Margin="2,0"/>
                              </DockPanel>
                            </Grid>
                            <DataTemplate.Triggers>
                              <DataTrigger Binding="{Binding IsFile}" Value="True">
                                <Setter TargetName="TextValueBox" Property="Visibility" Value="Collapsed"/>
                                <Setter TargetName="FileValuePanel" Property="Visibility" Value="Visible"/>
                              </DataTrigger>
                              <DataTrigger Binding="{Binding HasValue}" Value="False">
                                <Setter TargetName="FileLabelText" Property="Foreground" Value="{StaticResource Muted}"/>
                                <Setter TargetName="FileLabelText" Property="FontStyle" Value="Italic"/>
                              </DataTrigger>
                            </DataTemplate.Triggers>
                          </DataTemplate>
                        </DataGridTemplateColumn.CellTemplate>
                      </DataGridTemplateColumn>
                      <DataGridTemplateColumn Header="File name" Width="150">
                        <DataGridTemplateColumn.CellTemplate>
                          <DataTemplate>
                            <Grid>
                              <TextBlock x:Name="FileNameDash" Text="&#x2013;" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="4,0" ToolTip="Only used for file uploads"/>
                              <TextBox x:Name="FileNameBox" Text="{Binding FileName, UpdateSourceTrigger=PropertyChanged}" BorderThickness="0" Background="Transparent" Padding="2,0" VerticalContentAlignment="Center" MinHeight="24" Visibility="Collapsed" ToolTip="File name sent to the server"/>
                            </Grid>
                            <DataTemplate.Triggers>
                              <DataTrigger Binding="{Binding IsFile}" Value="True"><Setter TargetName="FileNameBox" Property="Visibility" Value="Visible"/><Setter TargetName="FileNameDash" Property="Visibility" Value="Collapsed"/></DataTrigger>
                            </DataTemplate.Triggers>
                          </DataTemplate>
                        </DataGridTemplateColumn.CellTemplate>
                      </DataGridTemplateColumn>
                      <DataGridTemplateColumn Header="Content type" Width="170">
                        <DataGridTemplateColumn.CellTemplate>
                          <DataTemplate>
                            <Grid>
                              <TextBlock x:Name="ContentTypeDash" Text="&#x2013;" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="4,0" ToolTip="Only used for file uploads"/>
                              <TextBox x:Name="ContentTypeBox" Text="{Binding ContentType, UpdateSourceTrigger=PropertyChanged}" BorderThickness="0" Background="Transparent" Padding="2,0" VerticalContentAlignment="Center" MinHeight="24" Visibility="Collapsed" ToolTip="MIME type of the file (filled in automatically)"/>
                            </Grid>
                            <DataTemplate.Triggers>
                              <DataTrigger Binding="{Binding IsFile}" Value="True"><Setter TargetName="ContentTypeBox" Property="Visibility" Value="Visible"/><Setter TargetName="ContentTypeDash" Property="Visibility" Value="Collapsed"/></DataTrigger>
                            </DataTemplate.Triggers>
                          </DataTemplate>
                        </DataGridTemplateColumn.CellTemplate>
                      </DataGridTemplateColumn>
                    </DataGrid.Columns>
                  </DataGrid>
                </Grid>
                <Grid x:Name="GraphQLPanel" Visibility="Collapsed">
                  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="10"/><ColumnDefinition Width="0.6*"/></Grid.ColumnDefinitions>
                  <Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                    <TextBlock Style="{StaticResource SectionLabel}" Text="QUERY"/><TextBox x:Name="GqlQueryBox" Grid.Row="1" Margin="0,6,0,0" Style="{StaticResource CodeBox}"/></Grid>
                  <Grid Grid.Column="2"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                    <TextBlock Style="{StaticResource SectionLabel}" Text="VARIABLES (JSON)"/><TextBox x:Name="GqlVarsBox" Grid.Row="1" Margin="0,6,0,0" Style="{StaticResource CodeBox}"/></Grid>
                </Grid>
              </Grid>
            </Grid>
          </TabItem>
          <TabItem x:Name="TabAuth" Header="Auth">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
              <StackPanel Margin="14">
                <ComboBox x:Name="AuthTypeBox" Width="240" Height="30" HorizontalAlignment="Left" VerticalContentAlignment="Center"/>
                <TextBlock x:Name="InheritNote" Margin="0,12,0,0" TextWrapping="Wrap" Foreground="{StaticResource Muted}" Visibility="Collapsed" Text="Uses the auth set on the parent folder or collection (Collections panel: right-click a folder or collection, then Settings). Requests that are not saved in a collection send no auth."/>
                <StackPanel x:Name="BearerPanel" Margin="0,12,0,0" Visibility="Collapsed">
                  <TextBlock Style="{StaticResource SectionLabel}" Text="TOKEN"/>
                  <TextBox x:Name="BearerTokenBox" Margin="0,6,0,0" Height="30" VerticalContentAlignment="Center"/>
                </StackPanel>
                <Grid x:Name="BasicPanel" Margin="0,12,0,0" Visibility="Collapsed">
                  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                  <StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="USERNAME"/><TextBox x:Name="BasicUserBox" Margin="0,6,0,0" Height="30" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Column="2"><TextBlock Style="{StaticResource SectionLabel}" Text="PASSWORD"/><PasswordBox x:Name="BasicPasswordBox" Margin="0,6,0,0" Height="30" VerticalContentAlignment="Center"/></StackPanel>
                </Grid>
                <Grid x:Name="ApiKeyPanel" Margin="0,12,0,0" Visibility="Collapsed">
                  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/><ColumnDefinition Width="14"/><ColumnDefinition Width="170"/></Grid.ColumnDefinitions>
                  <StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="KEY NAME"/><TextBox x:Name="ApiKeyNameBox" Margin="0,6,0,0" Height="30" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Column="2"><TextBlock Style="{StaticResource SectionLabel}" Text="VALUE"/><TextBox x:Name="ApiKeyValueBox" Margin="0,6,0,0" Height="30" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Column="4"><TextBlock Style="{StaticResource SectionLabel}" Text="ADD TO"/><ComboBox x:Name="ApiKeyLocationBox" Margin="0,6,0,0" Height="30" VerticalContentAlignment="Center"/></StackPanel>
                </Grid>
                <Grid x:Name="OAuthPanel" Margin="0,12,0,0" Visibility="Collapsed">
                  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                  <StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="CLIENT ID"/><TextBox x:Name="OAuthClientIdBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Column="2"><TextBlock Style="{StaticResource SectionLabel}" Text="CLIENT SECRET"/><TextBox x:Name="OAuthClientSecretBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Row="1"><TextBlock Style="{StaticResource SectionLabel}" Text="AUTHORIZATION ENDPOINT"/><TextBox x:Name="OAuthAuthEndpointBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Row="1" Grid.Column="2"><TextBlock Style="{StaticResource SectionLabel}" Text="TOKEN ENDPOINT"/><TextBox x:Name="OAuthTokenEndpointBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Row="2"><TextBlock Style="{StaticResource SectionLabel}" Text="REDIRECT URI"/><TextBox x:Name="OAuthRedirectUriBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Row="2" Grid.Column="2"><TextBlock Style="{StaticResource SectionLabel}" Text="SCOPE"/><TextBox x:Name="OAuthScopeBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Row="3" Grid.ColumnSpan="3"><TextBlock Style="{StaticResource SectionLabel}" Text="ACCESS TOKEN"/><TextBox x:Name="OAuthAccessTokenBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Row="4"><TextBlock Style="{StaticResource SectionLabel}" Text="REFRESH TOKEN"/><TextBox x:Name="OAuthRefreshTokenBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel Grid.Row="4" Grid.Column="2"><TextBlock Style="{StaticResource SectionLabel}" Text="EXPIRES IN (SECONDS)"/><TextBox x:Name="OAuthExpiresInBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <WrapPanel Grid.Row="5" Grid.ColumnSpan="3">
                    <Button x:Name="OAuthClientCredentialsButton" Style="{StaticResource SmallButton}" Content="Get token (client credentials)"/>
                    <Button x:Name="OAuthAuthorizationCodeButton" Style="{StaticResource SmallButton}" Content="Get token (authorization code)..."/>
                    <Button x:Name="OAuthRefreshButton" Style="{StaticResource SmallButton}" Content="Refresh token"/>
                    <TextBlock x:Name="OAuthStatusText" VerticalAlignment="Center" Foreground="{StaticResource Muted}"/>
                  </WrapPanel>
                </Grid>
                <Grid x:Name="CertPanel" Margin="0,12,0,0" Visibility="Collapsed">
                  <Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                  <StackPanel><TextBlock Style="{StaticResource SectionLabel}" Text="SOURCE"/><ComboBox x:Name="CertSourceBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel x:Name="CertPathPanel" Grid.Column="2"><TextBlock Style="{StaticResource SectionLabel}" Text="PFX FILE"/><TextBox x:Name="CertPathBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <Button x:Name="CertBrowseButton" Grid.Column="3" Margin="8,22,0,10" Padding="12,3" Content="Browse..."/>
                  <StackPanel x:Name="CertPasswordPanel" Grid.Row="1" Grid.Column="2"><TextBlock Style="{StaticResource SectionLabel}" Text="PFX PASSWORD"/><PasswordBox x:Name="CertPasswordBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                  <StackPanel x:Name="CertThumbPanel" Grid.Column="2" Visibility="Collapsed"><TextBlock Style="{StaticResource SectionLabel}" Text="THUMBPRINT (CURRENT USER STORE)"/><TextBox x:Name="CertThumbBox" Margin="0,6,0,10" Height="28" VerticalContentAlignment="Center"/></StackPanel>
                </Grid>
              </StackPanel>
            </ScrollViewer>
          </TabItem>
          <TabItem x:Name="TabPreRequest" Header="Pre-request">
            <Grid Margin="10"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
              <TextBlock Style="{StaticResource SectionLabel}" TextWrapping="Wrap" Text="POWERSHELL RUN BEFORE SENDING  -  $ApiRequest (Method, Url, Headers, Body) and $Environment are available and may be changed"/>
              <TextBox x:Name="PreRequestBox" Grid.Row="1" Margin="0,8,0,0" Style="{StaticResource CodeBox}"/>
            </Grid>
          </TabItem>
          <TabItem x:Name="TabTests" Header="Tests">
            <Grid Margin="10"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
              <DockPanel>
                <Button x:Name="TestSnippetsButton" DockPanel.Dock="Right" Style="{StaticResource SmallButton}" Margin="8,0,0,0" Content="Insert snippet &#x25BE;"/>
                <TextBlock Style="{StaticResource SectionLabel}" TextWrapping="Wrap" VerticalAlignment="Center" Text="POWERSHELL RUN AFTER THE RESPONSE  -  $statusCode, $headers, $body, $jsonBody, $responseTimeMs and Assert-Equal / Assert-Contains / Assert-StatusIs / Assert-True"/>
              </DockPanel>
              <TextBox x:Name="TestsBox" Grid.Row="1" Margin="0,8,0,0" Style="{StaticResource CodeBox}"/>
            </Grid>
          </TabItem>
          <TabItem x:Name="TabOptions" Header="Options">
            <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
              <StackPanel Margin="14,12,14,12" MaxWidth="820" HorizontalAlignment="Stretch">
                <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="16,12" Margin="0,0,0,12">
                  <StackPanel>
                    <TextBlock Style="{StaticResource SectionLabel}" Text="SAVE RESPONSE TO FILE"/>
                    <TextBlock Margin="0,4,0,10" TextWrapping="Wrap" Foreground="{StaticResource Muted}" Text="Binary and attachment responses (for example a generated document) are written to this file after each send. When Auto-save is switched on in Settings, files go to the auto-save folder instead."/>
                    <Grid>
                      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                      <TextBox x:Name="OutputFileBox" Height="30" VerticalContentAlignment="Center" ToolTip="Full path of the file to write, for example C:\Temp\result.docx"/>
                      <Button x:Name="OutputFileBrowseButton" Grid.Column="1" Style="{StaticResource SmallButton}" Height="30" Margin="8,0,6,0" Content="Browse..."/>
                      <Button x:Name="OutputFileClearButton" Grid.Column="2" Style="{StaticResource SmallButton}" Height="30" Margin="0" Content="Clear"/>
                    </Grid>
                  </StackPanel>
                </Border>
                <Border x:Name="MultipartOptionsPanel" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="16,12">
                  <StackPanel>
                    <TextBlock Style="{StaticResource SectionLabel}" Text="MULTIPART / FORM-DATA"/>
                    <TextBlock x:Name="MultipartOptionsNote" Margin="0,4,0,10" TextWrapping="Wrap" Foreground="{StaticResource Muted}" Text="Only used when the body type is multipart/form-data."/>
                    <CheckBox x:Name="IncludeFilenameBox" Content="Send the file name with each file (filename=...)" IsChecked="True" Margin="0,2,0,4"/>
                    <CheckBox x:Name="IncludeContentTypeBox" Content="Send the content type with each file (Content-Type)" IsChecked="True" Margin="0,2,0,4"/>
                    <TextBlock Style="{StaticResource SectionLabel}" Text="OUTPUT FORMAT FIELD" Margin="0,12,0,4"/>
                    <TextBox x:Name="OutputFormatBox" Height="30" VerticalContentAlignment="Center" ToolTip="Extra form field, for example outputFormat=TrackChanges"/>
                    <TextBlock Margin="0,4,0,0" TextWrapping="Wrap" Foreground="{StaticResource Muted}" Text="Optional extra form field added to the request as name=value, for example outputFormat=TrackChanges. Leave empty if the API does not need it."/>
                  </StackPanel>
                </Border>
              </StackPanel>
            </ScrollViewer>
          </TabItem>
        </TabControl>

        <GridSplitter x:Name="WorkspaceSplitter" Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="3" HorizontalAlignment="Stretch" VerticalAlignment="Center" Height="4" Background="{StaticResource Border}"/>

        <!-- Response -->
        <Border x:Name="ResponsePanel" Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="3" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="6" ToolTip="Right-click the toolbar for docking options">
          <Grid>
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <WrapPanel x:Name="ResponseToolbar" Margin="12,8,12,4" Background="Transparent">
              <TextBlock Style="{StaticResource SectionLabel}" Text="RESPONSE" VerticalAlignment="Center" Margin="0,0,12,0"/>
              <Border x:Name="StatusBadge" CornerRadius="10" Padding="10,2" Background="#9AA7BD" Visibility="Collapsed" Margin="0,0,12,0">
                <TextBlock x:Name="ResponseStatusText" Foreground="White" FontWeight="SemiBold"/>
              </Border>
              <TextBlock x:Name="ResponseTimeText" VerticalAlignment="Center" Foreground="{StaticResource Muted}" Margin="0,0,12,0"/>
              <TextBlock x:Name="ResponseSizeText" VerticalAlignment="Center" Foreground="{StaticResource Muted}" Margin="0,0,16,0"/>
              <Button x:Name="PrettifyButton" Style="{StaticResource SmallButton}" Content="Prettify"/>
              <Button x:Name="SaveResponseButton" Style="{StaticResource SmallButton}" Content="Save..."/>
              <Button x:Name="CopyResponseButton" Style="{StaticResource SmallButton}" Content="Copy"/>
              <Button x:Name="GoToLineButton" Style="{StaticResource SmallButton}" Content="Go to line..."/>
              <Button x:Name="FindButton" Style="{StaticResource SmallButton}" Content="Find"/>
              <Button x:Name="ExtractButton" Style="{StaticResource SmallButton}" Content="Extract variable"/>
              <CheckBox x:Name="WrapBox" Content="Wrap" VerticalAlignment="Center" Margin="4,0,12,0"/>
            </WrapPanel>
            <Grid x:Name="FindBar" Grid.Row="1" Margin="12,0,12,6" Visibility="Collapsed">
              <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
              <TextBox x:Name="FindBox" Height="28" VerticalContentAlignment="Center" ToolTip="Enter = next, Shift+Enter = previous, Esc = close"/>
              <StackPanel Grid.Column="1" Orientation="Horizontal" Margin="8,0,0,0">
                <Button x:Name="FindPrevButton" Style="{StaticResource SmallButton}" Content="&#x25B2;"/>
                <Button x:Name="FindNextButton" Style="{StaticResource SmallButton}" Content="&#x25BC;"/>
                <TextBlock x:Name="FindCountText" VerticalAlignment="Center" Foreground="{StaticResource Muted}" Margin="4,0,8,0"/>
                <Button x:Name="FindCloseButton" Style="{StaticResource SmallButton}" Margin="0" Content="&#x2715;"/>
              </StackPanel>
            </Grid>
            <TabControl x:Name="ResponseTabs" Grid.Row="2" BorderThickness="0,1,0,0" BorderBrush="{StaticResource Border}" Background="Transparent">
              <TabItem x:Name="TabResponse" Header="Response">
                <Grid>
                  <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                  <Border x:Name="ResponseBodyEditorHost" Margin="4" BorderThickness="0" Background="{StaticResource Input}" BorderBrush="{StaticResource Border}" CornerRadius="6">
                    <Grid>
                      <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                      <ScrollViewer x:Name="ResponseBodyGutterScroll" VerticalScrollBarVisibility="Hidden" HorizontalScrollBarVisibility="Disabled" IsHitTestVisible="False" Padding="0,4,0,4" Background="{StaticResource Surface}"><TextBlock x:Name="ResponseBodyGutter" FontFamily="Consolas" FontSize="13" Foreground="{StaticResource Muted}" TextAlignment="Right" MinWidth="26" Margin="8,0,8,0"/></ScrollViewer>
                      <ScrollViewer x:Name="ResponseBodyScroll" Grid.Column="1" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" Padding="4,4,6,4">
                        <Grid MinWidth="{Binding ViewportWidth, ElementName=ResponseBodyScroll}" MinHeight="{Binding ViewportHeight, ElementName=ResponseBodyScroll}" Background="Transparent"><TextBlock x:Name="ResponseBodyHighlight" FontFamily="Consolas" FontSize="13" Margin="2,0,0,0" TextWrapping="NoWrap" IsHitTestVisible="False"/><TextBox x:Name="ResponseBodyBox" FontFamily="Consolas" FontSize="13" Background="Transparent" BorderThickness="0" Padding="0" VerticalScrollBarVisibility="Disabled" HorizontalScrollBarVisibility="Disabled" TextWrapping="NoWrap" IsReadOnly="True" IsReadOnlyCaretVisible="True" IsUndoEnabled="False" IsInactiveSelectionHighlightEnabled="True"/></Grid>
                      </ScrollViewer>
                    </Grid>
                  </Border>
                  <Border x:Name="ExtractPanel" Grid.Row="1" Visibility="Collapsed" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="0,1,0,0" Padding="10,8">
                    <WrapPanel>
                      <TextBlock Style="{StaticResource SectionLabel}" Text="EXTRACT" VerticalAlignment="Center" Margin="0,0,8,0"/>
                      <ComboBox x:Name="ExtractSourceBox" Width="80" Height="26" Margin="0,0,6,0" VerticalContentAlignment="Center"/>
                      <ComboBox x:Name="ExtractModeBox" Width="90" Height="26" Margin="0,0,6,0" VerticalContentAlignment="Center"/>
                      <TextBox x:Name="ExtractPathBox" Width="200" Height="26" Margin="0,0,6,0" VerticalContentAlignment="Center" ToolTip="JSON path (data.items[0].id) or a regex (first group is used)"/>
                      <TextBlock Text="to" VerticalAlignment="Center" Margin="0,0,6,0"/>
                      <TextBox x:Name="ExtractNameBox" Width="130" Height="26" Margin="0,0,6,0" VerticalContentAlignment="Center" ToolTip="Variable name"/>
                      <ComboBox x:Name="ExtractScopeBox" Width="110" Height="26" Margin="0,0,6,0" VerticalContentAlignment="Center"/>
                      <ComboBox x:Name="ExtractExistingBox" Width="130" Height="26" Margin="0,0,6,0" VerticalContentAlignment="Center" ToolTip="Existing variables in this scope"/>
                      <Button x:Name="ExtractRunButton" Style="{StaticResource PrimaryButton}" Padding="12,3" Content="Extract"/>
                      <TextBlock x:Name="ExtractStatusText" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="{StaticResource Muted}"/>
                    </WrapPanel>
                  </Border>
                </Grid>
              </TabItem>
              <TabItem x:Name="TabResponseHeaders" Header="Response Headers"><TextBox x:Name="ResponseHeadersBox" Style="{StaticResource CodeBox}" IsReadOnly="True" IsReadOnlyCaretVisible="True" BorderThickness="0" Margin="4"/></TabItem>
              <TabItem x:Name="TabJsonTree" Header="JSON Tree">
                <Grid Margin="4">
                  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                  <WrapPanel Margin="4,4,4,6">
                    <TextBox x:Name="JsonSearchBox" Width="220" Height="26" VerticalContentAlignment="Center" Margin="0,0,6,0" ToolTip="Search keys and values (Enter = next)"/>
                    <Button x:Name="JsonSearchNextButton" Style="{StaticResource SmallButton}" Content="Find next"/>
                    <Button x:Name="JsonExpandButton" Style="{StaticResource SmallButton}" Content="Expand all"/>
                    <Button x:Name="JsonCollapseButton" Style="{StaticResource SmallButton}" Content="Collapse all"/>
                    <Button x:Name="JsonCopyPathButton" Style="{StaticResource SmallButton}" Content="Copy path"/>
                    <TextBlock x:Name="JsonStatusText" VerticalAlignment="Center" Foreground="{StaticResource Muted}"/>
                  </WrapPanel>
                  <TreeView x:Name="JsonTree" Grid.Row="1" BorderThickness="0" Background="Transparent" FontFamily="Consolas"/>
                </Grid>
              </TabItem>
              <TabItem x:Name="TabCode" Header="Code Snippets">
                <Grid Margin="4"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                  <StackPanel Orientation="Horizontal" Margin="4,4,4,6">
                    <ComboBox x:Name="CodeLanguageBox" Width="150" Height="26" VerticalContentAlignment="Center" Margin="0,0,8,0"/>
                    <Button x:Name="CodeRefreshButton" Style="{StaticResource SmallButton}" Content="Refresh"/>
                    <Button x:Name="CodeCopyButton" Style="{StaticResource SmallButton}" Content="Copy"/>
                  </StackPanel>
                  <TextBox x:Name="CodeBox" Grid.Row="1" Style="{StaticResource CodeBox}" IsReadOnly="True" BorderThickness="0"/>
                </Grid>
              </TabItem>
              <TabItem x:Name="TabConsole" Header="Console">
                <Grid Margin="4"><Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                  <TextBox x:Name="ConsoleOutputBox" Style="{StaticResource CodeBox}" IsReadOnly="True" Background="Black" Foreground="White" FontSize="12"/>
                  <DockPanel Grid.Row="1" Margin="0,6,0,0">
                    <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" Margin="8,0,0,0">
                      <Button x:Name="ConsoleRunButton" Style="{StaticResource PrimaryButton}" Padding="14,4" Margin="0,0,6,0" Content="Run"/>
                      <Button x:Name="ConsoleClearButton" Padding="14,4" Content="Clear"/>
                    </StackPanel>
                    <TextBox x:Name="ConsoleInputBox" Height="64" Style="{StaticResource CodeBox}" ToolTip="Ctrl+Enter or Shift+Enter runs. Prefix: python: js: php: ruby: go: bat: bash:"/>
                  </DockPanel>
                </Grid>
              </TabItem>
              <TabItem x:Name="TabPreview" Header="Preview" Visibility="Collapsed">
                <Grid><Image x:Name="PreviewImage" Stretch="Uniform" Visibility="Collapsed" Margin="8"/><WebBrowser x:Name="PreviewBrowser" Visibility="Collapsed"/></Grid>
              </TabItem>
              <TabItem x:Name="TabTestResults" Header="Test Results">
                <ListBox x:Name="TestResultsList" BorderThickness="0" Background="Transparent" Margin="4"/>
              </TabItem>
            </TabControl>
          </Grid>
        </Border>
      </Grid>
    </Grid>
  </Grid>
</Window>
'@
    $controlNames = @(
    'StatusText', 'EnvironmentPanel', 'EnvironmentBox', 'ManageEnvironmentsButton', 'SettingsButton', 'MainMenu', 'MenuImportCurl',
    'MenuImportPostman', 'MenuImportWorkspace', 'MenuExportWorkspace', 'MenuResetLayout', 'MenuSettings', 'MenuExit', 'MenuEnvironments',
    'MenuGlobalVariables', 'MenuTemplates', 'MenuProxy', 'MenuCookieJar', 'MenuJwt', 'MenuReport', 'MenuWebSocket', 'MenuGrpc', 'MenuLoadTester',
    'MenuMonitorManager', 'MenuMonitorDashboard', 'MenuMonitorBrowser', 'MenuAbout', 'MenuShortcuts', 'RequestTabsStrip', 'NewTabButton',
    'MethodBox', 'UrlEditorHost', 'UrlScroll', 'UrlHighlight', 'UrlBox', 'SendButton', 'StopButton', 'RepeatButton', 'SaveRequestButton',
    'TemplatesButton', 'SidebarColumn', 'SidebarSplitterColumn', 'SidebarTabs', 'TabCollections', 'CollectionFilterBox', 'CollectionsTree',
    'NewCollectionButton', 'ImportCollectionsButton', 'ExportCollectionsButton', 'TabHistory', 'HistoryFilterBox', 'HistoryEnvironmentBox',
    'HistoryList', 'ClearHistoryButton', 'ExportHistoryButton', 'SidebarSplitter', 'WorkspaceGrid', 'RequestTabs', 'TabParams', 'AddParamButton',
    'RemoveParamButton', 'ParamsGrid', 'TabHeaders', 'HeadersEditorHost', 'HeadersScroll', 'HeadersHighlight', 'HeadersBox', 'TabBody',
    'BodyTypeBox', 'BeautifyButton', 'BodyOptionsHint', 'BodyEditorHost', 'BodyGutterScroll', 'BodyGutter', 'BodyScroll', 'BodyHighlight', 'BodyBox',
    'MultipartPanel', 'AddFieldButton', 'AddFileButton', 'RemoveRowButton', 'ClearRowsButton', 'MultipartGrid', 'GraphQLPanel', 'GqlQueryBox',
    'GqlVarsBox', 'TabAuth', 'AuthTypeBox', 'InheritNote', 'BearerPanel', 'BearerTokenBox', 'BasicPanel', 'BasicUserBox', 'BasicPasswordBox',
    'ApiKeyPanel', 'ApiKeyNameBox', 'ApiKeyValueBox', 'ApiKeyLocationBox', 'OAuthPanel', 'OAuthClientIdBox', 'OAuthClientSecretBox',
    'OAuthAuthEndpointBox', 'OAuthTokenEndpointBox', 'OAuthRedirectUriBox', 'OAuthScopeBox', 'OAuthAccessTokenBox', 'OAuthRefreshTokenBox',
    'OAuthExpiresInBox', 'OAuthClientCredentialsButton', 'OAuthAuthorizationCodeButton', 'OAuthRefreshButton', 'OAuthStatusText', 'CertPanel',
    'CertSourceBox', 'CertPathPanel', 'CertPathBox', 'CertBrowseButton', 'CertPasswordPanel', 'CertPasswordBox', 'CertThumbPanel', 'CertThumbBox',
    'TabPreRequest', 'PreRequestBox', 'TabTests', 'TestSnippetsButton', 'TestsBox', 'TabOptions', 'OutputFileBox', 'OutputFileBrowseButton',
    'OutputFileClearButton', 'MultipartOptionsPanel', 'MultipartOptionsNote', 'IncludeFilenameBox', 'IncludeContentTypeBox', 'OutputFormatBox',
    'WorkspaceSplitter', 'ResponsePanel', 'ResponseToolbar', 'StatusBadge', 'ResponseStatusText', 'ResponseTimeText', 'ResponseSizeText',
    'PrettifyButton', 'SaveResponseButton', 'CopyResponseButton', 'GoToLineButton', 'FindButton', 'ExtractButton', 'WrapBox', 'FindBar', 'FindBox',
    'FindPrevButton', 'FindNextButton', 'FindCountText', 'FindCloseButton', 'ResponseTabs', 'TabResponse', 'ResponseBodyEditorHost',
    'ResponseBodyGutterScroll', 'ResponseBodyGutter', 'ResponseBodyScroll', 'ResponseBodyHighlight', 'ResponseBodyBox', 'ExtractPanel',
    'ExtractSourceBox', 'ExtractModeBox', 'ExtractPathBox', 'ExtractNameBox', 'ExtractScopeBox', 'ExtractExistingBox', 'ExtractRunButton',
    'ExtractStatusText', 'TabResponseHeaders', 'ResponseHeadersBox', 'TabJsonTree', 'JsonSearchBox', 'JsonSearchNextButton', 'JsonExpandButton',
    'JsonCollapseButton', 'JsonCopyPathButton', 'JsonStatusText', 'JsonTree', 'TabCode', 'CodeLanguageBox', 'CodeRefreshButton', 'CodeCopyButton',
    'CodeBox', 'TabConsole', 'ConsoleOutputBox', 'ConsoleRunButton', 'ConsoleClearButton', 'ConsoleInputBox', 'TabPreview', 'PreviewImage',
    'PreviewBrowser', 'TabTestResults', 'TestResultsList'
    )
    $uiBundle = New-WpfWindowFromXaml -Xaml $xaml -ControlNames $controlNames
    $window = $uiBundle.Window
    $script:ui = $uiBundle.Controls
    $script:MainWindowContext = @{ Window = $window; Controls = $script:ui }
    $window.Title = "API Tester v$($script:AppVersion)"

    Initialize-MainWindowControls
    Register-MainWindowHandlers
    Register-SidebarHandlers
    Register-MainMenuHandlers -Controls $script:ui

    Import-RequestTabs
    if ($OpenRequestFile) {
        # Secondary window ("Open in new window"): just this request; it does not run monitors or save the main tabs.
        $script:isSecondaryWindow = $true
        try {
            $opened = Get-Content -Path $OpenRequestFile -Raw | ConvertFrom-Json
            Initialize-RequestTabDefaults -TabState $opened
            $script:requestTabs = @($opened); $script:activeRequestTabId = $opened.Id
            Remove-Item -Path $OpenRequestFile -Force -ErrorAction SilentlyContinue
            $window.Title = "API Tester - $($opened.Name)"
        } catch { Write-Log "Could not open the request file: $($_.Exception.Message)" -Level Error }
    } elseif (-not $script:settings.RestoreRequestTabs) {
        # The tabs file is shared with the classic window; by default the new window starts with a single fresh tab.
        $script:requestTabs = @(New-RequestTabState -Name 'Request 1' -Method 'GET' -BodyType 'application/json' -IncludeFilename ([bool]$script:settings.IncludeFilename) -IncludeContentType ([bool]$script:settings.IncludeContentType))
        $script:activeRequestTabId = $script:requestTabs[0].Id
    }
    if (-not $script:isSecondaryWindow) { Restore-DraftSession }
    Update-RequestTabsStrip
    Set-EditorState -State (Get-ActiveRequestTab)
    Update-CollectionsTree
    Update-HistoryList
    Update-UiFromSettings
    Set-UiStatus 'Ready'
    if (-not $script:isSecondaryWindow) { Start-MonitorEngine }

    $autoSaveTimer = New-Object System.Windows.Threading.DispatcherTimer
    $autoSaveTimer.Interval = [TimeSpan]::FromSeconds(2)
    $autoSaveTimer.Add_Tick({ Invoke-UiGuard { if ($script:editorDirty) { $script:editorDirty = $false; Save-ActiveRequestTab; Save-DraftState } } 'Auto-save' })
    $autoSaveTimer.Start()
    $script:autoSaveTimer = $autoSaveTimer

    # Any error escaping an event handler is reported instead of closing the window.
    $window.Dispatcher.Add_UnhandledException({
        param($sender, $exceptionArgs)
        $exceptionArgs.Handled = $true
        try {
            $errorRecord = $exceptionArgs.Exception
            Write-Log "Unhandled UI error: $($errorRecord.ToString())" -Level Error
            Set-UiStatus "Error: $($errorRecord.Message)"
        } catch { }
    })

    $window.Add_Closing({
        param($sender, $closingArgs)
        $runningCount = @($script:pendingRequests.Keys).Count
        if ($runningCount -gt 0) {
            $answer = [System.Windows.MessageBox]::Show($sender, "$runningCount request(s) are still running. Close the application and cancel them?", 'Requests running', 'YesNo', 'Warning')
            if ($answer -ne 'Yes') { $closingArgs.Cancel = $true; return }
        }
        $script:startMonitorServiceOnExit = $false
        $activeMonitors = @($script:monitors | Where-Object { $_ -and $_.Status -eq 'Running' }).Count
        if (-not $script:isSecondaryWindow -and $activeMonitors -gt 0 -and -not (Test-MonitorServiceRunning -NoCache)) {
            $answer = [System.Windows.MessageBox]::Show($sender, "$activeMonitors monitor(s) are running.`n`nKeep them running in the background after API Tester closes?`n`nYes - keep running (tray icon)`nNo - stop them`nCancel - don't close", 'Monitors', 'YesNoCancel', 'Question')
            if ($answer -eq 'Cancel') { $closingArgs.Cancel = $true; return }
            $script:startMonitorServiceOnExit = ($answer -eq 'Yes')
        }
        try { $script:autoSaveTimer.Stop() } catch { }
        try { Stop-MonitorEngine } catch { }
        if ($script:startMonitorServiceOnExit) { try { Save-Monitors; [void](Start-MonitorService) } catch { Write-Log "Could not start background monitors: $($_.Exception.Message)" -Level Error } }
        try { if ($script:requestPollTimer) { $script:requestPollTimer.Stop() } } catch { }
        foreach ($pending in @($script:pendingRequests.Values)) { try { $pending.State.Cancellation.Cancel() } catch { } }
        try { Save-ActiveRequestTab; Save-RequestTabs } catch { }
        if (-not $script:isSecondaryWindow) { try { if (Test-Path $draftsFilePath) { Remove-Item $draftsFilePath -Force -ErrorAction SilentlyContinue } } catch { } }
        try { Close-FloatingPanels } catch { }
        if (-not $script:isSecondaryWindow) { try { Save-MainWindowBounds -Window $sender } catch { } }
        try { Save-Settings } catch { }
    })
    $window.Add_ContentRendered({
        $script:ui.UrlBox.Focus() | Out-Null
        if ($script:startupDockState -eq 'Undocked') { Invoke-UiGuard { Set-ResponseDock -Dock 'Undocked' } 'Undock' }
        if ($script:settings.HistoryUndocked) { Invoke-UiGuard { Set-SidebarDocked -Docked $false } 'Undock' }
        if (-not $script:isSecondaryWindow) { Invoke-UiGuard { Start-StartupUpdateCheck } 'Update check' }
    })

    Set-MainWindowInitialBounds -Window $window
    [void]$window.ShowDialog()
    $script:MainWindowContext = $null
    $script:ui = $null
}

function Initialize-MainWindowControls {
    $controls = $script:ui
    $methods = @('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')
    if ($script:settings.EnableAllMethods) { $methods += @('TRACE', 'CONNECT') }
    foreach ($method in $methods) { [void]$controls.MethodBox.Items.Add($method) }
    foreach ($bodyType in @('multipart/form-data', 'application/json', 'application/xml', 'text/plain', 'application/x-www-form-urlencoded', 'GraphQL')) { [void]$controls.BodyTypeBox.Items.Add($bodyType) }
    foreach ($authType in @('Inherit', 'No Auth', 'API Key', 'Bearer Token', 'Basic Auth', 'Auth2', 'Client Certificate')) { [void]$controls.AuthTypeBox.Items.Add($authType) }
    foreach ($location in @('Header', 'Query Parameter')) { [void]$controls.ApiKeyLocationBox.Items.Add($location) }
    foreach ($source in @('PFX File', 'User Store')) { [void]$controls.CertSourceBox.Items.Add($source) }
    foreach ($language in @('cURL', 'PowerShell', 'Python', 'C#', 'JavaScript', 'JavaScript (axios)', 'Go', 'Java')) { [void]$controls.CodeLanguageBox.Items.Add($language) }
    foreach ($source in @('Body', 'Headers')) { [void]$controls.ExtractSourceBox.Items.Add($source) }
    foreach ($mode in @('JSON Path', 'Regex')) { [void]$controls.ExtractModeBox.Items.Add($mode) }
    foreach ($scope in @('Global', 'Collection', 'Environment')) { [void]$controls.ExtractScopeBox.Items.Add($scope) }
    $controls.MethodBox.SelectedIndex = 0
    $controls.BodyTypeBox.SelectedItem = 'application/json'
    $controls.AuthTypeBox.SelectedItem = 'No Auth'
    $controls.ApiKeyLocationBox.SelectedIndex = 0
    $controls.CertSourceBox.SelectedIndex = 0
    $controls.CodeLanguageBox.SelectedIndex = 0
    $controls.ExtractSourceBox.SelectedIndex = 0
    $controls.ExtractModeBox.SelectedIndex = 0
    $controls.ExtractScopeBox.SelectedIndex = 0
    $dockState = if ($script:settings.ResponseDockState -in @('Bottom', 'Right', 'Left', 'Undocked')) { $script:settings.ResponseDockState } else { 'Right' }

    $script:multipartRows = New-Object 'System.Collections.ObjectModel.ObservableCollection[MultipartRow]'
    $controls.MultipartGrid.ItemsSource = $script:multipartRows
    $script:paramRows = New-Object 'System.Collections.ObjectModel.ObservableCollection[ParamRow]'
    $controls.ParamsGrid.ItemsSource = $script:paramRows
    $controls.TestSnippetsButton.ContextMenu = New-TestSnippetMenu
    Register-CodeEditor -Name 'Url' -LanguageHint { 'text' }
    Register-CodeEditor -Name 'Headers' -LanguageHint { 'text' }
    Register-CodeEditor -Name 'Body' -LanguageHint { [string]$script:ui.BodyTypeBox.SelectedItem }
    Register-CodeEditor -Name 'ResponseBody' -LanguageHint { if ($script:lastResult) { [string]$script:lastResult.ContentType } else { '' } }
    $script:editorDirty = $false
    $script:isSwitchingRequestTab = $false
    $script:pendingRequests = @{}
    $script:lastResult = $null

    Update-EnvironmentChoices
    $startEnvironment = $script:settings.LastActiveEnvironment
    if ($startEnvironment -and $controls.EnvironmentBox.Items.Contains($startEnvironment)) { $controls.EnvironmentBox.SelectedItem = $startEnvironment }
    $script:activeEnvironment = [string]$controls.EnvironmentBox.SelectedItem
    $controls.ConsoleOutputBox.Text = "Welcome to API Tester Console.`r`nDefault language: $(if ($script:settings.DefaultConsoleLanguage) { $script:settings.DefaultConsoleLanguage } else { 'PowerShell' }).`r`nPrefix commands with 'python:', 'js:', 'php:', 'ruby:', 'go:', 'bat:', 'bash:' to switch languages.`r`nExample: python: print('Hello')`r`n`r`n"
    # An undocked panel needs the main window on screen first, so it is opened after ContentRendered.
    Set-ResponseDock -Dock $(if ($dockState -eq 'Undocked') { 'Right' } else { $dockState })
    $script:startupDockState = $dockState
}

function Register-MainWindowHandlers {
    $controls = $script:ui

    # --- header / environments ---
    $controls.EnvironmentBox.Add_SelectionChanged({ Invoke-UiGuard { Select-Environment } 'Environment' })
    $controls.ManageEnvironmentsButton.Add_Click({ Invoke-UiGuard { Show-EnvironmentManager } 'Environments' })
    $controls.SettingsButton.Add_Click({ Invoke-UiGuard { Invoke-MenuSettings } 'Settings' })

    # --- request tabs strip ---
    $controls.RequestTabsStrip.Add_SelectionChanged({ Invoke-UiGuard { Switch-RequestTabFromStrip } 'Switch tab' })
    $controls.NewTabButton.Add_Click({ Invoke-UiGuard { [void](Add-RequestTab) } 'New tab' })

    # --- request bar ---
    $controls.SendButton.Add_Click({ Invoke-UiGuard { Invoke-SendRequest } 'Send' })
    $controls.StopButton.Add_Click({ Invoke-UiGuard { Stop-SendRequest } 'Cancel' })
    $controls.RepeatButton.Add_Click({ Invoke-UiGuard { Invoke-RepeatRequest } 'Repeat' })
    $controls.SaveRequestButton.Add_Click({ Invoke-UiGuard { Save-CurrentRequest } 'Save request' })
    $controls.TemplatesButton.Add_Click({ Invoke-UiGuard { Show-RequestTemplatesDialog } 'Templates' })

    # --- editor: body ---
    $controls.BodyTypeBox.Add_SelectionChanged({ Invoke-UiGuard { Set-BodyEditorMode } 'Body type' })
    $controls.BeautifyButton.Add_Click({ Invoke-UiGuard { Format-BodyEditor } 'Beautify' })
    $controls.AddFieldButton.Add_Click({ Invoke-UiGuard { Add-MultipartRow -Kind 'Text' } 'Add field' })
    $controls.AddFileButton.Add_Click({ Invoke-UiGuard { Add-MultipartFiles } 'Attach files' })
    $controls.RemoveRowButton.Add_Click({ Invoke-UiGuard { Remove-MultipartRows } 'Remove rows' })
    $controls.ClearRowsButton.Add_Click({ Invoke-UiGuard { $script:multipartRows.Clear(); $script:editorDirty = $true } 'Clear rows' })
    $controls.MultipartPanel.Add_DragOver({
        param($sender, $dragArgs)
        $dragArgs.Effects = if ($dragArgs.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) { [System.Windows.DragDropEffects]::Copy } else { [System.Windows.DragDropEffects]::None }
        $dragArgs.Handled = $true
    })
    $controls.MultipartPanel.Add_Drop({
        param($sender, $dropArgs)
        $dropArgs.Handled = $true
        $paths = @($dropArgs.Data.GetData([System.Windows.DataFormats]::FileDrop))
        # Dropped onto a row: attach to that key; otherwise new rows.
        $targetRow = $null
        try {
            $source = $dropArgs.OriginalSource -as [System.Windows.DependencyObject]
            while ($source -and $source -isnot [System.Windows.Controls.DataGridRow]) { $source = [System.Windows.Media.VisualTreeHelper]::GetParent($source) }
            if ($source) { $targetRow = $source.Item }
        } catch { }
        Invoke-UiGuard { Add-MultipartFiles -Paths $paths -TargetRow $targetRow } 'Drop files'
    })
    # The Browse button inside each Value cell.
    $controls.MultipartGrid.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
        param($sender, $clickArgs)
        $button = $clickArgs.OriginalSource
        if ($button -is [System.Windows.Controls.Button] -and [string]$button.Tag -eq 'BrowseFile') {
            $clickArgs.Handled = $true
            $row = $button.DataContext
            Invoke-UiGuard { Add-MultipartFiles -TargetRow $row -SingleFile } 'Attach file'
        }
    })
    $controls.MultipartGrid.Add_PreviewGotKeyboardFocus({
        param($sender, $focusArgs)
        $modifiers = [System.Windows.Input.Keyboard]::Modifiers
        if ($modifiers -band ([System.Windows.Input.ModifierKeys]::Control -bor [System.Windows.Input.ModifierKeys]::Shift)) { return }
        $element = $focusArgs.NewFocus -as [System.Windows.DependencyObject]
        while ($element -and $element -isnot [System.Windows.Controls.DataGridRow]) { $element = [System.Windows.Media.VisualTreeHelper]::GetParent($element) }
        if ($element -and -not $element.IsSelected) { $sender.SelectedItem = $element.Item }
    })
    $controls.IncludeFilenameBox.Add_Click({ $script:editorDirty = $true })
    $controls.IncludeContentTypeBox.Add_Click({ $script:editorDirty = $true })

    # --- editor: auth ---
    $controls.AuthTypeBox.Add_SelectionChanged({ Invoke-UiGuard { Update-AuthPanels } 'Auth type' })
    $controls.CertSourceBox.Add_SelectionChanged({ Invoke-UiGuard { Update-AuthPanels } 'Certificate source' })
    $controls.CertBrowseButton.Add_Click({
        Invoke-UiGuard {
            $dialog = New-Object Microsoft.Win32.OpenFileDialog
            $dialog.Filter = 'Certificates (*.pfx;*.p12)|*.pfx;*.p12|All files (*.*)|*.*'
            if ($dialog.ShowDialog((Get-MainWindow)) -eq $true) { $script:ui.CertPathBox.Text = $dialog.FileName }
        } 'Browse certificate'
    })
    $controls.OAuthClientCredentialsButton.Add_Click({ Invoke-UiGuard { Invoke-OAuthClientCredentials } 'OAuth token' })
    $controls.OAuthAuthorizationCodeButton.Add_Click({ Invoke-UiGuard { Invoke-OAuthAuthorizationCode } 'OAuth authorization code' })
    $controls.OAuthRefreshButton.Add_Click({ Invoke-UiGuard { Invoke-OAuthRefresh } 'OAuth refresh' })

    # --- mark the editor dirty on any change so the active tab is saved automatically ---
    foreach ($textBox in @($controls.UrlBox, $controls.HeadersBox, $controls.BodyBox, $controls.OutputFormatBox, $controls.GqlQueryBox, $controls.GqlVarsBox, $controls.PreRequestBox, $controls.TestsBox,
            $controls.BearerTokenBox, $controls.BasicUserBox, $controls.ApiKeyNameBox, $controls.ApiKeyValueBox, $controls.OAuthClientIdBox, $controls.OAuthClientSecretBox,
            $controls.OAuthAuthEndpointBox, $controls.OAuthTokenEndpointBox, $controls.OAuthRedirectUriBox, $controls.OAuthScopeBox, $controls.OAuthAccessTokenBox,
            $controls.OAuthRefreshTokenBox, $controls.OAuthExpiresInBox, $controls.CertPathBox, $controls.CertThumbBox)) {
        $textBox.Add_TextChanged({ $script:editorDirty = $true })
    }
    $controls.MethodBox.Add_SelectionChanged({ $script:editorDirty = $true })
    $controls.BasicPasswordBox.Add_PasswordChanged({ $script:editorDirty = $true })
    $controls.CertPasswordBox.Add_PasswordChanged({ $script:editorDirty = $true })
    $controls.UrlBox.Add_TextChanged({ Invoke-UiGuard { Update-ActiveTabCaption; if (-not $script:isSyncingParams) { Update-ParamsFromUrl } } 'Tab caption' })
    $controls.AddParamButton.Add_Click({ Invoke-UiGuard { Add-ParamRow } 'Add parameter' })
    $controls.RemoveParamButton.Add_Click({ Invoke-UiGuard { Remove-ParamRows } 'Remove parameters' })
    $controls.TestSnippetsButton.Add_Click({ param($sender) $sender.ContextMenu.PlacementTarget = $sender; $sender.ContextMenu.IsOpen = $true })

    # --- response toolbar ---
    $controls.PrettifyButton.Add_Click({ Invoke-UiGuard { Format-ResponseBody } 'Prettify' })
    $controls.SaveResponseButton.Add_Click({ Invoke-UiGuard { Save-ResponseToFile } 'Save response' })
    $controls.CopyResponseButton.Add_Click({ Invoke-UiGuard { Copy-ResponseToClipboard } 'Copy response' })
    $controls.GoToLineButton.Add_Click({ Invoke-UiGuard { Move-ResponseToLine } 'Go to line' })
    $controls.FindButton.Add_Click({ Invoke-UiGuard { Show-FindBar } 'Find' })
    $controls.ExtractButton.Add_Click({
        Invoke-UiGuard {
        $panel = $script:ui.ExtractPanel
        $panel.Visibility = if ($panel.Visibility -eq 'Visible') { 'Collapsed' } else { 'Visible' }
        if ($panel.Visibility -eq 'Visible') { $script:ui.ResponseTabs.SelectedItem = $script:ui.TabResponse; Update-ExtractVariableChoices }
        } 'Extract'
    })
    $controls.WrapBox.Add_Checked({ Set-ResponseWrap -Wrap $true })
    $controls.WrapBox.Add_Unchecked({ Set-ResponseWrap -Wrap $false })
    $controls.OutputFileClearButton.Add_Click({ $script:ui.OutputFileBox.Text = '' })
    $controls.OutputFileBox.Add_TextChanged({ Update-OptionsTabHeader })
    $controls.OutputFormatBox.Add_TextChanged({ Update-OptionsTabHeader })
    $controls.OutputFileBrowseButton.Add_Click({
        Invoke-UiGuard {
            $picker = New-Object Microsoft.Win32.SaveFileDialog
            $picker.Filter = 'All files (*.*)|*.*'
            if ($picker.ShowDialog((Get-MainWindow)) -eq $true) { $script:ui.OutputFileBox.Text = $picker.FileName }
        } 'Output file'
    })

    # --- docking (classic-style right-click menus) ---
    $controls.ResponseToolbar.ContextMenu = New-DockingContextMenu
    $controls.SidebarTabs.ContextMenu = New-SidebarDockingMenu

    # --- find bar ---
    $controls.FindBox.Add_TextChanged({ Invoke-UiGuard { Update-FindMatches } 'Find' })
    $controls.FindNextButton.Add_Click({ Invoke-UiGuard { Step-FindMatch -Forward $true } 'Find next' })
    $controls.FindPrevButton.Add_Click({ Invoke-UiGuard { Step-FindMatch -Forward $false } 'Find previous' })
    $controls.FindCloseButton.Add_Click({ Hide-FindBar })
    $controls.FindBox.Add_KeyDown({
        param($sender, $keyArgs)
        if ($keyArgs.Key -eq [System.Windows.Input.Key]::Return) {
            $shift = [System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift
            Invoke-UiGuard { Step-FindMatch -Forward (-not $shift) } 'Find'
            $keyArgs.Handled = $true
        } elseif ($keyArgs.Key -eq [System.Windows.Input.Key]::Escape) { Hide-FindBar; $keyArgs.Handled = $true }
    })

    # --- extract variable ---
    $controls.ExtractModeBox.Add_SelectionChanged({ $script:ui.ExtractSourceBox.IsEnabled = $true })
    $controls.ExtractScopeBox.Add_SelectionChanged({ Update-ExtractVariableChoices })
    $controls.ExtractExistingBox.Add_SelectionChanged({ if ($script:ui.ExtractExistingBox.SelectedItem) { $script:ui.ExtractNameBox.Text = [string]$script:ui.ExtractExistingBox.SelectedItem } })
    $controls.ExtractRunButton.Add_Click({ Invoke-UiGuard { Invoke-ExtractVariable } 'Extract variable' })

    # --- JSON tree ---
    $controls.JsonSearchNextButton.Add_Click({ Invoke-UiGuard { Step-JsonTreeSearch } 'JSON search' })
    $controls.JsonSearchBox.Add_KeyDown({ param($sender, $keyArgs) if ($keyArgs.Key -eq [System.Windows.Input.Key]::Return) { Invoke-UiGuard { Step-JsonTreeSearch } 'JSON search'; $keyArgs.Handled = $true } })
    $controls.JsonSearchBox.Add_TextChanged({ $script:jsonSearchIndex = -1 })
    $controls.JsonExpandButton.Add_Click({ Set-JsonTreeExpanded -Expanded $true })
    $controls.JsonCollapseButton.Add_Click({ Set-JsonTreeExpanded -Expanded $false })
    $controls.JsonCopyPathButton.Add_Click({ Copy-JsonTreePath })

    # --- code snippets ---
    $controls.CodeLanguageBox.Add_SelectionChanged({ Invoke-UiGuard { Update-CodeSnippet } 'Code snippet' })
    $controls.CodeRefreshButton.Add_Click({ Invoke-UiGuard { Update-CodeSnippet } 'Code snippet' })
    $controls.CodeCopyButton.Add_Click({ if ($script:ui.CodeBox.Text) { [System.Windows.Clipboard]::SetText($script:ui.CodeBox.Text); Set-UiStatus 'Code snippet copied.' } })
    $controls.ResponseTabs.Add_SelectionChanged({
        param($sender, $selectionArgs)
        if ($selectionArgs.OriginalSource -eq $script:ui.ResponseTabs -and $script:ui.ResponseTabs.SelectedItem -eq $script:ui.TabCode) { Invoke-UiGuard { Update-CodeSnippet } 'Code snippet' }
    })

    # --- console ---
    $controls.ConsoleRunButton.Add_Click({ Invoke-UiGuard { Invoke-ConsoleRun } 'Console' })
    $controls.ConsoleClearButton.Add_Click({ $script:ui.ConsoleOutputBox.Clear() })
    $controls.ConsoleInputBox.Add_PreviewKeyDown({
        param($sender, $keyArgs)
        $modifiers = [System.Windows.Input.Keyboard]::Modifiers
        $runChord = ($modifiers -band [System.Windows.Input.ModifierKeys]::Control) -or ($modifiers -band [System.Windows.Input.ModifierKeys]::Shift)
        if ($keyArgs.Key -eq [System.Windows.Input.Key]::Return -and $runChord) { $keyArgs.Handled = $true; Invoke-UiGuard { Invoke-ConsoleRun } 'Console' }
    })

    # --- window-level shortcuts ---
    $script:MainWindowContext.Window.Add_PreviewKeyDown({
        param($sender, $keyArgs)
        $ctrl = [System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control
        $shift = [System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift
        if (-not $ctrl) { return }
        $key = $keyArgs.Key
        if ($key -eq [System.Windows.Input.Key]::Return -and $shift) { $keyArgs.Handled = $true; $script:ui.ResponseTabs.SelectedItem = $script:ui.TabConsole; Invoke-UiGuard { Invoke-ConsoleRun } 'Console' }
        elseif ($key -eq [System.Windows.Input.Key]::Return -and $keyArgs.OriginalSource -ne $script:ui.ConsoleInputBox) { $keyArgs.Handled = $true; Invoke-UiGuard { Invoke-SendRequest } 'Send' }
        elseif ($key -eq [System.Windows.Input.Key]::T) { $keyArgs.Handled = $true; Invoke-UiGuard { [void](Add-RequestTab) } 'New tab' }
        elseif ($key -eq [System.Windows.Input.Key]::W) { $keyArgs.Handled = $true; Invoke-UiGuard { Remove-ActiveRequestTab } 'Close tab' }
        elseif ($key -eq [System.Windows.Input.Key]::F) { $keyArgs.Handled = $true; Invoke-UiGuard { Show-FindBar } 'Find' }
    })
}

# Sizes the main window for the screen. First launch: up to 1440 x 900, never larger than the work area (and maximised
# on small screens, where the sidebar is narrowed and the response is docked below the editor). Later launches restore
# the size and position saved on exit, as long as they are still on a connected screen.
function Set-MainWindowInitialBounds {
    param($Window)
    $area = [System.Windows.SystemParameters]::WorkArea
    $Window.MinWidth = [Math]::Min(1000, $area.Width - 20)
    $Window.MinHeight = [Math]::Min(640, $area.Height - 20)
    $Window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual
    $saved = $script:settings.WindowBounds
    $left = [double](Get-ObjectProperty $saved 'Left' ([double]::NaN)); $top = [double](Get-ObjectProperty $saved 'Top' ([double]::NaN))
    $width = [double](Get-ObjectProperty $saved 'Width' 0); $height = [double](Get-ObjectProperty $saved 'Height' 0)
    $virtualScreen = [System.Windows.Rect]::new([System.Windows.SystemParameters]::VirtualScreenLeft, [System.Windows.SystemParameters]::VirtualScreenTop,
        [System.Windows.SystemParameters]::VirtualScreenWidth, [System.Windows.SystemParameters]::VirtualScreenHeight)
    $savedIsUsable = $saved -and -not [double]::IsNaN($left) -and -not [double]::IsNaN($top) -and $width -ge 400 -and $height -ge 300 -and
        $virtualScreen.IntersectsWith([System.Windows.Rect]::new($left + 40, $top + 10, [Math]::Max(1, $width - 80), 60))
    if ($savedIsUsable) {
        $Window.Width = [Math]::Min($width, $virtualScreen.Width); $Window.Height = [Math]::Min($height, $virtualScreen.Height)
        $Window.Left = $left; $Window.Top = $top
        if ([bool](Get-ObjectProperty $saved 'Maximized' $false)) { $Window.Add_SourceInitialized({ param($sender) $sender.WindowState = [System.Windows.WindowState]::Maximized }) }
        $Window.Add_Loaded({ param($sender) Move-WindowIntoWorkArea -Window $sender })
        return
    }
    $Window.Width = [Math]::Min(1440, $area.Width - 24)
    $Window.Height = [Math]::Min(900, $area.Height - 24)
    $Window.Left = $area.Left + ($area.Width - $Window.Width) / 2
    $Window.Top = $area.Top + ($area.Height - $Window.Height) / 2
    if ($area.Width -lt 1280 -or $area.Height -lt 760) {
        $Window.Add_SourceInitialized({ param($sender) $sender.WindowState = [System.Windows.WindowState]::Maximized })
        $script:ui.SidebarColumn.Width = [System.Windows.GridLength]::new(250)
        if ($area.Width -lt 1280 -and $script:settings.ResponseDockState -in @('Right', 'Left')) { Set-ResponseDock -Dock 'Bottom'; $script:startupDockState = 'Bottom' }
    }
}

function Save-MainWindowBounds {
    param($Window)
    $bounds = if ($Window.WindowState -eq [System.Windows.WindowState]::Normal) { [System.Windows.Rect]::new($Window.Left, $Window.Top, $Window.ActualWidth, $Window.ActualHeight) } else { $Window.RestoreBounds }
    if ($bounds.IsEmpty -or $bounds.Width -lt 400) { return }
    $script:settings.WindowBounds = @{ Left = [Math]::Round($bounds.Left); Top = [Math]::Round($bounds.Top); Width = [Math]::Round($bounds.Width); Height = [Math]::Round($bounds.Height)
        Maximized = ($Window.WindowState -eq [System.Windows.WindowState]::Maximized) }
}

# Runs an action; any error is shown in the header pill and written to the application log instead of crashing the window.
function Invoke-UiGuard {
    param([scriptblock]$Action, [string]$What = 'Action')
    try { & $Action }
    catch {
        Write-Log "$What failed: $($_.Exception.Message)" -Level Info
        Set-UiStatus "$What failed: $($_.Exception.Message)"
    }
}
#endregion
