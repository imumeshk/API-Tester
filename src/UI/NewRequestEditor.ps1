#region XAML Main Window - request editor, tabs, sending, response viewer

function Initialize-NewUiTypes {
    if ('MultipartRow' -as [type]) { return }
    $rowTypes = @'
using System.ComponentModel;

public class MultipartRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler PropertyChanged;
    private void Raise(string propertyName)
    {
        PropertyChangedEventHandler handler = PropertyChanged;
        if (handler != null) { handler(this, new PropertyChangedEventArgs(propertyName)); }
    }
    private string key, kind, value, fileName, contentType;
    private static readonly string[] kinds = new string[] { "Text", "File" };
    public string[] KindChoices { get { return kinds; } }
    public bool IsFile { get { return kind == "File"; } }
    public bool HasValue { get { return !string.IsNullOrEmpty(this.value); } }
    public string FileLabel { get { return string.IsNullOrEmpty(this.value) ? "No file chosen" : this.value; } }
    public string Key { get { return key; } set { key = value; Raise("Key"); } }
    public string Kind { get { return kind; } set { kind = value; Raise("Kind"); Raise("IsFile"); } }
    public string Value { get { return this.value; } set { this.value = value; Raise("Value"); Raise("HasValue"); Raise("FileLabel"); } }
    public string FileName { get { return fileName; } set { fileName = value; Raise("FileName"); } }
    public string ContentType { get { return contentType; } set { contentType = value; Raise("ContentType"); } }
}

public class ParamRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler PropertyChanged;
    private string key, value;
    private void Raise(string propertyName) { PropertyChangedEventHandler handler = PropertyChanged; if (handler != null) { handler(this, new PropertyChangedEventArgs(propertyName)); } }
    public string Key { get { return key; } set { key = value; Raise("Key"); } }
    public string Value { get { return this.value; } set { this.value = value; Raise("Value"); } }
}

public class VariableRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler PropertyChanged;
    private string name, value;
    private bool isSecret, reveal;
    private void Raise(string propertyName) { PropertyChangedEventHandler handler = PropertyChanged; if (handler != null) { handler(this, new PropertyChangedEventArgs(propertyName)); } }
    public string Name { get { return name; } set { name = value; Raise("Name"); } }
    public string Value { get { return this.value; } set { this.value = value; Raise("Value"); Raise("DisplayValue"); } }
    public bool IsSecret { get { return isSecret; } set { isSecret = value; Raise("IsSecret"); Raise("DisplayValue"); } }
    public bool Reveal { get { return reveal; } set { reveal = value; Raise("Reveal"); Raise("DisplayValue"); } }
    public string DisplayValue { get { return (isSecret && !reveal && !string.IsNullOrEmpty(this.value)) ? new string((char)0x2022, 8) : this.value; } }
}

public class SimpleRow
{
    public string C1 { get; set; }
    public string C2 { get; set; }
    public string C3 { get; set; }
    public string C4 { get; set; }
    public string C5 { get; set; }
    public object Item { get; set; }
}

public class RunnerRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler PropertyChanged;
    private void Raise(string propertyName)
    {
        PropertyChangedEventHandler handler = PropertyChanged;
        if (handler != null) { handler(this, new PropertyChangedEventArgs(propertyName)); }
    }
    private bool run = true;
    private string name, method, url, status, result, timeMs, tests;
    public bool Run { get { return run; } set { run = value; Raise("Run"); } }
    public string Name { get { return name; } set { name = value; Raise("Name"); } }
    public string Method { get { return method; } set { method = value; Raise("Method"); } }
    public string Url { get { return url; } set { url = value; Raise("Url"); } }
    public string Status { get { return status; } set { status = value; Raise("Status"); } }
    public string Result { get { return result; } set { result = value; Raise("Result"); } }
    public string TimeMs { get { return timeMs; } set { timeMs = value; Raise("TimeMs"); } }
    public string Tests { get { return tests; } set { tests = value; Raise("Tests"); } }
    public object Item { get; set; }
    public object Variables { get; set; }
}
'@
    if (-not (Import-CompiledTypes -Name 'ApiTesterRows' -ProbeType 'MultipartRow' -Source $rowTypes)) { throw 'The editor types could not be compiled.' }

    # Fast syntax highlighting (needs the WPF assemblies). Without it the slower PowerShell highlighter is used.
    $highlighterSource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;

// A {{variable}} found while highlighting (used for the hover tooltip).
public class HighlightVariable
{
    public int Start;
    public int End;
    public string Name;
}

// Syntax highlighting for the code editors. One shared brush per token kind: a theme change only recolours the brushes,
// so the text does not have to be highlighted again.
public static class ApiTesterHighlighter
{
    private static readonly Dictionary<string, SolidColorBrush> brushes = new Dictionary<string, SolidColorBrush>();
    private static readonly Dictionary<string, Regex> patterns = new Dictionary<string, Regex>();
    private static readonly string[] kinds = { "variable", "comment", "key", "string", "number", "literal", "tag", "attribute", "punctuation" };

    public static void SetPattern(string language, string pattern)
    {
        patterns[language] = new Regex(pattern, RegexOptions.Compiled);
    }

    public static void SetPalette(IDictionary palette)
    {
        foreach (DictionaryEntry entry in palette)
        {
            string kind = Convert.ToString(entry.Key);
            Color color = (Color)ColorConverter.ConvertFromString(Convert.ToString(entry.Value));
            SolidColorBrush brush;
            if (brushes.TryGetValue(kind, out brush)) { brush.Color = color; }
            else { brushes[kind] = new SolidColorBrush(color); }
        }
    }

    public static SolidColorBrush GetBrush(string kind)
    {
        SolidColorBrush brush;
        return brushes.TryGetValue(kind, out brush) ? brush : null;
    }

    public static List<HighlightVariable> Apply(TextBlock target, string text, string language, string[] knownVariables)
    {
        List<HighlightVariable> variables = new List<HighlightVariable>();
        Dictionary<string, bool> known = new Dictionary<string, bool>(StringComparer.Ordinal);
        if (knownVariables != null) { foreach (string variableName in knownVariables) { if (variableName != null) { known[variableName] = true; } } }
        target.Inlines.Clear();
        if (text == null) { text = string.Empty; }
        Regex regex;
        if (!patterns.TryGetValue(language ?? "text", out regex) && !patterns.TryGetValue("text", out regex)) { target.Text = text; return variables; }
        int position = 0;
        foreach (Match match in regex.Matches(text))
        {
            if (match.Index > position) { target.Inlines.Add(new Run(text.Substring(position, match.Index - position))); }
            string kind = "punctuation";
            foreach (string candidate in kinds) { if (match.Groups[candidate].Success) { kind = candidate; break; } }
            Run run = new Run(match.Value);
            if (kind == "variable")
            {
                string name = match.Value.Substring(2, match.Value.Length - 4).Trim();
                run.Foreground = GetBrush(known.ContainsKey(name) ? "variable" : "missing") ?? Brushes.Gray;
                run.FontWeight = FontWeights.SemiBold;
                variables.Add(new HighlightVariable { Start = match.Index, End = match.Index + match.Length, Name = name });
            }
            else
            {
                Brush brush = GetBrush(kind);
                if (brush != null) { run.Foreground = brush; }
            }
            target.Inlines.Add(run);
            position = match.Index + match.Length;
        }
        if (position < text.Length) { target.Inlines.Add(new Run(text.Substring(position))); }
        // A trailing newline needs an extra line so the overlay keeps the same height as the text box.
        if (text.EndsWith("\n")) { target.Inlines.Add(new Run(" ")); }
        return variables;
    }
}
'@
    $wpfAssemblies = @([System.Windows.Controls.TextBlock].Assembly.Location, [System.Windows.Media.Brush].Assembly.Location,
        [System.Windows.DependencyObject].Assembly.Location, [System.Xaml.XamlReader].Assembly.Location)
    $script:fastHighlighter = Import-CompiledTypes -Name 'ApiTesterHighlighter' -ProbeType 'ApiTesterHighlighter' -Source $highlighterSource -References $wpfAssemblies
}

# Reads a property from a hashtable or a PSCustomObject (collections and tabs are stored as either).
function Get-ObjectProperty {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } else { return $Default } }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $Default
}

function Format-XmlText {
    param([string]$Text)
    $document = New-Object System.Xml.XmlDocument
    $document.LoadXml($Text)
    $stringWriter = New-Object System.IO.StringWriter
    $xmlWriter = New-Object System.Xml.XmlTextWriter($stringWriter)
    $xmlWriter.Formatting = [System.Xml.Formatting]::Indented
    $xmlWriter.Indentation = 2
    $document.WriteTo($xmlWriter)
    $xmlWriter.Flush()
    return $stringWriter.ToString()
}

# ------------------------------------------------------------------------------------------------
# Authentication panel
# ------------------------------------------------------------------------------------------------

function Update-AuthPanels {
    $controls = $script:ui
    $authType = [string]$controls.AuthTypeBox.SelectedItem
    $controls.InheritNote.Visibility = if ($authType -eq 'Inherit') { 'Visible' } else { 'Collapsed' }
    $controls.BearerPanel.Visibility = if ($authType -eq 'Bearer Token') { 'Visible' } else { 'Collapsed' }
    $controls.BasicPanel.Visibility  = if ($authType -eq 'Basic Auth') { 'Visible' } else { 'Collapsed' }
    $controls.ApiKeyPanel.Visibility = if ($authType -eq 'API Key') { 'Visible' } else { 'Collapsed' }
    $controls.OAuthPanel.Visibility  = if ($authType -eq 'Auth2') { 'Visible' } else { 'Collapsed' }
    $controls.CertPanel.Visibility   = if ($authType -eq 'Client Certificate') { 'Visible' } else { 'Collapsed' }
    $isPfx = ([string]$controls.CertSourceBox.SelectedItem -ne 'User Store')
    $controls.CertPathPanel.Visibility = if ($isPfx) { 'Visible' } else { 'Collapsed' }
    $controls.CertBrowseButton.Visibility = if ($isPfx) { 'Visible' } else { 'Collapsed' }
    $controls.CertPasswordPanel.Visibility = if ($isPfx) { 'Visible' } else { 'Collapsed' }
    $controls.CertThumbPanel.Visibility = if ($isPfx) { 'Collapsed' } else { 'Visible' }
    $script:editorDirty = $true
}

function Get-AuthFromEditor {
    $controls = $script:ui
    $authType = [string]$controls.AuthTypeBox.SelectedItem
    if (-not $authType) { $authType = 'No Auth' }
    $auth = @{ Type = $authType }
    switch ($authType) {
        'API Key'      { $auth.Key = $controls.ApiKeyNameBox.Text; $auth.Value = $controls.ApiKeyValueBox.Text; $auth.AddTo = [string]$controls.ApiKeyLocationBox.SelectedItem }
        'Bearer Token' { $auth.Token = $controls.BearerTokenBox.Text }
        'Basic Auth'   { $auth.Username = $controls.BasicUserBox.Text; $auth.Password = $controls.BasicPasswordBox.Password }
        'Auth2' {
            $auth.ClientId = $controls.OAuthClientIdBox.Text; $auth.ClientSecret = $controls.OAuthClientSecretBox.Text
            $auth.AuthEndpoint = $controls.OAuthAuthEndpointBox.Text; $auth.RedirectUri = $controls.OAuthRedirectUriBox.Text
            $auth.TokenEndpoint = $controls.OAuthTokenEndpointBox.Text; $auth.Scope = $controls.OAuthScopeBox.Text
            $auth.AccessToken = $controls.OAuthAccessTokenBox.Text; $auth.RefreshToken = $controls.OAuthRefreshTokenBox.Text
            $auth.ExpiresIn = $controls.OAuthExpiresInBox.Text; $auth.TokenExpiryTimestamp = $script:oauthExpiry
        }
        'Client Certificate' {
            $auth.Source = [string]$controls.CertSourceBox.SelectedItem; $auth.Path = $controls.CertPathBox.Text
            $auth.Password = $controls.CertPasswordBox.Password; $auth.Thumbprint = $controls.CertThumbBox.Text
        }
    }
    return $auth
}

function Set-AuthToEditor {
    param($Auth)
    $controls = $script:ui
    foreach ($box in @($controls.BearerTokenBox, $controls.BasicUserBox, $controls.ApiKeyNameBox, $controls.ApiKeyValueBox, $controls.OAuthClientIdBox, $controls.OAuthClientSecretBox, $controls.OAuthAuthEndpointBox,
            $controls.OAuthTokenEndpointBox, $controls.OAuthRedirectUriBox, $controls.OAuthScopeBox, $controls.OAuthAccessTokenBox, $controls.OAuthRefreshTokenBox, $controls.OAuthExpiresInBox, $controls.CertPathBox, $controls.CertThumbBox)) { $box.Text = '' }
    $controls.BasicPasswordBox.Password = ''; $controls.CertPasswordBox.Password = ''
    $script:oauthExpiry = ''
    $authType = [string](Get-ObjectProperty $Auth 'Type' 'No Auth')
    if (-not $controls.AuthTypeBox.Items.Contains($authType)) { $authType = 'No Auth' }
    $controls.AuthTypeBox.SelectedItem = $authType
    switch ($authType) {
        'API Key' {
            $controls.ApiKeyNameBox.Text = [string](Get-ObjectProperty $Auth 'Key' ''); $controls.ApiKeyValueBox.Text = [string](Get-ObjectProperty $Auth 'Value' '')
            $addTo = [string](Get-ObjectProperty $Auth 'AddTo' 'Header'); $controls.ApiKeyLocationBox.SelectedItem = if ($controls.ApiKeyLocationBox.Items.Contains($addTo)) { $addTo } else { 'Header' }
        }
        'Bearer Token' { $controls.BearerTokenBox.Text = [string](Get-ObjectProperty $Auth 'Token' '') }
        'Basic Auth'   { $controls.BasicUserBox.Text = [string](Get-ObjectProperty $Auth 'Username' ''); $controls.BasicPasswordBox.Password = [string](Get-ObjectProperty $Auth 'Password' '') }
        'Auth2' {
            $controls.OAuthClientIdBox.Text = [string](Get-ObjectProperty $Auth 'ClientId' ''); $controls.OAuthClientSecretBox.Text = [string](Get-ObjectProperty $Auth 'ClientSecret' '')
            $controls.OAuthAuthEndpointBox.Text = [string](Get-ObjectProperty $Auth 'AuthEndpoint' ''); $controls.OAuthRedirectUriBox.Text = [string](Get-ObjectProperty $Auth 'RedirectUri' '')
            $controls.OAuthTokenEndpointBox.Text = [string](Get-ObjectProperty $Auth 'TokenEndpoint' ''); $controls.OAuthScopeBox.Text = [string](Get-ObjectProperty $Auth 'Scope' '')
            $controls.OAuthAccessTokenBox.Text = [string](Get-ObjectProperty $Auth 'AccessToken' ''); $controls.OAuthRefreshTokenBox.Text = [string](Get-ObjectProperty $Auth 'RefreshToken' '')
            $controls.OAuthExpiresInBox.Text = [string](Get-ObjectProperty $Auth 'ExpiresIn' ''); $script:oauthExpiry = [string](Get-ObjectProperty $Auth 'TokenExpiryTimestamp' '')
        }
        'Client Certificate' {
            $source = [string](Get-ObjectProperty $Auth 'Source' 'PFX File'); $controls.CertSourceBox.SelectedItem = if ($controls.CertSourceBox.Items.Contains($source)) { $source } else { 'PFX File' }
            $controls.CertPathBox.Text = [string](Get-ObjectProperty $Auth 'Path' ''); $controls.CertPasswordBox.Password = [string](Get-ObjectProperty $Auth 'Password' ''); $controls.CertThumbBox.Text = [string](Get-ObjectProperty $Auth 'Thumbprint' '')
        }
    }
    Update-AuthPanels
}

function Set-OAuthTokenResult {
    param($Token)
    $controls = $script:ui
    $controls.OAuthAccessTokenBox.Text = $Token.AccessToken
    if ($Token.RefreshToken) { $controls.OAuthRefreshTokenBox.Text = $Token.RefreshToken }
    $controls.OAuthExpiresInBox.Text = $Token.ExpiresIn
    $script:oauthExpiry = $Token.TokenExpiryTimestamp
    $controls.OAuthStatusText.Text = "Token received at $(Get-Date -Format 'HH:mm:ss')."
    $script:editorDirty = $true
}

function Invoke-OAuthClientCredentials {
    $controls = $script:ui
    if (-not $controls.OAuthTokenEndpointBox.Text) { $controls.OAuthStatusText.Text = 'Enter the token endpoint first.'; return }
    $controls.OAuthStatusText.Text = 'Requesting token...'
    $token = Invoke-OAuth2TokenRequest -TokenEndpoint (Expand-Variables $controls.OAuthTokenEndpointBox.Text) -Form @{
        grant_type = 'client_credentials'; client_id = (Expand-Variables $controls.OAuthClientIdBox.Text); client_secret = (Expand-Variables $controls.OAuthClientSecretBox.Text); scope = $controls.OAuthScopeBox.Text }
    Set-OAuthTokenResult -Token $token
}

# Opens the authorization page in an embedded browser and returns the code when the browser reaches the redirect URI
# (classic behaviour). Returns $null when the window is closed first.
function Show-OAuthBrowserDialog {
    param([string]$AuthUrl, [string]$RedirectUri)
    $window = New-Object System.Windows.Window
    $window.Title = 'Sign in'; $window.Width = 900; $window.Height = 720
    $window.Owner = Get-MainWindow; $window.WindowStartupLocation = 'CenterOwner'
    $browser = New-Object System.Windows.Controls.WebBrowser
    $window.Content = $browser
    $script:oauthBrowserCode = $null
    $browser.Add_Navigating({
        param($sender, $navigationArgs)
        $target = if ($navigationArgs.Uri) { $navigationArgs.Uri.AbsoluteUri } else { '' }
        if ($RedirectUri -and $target.StartsWith($RedirectUri, [System.StringComparison]::OrdinalIgnoreCase)) {
            $navigationArgs.Cancel = $true
            if ($target -match '[?&]code=([^&#]+)') { $script:oauthBrowserCode = [uri]::UnescapeDataString($Matches[1]) }
            $window.Close()
        }
    })
    $browser.Navigate($AuthUrl)
    Set-WindowFitToScreen -Window $window -Reference (Get-MainWindow)
    [void]$window.ShowDialog()
    return $script:oauthBrowserCode
}

function Invoke-OAuthAuthorizationCode {
    $controls = $script:ui
    if (-not $controls.OAuthAuthEndpointBox.Text -or -not $controls.OAuthTokenEndpointBox.Text) { $controls.OAuthStatusText.Text = 'Enter the authorization and token endpoints first.'; return }
    $state = [guid]::NewGuid().ToString('N')
    $query = "response_type=code&client_id=$([uri]::EscapeDataString((Expand-Variables $controls.OAuthClientIdBox.Text)))&redirect_uri=$([uri]::EscapeDataString($controls.OAuthRedirectUriBox.Text))&scope=$([uri]::EscapeDataString($controls.OAuthScopeBox.Text))&state=$state"
    $separator = if ($controls.OAuthAuthEndpointBox.Text.Contains('?')) { '&' } else { '?' }
    $authUrl = $controls.OAuthAuthEndpointBox.Text + $separator + $query
    $code = $null
    try { $code = Show-OAuthBrowserDialog -AuthUrl $authUrl -RedirectUri $controls.OAuthRedirectUriBox.Text } catch { $code = $null }
    if (-not $code) {
        # Fallback: some providers block embedded browsers - sign in with the system browser and paste the code.
        Start-Process $authUrl
        $pasted = Show-InputBox -Prompt "Sign in in your browser. When it redirects, paste the authorization code - or the whole redirect URL - here:" -Title 'Authorization code'
        if ([string]::IsNullOrWhiteSpace($pasted)) { return }
        $code = $pasted.Trim()
        if ($code -match '[?&]code=([^&#]+)') { $code = [uri]::UnescapeDataString($Matches[1]) }
    }
    $controls.OAuthStatusText.Text = 'Exchanging code...'
    $token = Invoke-OAuth2TokenRequest -TokenEndpoint (Expand-Variables $controls.OAuthTokenEndpointBox.Text) -Form @{
        grant_type = 'authorization_code'; code = $code; redirect_uri = $controls.OAuthRedirectUriBox.Text
        client_id = (Expand-Variables $controls.OAuthClientIdBox.Text); client_secret = (Expand-Variables $controls.OAuthClientSecretBox.Text) }
    Set-OAuthTokenResult -Token $token
}

function Invoke-OAuthRefresh {
    $controls = $script:ui
    if (-not $controls.OAuthRefreshTokenBox.Text -or -not $controls.OAuthTokenEndpointBox.Text) { $controls.OAuthStatusText.Text = 'A refresh token and token endpoint are required.'; return }
    $controls.OAuthStatusText.Text = 'Refreshing...'
    $token = Invoke-OAuth2TokenRequest -TokenEndpoint (Expand-Variables $controls.OAuthTokenEndpointBox.Text) -Form @{
        grant_type = 'refresh_token'; refresh_token = $controls.OAuthRefreshTokenBox.Text
        client_id = (Expand-Variables $controls.OAuthClientIdBox.Text); client_secret = (Expand-Variables $controls.OAuthClientSecretBox.Text) }
    Set-OAuthTokenResult -Token $token
}

# ------------------------------------------------------------------------------------------------
# Body editor (raw / multipart with file attachments / GraphQL)
# ------------------------------------------------------------------------------------------------

# Ends any in-progress cell edit (used before sending or switching tabs - never by the auto-save timer,
# so typing in the grid is not interrupted).
function Complete-MultipartEdit {
    try { [void]$script:ui.MultipartGrid.CommitEdit([System.Windows.Controls.DataGridEditingUnit]::Row, $true) } catch { }
}

function Sync-MultipartGridToBody {
    $controls = $script:ui
    $items = foreach ($row in $script:multipartRows) {
        [PSCustomObject]@{ Key = $row.Key; Kind = $(if ($row.Kind -eq 'File') { 'File' } else { 'Value' }); Value = $row.Value; FileName = $row.FileName; ContentType = $row.ContentType }
    }
    $bodyText = ConvertTo-MultipartBodyText -Items @($items) -IncludeFilename ([bool]$controls.IncludeFilenameBox.IsChecked) -IncludeContentType ([bool]$controls.IncludeContentTypeBox.IsChecked)
    if ($controls.BodyBox.Text -ne $bodyText) { $controls.BodyBox.Text = $bodyText }
}

# Text rows hold a value; File rows hold a path. Switching a row to File opens the file picker straight away
# (unless it already points at a file); switching back to Text clears the file-only fields.
function Register-MultipartRowEvents {
    param($Row)
    $Row.Add_PropertyChanged({
        param($sender, $changeArgs)
        $script:editorDirty = $true
        if ($changeArgs.PropertyName -ne 'Kind') { return }
        if ($sender.Kind -eq 'File') {
            if (-not $sender.Value -or -not (Test-Path -LiteralPath $sender.Value -PathType Leaf)) {
                $script:multipartRowToBrowse = $sender
                [void]$script:ui.MultipartGrid.Dispatcher.BeginInvoke([System.Action]{
                    $target = $script:multipartRowToBrowse
                    $script:multipartRowToBrowse = $null
                    if ($target) { Invoke-UiGuard { Add-MultipartFiles -TargetRow $target -SingleFile } 'Attach file' }
                })
            }
        } else {
            $sender.FileName = ''; $sender.ContentType = ''
            if ($sender.Value -and (Test-Path -LiteralPath $sender.Value -PathType Leaf)) { $sender.Value = '' }
        }
    })
}

function Sync-BodyToMultipartGrid {
    $script:multipartRows.Clear()
    foreach ($item in (Convert-MultipartBodyToItems -BodyText $script:ui.BodyBox.Text)) {
        $row = New-Object MultipartRow
        $row.Key = $item.Key; $row.Kind = $(if ($item.Kind -eq 'File') { 'File' } else { 'Text' }); $row.Value = $item.Value; $row.FileName = $item.FileName; $row.ContentType = $item.ContentType
        Register-MultipartRowEvents -Row $row
        $script:multipartRows.Add($row)
    }
}

function Add-MultipartRow {
    param([string]$Kind = 'Text', [string]$Key = '', [string]$Value = '', [string]$FileName = '', [string]$ContentType = '')
    $row = New-Object MultipartRow
    $row.Kind = if ($Kind -eq 'File') { 'File' } else { 'Text' }
    $row.Key = if ($Key) { $Key } elseif ($Kind -eq 'File') { 'file' } else { 'field' }
    $row.Value = $Value; $row.FileName = $FileName; $row.ContentType = $ContentType
    Register-MultipartRowEvents -Row $row
    $script:multipartRows.Add($row)
    $script:ui.MultipartGrid.SelectedItem = $row
    $script:editorDirty = $true
    return $row
}

function Set-MultipartRowFile {
    param($Row, [string]$Path)
    $Row.Value = $Path
    $Row.Kind = 'File'
    $Row.FileName = [System.IO.Path]::GetFileName($Path)
    $Row.ContentType = Get-MimeType -filePath $Path
    $script:editorDirty = $true
}

# Attaches files. With -TargetRow (or a selected row) the first file goes to that existing key and any further
# files are added as new rows with the same key; otherwise every file becomes a new "file" row.
function Add-MultipartFiles {
    param([string[]]$Paths = @(), $TargetRow = $null, [switch]$SingleFile)
    $grid = $script:ui.MultipartGrid
    Complete-MultipartEdit
    if (-not $TargetRow -and -not $SingleFile -and $grid.SelectedItems.Count -eq 1) { $TargetRow = $grid.SelectedItem }
    if ($Paths.Count -eq 0) {
        $dialog = New-Object Microsoft.Win32.OpenFileDialog
        $dialog.Title = if ($TargetRow) { "Attach a file to '$($TargetRow.Key)'" } else { 'Attach file(s)' }
        $dialog.Multiselect = -not $SingleFile
        if ($dialog.ShowDialog((Get-MainWindow)) -ne $true) { return }
        $Paths = @($dialog.FileNames)
    }
    $Paths = @($Paths | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) })
    if ($Paths.Count -eq 0) { return }
    if ([string]$script:ui.BodyTypeBox.SelectedItem -ne 'multipart/form-data') { $script:ui.BodyTypeBox.SelectedItem = 'multipart/form-data' }
    $remaining = $Paths
    $key = 'file'
    if ($TargetRow) {
        Set-MultipartRowFile -Row $TargetRow -Path $Paths[0]
        $key = if ($TargetRow.Key) { $TargetRow.Key } else { 'file' }
        $remaining = @($Paths | Select-Object -Skip 1)
    }
    foreach ($path in $remaining) { $newRow = Add-MultipartRow -Kind 'File' -Key $key; Set-MultipartRowFile -Row $newRow -Path $path }
    Sync-MultipartGridToBody
    Set-UiStatus "Attached $($Paths.Count) file(s)$(if ($TargetRow) { " to '$key'" })."
}

function Remove-MultipartRows {
    $grid = $script:ui.MultipartGrid
    Complete-MultipartEdit
    foreach ($row in @($grid.SelectedItems)) { [void]$script:multipartRows.Remove($row) }
    $script:editorDirty = $true
}

# "Options" shows a dot when a save-to-file path or an output format field is set, so it is not forgotten.
function Update-OptionsTabHeader {
    $controls = $script:ui
    if (-not $controls -or -not $controls.TabOptions) { return }
    $inUse = (-not [string]::IsNullOrWhiteSpace($controls.OutputFileBox.Text)) -or (-not [string]::IsNullOrWhiteSpace($controls.OutputFormatBox.Text))
    $controls.TabOptions.Header = if ($inUse) { "Options $([char]0x2022)" } else { 'Options' }
}

function Set-BodyEditorMode {
    param([switch]$Force)
    if ($script:isSwitchingRequestTab -and -not $Force) { return }
    $controls = $script:ui
    $mode = [string]$controls.BodyTypeBox.SelectedItem
    if ($script:lastBodyMode -eq 'multipart/form-data' -and $mode -ne 'multipart/form-data') { Sync-MultipartGridToBody }
    $controls.BodyEditorHost.Visibility = if ($mode -eq 'multipart/form-data' -or $mode -eq 'GraphQL') { 'Collapsed' } else { 'Visible' }
    $controls.MultipartPanel.Visibility = if ($mode -eq 'multipart/form-data') { 'Visible' } else { 'Collapsed' }
    $controls.GraphQLPanel.Visibility = if ($mode -eq 'GraphQL') { 'Visible' } else { 'Collapsed' }
    if ($mode -eq 'multipart/form-data' -and $script:lastBodyMode -ne 'multipart/form-data') { Sync-BodyToMultipartGrid }
    $controls.BeautifyButton.IsEnabled = ($mode -eq 'application/json' -or $mode -eq 'application/xml')
    $multipartVisibility = if ($mode -eq 'multipart/form-data') { 'Visible' } else { 'Collapsed' }
    # Multipart options live on the Options tab; they are greyed out for other body types.
    $isMultipart = ($mode -eq 'multipart/form-data')
    $controls.MultipartOptionsPanel.IsEnabled = $isMultipart
    $controls.MultipartOptionsNote.Text = if ($isMultipart) { 'Used by this request (body type multipart/form-data).' } else { 'Only used when the body type is multipart/form-data.' }
    $controls.BodyOptionsHint.Visibility = $multipartVisibility
    $script:lastBodyMode = $mode
    $script:editorDirty = $true
    if ($script:codeEditors['Body']) { $script:codeEditors['Body'].Timer.Stop(); $script:codeEditors['Body'].Timer.Start() }
}

function Format-BodyEditor {
    $controls = $script:ui
    $mode = [string]$controls.BodyTypeBox.SelectedItem
    if ($controls.BodyBox.Text.Length -gt 1500000) { Set-UiStatus 'Body is too large to beautify.'; return }
    try {
        if ($mode -eq 'application/xml') { $controls.BodyBox.Text = Format-XmlText -Text $controls.BodyBox.Text }
        else { $controls.BodyBox.Text = Format-JsonText -Text $controls.BodyBox.Text }
    } catch { Set-UiStatus "Could not beautify: $($_.Exception.Message)" }
}

# ------------------------------------------------------------------------------------------------
# Editor <-> request state
# ------------------------------------------------------------------------------------------------

function Get-EditorState {
    $controls = $script:ui
    $tab = Get-ActiveRequestTab
    if ([string]$controls.BodyTypeBox.SelectedItem -eq 'multipart/form-data') { Sync-MultipartGridToBody }
    $state = New-RequestTabState -Name $(if ($tab) { $tab.Name } else { 'Request' }) -Method ([string]$controls.MethodBox.SelectedItem) -Url $controls.UrlBox.Text -Headers $controls.HeadersBox.Text `
        -Body $controls.BodyBox.Text -BodyType ([string]$controls.BodyTypeBox.SelectedItem) -OutputFormat $controls.OutputFormatBox.Text -Tests $controls.TestsBox.Text -PreRequestScript $controls.PreRequestBox.Text `
        -Environment ([string]$controls.EnvironmentBox.SelectedItem) -Authentication (Get-AuthFromEditor) -GqlQuery $controls.GqlQueryBox.Text -GqlVars $controls.GqlVarsBox.Text `
        -IncludeFilename ([bool]$controls.IncludeFilenameBox.IsChecked) -IncludeContentType ([bool]$controls.IncludeContentTypeBox.IsChecked)
    if ($tab) { $state.Id = $tab.Id }
    return $state
}

function Set-EditorState {
    param($State)
    if (-not $State) { return }
    $controls = $script:ui
    $script:isSwitchingRequestTab = $true
    try {
        $method = [string](Get-ObjectProperty $State 'Method' 'GET')
        if (-not $controls.MethodBox.Items.Contains($method)) { [void]$controls.MethodBox.Items.Add($method) }
        $controls.MethodBox.SelectedItem = $method
        $controls.UrlBox.Text = [string](Get-ObjectProperty $State 'Url' '')
        $controls.HeadersBox.Text = [string](Get-ObjectProperty $State 'Headers' '')
        $controls.BodyBox.Text = [string](Get-ObjectProperty $State 'Body' '')
        $controls.GqlQueryBox.Text = [string](Get-ObjectProperty $State 'GqlQuery' '')
        $controls.GqlVarsBox.Text = [string](Get-ObjectProperty $State 'GqlVars' '')
        $controls.OutputFormatBox.Text = [string](Get-ObjectProperty $State 'OutputFormat' '')
        $controls.TestsBox.Text = [string](Get-ObjectProperty $State 'Tests' '')
        $controls.PreRequestBox.Text = [string](Get-ObjectProperty $State 'PreRequestScript' '')
        $controls.IncludeFilenameBox.IsChecked = [bool](Get-ObjectProperty $State 'IncludeFilename' $true)
        $controls.IncludeContentTypeBox.IsChecked = [bool](Get-ObjectProperty $State 'IncludeContentType' $true)
        $bodyType = ConvertTo-MimeBodyType -Name ([string](Get-ObjectProperty $State 'BodyType' 'application/json'))
        if (-not $controls.BodyTypeBox.Items.Contains($bodyType)) { $bodyType = 'application/json' }
        $script:lastBodyMode = ''
        $controls.BodyTypeBox.SelectedItem = $bodyType
        Set-BodyEditorMode -Force
        Set-AuthToEditor -Auth (Get-ObjectProperty $State 'Authentication' $null)
        $environmentName = [string](Get-ObjectProperty $State 'Environment' 'No Environment')
        if ($environmentName -and $controls.EnvironmentBox.Items.Contains($environmentName)) { $controls.EnvironmentBox.SelectedItem = $environmentName }
        $script:activeEnvironment = [string]$controls.EnvironmentBox.SelectedItem
        $source = if ($script:tabSources) { $script:tabSources[[string](Get-ObjectProperty $State 'Id' '')] } else { $null }
        $script:activeCollection = if ($source) { $source.Root } else { $null }
        $script:activeCollectionVariables = if ($script:activeCollection -and $script:activeCollection.Variables) { $script:activeCollection.Variables } else { @{} }
    } finally {
        $script:isSwitchingRequestTab = $false
    }
    $stored = if ($script:tabResults) { $script:tabResults[[string](Get-ObjectProperty $State 'Id' '')] } else { $null }
    if ($stored) { Show-ResponseResult -Result $stored } else { Clear-ResponseView }
    $script:editorDirty = $false
}

# ------------------------------------------------------------------------------------------------
# Request tabs (each tab shows a running indicator and its own close button)
# ------------------------------------------------------------------------------------------------

$script:tabResults = @{}
$script:tabSources = @{}
$script:tabCaptions = @{}
$script:tabIndicators = @{}
$script:pendingRequests = @{}

function Get-ActiveRequestTab {
    if (-not $script:activeRequestTabId) { return $null }
    return @($script:requestTabs | Where-Object { $_.Id -eq $script:activeRequestTabId })[0]
}

function Get-RequestTabById {
    param([string]$Id)
    return @($script:requestTabs | Where-Object { $_.Id -eq $Id })[0]
}

function New-RequestTabContextMenu {
    param([string]$TabId)
    $menu = New-Object System.Windows.Controls.ContextMenu
    $entries = @(
        @('Rename...', { param($sender) Invoke-UiGuard { Switch-RequestTab -Id ([string]$sender.Tag); Rename-ActiveRequestTab } 'Rename tab' }),
        @('Duplicate', { param($sender) Invoke-UiGuard { Switch-RequestTab -Id ([string]$sender.Tag); Copy-ActiveRequestTab } 'Duplicate tab' }),
        @('Open in new window', { param($sender) Invoke-UiGuard { Open-RequestInNewWindow -TabId ([string]$sender.Tag) } 'Open in new window' }),
        @('-', $null),
        @('Close', { param($sender) Invoke-UiGuard { Close-RequestTab -Id ([string]$sender.Tag) } 'Close tab' }),
        @('Close other tabs', { param($sender) Invoke-UiGuard { Close-OtherRequestTabs -KeepId ([string]$sender.Tag) } 'Close tabs' })
    )
    foreach ($entry in $entries) {
        if ($entry[0] -eq '-') { [void]$menu.Items.Add((New-Object System.Windows.Controls.Separator)); continue }
        $menuItem = New-Object System.Windows.Controls.MenuItem
        $menuItem.Header = $entry[0]; $menuItem.Tag = $TabId
        $menuItem.Add_Click($entry[1])
        [void]$menu.Items.Add($menuItem)
    }
    return $menu
}

function Update-RequestTabsStrip {
    $strip = $script:ui.RequestTabsStrip
    $script:isSwitchingRequestTab = $true
    try {
        $strip.Items.Clear()
        $script:tabCaptions = @{}; $script:tabIndicators = @{}
        $closeStyle = (Get-MainWindow).FindResource('TabCloseButton')
        foreach ($tab in $script:requestTabs) {
            $panel = New-Object System.Windows.Controls.StackPanel
            $panel.Orientation = 'Horizontal'
            $indicator = New-Object System.Windows.Shapes.Ellipse
            $indicator.Width = 8; $indicator.Height = 8; $indicator.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0); $indicator.VerticalAlignment = 'Center'
            $indicator.Fill = ConvertTo-WpfBrush '#F59E0B'; $indicator.ToolTip = 'A request is running in this tab'
            $indicator.Visibility = if ($script:pendingRequests.ContainsKey([string]$tab.Id)) { 'Visible' } else { 'Collapsed' }
            $caption = New-Object System.Windows.Controls.TextBlock
            $caption.Text = if ([string]::IsNullOrWhiteSpace($tab.Name)) { 'Request' } else { $tab.Name }
            $caption.VerticalAlignment = 'Center'; $caption.MaxWidth = 240; $caption.TextTrimming = 'CharacterEllipsis'
            $closeButton = New-Object System.Windows.Controls.Button
            $closeButton.Style = $closeStyle; $closeButton.Tag = [string]$tab.Id; $closeButton.ToolTip = 'Close tab (Ctrl+W)'
            $closeButton.Add_Click({ param($sender, $clickArgs) $clickArgs.Handled = $true; Invoke-UiGuard { Close-RequestTab -Id ([string]$sender.Tag) } 'Close tab' })
            [void]$panel.Children.Add($indicator); [void]$panel.Children.Add($caption); [void]$panel.Children.Add($closeButton)

            $item = New-Object System.Windows.Controls.ListBoxItem
            $item.Content = $panel
            $item.Tag = [string]$tab.Id
            $item.ToolTip = 'Drag to reorder - double-click to rename - middle-click to close - right-click for more'
            $item.ContextMenu = New-RequestTabContextMenu -TabId ([string]$tab.Id)
            Register-RequestTabDragDrop -Item $item
            $item.Add_MouseDoubleClick({ Invoke-UiGuard { Rename-ActiveRequestTab } 'Rename tab' })
            $item.Add_PreviewMouseDown({
                param($sender, $mouseArgs)
                if ($mouseArgs.ChangedButton -eq [System.Windows.Input.MouseButton]::Middle) { $mouseArgs.Handled = $true; Invoke-UiGuard { Close-RequestTab -Id ([string]$sender.Tag) } 'Close tab' }
            })
            [void]$strip.Items.Add($item)
            $script:tabCaptions[[string]$tab.Id] = $caption
            $script:tabIndicators[[string]$tab.Id] = $indicator
            if ($tab.Id -eq $script:activeRequestTabId) { $strip.SelectedItem = $item }
        }
    } finally { $script:isSwitchingRequestTab = $false }
}

function Update-TabRunningIndicators {
    foreach ($tabId in @($script:tabIndicators.Keys)) {
        $script:tabIndicators[$tabId].Visibility = if ($script:pendingRequests.ContainsKey($tabId)) { 'Visible' } else { 'Collapsed' }
    }
}

function Update-ActiveTabCaption {
    $tab = Get-ActiveRequestTab
    if ($tab -and $script:tabCaptions[[string]$tab.Id]) { $script:tabCaptions[[string]$tab.Id].Text = $tab.Name }
}

function Save-ActiveRequestTab {
    if ($script:isSwitchingRequestTab -or -not $script:ui) { return }
    $current = Get-ActiveRequestTab
    if (-not $current) { return }
    $captured = Get-EditorState
    for ($index = 0; $index -lt $script:requestTabs.Count; $index++) {
        if ($script:requestTabs[$index].Id -eq $captured.Id) { $script:requestTabs[$index] = $captured; break }
    }
    Save-RequestTabs
}

function Switch-RequestTabFromStrip {
    if ($script:isSwitchingRequestTab) { return }
    $item = $script:ui.RequestTabsStrip.SelectedItem
    if (-not $item -or $item.Tag -eq $script:activeRequestTabId) { return }
    Switch-RequestTab -Id $item.Tag
}

function Switch-RequestTab {
    param([string]$Id)
    if ($Id -eq [string]$script:activeRequestTabId) { return }
    Complete-MultipartEdit
    Save-ActiveRequestTab
    $script:activeRequestTabId = $Id
    Set-EditorState -State (Get-ActiveRequestTab)
    $script:isSwitchingRequestTab = $true
    try { foreach ($item in $script:ui.RequestTabsStrip.Items) { if ($item.Tag -eq $Id) { $script:ui.RequestTabsStrip.SelectedItem = $item } } } finally { $script:isSwitchingRequestTab = $false }
    Update-SendButtons
    if (-not $script:pendingRequests.ContainsKey($Id)) { Set-UiStatus 'Ready' } else { Set-UiStatus 'A request is running in this tab...' }
}

function Add-RequestTab {
    param($InitialState = $null)
    Save-ActiveRequestTab
    if ($InitialState) {
        $newState = Copy-RequestData $InitialState
        Initialize-RequestTabDefaults -TabState $newState
        $newState.Id = [guid]::NewGuid().ToString()
        if ([string]::IsNullOrWhiteSpace($newState.Name)) { $newState.Name = "Request $($script:requestTabs.Count + 1)" }
    } else {
        $newState = New-RequestTabState -Name "Request $($script:requestTabs.Count + 1)" -Method 'GET' -BodyType 'application/json' -Environment ([string]$script:ui.EnvironmentBox.SelectedItem) `
            -IncludeFilename ([bool]$script:settings.IncludeFilename) -IncludeContentType ([bool]$script:settings.IncludeContentType)
    }
    $script:requestTabs += $newState
    $script:activeRequestTabId = $newState.Id
    Update-RequestTabsStrip
    Set-EditorState -State $newState
    Update-SendButtons
    Save-RequestTabs
    return $newState
}

# Closes a tab. A tab with a running request asks first and cancels the request.
function Close-RequestTab {
    param([string]$Id, [switch]$NoConfirm)
    if (-not $Id) { return }
    if ($script:requestTabs.Count -le 1) { Set-UiStatus 'At least one request tab must remain open.'; return $false }
    $tab = Get-RequestTabById -Id $Id
    if (-not $tab) { return $false }
    if ($script:pendingRequests.ContainsKey($Id)) {
        if (-not $NoConfirm) {
            $answer = [System.Windows.MessageBox]::Show((Get-MainWindow), "A request is still running in '$($tab.Name)'.`n`nClose the tab and cancel the request?", 'Request running', 'YesNo', 'Warning')
            if ($answer -ne 'Yes') { return $false }
        }
        $pending = $script:pendingRequests[$Id]
        $pending.Repeat = $null
        try { $pending.State.Cancellation.Cancel() } catch { }
        $script:pendingRequests.Remove($Id)
    }
    $wasActive = ($Id -eq [string]$script:activeRequestTabId)
    if ($wasActive) { $script:isSwitchingRequestTab = $false } else { Save-ActiveRequestTab }
    $currentIndex = [array]::IndexOf(@($script:requestTabs.Id), $Id)
    $script:requestTabs = @($script:requestTabs | Where-Object { $_.Id -ne $Id })
    $script:tabResults.Remove($Id)
    $script:tabSources.Remove($Id)
    if ($wasActive) {
        if ($currentIndex -ge $script:requestTabs.Count) { $currentIndex = $script:requestTabs.Count - 1 }
        $script:activeRequestTabId = $script:requestTabs[[Math]::Max(0, $currentIndex)].Id
        Update-RequestTabsStrip
        Set-EditorState -State (Get-ActiveRequestTab)
    } else {
        Update-RequestTabsStrip
    }
    Update-SendButtons
    Save-RequestTabs
    return $true
}

function Close-OtherRequestTabs {
    param([string]$KeepId)
    $others = @($script:requestTabs | Where-Object { $_.Id -ne $KeepId })
    $running = @($others | Where-Object { $script:pendingRequests.ContainsKey([string]$_.Id) })
    if ($running.Count -gt 0) {
        $answer = [System.Windows.MessageBox]::Show((Get-MainWindow), "$($running.Count) of the other tabs still have a running request.`n`nClose them and cancel the requests?", 'Requests running', 'YesNo', 'Warning')
        if ($answer -ne 'Yes') { return }
    }
    Switch-RequestTab -Id $KeepId
    foreach ($tab in $others) { [void](Close-RequestTab -Id ([string]$tab.Id) -NoConfirm) }
}

function Remove-ActiveRequestTab { [void](Close-RequestTab -Id ([string]$script:activeRequestTabId)) }

function Copy-ActiveRequestTab {
    $state = Get-EditorState
    $state.Name = "$($state.Name) (copy)"
    [void](Add-RequestTab -InitialState $state)
}

function Rename-ActiveRequestTab {
    $tab = Get-ActiveRequestTab
    if (-not $tab) { return }
    $newName = Show-InputBox -Prompt 'Tab name:' -Title 'Rename tab' -DefaultText $tab.Name
    if ([string]::IsNullOrWhiteSpace($newName)) { return }
    $tab.Name = $newName.Trim()
    Update-ActiveTabCaption
    Save-ActiveRequestTab
}

# Classic behaviour: if the app did not close normally, offer to restore the unsaved session.
function Restore-DraftSession {
    $drafts = Import-DraftState
    if (-not $drafts) { return }
    $answer = [System.Windows.MessageBox]::Show('An unsaved session (draft) was found. Would you like to restore it?', 'Restore Session', 'YesNo', 'Question')
    if ($answer -eq 'Yes') {
        $restored = @()
        foreach ($draft in @($drafts)) { if ($draft) { Initialize-RequestTabDefaults -TabState $draft; $restored += $draft } }
        if ($restored.Count -gt 0) { $script:requestTabs = $restored; $script:activeRequestTabId = $restored[0].Id }
    }
    if (Test-Path $draftsFilePath) { Remove-Item $draftsFilePath -Force -ErrorAction SilentlyContinue }
}

# ------------------------------------------------------------------------------------------------
# Environments
# ------------------------------------------------------------------------------------------------

function Select-Environment {
    $controls = $script:ui
    $name = [string]$controls.EnvironmentBox.SelectedItem
    if (-not $name) { return }
    $script:activeEnvironment = $name
    if ($script:isSwitchingRequestTab) { return }
    $script:settings.LastActiveEnvironment = $name
    $script:editorDirty = $true
    if ($name -ne 'No Environment' -and $script:environments.ContainsKey($name)) {
        $environmentData = $script:environments[$name]
        $environmentUrl = [string](Get-ObjectProperty $environmentData 'Url' '')
        $environmentHeaders = [string](Get-ObjectProperty $environmentData 'Headers' '')
        $environmentAuth = Get-ObjectProperty $environmentData 'Authentication' $null
        if ($environmentUrl) { $controls.UrlBox.Text = $environmentUrl }
        if ($environmentHeaders) { $controls.HeadersBox.Text = $environmentHeaders }
        if ($environmentAuth -and [string](Get-ObjectProperty $environmentAuth 'Type' 'No Auth') -ne 'No Auth') { Set-AuthToEditor -Auth $environmentAuth }
        Set-UiStatus "Applied environment '$name'."
    }
    Update-ExtractVariableChoices
    Update-AllCodeHighlights -Except 'ResponseBody'
}

# ------------------------------------------------------------------------------------------------
# Sending (every tab can have its own request in flight)
# ------------------------------------------------------------------------------------------------

function Update-SendButtons {
    $controls = $script:ui
    if (-not $controls) { return }
    $busy = $script:pendingRequests.ContainsKey([string]$script:activeRequestTabId)
    $controls.SendButton.IsEnabled = -not $busy
    $controls.StopButton.IsEnabled = $busy
    $controls.RepeatButton.IsEnabled = -not $busy
}

# Starts the HTTP request for a tab. Throws if the request cannot be built.
function Start-TabRequest {
    param([string]$TabId, $State, $Repeat = $null, [switch]$RunPreRequest, $HistoryEntry = $null)
    if ($RunPreRequest -and $State.PreRequestScript -match '\S') {
        $modified = Invoke-PreRequestScript -ScriptText $State.PreRequestScript -Request $State
        $State.Method = [string]$modified.Method; $State.Url = [string]$modified.Url; $State.Headers = [string]$modified.Headers; $State.Body = [string]$modified.Body
    }
    $timeoutSeconds = if ($script:settings.RequestTimeoutSeconds -gt 0) { [int]$script:settings.RequestTimeoutSeconds } else { 60 }
    $requestState = Start-HttpRequestFromObject -Request $State -TimeoutSeconds $timeoutSeconds
    $script:pendingRequests[$TabId] = @{ State = $requestState; Request = $State; Repeat = $Repeat; HistoryEntry = $HistoryEntry }
    if (-not $script:requestPollTimer) {
        $script:requestPollTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:requestPollTimer.Interval = [TimeSpan]::FromMilliseconds(100)
        $script:requestPollTimer.Add_Tick({ Invoke-UiGuard { Update-RequestPoll } 'Request' })
    }
    $script:requestPollTimer.Start()
    Update-SendButtons
    Update-TabRunningIndicators
    return $requestState
}

function Invoke-SendRequest {
    param($Repeat = $null)
    $controls = $script:ui
    $tabId = [string]$script:activeRequestTabId
    if ($script:pendingRequests.ContainsKey($tabId)) { return }

    Complete-MultipartEdit
    $state = Get-EditorState
    if ([string]::IsNullOrWhiteSpace($state.Url)) { Set-UiStatus 'Enter a URL first.'; [void]$controls.UrlBox.Focus(); return }

    # Folder / collection settings (auth, headers, scripts) apply to requests that live in a collection.
    $source = $script:tabSources[$tabId]
    $effective = Resolve-InheritedRequest -Request $state -Root $(if ($source) { $source.Root }) -Item $(if ($source) { $source.Item })

    if ($effective.PreRequestScript -match '\S') {
        try {
            $modified = Invoke-PreRequestScript -ScriptText $effective.PreRequestScript -Request $effective
            $effective.Method = [string]$modified.Method; $effective.Url = [string]$modified.Url; $effective.Headers = [string]$modified.Headers; $effective.Body = [string]$modified.Body
            # Without inherited settings the script's changes are shown in the editor (classic behaviour).
            if (-not $effective.HasInheritance) {
                if ($controls.MethodBox.Items.Contains($effective.Method)) { $controls.MethodBox.SelectedItem = $effective.Method }
                $controls.UrlBox.Text = $effective.Url; $controls.HeadersBox.Text = $effective.Headers
                if ([string]$controls.BodyTypeBox.SelectedItem -ne 'multipart/form-data') { $controls.BodyBox.Text = $effective.Body }
            }
        } catch {
            [void][System.Windows.MessageBox]::Show((Get-MainWindow), "Pre-request script failed:`n$($_.Exception.Message)", 'Pre-request script', 'OK', 'Error')
            return
        }
    }

    $historyEntry = if (-not $Repeat) { Add-HistoryEntry -State $state } else { $null }
    Save-ActiveRequestTab

    try {
        $started = Start-TabRequest -TabId $tabId -State $effective -Repeat $Repeat -HistoryEntry $historyEntry
    } catch {
        $failure = @{ Success = $false; ErrorMessage = $_.Exception.Message; ElapsedMs = 0 }
        $script:tabResults[$tabId] = $failure
        Show-ResponseResult -Result $failure -Live
        return
    }
    $label = if ($Repeat) { "Sending ($($Repeat.Done + 1)/$($Repeat.Total))..." } else { 'Sending...' }
    Set-UiStatus "$label $($effective.Method) $($started.Url)"
}

function Update-RequestPoll {
    foreach ($tabId in @($script:pendingRequests.Keys)) {
        $pending = $script:pendingRequests[$tabId]
        if (-not $pending.State.Task.IsCompleted) { continue }
        $script:pendingRequests.Remove($tabId)
        $result = Get-HttpRequestResult -RequestState $pending.State
        if ($pending.HistoryEntry) { Set-HistoryResponse -Entry $pending.HistoryEntry -Result $result }
        Complete-SendRequest -TabId $tabId -Result $result -State $pending.Request -Repeat $pending.Repeat
    }
    if ($script:pendingRequests.Count -eq 0) { $script:requestPollTimer.Stop() }
    Update-SendButtons
    Update-TabRunningIndicators
    if ($script:themeReloadPending -and $script:pendingRequests.Count -eq 0) { $script:themeReloadPending = $false; Restart-MainWindow }
}

function Complete-SendRequest {
    param([string]$TabId, $Result, $State, $Repeat = $null)
    if ($Result.Success -and $State.Tests -match '\S') { $Result.TestResults = @(Invoke-TestScript -ScriptText $State.Tests -Result $Result) }
    if ($Result.Success) { Save-ResponseFileIfNeeded -Result $Result -State $State }
    $script:tabResults[$TabId] = $Result
    $isActive = ($TabId -eq [string]$script:activeRequestTabId)

    # An OAuth token refreshed while sending is written back to the tab.
    if ($Result.Success -and $Result.Authentication -and $Result.Authentication.Type -eq 'Auth2' -and $Result.Authentication.AccessToken) {
        if ($isActive) { if ($Result.Authentication.AccessToken -ne $script:ui.OAuthAccessTokenBox.Text) { Set-AuthToEditor -Auth $Result.Authentication } }
        else { $tab = Get-RequestTabById -Id $TabId; if ($tab) { $tab.Authentication = Copy-RequestData $Result.Authentication; Save-RequestTabs } }
    }

    if ($isActive) { Show-ResponseResult -Result $Result -Live }
    else {
        $tab = Get-RequestTabById -Id $TabId
        $summary = if ($Result.Success) { "$($Result.StatusCode) $($Result.ReasonPhrase)" } else { [string]$Result.ErrorMessage }
        Set-UiStatus "Request in '$(if ($tab) { $tab.Name } else { 'tab' })' finished: $summary"
    }

    if ($Repeat) {
        $Repeat.Done++
        if ($Result.Success -and $Result.StatusCode -lt 400) { $Repeat.Passed++ } else { $Repeat.Failed++ }
        if ($Repeat.Done -lt $Repeat.Total -and -not $Result.Canceled -and (Get-RequestTabById -Id $TabId)) {
            try { [void](Start-TabRequest -TabId $TabId -State $State -Repeat $Repeat -RunPreRequest); if ($isActive) { Set-UiStatus "Sending ($($Repeat.Done + 1)/$($Repeat.Total))..." }; return }
            catch { Set-UiStatus "Repeat stopped: $($_.Exception.Message)" }
        }
        Set-UiStatus "Repeat finished: $($Repeat.Passed) succeeded, $($Repeat.Failed) failed (of $($Repeat.Total))."
    }
}

function Stop-SendRequest {
    $tabId = [string]$script:activeRequestTabId
    if (-not $script:pendingRequests.ContainsKey($tabId)) { return }
    $pending = $script:pendingRequests[$tabId]
    $pending.Repeat = $null
    try { $pending.State.Cancellation.Cancel() } catch { }
}

function Invoke-RepeatRequest {
    $maximum = if ($script:settings.MaxRepeatCount -gt 0) { [int]$script:settings.MaxRepeatCount } else { 5 }
    $answer = Show-InputBox -Prompt "How many times should the request be sent? (1 - $maximum)" -Title 'Repeat request' -DefaultText '3'
    $count = 0
    if (-not [int]::TryParse($answer, [ref]$count) -or $count -lt 1) { return }
    Invoke-SendRequest -Repeat @{ Total = [Math]::Min($count, $maximum); Done = 0; Passed = 0; Failed = 0 }
}

# ------------------------------------------------------------------------------------------------
# Response viewer
# ------------------------------------------------------------------------------------------------

function Clear-ResponseView {
    $controls = $script:ui
    $controls.StatusBadge.Visibility = 'Collapsed'
    $controls.ResponseTimeText.Text = ''; $controls.ResponseSizeText.Text = ''
    $controls.ResponseBodyBox.Text = ''; $controls.ResponseHeadersBox.Text = ''
    $controls.JsonTree.Items.Clear()
    $controls.TestResultsList.Items.Clear()
    $controls.TabPreview.Visibility = 'Collapsed'
    $script:lastResponseText = ''; $script:lastResponseHeadersText = ''; $script:lastResult = $null
    Update-FindMatches
}

function Set-ResponseWrap {
    param([bool]$Wrap)
    $mode = if ($Wrap) { 'Wrap' } else { 'NoWrap' }
    Set-CodeEditorWrap -Name 'ResponseBody' -Wrap $Wrap
    foreach ($box in @($script:ui.ResponseHeadersBox, $script:ui.CodeBox)) { $box.TextWrapping = $mode }
}

function Show-ResponseResult {
    param($Result, [switch]$Live)
    $controls = $script:ui
    $controls.ResponseTimeText.Text = "$($Result.ElapsedMs) ms"
    $brushConverter = New-Object System.Windows.Media.BrushConverter

    if (-not $Result.Success) {
        $controls.StatusBadge.Visibility = 'Visible'
        $controls.StatusBadge.Background = $brushConverter.ConvertFromString('#D93025')
        $controls.ResponseStatusText.Text = if ($Result.Canceled) { 'Canceled' } else { 'Error' }
        $controls.ResponseSizeText.Text = ''
        $controls.ResponseBodyBox.Text = [string]$Result.ErrorMessage
        $controls.ResponseHeadersBox.Text = ''
        $controls.JsonTree.Items.Clear()
        $controls.TestResultsList.Items.Clear()
        $controls.TabPreview.Visibility = 'Collapsed'
        $script:lastResponseText = ''; $script:lastResponseHeadersText = ''
        $script:lastResult = $Result
        if ($Live) { Set-UiStatus ([string]$Result.ErrorMessage) }
        Update-FindMatches
        return
    }

    $script:lastResult = $Result
    $badgeColor = if ($Result.StatusCode -lt 300) { '#107C10' } elseif ($Result.StatusCode -lt 400) { '#B45309' } else { '#D93025' }
    $controls.StatusBadge.Visibility = 'Visible'
    $controls.StatusBadge.Background = $brushConverter.ConvertFromString($badgeColor)
    $controls.ResponseStatusText.Text = "$($Result.StatusCode) $($Result.ReasonPhrase)".Trim()
    $controls.ResponseSizeText.Text = Format-Bytes $Result.SizeBytes
    $script:lastResponseHeadersText = ($Result.HeaderLines -join "`r`n")
    $controls.ResponseHeadersBox.Text = $script:lastResponseHeadersText

    if ($Result.IsBinary) {
        $script:lastResponseText = ''
        $savedNote = if ($Result.SavedPath) { "Saved to: $($Result.SavedPath)" } elseif ($Result.SaveNote) { $Result.SaveNote } else { "Use 'Save...' to write the response to a file, or set an Output file on the Body tab before sending." }
        $controls.ResponseBodyBox.Text = "[Binary content: $($Result.ContentType), $(Format-Bytes $Result.SizeBytes)]`r`n`r`n$savedNote"
    } else {
        $script:lastResponseText = [string]$Result.Body
        $displayText = $script:lastResponseText
        if ($displayText.Length -le 1500000) {
            try {
                if (($Result.ContentType -match 'json') -or ($displayText.TrimStart() -match '^[\{\[]')) { $displayText = Format-JsonText -Text $displayText }
                elseif ($Result.ContentType -match 'xml' -and $Result.ContentType -notmatch 'html') { $displayText = Format-XmlText -Text $displayText }
            } catch { $displayText = $script:lastResponseText }
        }
        if ($Result.SavedPath) { $displayText = "[Saved to: $($Result.SavedPath)]`r`n`r`n$displayText" }
        $controls.ResponseBodyBox.Text = $displayText
    }

    Show-ResponsePreview -Result $Result
    Update-JsonTree
    Update-FindMatches
    if ($controls.ResponseTabs.SelectedItem -eq $controls.TabCode) { Update-CodeSnippet }
    Update-ExtractVariableChoices
    if ($Result.TestResults) { Show-TestResults -Results $Result.TestResults -Select:$Live } else { $controls.TestResultsList.Items.Clear() }
    if ($Live -and -not $Result.TestResults) { Set-UiStatus "$($Result.StatusCode) $($Result.ReasonPhrase) in $($Result.ElapsedMs) ms" }
}

function Show-TestResults {
    param($Results, [switch]$Select)
    $controls = $script:ui
    $controls.TestResultsList.Items.Clear()
    $failed = 0
    foreach ($testResult in @($Results)) {
        $textBlock = New-Object System.Windows.Controls.TextBlock
        $textBlock.TextWrapping = 'Wrap'
        $textBlock.Text = "[$($testResult.Status)] $($testResult.Message)"
        $textBlock.Foreground = switch ($testResult.Status) { 'PASS' { [System.Windows.Media.Brushes]::SeaGreen } 'FAIL' { [System.Windows.Media.Brushes]::Firebrick } default { [System.Windows.Media.Brushes]::DarkOrange } }
        if ($testResult.Status -ne 'PASS') { $failed++ }
        [void]$controls.TestResultsList.Items.Add($textBlock)
    }
    if ($controls.TestResultsList.Items.Count -gt 0) {
        $controls.TabTestResults.Visibility = 'Visible'
        if ($Select) { $controls.ResponseTabs.SelectedItem = $controls.TabTestResults }
        Set-UiStatus "Tests: $($controls.TestResultsList.Items.Count - $failed) passed, $failed failed."
    }
}

function Show-ResponsePreview {
    param($Result)
    $controls = $script:ui
    $controls.PreviewImage.Visibility = 'Collapsed'
    $controls.PreviewBrowser.Visibility = 'Collapsed'
    $shown = $false
    try {
        if ($Result.IsBinary -and $Result.ContentType -match '^image/') {
            $stream = New-Object System.IO.MemoryStream(, [byte[]]$Result.BodyBytes)
            $bitmap = New-Object System.Windows.Media.Imaging.BitmapImage
            $bitmap.BeginInit(); $bitmap.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad; $bitmap.StreamSource = $stream; $bitmap.EndInit()
            $controls.PreviewImage.Source = $bitmap
            $controls.PreviewImage.Visibility = 'Visible'
            $shown = $true
        } elseif (-not $Result.IsBinary -and ($Result.ContentType -match 'html' -or (Test-IsHtmlBody -Body $Result.Body))) {
            $controls.PreviewBrowser.NavigateToString([string]$Result.Body)
            $controls.PreviewBrowser.Visibility = 'Visible'
            $shown = $true
        }
    } catch { $shown = $false }
    $controls.TabPreview.Visibility = if ($shown) { 'Visible' } else { 'Collapsed' }
    if (-not $shown -and $controls.ResponseTabs.SelectedItem -eq $controls.TabPreview) { $controls.ResponseTabs.SelectedItem = $controls.TabResponse }
}

function Format-ResponseBody {
    $text = [string]$script:lastResponseText
    if (-not $text) { return }
    try {
        $pretty = if ($text.TrimStart() -match '^[\{\[]') { Format-JsonText -Text $text } elseif ($text.TrimStart().StartsWith('<')) { Format-XmlText -Text $text } else { $text }
        $script:ui.ResponseBodyBox.Text = $pretty
    } catch { Set-UiStatus "Could not prettify: $($_.Exception.Message)" }
}

function Get-ResponseFileExtension {
    param([string]$ContentType)
    switch -Regex ($ContentType) {
        'json' { return '.json' } 'xml' { return '.xml' } 'html' { return '.html' } 'csv' { return '.csv' } 'pdf' { return '.pdf' }
        'png' { return '.png' } 'jpe?g' { return '.jpg' } 'gif' { return '.gif' } 'zip' { return '.zip' } '^text/' { return '.txt' }
        default { return '.bin' }
    }
}

function Save-ResponseToFile {
    $result = $script:lastResult
    if (-not $result -or -not $result.Success) { Set-UiStatus 'There is no response to save.'; return }
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title = 'Save response'
    $dialog.FileName = if ($result.ContentDispositionName) { $result.ContentDispositionName.Trim('"') } else { 'response' + (Get-ResponseFileExtension -ContentType $result.ContentType) }
    if ($dialog.ShowDialog((Get-MainWindow)) -ne $true) { return }
    [System.IO.File]::WriteAllBytes($dialog.FileName, [byte[]]$result.BodyBytes)
    Set-UiStatus "Saved response to $($dialog.FileName)"
}

# Settings: AutoSaveToFile + AutoSavePath (+ AutoRenameFile / AutoRenamePrefix) write every response to disk.
# Classic save rules for binary / attachment responses:
#  - Settings > Auto-save: written to the auto-save folder using the Content-Disposition filename; with Auto-rename the
#    name comes from the uploaded file(s) ("<prefix><name><ext>" or "<prefix><name1> and <name2><ext>").
#  - otherwise, when an Output file is set on the Body tab, the response is written there.
function Save-ResponseFileIfNeeded {
    param($Result, $State)
    try {
        $isAttachment = [bool](@($Result.HeaderLines) | Where-Object { $_ -match '^(?i)content-disposition\s*:.*attachment' })
        if (-not ($Result.IsBinary -or $isAttachment)) { return }
        $target = $null
        if ($script:settings.AutoSaveToFile -and $script:settings.AutoSavePath -and [System.IO.Directory]::Exists($script:settings.AutoSavePath)) {
            $fileName = ([string]$Result.ContentDispositionName).Trim('"')
            if (-not $fileName) { $Result.SaveNote = "Auto-save is enabled, but the server did not include a filename in the Content-Disposition header, so the file was not saved."; return }
            if ($script:settings.AutoRenameFile) {
                $uploads = @()
                if ([string]$State.BodyType -eq 'multipart/form-data') { $uploads = @(Convert-MultipartBodyToItems -BodyText ([string]$State.Body) | Where-Object { $_.Kind -eq 'File' }) }
                $prefix = if ($script:settings.EnableAutoRenamePrefix) { [string]$script:settings.AutoRenamePrefix } else { '' }
                $extension = [System.IO.Path]::GetExtension($fileName)
                $uploadName = { param($item) [System.IO.Path]::GetFileNameWithoutExtension($(if ($item.FileName) { $item.FileName } else { $item.Value })) }
                if ($uploads.Count -eq 1) { $fileName = "$prefix$(& $uploadName $uploads[0])$extension" }
                elseif ($uploads.Count -ge 2) { $fileName = "$prefix$(& $uploadName $uploads[0]) and $(& $uploadName $uploads[1])$extension" }
            }
            $target = Join-Path $script:settings.AutoSavePath $fileName
        } elseif ($script:ui -and -not [string]::IsNullOrWhiteSpace($script:ui.OutputFileBox.Text)) {
            $target = $script:ui.OutputFileBox.Text.Trim()
        }
        if (-not $target) { return }
        $parent = [System.IO.Path]::GetDirectoryName($target)
        if ($parent -and -not (Test-Path $parent)) { [System.IO.Directory]::CreateDirectory($parent) | Out-Null }
        [System.IO.File]::WriteAllBytes($target, [byte[]]$Result.BodyBytes)
        $Result.SavedPath = $target
        Write-Log "Saved file to $target" -Level Info
    } catch {
        $Result.SaveNote = "Could not save the file: $($_.Exception.Message)"
        Write-Log "Response save failed: $($_.Exception.Message)" -Level Info
    }
}

function Copy-ResponseToClipboard {
    $controls = $script:ui
    $text = if ($controls.ResponseTabs.SelectedItem -eq $controls.TabResponseHeaders) { $controls.ResponseHeadersBox.Text } elseif ($controls.ResponseTabs.SelectedItem -eq $controls.TabCode) { $controls.CodeBox.Text } else { $controls.ResponseBodyBox.Text }
    if ($text) { [System.Windows.Clipboard]::SetText($text); Set-UiStatus 'Copied to clipboard.' }
}

function Move-ResponseToLine {
    $box = $script:ui.ResponseBodyBox
    $answer = Show-InputBox -Prompt "Go to line (1 - $($box.LineCount)):" -Title 'Go to line' -DefaultText '1'
    $lineNumber = 0
    if (-not [int]::TryParse($answer, [ref]$lineNumber)) { return }
    $lineNumber = [Math]::Max(1, [Math]::Min($lineNumber, $box.LineCount))
    $script:ui.ResponseTabs.SelectedItem = $script:ui.TabResponse
    $startIndex = $box.GetCharacterIndexFromLineIndex($lineNumber - 1)
    $box.Select($startIndex, $box.GetLineLength($lineNumber - 1))
    Show-TextBoxIndex -Box $box -Index $startIndex
    [void]$box.Focus()
}

# ---- find in response ----
function Get-FindTarget {
    $controls = $script:ui
    $selected = $controls.ResponseTabs.SelectedItem
    if ($selected -eq $controls.TabResponseHeaders) { return $controls.ResponseHeadersBox }
    if ($selected -eq $controls.TabCode) { return $controls.CodeBox }
    if ($selected -eq $controls.TabConsole) { return $controls.ConsoleOutputBox }
    return $controls.ResponseBodyBox
}

function Show-FindBar {
    $controls = $script:ui
    if ($controls.ResponseTabs.SelectedItem -eq $controls.TabJsonTree) { [void]$controls.JsonSearchBox.Focus(); return }
    $controls.FindBar.Visibility = 'Visible'
    [void]$controls.FindBox.Focus()
    $controls.FindBox.SelectAll()
    Update-FindMatches
}

function Hide-FindBar {
    $script:ui.FindBar.Visibility = 'Collapsed'
    $script:findMatches = @()
}

function Update-FindMatches {
    $controls = $script:ui
    if (-not $controls -or $controls.FindBar.Visibility -ne 'Visible') { return }
    $script:findMatches = @()
    $script:findIndex = -1
    $term = $controls.FindBox.Text
    $target = Get-FindTarget
    if ($term) {
        $text = $target.Text
        $position = $text.IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase)
        $found = New-Object System.Collections.Generic.List[int]
        while ($position -ge 0 -and $found.Count -lt 20000) {
            $found.Add($position)
            $position = $text.IndexOf($term, $position + [Math]::Max(1, $term.Length), [System.StringComparison]::OrdinalIgnoreCase)
        }
        $script:findMatches = @($found)
    }
    $controls.FindCountText.Text = if ($term) { "$($script:findMatches.Count) match(es)" } else { '' }
    if ($script:findMatches.Count -gt 0) { Step-FindMatch -Forward $true }
}

function Step-FindMatch {
    param([bool]$Forward)
    $matchPositions = @($script:findMatches)
    if ($matchPositions.Count -eq 0) { return }
    $script:findIndex = if ($Forward) { ($script:findIndex + 1) % $matchPositions.Count } else { ($script:findIndex - 1 + $matchPositions.Count) % $matchPositions.Count }
    $target = Get-FindTarget
    $term = $script:ui.FindBox.Text
    $target.IsInactiveSelectionHighlightEnabled = $true
    $target.Select($matchPositions[$script:findIndex], $term.Length)
    Show-TextBoxIndex -Box $target -Index $matchPositions[$script:findIndex]
    $script:ui.FindCountText.Text = "$($script:findIndex + 1) of $($matchPositions.Count)"
}

# ---- extract variable ----
function Update-ExtractVariableChoices {
    $controls = $script:ui
    if (-not $controls) { return }
    $controls.ExtractExistingBox.Items.Clear()
    [void]$controls.ExtractExistingBox.Items.Add('')
    foreach ($name in (Get-VariableNames -Scope ([string]$controls.ExtractScopeBox.SelectedItem))) { [void]$controls.ExtractExistingBox.Items.Add($name) }
    $controls.ExtractExistingBox.SelectedIndex = 0
}

function Invoke-ExtractVariable {
    $controls = $script:ui
    $name = $controls.ExtractNameBox.Text.Trim()
    $brushes = [System.Windows.Media.Brushes]
    if (-not $name) { $controls.ExtractStatusText.Text = 'Variable name is required.'; $controls.ExtractStatusText.Foreground = $brushes::Firebrick; return }
    $extracted = Get-ExtractedValue -Source ([string]$controls.ExtractSourceBox.SelectedItem) -Mode ([string]$controls.ExtractModeBox.SelectedItem) -Path $controls.ExtractPathBox.Text `
        -BodyText $script:lastResponseText -HeadersText $script:lastResponseHeadersText
    if (-not $extracted.Success) { $controls.ExtractStatusText.Text = $extracted.Error; $controls.ExtractStatusText.Foreground = $brushes::Firebrick; return }
    $saved = Save-ExtractedVariable -Scope ([string]$controls.ExtractScopeBox.SelectedItem) -Name $name -Value ([string]$extracted.Value)
    $controls.ExtractStatusText.Text = $saved.Message
    $controls.ExtractStatusText.Foreground = if ($saved.Success) { $brushes::SeaGreen } else { $brushes::Firebrick }
    if ($saved.Success) { Update-ExtractVariableChoices; $controls.ExtractExistingBox.SelectedItem = $name }
}

# ---- JSON tree ----
function Add-JsonTreeNode {
    param($ParentItems, [string]$Label, $Value, [string]$Path)
    if ($script:jsonNodeCount -ge 5000) { return }
    $script:jsonNodeCount++
    $item = New-Object System.Windows.Controls.TreeViewItem
    $item.Tag = $Path
    $isObject = $Value -is [System.Management.Automation.PSCustomObject]
    $isArray = ($Value -is [System.Array]) -or ($Value -is [System.Collections.IList])
    if ($isObject) {
        $properties = @($Value.PSObject.Properties)
        $item.Header = "$Label : { $($properties.Count) }"
        foreach ($property in $properties) { Add-JsonTreeNode -ParentItems $item.Items -Label $property.Name -Value $property.Value -Path $(if ($Path) { "$Path.$($property.Name)" } else { $property.Name }) }
    } elseif ($isArray) {
        $elements = @($Value)
        $item.Header = "$Label : [ $($elements.Count) ]"
        for ($index = 0; $index -lt $elements.Count; $index++) { Add-JsonTreeNode -ParentItems $item.Items -Label "[$index]" -Value $elements[$index] -Path "$Path[$index]" }
    } else {
        $display = if ($null -eq $Value) { 'null' } elseif ($Value -is [string]) { '"' + $(if ($Value.Length -gt 200) { $Value.Substring(0, 200) + '...' } else { $Value }) + '"' } else { [string]$Value }
        $item.Header = "$Label : $display"
    }
    [void]$ParentItems.Add($item)
    [void]$script:jsonNodes.Add($item)
}

function Update-JsonTree {
    $controls = $script:ui
    $controls.JsonTree.Items.Clear()
    $script:jsonNodes = New-Object System.Collections.ArrayList
    $script:jsonSearchIndex = -1
    $controls.JsonStatusText.Text = ''
    $text = [string]$script:lastResponseText
    if ($controls.TabJsonTree.Visibility -ne 'Visible' -or -not $text -or $text.Length -gt 400000 -or $text.TrimStart() -notmatch '^[\{\[]') { return }
    try {
        $parsed = $text | ConvertFrom-Json -ErrorAction Stop
        $script:jsonNodeCount = 0
        Add-JsonTreeNode -ParentItems $controls.JsonTree.Items -Label 'root' -Value $parsed -Path ''
        if ($controls.JsonTree.Items.Count -gt 0) { $controls.JsonTree.Items[0].IsExpanded = $true }
        if ($script:jsonNodeCount -ge 5000) { $controls.JsonStatusText.Text = 'Showing the first 5000 nodes.' }
    } catch { $controls.JsonStatusText.Text = 'The response is not valid JSON.' }
}

function Step-JsonTreeSearch {
    $controls = $script:ui
    $term = $controls.JsonSearchBox.Text
    if (-not $term -or -not $script:jsonNodes) { return }
    $count = $script:jsonNodes.Count
    for ($offset = 1; $offset -le $count; $offset++) {
        $index = ($script:jsonSearchIndex + $offset) % $count
        $item = $script:jsonNodes[$index]
        if (([string]$item.Header).IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $script:jsonSearchIndex = $index
            $parent = $item.Parent
            while ($parent -is [System.Windows.Controls.TreeViewItem]) { $parent.IsExpanded = $true; $parent = $parent.Parent }
            $item.IsSelected = $true
            $item.BringIntoView()
            $controls.JsonStatusText.Text = "Match at node $($index + 1) of $count"
            return
        }
    }
    $controls.JsonStatusText.Text = 'No match.'
}

function Set-JsonTreeExpanded {
    param([bool]$Expanded)
    $walk = { param($items) foreach ($node in $items) { $node.IsExpanded = $Expanded; & $walk $node.Items } }
    & $walk $script:ui.JsonTree.Items
}

function Copy-JsonTreePath {
    $selected = $script:ui.JsonTree.SelectedItem
    if ($selected -and $selected.Tag) { [System.Windows.Clipboard]::SetText([string]$selected.Tag); $script:ui.JsonStatusText.Text = "Copied: $($selected.Tag)" }
}

# ---- code snippets ----
function Update-CodeSnippet {
    $controls = $script:ui
    $state = Get-EditorState
    $snippetSource = [PSCustomObject]@{
        Method = $state.Method; Url = (Expand-Variables -InputString $state.Url); Headers = (Expand-Variables -InputString $state.Headers)
        Body = (Expand-Variables -InputString $state.Body); BodyType = $state.BodyType
    }
    if ($state.BodyType -eq 'GraphQL') {
        $payload = [ordered]@{ query = $state.GqlQuery }
        if ($state.GqlVars -match '\S') { try { $payload['variables'] = $state.GqlVars | ConvertFrom-Json } catch { } }
        $snippetSource.Method = 'POST'; $snippetSource.Body = ($payload | ConvertTo-Json -Depth 20 -Compress); $snippetSource.BodyType = 'application/json'
    }
    $controls.CodeBox.Text = New-CodeSnippet -RequestItem $snippetSource -Language ([string]$controls.CodeLanguageBox.SelectedItem)
}

# ---- console ----
function Invoke-ConsoleRun {
    $controls = $script:ui
    $code = $controls.ConsoleInputBox.Text
    if ([string]::IsNullOrWhiteSpace($code)) { return }
    $defaultLanguage = if ($script:settings.DefaultConsoleLanguage) { [string]$script:settings.DefaultConsoleLanguage } else { 'PowerShell' }
    $controls.ConsoleOutputBox.AppendText("> $code`r`n")
    $consoleResult = Invoke-ConsoleCommand -Code $code -DefaultLanguage $defaultLanguage
    if ($consoleResult.Output) { $controls.ConsoleOutputBox.AppendText($consoleResult.Output) }
    if ($consoleResult.Error) { $controls.ConsoleOutputBox.AppendText("Error: $($consoleResult.Error)`r`n") }
    $controls.ConsoleOutputBox.AppendText("`r`n")
    $controls.ConsoleOutputBox.ScrollToEnd()
}

# ------------------------------------------------------------------------------------------------
# Layout and settings
# ------------------------------------------------------------------------------------------------

# Docks the response panel to the Bottom, Left or Right of the request editor, or undocks it into its own window
# (same options as the classic window's "Docking Options" menu).
function Set-ResponseDock {
    param([string]$Dock = 'Right')
    $controls = $script:ui
    $grid = $controls.WorkspaceGrid
    $response = $controls.ResponsePanel; $editor = $controls.RequestTabs; $splitter = $controls.WorkspaceSplitter

    if ($Dock -eq 'Undocked') {
        if ($script:responseWindow) { $script:responseWindow.Activate() | Out-Null; return }
        $grid.Children.Remove($response)
        $floating = New-Object System.Windows.Window
        $floating.Title = 'Response'; $floating.Width = 900; $floating.Height = 700
        $floating.Owner = Get-MainWindow
        $floating.WindowStartupLocation = 'CenterOwner'
        $floating.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'Form')
        $floating.SetResourceReference([System.Windows.Window]::ForegroundProperty, 'Text')
        $floating.FontFamily = New-Object System.Windows.Media.FontFamily('Segoe UI')
        foreach ($key in (Get-MainWindow).Resources.Keys) { $floating.Resources[$key] = (Get-MainWindow).Resources[$key] }
        Register-WpfWindow -Window $floating
        $response.Margin = [System.Windows.Thickness]::new(10)
        $floating.Content = $response
        $floating.Add_Closing({ if (-not $script:isRedockingResponse) { $script:responseWindowClosing = $true; try { Invoke-UiGuard { Set-ResponseDock -Dock 'Right'; Save-Settings } 'Dock' } finally { $script:responseWindowClosing = $false } } })
        $script:responseWindow = $floating
        Set-WindowFitToScreen -Window $floating -Reference (Get-MainWindow)
        $floating.Show()
        [System.Windows.Controls.Grid]::SetRow($editor, 0); [System.Windows.Controls.Grid]::SetColumn($editor, 0)
        [System.Windows.Controls.Grid]::SetRowSpan($editor, 3); [System.Windows.Controls.Grid]::SetColumnSpan($editor, 3)
        $grid.RowDefinitions[0].MinHeight = 0; $grid.RowDefinitions[2].MinHeight = 0
        $splitter.Visibility = 'Collapsed'
        $script:settings.ResponseDockState = 'Undocked'
        return
    }

    if ($script:responseWindow) {
        $script:isRedockingResponse = $true
        try { $script:responseWindow.Content = $null; if (-not $script:responseWindowClosing) { $script:responseWindow.Close() } } finally { $script:isRedockingResponse = $false }
        $script:responseWindow = $null
        $response.Margin = [System.Windows.Thickness]::new(0)
        [void]$grid.Children.Add($response)
    }
    $splitter.Visibility = 'Visible'
    $rows = $grid.RowDefinitions; $columns = $grid.ColumnDefinitions
    $star = { param([double]$value) [System.Windows.GridLength]::new($value, [System.Windows.GridUnitType]::Star) }
    $zero = [System.Windows.GridLength]::new(0)
    $thin = [System.Windows.GridLength]::new(6)
    $place = { param($element, [int]$row, [int]$column, [int]$rowSpan, [int]$columnSpan)
        [System.Windows.Controls.Grid]::SetRow($element, $row); [System.Windows.Controls.Grid]::SetColumn($element, $column)
        [System.Windows.Controls.Grid]::SetRowSpan($element, $rowSpan); [System.Windows.Controls.Grid]::SetColumnSpan($element, $columnSpan) }

    if ($Dock -eq 'Bottom') {
        $rows[0].Height = & $star 1; $rows[1].Height = $thin; $rows[2].Height = & $star 1.4
        $rows[0].MinHeight = 140; $rows[2].MinHeight = 160
        $columns[0].Width = & $star 1; $columns[1].Width = $zero; $columns[2].Width = $zero
        & $place $editor 0 0 1 3; & $place $splitter 1 0 1 3; & $place $response 2 0 1 3
        $splitter.HorizontalAlignment = 'Stretch'; $splitter.VerticalAlignment = 'Center'; $splitter.Height = 4; $splitter.Width = [double]::NaN
    } else {
        $rows[0].Height = & $star 1; $rows[1].Height = $zero; $rows[2].Height = $zero
        $rows[0].MinHeight = 0; $rows[2].MinHeight = 0
        $splitter.HorizontalAlignment = 'Center'; $splitter.VerticalAlignment = 'Stretch'; $splitter.Width = 4; $splitter.Height = [double]::NaN
        $columns[0].Width = & $star 1.2; $columns[1].Width = $thin; $columns[2].Width = & $star 1
        if ($Dock -eq 'Left') { & $place $response 0 0 3 1; & $place $splitter 0 1 3 1; & $place $editor 0 2 3 1 }
        else { & $place $editor 0 0 3 1; & $place $splitter 0 1 3 1; & $place $response 0 2 3 1 }
    }
    $script:settings.ResponseDockState = $Dock
}

$script:DockChoices = @(@('Dock to the right', 'Right'), @('Dock to the bottom', 'Bottom'), @('Dock to the left', 'Left'), @('Undock (own window)', 'Undocked'))

function Add-DockMenuItems {
    param($ItemsControl)
    foreach ($choice in $script:DockChoices) {
        $menuItem = New-Object System.Windows.Controls.MenuItem
        $menuItem.Header = $choice[0]; $menuItem.Tag = $choice[1]
        $menuItem.Add_Click({ param($sender) Invoke-UiGuard { Set-ResponseDock -Dock ([string]$sender.Tag); Save-Settings } 'Dock' })
        [void]$ItemsControl.Items.Add($menuItem)
    }
}

function Update-DockMenuChecks {
    param($ItemsControl)
    foreach ($menuItem in $ItemsControl.Items) { if ($menuItem -is [System.Windows.Controls.MenuItem]) { $menuItem.IsChecked = ([string]$menuItem.Tag -eq [string]$script:settings.ResponseDockState) } }
}

# Sub-menu "Response position" in the response toolbar's more menu.
function Initialize-DockMenu {
    param($MenuItem)
    Add-DockMenuItems -ItemsControl $MenuItem
    $MenuItem.Add_SubmenuOpened({ param($sender) Update-DockMenuChecks -ItemsControl $sender })
}

# Right-click menu on the response toolbar (classic behaviour).
function New-DockingContextMenu {
    $menu = New-Object System.Windows.Controls.ContextMenu
    Add-DockMenuItems -ItemsControl $menu
    $menu.Add_Opened({ param($sender) Update-DockMenuChecks -ItemsControl $sender })
    return $menu
}

# History/collections sidebar: classic "Undock Panel" / "Dock Panel".
function Set-SidebarDocked {
    param([bool]$Docked)
    $controls = $script:ui
    $sidebar = $controls.SidebarTabs
    if (-not $Docked) {
        if ($script:sidebarWindow) { $script:sidebarWindow.Activate() | Out-Null; return }
        $parent = $sidebar.Parent
        $parent.Children.Remove($sidebar)
        $controls.SidebarColumn.Width = [System.Windows.GridLength]::new(0); $controls.SidebarSplitterColumn.Width = [System.Windows.GridLength]::new(0)
        $controls.SidebarSplitter.Visibility = 'Collapsed'
        $floating = New-Object System.Windows.Window
        $floating.Title = 'Collections & History'; $floating.Width = 380; $floating.Height = 720
        $floating.Owner = Get-MainWindow
        $floating.WindowStartupLocation = 'Manual'
        $mainWindow = Get-MainWindow
        $floating.Left = [Math]::Max(0, $mainWindow.Left - 390); $floating.Top = $mainWindow.Top + 60
        $floating.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'Form')
        $floating.SetResourceReference([System.Windows.Window]::ForegroundProperty, 'Text')
        $floating.FontFamily = New-Object System.Windows.Media.FontFamily('Segoe UI')
        foreach ($key in $mainWindow.Resources.Keys) { $floating.Resources[$key] = $mainWindow.Resources[$key] }
        Register-WpfWindow -Window $floating
        $sidebar.Margin = [System.Windows.Thickness]::new(8)
        $floating.Content = $sidebar
        $floating.Add_Closing({ if (-not $script:isRedockingSidebar) { $script:sidebarWindowClosing = $true; try { Invoke-UiGuard { Set-SidebarDocked -Docked $true; Save-Settings } 'Dock' } finally { $script:sidebarWindowClosing = $false } } })
        $script:sidebarWindow = $floating
        Set-WindowFitToScreen -Window $floating -Reference (Get-MainWindow)
        $floating.Show()
        $script:settings.HistoryUndocked = $true
        return
    }
    if (-not $script:sidebarWindow) { return }
    $script:isRedockingSidebar = $true
    try { $script:sidebarWindow.Content = $null; if (-not $script:sidebarWindowClosing) { $script:sidebarWindow.Close() } } finally { $script:isRedockingSidebar = $false }
    $script:sidebarWindow = $null
    $sidebar.Margin = [System.Windows.Thickness]::new(0)
    [System.Windows.Controls.Grid]::SetColumn($sidebar, 0)
    [void]$controls.SidebarSplitter.Parent.Children.Add($sidebar)
    $controls.SidebarColumn.Width = [System.Windows.GridLength]::new(310); $controls.SidebarSplitterColumn.Width = [System.Windows.GridLength]::new(6)
    $controls.SidebarSplitter.Visibility = 'Visible'
    $script:settings.HistoryUndocked = $false
}

function New-SidebarDockingMenu {
    $menu = New-Object System.Windows.Controls.ContextMenu
    $menuItem = New-Object System.Windows.Controls.MenuItem
    $menuItem.Header = 'Undock Panel'
    $menuItem.Add_Click({ Invoke-UiGuard { Set-SidebarDocked -Docked ([bool]$script:sidebarWindow); Save-Settings } 'Dock' })
    [void]$menu.Items.Add($menuItem)
    $menu.Add_Opened({ param($sender) $sender.Items[0].Header = if ($script:sidebarWindow) { 'Dock Panel' } else { 'Undock Panel' } })
    return $menu
}

function Close-FloatingPanels {
    if ($script:responseWindow) { $script:isRedockingResponse = $true; try { $script:responseWindow.Close() } catch { }; $script:responseWindow = $null; $script:isRedockingResponse = $false; $script:settings.ResponseDockState = 'Undocked' }
    if ($script:sidebarWindow) { $script:isRedockingSidebar = $true; try { $script:sidebarWindow.Close() } catch { }; $script:sidebarWindow = $null; $script:isRedockingSidebar = $false }
}

function Update-MethodChoices {
    $box = $script:ui.MethodBox
    $current = [string]$box.SelectedItem
    $methods = @('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')
    if ($script:settings.EnableAllMethods) { $methods += @('TRACE', 'CONNECT') }
    if ($current -and $current -notin $methods) { $methods += $current }
    $script:isSwitchingRequestTab = $true
    try { $box.Items.Clear(); foreach ($method in $methods) { [void]$box.Items.Add($method) }; $box.SelectedItem = if ($current) { $current } else { 'GET' } }
    finally { $script:isSwitchingRequestTab = $false }
}

# Applies the "Show ... tab" settings, repeat button and response font size.
function Update-UiFromSettings {
    $controls = $script:ui
    if (-not $controls) { return }
    Update-MethodChoices
    $visibility = { param([bool]$show) if ($show) { 'Visible' } else { 'Collapsed' } }
    $controls.TabHeaders.Visibility = & $visibility ([bool]$script:settings.ShowRequestHeadersTab)
    $controls.TabAuth.Visibility = & $visibility ([bool]$script:settings.ShowAuthTab)
    $controls.TabPreRequest.Visibility = & $visibility ([bool]$script:settings.ShowPreRequestTab)
    $controls.TabTests.Visibility = & $visibility ([bool]$script:settings.ShowTestsTab)
    $controls.TabResponseHeaders.Visibility = & $visibility ([bool]$script:settings.ShowResponseHeaders)
    $controls.TabJsonTree.Visibility = & $visibility ([bool]$script:settings.ShowJsonTreeTab)
    $controls.TabConsole.Visibility = & $visibility ([bool]$script:settings.ShowConsoleTab)
    $controls.TabCode.Visibility = & $visibility ([bool]$script:settings.ShowCurl)
    $controls.TabTestResults.Visibility = if ($script:settings.ShowTestResultsTab -or $controls.TestResultsList.Items.Count -gt 0) { 'Visible' } else { 'Collapsed' }
    $controls.TabHistory.Visibility = & $visibility ([bool]$script:settings.ShowHistory)
    $controls.ResponsePanel.Visibility = & $visibility ([bool]$script:settings.ShowResponse)
    $controls.EnvironmentPanel.Visibility = & $visibility ([bool]$script:settings.ShowEnvironmentPanel)
    $controls.RepeatButton.Visibility = & $visibility ([bool]$script:settings.EnableRepeatRequest)
    $fontSize = if ($script:settings.ResponseFontSize -gt 0) { [double]$script:settings.ResponseFontSize * 1.6 } else { 13 }
    foreach ($box in @($controls.ResponseHeadersBox, $controls.CodeBox, $controls.ConsoleOutputBox)) { $box.FontSize = $fontSize; $box.IsInactiveSelectionHighlightEnabled = $true }
    Set-CodeEditorFontSize -Name 'ResponseBody' -Size $fontSize
    foreach ($tabControl in @($controls.RequestTabs, $controls.ResponseTabs, $controls.SidebarTabs)) {
        $selected = $tabControl.SelectedItem
        if (-not $selected -or $selected.Visibility -ne 'Visible') {
            $firstVisible = @($tabControl.Items | Where-Object { $_.Visibility -eq 'Visible' }) | Select-Object -First 1
            if ($firstVisible) { $tabControl.SelectedItem = $firstVisible }
        }
    }
    Update-ImportMenuVisibility
    Update-SendButtons
}
#endregion
