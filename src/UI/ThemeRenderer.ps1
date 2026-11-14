#region Themed Menus
# Menus, context menus and the status bar use a custom renderer so they follow the active theme
# (flat Litera-style look, readable in Dark mode). If the helper type cannot be compiled the app simply
# keeps the default renderer.

function Initialize-ThemedRenderer {
    if ($script:ThemedRendererReady) { return $true }
    try {
        Add-Type -ReferencedAssemblies 'System.Windows.Forms', 'System.Drawing' -TypeDefinition @'
using System.Drawing;
using System.Windows.Forms;

public class AppThemeColorTable : ProfessionalColorTable
{
    public Color Surface = Color.White;
    public Color Hover = Color.LightGray;
    public Color Border = Color.Gray;
    public AppThemeColorTable() { UseSystemColors = false; }
    public override Color ToolStripDropDownBackground { get { return Surface; } }
    public override Color MenuStripGradientBegin { get { return Surface; } }
    public override Color MenuStripGradientEnd { get { return Surface; } }
    public override Color MenuItemSelected { get { return Hover; } }
    public override Color MenuItemSelectedGradientBegin { get { return Hover; } }
    public override Color MenuItemSelectedGradientEnd { get { return Hover; } }
    public override Color MenuItemPressedGradientBegin { get { return Hover; } }
    public override Color MenuItemPressedGradientMiddle { get { return Hover; } }
    public override Color MenuItemPressedGradientEnd { get { return Hover; } }
    public override Color MenuItemBorder { get { return Hover; } }
    public override Color MenuBorder { get { return Border; } }
    public override Color ImageMarginGradientBegin { get { return Surface; } }
    public override Color ImageMarginGradientMiddle { get { return Surface; } }
    public override Color ImageMarginGradientEnd { get { return Surface; } }
    public override Color SeparatorDark { get { return Border; } }
    public override Color SeparatorLight { get { return Surface; } }
    public override Color ToolStripBorder { get { return Border; } }
}

public class AppThemeRenderer : ToolStripProfessionalRenderer
{
    public Color TextColor = Color.Black;
    public AppThemeRenderer(AppThemeColorTable table) : base(table) { RoundedEdges = false; }
    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        // Keep the white-on-blue status bar text; everything else follows the theme text color.
        if (!(e.ToolStrip is StatusStrip)) { e.TextColor = TextColor; }
        base.OnRenderItemText(e);
    }
}
'@
        $script:ThemedRendererReady = $true
    } catch {
        Write-Log "Themed menu renderer unavailable: $($_.Exception.Message)" -Level Info
        $script:ThemedRendererReady = $false
    }
    return $script:ThemedRendererReady
}

# Applies the current $script:Theme to every ToolStrip (menus, context menus, status bar) in the app.
function Set-ThemedToolStripRenderer {
    if (-not (Initialize-ThemedRenderer)) { return }
    try {
        $colorTable = New-Object AppThemeColorTable
        $colorTable.Surface = $script:Theme.GroupBackground
        $colorTable.Hover   = $script:Theme.SecondaryButton
        $colorTable.Border  = $script:Theme.BorderColor
        $renderer = New-Object AppThemeRenderer($colorTable)
        $renderer.TextColor = $script:Theme.TextColor
        [System.Windows.Forms.ToolStripManager]::Renderer = $renderer
    } catch {
        Write-Log "Could not apply themed renderer: $($_.Exception.Message)" -Level Info
    }
}
#endregion
