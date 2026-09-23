<#
.SYNOPSIS
  EntraAudit-GUI.ps1 - WinForms GUI launcher for EntraAudit-PS7.ps1

  Provides a graphical interface to:
    - Install the Microsoft Graph modules
    - Choose how to sign in: interactive (optionally through your own read-only
      app registration, -DelegatedClientId) or app-only with a certificate
    - Choose the audit checks: run all and untick the ones to skip, or run only
      the ticked ones
    - Configure options (inactivity thresholds, break-glass accounts, output)
    - Preview and run the read-only audit command. The preview and the Run Audit
      button sit in a bar pinned to the bottom of the window, so they stay visible
      while the check list scrolls.

  Requirements:
    - PowerShell 7 (pwsh.exe)
    - EntraAudit-PS7.ps1 and both EntraAudit-Checks-*.ps1 companion libraries
      in the same folder as this script
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This GUI requires PowerShell 7 (pwsh.exe). Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

Write-Host "Opening Entra Audit GUI..."

$ScriptDir = $PSScriptRoot
$AuditScriptPath = Join-Path $ScriptDir 'EntraAudit-PS7.ps1'
$RequiredAuditFiles = @('EntraAudit-PS7.ps1','EntraAudit-Checks-Governance.ps1','EntraAudit-Checks-Applications.ps1')
$MissingAuditFiles = @($RequiredAuditFiles | Where-Object { -not (Test-Path -LiteralPath (Join-Path $ScriptDir $_) -PathType Leaf) })
if ($MissingAuditFiles.Count -gt 0) {
    Write-Error "Required audit file(s) not found in '$ScriptDir': $($MissingAuditFiles -join ', '). Keep the GUI, main script, and both check libraries together."
    exit 1
}

Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
Add-Type -AssemblyName System.Drawing      -ErrorAction Stop
[System.Windows.Forms.Application]::EnableVisualStyles()

function Msg-Error([string]$Message) {
    [System.Windows.Forms.MessageBox]::Show($Message, "Entra Audit - please check",
        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
}
function Msg-Info([string]$Message) {
    [System.Windows.Forms.MessageBox]::Show($Message, "Entra Audit",
        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}

# -------------------------
# Audit check definitions (mirrors EntraAudit-PS7.ps1 -switches and the README table)
# -------------------------
$AuditChecks = [ordered]@{
    tenantinfo     = "Tenant / organization overview, verified domains, licensing"
    privroles      = "FLAGSHIP: privileged roles - permanent vs eligible (PIM) vs time-bound; works without P2, PIM eligibility detail needs P2"
    directoryroles = "Global Admin count and privileged assignment volume"
    accounts       = "Account hygiene (disabled-but-licensed, non-expiring passwords)"
    staleusers     = "Stale / inactive / never-signed-in users (needs P1)"
    guests         = "Guest / external user governance, privileged guests"
    mfa            = "MFA capability and authentication method strength"
    legacyauth     = "Legacy authentication usage (sign-in logs, needs P1)"
    tenantposture  = "Security Defaults, authorization policy and consent settings"
    capolicies     = "Conditional Access policy posture"
    riskyusers     = "Identity Protection: risky users / detections (needs P2)"
    riskyserviceprincipals = "Identity Protection: risky service principals (needs Workload ID Premium)"
    apps           = "App / service principal hygiene, over-privilege, credentials"
    appcredentials = "App registration secret/cert expiry - expired and expiring-soon credentials"
    consentgrants  = "OAuth2 delegated consent grants (illicit consent risk)"
    devices        = "Stale / unmanaged / non-compliant devices"
    trusts         = "Cross-tenant access and B2B trust"
    recentchanges  = "Recently created users/groups and directory audit"
    tenanthealth   = "Directory-sync / Password Hash Sync platform health"
    pimpolicies    = "PIM policy quality (activation MFA/approval/justification/duration) - needs P2"
    breakglass     = "Emergency-access (break-glass) account health - enter the accounts under Step 4 Options"
    authmethodpolicy = "Tenant authentication-methods policy (weak vs phishing-resistant)"
    accesspaths    = "Effective-access / attack-path graph (duplicate & ownership privilege paths)"
    staleapps      = "Stale / unused applications by service-principal sign-in activity - needs P1"
    recommendations = "Microsoft Entra recommendations and unresolved high-impact actions"
    securescore    = "Microsoft Identity Secure Score and incomplete control posture"
    accessreviews  = "Access-review coverage, recurrence, reviewers and completion behavior"
    identitygovernance = "Entitlement management, lifecycle workflows, Terms of Use and PIM for Groups"
    authrecovery   = "SSPR/recovery readiness, registration campaign and system-preferred MFA"
    groupgovernance = "Group ownership, role-assignable groups, dynamic rules and lifecycle settings"
    externaldelegation = "External delegation, GDAP relationships and partner trust governance"
    federationhealth = "Federated-domain certificate, endpoint and hybrid authentication health"
    workloadcredentials = "Application and service-principal credentials, federated identities and policy enforcement"
    enterpriseapps = "Enterprise-app ownership, assignment controls and high-impact permissions"
    monitoring     = "Audit/sign-in visibility, diagnostic export and alert-rule/action-group inventory"
    changemonitoring = "Recent security-sensitive directory, policy, role and application changes"
}

# -------------------------
# Form
# -------------------------
# Layout: a scrolling panel (Dock=Fill) holds steps 1-4; a fixed bar (Dock=Bottom) holds the
# command preview and the Run Audit / Close buttons so they are always on screen.
$form = New-Object System.Windows.Forms.Form
$form.Text = "Entra Audit - read-only security audit for Microsoft Entra ID"
# Never open taller/wider than the screen's working area: the pinned Run Audit bar sits at the
# bottom edge of the window and must not end up below the taskbar on a 768 px laptop screen.
$formWidth = 1000; $formHeight = 900
try {
    $workArea = [System.Windows.Forms.Screen]::FromPoint([System.Windows.Forms.Cursor]::Position).WorkingArea
    if ($workArea.Width -gt 0 -and $workArea.Height -gt 0) {
        $formWidth  = [Math]::Min($formWidth,  $workArea.Width)
        $formHeight = [Math]::Min($formHeight, $workArea.Height)
    }
} catch {
    Write-Verbose "Could not read the screen size; using the default window size. $($_.Exception.Message)"
}
$form.Size = [System.Drawing.Size]::new($formWidth, $formHeight)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = [System.Drawing.Size]::new([Math]::Min(820, $formWidth), [Math]::Min(640, $formHeight))

$panel = New-Object System.Windows.Forms.Panel
$panel.Dock = 'Fill'
$panel.AutoScroll = $true

$bottomBarHeight = 150
$bottom = New-Object System.Windows.Forms.Panel
$bottom.Dock = 'Bottom'
$bottom.Height = $bottomBarHeight

$form.Controls.Add($panel)  | Out-Null
$form.Controls.Add($bottom) | Out-Null
# WinForms docks children from the BACK of the z-order (highest index, i.e. added last) to the
# front, and a Fill control takes whatever is left at its turn. The bottom bar must therefore
# be docked before the Fill panel; BringToFront makes that explicit so the scroll panel (and its
# scrollbar) is never partly hidden under the bar.
$panel.BringToFront()

$tips = New-Object System.Windows.Forms.ToolTip
$tips.AutoPopDelay = 20000; $tips.InitialDelay = 400; $tips.ReshowDelay = 100

$leftLabel  = 16
$labelWidth = 240
$leftInput  = 266
$inputWidth = 680
$rowHeight  = 28
$checkRowHeight = 26
$contentRight = 956   # right edge of the content column (16 + 940)

# Every helper adds to the scrolling panel unless -Parent says otherwise (the bottom bar).
function Add-Label {
    param([string]$Text, [int]$Top, [int]$Width = $script:labelWidth, [int]$X = $script:leftLabel, [object]$Parent = $script:panel)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text; $l.Location = New-Object System.Drawing.Point($X, $Top)
    $l.Size = New-Object System.Drawing.Size($Width, 20)
    # A fixed-size label otherwise cuts text that does not fit without any cue (only the
    # first wrapped line is drawn). AutoEllipsis shows "..." and the full text on hover.
    $l.AutoEllipsis = $true
    $Parent.Controls.Add($l) | Out-Null; return $l
}
function Add-Hint {
    param([string]$Text, [int]$Top, [int]$Width = $script:inputWidth, [int]$X = $script:leftInput, [object]$Parent = $script:panel)
    $h = Add-Label -Text $Text -Top $Top -Width $Width -X $X -Parent $Parent
    $h.ForeColor = [System.Drawing.Color]::DimGray
    return $h
}
function Add-LabelBold {
    param([string]$Text, [int]$Top, [int]$Width = 940, [int]$X = $script:leftLabel, [object]$Parent = $script:panel)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text; $l.Font = New-Object System.Drawing.Font($l.Font, [System.Drawing.FontStyle]::Bold)
    $l.Location = New-Object System.Drawing.Point($X, $Top); $l.Size = New-Object System.Drawing.Size($Width, 22)
    $l.AutoEllipsis = $true
    $Parent.Controls.Add($l) | Out-Null; return $l
}
function Add-TextBox {
    param([int]$Top, [bool]$ReadOnly = $false, [bool]$Multiline = $false, [int]$Height = 22, [int]$Width = $script:inputWidth, [int]$X = $script:leftInput, [object]$Parent = $script:panel)
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = New-Object System.Drawing.Point($X, ($Top - 3))
    $t.Size = New-Object System.Drawing.Size($Width, $Height)
    $t.ReadOnly = $ReadOnly; $t.Multiline = $Multiline
    if ($Multiline) { $t.ScrollBars = 'Vertical' }
    $Parent.Controls.Add($t) | Out-Null; return $t
}
function Add-Check {
    param([string]$Text, [int]$Top, [bool]$Checked = $false, [int]$Width = 220, [int]$X = $script:leftInput, [object]$Parent = $script:panel)
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $Text; $c.Location = New-Object System.Drawing.Point($X, ($Top - 4))
    $c.Size = New-Object System.Drawing.Size($Width, 22); $c.Checked = $Checked
    $Parent.Controls.Add($c) | Out-Null; return $c
}
function Add-Radio {
    param([string]$Text, [int]$Top, [bool]$Checked = $false, [int]$Width = 220, [int]$X = $script:leftInput, [object]$Parent = $script:panel)
    $r = New-Object System.Windows.Forms.RadioButton
    $r.Text = $Text; $r.Location = New-Object System.Drawing.Point($X, ($Top - 4))
    $r.Size = New-Object System.Drawing.Size($Width, 22); $r.Checked = $Checked
    $Parent.Controls.Add($r) | Out-Null; return $r
}
function Add-Button {
    param([string]$Text, [int]$Top, [int]$Width = 200, [int]$Height = 30, [int]$X = $script:leftInput, [object]$Parent = $script:panel)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Location = New-Object System.Drawing.Point($X, ($Top - 2))
    $b.Size = New-Object System.Drawing.Size($Width, $Height)
    $Parent.Controls.Add($b) | Out-Null; return $b
}
function Add-Separator {
    param([int]$Top, [object]$Parent = $script:panel)
    $sep = New-Object System.Windows.Forms.Label
    $sep.BorderStyle = 'Fixed3D'; $sep.Location = New-Object System.Drawing.Point(16, $Top)
    $sep.Size = New-Object System.Drawing.Size(940, 2)
    $Parent.Controls.Add($sep) | Out-Null; return $sep
}
function Add-Tip {
    param([object]$Control, [string]$Text)
    $script:tips.SetToolTip($Control, $Text)
}

$y = 14

$lblTitle = Add-LabelBold "Entra Audit - read-only security audit for Microsoft Entra ID" $y
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblTitle.Size = New-Object System.Drawing.Size(940, 30)
$y += 36
$lblVer = Add-Label "Audit script: $AuditScriptPath" $y 940
$lblVer.ForeColor = [System.Drawing.Color]::Gray
$y += 24
$lblRo = Add-Label "Read-only: the audit only reads settings from Microsoft Graph (and Azure, when available). It never changes your tenant." $y 940
$lblRo.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 60)
$y += 26
Add-Separator $y | Out-Null; $y += 12

# === STEP 1: DEPENDENCIES ===
Add-LabelBold "Step 1 - Install the Microsoft Graph modules (first time only)" $y | Out-Null
$y += $rowHeight
Add-Label "Microsoft Graph PowerShell SDK:" $y | Out-Null
$btnInstall = Add-Button "Install Graph Modules" $y 220 28
Add-Hint "Opens a new PowerShell 7 window and installs for your user only." $y 440 ($leftInput + 236) | Out-Null
$y += 38
Add-Separator $y | Out-Null; $y += 12

# === STEP 2: SIGN-IN ===
Add-LabelBold "Step 2 - Choose how to sign in (the audit only asks for read permissions)" $y | Out-Null
$y += $rowHeight
$rdoInteractive = Add-Radio "Interactive: sign in with your own account" $y $true 330 $leftLabel
$rdoAppOnly     = Add-Radio "App-only: app registration with a certificate" $y $false 330 ($leftLabel + 350)
Add-Tip $rdoInteractive "A person signs in with their own account. Recommended for most audits. Give the account Global Reader + Security Reader; one check (federated identity credentials in workloadcredentials) needs app-only for full coverage - see PREREQUISITE.md."
Add-Tip $rdoAppOnly "Unattended run as a dedicated read-only app registration that signs in with a certificate on this computer."
$y += $rowHeight
$chkDeviceCode = Add-Check "Sign in with a code on another device instead of a pop-up (-UseDeviceCode)" $y $false 600 $leftLabel
Add-Tip $chkDeviceCode "Use this when no sign-in window can open here (remote session, server without a browser). You get a code to enter at microsoft.com/devicelogin."
$y += $rowHeight + 2

$lblTenant = Add-Label "Tenant ID or domain:" $y
$txtTenant = Add-TextBox $y -Width 300
Add-Hint "e.g. contoso.onmicrosoft.com (required for app-only)" $y 380 ($leftInput + 310) | Out-Null
$tipTenant = "Which tenant to audit: its tenant ID (a GUID) or a verified domain. Optional for interactive sign-in (your home tenant is used), required for app-only."
Add-Tip $lblTenant $tipTenant; Add-Tip $txtTenant $tipTenant
$y += $rowHeight
$lblDelegatedClientId = Add-Label "Own sign-in app ID (optional):" $y
$txtDelegatedClientId = Add-TextBox $y -Width 300
Add-Hint "Interactive only. Leave empty to use Microsoft's app." $y 380 ($leftInput + 310) | Out-Null
$tipDelegated = "Optional, interactive sign-in only (passed as -DelegatedClientId). The Application (client) ID of your own read-only app registration, used instead of Microsoft's shared 'Microsoft Graph Command Line Tools' app. Use it when that shared app holds write permissions from earlier use, which makes the audit refuse to run. The app must be a public client (mobile and desktop) with redirect URI http://localhost; for device-code sign-in also set Authentication > 'Allow public client flows' to Yes."
Add-Tip $lblDelegatedClientId $tipDelegated; Add-Tip $txtDelegatedClientId $tipDelegated
$y += $rowHeight
$lblClientId = Add-Label "App (client) ID:" $y
$txtClientId = Add-TextBox $y -Width 300
Add-Hint "App-only. The app registration's Application (client) ID." $y 380 ($leftInput + 310) | Out-Null
$tipClientId = "App-only sign-in (passed as -ClientId): the Application (client) ID of the read-only app registration. See PREREQUISITE.md for the exact permissions."
Add-Tip $lblClientId $tipClientId; Add-Tip $txtClientId $tipClientId
$y += $rowHeight
$lblThumb = Add-Label "Certificate thumbprint:" $y
$txtThumb = Add-TextBox $y -Width 300
Add-Hint "App-only. 40-character thumbprint of a certificate on this PC." $y 380 ($leftInput + 310) | Out-Null
$tipThumb = "App-only sign-in (passed as -CertificateThumbprint): the SHA-1 thumbprint of the app's certificate. The certificate and its private key must be installed on this computer (for example Cert:\CurrentUser\My)."
Add-Tip $lblThumb $tipThumb; Add-Tip $txtThumb $tipThumb
$y += $rowHeight + 4
Add-Separator $y | Out-Null; $y += 12

# === STEP 3: CHECK SELECTION ===
# One list serves both modes (it used to be two 36-row lists that were never usable at the
# same time): with 'Run all checks' ticked an unticked check is skipped (-all -exclude ...);
# without it only the ticked checks run (one -switch per check).
Add-LabelBold "Step 3 - Choose what to check" $y | Out-Null
$y += $rowHeight
$chkAll = Add-Check "Run all checks (recommended)" $y $true 300 $leftLabel
Add-Tip $chkAll "Ticked: every check runs, including checks added in later versions; untick a check below to skip it. Not ticked: only the checks you tick below run."
$btnTickAll   = Add-Button "Tick all"   $y 100 26 ($leftLabel + 726)
$btnUntickAll = Add-Button "Untick all" $y 100 26 ($leftLabel + 836)
$y += $rowHeight + 2
$lblSelHint = Add-Hint "" $y 940 $leftLabel   # text set by Sync-CheckListHint
$y += $checkRowHeight

$checkboxes = [ordered]@{}   # ordered, so the preview lists checks in the same order as the form
foreach ($key in $AuditChecks.Keys) {
    $chk = Add-Check "-$key" $y $true 200 $leftLabel
    $chk.Tag = $key
    $desc = Add-Label $AuditChecks[$key] ($y + 1) ($contentRight - ($leftLabel + 206)) ($leftLabel + 206)
    $desc.ForeColor = [System.Drawing.Color]::DimGray
    # Clicking the description toggles its checkbox, like clicking the checkbox text.
    $desc.Tag = $chk
    $desc.Add_Click({ $this.Tag.Checked = -not $this.Tag.Checked })
    $checkboxes[$key] = $chk
    $y += $checkRowHeight
}
$y += 6; Add-Separator $y | Out-Null; $y += 12

# === STEP 4: OPTIONS ===
Add-LabelBold "Step 4 - Options (optional - the defaults suit most tenants)" $y | Out-Null
$y += $rowHeight
Add-Label "Inactive after (days):" $y | Out-Null
$txtInactive = Add-TextBox $y -Width 120
$txtInactive.Text = "90"
Add-Hint "Users and devices with no sign-in for this long are reported as stale. Default 90." $y 560 ($leftInput + 130) | Out-Null
$y += $rowHeight
Add-Label "Credential warning (days):" $y | Out-Null
$txtExpiry = Add-TextBox $y -Width 120
$txtExpiry.Text = "30"
Add-Hint "Warn about app secrets and certificates that expire within this many days. Default 30." $y 560 ($leftInput + 130) | Out-Null
$y += $rowHeight
Add-Label "Recent-change window (days):" $y | Out-Null
$txtRecentDays = Add-TextBox $y -Width 120
$txtRecentDays.Text = "30"
Add-Hint "How far back to look for recently created or changed objects. Default 30." $y 560 ($leftInput + 130) | Out-Null
$y += $rowHeight
Add-Label "Unused-app window (days):" $y | Out-Null
$txtStaleApp = Add-TextBox $y -Width 120
$txtStaleApp.Text = "90"
Add-Hint "Apps with no sign-in for this long are reported as unused. Default 90." $y 560 ($leftInput + 130) | Out-Null
$y += $rowHeight
$lblBreakGlass = Add-Label "Break-glass accounts (UPNs):" $y
$txtBreakGlass = Add-TextBox $y
if ($txtBreakGlass.PSObject.Properties['PlaceholderText']) {
    $txtBreakGlass.PlaceholderText = "emergency1@contoso.onmicrosoft.com; emergency2@contoso.onmicrosoft.com"
}
$tipBreakGlass = "Your emergency-access (break-glass) admin accounts, separated by ';' (passed as -BreakGlassUpns). The audit checks their health and treats them as expected exceptions in the privileged-role, PIM and Conditional Access checks. Leave empty if you have none."
Add-Tip $lblBreakGlass $tipBreakGlass; Add-Tip $txtBreakGlass $tipBreakGlass
$y += $rowHeight
$lblOutput = Add-Label "Report folder (optional):" $y
$txtOutput = Add-TextBox $y -Width 560
$btnBrowse = Add-Button "Browse..." $y 110 24 ($leftInput + 570)
$tipOutput = "Where the report folder is created (passed as -OutputRoot). Empty = the folder this script is in. The reports contain sensitive security data: choose a folder only auditors can open."
Add-Tip $lblOutput $tipOutput; Add-Tip $txtOutput $tipOutput
$y += $rowHeight
$lblModules = Add-Label "Offline modules folder (optional):" $y
$txtModulesPath = Add-TextBox $y -Width 560
$btnBrowseModules = Add-Button "Browse..." $y 110 24 ($leftInput + 570)
$tipModules = "Only for computers without internet access (passed as -ModulesPath): a folder with the Microsoft Graph modules saved by Save-Module. See PREREQUISITE.md."
Add-Tip $lblModules $tipModules; Add-Tip $txtModulesPath $tipModules
$y += $rowHeight
$chkNoLaunch = Add-Check "Don't open the report automatically when the audit finishes (-NoLaunch)" $y $false 560 $leftLabel
$y += $rowHeight + 6

$panel.AutoScrollMinSize = [System.Drawing.Size]::new(0, ($y + 20))

# === BOTTOM BAR (always visible): COMMAND PREVIEW + RUN / CLOSE ===
$bottomSep = Add-Separator 0 -Parent $bottom
Add-LabelBold "Command that will run" 8 220 $leftLabel -Parent $bottom | Out-Null
Add-Hint "Updates as you change the settings above." 10 600 ($leftLabel + 230) -Parent $bottom | Out-Null
$txtPreview = Add-TextBox 35 -ReadOnly $true -Multiline $true -Height 62 -Width 940 -X $leftLabel -Parent $bottom
$txtPreview.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtPreview.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)

$btnRun = Add-Button "Run Audit" 102 220 40 $leftLabel -Parent $bottom
$btnRun.Font = New-Object System.Drawing.Font($btnRun.Font.FontFamily, 11, [System.Drawing.FontStyle]::Bold)
$btnRun.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnRun.ForeColor = [System.Drawing.Color]::White
$btnRun.FlatStyle = 'Flat'; $btnRun.FlatAppearance.BorderSize = 0
$btnClose = Add-Button "Close" 102 100 40 ($leftLabel + 230) -Parent $bottom
$lblRunHint = Add-Hint "Runs in a new PowerShell 7 window - sign in there if asked." 112 560 ($leftLabel + 346) -Parent $bottom

# Stretch the separator, preview and hint with the window. Done in code rather than with
# Anchor=Right, which captures the right-edge distance from the parent's size at the moment
# the child is added (before the bar is laid out) and can then size the preview far too wide.
function Sync-BottomBarWidth {
    $w = $script:bottom.ClientSize.Width
    if ($w -lt 300) { return }   # not laid out yet; the Resize event calls this again
    $script:bottomSep.Width  = $w - 2 * $script:leftLabel
    $script:txtPreview.Width = $w - 2 * $script:leftLabel
    $script:lblRunHint.Width = [Math]::Max(80, $w - $script:lblRunHint.Left - $script:leftLabel)
}
$bottom.Add_Resize({ Sync-BottomBarWidth })

# -------------------------
# Command builder
# -------------------------
# The preview is generated from the SAME argument array that is actually launched, so what
# the user sees matches what runs (pwsh.exe -ExecutionPolicy Bypass -File <script> <args>).
function Update-Preview {
    $script:txtPreview.Text = 'pwsh.exe ' + ((ConvertTo-ArgLine (Build-LaunchArgs)) -join ' ')
}

# -------------------------
# Launch via an ARGUMENT ARRAY (not a single command string) so paths, UPN lists,
# tenant ids and output folders with spaces/quotes/special characters are passed safely.
# -------------------------
function Test-IsGuid([string]$s) { $g = [guid]::Empty; return [guid]::TryParse(($s).Trim(), [ref]$g) }
# Strip whitespace AND Unicode format chars (\p{Cf}: LRM/RLM/BOM etc.) - certificate
# dialogs copy thumbprints with invisible marks that '\s' does not match, which would
# fail validation with a misleading "must be 40 hex characters" error.
function Test-IsThumbprint([string]$s) { return ((($s -replace '[\s\p{Cf}]','')) -match '^[0-9A-Fa-f]{40}$') }

# Start-Process -ArgumentList joins array elements with spaces WITHOUT quoting, so any value
# containing whitespace (e.g. the script path "C:\Users\Niclas Skarnes\..." or an -OutputRoot
# with spaces) MUST be pre-quoted or it is split into separate tokens. ';' and ',' are also
# quoted: pasted into a PowerShell console, an unquoted ';' terminates the statement and an
# unquoted 'a,b' is parsed as an array and splatted into separate native arguments.
function ConvertTo-ArgLine([string[]]$InputArgs) {
    @($InputArgs | ForEach-Object { if ($_ -match '[\s";,]') { '"' + ($_ -replace '"','""') + '"' } else { $_ } })
}

# Launch pwsh via .NET ProcessStartInfo.ArgumentList: each element is passed as a distinct
# argument and the runtime handles all native quoting, so we never hand-roll quote escaping
# for the actual launch (ConvertTo-ArgLine is only for the human-readable preview). pwsh is
# resolved from PATH rather than hard-coding 'pwsh.exe'.
function Start-PwshWithArgs {
    param([string[]]$LaunchArgs)
    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $pwsh
    $psi.UseShellExecute = $true   # open a new console window for the audit run
    foreach ($arg in $LaunchArgs) { [void]$psi.ArgumentList.Add($arg) }
    [System.Diagnostics.Process]::Start($psi) | Out-Null
}

function Build-LaunchArgs {
    param([switch]$InstallOnly)
    $a = @('-NoExit','-ExecutionPolicy','Bypass','-File', $script:AuditScriptPath)
    if ($InstallOnly) {
        $a += '-installdeps'
        # honor the offline modules path for installs too, not only audit runs
        if ($script:txtModulesPath.Text.Trim()) { $a += @('-ModulesPath', $script:txtModulesPath.Text.Trim()) }
        return $a
    }

    if ($script:chkAll.Checked) {
        # Run all: every check runs except the unticked ones.
        $a += '-all'
        $excludes = @(foreach ($key in $script:checkboxes.Keys) { if (-not $script:checkboxes[$key].Checked) { $key } })
        if ($excludes.Count -gt 0) { $a += @('-exclude', ($excludes -join ',')) }
    } else {
        # Only the ticked checks run.
        foreach ($key in $script:checkboxes.Keys) { if ($script:checkboxes[$key].Checked) { $a += "-$key" } }
    }
    if ($script:rdoAppOnly.Checked) {
        if ($script:txtClientId.Text.Trim()) { $a += @('-ClientId', $script:txtClientId.Text.Trim()) }
        if ($script:txtThumb.Text.Trim())    { $a += @('-CertificateThumbprint', ($script:txtThumb.Text -replace '[\s\p{Cf}]','')) }
    } else {
        if ($script:chkDeviceCode.Checked) { $a += '-UseDeviceCode' }
        # Interactive only, and only when filled in: an app-only run already names its app.
        if ($script:txtDelegatedClientId.Text.Trim()) { $a += @('-DelegatedClientId', $script:txtDelegatedClientId.Text.Trim()) }
    }
    if ($script:txtTenant.Text.Trim()) { $a += @('-TenantId', $script:txtTenant.Text.Trim()) }
    if ($script:txtInactive.Text.Trim() -and $script:txtInactive.Text.Trim() -ne '90') { $a += @('-InactiveDays', $script:txtInactive.Text.Trim()) }
    if ($script:txtExpiry.Text.Trim() -and $script:txtExpiry.Text.Trim() -ne '30')     { $a += @('-ExpiringCredentialDays', $script:txtExpiry.Text.Trim()) }
    if ($script:txtRecentDays.Text.Trim() -and $script:txtRecentDays.Text.Trim() -ne '30') { $a += @('-RecentChangeDays', $script:txtRecentDays.Text.Trim()) }
    if ($script:txtStaleApp.Text.Trim() -and $script:txtStaleApp.Text.Trim() -ne '90')     { $a += @('-StaleAppDays', $script:txtStaleApp.Text.Trim()) }
    if ($script:txtModulesPath.Text.Trim()) { $a += @('-ModulesPath', $script:txtModulesPath.Text.Trim()) }
    if ($script:txtBreakGlass.Text.Trim()) {
        $bgList = (($script:txtBreakGlass.Text -split '[;,]') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ';'
        if ($bgList) { $a += @('-BreakGlassUpns', $bgList) }
    }
    if ($script:txtOutput.Text.Trim()) { $a += @('-OutputRoot', $script:txtOutput.Text.Trim()) }
    if ($script:chkNoLaunch.Checked)   { $a += '-NoLaunch' }
    return $a
}

# -------------------------
# State helpers
# -------------------------
# Enable only the sign-in fields that apply to the chosen mode.
function Sync-SignInControl {
    $app = $script:rdoAppOnly.Checked
    $script:txtClientId.Enabled = $app
    $script:txtThumb.Enabled = $app
    $script:chkDeviceCode.Enabled = -not $app
    $script:txtDelegatedClientId.Enabled = -not $app
}

# Plain-language line under 'Run all checks' saying what the ticks mean and how many run.
function Sync-CheckListHint {
    $total  = $script:checkboxes.Count
    $ticked = @($script:checkboxes.Values | Where-Object { $_.Checked }).Count
    $script:lblSelHint.Text = if ($script:chkAll.Checked) {
        "$ticked of $total checks will run. Untick a check to skip it."
    } else {
        "$ticked of $total checks ticked - only the ticked checks will run. Tick 'Run all checks' to run everything."
    }
}

# Tick or untick every check at once; refresh the hint and preview once, not 36 times.
$script:bulkChange = $false
function Sync-CheckSelection {
    param([bool]$Checked)
    $script:bulkChange = $true
    try {
        foreach ($c in $script:checkboxes.Values) { $c.Checked = $Checked }
    } finally {
        $script:bulkChange = $false
    }
    Sync-CheckListHint
    Update-Preview
}

# -------------------------
# Events
# -------------------------
# Turning 'Run all' on ticks every check (untick to skip); turning it off clears the list so
# the user starts from nothing and ticks only what should run.
$chkAll.Add_CheckedChanged({ Sync-CheckSelection -Checked $script:chkAll.Checked })
$btnTickAll.Add_Click({ Sync-CheckSelection -Checked $true })
$btnUntickAll.Add_Click({ Sync-CheckSelection -Checked $false })

foreach ($key in $checkboxes.Keys) {
    $checkboxes[$key].Add_CheckedChanged({
        if (-not $script:bulkChange) { Sync-CheckListHint; Update-Preview }
    })
}
$rdoInteractive.Add_CheckedChanged({ Sync-SignInControl; Update-Preview })
$rdoAppOnly.Add_CheckedChanged({ Sync-SignInControl; Update-Preview })
$chkDeviceCode.Add_CheckedChanged({ Update-Preview })
$txtTenant.Add_TextChanged({ Update-Preview })
$txtDelegatedClientId.Add_TextChanged({ Update-Preview })
$txtClientId.Add_TextChanged({ Update-Preview })
$txtThumb.Add_TextChanged({ Update-Preview })
$txtInactive.Add_TextChanged({ Update-Preview })
$txtExpiry.Add_TextChanged({ Update-Preview })
$txtRecentDays.Add_TextChanged({ Update-Preview })
$txtStaleApp.Add_TextChanged({ Update-Preview })
$txtBreakGlass.Add_TextChanged({ Update-Preview })
$txtOutput.Add_TextChanged({ Update-Preview })
$txtModulesPath.Add_TextChanged({ Update-Preview })
$chkNoLaunch.Add_CheckedChanged({ Update-Preview })

$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $script:txtOutput.Text = $dlg.SelectedPath }
})
$btnBrowseModules.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $script:txtModulesPath.Text = $dlg.SelectedPath }
})

$btnInstall.Add_Click({
    try {
        Start-PwshWithArgs (Build-LaunchArgs -InstallOnly)
        Msg-Info "Module installation started in a new PowerShell 7 window. When it says the modules are installed, come back here and click Run Audit."
    } catch { Msg-Error "Could not start the module installation: $($_.Exception.Message)" }
})

$btnRun.Add_Click({
    $ticked = @($script:checkboxes.Keys | Where-Object { $script:checkboxes[$_].Checked })
    if ($ticked.Count -eq 0) {
        Msg-Error "No checks are ticked, so there is nothing to run. Tick at least one check in Step 3, or tick 'Run all checks'."; return
    }
    # App-only mode: require a valid Client Id, certificate thumbprint AND tenant (so
    # unattended/scheduled GUI-generated commands are deterministic).
    if ($script:rdoAppOnly.Checked) {
        if (-not (Test-IsGuid $script:txtClientId.Text))     { Msg-Error "App-only sign-in needs the App (client) ID of your app registration. It is a GUID such as 11111111-2222-3333-4444-555555555555."; return }
        if (-not (Test-IsThumbprint $script:txtThumb.Text))  { Msg-Error "The certificate thumbprint must be 40 characters long and use only 0-9 and A-F."; return }
        if (-not $script:txtTenant.Text.Trim())              { Msg-Error "App-only sign-in needs the tenant ID or domain (for example contoso.onmicrosoft.com)."; return }
    } else {
        $delegatedId = $script:txtDelegatedClientId.Text.Trim()
        if ($delegatedId -and -not (Test-IsGuid $delegatedId)) {
            Msg-Error "'Own sign-in app ID' must be the Application (client) ID of your app registration (a GUID such as 11111111-2222-3333-4444-555555555555). Leave it empty to use Microsoft's app."; return
        }
    }
    $tenant = $script:txtTenant.Text.Trim()
    if ($tenant -and -not ((Test-IsGuid $tenant) -or ($tenant -match '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'))) {
        Msg-Error "The tenant must be a tenant ID (a GUID) or a domain such as contoso.onmicrosoft.com."; return
    }
    foreach ($pair in @(
        @{ n='Inactive after'; t=$script:txtInactive }, @{ n='Credential warning'; t=$script:txtExpiry },
        @{ n='Recent-change window'; t=$script:txtRecentDays }, @{ n='Unused-app window'; t=$script:txtStaleApp }
    )) {
        $v = $pair.t.Text.Trim()
        # 1-3650 (mirrors the script's ValidateRange): 0 produces meaningless results and
        # an Int32-overflowing value would kill the launched pwsh at parameter binding.
        if ($v -and ($v -notmatch '^\d{1,4}$' -or [int]$v -lt 1 -or [int]$v -gt 3650)) {
            Msg-Error ("'{0}' must be a whole number of days between 1 and 3650." -f $pair.n); return
        }
    }
    if ($script:txtOutput.Text.Trim() -and -not (Test-Path -IsValid $script:txtOutput.Text.Trim())) {
        Msg-Error "The report folder is not a valid folder path."; return
    }
    if ($script:txtModulesPath.Text.Trim() -and -not (Test-Path -LiteralPath $script:txtModulesPath.Text.Trim() -PathType Container)) {
        Msg-Error "The offline modules folder does not exist."; return
    }
    try {
        Start-PwshWithArgs (Build-LaunchArgs)
        $script:form.Close()
    } catch { Msg-Error "Could not start the audit: $($_.Exception.Message)" }
})

$btnClose.Add_Click({ $script:form.Close() })

# Initial state
Sync-SignInControl
Sync-CheckListHint
Sync-BottomBarWidth
Update-Preview

$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
exit
