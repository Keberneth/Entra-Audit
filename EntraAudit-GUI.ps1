<#
.SYNOPSIS
  EntraAudit-GUI.ps1 - WinForms GUI launcher for EntraAudit-PS7.ps1

  Provides a graphical interface to:
    - Choose sign-in mode (interactive delegated, or app-only certificate)
    - Select audit checks (or run all) and exclude specific checks
    - Install the Microsoft Graph modules
    - Configure tuning options (inactivity threshold, break-glass accounts, output)
    - Preview and execute the read-only audit command

  Requirements:
    - PowerShell 7 (pwsh.exe)
    - EntraAudit-PS7.ps1 in the same folder as this script
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
if (-not (Test-Path $AuditScriptPath)) {
    Write-Error "EntraAudit-PS7.ps1 not found in '$ScriptDir'. Place this GUI in the same folder as EntraAudit-PS7.ps1."
    exit 1
}

Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
Add-Type -AssemblyName System.Drawing      -ErrorAction Stop
[System.Windows.Forms.Application]::EnableVisualStyles()

function Msg-Error([string]$Message) {
    [System.Windows.Forms.MessageBox]::Show($Message, "Error",
        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
}
function Msg-Info([string]$Message) {
    [System.Windows.Forms.MessageBox]::Show($Message, "Info",
        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}

# -------------------------
# Audit check definitions (mirrors EntraAudit-PS7.ps1 -switches)
# -------------------------
$AuditChecks = [ordered]@{
    tenantinfo     = "Tenant / organization overview, verified domains, licensing"
    privroles      = "FLAGSHIP: privileged roles - permanent (risk) vs eligible (PIM) vs time-bound"
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
    appcredentials = "App registration secret/cert expiry - expired (Medium), expiring soon (Low)"
    consentgrants  = "OAuth2 delegated consent grants (illicit consent risk)"
    devices        = "Stale / unmanaged / non-compliant devices"
    trusts         = "Cross-tenant access and B2B trust"
    recentchanges  = "Recently created users/groups and directory audit"
    tenanthealth   = "Directory-sync / Password Hash Sync platform health"
    pimpolicies    = "PIM policy quality (activation MFA/approval/justification/duration) - needs P2"
    breakglass     = "Emergency-access (break-glass) account health - pass -BreakGlassUpns"
    authmethodpolicy = "Tenant authentication-methods policy (weak vs phishing-resistant)"
    accesspaths    = "Effective-access / attack-path graph (duplicate & ownership privilege paths)"
    staleapps      = "Stale / unused applications by service-principal sign-in activity - needs P1"
}

# -------------------------
# Form
# -------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Entra Audit - Microsoft Entra ID Read-Only Security Audit"
$form.Size = New-Object System.Drawing.Size(1000, 900)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(820, 640)

$panel = New-Object System.Windows.Forms.Panel
$panel.Dock = 'Fill'
$panel.AutoScroll = $true
$form.Controls.Add($panel) | Out-Null

$leftLabel  = 16
$labelWidth = 240
$leftInput  = 266
$inputWidth = 680
$rowHeight  = 28

function Add-Label {
    param([string]$Text, [int]$Top, [int]$Width = $script:labelWidth, [int]$X = $script:leftLabel)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text; $l.Location = New-Object System.Drawing.Point($X, $Top)
    $l.Size = New-Object System.Drawing.Size($Width, 20)
    $script:panel.Controls.Add($l) | Out-Null; return $l
}
function Add-LabelBold {
    param([string]$Text, [int]$Top, [int]$Width = 940, [int]$X = $script:leftLabel)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text; $l.Font = New-Object System.Drawing.Font($l.Font, [System.Drawing.FontStyle]::Bold)
    $l.Location = New-Object System.Drawing.Point($X, $Top); $l.Size = New-Object System.Drawing.Size($Width, 22)
    $script:panel.Controls.Add($l) | Out-Null; return $l
}
function Add-TextBox {
    param([int]$Top, [bool]$ReadOnly = $false, [bool]$Multiline = $false, [int]$Height = 22, [int]$Width = $script:inputWidth, [int]$X = $script:leftInput)
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = New-Object System.Drawing.Point($X, ($Top - 3))
    $t.Size = New-Object System.Drawing.Size($Width, $Height)
    $t.ReadOnly = $ReadOnly; $t.Multiline = $Multiline
    if ($Multiline) { $t.ScrollBars = 'Vertical' }
    $script:panel.Controls.Add($t) | Out-Null; return $t
}
function Add-Check {
    param([string]$Text, [int]$Top, [bool]$Checked = $false, [int]$Width = 220, [int]$X = $script:leftInput)
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $Text; $c.Location = New-Object System.Drawing.Point($X, ($Top - 4))
    $c.Size = New-Object System.Drawing.Size($Width, 22); $c.Checked = $Checked
    $script:panel.Controls.Add($c) | Out-Null; return $c
}
function Add-Radio {
    param([string]$Text, [int]$Top, [bool]$Checked = $false, [int]$Width = 220, [int]$X = $script:leftInput)
    $r = New-Object System.Windows.Forms.RadioButton
    $r.Text = $Text; $r.Location = New-Object System.Drawing.Point($X, ($Top - 4))
    $r.Size = New-Object System.Drawing.Size($Width, 22); $r.Checked = $Checked
    $script:panel.Controls.Add($r) | Out-Null; return $r
}
function Add-Button {
    param([string]$Text, [int]$Top, [int]$Width = 200, [int]$Height = 30, [int]$X = $script:leftInput)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Location = New-Object System.Drawing.Point($X, ($Top - 2))
    $b.Size = New-Object System.Drawing.Size($Width, $Height)
    $script:panel.Controls.Add($b) | Out-Null; return $b
}
function Add-Separator {
    param([int]$Top)
    $sep = New-Object System.Windows.Forms.Label
    $sep.BorderStyle = 'Fixed3D'; $sep.Location = New-Object System.Drawing.Point(16, $Top)
    $sep.Size = New-Object System.Drawing.Size(940, 2)
    $script:panel.Controls.Add($sep) | Out-Null
}

$y = 14

$lblTitle = Add-LabelBold "Entra Audit - Microsoft Entra ID Security Audit (read-only)" $y
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblTitle.Size = New-Object System.Drawing.Size(940, 30)
$y += 36
$lblVer = Add-Label "Script: EntraAudit-PS7.ps1  |  Location: $ScriptDir" $y 940
$lblVer.ForeColor = [System.Drawing.Color]::Gray
$y += 28
$lblRo = Add-Label "This tool only READS from Microsoft Graph. It never creates, changes or deletes anything." $y 940
$lblRo.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 60)
$y += 26
Add-Separator $y; $y += 12

# === DEPENDENCIES ===
Add-LabelBold "Dependencies" $y | Out-Null
$y += $rowHeight
Add-Label "Microsoft Graph SDK modules" $y | Out-Null
$btnInstall = Add-Button "Install Graph Modules" $y 220 28
$y += 38
Add-Separator $y; $y += 12

# === SIGN-IN MODE ===
Add-LabelBold "Sign-in (read-only scopes only)" $y | Out-Null
$y += $rowHeight
$rdoInteractive = Add-Radio "Interactive (delegated)" $y $true 220 $leftLabel
$rdoAppOnly     = Add-Radio "App-only (certificate)" $y $false 220 ($leftLabel + 240)
$y += $rowHeight
$chkDeviceCode = Add-Check "-UseDeviceCode (device-code sign-in)" $y $false 320 $leftLabel
$y += $rowHeight + 2

Add-Label "Tenant Id / domain:" $y | Out-Null
$txtTenant = Add-TextBox $y
$y += $rowHeight
Add-Label "App (Client) Id:" $y | Out-Null
$txtClientId = Add-TextBox $y
$y += $rowHeight
Add-Label "Certificate Thumbprint:" $y | Out-Null
$txtThumb = Add-TextBox $y
$y += $rowHeight + 4
Add-Separator $y; $y += 12

# === AUDIT SELECTION ===
Add-LabelBold "Audit Selection" $y | Out-Null
$y += $rowHeight
$chkAll = Add-Check "Run All Checks (recommended)" $y $true 300 $leftInput
$y += $rowHeight + 2
$lblAllDesc = Add-Label "Runs every audit check. Uncheck to select individual checks below." ($y - 4) $inputWidth $leftInput
$lblAllDesc.ForeColor = [System.Drawing.Color]::Gray
$y += $rowHeight
Add-Separator $y; $y += 12

# === INDIVIDUAL CHECKS ===
Add-LabelBold "Individual Audit Checks" $y | Out-Null
$lblHint = Add-Label "(enabled when 'Run All' is unchecked)" ($y + 2) 320 ($leftLabel + 250)
$lblHint.ForeColor = [System.Drawing.Color]::Gray
$y += $rowHeight + 2

$checkboxes = @{}
foreach ($key in $AuditChecks.Keys) {
    $chk = Add-Check "-$key" $y $false 200 $leftLabel
    $chk.Enabled = $false; $chk.Tag = $key
    $desc = Add-Label $AuditChecks[$key] ($y + 1) 720 ($leftLabel + 206)
    $desc.ForeColor = [System.Drawing.Color]::DimGray
    $checkboxes[$key] = $chk
    $y += $rowHeight
}
$y += 6; Add-Separator $y; $y += 12

# === EXCLUDE (visible when Run All) ===
$lblExclude = Add-LabelBold "Exclude from 'Run All'" $y
$y += $rowHeight
$lblExcludeHint = Add-Label "Select checks to skip when running all:" ($y - 4) $inputWidth $leftInput
$lblExcludeHint.ForeColor = [System.Drawing.Color]::Gray
$y += 22
$excludeCheckboxes = @{}
$col = 0
foreach ($key in $AuditChecks.Keys) {
    $xPos = if ($col -eq 0) { $leftLabel } else { $leftLabel + 470 }
    $exChk = Add-Check "-$key" $y $false 200 $xPos
    $exDesc = Add-Label $AuditChecks[$key] ($y + 1) 250 ($xPos + 206)
    $exDesc.ForeColor = [System.Drawing.Color]::DimGray
    $exChk.Tag = "exclude_$key"
    $excludeCheckboxes[$key] = $exChk
    $col++
    if ($col -ge 2) { $col = 0; $y += 24 }
}
if ($col -ne 0) { $y += 24 }
$y += 6; Add-Separator $y; $y += 12

# === TUNING ===
Add-LabelBold "Options" $y | Out-Null
$y += $rowHeight
Add-Label "Inactivity threshold (days):" $y | Out-Null
$txtInactive = Add-TextBox $y -Width 120
$txtInactive.Text = "90"
$y += $rowHeight
Add-Label "Credential-expiry warning (days):" $y | Out-Null
$txtExpiry = Add-TextBox $y -Width 120
$txtExpiry.Text = "30"
$y += $rowHeight
Add-Label "Recent-change window (days):" $y | Out-Null
$txtRecentDays = Add-TextBox $y -Width 120
$txtRecentDays.Text = "30"
$y += $rowHeight
Add-Label "Stale-application window (days):" $y | Out-Null
$txtStaleApp = Add-TextBox $y -Width 120
$txtStaleApp.Text = "90"
$y += $rowHeight
Add-Label "Break-glass UPNs (semicolon-sep):" $y | Out-Null
$txtBreakGlass = Add-TextBox $y
$y += $rowHeight
Add-Label "Output folder (optional):" $y | Out-Null
$txtOutput = Add-TextBox $y -Width 560
$btnBrowse = Add-Button "Browse..." $y 110 24 ($leftInput + 570)
$y += $rowHeight
Add-Label "Offline modules path (optional):" $y | Out-Null
$txtModulesPath = Add-TextBox $y -Width 560
$btnBrowseModules = Add-Button "Browse..." $y 110 24 ($leftInput + 570)
$y += $rowHeight
$chkNoLaunch = Add-Check "-NoLaunch (don't auto-open the report)" $y $false 320 $leftLabel
$y += $rowHeight + 6
Add-Separator $y; $y += 12

# === COMMAND PREVIEW ===
Add-LabelBold "Command Preview" $y | Out-Null
$y += $rowHeight
$txtPreview = Add-TextBox $y -ReadOnly $true -Multiline $true -Height 70 -Width 930 -X 16
$txtPreview.Location = New-Object System.Drawing.Point(16, ($y - 3))
$txtPreview.Size = New-Object System.Drawing.Size(940, 70)
$txtPreview.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtPreview.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$y += 80

# === RUN / CLOSE ===
$btnRun = Add-Button "Run Audit" $y 220 42 $leftLabel
$btnRun.Font = New-Object System.Drawing.Font($btnRun.Font.FontFamily, 11, [System.Drawing.FontStyle]::Bold)
$btnRun.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnRun.ForeColor = [System.Drawing.Color]::White
$btnRun.FlatStyle = 'Flat'; $btnRun.FlatAppearance.BorderSize = 0
$btnClose = Add-Button "Close" $y 100 42 ($leftLabel + 230)
$y += 60

$panel.AutoScrollMinSize = New-Object System.Drawing.Size(0, ($y + 20))

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
function Test-IsThumbprint([string]$s) { return ((($s -replace '\s','')) -match '^[0-9A-Fa-f]{40}$') }

# Start-Process -ArgumentList joins array elements with spaces WITHOUT quoting, so any value
# containing whitespace (e.g. the script path "C:\Users\Niclas Skarnes\..." or an -OutputRoot
# with spaces) MUST be pre-quoted or it is split into separate tokens.
function ConvertTo-ArgLine([string[]]$InputArgs) {
    @($InputArgs | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"','""') + '"' } else { $_ } })
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
    if ($InstallOnly) { $a += '-installdeps'; return $a }

    if ($script:chkAll.Checked) {
        $a += '-all'
        $excludes = @()
        foreach ($key in $script:excludeCheckboxes.Keys) { if ($script:excludeCheckboxes[$key].Checked) { $excludes += $key } }
        if ($excludes.Count -gt 0) { $a += @('-exclude', ($excludes -join ',')) }
    } else {
        foreach ($key in $script:checkboxes.Keys) { if ($script:checkboxes[$key].Checked) { $a += "-$key" } }
    }
    if ($script:rdoAppOnly.Checked) {
        if ($script:txtClientId.Text.Trim()) { $a += @('-ClientId', $script:txtClientId.Text.Trim()) }
        if ($script:txtThumb.Text.Trim())    { $a += @('-CertificateThumbprint', ($script:txtThumb.Text -replace '\s','')) }
    } elseif ($script:chkDeviceCode.Checked) {
        $a += '-UseDeviceCode'
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
# Events
# -------------------------
$chkAll.Add_CheckedChanged({
    $allChecked = $this.Checked
    foreach ($key in $script:checkboxes.Keys) {
        $script:checkboxes[$key].Enabled = -not $allChecked
        if ($allChecked) { $script:checkboxes[$key].Checked = $false }
    }
    foreach ($key in $script:excludeCheckboxes.Keys) {
        $script:excludeCheckboxes[$key].Enabled = $allChecked
        if (-not $allChecked) { $script:excludeCheckboxes[$key].Checked = $false }
    }
    $script:lblExclude.Visible = $allChecked
    $script:lblExcludeHint.Visible = $allChecked
    Update-Preview
})

foreach ($key in $checkboxes.Keys)        { $checkboxes[$key].Add_CheckedChanged({ Update-Preview }) }
foreach ($key in $excludeCheckboxes.Keys) { $excludeCheckboxes[$key].Add_CheckedChanged({ Update-Preview }) }
$rdoInteractive.Add_CheckedChanged({
    $app = $script:rdoAppOnly.Checked
    $script:txtClientId.Enabled = $app; $script:txtThumb.Enabled = $app; $script:chkDeviceCode.Enabled = -not $app
    Update-Preview
})
$rdoAppOnly.Add_CheckedChanged({
    $app = $script:rdoAppOnly.Checked
    $script:txtClientId.Enabled = $app; $script:txtThumb.Enabled = $app; $script:chkDeviceCode.Enabled = -not $app
    Update-Preview
})
$chkDeviceCode.Add_CheckedChanged({ Update-Preview })
$txtTenant.Add_TextChanged({ Update-Preview })
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
        Msg-Info "Module installation launched in a new PowerShell 7 window."
    } catch { Msg-Error "Failed to launch install: $($_.Exception.Message)" }
})

$btnRun.Add_Click({
    if (-not $script:chkAll.Checked) {
        $any = $false
        foreach ($key in $script:checkboxes.Keys) { if ($script:checkboxes[$key].Checked) { $any = $true; break } }
        if (-not $any) { Msg-Error "No checks selected. Enable 'Run All Checks' or select at least one."; return }
    }
    # App-only mode: require a valid Client Id, certificate thumbprint AND tenant (so
    # unattended/scheduled GUI-generated commands are deterministic).
    if ($script:rdoAppOnly.Checked) {
        if (-not (Test-IsGuid $script:txtClientId.Text))     { Msg-Error "App-only sign-in requires a valid Client (Application) Id - a GUID."; return }
        if (-not (Test-IsThumbprint $script:txtThumb.Text))  { Msg-Error "Certificate Thumbprint must be 40 hexadecimal characters (SHA-1)."; return }
        if (-not $script:txtTenant.Text.Trim())              { Msg-Error "App-only sign-in requires a Tenant Id (GUID or verified domain)."; return }
    }
    $tenant = $script:txtTenant.Text.Trim()
    if ($tenant -and -not ((Test-IsGuid $tenant) -or ($tenant -match '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'))) {
        Msg-Error "Tenant Id must be a GUID or a domain (e.g. contoso.onmicrosoft.com)."; return
    }
    foreach ($pair in @(
        @{ n='Inactivity'; t=$script:txtInactive }, @{ n='Credential-expiry'; t=$script:txtExpiry },
        @{ n='Recent-change window'; t=$script:txtRecentDays }, @{ n='Stale-application window'; t=$script:txtStaleApp }
    )) {
        $v = $pair.t.Text.Trim()
        if ($v -and ($v -notmatch '^\d+$')) { Msg-Error ("{0} days must be a whole number." -f $pair.n); return }
    }
    if ($script:txtOutput.Text.Trim() -and -not (Test-Path -IsValid $script:txtOutput.Text.Trim())) {
        Msg-Error "Output folder path is not a valid path."; return
    }
    if ($script:txtModulesPath.Text.Trim() -and -not (Test-Path $script:txtModulesPath.Text.Trim())) {
        Msg-Error "Offline modules path does not exist."; return
    }
    try {
        Start-PwshWithArgs (Build-LaunchArgs)
        $script:form.Close()
    } catch { Msg-Error "Failed to launch audit: $($_.Exception.Message)" }
})

$btnClose.Add_Click({ $script:form.Close() })

# Initial state
$txtClientId.Enabled = $false; $txtThumb.Enabled = $false
foreach ($key in $excludeCheckboxes.Keys) { $excludeCheckboxes[$key].Enabled = $true }
Update-Preview

$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
exit
