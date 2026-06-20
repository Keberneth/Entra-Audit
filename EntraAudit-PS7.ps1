<#
.SYNOPSIS
  EntraAudit-PS7.ps1 - Read-only Microsoft Entra ID (Azure AD) security audit.

  A PowerShell 7 + Microsoft Graph audit tool that mirrors the on-prem AdAudit-PS7
  audit and produces the same style of severity-grouped HTML reports. Its flagship
  capability is classifying every privileged role assignment as PERMANENT (standing)
  vs ELIGIBLE (PIM) vs TIME-BOUND ACTIVE - a permanent Global Administrator is a risk
  and is flagged; the same role held as PIM-eligible is the desired posture and is not.

.DESCRIPTION
  STRICTLY READ-ONLY. The script requests only *.Read.* / *.Read.All Graph scopes,
  issues only GET requests, and aborts at startup if any write-capable scope is granted.
  It never creates, modifies, activates, revokes or deletes anything. All remediation
  text in the reports is advisory guidance for a human operator.

  Two sign-in modes (both read-only):
    - Interactive delegated  : an admin signs in (Global Reader + Security Reader
                               recommended) and consents to the read-only scopes.
    - App-only (certificate) : unattended runs via a dedicated read-only app
                               registration (-ClientId / -TenantId / -CertificateThumbprint).

  Output (mirrors the AD audit layout):
    <TenantName>-EntraAudit-<timestamp>\
      HTML Reports\  EntraAudit-Results.html, Risk-Report.html, Posture-Summary.html
      Raw Data\Source\  one evidence file (.csv/.txt) per check

.NOTES
  Requires PowerShell 7 (pwsh.exe) and the Microsoft Graph PowerShell SDK v2.x.
  See README.md for usage and PREREQUISITE.md for the exact permissions / setup.

.EXAMPLE
  .\EntraAudit-PS7.ps1 -all
  Interactive sign-in, run every check, write the reports.

.EXAMPLE
  .\EntraAudit-PS7.ps1 -all -exclude legacyauth,devices

.EXAMPLE
  .\EntraAudit-PS7.ps1 -privroles -mfa -capolicies

.EXAMPLE
  .\EntraAudit-PS7.ps1 -all -TenantId contoso.onmicrosoft.com -ClientId <appid> -CertificateThumbprint <thumb>
  Unattended app-only run.
#>

[CmdletBinding()]
param(
    # ---- Run modes ----
    [switch]$all,
    [string[]]$exclude,
    [string[]]$select,
    [switch]$installdeps,

    # ---- Individual checks (mirrors the AD audit switch style) ----
    [switch]$tenantinfo,        # Tenant / organization overview
    [switch]$privroles,         # FLAGSHIP: permanent vs eligible vs time-bound roles
    [switch]$directoryroles,    # Global Admin count & privileged assignment volume
    [switch]$accounts,          # Account hygiene (disabled-but-licensed, no-manager, never-expire)
    [switch]$staleusers,        # Stale / inactive / never-signed-in users
    [switch]$guests,            # Guest / external user governance
    [switch]$mfa,               # MFA capability & authentication-method strength
    [switch]$legacyauth,        # Legacy authentication usage
    [switch]$tenantposture,     # Security Defaults, authorization & consent settings
    [switch]$capolicies,        # Conditional Access policy posture
    [switch]$riskyusers,        # Identity Protection: risky users / detections / risky SPs
    [switch]$apps,              # App / service principal hygiene & over-privilege
    [switch]$consentgrants,     # OAuth2 delegated consent grants (illicit consent)
    [switch]$devices,           # Stale / unmanaged / non-compliant devices
    [switch]$trusts,            # Cross-tenant access & B2B trust
    [switch]$recentchanges,     # Recently created users/groups & directory audit
    [switch]$tenanthealth,      # Directory-sync / PHS platform health
    [switch]$pimpolicies,       # PIM role-management policy quality (activation MFA/approval/duration)
    [switch]$breakglass,        # Emergency-access (break-glass) account health
    [switch]$authmethodpolicy,  # Tenant authentication-methods policy
    [switch]$accesspaths,       # Effective-access / attack-path correlation

    # ---- Auth (app-only certificate; omit for interactive) ----
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [switch]$UseDeviceCode,

    # ---- Tuning ----
    [string]$OutputRoot,
    [string[]]$BreakGlassUpns,
    [int]$InactiveDays = 90,
    [int]$ExpiringCredentialDays = 30,
    [int]$RecentChangeDays = 30,
    [string]$ModulesPath,       # offline: folder containing Save-Module output
    [switch]$NoLaunch           # do not open the report when finished
)

$ErrorActionPreference = 'Continue'
$script:Version = 'EntraAudit-PS7 v1.0'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7 (pwsh.exe). Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

# ===========================================================================
# Read-only Graph scopes (delegated). The script NEVER requests a write scope.
# ===========================================================================
$script:ScopesRO = @(
    'Directory.Read.All'
    'AuditLog.Read.All'
    'Policy.Read.All'
    'RoleManagement.Read.Directory'
    'RoleEligibilitySchedule.Read.Directory'
    'RoleAssignmentSchedule.Read.Directory'
    'Application.Read.All'
    'User.Read.All'
    'Group.Read.All'
    'Organization.Read.All'
    'DelegatedPermissionGrant.Read.All'
    'Device.Read.All'
    'IdentityRiskyUser.Read.All'
    'IdentityRiskEvent.Read.All'
    'IdentityRiskyServicePrincipal.Read.All'
    'CrossTenantInformation.ReadBasic.All'
    'OnPremDirectorySynchronization.Read.All'
    'Reports.Read.All'
    'RoleManagementPolicy.Read.Directory'
    'Member.Read.Hidden'
)

$script:RequiredModules = @(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Identity.DirectoryManagement'
    'Microsoft.Graph.Identity.SignIns'
    'Microsoft.Graph.Identity.Governance'
    'Microsoft.Graph.Users'
    'Microsoft.Graph.Groups'
    'Microsoft.Graph.Applications'
    'Microsoft.Graph.Reports'
    'Microsoft.Graph.DirectoryObjects'
)

# High-value (write-capable) directory roles, by role template id.
# GA is the only Critical-tier role; the rest are Tier-0 High.
$script:GlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
$script:PrivilegedRoleTemplates = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
    '8329153b-31d0-4727-b945-745eb3bc5f31' = 'Domain Name Administrator'
    'd29b2b05-8046-44ba-8758-1e26182fcf32' = 'Directory Synchronization Accounts'
}

# Graph application permissions considered tier-0 dangerous on an app/SP.
$script:DangerousAppPermissions = @(
    'RoleManagement.ReadWrite.Directory','AppRoleAssignment.ReadWrite.All',
    'Application.ReadWrite.All','Directory.ReadWrite.All','full_access_as_app',
    'Mail.ReadWrite','Mail.Read','Mail.Send','Files.ReadWrite.All','Sites.FullControl.All',
    'User.ReadWrite.All','Group.ReadWrite.All','GroupMember.ReadWrite.All',
    'PrivilegedAccess.ReadWrite.AzureAD','RoleManagementPolicy.ReadWrite.Directory'
)

# ---------------------------------------------------------------------------
# Severity model (mirrors the AD audit). Score is used for within-band sort.
# ---------------------------------------------------------------------------
$script:SeverityScore = @{ Critical = 12; High = 8; Medium = 5; Low = 2; Information = 0 }

# ===========================================================================
# Shared state
# ===========================================================================
$script:Findings    = New-Object System.Collections.Generic.List[object]
$script:CheckStatus = [ordered]@{}
$script:AuthType    = 'Delegated'
$script:HasP1       = $false
$script:HasP2       = $false
$script:WorkloadIdP = $false
$script:Tenant      = $null
$script:UsersCache  = $null
$script:UserById    = @{}
$script:RegCache    = $null
$script:MfaCapableById = @{}
$script:RoleDefById = @{}
$script:RawDatasets = New-Object System.Collections.Generic.List[object]
$script:PrivAssignments = $null

# ===========================================================================
# Small helpers
# ===========================================================================
function Write-Info  { param([string]$m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Good  { param([string]$m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err2  { param([string]$m) Write-Host "[x] $m" -ForegroundColor Red }

function Normalize-Severity([string]$sev) {
    $s = ($sev -as [string]); if (-not $s) { return 'Low' }
    switch -Regex ($s.Trim().ToUpperInvariant()) {
        '^CRIT' { 'Critical'; break }
        '^HIGH' { 'High'; break }
        '^MED'  { 'Medium'; break }
        '^LOW'  { 'Low'; break }
        '^INFO' { 'Information'; break }
        default { 'Low' }
    }
}

function Get-SeverityRank([string]$Severity) {
    switch (Normalize-Severity $Severity) {
        'Critical' { 5 } 'High' { 4 } 'Medium' { 3 } 'Low' { 2 } 'Information' { 1 } default { 0 }
    }
}

function New-Slug([string]$Value) {
    $slug = (($Value -as [string]) -replace '[^A-Za-z0-9]+','-').Trim('-').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($slug)) { 'finding' } else { $slug }
}

function HtmlEncode([string]$s) { if ($null -eq $s) { '' } else { [System.Net.WebUtility]::HtmlEncode($s) } }
function HtmlAttrEncode([string]$s) { HtmlEncode $s }

function Get-Ap {
    param($obj, [string]$key)
    if ($obj -and $obj.AdditionalProperties -and $obj.AdditionalProperties.ContainsKey($key)) {
        return $obj.AdditionalProperties[$key]
    }
    return $null
}

# Split comma/semicolon-separated input (a single "-BreakGlassUpns a;b" or a real
# array both normalize the same way), trim, lowercase, de-duplicate.
function Normalize-StringList {
    param([string[]]$Values)
    @($Values | ForEach-Object { $_ -split '[;,]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
}

# Switch-style names (what the GUI emits) -> registry check ids. Only the three that
# differ need mapping; every other id equals its switch name.
$script:CheckAliases = @{ 'tenantinfo' = 'tenant-info'; 'privroles' = 'privileged-roles'; 'directoryroles' = 'directory-roles' }

function Resolve-CheckIds {
    param([string[]]$Values)
    $out = @()
    foreach ($raw in (Normalize-StringList -Values $Values)) {
        if ($script:Registry.Contains($raw)) { $out += $raw; continue }
        if ($script:CheckAliases.ContainsKey($raw)) { $out += $script:CheckAliases[$raw]; continue }
        Write-Warn2 "Unknown check id ignored: $raw"
    }
    @($out | Select-Object -Unique)
}

# Stable finding key: strip digits from the title so a changing COUNT
# ("5 stale users" -> "7 stale users") does not change the id; the rule slug plus the
# affected object identify the finding across runs (for new/resolved/trend comparison).
function New-FindingKey {
    param([string]$TenantId, [string]$CheckId, [string]$Title, [string]$AffectedPrincipal)
    $ruleSlug = (($Title -replace '\d+','') -replace '[^A-Za-z]+','-').Trim('-').ToLowerInvariant()
    $obj = if ($AffectedPrincipal) { $AffectedPrincipal.ToLowerInvariant() } else { 'tenant' }
    '{0}|{1}|{2}|{3}' -f $TenantId, $CheckId, $ruleSlug, $obj
}

# A CA policy enforces MFA if it uses the built-in 'mfa' grant OR an authentication
# strength (passwordless / phishing-resistant). Recognising auth strengths avoids
# false "no MFA policy" findings on modern tenants.
function Test-CaPolicyRequiresMfaOrStrength {
    param($Policy)
    $grant = $Policy.GrantControls
    if (-not $grant) { return $false }
    if (@($grant.BuiltInControls) -contains 'mfa') { return $true }
    if ($grant.AuthenticationStrength -and $grant.AuthenticationStrength.Id) { return $true }
    return $false
}

# ===========================================================================
# Finding emission + raw evidence
# ===========================================================================
function Add-EntraFinding {
    param(
        [string]$Severity, [string]$Title, [string]$Category, [string]$CheckId,
        [string]$Evidence, [string]$WhyItMatters, [string]$RecommendedAction,
        [string]$SourceFile, [string]$AffectedPrincipal, [object[]]$ResultRows
    )
    $Severity = Normalize-Severity $Severity
    $script:Findings.Add([pscustomobject]@{
        Severity          = $Severity
        Title             = $Title
        Category          = $Category
        CheckId           = $CheckId
        Evidence          = $Evidence
        WhyItMatters      = $WhyItMatters
        RecommendedAction = $RecommendedAction
        SourceFile        = $SourceFile
        AffectedPrincipal = $AffectedPrincipal
        ResultRows        = $ResultRows
        Score             = [int]$script:SeverityScore[$Severity]
    }) | Out-Null
}

# Writes each raw dataset three ways - CSV (data), TXT (plain), and a styled HTML
# table in the same design as the reports - and registers it for the Raw Data index.
# Returns the relative href (from HTML Reports\) to the HTML version so findings link
# to a readable page; the index also links the CSV/TXT for download.
function Write-Evidence {
    param(
        [string]$BaseName,          # e.g. 'privileged_roles'
        [object[]]$Rows,
        [string]$Title,
        [string[]]$Notes
    )
    $rel = $null
    try {
        $csvPath  = Join-Path $script:RawDir ($BaseName + '.csv')
        $txtPath  = Join-Path $script:RawDir ($BaseName + '.txt')
        $htmlPath = Join-Path $script:RawDir ($BaseName + '.html')
        $count = @($Rows).Count

        $header = @($Title, ('Generated: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')))
        if ($Notes) { $Notes | ForEach-Object { $header += $_ } }
        $header += ('Rows: {0}' -f $count); $header += ''

        if ($Rows -and $count -gt 0) {
            @($Rows) | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
            $table = @($Rows) | Format-Table -AutoSize | Out-String -Width 4096
            Set-Content -LiteralPath $txtPath -Value (($header -join "`r`n") + "`r`n" + $table) -Encoding UTF8
        } else {
            # Always write the CSV (even with no rows) so automation can rely on the file
            # existing and can distinguish "pass / no data" from "CSV generation failed".
            [pscustomobject]@{ Status = 'NoData'; Message = 'No rows returned for this check.' } | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
            $header += '(no matching objects)'
            Set-Content -LiteralPath $txtPath -Value ($header -join "`r`n") -Encoding UTF8
        }

        New-RawDataHtml -Path $htmlPath -Title $Title -Rows $Rows -Notes $Notes -CsvName ($BaseName + '.csv') -TxtName ($BaseName + '.txt')

        # Reports live in HTML Reports\, raw data in Raw Data\Source\
        $rel = '../Raw Data/Source/' + (Split-Path $htmlPath -Leaf)
        $script:RawDatasets.Add([pscustomobject]@{
            BaseName = $BaseName; Title = $Title; Rows = $count
            HtmlHref = $rel
            CsvHref  = ('../Raw Data/Source/' + $BaseName + '.csv')
            TxtHref  = ('../Raw Data/Source/' + $BaseName + '.txt')
        }) | Out-Null
    } catch {
        Write-Warn2 "Could not write evidence '$BaseName': $($_.Exception.Message)"
    }
    return $rel
}

# ===========================================================================
# Module install + Graph connection (read-only)
# ===========================================================================
function Install-EntraModules {
    Write-Info "Installing Microsoft Graph SDK sub-modules (CurrentUser scope)..."
    try {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }
        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        foreach ($m in $script:RequiredModules) {
            if (Get-Module -ListAvailable -Name $m) { Write-Good "$m already installed."; continue }
            Write-Info "Installing $m ..."
            Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -ErrorAction Stop
            Write-Good "$m installed."
        }
    } catch {
        throw "Module installation failed: $($_.Exception.Message)"
    }
}

function Import-EntraModules {
    if ($ModulesPath -and (Test-Path $ModulesPath)) {
        $env:PSModulePath = (Resolve-Path $ModulesPath).Path + [IO.Path]::PathSeparator + $env:PSModulePath
        Write-Info "Prepended offline modules path: $ModulesPath"
    }
    $missing = @()
    foreach ($m in $script:RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $m)) { $missing += $m; continue }
        try { Import-Module $m -ErrorAction Stop } catch { $missing += $m }
    }
    if ($missing.Count -gt 0) {
        throw "Required module(s) not available: $($missing -join ', '). Run with -installdeps (online) or see PREREQUISITE.md for offline install."
    }
}

function Connect-EntraAuditGraph {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $appOnly = ($ClientId -and $CertificateThumbprint)
    if ($appOnly) {
        Write-Info "Connecting to Microsoft Graph (app-only, certificate)..."
        $cp = @{ ClientId = $ClientId; CertificateThumbprint = $CertificateThumbprint; NoWelcome = $true }
        if ($TenantId) { $cp.TenantId = $TenantId }
        Connect-MgGraph @cp -ErrorAction Stop
        $script:AuthType = 'AppOnly'
    } else {
        Write-Info "Connecting to Microsoft Graph (interactive, read-only scopes)..."
        $cp = @{ Scopes = $script:ScopesRO; NoWelcome = $true }
        if ($TenantId)      { $cp.TenantId = $TenantId }
        if ($UseDeviceCode) { $cp.UseDeviceCode = $true }
        try {
            Connect-MgGraph @cp -ErrorAction Stop
        } catch {
            # WAM/window-handle failures (VS Code terminal, SSH, elevated) -> device code
            Write-Warn2 "Interactive sign-in failed ($($_.Exception.Message)). Retrying with device code..."
            $cp.UseDeviceCode = $true
            Connect-MgGraph @cp -ErrorAction Stop
        }
        $script:AuthType = 'Delegated'
    }

    $ctx = Get-MgContext
    if (-not $ctx) { throw 'Not connected to Microsoft Graph.' }

    # --- READ-ONLY SELF-CHECK: refuse to run if any write scope is present ---
    # NB: match only true write tokens. Do NOT add 'Manage' - it is a substring of
    # the legitimate read scope 'RoleManagement.Read.Directory' and would abort every run.
    $bad = @($ctx.Scopes | Where-Object { $_ -match '(?i)(ReadWrite|\.Write\b|AccessAsUser|FullControl)' })
    if ($bad.Count -gt 0) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        throw "Refusing to run: a non-read-only scope was granted -> $($bad -join ', '). This tool is read-only; reconnect with only *.Read.* scopes."
    }

    # App-only: Get-MgContext.Scopes is sparse, so the scope regex above is not a
    # reliable read-only guarantee. Inspect the running app's actual app-role assignments
    # across ALL resource APIs and FAIL CLOSED if any granted permission is write-capable.
    if ($appOnly) {
        try { Assert-AppOnlyReadOnly -ClientId $ClientId }
        catch {
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
            throw
        }
    }

    Write-Good ("Connected. Auth: {0} | Tenant: {1} | Account: {2}" -f $script:AuthType, $ctx.TenantId, ($ctx.Account ?? $ctx.AppName))
    return $ctx
}

# Fail-closed read-only enforcement for app-only runs: resolve the running service
# principal's granted application permissions (across every resource SP, not just Graph)
# and refuse to run if any is write-capable.
function Assert-AppOnlyReadOnly {
    param([Parameter(Mandatory)][string]$ClientId)
    $allSps = @(Get-MgServicePrincipal -All -Property 'id,appId,displayName,appRoles' -ErrorAction Stop)
    $self = $allSps | Where-Object { $_.AppId -eq $ClientId } | Select-Object -First 1
    if (-not $self) { throw "Cannot verify app-only read-only posture: no service principal found for ClientId $ClientId." }

    $roleMapByResourceId = @{}
    foreach ($sp in $allSps) {
        $m = @{}
        foreach ($role in @($sp.AppRoles)) { if ($role.Id) { $m[[string]$role.Id] = $role.Value } }
        $roleMapByResourceId[$sp.Id] = $m
    }
    $assignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $self.Id -All -ErrorAction Stop)
    $writePattern = '(?i)(ReadWrite|\.Write\b|FullControl|full_access|ManageAsApp|AccessAsUser)'
    $bad = @()
    foreach ($a in $assignments) {
        $value = $null
        if ($roleMapByResourceId.ContainsKey($a.ResourceId)) { $value = $roleMapByResourceId[$a.ResourceId][[string]$a.AppRoleId] }
        if ($value -and $value -match $writePattern) { $bad += ("{0}:{1}" -f $a.ResourceDisplayName, $value) }
    }
    if ($bad.Count -gt 0) {
        throw "Refusing app-only run: write-capable application permission(s) granted to this app -> $($bad -join ', '). This tool is read-only; remove these permissions or use a dedicated read-only app registration."
    }
    Write-Good ("App-only read-only verified: {0} application permission(s) granted, none write-capable." -f $assignments.Count)
}

# Delegated-only scope gate. Directory.Read.All implicitly covers narrower reads.
function Test-MgScope {
    param([string[]]$Required, [switch]$Quiet)
    if ($script:AuthType -ne 'Delegated') { return $true }   # app-only: rely on 403 at call time
    $have = @((Get-MgContext).Scopes)
    if ($have -contains 'Directory.Read.All') {
        $have += @('User.Read.All','Group.Read.All','Organization.Read.All','Device.Read.All','DelegatedPermissionGrant.Read.All')
    }
    $missing = @($Required | Where-Object { $_ -notin $have })
    if ($missing.Count -gt 0) {
        if (-not $Quiet) { Write-Warn2 "Skipping - missing scope(s): $($missing -join ', ')" }
        return $false
    }
    return $true
}

# Wraps a check: scope gate, run, classify status for the posture report.
function Invoke-AuditCheck {
    param(
        [string]$CheckId, [string]$Title, [string[]]$Scopes,
        [switch]$NeedP2, [switch]$NeedP1, [scriptblock]$Action
    )
    Write-Info "Running check: $Title"
    $before = $script:Findings.Count

    if ($Scopes -and -not (Test-MgScope $Scopes)) {
        $script:CheckStatus[$CheckId] = [pscustomobject]@{ Title=$Title; Status='Skipped-NoScope'; Count=0 }
        return
    }
    if ($NeedP1 -and -not $script:HasP1) {
        $script:CheckStatus[$CheckId] = [pscustomobject]@{ Title=$Title; Status='Skipped-NoLicense'; Count=0 }
        Write-Warn2 "  $Title -> Skipped-NoLicense (Entra ID P1 required)"
        return
    }
    if ($NeedP2 -and -not $script:HasP2) {
        $script:CheckStatus[$CheckId] = [pscustomobject]@{ Title=$Title; Status='Skipped-NoLicense'; Count=0 }
        Write-Warn2 "  $Title -> Skipped-NoLicense (Entra ID P2 required)"
        return
    }

    try {
        & $Action
        $added = $script:Findings.Count - $before
        $status = if ($added -gt 0) { "Findings($added)" } else { 'Pass' }
        $script:CheckStatus[$CheckId] = [pscustomobject]@{ Title=$Title; Status=$status; Count=$added }
        Write-Good "  $Title -> $status"
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($code -in 401,403 -or $_ -match 'Authorization_RequestDenied|Insufficient privileges|does not have the required') {
            $reason = if ($NeedP2 -and -not $script:HasP2) { 'Skipped-NoLicense' } else { 'Skipped-NoPermission' }
            $script:CheckStatus[$CheckId] = [pscustomobject]@{ Title=$Title; Status=$reason; Count=0 }
            Write-Warn2 "  $Title -> $reason"
        } else {
            $script:CheckStatus[$CheckId] = [pscustomobject]@{ Title=$Title; Status='Error'; Count=0 }
            Write-Err2 "  $Title -> error: $($_.Exception.Message)"
        }
    }
}

# ===========================================================================
# Cached data shared across checks
# ===========================================================================
function Get-EAUsers {
    if ($null -ne $script:UsersCache) { return $script:UsersCache }
    $props = @('Id','UserPrincipalName','DisplayName','AccountEnabled','UserType',
               'AssignedLicenses','LicenseAssignmentStates','PasswordPolicies',
               'OnPremisesSyncEnabled','CreatedDateTime',
               'ExternalUserState','ExternalUserStateChangeDateTime')
    if (Test-MgScope @('AuditLog.Read.All') -Quiet) { $props += 'SignInActivity' }
    $script:UsersCache = @(Get-MgUser -All -Property $props -ErrorAction Stop)
    $script:UserById = @{}
    foreach ($u in $script:UsersCache) { if ($u.Id) { $script:UserById[$u.Id] = $u } }
    return $script:UsersCache
}

function Get-EARegistrationDetails {
    if ($null -ne $script:RegCache) { return $script:RegCache }
    $script:RegCache = @(Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop)
    $script:MfaCapableById = @{}
    foreach ($r in $script:RegCache) { if ($r.Id) { $script:MfaCapableById[$r.Id] = [bool]$r.IsMfaCapable } }
    return $script:RegCache
}

function Get-EARoleDefMap {
    if ($script:RoleDefById.Count -gt 0) { return $script:RoleDefById }
    foreach ($rd in @(Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop)) {
        $script:RoleDefById[$rd.Id] = $rd
    }
    return $script:RoleDefById
}

# ===========================================================================
# CHECK 1 - tenant-info
# ===========================================================================
function Invoke-Check-TenantInfo {
    $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
    $script:Tenant = $org
    $skus = @(Get-MgSubscribedSku -All -ErrorAction SilentlyContinue)

    $verified = @($org.VerifiedDomains | ForEach-Object { "$($_.Name)$(if($_.IsDefault){' (default)'})$(if($_.Type -eq 'Federated'){' [FEDERATED]'})" })
    $techMails = @($org.TechnicalNotificationMails)
    $secMails  = @()
    try { $secMails = @($org.SecurityComplianceNotificationMails) } catch {}

    $rows = @()
    $rows += [pscustomobject]@{ Property='Tenant';            Value=$org.DisplayName }
    $rows += [pscustomobject]@{ Property='Tenant Id';         Value=$org.Id }
    $rows += [pscustomobject]@{ Property='Created';           Value=$org.CreatedDateTime }
    $rows += [pscustomobject]@{ Property='Country';           Value=$org.CountryLetterCode }
    $rows += [pscustomobject]@{ Property='Verified domains';  Value=($verified -join '; ') }
    $rows += [pscustomobject]@{ Property='Tech notification'; Value=($techMails -join '; ') }
    $rows += [pscustomobject]@{ Property='Security notification'; Value=($secMails -join '; ') }
    $rows += [pscustomobject]@{ Property='Licensing';         Value=("P1={0}; P2={1}; WorkloadId={2}" -f $script:HasP1,$script:HasP2,$script:WorkloadIdP) }
    foreach ($s in $skus) {
        $rows += [pscustomobject]@{ Property=("SKU {0}" -f $s.SkuPartNumber); Value=("{0}/{1} consumed/enabled" -f $s.ConsumedUnits, $s.PrepaidUnits.Enabled) }
    }
    $src = Write-Evidence -BaseName 'tenant_info' -Rows $rows -Title 'Tenant / Organization Overview'

    if ($techMails.Count -eq 0 -or $secMails.Count -eq 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'tenant-info' -Category 'Tenant Posture' `
            -Title 'Tenant security / technical notification addresses are not fully configured' `
            -Evidence ("Technical notification mails: {0}; Security notification mails: {1}" -f ($techMails.Count), ($secMails.Count)) `
            -WhyItMatters 'Microsoft sends service-health, security and compliance alerts to these addresses. If they are empty or point at a single person, outage and security notifications can be missed entirely.' `
            -RecommendedAction 'Populate the technical and security/compliance notification addresses with monitored distribution lists or a SecOps mailbox, not a single individual.' `
            -SourceFile $src -ResultRows $rows
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId 'tenant-info' -Category 'Tenant Posture' `
            -Title 'Tenant overview' `
            -Evidence ("{0} ({1}) - P1={2} P2={3}" -f $org.DisplayName, $org.Id, $script:HasP1, $script:HasP2) `
            -WhyItMatters 'Baseline tenant identity, verified domains, auth model and licensing tier. Establishes which premium-gated controls are available to the tenant.' `
            -RecommendedAction 'No action - context for the rest of the report.' `
            -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 2 - privileged-roles  (FLAGSHIP: permanent vs eligible vs time-bound)
# ===========================================================================
function Invoke-Check-PrivRoles {
    Get-EARoleDefMap | Out-Null
    try { Get-EAUsers | Out-Null } catch {}
    try { Get-EARegistrationDetails | Out-Null } catch {}

    $assignments = New-Object System.Collections.Generic.List[object]   # one row per (principal, role, state)

    # Resolve a directory-role template id -> our privileged classification
    function _RoleInfo([string]$roleDefId) {
        $rd = $script:RoleDefById[$roleDefId]
        $tmpl = if ($rd) { $rd.TemplateId } else { $roleDefId }
        $name = if ($rd) { $rd.DisplayName } else { $roleDefId }
        $isPriv = $script:PrivilegedRoleTemplates.ContainsKey($tmpl)
        $isGA   = ($tmpl -eq $script:GlobalAdminTemplateId)
        return [pscustomobject]@{ Name=$name; TemplateId=$tmpl; IsPrivileged=$isPriv; IsGA=$isGA }
    }

    function _Principal($p) {
        # Graph frequently omits @odata.type on the default (user) type when a Principal
        # is $expand-ed, and the UPN lives in AdditionalProperties (not as a first-class
        # member). Resolve UPN from the user cache as a fallback, and infer the type from
        # the UPN / known-user cache so the break-glass and guest/synced gates work.
        $id   = if ($p) { $p.Id } else { $null }
        $upn  = (Get-Ap $p 'userPrincipalName')
        $name = (Get-Ap $p 'displayName')
        if (-not $name -and $p -and $p.PSObject.Properties['DisplayName']) { $name = $p.DisplayName }
        if (-not $upn -and $id -and $script:UserById.ContainsKey($id)) { $upn = $script:UserById[$id].UserPrincipalName }

        $odt = Get-Ap $p '@odata.type'
        $type = if ($odt) { ($odt -replace '#microsoft.graph.','') }
                elseif ($upn) { 'user' }
                elseif ($id -and $script:UserById.ContainsKey($id)) { 'user' }
                else { '' }

        $synced = $false
        if ($id -and $script:UserById.ContainsKey($id)) { $synced = [bool]$script:UserById[$id].OnPremisesSyncEnabled }
        $mfa = $null
        if ($id -and $script:MfaCapableById.ContainsKey($id)) { $mfa = [bool]$script:MfaCapableById[$id] }
        return [pscustomobject]@{ Id=$id; Type=$type; Upn=$upn; Name=$name; Synced=$synced; MfaCapable=$mfa }
    }

    $pimAvailable = $true

    # --- Model A: ACTIVE assignment schedule instances (PIM-aware) ---
    try {
        foreach ($i in @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)) {
            $ri = _RoleInfo $i.RoleDefinitionId
            $pr = _Principal $i.Principal
            # Order matters: an Activated (JIT) instance is time-bound even on the rare
            # occasion its EndDateTime is null; only a non-activated null-end is permanent.
            $state = if ($i.AssignmentType -eq 'Activated') { 'TimeBound-Active(JIT)' }
                     elseif ($null -eq $i.EndDateTime) { 'Permanent' }
                     else { 'TimeBound-Assigned' }
            $assignments.Add([pscustomobject]@{
                PrincipalId=$pr.Id; Principal=($pr.Upn ?? $pr.Name); PrincipalType=$pr.Type
                Role=$ri.Name; RoleTemplateId=$ri.TemplateId; IsPrivileged=$ri.IsPrivileged; IsGA=$ri.IsGA
                State=$state; EndDateTime=$i.EndDateTime; MemberType=$i.MemberType; AssignmentType=$i.AssignmentType
                DirectoryScopeId=$i.DirectoryScopeId; Synced=$pr.Synced; MfaCapable=$pr.MfaCapable
            })
        }
    } catch {
        $pimAvailable = $false
        Write-Warn2 "  PIM active-schedule endpoint unavailable - falling back to classic role assignments."
    }

    # --- Model B: ELIGIBLE schedule instances (PIM) ---
    $eligibleCount = 0
    try {
        foreach ($i in @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)) {
            $ri = _RoleInfo $i.RoleDefinitionId
            $pr = _Principal $i.Principal
            $eligibleCount++
            $assignments.Add([pscustomobject]@{
                PrincipalId=$pr.Id; Principal=($pr.Upn ?? $pr.Name); PrincipalType=$pr.Type
                Role=$ri.Name; RoleTemplateId=$ri.TemplateId; IsPrivileged=$ri.IsPrivileged; IsGA=$ri.IsGA
                State='Eligible'; EndDateTime=$i.EndDateTime; MemberType=$i.MemberType; AssignmentType='Eligible'
                DirectoryScopeId=$i.DirectoryScopeId; Synced=$pr.Synced; MfaCapable=$pr.MfaCapable
            })
        }
    } catch {
        Write-Warn2 "  PIM eligibility endpoint unavailable (requires Entra ID P2)."
    }

    # --- Fallback: classic roleAssignments when PIM is not in use/licensed ---
    if (-not $pimAvailable -or $assignments.Count -eq 0) {
        try {
            foreach ($a in @(Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop)) {
                $ri = _RoleInfo $a.RoleDefinitionId
                $pr = _Principal $a.Principal
                $assignments.Add([pscustomobject]@{
                    PrincipalId=$pr.Id; Principal=($pr.Upn ?? $pr.Name); PrincipalType=$pr.Type
                    Role=$ri.Name; RoleTemplateId=$ri.TemplateId; IsPrivileged=$ri.IsPrivileged; IsGA=$ri.IsGA
                    State='Permanent'; EndDateTime=$null; MemberType='Direct'; AssignmentType='Assigned'
                    DirectoryScopeId=$a.DirectoryScopeId; Synced=$pr.Synced; MfaCapable=$pr.MfaCapable
                })
            }
        } catch {
            # last resort: classic directoryRoles + members
            foreach ($dr in @(Get-MgDirectoryRole -All -ErrorAction SilentlyContinue)) {
                $ri = _RoleInfo $dr.RoleTemplateId
                foreach ($m in @(Get-MgDirectoryRoleMember -DirectoryRoleId $dr.Id -All -ErrorAction SilentlyContinue)) {
                    $pr = _Principal $m
                    $assignments.Add([pscustomobject]@{
                        PrincipalId=$pr.Id; Principal=($pr.Upn ?? $pr.Name); PrincipalType=$pr.Type
                        Role=$ri.Name; RoleTemplateId=$ri.TemplateId; IsPrivileged=$ri.IsPrivileged; IsGA=$ri.IsGA
                        State='Permanent'; EndDateTime=$null; MemberType='Direct'; AssignmentType='Assigned'
                        DirectoryScopeId='/'; Synced=$pr.Synced; MfaCapable=$pr.MfaCapable
                    })
                }
            }
        }
    }

    # De-duplicate (PrincipalId, RoleTemplateId, DirectoryScopeId, State)
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $rows = @()
    foreach ($a in $assignments) {
        $k = '{0}|{1}|{2}|{3}' -f $a.PrincipalId,$a.RoleTemplateId,$a.DirectoryScopeId,$a.State
        if ($seen.Add($k)) { $rows += $a }
    }

    $src = Write-Evidence -BaseName 'privileged_roles' -Rows $rows `
        -Title 'Privileged Role Assignments - Permanent vs Eligible vs Time-Bound' `
        -Notes @("PIM endpoints available: $pimAvailable", "Eligible assignments: $eligibleCount")

    $bg = Normalize-StringList -Values $BreakGlassUpns
    $permanentPriv = @($rows | Where-Object { $_.IsPrivileged -and $_.State -eq 'Permanent' })
    $permanentGA   = @($permanentPriv | Where-Object { $_.IsGA })

    # Per-assignment findings for permanent privileged roles
    foreach ($a in $permanentPriv) {
        $isBreakGlass = ($a.Principal -and ($a.Principal.ToLowerInvariant() -in $bg) -and -not $a.Synced -and $a.PrincipalType -eq 'user')
        if ($isBreakGlass) { continue }   # designated break-glass: permanence is expected

        $sev = if ($a.IsGA) { 'Critical' } else { 'High' }
        $reasons = @()
        if ($a.MfaCapable -eq $false) { $sev = 'Critical'; $reasons += 'not MFA-capable' }
        if ($a.Synced)                { if ($sev -ne 'Critical') { $sev = 'High' }; $reasons += 'on-prem synced admin' }
        if ($a.PrincipalType -in @('servicePrincipal','group')) { $sev = 'Critical'; $reasons += "$($a.PrincipalType) principal" }
        if ($a.Principal -like '*#EXT#*') { $sev = 'Critical'; $reasons += 'guest/external' }

        $extra = if ($reasons.Count) { ' (' + ($reasons -join ', ') + ')' } else { '' }
        Add-EntraFinding -Severity $sev -CheckId 'privileged-roles' -Category 'Privileged Access' `
            -Title ("Permanent (standing) {0}: {1}" -f $a.Role, $a.Principal) `
            -Evidence ("{0} holds {1} as a PERMANENT/standing assignment{2}." -f $a.Principal, $a.Role, $extra) `
            -WhyItMatters 'Standing privileged access is the largest cloud attack surface - the credential is always active. PIM-eligible (just-in-time) access is the target posture; permanent high-value roles, synced admins, and SP/guest admins defeat the boundaries PIM enforces.' `
            -RecommendedAction 'Convert this assignment to PIM-eligible (JIT) and remove the standing grant. Keep only two cloud-only break-glass Global Admins permanent. Require phishing-resistant MFA on every privileged principal.' `
            -SourceFile $src -AffectedPrincipal $a.Principal `
            -ResultRows @($rows | Where-Object { $_.PrincipalId -eq $a.PrincipalId })
    }

    # Redundant: principal is BOTH eligible AND permanently active for the same role
    $byPrincipalRole = $rows | Group-Object PrincipalId, RoleTemplateId, DirectoryScopeId
    foreach ($g in $byPrincipalRole) {
        $states = @($g.Group.State)
        if (($states -contains 'Permanent') -and ($states -contains 'Eligible')) {
            $a = $g.Group | Select-Object -First 1
            Add-EntraFinding -Severity 'High' -CheckId 'privileged-roles' -Category 'Privileged Access' `
                -Title ("Redundant standing + eligible for {0}: {1}" -f $a.Role, $a.Principal) `
                -Evidence ("{0} is both PIM-eligible and permanently active for {1} - the standing grant defeats PIM." -f $a.Principal, $a.Role) `
                -WhyItMatters 'When a principal is already eligible for a role, an additional permanent active assignment removes the just-in-time control entirely while giving the illusion of PIM coverage.' `
                -RecommendedAction 'Remove the permanent active assignment and rely on the PIM-eligible assignment with activation/approval.' `
                -SourceFile $src -AffectedPrincipal $a.Principal -ResultRows $g.Group
        }
    }

    # Break-glass posture
    if ($permanentGA.Count -eq 0 -and $pimAvailable) {
        Add-EntraFinding -Severity 'High' -CheckId 'privileged-roles' -Category 'Privileged Access' `
            -Title 'No permanent break-glass Global Administrator detected' `
            -Evidence 'Every Global Administrator appears eligible/time-bound only.' `
            -WhyItMatters 'If PIM, MFA or federation breaks, an all-eligible model can lock every admin out of the tenant. Microsoft guidance is to keep two cloud-only emergency-access (break-glass) Global Admins.' `
            -RecommendedAction 'Maintain two cloud-only break-glass Global Admin accounts excluded from Conditional Access, with long complex passwords stored offline, and monitor their sign-ins.' `
            -SourceFile $src
    }

    # PIM not in use / over-reliance on standing access
    if ($eligibleCount -eq 0 -and $permanentPriv.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'privileged-roles' -Category 'Privileged Access' `
            -Title 'PIM/just-in-time access is not in use - over-reliance on standing privilege' `
            -Evidence ("{0} permanent privileged assignment(s), 0 eligible (PIM) assignments." -f $permanentPriv.Count) `
            -WhyItMatters 'Without PIM-eligible assignments every admin right is standing access. Eligible/JIT activation with approval and time limits is the recommended posture and requires Entra ID P2.' `
            -RecommendedAction 'License Entra ID P2 and onboard privileged roles to PIM, converting standing assignments to eligible with activation requirements.' `
            -SourceFile $src
    }

    # Information: eligible assignments (the good posture) listed for visibility
    $eligible = @($rows | Where-Object { $_.State -eq 'Eligible' -and $_.IsPrivileged })
    if ($eligible.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'privileged-roles' -Category 'Privileged Access' `
            -Title ("{0} privileged role(s) held as PIM-eligible (desired posture)" -f $eligible.Count) `
            -Evidence 'These principals must activate the role just-in-time - this is the recommended model and is not a finding.' `
            -WhyItMatters 'Eligible (just-in-time) privileged access limits the window in which admin rights are usable and is the target state for all privileged roles.' `
            -RecommendedAction 'No action - maintain and extend eligible-only assignments to the remaining standing roles.' `
            -SourceFile $src -ResultRows $eligible
    }
}

# ===========================================================================
# CHECK 3 - directory-roles  (counts / volume)
# ===========================================================================
function Invoke-Check-DirectoryRoles {
    Get-EARoleDefMap | Out-Null
    $rows = @()
    $active = @()
    try { $active += @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop) } catch {}
    if ($active.Count -eq 0) {
        try { $active += @(Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction SilentlyContinue) } catch {}
    }

    # Key by role TEMPLATE id (not display name, which can be localized/renamed) so the
    # privileged classification and GA count are robust.
    $byRole = @{}        # templateId -> HashSet[principalId]
    $roleName = @{}      # templateId -> display name
    foreach ($a in $active) {
        $rd = $script:RoleDefById[$a.RoleDefinitionId]
        $tmpl = if ($rd) { $rd.TemplateId } else { $a.RoleDefinitionId }
        $roleName[$tmpl] = if ($rd) { $rd.DisplayName } else { $a.RoleDefinitionId }
        if (-not $byRole.ContainsKey($tmpl)) { $byRole[$tmpl] = [System.Collections.Generic.HashSet[string]]::new() }
        $prinId = if ($a.PrincipalId) { $a.PrincipalId } elseif ($a.Principal) { $a.Principal.Id } else { $null }
        if ($prinId) { [void]$byRole[$tmpl].Add($prinId) }
    }
    foreach ($tmpl in ($byRole.Keys | Sort-Object { $roleName[$_] })) {
        $rows += [pscustomobject]@{ Role=$roleName[$tmpl]; DistinctPrincipals=$byRole[$tmpl].Count; Privileged=$script:PrivilegedRoleTemplates.ContainsKey($tmpl) }
    }
    $src = Write-Evidence -BaseName 'directory_role_counts' -Rows $rows -Title 'Active Privileged Role Assignment Volume'

    $gaCount = if ($byRole.ContainsKey($script:GlobalAdminTemplateId)) { $byRole[$script:GlobalAdminTemplateId].Count } else { 0 }
    $totalPriv = 0
    foreach ($tmpl in $byRole.Keys) { if ($script:PrivilegedRoleTemplates.ContainsKey($tmpl)) { $totalPriv += $byRole[$tmpl].Count } }

    if ($gaCount -gt 5) {
        Add-EntraFinding -Severity 'High' -CheckId 'directory-roles' -Category 'Privileged Access' `
            -Title ("{0} active Global Administrators (recommended < 5)" -f $gaCount) `
            -Evidence ("Distinct active Global Administrators: {0}" -f $gaCount) `
            -WhyItMatters 'Each Global Admin widens the blast radius of a single credential compromise. Microsoft recommends fewer than five Global Admins (plus two break-glass). This is the cloud analog of the AD Domain Admins size review.' `
            -RecommendedAction 'Reduce standing Global Admins to the minimum, reassign day-to-day work to least-privilege roles, and move the rest to PIM-eligible.' `
            -SourceFile $src -ResultRows $rows
    } elseif ($gaCount -ge 4) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'directory-roles' -Category 'Privileged Access' `
            -Title ("{0} active Global Administrators (watch)" -f $gaCount) `
            -Evidence ("Distinct active Global Administrators: {0}" -f $gaCount) `
            -WhyItMatters 'Global Admin count is approaching the recommended ceiling of five. Excess admins increase the risk surface.' `
            -RecommendedAction 'Review whether every Global Admin still needs the role; prefer least-privilege roles and PIM-eligible assignments.' `
            -SourceFile $src -ResultRows $rows
    }
    if ($totalPriv -gt 10) {
        Add-EntraFinding -Severity 'High' -CheckId 'directory-roles' -Category 'Privileged Access' `
            -Title ("{0} total privileged role assignments (recommended < 10)" -f $totalPriv) `
            -Evidence ("Total active assignments across high-value roles: {0}" -f $totalPriv) `
            -WhyItMatters 'A large standing privileged footprint means many credentials can each cause tenant-wide damage if compromised.' `
            -RecommendedAction 'Consolidate and reduce privileged assignments; adopt PIM-eligible (JIT) for all high-value roles.' `
            -SourceFile $src -ResultRows $rows
    }
    if ($script:Findings.Where({$_.CheckId -eq 'directory-roles'}).Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'directory-roles' -Category 'Privileged Access' `
            -Title 'Privileged role assignment volume within recommended limits' `
            -Evidence ("Global Admins: {0}; total privileged assignments: {1}" -f $gaCount, $totalPriv) `
            -WhyItMatters 'Keeping admin counts low limits the impact of any single compromised credential.' `
            -RecommendedAction 'Maintain the current low admin footprint and continue moving roles to PIM-eligible.' `
            -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 4 - accounts (hygiene)
# ===========================================================================
function Invoke-Check-Accounts {
    $users = Get-EAUsers
    try { Get-EARegistrationDetails | Out-Null } catch {}

    $disabledLicensed = @($users | Where-Object { -not $_.AccountEnabled -and @($_.AssignedLicenses).Count -gt 0 })
    $neverExpire      = @($users | Where-Object { $_.PasswordPolicies -and $_.PasswordPolicies -match 'DisablePasswordExpiration' })
    $weakPwPolicy     = @($users | Where-Object { $_.PasswordPolicies -and $_.PasswordPolicies -match 'DisableStrongPassword' })
    $rows = $users | Select-Object UserPrincipalName, DisplayName, AccountEnabled, UserType,
        @{n='Licensed';e={ @($_.AssignedLicenses).Count -gt 0 }},
        @{n='PasswordPolicies';e={ $_.PasswordPolicies }},
        @{n='Synced';e={ [bool]$_.OnPremisesSyncEnabled }}, CreatedDateTime
    $src = Write-Evidence -BaseName 'accounts' -Rows $rows -Title 'Account Hygiene'

    if ($disabledLicensed.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accounts' -Category 'Identity Hygiene' `
            -Title ("{0} disabled account(s) still hold licenses" -f $disabledLicensed.Count) `
            -Evidence ("Disabled-but-licensed accounts: {0}" -f (($disabledLicensed | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Disabled accounts that keep licenses waste spend and re-arm instantly with full access if the account is re-enabled. Licenses may be inherited via group membership.' `
            -RecommendedAction 'Reclaim licenses from disabled accounts (remove the group membership where the license is group-inherited) as part of the leaver process.' `
            -SourceFile $src -ResultRows @($disabledLicensed | Select-Object UserPrincipalName,DisplayName,AccountEnabled)
    }
    if ($neverExpire.Count -gt 0) {
        $noMfaNeverExpire = @($neverExpire | Where-Object { $_.Id -and $script:MfaCapableById.ContainsKey($_.Id) -and -not $script:MfaCapableById[$_.Id] })
        $sev = if ($noMfaNeverExpire.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EntraFinding -Severity $sev -CheckId 'accounts' -Category 'Identity Hygiene' `
            -Title ("{0} account(s) configured with non-expiring passwords" -f $neverExpire.Count) `
            -Evidence ("PasswordPolicies=DisablePasswordExpiration on {0} account(s); {1} of them are not MFA-capable." -f $neverExpire.Count, $noMfaNeverExpire.Count) `
            -WhyItMatters 'A password that never expires and is not backed by strong MFA is a long-lived, crackable credential - especially dangerous on admin or service accounts.' `
            -RecommendedAction 'Require phishing-resistant MFA before allowing non-expiring passwords, or remove DisablePasswordExpiration. Prefer managed identities / certificate auth for service accounts.' `
            -SourceFile $src -ResultRows @($neverExpire | Select-Object UserPrincipalName,DisplayName,PasswordPolicies)
    }
    if ($weakPwPolicy.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accounts' -Category 'Identity Hygiene' `
            -Title ("{0} account(s) have strong-password enforcement disabled" -f $weakPwPolicy.Count) `
            -Evidence ("PasswordPolicies=DisableStrongPassword on {0} account(s)." -f $weakPwPolicy.Count) `
            -WhyItMatters 'Disabling strong-password enforcement permits weak, easily guessed passwords on cloud accounts.' `
            -RecommendedAction 'Remove DisableStrongPassword and enforce Entra password protection / banned-password lists.' `
            -SourceFile $src -ResultRows @($weakPwPolicy | Select-Object UserPrincipalName,PasswordPolicies)
    }
    # Synced vs cloud-only baseline
    $synced = @($users | Where-Object { $_.OnPremisesSyncEnabled }).Count
    Add-EntraFinding -Severity 'Information' -CheckId 'accounts' -Category 'Identity Hygiene' `
        -Title 'Account population overview' `
        -Evidence ("Total users: {0}; enabled: {1}; synced from on-prem: {2}; cloud-only: {3}; guests: {4}" -f `
            $users.Count, @($users|?{$_.AccountEnabled}).Count, $synced, ($users.Count-$synced), @($users|?{$_.UserType -eq 'Guest'}).Count) `
        -WhyItMatters 'Baseline of the directory population and the hybrid split, for context across the rest of the report.' `
        -RecommendedAction 'No action - context.' -SourceFile $src
}

# ===========================================================================
# CHECK 5 - staleusers
# ===========================================================================
function Invoke-Check-StaleUsers {
    if (-not (Test-MgScope @('AuditLog.Read.All') -Quiet)) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleusers' -Category 'Identity Hygiene' `
            -Title 'Sign-in activity not assessed (AuditLog.Read.All / P1 required)' `
            -Evidence 'signInActivity could not be read without AuditLog.Read.All and Entra ID P1.' `
            -WhyItMatters 'Without sign-in activity, stale/never-used accounts cannot be identified - this is a coverage gap, not a clean result.' `
            -RecommendedAction 'Grant AuditLog.Read.All and ensure Entra ID P1+ so sign-in activity is available.' -SourceFile $null
        return
    }
    $users = Get-EAUsers

    # Privileged principals get a tighter inactivity bar (escalated severity).
    $privIds = @{}
    try {
        $active = @(); try { $active += @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction Stop) } catch {}
        if ($active.Count -eq 0) { try { $active += @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction SilentlyContinue) } catch {} }
        foreach ($a in $active) { if ($a.PrincipalId) { $privIds[$a.PrincipalId] = $true } }
    } catch {}

    $now0      = (Get-Date).ToUniversalTime()
    $cut       = $now0.AddDays(-$InactiveDays)
    $cut180    = $now0.AddDays(-180)
    $created30 = $now0.AddDays(-30)
    $privCut   = $now0.AddDays(-([Math]::Min($InactiveDays, 45)))   # admins held to <= 45 days

    $rows = @()
    foreach ($u in $users) {
        if ($u.UserType -eq 'Guest') { continue }
        $sa = $u.SignInActivity
        $eff = $null; $conf = 'NeverSeen'
        if ($sa) {
            # Prefer lastSuccessfulSignInDateTime: lastSignInDateTime can be a FAILED attempt
            # (e.g. password-spray), which would make a dormant account look active.
            if ($sa.LastSuccessfulSignInDateTime) {
                $eff = [datetime]$sa.LastSuccessfulSignInDateTime; $conf = 'SuccessfulSignIn'
            } elseif ($sa.LastSignInDateTime -or $sa.LastNonInteractiveSignInDateTime) {
                $eff = @($sa.LastSignInDateTime, $sa.LastNonInteractiveSignInDateTime) | Where-Object { $_ } | ForEach-Object { [datetime]$_ } | Sort-Object -Descending | Select-Object -First 1
                $conf = 'AttemptOnly'
            }
        }
        $rows += [pscustomobject]@{
            UserPrincipalName       = $u.UserPrincipalName
            Enabled                 = $u.AccountEnabled
            Privileged              = [bool]($u.Id -and $privIds.ContainsKey($u.Id))
            Created                 = $u.CreatedDateTime
            LastSuccessfulOrAttempt = $eff
            Confidence              = $conf
        }
    }
    $src = Write-Evidence -BaseName 'stale_users' -Rows $rows -Title ("Stale / Inactive Users (> {0} days)" -f $InactiveDays) `
        -Notes @('Activity prefers lastSuccessfulSignInDateTime. Confidence "AttemptOnly" = only failed/attempted sign-ins were recorded (no successful sign-in).')

    $privStale  = @($rows | Where-Object { $_.Privileged -and $_.Enabled -and (($_.Confidence -eq 'NeverSeen') -or ($_.LastSuccessfulOrAttempt -lt $privCut)) })
    $never      = @($rows | Where-Object { -not $_.Privileged -and $_.Confidence -eq 'NeverSeen' -and $_.Enabled -and $_.Created -and $_.Created -lt $created30 })
    $stale      = @($rows | Where-Object { -not $_.Privileged -and $_.Confidence -ne 'NeverSeen' -and $_.Enabled -and $_.LastSuccessfulOrAttempt -lt $cut })
    $stale180   = @($stale | Where-Object { $_.LastSuccessfulOrAttempt -lt $cut180 })
    $attemptOnly= @($rows | Where-Object { -not $_.Privileged -and $_.Confidence -eq 'AttemptOnly' -and $_.Enabled -and $_.LastSuccessfulOrAttempt -lt $cut })

    if ($privStale.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'staleusers' -Category 'Identity Hygiene' `
            -Title ("{0} privileged account(s) inactive / never successfully signed in" -f $privStale.Count) `
            -Evidence ("Privileged accounts with no successful sign-in within {0} days: {1}" -f ([Math]::Min($InactiveDays,45)), (($privStale | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'A dormant account that still holds an admin role is standing privilege nobody is watching - an ideal takeover target. Admins should be held to a tighter inactivity bar than normal users.' `
            -RecommendedAction 'Confirm the role is still needed; remove the standing privilege (move to PIM-eligible) or disable the account. Investigate any admin that has never successfully signed in.' `
            -SourceFile $src -ResultRows @($privStale | Select-Object UserPrincipalName,LastSuccessfulOrAttempt,Confidence)
    }
    if ($stale.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'staleusers' -Category 'Identity Hygiene' `
            -Title ("{0} enabled account(s) inactive > {1} days" -f $stale.Count, $InactiveDays) `
            -Evidence ("{0} enabled users have no successful sign-in for over {1} days ({2} over 180 days)." -f $stale.Count, $InactiveDays, $stale180.Count) `
            -WhyItMatters 'Inactive but enabled accounts are prime password-spray targets and usually fall outside normal monitoring. Mirrors the AD inactive-account review.' `
            -RecommendedAction 'Disable accounts inactive beyond the threshold after confirmation, and delete after a retention window.' `
            -SourceFile $src -ResultRows @($stale | Select-Object UserPrincipalName,LastSuccessfulOrAttempt,Confidence | Sort-Object LastSuccessfulOrAttempt)
    }
    if ($never.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'staleusers' -Category 'Identity Hygiene' `
            -Title ("{0} enabled account(s) have never successfully signed in" -f $never.Count) `
            -Evidence ("{0} enabled accounts older than 30 days with no successful sign-in on record." -f $never.Count) `
            -WhyItMatters 'Never-used accounts indicate provisioning errors or dormant accounts that can be used as backdoors.' `
            -RecommendedAction 'Verify each never-signed-in account is required; disable and remove the unneeded ones.' `
            -SourceFile $src -ResultRows @($never | Select-Object UserPrincipalName,Created)
    }
    if ($attemptOnly.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'staleusers' -Category 'Identity Hygiene' `
            -Title ("{0} enabled account(s) show only attempted (not successful) sign-ins" -f $attemptOnly.Count) `
            -Evidence ("{0} accounts have sign-in attempts but no recent successful sign-in - possible password-spray noise on otherwise dormant accounts." -f $attemptOnly.Count) `
            -WhyItMatters 'Attempts without a successful sign-in can make a dormant account look active and may indicate targeting (e.g. password spray).' `
            -RecommendedAction 'Treat these as effectively inactive for lifecycle purposes and review the sign-in logs for malicious attempts.' `
            -SourceFile $src -ResultRows @($attemptOnly | Select-Object UserPrincipalName,LastSuccessfulOrAttempt,Confidence)
    }
}

# ===========================================================================
# CHECK 6 - guests
# ===========================================================================
function Invoke-Check-Guests {
    $users = Get-EAUsers
    $guestUsers = @($users | Where-Object { $_.UserType -eq 'Guest' })

    # privileged guests (cross-ref active role assignments)
    $privGuestUpns = @()
    try {
        Get-EARoleDefMap | Out-Null
        $active = @()
        try { $active += @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop) } catch {}
        if ($active.Count -eq 0) { try { $active += @(Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction SilentlyContinue) } catch {} }
        foreach ($a in $active) {
            $upn = Get-Ap $a.Principal 'userPrincipalName'
            if ($upn -and $upn -like '*#EXT#*') { $privGuestUpns += $upn }
        }
        $privGuestUpns = @($privGuestUpns | Sort-Object -Unique)
    } catch {}

    $authz = $null; try { $authz = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue } catch {}
    $rows = $guestUsers | Select-Object UserPrincipalName, DisplayName, AccountEnabled, CreatedDateTime,
        @{n='ExternalUserState';e={ $_.ExternalUserState }},
        @{n='StateChanged';e={ $_.ExternalUserStateChangeDateTime }}
    $notes = @()
    if ($authz) { $notes += ("AllowInvitesFrom: {0}" -f $authz.AllowInvitesFrom); $notes += ("GuestUserRoleId: {0}" -f $authz.GuestUserRoleId) }
    $src = Write-Evidence -BaseName 'guests' -Rows $rows -Title 'Guest / External Users' -Notes $notes

    if ($privGuestUpns.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'guests' -Category 'External Access' `
            -Title ("{0} guest/external account(s) hold a directory role" -f $privGuestUpns.Count) `
            -Evidence ("Privileged guests: {0}" -f ($privGuestUpns -join ', ')) `
            -WhyItMatters 'A guest holding an admin role is an externally-managed identity with tenant power - you do not control its credentials, MFA or lifecycle.' `
            -RecommendedAction 'Remove guests from privileged roles; if external administration is required, use a dedicated member account governed by your own controls.' `
            -SourceFile $src -ResultRows @($privGuestUpns | ForEach-Object { [pscustomobject]@{ Guest=$_ } })
    }
    if ($authz) {
        if ($authz.GuestUserRoleId -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') {
            Add-EntraFinding -Severity 'High' -CheckId 'guests' -Category 'External Access' `
                -Title 'Guests have the same directory permissions as members' `
                -Evidence 'GuestUserRoleId = Member (a0b1b346-...). Guests can read most directory objects.' `
                -WhyItMatters 'Granting guests full member-level directory access lets external identities enumerate users, groups, apps and roles.' `
                -RecommendedAction 'Set guest access to the most restrictive role (2af84b1e-...) so guests cannot read directory objects they were not invited to.' `
                -SourceFile $src
        }
        if ($authz.AllowInvitesFrom -in @('everyone','adminsGuestInvitersAndAllMembers')) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'guests' -Category 'External Access' `
                -Title ("Any member can invite guests (AllowInvitesFrom = {0})" -f $authz.AllowInvitesFrom) `
                -Evidence ("AllowInvitesFrom = {0}" -f $authz.AllowInvitesFrom) `
                -WhyItMatters 'Unrestricted guest invitations expand the external attack surface without governance and enable consent-phishing footholds.' `
                -RecommendedAction 'Restrict guest invitations to admins or designated guest inviters.' -SourceFile $src
        }
    }
    $now0 = (Get-Date).ToUniversalTime()
    $pending   = @($guestUsers | Where-Object { $_.ExternalUserState -eq 'PendingAcceptance' })
    $pending90 = @($pending | Where-Object { $_.ExternalUserStateChangeDateTime -and ([datetime]$_.ExternalUserStateChangeDateTime) -lt $now0.AddDays(-90) })
    $pending30 = @($pending | Where-Object { $_.ExternalUserStateChangeDateTime -and ([datetime]$_.ExternalUserStateChangeDateTime) -lt $now0.AddDays(-30) -and ([datetime]$_.ExternalUserStateChangeDateTime) -ge $now0.AddDays(-90) })
    if ($pending90.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'guests' -Category 'External Access' `
            -Title ("{0} guest invitation(s) pending acceptance > 90 days" -f $pending90.Count) `
            -Evidence ("Guests in PendingAcceptance for over 90 days: {0}" -f $pending90.Count) `
            -WhyItMatters 'Long-pending invitations are stale external objects that clutter the directory and can mask abandoned or mistaken invites.' `
            -RecommendedAction 'Remove guest objects whose invitations have been pending for over 90 days.' `
            -SourceFile $src -ResultRows @($pending90 | Select-Object UserPrincipalName,ExternalUserStateChangeDateTime)
    }
    if ($pending30.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'guests' -Category 'External Access' `
            -Title ("{0} guest invitation(s) pending acceptance 30-90 days" -f $pending30.Count) `
            -Evidence ("Guests in PendingAcceptance for 30-90 days: {0}" -f $pending30.Count) `
            -WhyItMatters 'Invitations that linger unredeemed are usually abandoned and should be cleaned up.' `
            -RecommendedAction 'Follow up on or remove guest invitations that remain unredeemed beyond 30 days.' `
            -SourceFile $src -ResultRows @($pending30 | Select-Object UserPrincipalName,ExternalUserStateChangeDateTime)
    }
    Add-EntraFinding -Severity 'Information' -CheckId 'guests' -Category 'External Access' `
        -Title ("{0} guest/external user(s) in the tenant" -f $guestUsers.Count) `
        -Evidence ("Guest count: {0}" -f $guestUsers.Count) `
        -WhyItMatters 'Baseline of external collaboration scale.' -RecommendedAction 'No action - context.' -SourceFile $src
}

# ===========================================================================
# CHECK 7 - mfa
# ===========================================================================
function Invoke-Check-Mfa {
    $reg = Get-EARegistrationDetails
    # privileged principals
    $privIds = @{}
    try {
        Get-EARoleDefMap | Out-Null
        $active = @()
        try { $active += @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop) } catch {}
        if ($active.Count -eq 0) { try { $active += @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction SilentlyContinue) } catch {} }
        foreach ($a in $active) { if ($a.PrincipalId) { $privIds[$a.PrincipalId] = $true } }
    } catch {}

    # Disabled accounts are excluded from the risk findings (a disabled account that is
    # not MFA-capable is not a live risk).
    $enabledById = @{}
    try { foreach ($u in (Get-EAUsers)) { if ($u.Id) { $enabledById[$u.Id] = [bool]$u.AccountEnabled } } } catch {}

    # Method-strength categories from the registration report's methodsRegistered.
    # Phishing-resistant: FIDO2 / Windows Hello / passkeys / certificate-based.
    # Strong (not phishing-resistant): Authenticator app / OTP / TAP.
    # Weak: SMS / voice / email (anything not matching strong or phishing-resistant).
    # Match the real methodsRegistered enum values. TAP is a bootstrap/recovery credential,
    # not steady-state MFA, so it is deliberately NOT counted as "strong" - a TAP-only admin
    # should still surface in the weak/no-strong bucket.
    $phishRx  = '(?i)(fido2|windowsHello|passKey|x509Certificate)'
    $strongRx = '(?i)(microsoftAuthenticator|oneTimePasscode)'

    $rows = @()
    foreach ($r in $reg) {
        $methods = @($r.MethodsRegistered)
        $hasPhish  = (@($methods | Where-Object { $_ -match $phishRx }).Count -gt 0)
        $hasStrong = (@($methods | Where-Object { $_ -match $strongRx }).Count -gt 0)
        $isPriv = ([bool]$r.IsAdmin -or ($r.Id -and $privIds.ContainsKey($r.Id)))
        $enabled = if ($r.Id -and $enabledById.ContainsKey($r.Id)) { $enabledById[$r.Id] } else { $true }
        $rows += [pscustomobject]@{
            UserPrincipalName=$r.UserPrincipalName; Privileged=$isPriv; Enabled=$enabled
            MfaRegistered=[bool]$r.IsMfaRegistered; MfaCapable=[bool]$r.IsMfaCapable
            StrongMethod=$hasStrong; PhishingResistant=$hasPhish; Methods=($methods -join ',')
        }
    }
    $src = Write-Evidence -BaseName 'mfa_registration' -Rows $rows -Title 'MFA Posture - Registered / Capable / Strong / Phishing-Resistant'

    $priv         = @($rows | Where-Object { $_.Privileged -and $_.Enabled })
    $privNoMfa    = @($priv | Where-Object { -not $_.MfaCapable })
    $privWeakOnly = @($priv | Where-Object { $_.MfaCapable -and -not $_.StrongMethod -and -not $_.PhishingResistant })
    $privNoPhish  = @($priv | Where-Object { $_.MfaCapable -and $_.StrongMethod -and -not $_.PhishingResistant })
    $memberNoMfa  = @($rows | Where-Object { -not $_.Privileged -and $_.Enabled -and -not $_.MfaCapable })
    $enabledRows  = @($rows | Where-Object { $_.Enabled })

    if ($privNoMfa.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId 'mfa' -Category 'Authentication' `
            -Title ("{0} privileged account(s) are NOT MFA-capable" -f $privNoMfa.Count) `
            -Evidence ("Admins without MFA capability: {0}" -f (($privNoMfa | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'An admin that is not MFA-capable is effectively password-only and cannot be challenged - the single highest-value credential-theft target in the tenant.' `
            -RecommendedAction 'Require phishing-resistant MFA (FIDO2 / Windows Hello / passkeys) for every privileged account before any standing or eligible role use.' `
            -SourceFile $src -ResultRows @($privNoMfa | Select-Object UserPrincipalName,MfaCapable,Methods)
    }
    if ($privWeakOnly.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'mfa' -Category 'Authentication' `
            -Title ("{0} privileged account(s) rely on weak MFA methods only (SMS/voice/email)" -f $privWeakOnly.Count) `
            -Evidence ("Admins with only weak methods: {0}" -f (($privWeakOnly | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'SMS/voice/email factors are phishable and SIM-swappable. An admin whose only MFA is a weak factor can be phished or SIM-swapped into a full account takeover.' `
            -RecommendedAction 'Register FIDO2 / Windows Hello / passkeys for these admins and retire SMS/voice as a factor.' `
            -SourceFile $src -ResultRows @($privWeakOnly | Select-Object UserPrincipalName,Methods)
    }
    if ($privNoPhish.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'mfa' -Category 'Authentication' `
            -Title ("{0} privileged account(s) have MFA but no phishing-resistant method" -f $privNoPhish.Count) `
            -Evidence ("Admins with strong-but-phishable MFA (e.g. Authenticator push, OTP): {0}" -f (($privNoPhish | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Push/OTP MFA is far better than passwords but is still phishable (real-time relay, MFA fatigue). Privileged accounts should use phishing-resistant methods.' `
            -RecommendedAction 'Roll out FIDO2 security keys / passkeys / Windows Hello to all privileged users and require phishing-resistant authentication strength via Conditional Access.' `
            -SourceFile $src -ResultRows @($privNoPhish | Select-Object UserPrincipalName,Methods)
    }
    if ($memberNoMfa.Count -gt 0) {
        $denom = [Math]::Max(1, @($rows | Where-Object { -not $_.Privileged -and $_.Enabled }).Count)
        $sev = if (($memberNoMfa.Count / [double]$denom) -gt 0.25) { 'Medium' } else { 'Low' }
        Add-EntraFinding -Severity $sev -CheckId 'mfa' -Category 'Authentication' `
            -Title ("{0} enabled non-admin account(s) are not MFA-capable" -f $memberNoMfa.Count) `
            -Evidence ("Enabled members without MFA capability: {0} of {1} enabled members." -f $memberNoMfa.Count, $denom) `
            -WhyItMatters 'Accounts that cannot be MFA-challenged are password-only and vulnerable to spray and replay.' `
            -RecommendedAction 'Drive MFA registration / capability to 100% for enabled members via registration campaigns and Conditional Access.' `
            -SourceFile $src
    }
    $prAdopt = if ($enabledRows.Count) { [math]::Round((100 * @($enabledRows | Where-Object { $_.PhishingResistant }).Count / $enabledRows.Count), 1) } else { 0 }
    Add-EntraFinding -Severity 'Information' -CheckId 'mfa' -Category 'Authentication' `
        -Title ("Phishing-resistant MFA adoption: {0}% of enabled accounts" -f $prAdopt) `
        -Evidence ("{0} of {1} enabled accounts have a phishing-resistant method registered; {2} privileged account(s) reviewed." -f @($enabledRows | Where-Object { $_.PhishingResistant }).Count, $enabledRows.Count, $priv.Count) `
        -WhyItMatters 'Phishing-resistant adoption is the strongest single indicator of authentication maturity.' `
        -RecommendedAction 'Drive phishing-resistant methods to 100% for privileged users first, then the wider population.' -SourceFile $src
}

# ===========================================================================
# CHECK 8 - legacyauth
# ===========================================================================
function Invoke-Check-LegacyAuth {
    $since = (Get-Date).ToUniversalTime().AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $legacyClients = 'Exchange ActiveSync|Authenticated SMTP|IMAP4|POP3|MAPI Over HTTP|Other clients|AutoDiscover|Exchange Online PowerShell|Exchange Web Services|Outlook Anywhere'
    $signins = @(Get-MgAuditLogSignIn -All -Filter "createdDateTime ge $since" -ErrorAction Stop |
        Where-Object { $_.ClientAppUsed -and $_.ClientAppUsed -match $legacyClients })

    $rows = $signins | Select-Object CreatedDateTime, UserPrincipalName, ClientAppUsed, AppDisplayName,
        @{n='Status';e={ $_.Status.ErrorCode }}, IPAddress | Sort-Object CreatedDateTime -Descending
    $src = Write-Evidence -BaseName 'legacy_auth_signins' -Rows $rows -Title 'Legacy Authentication Sign-ins (last 30 days)'

    $success = @($signins | Where-Object { $_.Status.ErrorCode -eq 0 })
    $failOnly = @($signins | Where-Object { $_.Status.ErrorCode -ne 0 })

    if ($success.Count -gt 0) {
        $upns = @($success | Select-Object -ExpandProperty UserPrincipalName -Unique)
        Add-EntraFinding -Severity 'High' -CheckId 'legacyauth' -Category 'Authentication' `
            -Title ("{0} successful legacy-authentication sign-in(s) in the last 30 days" -f $success.Count) `
            -Evidence ("Successful legacy sign-ins by {0} account(s) via {1}." -f $upns.Count, (($success.ClientAppUsed | Select-Object -Unique) -join ', ')) `
            -WhyItMatters 'Legacy protocols do not support modern auth and bypass Conditional Access MFA entirely - a single successful legacy sign-in proves MFA is circumventable and is the preferred path for password-spray.' `
            -RecommendedAction 'Block legacy authentication with a Conditional Access policy (clientAppTypes = exchangeActiveSync + other -> block) and migrate the identified users/clients to modern auth.' `
            -SourceFile $src -ResultRows @($success | Select-Object CreatedDateTime,UserPrincipalName,ClientAppUsed | Select-Object -First 50)
    } elseif ($failOnly.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'legacyauth' -Category 'Authentication' `
            -Title ("Legacy-auth attempts seen but all blocked ({0} failed)" -f $failOnly.Count) `
            -Evidence 'Legacy authentication attempts were blocked, but clients are still configured to try it.' `
            -WhyItMatters 'Blocked legacy attempts mean a control is working, but the configured clients remain a latent risk if the block is ever removed.' `
            -RecommendedAction 'Confirm a CA legacy-auth block is enforced for all users and remediate the client configurations still attempting legacy auth.' `
            -SourceFile $src
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId 'legacyauth' -Category 'Authentication' `
            -Title 'No legacy-authentication sign-ins observed (last 30 days)' `
            -Evidence 'No legacy-protocol sign-ins in the sign-in logs window.' `
            -WhyItMatters 'Absence of legacy auth in the log window suggests modern auth is enforced (within retention limits).' `
            -RecommendedAction 'Maintain a Conditional Access policy that blocks legacy authentication.' -SourceFile $src
    }
}

# ===========================================================================
# CHECK 9 - tenantposture (security defaults, authorization, consent)
# ===========================================================================
function Invoke-Check-TenantPosture {
    $sd = $null; try { $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop } catch {}
    $authz = $null; try { $authz = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue } catch {}
    $caCount = 0; try { $caCount = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'enabled' }).Count } catch {}

    $rows = @()
    if ($sd)    { $rows += [pscustomobject]@{ Setting='Security Defaults enabled'; Value=$sd.IsEnabled } }
    if ($authz) {
        $rows += [pscustomobject]@{ Setting='Users may create app registrations'; Value=$authz.DefaultUserRolePermissions.AllowedToCreateApps }
        $rows += [pscustomobject]@{ Setting='Users may create security groups';   Value=$authz.DefaultUserRolePermissions.AllowedToCreateSecurityGroups }
        $rows += [pscustomobject]@{ Setting='Users may create tenants';           Value=$authz.DefaultUserRolePermissions.AllowedToCreateTenants }
        $rows += [pscustomobject]@{ Setting='Users may read other users';         Value=$authz.DefaultUserRolePermissions.AllowedToReadOtherUsers }
        $rows += [pscustomobject]@{ Setting='Email-verified users may join';      Value=$authz.AllowEmailVerifiedUsersToJoinOrganization }
        $rows += [pscustomobject]@{ Setting='AllowInvitesFrom';                   Value=$authz.AllowInvitesFrom }
        $rows += [pscustomobject]@{ Setting='User consent allowed for risky apps';Value=$authz.AllowUserConsentForRiskyApps }
        $rows += [pscustomobject]@{ Setting='PermissionGrantPoliciesAssigned';    Value=($authz.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned -join ',') }
    }
    $src = Write-Evidence -BaseName 'tenant_posture' -Rows $rows -Title 'Security Defaults, Authorization & Consent Settings'

    if ($sd -and -not $sd.IsEnabled -and $caCount -eq 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'tenantposture' -Category 'Tenant Posture' `
            -Title 'Security Defaults are OFF and no enabled Conditional Access policy enforces MFA' `
            -Evidence 'IsEnabled=false on Security Defaults with zero enabled CA policies - the tenant can be password-only.' `
            -WhyItMatters 'With neither Security Defaults nor Conditional Access, there is no baseline MFA enforcement at all - the most common cause of account takeover.' `
            -RecommendedAction 'Enable Conditional Access MFA policies (preferred on licensed tenants) or turn on Security Defaults as an interim baseline.' -SourceFile $src
    } elseif ($sd -and $sd.IsEnabled -and $caCount -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'tenantposture' -Category 'Tenant Posture' `
            -Title 'Security Defaults enabled while Conditional Access policies also exist' `
            -Evidence 'Security Defaults and CA cannot be used together for granular control.' `
            -WhyItMatters 'Running Security Defaults alongside CA suggests the org has not fully moved to Conditional Access, limiting granular control.' `
            -RecommendedAction 'Disable Security Defaults and drive MFA/legacy-auth/device posture entirely from Conditional Access.' -SourceFile $src
    }
    if ($authz) {
        if ($authz.DefaultUserRolePermissions.AllowedToCreateApps) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'tenantposture' -Category 'Tenant Posture' `
                -Title 'Standard users can register applications' `
                -Evidence 'DefaultUserRolePermissions.AllowedToCreateApps = true.' `
                -WhyItMatters 'Allowing any user to register apps enables consent-phishing and shadow-IT app sprawl that bypasses governance.' `
                -RecommendedAction 'Set AllowedToCreateApps = false and route app registration through a request/approval process.' -SourceFile $src
        }
        if ($authz.AllowEmailVerifiedUsersToJoinOrganization) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'tenantposture' -Category 'Tenant Posture' `
                -Title 'Email-verified users may self-join the tenant' `
                -Evidence 'AllowEmailVerifiedUsersToJoinOrganization = true.' `
                -WhyItMatters 'Self-service join allows external users to create accounts in your tenant without invitation.' `
                -RecommendedAction 'Disable email-verified self-service sign-up unless explicitly required.' -SourceFile $src
        }
        $pg = @($authz.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)
        if ($pg -match 'legacy') {
            Add-EntraFinding -Severity 'High' -CheckId 'tenantposture' -Category 'Tenant Posture' `
                -Title 'Permissive user consent to applications is enabled (legacy policy)' `
                -Evidence ("PermissionGrantPoliciesAssigned = {0}" -f ($pg -join ',')) `
                -WhyItMatters 'Permissive user consent is the classic illicit-consent-grant entry point - a phishing app can obtain mailbox/file access with one user click.' `
                -RecommendedAction 'Restrict user consent to verified-publisher low-impact permissions (or none) and enable the admin-consent request workflow.' -SourceFile $src
        }
    }
    if ($script:Findings.Where({$_.CheckId -eq 'tenantposture'}).Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'tenantposture' -Category 'Tenant Posture' `
            -Title 'Tenant default permissions and consent settings reviewed' `
            -Evidence 'No permissive defaults detected in authorization / consent settings.' `
            -WhyItMatters 'Restrictive tenant defaults reduce the consent-phishing and shadow-IT attack surface.' `
            -RecommendedAction 'Maintain restrictive defaults and review periodically.' -SourceFile $src
    }
}

# ===========================================================================
# CHECK 10 - capolicies (Conditional Access posture)
# ===========================================================================
function Invoke-Check-CAPolicies {
    $pols = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
    $named = @(); try { $named = @(Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction SilentlyContinue) } catch {}

    $rows = $pols | Select-Object DisplayName, State,
        @{n='Users';e={ ($_.Conditions.Users.IncludeUsers -join ',') }},
        @{n='Apps';e={ ($_.Conditions.Applications.IncludeApplications -join ',') }},
        @{n='Controls';e={ ($_.GrantControls.BuiltInControls -join ',') }},
        @{n='ClientApps';e={ ($_.Conditions.ClientAppTypes -join ',') }}
    $src = Write-Evidence -BaseName 'conditional_access' -Rows $rows -Title 'Conditional Access Policies'
    if ($named.Count -gt 0) {
        $nrows = $named | Select-Object DisplayName, @{n='Trusted';e={ (Get-Ap $_ 'isTrusted') }}, @{n='Type';e={ (Get-Ap $_ '@odata.type') }}
        Write-Evidence -BaseName 'named_locations' -Rows $nrows -Title 'Named Locations' | Out-Null
    }

    $enabled = @($pols | Where-Object { $_.State -eq 'enabled' })

    function _Has([scriptblock]$pred) { @($enabled | Where-Object $pred).Count -gt 0 }

    $mfaForAdmins = _Has {
        (Test-CaPolicyRequiresMfaOrStrength $_) -and
        ($_.Conditions.Users.IncludeRoles -and @($_.Conditions.Users.IncludeRoles).Count -gt 0)
    }
    $mfaForAll = _Has {
        (Test-CaPolicyRequiresMfaOrStrength $_) -and
        ($_.Conditions.Users.IncludeUsers -contains 'All')
    }
    $blocksLegacy = _Has {
        ($_.GrantControls.BuiltInControls -contains 'block') -and
        ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or $_.Conditions.ClientAppTypes -contains 'other')
    }

    if ($pols.Count -eq 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No Conditional Access policies are configured' `
            -Evidence 'Zero CA policies returned.' `
            -WhyItMatters 'Conditional Access is the cloud control plane (the GPO analog). With no policies, MFA, legacy-auth blocking and device compliance are not enforced.' `
            -RecommendedAction 'Create baseline CA policies: MFA for admins, MFA for all users, block legacy auth, require compliant/hybrid-joined devices.' -SourceFile $src
        return
    }
    if (-not $mfaForAdmins) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No enabled Conditional Access policy requires MFA for administrators' `
            -Evidence 'No enabled policy targets directory roles with an MFA grant control.' `
            -WhyItMatters 'Admins are the highest-value targets; without an enforced MFA policy their accounts can be taken over with a stolen password.' `
            -RecommendedAction 'Create an enabled CA policy requiring MFA (preferably phishing-resistant) for all privileged directory roles.' -SourceFile $src
    }
    if (-not $mfaForAll) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No enabled Conditional Access policy requires MFA for all users' `
            -Evidence 'No enabled policy applies an MFA grant to All users.' `
            -WhyItMatters 'Without tenant-wide MFA, any single password compromise grants access. This is the baseline cloud identity control.' `
            -RecommendedAction 'Create an enabled CA policy requiring MFA for all users (with break-glass exclusions).' -SourceFile $src
    }
    if (-not $blocksLegacy) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No enabled Conditional Access policy blocks legacy authentication' `
            -Evidence 'No enabled policy blocks exchangeActiveSync / other (legacy) client app types.' `
            -WhyItMatters 'Legacy auth bypasses MFA; without a block, password-spray against legacy protocols defeats Conditional Access.' `
            -RecommendedAction 'Create an enabled CA policy blocking legacy authentication for all users.' -SourceFile $src
    }
    # Disabled / report-only policies named like MFA (false sense of security)
    $disabledMfaNamed = @($pols | Where-Object { $_.State -ne 'enabled' -and $_.DisplayName -match 'mfa|multi.?factor' })
    if ($disabledMfaNamed.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("{0} MFA-style Conditional Access policy is disabled or report-only" -f $disabledMfaNamed.Count) `
            -Evidence ("Disabled/report-only MFA-named policies: {0}" -f (($disabledMfaNamed.DisplayName) -join ', ')) `
            -WhyItMatters 'A policy that looks like it enforces MFA but is disabled or report-only provides no protection while implying coverage exists.' `
            -RecommendedAction 'Enable the policy (after report-only validation) or remove it so the policy set reflects what is actually enforced.' `
            -SourceFile $src -ResultRows @($disabledMfaNamed | Select-Object DisplayName,State)
    }
    # Trusted named locations that are broad/public
    foreach ($n in $named) {
        $isTrusted = (Get-Ap $n 'isTrusted')
        $ranges = (Get-Ap $n 'ipRanges')
        if ($isTrusted -and $ranges) {
            $broad = @($ranges | Where-Object { (Get-Ap $_ 'cidrAddress') -match '/(?:[0-9]|1[0-6])$' })
            if ($broad.Count -gt 0) {
                Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                    -Title ("Trusted named location '{0}' contains a very broad IP range" -f $n.DisplayName) `
                    -Evidence 'A trusted location with a wide CIDR can be used to bypass MFA from large address space.' `
                    -WhyItMatters 'Trusted locations are commonly used as MFA exclusions; an over-broad trusted range turns into a Conditional Access bypass primitive.' `
                    -RecommendedAction 'Restrict trusted named locations to specific corporate egress IPs only; never use them to broadly exclude MFA.' -SourceFile $src
            }
        }
    }
    # Privileged accounts that are NOT required to MFA (excluded from MFA-enforcing policies)
    $mfaPolicies = @($enabled | Where-Object { Test-CaPolicyRequiresMfaOrStrength $_ })
    if ($mfaPolicies.Count -gt 0) {
        $excludedUserIds = New-Object System.Collections.Generic.HashSet[string]
        $excludedGroupIds = @()
        foreach ($p in $mfaPolicies) {
            foreach ($uid in @($p.Conditions.Users.ExcludeUsers)) { if ($uid -and $uid -notmatch 'All|GuestsOrExternalUsers|None') { [void]$excludedUserIds.Add($uid) } }
            foreach ($gid in @($p.Conditions.Users.ExcludeGroups)) { if ($gid -and $gid -notmatch 'All|GuestsOrExternalUsers|None') { $excludedGroupIds += $gid } }
        }
        foreach ($gid in (@($excludedGroupIds) | Where-Object { $_ } | Select-Object -Unique)) {
            try { foreach ($m in @(Get-MgGroupTransitiveMember -GroupId $gid -All -ErrorAction SilentlyContinue)) { if ($m.Id) { [void]$excludedUserIds.Add($m.Id) } } } catch {}
        }
        $privIds = @{}
        foreach ($a in (Get-EAPrivAssignments)) { if ($a.PrincipalId -and $a.State -eq 'Active') { $privIds[$a.PrincipalId] = $true } }
        $bg = Normalize-StringList -Values $BreakGlassUpns
        $excludedPriv = @()
        foreach ($id in $excludedUserIds) {
            if (-not $privIds.ContainsKey($id)) { continue }
            $upn = if ($script:UserById.ContainsKey($id)) { $script:UserById[$id].UserPrincipalName } else { $id }
            if ($upn -and $upn.ToLowerInvariant() -in $bg) { continue }   # break-glass exclusion is expected
            $excludedPriv += [pscustomobject]@{ Account = $upn }
        }
        if ($excludedPriv.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title ("{0} privileged account(s) are EXCLUDED from MFA Conditional Access" -f $excludedPriv.Count) `
                -Evidence ("Admins not required to MFA (directly or via an excluded group): {0}" -f (($excludedPriv | Select-Object -First 10 -ExpandProperty Account) -join ', ')) `
                -WhyItMatters 'An admin excluded from every MFA-enforcing policy can sign in with a password alone - the exclusion silently removes MFA from the highest-value accounts. Only the two designated break-glass accounts should be excluded.' `
                -RecommendedAction 'Remove privileged accounts from MFA-policy exclusions (and from excluded groups); keep only the two break-glass accounts excluded.' `
                -SourceFile $src -ResultRows $excludedPriv
        }
    }

    if ($script:Findings.Where({$_.CheckId -eq 'capolicies'}).Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("{0} Conditional Access policy/policies enforce baseline controls" -f $enabled.Count) `
            -Evidence 'MFA-for-admins, MFA-for-all and legacy-auth-block policies were detected.' `
            -WhyItMatters 'A healthy CA baseline is the cloud control plane equivalent of well-managed GPOs.' `
            -RecommendedAction 'Maintain and extend CA coverage (device compliance, risk-based policies on P2).' -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 11 - riskyusers (Identity Protection)
# ===========================================================================
function Invoke-Check-RiskyUsers {
    $risky = @(Get-MgRiskyUser -All -ErrorAction Stop | Where-Object { $_.RiskState -in @('atRisk','confirmedCompromised') })
    $detections = @()
    try { $detections = @(Get-MgRiskDetection -All -ErrorAction SilentlyContinue) } catch {}
    $rows = $risky | Select-Object UserPrincipalName, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime
    $src = Write-Evidence -BaseName 'risky_users' -Rows $rows -Title 'Identity Protection - Risky Users'
    if ($detections.Count -gt 0) {
        $drows = $detections | Select-Object UserPrincipalName, RiskEventType, RiskLevel, RiskState, DetectedDateTime, IPAddress
        Write-Evidence -BaseName 'risk_detections' -Rows $drows -Title 'Identity Protection - Risk Detections' | Out-Null
    }

    # privileged cross-ref
    $privIds = @{}
    try {
        $active = @(); try { $active += @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction Stop) } catch {}
        if ($active.Count -eq 0) { try { $active += @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction SilentlyContinue) } catch {} }
        foreach ($a in $active) { if ($a.PrincipalId) { $privIds[$a.PrincipalId] = $true } }
    } catch {}

    if ($risky.Count -gt 0) {
        $privRisky = @($risky | Where-Object { $_.Id -and $privIds.ContainsKey($_.Id) })
        if ($privRisky.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'riskyusers' -Category 'Threat Signals' `
                -Title ("{0} PRIVILEGED user(s) are flagged at-risk / compromised" -f $privRisky.Count) `
                -Evidence ("At-risk admins: {0}" -f (($privRisky | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
                -WhyItMatters 'A privileged identity flagged at-risk or confirmed-compromised is an active incident with tenant-wide blast radius - not a hygiene gap.' `
                -RecommendedAction 'Investigate and remediate immediately: reset credentials, revoke refresh tokens/sessions, and review audit logs for misuse. Prioritise these accounts.' `
                -SourceFile $src -ResultRows @($privRisky | Select-Object UserPrincipalName,RiskLevel,RiskState)
        }
        $other = @($risky | Where-Object { -not ($_.Id -and $privIds.ContainsKey($_.Id)) })
        if ($other.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'riskyusers' -Category 'Threat Signals' `
                -Title ("{0} user(s) flagged at-risk / compromised by Identity Protection" -f $other.Count) `
                -Evidence ("At-risk users: {0}" -f (($other | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
                -WhyItMatters 'These are Microsoft live threat signals indicating likely credential compromise (leaked credentials, password spray, anomalous sign-ins).' `
                -RecommendedAction 'Investigate and remediate risky users; enable risk-based Conditional Access to auto-respond (require MFA / block on risk).' `
                -SourceFile $src -ResultRows @($other | Select-Object UserPrincipalName,RiskLevel,RiskState)
        }
    } else {
        $lic = if ($script:HasP2) { 'no at-risk users currently flagged' } else { 'Identity Protection requires Entra ID P2 - result may be license-gated' }
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyusers' -Category 'Threat Signals' `
            -Title 'No at-risk users flagged by Identity Protection' `
            -Evidence $lic `
            -WhyItMatters 'Identity Protection surfaces compromised and risky identities in near real time.' `
            -RecommendedAction 'Ensure Entra ID P2 is licensed and risk-based Conditional Access policies are enabled.' -SourceFile $src
    }

    # Risky service principals (beta, best-effort)
    try {
        $rsp = @()
        if (Get-Command Get-MgRiskyServicePrincipal -ErrorAction SilentlyContinue) {
            $rsp = @(Get-MgRiskyServicePrincipal -All -ErrorAction SilentlyContinue | Where-Object { $_.RiskState -in @('atRisk','confirmedCompromised') })
        } else {
            $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/identityProtection/riskyServicePrincipals' -ErrorAction SilentlyContinue
            if ($resp.value) { $rsp = @($resp.value | Where-Object { $_.riskState -in @('atRisk','confirmedCompromised') }) }
        }
        if ($rsp.Count -gt 0) {
            $rsprows = $rsp | Select-Object @{n='DisplayName';e={ $_.DisplayName ?? $_.displayName }}, @{n='RiskState';e={ $_.RiskState ?? $_.riskState }}
            $rspsrc = Write-Evidence -BaseName 'risky_serviceprincipals' -Rows $rsprows -Title 'Identity Protection - Risky Service Principals'
            Add-EntraFinding -Severity 'High' -CheckId 'riskyusers' -Category 'Threat Signals' `
                -Title ("{0} risky service principal(s) flagged" -f $rsp.Count) `
                -Evidence 'A workload identity (app/service principal) is flagged as risky/compromised.' `
                -WhyItMatters 'A compromised workload identity often holds application permissions exercised without any user interaction - a high-impact, stealthy foothold.' `
                -RecommendedAction 'Investigate the flagged service principals, rotate their credentials, and review their granted application permissions.' -SourceFile $rspsrc -ResultRows $rsprows
        }
    } catch {}
}

# ===========================================================================
# CHECK 12 - apps (app / service principal hygiene & over-privilege)
# ===========================================================================
function Invoke-Check-Apps {
    # keyCredentials/passwordCredentials require an explicit $select on Get-MgApplication.
    $appProps = 'id,appId,displayName,passwordCredentials,keyCredentials,signInAudience,verifiedPublisher,createdDateTime'
    $apps = @(Get-MgApplication -All -Property $appProps -ErrorAction Stop)
    $sps  = @(Get-MgServicePrincipal -All -Property 'id,appId,displayName,appRoles,servicePrincipalType,accountEnabled' -ErrorAction Stop)
    $script:AppCount = $apps.Count
    $now = (Get-Date).ToUniversalTime()
    $soon = $now.AddDays($ExpiringCredentialDays)

    # --- credentials ---
    $credRows = @()
    foreach ($a in $apps) {
        foreach ($c in @($a.PasswordCredentials)) {
            $credRows += [pscustomobject]@{ App=$a.DisplayName; AppId=$a.AppId; Type='Secret'; KeyId=$c.KeyId; End=$c.EndDateTime; Expired=($c.EndDateTime -lt $now); ExpiringSoon=($c.EndDateTime -ge $now -and $c.EndDateTime -lt $soon) }
        }
        foreach ($c in @($a.KeyCredentials)) {
            $credRows += [pscustomobject]@{ App=$a.DisplayName; AppId=$a.AppId; Type=('Cert/' + $c.Usage); KeyId=$c.KeyId; End=$c.EndDateTime; Expired=($c.EndDateTime -lt $now); ExpiringSoon=($c.EndDateTime -ge $now -and $c.EndDateTime -lt $soon) }
        }
    }
    $credSrc = Write-Evidence -BaseName 'app_credentials' -Rows $credRows -Title 'Application Credentials'

    $expired  = @($credRows | Where-Object { $_.Expired })
    $expiring = @($credRows | Where-Object { $_.ExpiringSoon })
    if ($expiring.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Applications' `
            -Title ("{0} application credential(s) expire within {1} days" -f $expiring.Count, $ExpiringCredentialDays) `
            -Evidence ("Apps with expiring credentials: {0}" -f (($expiring.App | Select-Object -Unique | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Expiring credentials cause integration outages when they lapse; tracking them avoids surprise failures and credential sprawl.' `
            -RecommendedAction 'Rotate to certificates with short (<=180 day) lifetimes and remove unused credentials.' `
            -SourceFile $credSrc -ResultRows @($expiring | Select-Object App,Type,End)
    }
    if ($expired.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'apps' -Category 'Applications' `
            -Title ("{0} expired application credential(s) still present" -f $expired.Count) `
            -Evidence ("Expired credentials linger on {0} entries." -f $expired.Count) `
            -WhyItMatters 'Expired credentials are clutter and can mask which credential an app actually uses.' `
            -RecommendedAction 'Remove expired credentials from the application objects.' -SourceFile $credSrc -ResultRows @($expired | Select-Object App,Type,End)
    }

    # --- application permissions across ALL resource APIs (not just Microsoft Graph) ---
    # Build appRoleId -> value map per RESOURCE service principal so dangerous permissions
    # against Exchange Online, SharePoint, Azure Service Management and custom APIs are
    # detected too, and classify each as tier-0 (Critical) or write/high (High).
    $spById = @{}; foreach ($sp in $sps) { if ($sp.Id) { $spById[$sp.Id] = $sp } }
    $appById = @{}; foreach ($a in $apps) { if ($a.AppId) { $appById[$a.AppId] = $a } }
    $resourceRoleMap = @{}
    $writeRx = '(?i)(ReadWrite|\.Write|FullControl|full_access|ManageAsApp|Mail\.Send)'

    function _ResolveAppRoleValue([string]$resourceId, [string]$appRoleId) {
        if (-not $resourceRoleMap.ContainsKey($resourceId)) {
            $m = @{}
            $rsp = $spById[$resourceId]
            if ($rsp) { foreach ($r in @($rsp.AppRoles)) { if ($r.Id) { $m[[string]$r.Id] = $r.Value } } }
            $resourceRoleMap[$resourceId] = $m
        }
        $v = $resourceRoleMap[$resourceId][[string]$appRoleId]
        if ($v) { $v } else { [string]$appRoleId }
    }

    $permRows = @()
    foreach ($sp in $sps) {
        $asn = @()
        try { $asn = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue) } catch {}
        foreach ($x in $asn) {
            $permName = _ResolveAppRoleValue $x.ResourceId $x.AppRoleId
            $isTier0 = ($permName -in $script:DangerousAppPermissions)
            $isWrite = ($permName -match $writeRx)
            if (-not ($isTier0 -or $isWrite)) { continue }
            $tier = if ($isTier0) { 'Tier0' } else { 'Write/High' }
            $permRows += [pscustomobject]@{
                ServicePrincipal=$sp.DisplayName; AppId=$sp.AppId; SpId=$sp.Id
                Permission=$permName; Resource=$x.ResourceDisplayName; Tier=$tier
            }
        }
    }
    $permSrc = Write-Evidence -BaseName 'app_permissions' -Rows $permRows -Title 'Application Permissions (write / high-privilege, all resource APIs)'

    $tier0 = @($permRows | Where-Object { $_.Tier -eq 'Tier0' })
    $writePerms = @($permRows | Where-Object { $_.Tier -eq 'Write/High' })
    if ($tier0.Count -gt 0) {
        $spNames = @($tier0.ServicePrincipal | Select-Object -Unique)
        Add-EntraFinding -Severity 'Critical' -CheckId 'apps' -Category 'Applications' `
            -Title ("{0} service principal(s) hold tier-0 application permissions" -f $spNames.Count) `
            -Evidence ("Tier-0 over-privileged apps: {0}" -f (($spNames | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Application permissions need no signed-in user and are fully exercised by a single leaked secret - the cloud equivalent of dangerous directory ACLs plus Kerberoastable service accounts. Permissions like RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All or full mailbox access are tenant-takeover primitives regardless of which API (Graph, Exchange, SharePoint, custom) grants them.' `
            -RecommendedAction 'Remove tier-0 application permissions that are not justified, replace with least-privilege scoped permissions, and rotate the apps to certificate credentials.' `
            -SourceFile $permSrc -ResultRows $tier0
    }
    if ($writePerms.Count -gt 0) {
        $spNames = @($writePerms.ServicePrincipal | Select-Object -Unique)
        Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Applications' `
            -Title ("{0} service principal(s) hold write-level application permissions" -f $spNames.Count) `
            -Evidence ("Apps with write/high permissions: {0}" -f (($spNames | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Write-capable application permissions (ReadWrite / FullControl / Mail.Send / full_access) let a non-interactive app modify data or configuration tenant-wide. A leaked secret on such an app is a direct data-integrity and persistence risk.' `
            -RecommendedAction 'Confirm each write permission is required; downgrade to read-only where possible and scope to specific resources. Ensure these apps use certificates and have accountable owners.' `
            -SourceFile $permSrc -ResultRows $writePerms
    }

    # --- over-privileged SP hardening: owners, verified publisher, multi-tenant ---
    $privSpIds = @($permRows.SpId | Select-Object -Unique)
    # privileged user set: an over-privileged app owned by a NON-privileged or disabled user
    # is an escalation path (that owner can add a credential and act as the app).
    $privUserIds = @{}
    try { foreach ($a in (Get-EAPrivAssignments)) { if ($a.PrincipalId -and $a.PrincipalType -eq 'user') { $privUserIds[$a.PrincipalId] = $true } } } catch {}
    $hardenRows = @()
    foreach ($spId in $privSpIds) {
        $sp = $spById[$spId]; if (-not $sp) { continue }
        $owners = @(); try { $owners = @(Get-MgServicePrincipalOwner -ServicePrincipalId $spId -All -ErrorAction SilentlyContinue) } catch {}
        $ownerUpns = @($owners | ForEach-Object { Get-Ap $_ 'userPrincipalName' } | Where-Object { $_ })
        $guestOwner = (@($ownerUpns | Where-Object { $_ -like '*#EXT#*' }).Count -gt 0)
        $nonAdminOwner = $false
        foreach ($o in $owners) {
            $oid = $o.Id; $oupn = Get-Ap $o 'userPrincipalName'
            if (-not $oupn -or $oupn -like '*#EXT#*') { continue }   # user owners only; guests counted separately
            $disabled = ($oid -and $script:UserById.ContainsKey($oid) -and -not [bool]$script:UserById[$oid].AccountEnabled)
            $isPriv   = ($oid -and $privUserIds.ContainsKey($oid))
            if ($disabled -or -not $isPriv) { $nonAdminOwner = $true }
        }
        $app = $appById[$sp.AppId]
        $multiTenant = [bool]($app -and $app.SignInAudience -match 'AzureADMultipleOrgs')
        # verifiedPublisher exists on the application object, not the service principal.
        $verifiedPub = [bool]($app -and $app.VerifiedPublisher -and $app.VerifiedPublisher.DisplayName)
        $hardenRows += [pscustomobject]@{
            ServicePrincipal=$sp.DisplayName; AppId=$sp.AppId; OwnerCount=$owners.Count
            Owners=($ownerUpns -join ','); GuestOwner=$guestOwner; NonAdminOwner=$nonAdminOwner; MultiTenant=$multiTenant; VerifiedPublisher=$verifiedPub
        }
    }
    if ($hardenRows.Count -gt 0) {
        $hsrc = Write-Evidence -BaseName 'app_overprivileged_hardening' -Rows $hardenRows -Title 'Over-Privileged App Hardening (owners / publisher / tenancy)'
        $noOwner = @($hardenRows | Where-Object { $_.OwnerCount -eq 0 })
        $guestOwned = @($hardenRows | Where-Object { $_.GuestOwner })
        $mtUnverified = @($hardenRows | Where-Object { $_.MultiTenant -and -not $_.VerifiedPublisher })
        if ($noOwner.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'apps' -Category 'Applications' `
                -Title ("{0} over-privileged service principal(s) have NO owner" -f $noOwner.Count) `
                -Evidence ("Ownerless high-permission apps: {0}" -f (($noOwner.ServicePrincipal | Select-Object -First 10) -join ', ')) `
                -WhyItMatters 'A high-permission app with no owner is unaccountable - nobody is responsible for its credentials or permissions, and its compromise may go unnoticed.' `
                -RecommendedAction 'Assign an accountable administrative owner to every high-permission app, or decommission it.' -SourceFile $hsrc -ResultRows $noOwner
        }
        if ($guestOwned.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'apps' -Category 'Applications' `
                -Title ("{0} over-privileged service principal(s) owned by a guest/external user" -f $guestOwned.Count) `
                -Evidence ("Guest-owned high-permission apps: {0}" -f (($guestOwned.ServicePrincipal | Select-Object -First 10) -join ', ')) `
                -WhyItMatters 'A guest who owns a high-permission app can add credentials to it and act with its application permissions - an externally-controlled tenant-takeover path.' `
                -RecommendedAction 'Remove guest/external owners from high-permission apps immediately and review the app for unexpected credentials.' -SourceFile $hsrc -ResultRows $guestOwned
        }
        if ($mtUnverified.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Applications' `
                -Title ("{0} multi-tenant high-permission app(s) without a verified publisher" -f $mtUnverified.Count) `
                -Evidence ("Multi-tenant + unverified-publisher high-permission apps: {0}" -f (($mtUnverified.ServicePrincipal | Select-Object -First 10) -join ', ')) `
                -WhyItMatters 'Multi-tenant apps from unverified publishers holding high permissions are a common consent-phishing and supply-chain risk.' `
                -RecommendedAction 'Verify the publisher and necessity of each multi-tenant high-permission app; restrict user consent to verified publishers.' -SourceFile $hsrc -ResultRows $mtUnverified
        }
        $nonAdminOwned = @($hardenRows | Where-Object { $_.NonAdminOwner -and -not $_.GuestOwner })
        if ($nonAdminOwned.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Applications' `
                -Title ("{0} over-privileged app(s) owned by a non-privileged or disabled user" -f $nonAdminOwned.Count) `
                -Evidence ("High-permission apps with a non-admin/disabled user owner: {0}" -f (($nonAdminOwned.ServicePrincipal | Select-Object -First 10) -join ', ')) `
                -WhyItMatters 'A non-privileged (or disabled-but-still-owner) user who owns a high-permission app can add a credential to it and act with the app''s application permissions - an indirect privilege-escalation path that bypasses the directory-role model.' `
                -RecommendedAction 'Restrict ownership of high-permission apps to accountable administrators; remove non-privileged and disabled user owners.' -SourceFile $hsrc -ResultRows $nonAdminOwned
        }
    }

    # --- owners (no-owner credentialed app) ---
    $ownerRows = @()
    foreach ($a in $apps) {
        if (@($a.PasswordCredentials).Count -gt 0 -or @($a.KeyCredentials).Count -gt 0) {
            $owners = @(); try { $owners = @(Get-MgApplicationOwner -ApplicationId $a.Id -All -ErrorAction SilentlyContinue) } catch {}
            if ($owners.Count -eq 0) {
                $ownerRows += [pscustomobject]@{ App=$a.DisplayName; AppId=$a.AppId; Note='Orphaned credentialed app' }
            }
        }
    }
    $ownerSrc = Write-Evidence -BaseName 'app_owners' -Rows $ownerRows -Title 'Application Ownership'
    if ($ownerRows.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Applications' `
            -Title ("{0} credentialed application(s) have no owner" -f $ownerRows.Count) `
            -Evidence 'Orphaned apps with live credentials have no accountable owner.' `
            -WhyItMatters 'No-owner apps drift out of governance; nobody is responsible for rotating credentials or reviewing permissions.' `
            -RecommendedAction 'Assign accountable (admin) owners to every credentialed application, or decommission unused apps.' -SourceFile $ownerSrc -ResultRows $ownerRows
    }

    # --- role-assignable groups + non-admin owners ---
    try {
        $raGroups = @(Get-MgGroup -Filter 'isAssignableToRole eq true' -All -ConsistencyLevel eventual -CountVariable c -ErrorAction SilentlyContinue)
        $grows = @()
        foreach ($g in $raGroups) {
            $owners = @(); try { $owners = @(Get-MgGroupOwner -GroupId $g.Id -All -ErrorAction SilentlyContinue) } catch {}
            $grows += [pscustomobject]@{ Group=$g.DisplayName; Owners=(@($owners | ForEach-Object { Get-Ap $_ 'userPrincipalName' }) -join ','); OwnerCount=$owners.Count }
        }
        $gsrc = Write-Evidence -BaseName 'role_assignable_groups' -Rows $grows -Title 'Role-Assignable Groups'
        $owned = @($grows | Where-Object { $_.OwnerCount -gt 0 })
        if ($owned.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Privileged Access' `
                -Title ("{0} role-assignable group(s) have owners who can add members" -f $owned.Count) `
                -Evidence ("Role-assignable groups with owners: {0}" -f (($owned.Group) -join ', ')) `
                -WhyItMatters 'An owner of a role-assignable group can add themselves or others, inheriting the group''s privileged role - a WriteOwner/GenericAll-style escalation path.' `
                -RecommendedAction 'Remove non-administrative owners from role-assignable groups and manage membership through PIM for Groups with approval.' `
                -SourceFile $gsrc -ResultRows $owned
        }
    } catch {}
}

# ===========================================================================
# CHECK 13 - consentgrants (OAuth2 delegated grants)
# ===========================================================================
function Invoke-Check-ConsentGrants {
    $grants = @(Get-MgOauth2PermissionGrant -All -ErrorAction Stop)
    $spById = @{}
    foreach ($g in $grants) {
        foreach ($id in @($g.ClientId, $g.ResourceId)) {
            if ($id -and -not $spById.ContainsKey($id)) {
                try { $spById[$id] = (Get-MgServicePrincipal -ServicePrincipalId $id -ErrorAction SilentlyContinue) } catch {}
            }
        }
    }
    $highScopes = 'Mail\.|Files\.ReadWrite|offline_access|Directory\.ReadWrite|User\.ReadWrite|full_access|Sites\.ReadWrite|Sites\.FullControl'
    $rows = @()
    foreach ($g in $grants) {
        $client = if ($spById.ContainsKey($g.ClientId)) { $spById[$g.ClientId] } else { $null }
        $rows += [pscustomobject]@{
            Client=($client.DisplayName ?? $g.ClientId); ConsentType=$g.ConsentType
            Resource=(($spById[$g.ResourceId]).DisplayName ?? $g.ResourceId); Scope=$g.Scope
            High=($g.Scope -match $highScopes)
        }
    }
    $src = Write-Evidence -BaseName 'oauth_consent_grants' -Rows $rows -Title 'OAuth2 Delegated Consent Grants'

    $tenantWideHigh = @($rows | Where-Object { $_.ConsentType -eq 'AllPrincipals' -and $_.High })
    if ($tenantWideHigh.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'consentgrants' -Category 'Applications' `
            -Title ("{0} tenant-wide OAuth consent grant(s) with high-impact scopes" -f $tenantWideHigh.Count) `
            -Evidence ("Tenant-wide high-scope clients: {0}" -f (($tenantWideHigh.Client | Select-Object -Unique | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'A tenant-wide (AllPrincipals) delegated grant applies to every user persistently and acts as the signed-in user - the dominant phishing-driven data-exfiltration vector in Entra. offline_access lets the token survive a password reset.' `
            -RecommendedAction 'Review every AllPrincipals high-scope grant, revoke those to unrecognised/unverified clients (and revoke sessions), and restrict user consent to break the re-grant loop.' `
            -SourceFile $src -ResultRows $tenantWideHigh
    }
    $userHigh = @($rows | Where-Object { $_.ConsentType -ne 'AllPrincipals' -and $_.High })
    if ($userHigh.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'consentgrants' -Category 'Applications' `
            -Title ("{0} user-consented grant(s) with high-impact scopes" -f $userHigh.Count) `
            -Evidence 'Individual users consented apps to mail/file/directory scopes.' `
            -WhyItMatters 'Targeted consent phishing tricks individual users into granting an app access to their mailbox or files.' `
            -RecommendedAction 'Review per-user high-scope grants for unrecognised apps and restrict user consent to verified publishers / low-impact permissions.' `
            -SourceFile $src -ResultRows $userHigh
    }
    # Admin consent request workflow - if disabled while user consent is permissive,
    # users have no safe path to request apps and may be tempted into risky self-consent.
    try {
        $acr = Get-MgPolicyAdminConsentRequestPolicy -ErrorAction SilentlyContinue
        if ($acr -and -not $acr.IsEnabled) {
            Add-EntraFinding -Severity 'Low' -CheckId 'consentgrants' -Category 'Applications' `
                -Title 'Admin consent request workflow is disabled' `
                -Evidence 'adminConsentRequestPolicy.isEnabled = false.' `
                -WhyItMatters 'Without an admin-consent request workflow, users cannot request approval for apps that need admin consent - which pushes orgs toward leaving user consent permissive (the illicit-consent risk).' `
                -RecommendedAction 'Enable the admin consent request workflow so user consent can be restricted while users still have a governed path to request apps.' -SourceFile $src
        }
    } catch {}

    if ($tenantWideHigh.Count -eq 0 -and $userHigh.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'consentgrants' -Category 'Applications' `
            -Title 'No high-impact OAuth consent grants detected' `
            -Evidence ("{0} delegated grants reviewed; none combine tenant-wide consent with high-impact scopes." -f $rows.Count) `
            -WhyItMatters 'Controlling app consent prevents illicit-consent data exfiltration.' `
            -RecommendedAction 'Keep user consent restricted and review grants periodically.' -SourceFile $src
    }
}

# ===========================================================================
# CHECK 14 - devices
# ===========================================================================
function Invoke-Check-Devices {
    $devices = @(Get-MgDevice -All -Property Id,DisplayName,AccountEnabled,ApproximateLastSignInDateTime,IsManaged,IsCompliant,TrustType,OperatingSystem,OperatingSystemVersion -ErrorAction Stop)
    $cut = (Get-Date).ToUniversalTime().AddDays(-$InactiveDays)
    $rows = $devices | Select-Object DisplayName, AccountEnabled, ApproximateLastSignInDateTime, IsManaged, IsCompliant, TrustType, OperatingSystem, OperatingSystemVersion
    $src = Write-Evidence -BaseName 'devices' -Rows $rows -Title 'Devices'

    $stale = @($devices | Where-Object { -not $_.ApproximateLastSignInDateTime -or $_.ApproximateLastSignInDateTime -lt $cut })
    $unmanaged = @($devices | Where-Object { $_.AccountEnabled -and ($_.IsManaged -eq $false -or $_.IsCompliant -eq $false) })

    if ($stale.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'devices' -Category 'Devices' `
            -Title ("{0} stale device record(s) (no sign-in > {1} days)" -f $stale.Count, $InactiveDays) `
            -Evidence ("Stale device objects: {0}" -f $stale.Count) `
            -WhyItMatters 'Stale device objects inflate the trusted-device footprint and can satisfy device-based Conditional Access long after the device is gone. Mirrors the AD inactive-computer check.' `
            -RecommendedAction 'Remove stale device records on a schedule (e.g. clean up devices inactive over 90 days).' `
            -SourceFile $src -ResultRows @($stale | Select-Object DisplayName,ApproximateLastSignInDateTime,TrustType | Select-Object -First 100)
    }
    if ($unmanaged.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'devices' -Category 'Devices' `
            -Title ("{0} enabled device(s) are unmanaged or non-compliant" -f $unmanaged.Count) `
            -Evidence ("Unmanaged/non-compliant enabled devices: {0}" -f $unmanaged.Count) `
            -WhyItMatters 'Unmanaged or non-compliant devices accessing corporate resources are Conditional-Access bypass surface, especially BYOD (Workplace) registrations.' `
            -RecommendedAction 'Require device compliance via Conditional Access and scrutinise BYOD devices accessing sensitive resources.' `
            -SourceFile $src -ResultRows @($unmanaged | Select-Object DisplayName,IsManaged,IsCompliant,TrustType | Select-Object -First 100)
    }
    if ($stale.Count -eq 0 -and $unmanaged.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'devices' -Category 'Devices' `
            -Title ("{0} device(s) reviewed - no stale or unmanaged devices flagged" -f $devices.Count) `
            -Evidence 'Device hygiene within thresholds.' -WhyItMatters 'Healthy device inventory supports device-based Conditional Access.' `
            -RecommendedAction 'Maintain device lifecycle cleanup and compliance policies.' -SourceFile $src
    }
}

# ===========================================================================
# CHECK 15 - trusts (cross-tenant access)
# ===========================================================================
function Invoke-Check-Trusts {
    $def = $null; try { $def = Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction Stop } catch {}
    $partners = @(); try { $partners = @(Get-MgPolicyCrossTenantAccessPolicyPartner -All -ErrorAction SilentlyContinue) } catch {}

    $rows = @()
    if ($def) {
        $rows += [pscustomobject]@{ Scope='Default'; Setting='B2B collaboration inbound'; Value=($def.B2bCollaborationInbound.UsersAndGroups.AccessType) }
        $rows += [pscustomobject]@{ Scope='Default'; Setting='Inbound trust: MFA accepted'; Value=($def.InboundTrust.IsMfaAccepted) }
        $rows += [pscustomobject]@{ Scope='Default'; Setting='Inbound trust: compliant device accepted'; Value=($def.InboundTrust.IsCompliantDeviceAccepted) }
        $rows += [pscustomobject]@{ Scope='Default'; Setting='Automatic inbound user consent'; Value=($def.AutomaticUserConsentSettings.InboundAllowed) }
    }
    foreach ($p in $partners) {
        $rows += [pscustomobject]@{ Scope=("Partner " + $p.TenantId); Setting='InboundTrust MFA accepted'; Value=($p.InboundTrust.IsMfaAccepted) }
    }
    $src = Write-Evidence -BaseName 'cross_tenant_access' -Rows $rows -Title 'Cross-Tenant Access & B2B Trust'

    if ($def -and $def.InboundTrust.IsMfaAccepted -and $partners.Count -eq 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'trusts' -Category 'External Access' `
            -Title 'Default cross-tenant policy trusts external MFA claims for all tenants' `
            -Evidence 'InboundTrust.IsMfaAccepted = true on the default (all tenants) policy with no per-partner overrides.' `
            -WhyItMatters 'Trusting MFA claims from arbitrary external tenants lets their posture decisions satisfy your MFA requirement, weakening Conditional Access for guests.' `
            -RecommendedAction 'Scope inbound MFA/compliance trust to named partner tenants rather than trusting all tenants by default.' -SourceFile $src
    }
    if ($def -and $def.AutomaticUserConsentSettings.InboundAllowed) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'trusts' -Category 'External Access' `
            -Title 'Automatic inbound guest redemption is enabled by default' `
            -Evidence 'AutomaticUserConsentSettings.InboundAllowed = true (default).' `
            -WhyItMatters 'Auto-redemption removes the consent step for external users, broadening cross-tenant access without explicit approval.' `
            -RecommendedAction 'Restrict automatic redemption to specific trusted partner tenants.' -SourceFile $src
    }
    if (-not $def -and $partners.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'trusts' -Category 'External Access' `
            -Title 'Cross-tenant access policy not assessed' `
            -Evidence 'No cross-tenant access policy returned (may be default configuration or missing scope).' `
            -WhyItMatters 'Cross-tenant access governs B2B trust with other tenants.' `
            -RecommendedAction 'Review cross-tenant access settings in the Entra portal.' -SourceFile $src
    } elseif ($script:Findings.Where({$_.CheckId -eq 'trusts'}).Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'trusts' -Category 'External Access' `
            -Title 'Cross-tenant access settings reviewed' `
            -Evidence 'No broad external-trust settings flagged.' -WhyItMatters 'Scoped external trust limits exposure to other tenants.' `
            -RecommendedAction 'Keep external trust scoped to named partners.' -SourceFile $src
    }
}

# ===========================================================================
# CHECK 16 - recentchanges
# ===========================================================================
function Invoke-Check-RecentChanges {
    $since = (Get-Date).ToUniversalTime().AddDays(-$RecentChangeDays)
    $sinceStr = $since.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $newUsers = @(Get-MgUser -Filter "createdDateTime ge $sinceStr" -All -ConsistencyLevel eventual -CountVariable c -Property Id,UserPrincipalName,CreatedDateTime,UserType,AccountEnabled -ErrorAction Stop)
    $newGroups = @(); try { $newGroups = @(Get-MgGroup -Filter "createdDateTime ge $sinceStr" -All -ConsistencyLevel eventual -CountVariable c2 -Property Id,DisplayName,CreatedDateTime -ErrorAction SilentlyContinue) } catch {}

    $rows = @()
    $rows += $newUsers | Select-Object @{n='Type';e={'User'}}, @{n='Name';e={$_.UserPrincipalName}}, CreatedDateTime, @{n='Enabled';e={$_.AccountEnabled}}
    $rows += $newGroups | Select-Object @{n='Type';e={'Group'}}, @{n='Name';e={$_.DisplayName}}, CreatedDateTime, @{n='Enabled';e={''}}
    $src = Write-Evidence -BaseName 'recent_changes' -Rows $rows -Title ("Recently Created Users / Groups (last {0} days)" -f $RecentChangeDays)

    # role assignment changes from directory audit
    $roleChanges = @()
    try {
        $roleChanges = @(Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $sinceStr and category eq 'RoleManagement'" -All -ErrorAction SilentlyContinue)
    } catch {}
    if ($roleChanges.Count -gt 0) {
        $rcrows = $roleChanges | Select-Object ActivityDateTime, ActivityDisplayName,
            @{n='Initiator';e={ $_.InitiatedBy.User.UserPrincipalName }},
            @{n='Target';e={ ($_.TargetResources.UserPrincipalName -join ',') }}
        Write-Evidence -BaseName 'recent_role_changes' -Rows $rcrows -Title 'Recent Role-Management Changes' | Out-Null
        Add-EntraFinding -Severity 'Medium' -CheckId 'recentchanges' -Category 'Change Monitoring' `
            -Title ("{0} role-management change(s) in the last {1} days" -f $roleChanges.Count, $RecentChangeDays) `
            -Evidence 'Privileged role assignments/removals occurred recently and should be verified against change records.' `
            -WhyItMatters 'New role grants in the recent window are where rogue-admin or compromised-provisioning activity first appears. Direct equivalent of the AD recent-changes review.' `
            -RecommendedAction 'Verify each recent role change against an approved change record and investigate any unexpected initiator.' `
            -SourceFile $src -ResultRows @($rcrows | Select-Object -First 50)
    }
    Add-EntraFinding -Severity 'Information' -CheckId 'recentchanges' -Category 'Change Monitoring' `
        -Title ("{0} user(s) and {1} group(s) created in the last {2} days" -f $newUsers.Count, $newGroups.Count, $RecentChangeDays) `
        -Evidence ("New users: {0}; new groups: {1}." -f $newUsers.Count, $newGroups.Count) `
        -WhyItMatters 'New principals should correspond to approved onboarding; unexpected creations can indicate rogue provisioning.' `
        -RecommendedAction 'Spot-check recently created principals against HR/onboarding records.' -SourceFile $src -ResultRows $rows
}

# ===========================================================================
# CHECK 17 - tenanthealth (directory sync / PHS)
# ===========================================================================
function Invoke-Check-TenantHealth {
    if (-not $script:Tenant) { try { $script:Tenant = Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {} }
    $org = $script:Tenant
    $sync = $null; try { $sync = Get-MgDirectoryOnPremiseSynchronization -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}

    $rows = @()
    if ($org) {
        $rows += [pscustomobject]@{ Property='OnPremisesSyncEnabled'; Value=$org.OnPremisesSyncEnabled }
        $rows += [pscustomobject]@{ Property='OnPremisesLastSyncDateTime'; Value=$org.OnPremisesLastSyncDateTime }
    }
    if ($sync) {
        $rows += [pscustomobject]@{ Property='PasswordSyncEnabled'; Value=$sync.Features.PasswordSyncEnabled }
        $rows += [pscustomobject]@{ Property='BlockSoftMatchEnabled'; Value=$sync.Features.BlockSoftMatchEnabled }
        $rows += [pscustomobject]@{ Property='CloudPasswordPolicyForPasswordSyncedUsers'; Value=$sync.Features.CloudPasswordPolicyForPasswordSyncedUsersEnabled }
    }
    $src = Write-Evidence -BaseName 'tenant_health' -Rows $rows -Title 'Directory-Sync / PHS Platform Health'

    if (-not $org -or -not $org.OnPremisesSyncEnabled) {
        Add-EntraFinding -Severity 'Information' -CheckId 'tenanthealth' -Category 'Platform Health' `
            -Title 'Tenant is cloud-only (no on-prem directory sync)' `
            -Evidence 'OnPremisesSyncEnabled is false/absent.' `
            -WhyItMatters 'Cloud-only tenants have no hybrid sync backbone to monitor; this is expected and not an error.' `
            -RecommendedAction 'No action.' -SourceFile $src
        return
    }
    if ($org.OnPremisesLastSyncDateTime -and $org.OnPremisesLastSyncDateTime -lt (Get-Date).ToUniversalTime().AddHours(-3)) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'tenanthealth' -Category 'Platform Health' `
            -Title 'Directory synchronisation is stale (> 3 hours)' `
            -Evidence ("Last sync: {0}" -f $org.OnPremisesLastSyncDateTime) `
            -WhyItMatters 'Stale sync leaves deprovisioned on-prem accounts active in the cloud and delays propagation of disables/lockouts. The hybrid analog of AD replication health.' `
            -RecommendedAction 'Investigate Entra Connect health; restore a healthy 30-minute sync cadence.' -SourceFile $src
    }
    if ($sync -and -not $sync.Features.PasswordSyncEnabled) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'tenanthealth' -Category 'Platform Health' `
            -Title 'Password Hash Sync is disabled' `
            -Evidence 'PasswordSyncEnabled = false on a synced tenant.' `
            -WhyItMatters 'Without PHS there is no leaked-credential detection and no auth fallback if federation fails.' `
            -RecommendedAction 'Enable Password Hash Sync (at minimum for leaked-credential detection) even when using federation or PTA.' -SourceFile $src
    }
    if ($sync -and -not $sync.Features.BlockSoftMatchEnabled) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'tenanthealth' -Category 'Platform Health' `
            -Title 'Soft-match is not blocked' `
            -Evidence 'BlockSoftMatchEnabled = false.' `
            -WhyItMatters 'Soft-matching can be abused to hijack a cloud object by matching a crafted on-prem object on proxyAddresses/UPN.' `
            -RecommendedAction 'Enable BlockSoftMatch once initial matching is complete.' -SourceFile $src
    }
    if ($script:Findings.Where({$_.CheckId -eq 'tenanthealth'}).Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'tenanthealth' -Category 'Platform Health' `
            -Title 'Hybrid directory sync health within thresholds' `
            -Evidence 'Sync recent; PHS and soft-match protections enabled.' -WhyItMatters 'Healthy sync is the hybrid identity backbone.' `
            -RecommendedAction 'Maintain Entra Connect health monitoring.' -SourceFile $src
    }
}

# ===========================================================================
# Shared privileged-assignment cache (used by the access-path / break-glass checks)
# ===========================================================================
function Get-EAPrivAssignments {
    if ($null -ne $script:PrivAssignments) { return $script:PrivAssignments }
    Get-EARoleDefMap | Out-Null
    try { Get-EAUsers | Out-Null } catch {}
    $list = New-Object System.Collections.Generic.List[object]

    function _Add($a, $state) {
        $rd = $script:RoleDefById[$a.RoleDefinitionId]
        $tmpl = if ($rd) { $rd.TemplateId } else { [string]$a.RoleDefinitionId }
        $name = if ($rd) { $rd.DisplayName } else { [string]$a.RoleDefinitionId }
        $p = $a.Principal
        $id = if ($a.PrincipalId) { $a.PrincipalId } elseif ($p) { $p.Id } else { $null }
        $odt = Get-Ap $p '@odata.type'
        $upn = Get-Ap $p 'userPrincipalName'
        $pname = Get-Ap $p 'displayName'
        if (-not $upn -and $id -and $script:UserById.ContainsKey($id)) { $upn = $script:UserById[$id].UserPrincipalName }
        $ptype = if ($odt) { ($odt -replace '#microsoft.graph.','') } elseif ($upn) { 'user' } elseif ($id -and $script:UserById.ContainsKey($id)) { 'user' } else { 'group/sp' }
        $list.Add([pscustomobject]@{
            PrincipalId=$id; PrincipalType=$ptype; PrincipalUpn=$upn; PrincipalName=$pname
            RoleTemplateId=$tmpl; RoleName=$name; State=$state
            IsPrivileged=$script:PrivilegedRoleTemplates.ContainsKey($tmpl); IsGA=($tmpl -eq $script:GlobalAdminTemplateId)
        }) | Out-Null
    }

    $active = @()
    try { $active += @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop) } catch {}
    if ($active.Count -eq 0) { try { $active += @(Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction SilentlyContinue) } catch {} }
    foreach ($a in $active) { _Add $a 'Active' }
    try { foreach ($a in @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal -ErrorAction SilentlyContinue)) { _Add $a 'Eligible' } } catch {}

    $script:PrivAssignments = $list
    return $list
}

# ===========================================================================
# CHECK 18 - pimpolicies (PIM role-management policy quality)
# ===========================================================================
function Invoke-Check-PimPolicies {
    Get-EARoleDefMap | Out-Null
    # scopeType for Entra directory-role policies is 'DirectoryRole' on most tenants but
    # 'Directory' on some - try the documented value first, fall back to the other.
    function _FetchPim([string]$scopeType) {
        $u = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq '$scopeType'&`$expand=policy(`$expand=rules)"
        $acc = @(); $g = 0
        while ($u -and $g -lt 50) {
            $r = Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop
            if ($r['value']) { $acc += @($r['value']) }
            $u = $r['@odata.nextLink']; $g++
        }
        return $acc
    }
    $scopeUsed = 'DirectoryRole'
    $assignments = @(_FetchPim 'DirectoryRole')
    if ($assignments.Count -eq 0) { $scopeUsed = 'Directory'; $assignments = @(_FetchPim 'Directory') }

    $rows = @()
    $noMfaCrit = @(); $noMfaHigh = @(); $noJust = @(); $noApproval = @(); $longDur = @(); $permActiveRoles = @(); $permEligRoles = @()

    foreach ($pa in $assignments) {
        $rdId = [string]$pa['roleDefinitionId']
        if (-not $script:PrivilegedRoleTemplates.ContainsKey($rdId)) { continue }
        $roleName = $script:PrivilegedRoleTemplates[$rdId]
        $isGAorPRA = ($rdId -eq $script:GlobalAdminTemplateId -or $roleName -match 'Privileged Role Administrator|Privileged Authentication')

        $rules = @()
        if ($pa['policy'] -and $pa['policy']['rules']) { $rules = @($pa['policy']['rules']) }
        $mfa = $null; $just = $null; $appr = $null; $maxH = $null; $permA = $null; $permE = $null
        foreach ($r in $rules) {
            $rid = [string]$r['id']
            switch -Regex ($rid) {
                'Enablement_EndUser_Assignment' { $en = @($r['enabledRules']); $mfa = ($en -contains 'MultiFactorAuthentication'); $just = ($en -contains 'Justification') }
                'Approval_EndUser_Assignment'   { if ($r['setting']) { $appr = [bool]$r['setting']['isApprovalRequired'] } }
                'Expiration_EndUser_Assignment' {
                    $d = [string]$r['maximumDuration']
                    if ($d -match 'PT(\d+)H') { $maxH = [int]$matches[1] } elseif ($d -match 'PT(\d+)M') { $maxH = [math]::Round(([int]$matches[1]/60),1) }
                }
                'Expiration_Admin_Assignment'   { if ($r.ContainsKey('isExpirationRequired')) { $permA = (-not [bool]$r['isExpirationRequired']) } }
                'Expiration_Admin_Eligibility'  { if ($r.ContainsKey('isExpirationRequired')) { $permE = (-not [bool]$r['isExpirationRequired']) } }
            }
        }
        $rows += [pscustomobject]@{ Role=$roleName; MfaOnActivation=$mfa; JustificationRequired=$just; ApprovalRequired=$appr; MaxActivationHours=$maxH; PermanentActiveAllowed=$permA; PermanentEligibleAllowed=$permE }

        if ($mfa -eq $false) { if ($isGAorPRA) { $noMfaCrit += $roleName } else { $noMfaHigh += $roleName } }
        if ($isGAorPRA -and $just -eq $false) { $noJust += $roleName }
        if ($isGAorPRA -and $appr -eq $false) { $noApproval += $roleName }
        if ($maxH -and $maxH -gt 8) { $longDur += ("{0} ({1}h)" -f $roleName, $maxH) }
        if ($permA -eq $true) { $permActiveRoles += $roleName }
        if ($permE -eq $true) { $permEligRoles += $roleName }
    }
    $src = Write-Evidence -BaseName 'pim_policies' -Rows $rows -Title 'PIM Role-Management Policy Rules (privileged roles)' -Notes @("Policy scopeType used: $scopeUsed")

    if ($rows.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title 'PIM role-management policies not assessed' `
            -Evidence 'No privileged-role PIM policies returned (requires Entra ID P2 and RoleManagementPolicy.Read.Directory).' `
            -WhyItMatters 'PIM activation policy rules (MFA on activation, approval, justification, max duration, permanent-allowed) are the controls that make eligible access safe.' `
            -RecommendedAction 'License Entra ID P2 and grant RoleManagementPolicy.Read.Directory to assess PIM policy quality.' -SourceFile $src
        return
    }
    if ($noMfaCrit.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} top-tier role(s) can be PIM-activated WITHOUT MFA" -f $noMfaCrit.Count) `
            -Evidence ("Roles allowing activation without MFA: {0}" -f ($noMfaCrit -join ', ')) `
            -WhyItMatters 'If Global Administrator / Privileged Role Administrator can be activated without MFA, a stolen password alone yields tenant-takeover privilege - PIM provides no real barrier.' `
            -RecommendedAction 'Edit the PIM policy for these roles to require MFA (preferably phishing-resistant authentication strength) on activation.' -SourceFile $src
    }
    if ($noMfaHigh.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} privileged role(s) can be PIM-activated without MFA" -f $noMfaHigh.Count) `
            -Evidence ("Roles allowing activation without MFA: {0}" -f ($noMfaHigh -join ', ')) `
            -WhyItMatters 'Activating a privileged role without MFA lets a compromised password reach admin access.' `
            -RecommendedAction 'Require MFA on activation for every privileged role in PIM.' -SourceFile $src
    }
    if ($noApproval.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} top-tier role(s) require no approval to activate" -f $noApproval.Count) `
            -Evidence ("Roles without activation approval: {0}" -f ($noApproval -join ', ')) `
            -WhyItMatters 'Without approval, a single compromised eligible account can self-elevate to Global Admin unobserved.' `
            -RecommendedAction 'Require approval for activation of the most sensitive roles (GA / Privileged Role Admin).' -SourceFile $src
    }
    if ($noJust.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} top-tier role(s) require no justification to activate" -f $noJust.Count) `
            -Evidence ("Roles without justification: {0}" -f ($noJust -join ', ')) `
            -WhyItMatters 'Justification provides an audit trail of why privilege was used; its absence weakens accountability.' `
            -RecommendedAction 'Require justification on activation for sensitive roles.' -SourceFile $src
    }
    if ($longDur.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} privileged role(s) allow activation longer than 8 hours" -f $longDur.Count) `
            -Evidence ("Long activation windows: {0}" -f ($longDur -join ', ')) `
            -WhyItMatters 'Long activation windows widen the time an elevated session can be abused if the device or token is compromised.' `
            -RecommendedAction 'Reduce maximum activation duration to <=8 hours for privileged roles.' -SourceFile $src
    }
    if ($permActiveRoles.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} privileged role(s) permit permanent ACTIVE assignment" -f $permActiveRoles.Count) `
            -Evidence ("Roles allowing permanent active assignment: {0}" -f ($permActiveRoles -join ', ')) `
            -WhyItMatters 'Allowing permanent active assignment defeats the just-in-time model - admins can hold standing privilege despite PIM being configured.' `
            -RecommendedAction 'Set the PIM policy to require expiration on active assignments (force eligible/JIT instead of permanent active).' -SourceFile $src
    }
    if ($permEligRoles.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} privileged role(s) permit permanent ELIGIBLE assignment without review" -f $permEligRoles.Count) `
            -Evidence ("Roles allowing permanent eligible assignment: {0}" -f ($permEligRoles -join ', ')) `
            -WhyItMatters 'Permanent eligibility without periodic review lets stale eligibility accumulate over time.' `
            -RecommendedAction 'Require expiration/renewal on eligible assignments and pair with access reviews.' -SourceFile $src
    }
    if ($script:Findings.Where({$_.CheckId -eq 'pimpolicies'}).Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title 'PIM activation policies enforce MFA / approval / time limits' `
            -Evidence ("{0} privileged role policy/policies reviewed - no weak activation controls found." -f $rows.Count) `
            -WhyItMatters 'Strong PIM activation policies make eligible (JIT) privileged access safe.' `
            -RecommendedAction 'Maintain MFA-on-activation, approval for top-tier roles, and short activation windows.' -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 19 - breakglass (emergency-access account health)
# ===========================================================================
function Invoke-Check-BreakGlass {
    $users = Get-EAUsers
    $byUpn = @{}; foreach ($u in $users) { if ($u.UserPrincipalName) { $byUpn[$u.UserPrincipalName.ToLowerInvariant()] = $u } }

    # current Global Administrators
    $gaIds = @{}
    foreach ($a in (Get-EAPrivAssignments)) { if ($a.IsGA -and $a.State -eq 'Active' -and $a.PrincipalId) { $gaIds[$a.PrincipalId] = $true } }

    $bg = Normalize-StringList -Values $BreakGlassUpns

    if ($bg.Count -eq 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'breakglass' -Category 'Privileged Access' `
            -Title 'No emergency-access (break-glass) accounts have been designated for validation' `
            -Evidence 'Run with -BreakGlassUpns "bg1@tenant.onmicrosoft.com;bg2@tenant.onmicrosoft.com" so the script can validate them.' `
            -WhyItMatters 'Microsoft recommends two cloud-only emergency-access Global Admins, excluded from Conditional Access, to avoid total lockout if MFA/federation/PIM breaks. Without designated accounts this control cannot be validated.' `
            -RecommendedAction 'Create two cloud-only break-glass Global Admin accounts on the .onmicrosoft.com domain, exclude them from CA lockout policies, store credentials offline, monitor their sign-ins, and re-run with -BreakGlassUpns.' -SourceFile $null
        return
    }
    if ($bg.Count -lt 2) {
        Add-EntraFinding -Severity 'Critical' -CheckId 'breakglass' -Category 'Privileged Access' `
            -Title 'Fewer than two emergency-access accounts configured' `
            -Evidence ("Only {0} break-glass account designated." -f $bg.Count) `
            -WhyItMatters 'A single emergency-access account is a single point of failure; if it is lost or locked out, recovery from a tenant-wide lockout may be impossible.' `
            -RecommendedAction 'Maintain at least two cloud-only break-glass Global Admin accounts.' -SourceFile $null
    }

    $rows = @()
    foreach ($upn in $bg) {
        $u = $byUpn[$upn.ToLowerInvariant()]
        if (-not $u) {
            Add-EntraFinding -Severity 'High' -CheckId 'breakglass' -Category 'Privileged Access' `
                -Title ("Designated break-glass account not found: {0}" -f $upn) `
                -Evidence 'The UPN passed to -BreakGlassUpns does not resolve to a user.' `
                -WhyItMatters 'A misconfigured emergency-access reference means the account you think protects you may not exist.' `
                -RecommendedAction 'Verify the break-glass UPN is correct and the account exists.' -SourceFile $null
            continue
        }
        $isGA      = [bool]($u.Id -and $gaIds.ContainsKey($u.Id))
        $cloudOnly = -not [bool]$u.OnPremisesSyncEnabled
        $onmsft    = ($u.UserPrincipalName -like '*.onmicrosoft.com')
        $licensed  = (@($u.AssignedLicenses).Count -gt 0)
        $lastSucc  = $null
        if ($u.SignInActivity -and $u.SignInActivity.LastSuccessfulSignInDateTime) { $lastSucc = [datetime]$u.SignInActivity.LastSuccessfulSignInDateTime }
        $rows += [pscustomobject]@{ Account=$u.UserPrincipalName; GlobalAdmin=$isGA; CloudOnly=$cloudOnly; OnMicrosoftDomain=$onmsft; Licensed=$licensed; LastSuccessfulSignIn=$lastSucc }

        if (-not $isGA) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'breakglass' -Category 'Privileged Access' `
                -Title ("Break-glass account is not a permanent Global Administrator: {0}" -f $u.UserPrincipalName) `
                -Evidence 'The emergency-access account does not currently hold an active Global Administrator role.' `
                -WhyItMatters 'A break-glass account must have standing Global Admin so it can recover the tenant when all other access fails.' `
                -RecommendedAction 'Assign permanent Global Administrator to the break-glass account.' -SourceFile $null -AffectedPrincipal $u.UserPrincipalName
        }
        if (-not $cloudOnly) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'breakglass' -Category 'Privileged Access' `
                -Title ("Break-glass account is synced/federated, not cloud-only: {0}" -f $u.UserPrincipalName) `
                -Evidence 'onPremisesSyncEnabled is true on the emergency-access account.' `
                -WhyItMatters 'A synced/federated break-glass account depends on on-prem AD / federation - exactly the systems that may be down during an emergency.' `
                -RecommendedAction 'Recreate the break-glass account as a cloud-only account.' -SourceFile $null -AffectedPrincipal $u.UserPrincipalName
        }
        if (-not $onmsft) {
            Add-EntraFinding -Severity 'High' -CheckId 'breakglass' -Category 'Privileged Access' `
                -Title ("Break-glass account does not use the .onmicrosoft.com domain: {0}" -f $u.UserPrincipalName) `
                -Evidence 'Emergency-access accounts should use the tenant .onmicrosoft.com domain to avoid dependency on custom/federated domains.' `
                -WhyItMatters 'A custom or federated domain can become unavailable; the .onmicrosoft.com domain is always present and cloud-resolved.' `
                -RecommendedAction 'Use a UPN on the tenant .onmicrosoft.com domain for break-glass accounts.' -SourceFile $null -AffectedPrincipal $u.UserPrincipalName
        }
        if ($null -eq $lastSucc -or $lastSucc -lt (Get-Date).ToUniversalTime().AddDays(-90)) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'breakglass' -Category 'Privileged Access' `
                -Title ("Break-glass account has no successful sign-in in 90 days: {0}" -f $u.UserPrincipalName) `
                -Evidence ("Last successful sign-in: {0}" -f ($lastSucc ?? 'never / unknown')) `
                -WhyItMatters 'Emergency-access accounts must be periodically tested so you know they work and that alerting fires before a real emergency.' `
                -RecommendedAction "Perform a documented emergency-access test: verify sign-in succeeds, verify alerting fires, and record the test date and owner." -SourceFile $null -AffectedPrincipal $u.UserPrincipalName
        }
        if ($licensed) {
            Add-EntraFinding -Severity 'Low' -CheckId 'breakglass' -Category 'Privileged Access' `
                -Title ("Break-glass account is licensed like a normal user: {0}" -f $u.UserPrincipalName) `
                -Evidence 'Emergency-access accounts should carry minimal licensing.' `
                -WhyItMatters 'Excess licensing on a break-glass account increases its footprint and exposure.' `
                -RecommendedAction 'Keep break-glass licensing to the minimum required for sign-in and logging.' -SourceFile $null -AffectedPrincipal $u.UserPrincipalName
        }
    }
    $src = Write-Evidence -BaseName 'break_glass' -Rows $rows -Title 'Emergency-Access (Break-Glass) Account Health'
    if ($script:Findings.Where({$_.CheckId -eq 'breakglass'}).Count -eq 0 -and $rows.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'breakglass' -Category 'Privileged Access' `
            -Title 'Break-glass accounts meet the emergency-access baseline' `
            -Evidence ("{0} cloud-only Global Admin emergency-access account(s) validated." -f $rows.Count) `
            -WhyItMatters 'Healthy emergency-access accounts prevent tenant lockout.' `
            -RecommendedAction 'Continue periodic documented break-glass tests and monitor their sign-ins.' -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 20 - authmethodpolicy (tenant authentication-method policy)
# ===========================================================================
function Invoke-Check-AuthMethodPolicy {
    $pol = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
    $configs = @($pol.AuthenticationMethodConfigurations)
    $rows = $configs | Select-Object Id, State
    $src = Write-Evidence -BaseName 'auth_method_policy' -Rows $rows -Title 'Authentication Methods Policy'

    function _State([string]$id) { ($configs | Where-Object { $_.Id -eq $id } | Select-Object -First 1).State }

    $smsOn   = ((_State 'Sms')   -eq 'enabled')
    $voiceOn = ((_State 'Voice') -eq 'enabled')
    $fido2On = ((_State 'Fido2') -eq 'enabled')
    $whfbOn  = ((_State 'WindowsHelloForBusiness') -eq 'enabled')
    $tapOn   = ((_State 'TemporaryAccessPass') -eq 'enabled')

    if ($smsOn -or $voiceOn) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Phishable authentication methods (SMS / voice) are enabled tenant-wide' `
            -Evidence ("SMS enabled: {0}; Voice enabled: {1}" -f $smsOn, $voiceOn) `
            -WhyItMatters 'SMS and voice are phishable and SIM-swappable. Allowing them as MFA methods keeps a weak factor available to attackers.' `
            -RecommendedAction 'Phase out SMS/voice in favour of phishing-resistant methods (FIDO2/passkeys, Windows Hello) and limit their use via authentication strengths.' -SourceFile $src
    }
    if (-not ($fido2On -or $whfbOn)) {
        Add-EntraFinding -Severity 'Low' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'No phishing-resistant method (FIDO2 / Windows Hello) is enabled' `
            -Evidence 'Neither FIDO2 nor Windows Hello for Business is enabled in the authentication methods policy.' `
            -WhyItMatters 'Phishing-resistant authentication is the strongest defence for privileged accounts; if it is not enabled, admins cannot register it.' `
            -RecommendedAction 'Enable FIDO2 security keys / passkeys and Windows Hello for Business and require them for privileged users.' -SourceFile $src
    }
    if ($tapOn) {
        $tap = $configs | Where-Object { $_.Id -eq 'TemporaryAccessPass' } | Select-Object -First 1
        $oneTime = $true
        try { if ($tap.AdditionalProperties -and $tap.AdditionalProperties.ContainsKey('isUsableOnce')) { $oneTime = [bool]$tap.AdditionalProperties['isUsableOnce'] } } catch {}
        if (-not $oneTime) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title 'Temporary Access Pass is enabled and reusable (not one-time)' `
                -Evidence 'TAP is configured as reusable rather than one-time use.' `
                -WhyItMatters 'A reusable Temporary Access Pass is a long-lived bypass credential that can be abused if intercepted.' `
                -RecommendedAction 'Configure Temporary Access Pass as one-time use with a short lifetime.' -SourceFile $src
        }
    }
    if ($script:Findings.Where({$_.CheckId -eq 'authmethodpolicy'}).Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Authentication methods policy reviewed' `
            -Evidence ("Phishing-resistant enabled: FIDO2={0}, WHfB={1}; SMS={2}, Voice={3}." -f $fido2On,$whfbOn,$smsOn,$voiceOn) `
            -WhyItMatters 'The method policy decides which factors users can register and use.' `
            -RecommendedAction 'Prefer phishing-resistant methods; minimise SMS/voice.' -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 21 - accesspaths (effective-access / attack-path correlation)
# ===========================================================================
function Invoke-Check-AccessPaths {
    $assignments = Get-EAPrivAssignments
    try { Get-EAUsers | Out-Null } catch {}

    # Direct (user) privileged assignments, tracking activation state (Active wins).
    $directKey = @{}   # "userId|roleTemplateId" -> 'Active' | 'Eligible'
    foreach ($a in $assignments) {
        if ($a.IsPrivileged -and $a.PrincipalType -eq 'user' -and $a.PrincipalId) {
            $k = '{0}|{1}' -f $a.PrincipalId, $a.RoleTemplateId
            if ($a.State -eq 'Active' -or -not $directKey.ContainsKey($k)) { $directKey[$k] = $a.State }
        }
    }

    # Group-based privileged assignments -> expand to user members (carrying the group's state).
    $groupAssign = @($assignments | Where-Object { $_.IsPrivileged -and $_.PrincipalType -eq 'group' -and $_.PrincipalId })
    $pathByUserRole = @{}     # "userId|roleTemplateId" -> list of @{Group;State}
    $hiddenGaps = @()
    foreach ($g in $groupAssign) {
        $members = @()
        try { $members = @(Get-MgGroupTransitiveMember -GroupId $g.PrincipalId -All -ErrorAction Stop) } catch {
            $hiddenGaps += ($g.PrincipalName ?? $g.PrincipalId); continue
        }
        foreach ($m in $members) {
            $mid = $m.Id
            $mtype = [string](Get-Ap $m '@odata.type')
            $upn = Get-Ap $m 'userPrincipalName'
            if (-not $upn -and $mtype -ne '#microsoft.graph.user') { continue }   # count only user members (incl. UPN-less user objects)
            $key = '{0}|{1}' -f $mid, $g.RoleTemplateId
            if (-not $pathByUserRole.ContainsKey($key)) { $pathByUserRole[$key] = New-Object System.Collections.Generic.List[object] }
            $pathByUserRole[$key].Add([pscustomobject]@{ Group=($g.PrincipalName ?? 'group'); State=$g.State }) | Out-Null
        }
    }

    # Duplicate / parallel paths, classified by activation model: a duplicate that
    # involves an ACTIVE (standing) path is more serious than eligible-only duplication.
    $dupRows = @()
    foreach ($key in $pathByUserRole.Keys) {
        $paths = @($pathByUserRole[$key])
        $groups = @($paths.Group | Select-Object -Unique)
        $parts = $key -split '\|', 2; $uid = $parts[0]; $rtid = $parts[1]
        $directS = if ($directKey.ContainsKey($key)) { $directKey[$key] } else { $null }
        $pathCount = $groups.Count + [int]([bool]$directS)
        if ($pathCount -le 1) { continue }
        $involvesActive = ($directS -eq 'Active') -or (@($paths | Where-Object { $_.State -eq 'Active' }).Count -gt 0)
        $activationModel = if ($involvesActive) { 'Active path' } else { 'Eligible-only' }
        $upn = if ($script:UserById.ContainsKey($uid)) { $script:UserById[$uid].UserPrincipalName } else { $uid }
        $dupRows += [pscustomobject]@{
            User=$upn; Role=$script:PrivilegedRoleTemplates[$rtid]; ViaGroups=($groups -join ', ')
            AlsoDirect=[bool]$directS; DirectState=$directS; ActivationModel=$activationModel; PathCount=$pathCount
        }
    }
    $src = Write-Evidence -BaseName 'access_paths' -Rows $dupRows -Title 'Effective Access - Duplicate / Parallel Privileged Paths'
    $dupActive = @($dupRows | Where-Object { $_.ActivationModel -eq 'Active path' })
    $dupElig   = @($dupRows | Where-Object { $_.ActivationModel -ne 'Active path' })
    if ($dupActive.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ("{0} user-role pair(s) reach the same privileged role via multiple ACTIVE paths" -f $dupActive.Count) `
            -Evidence ("Standing parallel privilege paths (multiple active groups, or active direct + group): {0}" -f (($dupActive | Select-Object -First 8 | ForEach-Object { "$($_.User)->$($_.Role)" }) -join '; ')) `
            -WhyItMatters 'When a user holds the same privileged role through more than one active path, removing one assignment does not remove the privilege. Standing parallel paths hide access and frustrate clean de-provisioning ("parallel movement").' `
            -RecommendedAction 'Consolidate each privileged role to a single, reviewed path per user; remove redundant active grants and prefer a single PIM-eligible assignment.' `
            -SourceFile $src -ResultRows $dupActive
    }
    if ($dupElig.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ("{0} user-role pair(s) are eligible for the same privileged role via multiple paths" -f $dupElig.Count) `
            -Evidence ("Eligible-only parallel paths (multiple eligible groups): {0}" -f (($dupElig | Select-Object -First 8 | ForEach-Object { "$($_.User)->$($_.Role)" }) -join '; ')) `
            -WhyItMatters 'Multiple eligible paths to the same role complicate review and de-provisioning even though access is just-in-time. Lower severity than standing duplication, but still worth consolidating.' `
            -RecommendedAction 'Consolidate eligible assignments to a single reviewed path per user/role.' `
            -SourceFile $src -ResultRows $dupElig
    }

    # "Already privileged" = the full effective set: direct privileged users PLUS every
    # user reachable to a privileged role via a group. An owner who is already privileged
    # this way is not gaining anything new, so we don't flag them as an escalation path.
    $allPrivUserIds = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in $directKey.Keys) { [void]$allPrivUserIds.Add((($k -split '\|', 2)[0])) }
    foreach ($key in $pathByUserRole.Keys) { [void]$allPrivUserIds.Add((($key -split '\|', 2)[0])) }

    # Ownership-based escalation: owners of groups assigned a privileged role.
    $ownEscRows = @()
    foreach ($g in $groupAssign) {
        $owners = @(); try { $owners = @(Get-MgGroupOwner -GroupId $g.PrincipalId -All -ErrorAction SilentlyContinue) } catch {}
        foreach ($o in $owners) {
            $oid   = $o.Id
            $otype = [string](Get-Ap $o '@odata.type')
            $oupn  = Get-Ap $o 'userPrincipalName'
            $oname = Get-Ap $o 'displayName'
            $label = if ($oupn) { $oupn } elseif ($oname) { $oname } else { $oid }
            $isUser = (($otype -eq '#microsoft.graph.user') -or [bool]$oupn)
            $ownerType = if ($otype) { ($otype -replace '#microsoft.graph.','') } elseif ($isUser) { 'user' } else { 'unknown' }

            if ($isUser) {
                $isGuest = ($oupn -like '*#EXT#*')
                $alreadyPriv = ($oid -and $allPrivUserIds.Contains($oid))
                $disabled = $false
                if ($oid -and $script:UserById.ContainsKey($oid)) { $disabled = -not [bool]$script:UserById[$oid].AccountEnabled }
                # A non-privileged, guest, or disabled owner can add themselves to the group
                # and inherit the privileged role. An already-privileged owner gains nothing.
                if ($alreadyPriv -and -not $isGuest -and -not $disabled) { continue }
                $ownEscRows += [pscustomobject]@{
                    Owner=$label; OwnerType=$ownerType; Group=($g.PrincipalName ?? $g.PrincipalId); GrantsRole=$g.RoleName
                    OwnerGuest=$isGuest; OwnerDisabled=$disabled; OwnerAlreadyPrivileged=$alreadyPriv
                }
            } else {
                # Non-human owner (service principal / nested group) that can add members to a
                # role-granting group - a real but distinct path; label it rather than mis-report as a user.
                $ownEscRows += [pscustomobject]@{
                    Owner=$label; OwnerType=$ownerType; Group=($g.PrincipalName ?? $g.PrincipalId); GrantsRole=$g.RoleName
                    OwnerGuest=$false; OwnerDisabled=$false; OwnerAlreadyPrivileged=$false
                }
            }
        }
    }
    if ($ownEscRows.Count -gt 0) {
        $sev = if (@($ownEscRows | Where-Object { $_.OwnerGuest -or $_.OwnerDisabled }).Count -gt 0) { 'Critical' } else { 'High' }
        $osrc = Write-Evidence -BaseName 'access_paths_ownership' -Rows $ownEscRows -Title 'Effective Access - Ownership-Based Escalation'
        Add-EntraFinding -Severity $sev -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ("{0} ownership-based privilege-escalation path(s) via role-granting groups" -f $ownEscRows.Count) `
            -Evidence ("Owners who can add themselves to a privileged group: {0}" -f (($ownEscRows | Select-Object -First 8 | ForEach-Object { "$($_.Owner)->$($_.Group)" }) -join '; ')) `
            -WhyItMatters 'An owner of a group that is assigned a privileged role can add themselves (or anyone) to the group and inherit that role. A guest, disabled, or non-privileged owner is therefore an indirect privilege-escalation path - the cloud analog of a dangerous WriteOwner/AddMember ACL.' `
            -RecommendedAction 'Remove non-administrative, guest and disabled owners from groups that are assigned privileged roles; manage membership through PIM for Groups with approval.' `
            -SourceFile $osrc -ResultRows $ownEscRows
    }

    # Owners of groups EXCLUDED from Conditional Access policies (especially MFA-enforcing
    # ones) can add themselves to the group and thereby exempt their own account.
    $caExcl = @{}   # groupId -> pscustomobject{ Policies=List; EnforcesMfa }
    try {
        foreach ($p in @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' })) {
            $enforces = Test-CaPolicyRequiresMfaOrStrength $p
            foreach ($gid in @($p.Conditions.Users.ExcludeGroups)) {
                if (-not $gid -or $gid -match 'All|GuestsOrExternalUsers|None') { continue }
                if (-not $caExcl.ContainsKey($gid)) { $caExcl[$gid] = [pscustomobject]@{ Policies=(New-Object System.Collections.Generic.List[string]); EnforcesMfa=$false } }
                $caExcl[$gid].Policies.Add($p.DisplayName)
                if ($enforces) { $caExcl[$gid].EnforcesMfa = $true }
            }
        }
    } catch {}
    $caOwnRows = @()
    foreach ($gid in $caExcl.Keys) {
        $info = $caExcl[$gid]
        $gname = $gid
        try { $gg = Get-MgGroup -GroupId $gid -Property 'id,displayName' -ErrorAction SilentlyContinue; if ($gg) { $gname = $gg.DisplayName } } catch {}
        $owners = @(); try { $owners = @(Get-MgGroupOwner -GroupId $gid -All -ErrorAction SilentlyContinue) } catch {}
        foreach ($o in $owners) {
            $oupn = Get-Ap $o 'userPrincipalName'; $oname = Get-Ap $o 'displayName'
            $label = if ($oupn) { $oupn } elseif ($oname) { $oname } else { $o.Id }
            $caOwnRows += [pscustomobject]@{ Owner=$label; ExcludedGroup=$gname; EnforcesMfa=$info.EnforcesMfa; Policies=(($info.Policies | Select-Object -Unique) -join '; ') }
        }
    }
    if ($caOwnRows.Count -gt 0) {
        $csrc = Write-Evidence -BaseName 'access_paths_ca_exclusions' -Rows $caOwnRows -Title 'Effective Access - CA Exclusion Group Ownership'
        $mfaExcl = @($caOwnRows | Where-Object { $_.EnforcesMfa })
        $otherExcl = @($caOwnRows | Where-Object { -not $_.EnforcesMfa })
        if ($mfaExcl.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'accesspaths' -Category 'Privileged Access' `
                -Title ("{0} owner(s) of MFA-exclusion groups can self-add to bypass MFA" -f $mfaExcl.Count) `
                -Evidence ("Owners of groups excluded from an MFA-enforcing CA policy: {0}" -f (($mfaExcl | Select-Object -First 8 | ForEach-Object { "$($_.Owner)->$($_.ExcludedGroup)" }) -join '; ')) `
                -WhyItMatters 'An owner of a group excluded from an MFA Conditional Access policy can add themselves to that group and exempt their own account from MFA - a direct control bypass that needs no role at all.' `
                -RecommendedAction 'Remove non-administrative/guest owners from CA-exclusion groups, keep exclusion membership minimal (ideally only the two break-glass accounts), and manage membership via PIM for Groups.' `
                -SourceFile $csrc -ResultRows $mfaExcl
        }
        if ($otherExcl.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'accesspaths' -Category 'Privileged Access' `
                -Title ("{0} owner(s) of Conditional Access exclusion groups can change their own policy exposure" -f $otherExcl.Count) `
                -Evidence ("Owners of CA-exclusion groups (non-MFA policies): {0}" -f (($otherExcl | Select-Object -First 8 | ForEach-Object { "$($_.Owner)->$($_.ExcludedGroup)" }) -join '; ')) `
                -WhyItMatters 'An owner of any CA-exclusion group can add themselves to change which Conditional Access controls apply to their account.' `
                -RecommendedAction 'Tightly control membership and ownership of all Conditional Access exclusion groups.' `
                -SourceFile $csrc -ResultRows $otherExcl
        }
    }

    if ($hiddenGaps.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ("{0} role-granting group(s) could not be fully expanded (coverage gap)" -f $hiddenGaps.Count) `
            -Evidence ("Membership could not be read (hidden membership / permission): {0}" -f (($hiddenGaps | Select-Object -First 8) -join ', ')) `
            -WhyItMatters 'Groups with hidden membership or insufficient read permission cannot be fully evaluated for privilege paths - the absence of a finding here is a coverage gap, not a clean result.' `
            -RecommendedAction 'Grant Member.Read.Hidden (read-only) to evaluate hidden-membership groups, or review those groups manually.' -SourceFile $src
    }

    if ($dupRows.Count -eq 0 -and $ownEscRows.Count -eq 0 -and $caOwnRows.Count -eq 0 -and $hiddenGaps.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'No duplicate privilege paths or ownership-escalation paths detected' `
            -Evidence 'Each privileged role is reached through a single reviewed path, and role-granting groups have no unsafe owners.' `
            -WhyItMatters 'Single, reviewed privilege paths make de-provisioning reliable and reduce hidden standing access.' `
            -RecommendedAction 'Maintain single-path privileged assignments and safe group ownership.' -SourceFile $src
    }
}

# ===========================================================================
# REPORT ENGINE  (HTML/CSS/JS reused verbatim from the AD audit for an
# identical look: light/dark theme, severity badges, filterable finding
# cards, executive risk report with score band matrix.)
# ===========================================================================

function New-FindingAnchor([object]$f) {
    'finding-' + (New-Slug ('{0}-{1}' -f $f.Title, $f.CheckId))
}

function Get-EntraPrimaryNav([string]$Active, [string]$HrefPrefix = '') {
    # $HrefPrefix lets pages OUTSIDE the 'HTML Reports' folder (the per-dataset raw
    # pages live in 'Raw Data\Source') point back at the reports with '../../HTML Reports/'.
    $links = @(
        @{ Key='audit';   Href='EntraAudit-Results.html'; Label='Audit Results' }
        @{ Key='risk';    Href='Risk-Report.html';        Label='Risk Report' }
        @{ Key='posture'; Href='Posture-Summary.html';    Label='Posture Summary' }
        @{ Key='raw';     Href='Raw-Data.html';           Label='Raw Data' }
    )
    $css = @'
<style>
.primary-nav{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 20px;padding:10px 14px;background:var(--panel,#fff);border:1px solid var(--line,#d9e0ea);border-radius:12px;box-shadow:var(--shadow,0 10px 24px rgba(15,23,42,.08))}
.primary-nav-link{padding:6px 12px;border-radius:999px;font-size:.85rem;font-weight:600;text-decoration:none;color:var(--text,#1b2430);border:1px solid transparent}
.primary-nav-link:hover{background:var(--accent-soft,#dbeafe);text-decoration:none}
.primary-nav-link.active{background:var(--accent,#3b82f6);color:#fff;border-color:var(--accent,#3b82f6)}
</style>
'@
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($css)
    [void]$sb.Append("<nav class='primary-nav'>")
    foreach ($l in $links) {
        $cls = if ($l.Key -eq $Active) { 'primary-nav-link active' } else { 'primary-nav-link' }
        [void]$sb.Append("<a class='$cls' href='$(HtmlAttrEncode ($HrefPrefix + $l.Href))'>$($l.Label)</a>")
    }
    [void]$sb.Append('</nav>')
    $sb.ToString()
}

function New-EvidenceTableHtml($rows, [int]$maxRows = 200) {
    if (-not $rows) { return "<div class='result-empty'>No matching objects were found for this check.</div>" }
    $arr = @($rows)
    if ($arr.Count -eq 0) { return "<div class='result-empty'>No matching objects were found for this check.</div>" }
    $cols = @($arr[0].PSObject.Properties.Name)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='result-scroll'><table class='result-table'><thead><tr>")
    foreach ($c in $cols) { [void]$sb.Append("<th>$(HtmlEncode $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    $shown = 0
    foreach ($r in $arr) {
        if ($shown -ge $maxRows) { break }
        [void]$sb.Append('<tr>')
        foreach ($c in $cols) {
            $v = $r.$c
            $s = if ($null -eq $v) { '' } else { [string]$v }
            [void]$sb.Append("<td>$(HtmlEncode $s)</td>")
        }
        [void]$sb.Append('</tr>'); $shown++
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($arr.Count -gt $maxRows) { [void]$sb.Append("<div class='result-note'>Showing $maxRows of $($arr.Count) rows. Full data in the linked CSV/TXT source file.</div>") }
    $sb.ToString()
}

# Theme toggle + live row filter for the standalone raw-data pages. Targets BODY
# data-theme to match Get-EntraMainCss (the risk pages target the <html> element).
function Get-EntraRawJs {
@'
<script>
(function(){
  function q(s){return document.querySelector(s);}
  function cur(){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(e){}if(s==='light'||s==='dark')return s;return (window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light';}
  function ap(t){document.body.setAttribute('data-theme',t);var b=q('#themeToggle');if(b)b.innerText=t==='dark'?'Light mode':'Dark mode';try{localStorage.setItem('entraaudit-theme',t);}catch(e){}}
  ap(cur());
  var b=q('#themeToggle');if(b)b.addEventListener('click',function(){ap(document.body.getAttribute('data-theme')==='dark'?'light':'dark');});
  var inp=q('#rawSearch');if(inp){inp.addEventListener('input',function(){var v=(this.value||'').toLowerCase();Array.prototype.slice.call(document.querySelectorAll('.result-table tbody tr')).forEach(function(r){r.style.display=((r.innerText||'').toLowerCase().indexOf(v)>=0)?'':'none';});});}
})();
</script>
'@
}

# Standalone, styled HTML view of one raw dataset (same design as the reports).
function New-RawDataHtml {
    param([string]$Path, [string]$Title, [object[]]$Rows, [string[]]$Notes, [string]$CsvName, [string]$TxtName)
    $css = Get-EntraMainCss
    $nav = Get-EntraPrimaryNav 'raw' '../../HTML Reports/'
    $js  = Get-EntraRawJs
    $count = @($Rows).Count
    $table = New-EvidenceTableHtml $Rows 2000
    $notesHtml = if ($Notes) { ($Notes | ForEach-Object { "<div class='meta'>$(HtmlEncode $_)</div>" }) -join "`n" } else { '' }
    $gen = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Audit - $(HtmlEncode $Title)</title>
$css
</head>
<body data-theme="light">
<div class="container">
$nav
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>$(HtmlEncode $Title)</h1>
        <div class="meta">
          Raw evidence &mdash; <b>$count</b> row(s)<br>
          Generated: $(HtmlEncode $gen)<br>
          Download full data: <a href="$(HtmlAttrEncode $CsvName)" download>CSV</a> &middot; <a href="$(HtmlAttrEncode $TxtName)" download>TXT</a> &middot; <a href="../../HTML Reports/EntraAudit-Results.html">Back to findings</a>
        </div>
        $notesHtml
      </div>
      <div class="hero-actions"><button type="button" class="theme-toggle" id="themeToggle">Dark mode</button></div>
    </div>
  </section>
  <section class="toolbar">
    <div class="toolbar-row">
      <div class="filter"><label for="rawSearch">Filter rows</label><input id="rawSearch" type="text" placeholder="Type to filter the table..."></div>
    </div>
  </section>
  <div style="margin-top:8px">$table</div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
}

function Get-EntraMainCss {
@'
<style>
:root{
  --bg:#f5f7fb;--panel:#ffffff;--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;
  --shadow:0 10px 24px rgba(15,23,42,.08);
  --critical:#c62828;--high:#ef6c00;--medium:#0277bd;--low:#2e7d32;--information:#6c757d;
  --critical-soft:#fdecec;--high-soft:#fff2e5;--medium-soft:#e8f4fd;--low-soft:#edf8ee;--information-soft:#f2f4f6;
  --result-panel:#ffffff;--accent:#3b82f6;--accent-soft:#dbeafe;
}
body[data-theme="dark"]{
  --bg:#0f172a;--panel:#111827;--text:#e5e7eb;--muted:#94a3b8;--line:#334155;
  --shadow:0 10px 24px rgba(0,0,0,.35);
  --critical:#f87171;--high:#fb923c;--medium:#60a5fa;--low:#4ade80;--information:#cbd5e1;
  --critical-soft:rgba(248,113,113,.15);--high-soft:rgba(251,146,60,.14);--medium-soft:rgba(96,165,250,.14);
  --low-soft:rgba(74,222,128,.14);--information-soft:rgba(203,213,225,.12);--result-panel:#0b1220;
}
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);}
a{color:#0f5cb8;text-decoration:none}
body[data-theme="dark"] a{color:#93c5fd}
a:hover{text-decoration:underline}
.container{max-width:1280px;margin:0 auto;padding:28px 22px 48px}
.hero{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:24px;}
.hero-top{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;align-items:flex-start;}
.hero-actions{display:flex;flex-direction:column;align-items:flex-end;gap:12px;}
.theme-toggle{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:999px;padding:10px 14px;font-size:13px;font-weight:700;cursor:pointer;}
.theme-toggle:hover{transform:translateY(-1px)}
h1{margin:0 0 8px;font-size:28px}
.meta{color:var(--muted);font-size:14px;line-height:1.6}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:22px}
.metric{border:1px solid var(--line);border-radius:14px;padding:14px 16px;background:var(--panel);}
.metric-label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
.metric-value{font-size:30px;font-weight:800;margin-top:6px}
.metric.sev-Critical{background:var(--critical-soft)}
.metric.sev-High{background:var(--high-soft)}
.metric.sev-Medium{background:var(--medium-soft)}
.metric.sev-Low{background:var(--low-soft)}
.metric.sev-Information{background:var(--information-soft)}
.layout{display:grid;grid-template-columns:280px minmax(0,1fr);gap:20px;margin-top:20px}
.sidebar{position:sticky;top:18px;align-self:start;background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;}
.sidebar h3,.content h2{margin-top:0}
.sidebar ul{list-style:none;padding:0;margin:0}
.sidebar li{margin:10px 0}
.index-group{margin-top:18px;padding-top:18px;border-top:1px solid var(--line)}
.index-group h4{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.index-detail{border:1px solid var(--line);border-radius:12px;padding:8px 10px;background:#f8fafc;margin-bottom:10px}
body[data-theme="dark"] .index-detail{background:var(--result-panel)}
.index-detail summary{cursor:pointer;font-weight:700;list-style:none}
.index-detail summary::-webkit-details-marker{display:none}
.index-detail ol{margin:10px 0 0 18px;padding:0;max-height:260px;overflow:auto}
.index-detail li{margin:6px 0}
.index-detail a{color:var(--text)}
.badge{display:inline-flex;align-items:center;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:800;letter-spacing:.02em;margin-right:8px;border:1px solid transparent;}
.badge.sev-Critical{background:var(--critical-soft);color:var(--critical);border-color:rgba(198,40,40,.25)}
.badge.sev-High{background:var(--high-soft);color:var(--high);border-color:rgba(239,108,0,.25)}
.badge.sev-Medium{background:var(--medium-soft);color:var(--medium);border-color:rgba(2,119,189,.25)}
.badge.sev-Low{background:var(--low-soft);color:var(--low);border-color:rgba(46,125,50,.25)}
.badge.sev-Information{background:var(--information-soft);color:var(--information);border-color:rgba(108,117,125,.25)}
.category{display:inline-flex;align-items:center;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:700;color:var(--muted);background:#f4f6f9;border:1px solid var(--line);margin-right:8px;}
body[data-theme="dark"] .category{background:#1f2937}
.toolbar{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:16px;margin-bottom:18px;}
.toolbar-row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;}
label{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
select,input{width:100%;min-height:42px;border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:var(--panel);color:var(--text);}
.filter{min-width:220px;flex:1}
.section-header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:0 0 12px;}
.section-header h2{margin:0;font-size:24px}
.section-count{color:var(--muted);font-size:14px;font-weight:700}
.finding{background:var(--panel);border:1px solid var(--line);border-left:6px solid var(--information);border-radius:16px;box-shadow:var(--shadow);margin-bottom:14px;overflow:hidden;}
.finding.sev-Critical{border-left-color:var(--critical)}
.finding.sev-High{border-left-color:var(--high)}
.finding.sev-Medium{border-left-color:var(--medium)}
.finding.sev-Low{border-left-color:var(--low)}
.finding.sev-Information{border-left-color:var(--information)}
.finding summary{list-style:none;cursor:pointer;padding:18px 18px 16px;}
.finding summary::-webkit-details-marker{display:none}
.finding-head{display:flex;flex-direction:column;gap:10px}
.finding-title-wrap{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.finding-title{font-size:18px;font-weight:800}
.finding-summary{color:var(--muted);line-height:1.5}
.finding-body{padding:0 18px 18px}
.finding-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.panel{background:#f8fafc;border:1px solid var(--line);border-radius:12px;padding:14px;}
body[data-theme="dark"] .panel{background:var(--result-panel)}
.panel h4{margin:0 0 8px;font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.panel p{margin:0;line-height:1.55}
.panel.evidence{margin-top:12px}
.priority{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;margin-bottom:18px}
.priority ul{margin:0;padding-left:18px}
.priority li{margin:10px 0;line-height:1.5}
.priority-title{font-weight:700;color:var(--text)}
.priority-evidence{display:block;color:var(--muted);margin-top:4px}
.empty{background:var(--panel);border:1px dashed var(--line);border-radius:14px;padding:16px;color:var(--muted)}
.mono{font-family:Consolas,Menlo,Monaco,monospace}
.download-link{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:10px 14px;border-radius:10px;border:1px solid var(--line);background:var(--panel);color:var(--text);font-weight:700;max-width:260px;}
.result-note{font-size:13px;color:var(--muted);margin:10px 0}
.result-scroll{max-height:360px;overflow:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel);}
.result-table{width:100%;border-collapse:collapse;font-size:13px;}
.result-table th,.result-table td{border-bottom:1px solid var(--line);padding:10px 12px;vertical-align:top;text-align:left;}
.result-table th{position:sticky;top:0;background:#eef2f7;z-index:1;}
body[data-theme="dark"] .result-table th{background:#0b1220}
.result-empty{color:var(--muted);line-height:1.5}
.status-table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.status-table th,.status-table td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;font-size:14px}
.status-table th{color:var(--muted);text-transform:uppercase;font-size:12px;letter-spacing:.06em}
.pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:800;border:1px solid var(--line)}
.pill.ok{background:var(--low-soft);color:var(--low)}
.pill.find{background:var(--high-soft);color:var(--high)}
.pill.skip{background:var(--information-soft);color:var(--information)}
.pill.err{background:var(--critical-soft);color:var(--critical)}
@media (max-width: 980px){.layout{grid-template-columns:1fr}.sidebar{position:static}.hero-actions{align-items:flex-start}}
</style>
'@
}

function Get-EntraMainJs {
@'
<script>
(function(){
  function q(s){return document.querySelector(s);}
  function qa(s){return Array.prototype.slice.call(document.querySelectorAll(s));}
  function findings(){return qa('.finding');}
  function osPrefersDark(){return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);}
  function currentTheme(){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(_){}if(s==='light'||s==='dark')return s;return osPrefersDark()?'dark':'light';}
  function applyTheme(t){document.body.setAttribute('data-theme',t);var b=q('#themeToggle');if(b){b.innerText=t==='dark'?'Light mode':'Dark mode';}try{localStorage.setItem('entraaudit-theme',t);}catch(e){}}
  function applyFilters(){var sev=q('#severityFilter').value;var query=(q('#searchFilter').value||'').toLowerCase().trim();var visible=0;findings().forEach(function(it){var s=it.getAttribute('data-sev');var text=(it.innerText||'').toLowerCase();var show=(sev==='All'||s===sev)&&(!query||text.indexOf(query)>=0);it.style.display=show?'':'none';if(show)visible++;});var el=q('#visibleFindings');if(el)el.value=visible;}
  var b=q('#themeToggle');if(b){b.addEventListener('click',function(){var n=document.body.getAttribute('data-theme')==='dark'?'light':'dark';applyTheme(n);});}
  applyTheme(currentTheme());
  if(window.matchMedia){var mq=window.matchMedia('(prefers-color-scheme: dark)');var h=function(e){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(_){}if(s!=='light'&&s!=='dark')applyTheme(e.matches?'dark':'light');};if(mq.addEventListener)mq.addEventListener('change',h);else if(mq.addListener)mq.addListener(h);}
  var sf=q('#severityFilter');if(sf)sf.addEventListener('change',applyFilters);
  var se=q('#searchFilter');if(se)se.addEventListener('input',applyFilters);
  applyFilters();
})();
</script>
'@
}

function Get-EntraRiskCss {
@'
<style>
:root{--bg:#f5f7fb;--bg-glow1:rgba(105,177,255,.10);--bg-glow2:rgba(255,169,64,.10);--panel:#ffffff;--panel-soft:rgba(15,23,42,.04);--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;--shadow:0 10px 24px rgba(15,23,42,.08);--radius:14px;--critical-bg:#fdecec;--critical-text:#c62828;--high-bg:#fff2e5;--high-text:#ef6c00;--medium-bg:#e8f4fd;--medium-text:#0277bd;--low-bg:#edf8ee;--low-text:#2e7d32;--info-bg:#f2f4f6;--info-text:#6c757d;--link:#0f5cb8;--pre-bg:#f8fafc;--pre-text:#1b2430;--accent:#3b82f6;--accent-soft:#dbeafe;}
@media (prefers-color-scheme: dark){:root{--bg:#0b1220;--bg-glow1:rgba(105,177,255,.18);--bg-glow2:rgba(255,169,64,.16);--panel:#111827;--panel-soft:rgba(255,255,255,.06);--text:#e8edf6;--muted:#b7c0d6;--line:rgba(255,255,255,.10);--shadow:0 10px 30px rgba(0,0,0,.35);--critical-bg:rgba(255,77,79,.18);--critical-text:#fecaca;--high-bg:rgba(255,169,64,.18);--high-text:#fed7aa;--medium-bg:rgba(105,177,255,.18);--medium-text:#bfdbfe;--low-bg:rgba(149,222,100,.18);--low-text:#bbf7d0;--info-bg:rgba(160,160,160,.18);--info-text:#e2e8f0;--link:#cfe1ff;--pre-bg:rgba(0,0,0,.25);--pre-text:#dbe6ff;}}
html[data-theme="light"]{--bg:#f5f7fb;--panel:#ffffff;--panel-soft:rgba(15,23,42,.04);--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;--shadow:0 10px 24px rgba(15,23,42,.08);--critical-bg:#fdecec;--critical-text:#c62828;--high-bg:#fff2e5;--high-text:#ef6c00;--medium-bg:#e8f4fd;--medium-text:#0277bd;--low-bg:#edf8ee;--low-text:#2e7d32;--info-bg:#f2f4f6;--info-text:#6c757d;--link:#0f5cb8;--pre-bg:#f8fafc;--pre-text:#1b2430;}
html[data-theme="dark"]{--bg:#0b1220;--panel:#111827;--panel-soft:rgba(255,255,255,.06);--text:#e8edf6;--muted:#b7c0d6;--line:rgba(255,255,255,.10);--shadow:0 10px 30px rgba(0,0,0,.35);--critical-bg:rgba(255,77,79,.18);--critical-text:#fecaca;--high-bg:rgba(255,169,64,.18);--high-text:#fed7aa;--medium-bg:rgba(105,177,255,.18);--medium-text:#bfdbfe;--low-bg:rgba(149,222,100,.18);--low-text:#bbf7d0;--info-bg:rgba(160,160,160,.18);--info-text:#e2e8f0;--link:#cfe1ff;--pre-bg:rgba(0,0,0,.25);--pre-text:#dbe6ff;}
*{box-sizing:border-box}
body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:radial-gradient(1200px 700px at 20% 10%,var(--bg-glow1),transparent 60%),radial-gradient(1200px 700px at 80% 0%,var(--bg-glow2),transparent 55%),var(--bg);color:var(--text);}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
.container{max-width:1200px;margin:0 auto;padding:28px 20px 60px}
.header{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:22px 22px 18px;}
.h-title{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;flex-wrap:wrap}
h1{font-size:22px;margin:0 0 6px;letter-spacing:.2px}
.meta{color:var(--muted);font-size:13px}
.theme-toggle{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:999px;padding:8px 14px;font-size:13px;font-weight:700;cursor:pointer;margin-bottom:10px;}
.theme-toggle:hover{filter:brightness(1.05)}
.badge{display:inline-flex;align-items:center;gap:10px;padding:10px 12px;border-radius:999px;border:1px solid var(--line);background:var(--panel-soft);font-weight:700;}
.badge .grade{font-size:13px;color:var(--muted);font-weight:600}
.badge .value{font-size:15px}
.badge.Critical{background:var(--critical-bg);color:var(--critical-text)}
.badge.High{background:var(--high-bg);color:var(--high-text)}
.badge.Medium{background:var(--medium-bg);color:var(--medium-text)}
.badge.Low{background:var(--low-bg);color:var(--low-text)}
.badge.Information{background:var(--info-bg);color:var(--info-text)}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin-top:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:14px 14px 12px;min-height:88px;}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em}
.card .v{font-size:22px;font-weight:800;margin-top:6px}
.card .s{margin-top:4px;color:var(--muted);font-size:12px}
.span-3{grid-column:span 3}.span-4{grid-column:span 4}
.pill{display:inline-flex;align-items:center;justify-content:center;padding:4px 10px;border-radius:999px;font-weight:800;font-size:12px;border:1px solid var(--line);min-width:86px;}
.sev-Critical{background:var(--critical-bg);color:var(--critical-text)}
.sev-High{background:var(--high-bg);color:var(--high-text)}
.sev-Medium{background:var(--medium-bg);color:var(--medium-text)}
.sev-Low{background:var(--low-bg);color:var(--low-text)}
.sev-Information{background:var(--info-bg);color:var(--info-text)}
.section{margin-top:18px}.section h2{margin:0 0 10px;font-size:16px}
.callout{border:1px solid var(--line);border-radius:var(--radius);padding:14px;background:var(--panel)}
.callout p{margin:0;line-height:1.4}.callout ul{margin:10px 0 0 18px}.callout li{margin:6px 0}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin:10px 0}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
select,input{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:8px 10px;outline:none;}
input{min-width:240px}
small{color:var(--muted)}
table{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;background:var(--panel)}
th,td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em;background:var(--panel-soft)}
th[data-sort]{cursor:pointer;user-select:none}
tr:hover td{background:var(--panel-soft)}
td.score{font-weight:800}td.title{font-weight:700}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
td.source .mono{font-size:12px;color:var(--link)}
.footer{margin-top:16px;color:var(--muted);font-size:12px}
.matrix-wrap{margin-top:10px}
table.matrix{table-layout:fixed;}
table.matrix th,table.matrix td{padding:14px 18px;}
table.matrix th{cursor:default;}
table.matrix th:nth-child(1),table.matrix td:nth-child(1){width:18%;padding-left:22px;}
table.matrix th:nth-child(2),table.matrix td:nth-child(2){width:18%;text-align:center;}
table.matrix th:nth-child(3),table.matrix td:nth-child(3){width:64%;padding-left:22px;}
.matrix-row.active td{background:var(--panel-soft)}
</style>
'@
}

function Get-EntraRiskJs {
@'
<script>
(function(){
  function q(s){return document.querySelector(s);}
  function qa(s){return Array.prototype.slice.call(document.querySelectorAll(s));}
  function rows(){return qa('#findings-body tr');}
  function currentTheme(){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(e){}if(s==='light'||s==='dark')return s;if(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)return 'dark';return 'light';}
  function applyTheme(t){document.documentElement.setAttribute('data-theme',t);var b=q('#themeToggle');if(b){b.innerText=(t==='dark')?'Light mode':'Dark mode';}try{localStorage.setItem('entraaudit-theme',t);}catch(e){}}
  applyTheme(currentTheme());
  var tb=q('#themeToggle');if(tb){tb.addEventListener('click',function(){var n=(document.documentElement.getAttribute('data-theme')==='dark')?'light':'dark';applyTheme(n);});}
  if(window.matchMedia){var mq=window.matchMedia('(prefers-color-scheme: dark)');var h=function(e){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(_){}if(s!=='light'&&s!=='dark')applyTheme(e.matches?'dark':'light');};if(mq.addEventListener)mq.addEventListener('change',h);else if(mq.addListener)mq.addListener(h);}
  function applyFilters(){var sev=q('#sevFilter').value;var s=(q('#search').value||'').toLowerCase().trim();var visible=0;rows().forEach(function(r){var rs=r.getAttribute('data-sev');var text=(r.innerText||'').toLowerCase();var show=((sev==='All')||(rs===sev))&&((!s)||(text.indexOf(s)>=0));r.style.display=show?'':'none';if(show)visible++;});q('#visibleCount').innerText=visible;}
  var sortCol=null,sortAsc=false;var order=['Critical','High','Medium','Low','Information'];
  function sortBy(col){sortAsc=(sortCol===col)?!sortAsc:true;sortCol=col;var arr=rows().slice().sort(function(a,b){var ka,kb;if(col==='severity'){ka=order.indexOf(a.getAttribute('data-sev'));kb=order.indexOf(b.getAttribute('data-sev'));}else if(col==='title'){ka=(a.querySelector('.title')||{}).innerText||'';kb=(b.querySelector('.title')||{}).innerText||'';}else{ka=a.innerText;kb=b.innerText;}if(ka<kb)return sortAsc?-1:1;if(ka>kb)return sortAsc?1:-1;return 0;});var tbody=q('#findings-body');arr.forEach(function(r){tbody.appendChild(r);});applyFilters();}
  q('#sevFilter').addEventListener('change',applyFilters);
  q('#search').addEventListener('input',applyFilters);
  qa('th[data-sort]').forEach(function(th){th.addEventListener('click',function(){sortBy(th.getAttribute('data-sort'));});});
  applyFilters();sortBy('severity');
})();
</script>
'@
}

function Get-EntraRiskScore($findings) {
    $c = @($findings | Where-Object { (Normalize-Severity $_.Severity) -eq 'Critical' }).Count
    $h = @($findings | Where-Object { (Normalize-Severity $_.Severity) -eq 'High' }).Count
    $m = @($findings | Where-Object { (Normalize-Severity $_.Severity) -eq 'Medium' }).Count
    $l = @($findings | Where-Object { (Normalize-Severity $_.Severity) -eq 'Low' }).Count
    $cd = if ($c -ge 1) { [Math]::Min(60, 25 + 10 * ($c - 1)) } else { 0 }
    $hd = if ($h -ge 1) { [Math]::Min(40, 12 + 5 * ($h - 1)) } else { 0 }
    $md = if ($m -ge 1) { [Math]::Min(25, 5 + 2 * ($m - 1)) } else { 0 }
    $ld = if ($l -ge 1) { [Math]::Min(10, 1 + 0.5 * ($l - 1)) } else { 0 }
    $score = [int][Math]::Max(0, [Math]::Round(100 - $cd - $hd - $md - $ld))
    if ($c -ge 1 -and $score -gt 49) { $score = 49 }
    $band = if ($score -ge 90) { 'Excellent' } elseif ($score -ge 75) { 'Good' } elseif ($score -ge 50) { 'Fair' } elseif ($score -ge 25) { 'Poor' } else { 'Critical' }
    [pscustomobject]@{ Score = $score; Band = $band; Critical = $c; High = $h; Medium = $m; Low = $l }
}

function Get-BandBadgeClass([string]$band) {
    switch ($band) { 'Excellent' { 'Low' } 'Good' { 'Low' } 'Fair' { 'Medium' } 'Poor' { 'High' } 'Critical' { 'Critical' } default { 'Information' } }
}

function Resolve-SourceHref([string]$src) {
    if ([string]::IsNullOrWhiteSpace($src)) { return '' }
    return ($src -replace ' ', '%20')
}

function Write-EntraResultsReport {
    param([string]$Path, [object[]]$Items, [hashtable]$Counts, [string]$TenantName, [string]$GeneratedOn, [string]$Subtitle)

    $severityOrder = @('Critical','High','Medium','Low','Information')
    $total = @($Items).Count

    $countCards = foreach ($sev in $severityOrder) {
        $n = if ($Counts.ContainsKey($sev)) { [int]$Counts[$sev] } else { 0 }
        "<div class='metric sev-$sev'><div class='metric-label'>$sev</div><div class='metric-value'>$n</div></div>"
    }

    $priority = @($Items | Where-Object { (Normalize-Severity $_.Severity) -in @('Critical','High') } |
        Sort-Object @{e={Get-SeverityRank $_.Severity};Descending=$true}, Title | Select-Object -First 8)
    $priorityHtml = if ($priority.Count -gt 0) {
        foreach ($it in $priority) {
            $a = New-FindingAnchor $it
            "<li><span class='badge sev-$(Normalize-Severity $it.Severity)'>$(Normalize-Severity $it.Severity)</span><a class='priority-title' href='#$a'>$(HtmlEncode $it.Title)</a><span class='priority-evidence'>$(HtmlEncode $it.Evidence)</span></li>"
        }
    } else { '<li>No high-priority findings were identified.</li>' }

    $indexHtml = New-Object System.Collections.Generic.List[string]
    foreach ($sev in $severityOrder) {
        $bucket = @($Items | Where-Object { (Normalize-Severity $_.Severity) -eq $sev } | Sort-Object Category, Title)
        if ($bucket.Count -eq 0) { continue }
        $rows = foreach ($it in $bucket) { $a = New-FindingAnchor $it; "<li><a href='#$(HtmlAttrEncode $a)'>$(HtmlEncode $it.Title)</a></li>" }
        $indexHtml.Add("<details class='index-detail'><summary>$sev ($($bucket.Count))</summary><ol>$($rows -join "`n")</ol></details>") | Out-Null
    }
    if ($indexHtml.Count -eq 0) { $indexHtml.Add("<div class='empty'>No findings.</div>") | Out-Null }

    $sectionHtml = New-Object System.Collections.Generic.List[string]
    foreach ($sev in $severityOrder) {
        $bucket = @($Items | Where-Object { (Normalize-Severity $_.Severity) -eq $sev } | Sort-Object Category, Title)
        $cards = New-Object System.Collections.Generic.List[string]
        if ($bucket.Count -eq 0) {
            $cards.Add("<div class='empty'>No findings in this severity band.</div>") | Out-Null
        } else {
            foreach ($it in $bucket) {
                $sevNorm = Normalize-Severity $it.Severity
                $a = New-FindingAnchor $it
                $resultPanel = New-EvidenceTableHtml $it.ResultRows
                $srcHref = Resolve-SourceHref $it.SourceFile
                $srcHtml = if ($srcHref) {
                    "<a class='download-link' href='$(HtmlAttrEncode $srcHref)' target='_blank' rel='noopener'>Open source evidence</a><div class='result-note mono'>$(HtmlEncode (Split-Path $it.SourceFile -Leaf))</div>"
                } else { "<span class='mono'>No separate evidence file for this finding.</span>" }
                $affected = if ($it.AffectedPrincipal) { "<div class='result-note'>Affected principal: <span class='mono'>$(HtmlEncode $it.AffectedPrincipal)</span></div>" } else { '' }

                $cards.Add(@"
<details class="finding sev-$sevNorm" data-sev="$sevNorm" data-category="$(HtmlAttrEncode $it.Category)" id="$a">
  <summary>
    <div class="finding-head">
      <div class="finding-title-wrap">
        <span class="badge sev-$sevNorm">$sevNorm</span>
        <span class="category">$(HtmlEncode $it.Category)</span>
        <span class="finding-title">$(HtmlEncode $it.Title)</span>
      </div>
      <div class="finding-summary">$(HtmlEncode $it.Evidence)</div>
    </div>
  </summary>
  <div class="finding-body">
    <div class="finding-grid">
      <div class="panel"><h4>What was observed</h4><p>$(HtmlEncode $it.Evidence)</p></div>
      <div class="panel"><h4>Why it matters</h4><p>$(HtmlEncode $it.WhyItMatters)</p></div>
      <div class="panel"><h4>Recommended action</h4><p>$(HtmlEncode $it.RecommendedAction)</p></div>
      <div class="panel"><h4>Source evidence</h4>$srcHtml</div>
    </div>
    <div class="panel evidence"><h4>Result details</h4>$affected $resultPanel</div>
  </div>
</details>
"@) | Out-Null
            }
        }
        $sectionHtml.Add("<section class='severity-section' id='section-$(New-Slug $sev)'><div class='section-header'><h2>$sev</h2><div class='section-count'>$($bucket.Count) findings</div></div>$($cards -join "`n")</section>") | Out-Null
    }

    $css = Get-EntraMainCss
    $js  = Get-EntraMainJs
    $nav = Get-EntraPrimaryNav 'audit'

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Audit - Results</title>
$css
</head>
<body data-theme="light">
<div class="container">
$nav
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>Microsoft Entra ID Audit Results</h1>
        <div class="meta">
          Tenant: <span class="mono">$(HtmlEncode $TenantName)</span><br>
          Generated: $(HtmlEncode $GeneratedOn)<br>
          $Subtitle<br>
          Read-only audit &mdash; no changes were made to the tenant. Raw evidence is written to the <span class="mono">Raw Data\Source</span> folder.
        </div>
      </div>
      <div class="hero-actions">
        <button type="button" class="theme-toggle" id="themeToggle">Dark mode</button>
        <div class="meta">Total findings: <b>$total</b><br>Executive view: <a href="Risk-Report.html">Risk-Report.html</a></div>
      </div>
    </div>
    <div class="metrics">$($countCards -join "`n")</div>
  </section>
  <div class="layout">
    <aside class="sidebar">
      <h3>Navigate</h3>
      <ul>
        <li><a href="#priority-actions">Priority actions</a></li>
        <li><a href="#section-critical">Critical findings</a></li>
        <li><a href="#section-high">High findings</a></li>
        <li><a href="#section-medium">Medium findings</a></li>
        <li><a href="#section-low">Low findings</a></li>
        <li><a href="#section-information">Information</a></li>
      </ul>
      <div class="index-group"><h4>Finding index</h4>$($indexHtml -join "`n")</div>
    </aside>
    <main class="content">
      <section class="priority" id="priority-actions">
        <div class="section-header"><h2>Priority actions</h2><div class="section-count">Highest-severity findings first</div></div>
        <ul>$($priorityHtml -join "`n")</ul>
      </section>
      <section class="toolbar">
        <div class="toolbar-row">
          <div class="filter"><label for="severityFilter">Severity</label>
            <select id="severityFilter"><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Information</option></select></div>
          <div class="filter"><label for="searchFilter">Search</label><input id="searchFilter" type="text" placeholder="Search findings, evidence, category"></div>
          <div class="filter"><label>Visible findings</label><input type="text" value="$total" id="visibleFindings" readonly></div>
        </div>
      </section>
      $($sectionHtml -join "`n")
    </main>
  </div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
}

function Write-EntraRiskReport {
    param([string]$Path, [object[]]$Items, [hashtable]$Counts, [string]$TenantName, [string]$GeneratedOn, [pscustomobject]$Score, [hashtable]$Stats)

    $bandClass = Get-BandBadgeClass $Score.Band
    $bands = @(
        [pscustomobject]@{ Level='Excellent'; Range='90 - 100'; Meaning='Best-practice posture; no Critical or High findings. Maintain and monitor.' }
        [pscustomobject]@{ Level='Good';      Range='75 - 89';  Meaning='Minor gaps, mostly Low/Medium. Address during routine maintenance.' }
        [pscustomobject]@{ Level='Fair';      Range='50 - 74';  Meaning='Material High findings to remediate in the next hardening cycle.' }
        [pscustomobject]@{ Level='Poor';      Range='25 - 49';  Meaning='High/Critical exposure; prompt action with assigned owners.' }
        [pscustomobject]@{ Level='Critical';  Range='0 - 24';   Meaning='Multiple Critical findings; likely active risk. Treat as a priority workstream.' }
    )
    $matrixRows = foreach ($b in $bands) {
        $cls = if ($b.Level -eq $Score.Band) { "matrix-row active sev-$(Get-BandBadgeClass $b.Level)" } else { "matrix-row sev-$(Get-BandBadgeClass $b.Level)" }
        "<tr class='$cls'><td><span class='pill sev-$(Get-BandBadgeClass $b.Level)'>$($b.Level)</span></td><td class='mono'>$($b.Range)</td><td>$(HtmlEncode $b.Meaning)</td></tr>"
    }

    $sorted = $Items | Sort-Object @{e={Get-SeverityRank $_.Severity};Descending=$true}, Title
    $tableRows = foreach ($f in $sorted) {
        $sev = Normalize-Severity $f.Severity
        $href = Resolve-SourceHref $f.SourceFile
        $detail = if ($href) { "<a href='$(HtmlAttrEncode $href)' target='_blank'><span class='mono'>Evidence</span></a>" } else { "<a href='EntraAudit-Results.html#$(New-FindingAnchor $f)'><span class='mono'>Details</span></a>" }
        "<tr data-sev='$sev'><td><span class='pill sev-$sev'>$sev</span></td><td class='title'>$(HtmlEncode $f.Title)</td><td class='evidence'>$(HtmlEncode $f.Evidence)</td><td class='source'>$detail</td></tr>"
    }

    # top risks roll-up (the Critical-driving findings)
    $topRisks = @($Items | Where-Object { (Normalize-Severity $_.Severity) -eq 'Critical' } | Sort-Object Title | Select-Object -First 8)
    $topHtml = if ($topRisks.Count -gt 0) {
        ($topRisks | ForEach-Object { "<li><span class='pill sev-Critical'>Critical</span> $(HtmlEncode $_.Title)</li>" }) -join "`n"
    } else { '<li>No Critical findings - no tenant-takeover-class risks identified.</li>' }

    $catGroups = $Items | ForEach-Object { [pscustomobject]@{ Category=$_.Category; Severity=(Normalize-Severity $_.Severity) } } |
        Group-Object Category | Sort-Object Name
    $catRows = foreach ($cg in $catGroups) {
        $cc=@($cg.Group|?{$_.Severity -eq 'Critical'}).Count; $ch=@($cg.Group|?{$_.Severity -eq 'High'}).Count
        $cm=@($cg.Group|?{$_.Severity -eq 'Medium'}).Count; $cl=@($cg.Group|?{$_.Severity -eq 'Low'}).Count
        "<tr><td>$(HtmlEncode $cg.Name)</td><td style='text-align:center'>$(if($cc){"<span class='pill sev-Critical'>$cc</span>"}else{'-'})</td><td style='text-align:center'>$(if($ch){"<span class='pill sev-High'>$ch</span>"}else{'-'})</td><td style='text-align:center'>$(if($cm){"<span class='pill sev-Medium'>$cm</span>"}else{'-'})</td><td style='text-align:center'>$(if($cl){"<span class='pill sev-Low'>$cl</span>"}else{'-'})</td><td style='text-align:center;font-weight:700'>$($cg.Count)</td></tr>"
    }

    $css = Get-EntraRiskCss
    $js  = Get-EntraRiskJs
    $nav = Get-EntraPrimaryNav 'risk'

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Audit - Risk Report</title>
$css
</head>
<body>
<div class="container">
$nav
  <div class="header">
    <div class="h-title">
      <div>
        <h1>Microsoft Entra ID Audit - Risk Report</h1>
        <div class="meta">Tenant: <span class="mono">$(HtmlEncode $TenantName)</span> | Generated: $(HtmlEncode $GeneratedOn) | <a href="EntraAudit-Results.html">Detailed findings</a></div>
        <div class="meta" style="margin-top:4px">$($script:Version) | Auth: <span class="mono">$($script:AuthType)</span> | Licensing: P1=$($script:HasP1) P2=$($script:HasP2)</div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:10px">
        <button id="themeToggle" type="button" class="theme-toggle">Toggle theme</button>
        <div class="badge $bandClass">
          <div><div class="grade">Overall Risk</div><div class="value">$($Score.Band)</div></div>
          <div style="width:1px;height:28px;background:var(--line)"></div>
          <div><div class="grade">Score</div><div class="value">$($Score.Score) / 100</div></div>
        </div>
      </div>
    </div>
    <div class="grid">
      <div class="card span-3"><div class="k">Critical</div><div class="v">$($Counts.Critical)</div><div class="s">Immediate remediation</div></div>
      <div class="card span-3"><div class="k">High</div><div class="v">$($Counts.High)</div><div class="s">Prioritize</div></div>
      <div class="card span-3"><div class="k">Medium</div><div class="v">$($Counts.Medium)</div><div class="s">Plan hardening</div></div>
      <div class="card span-3"><div class="k">Low</div><div class="v">$($Counts.Low)</div><div class="s">Maintain baseline</div></div>
      <div class="card span-4"><div class="k">Users</div><div class="v">$($Stats.Users)</div><div class="s">Directory members + guests</div></div>
      <div class="card span-4"><div class="k">Guests</div><div class="v">$($Stats.Guests)</div><div class="s">External identities</div></div>
      <div class="card span-4"><div class="k">Applications</div><div class="v">$($Stats.Apps)</div><div class="s">App registrations</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Top risks</h2>
    <div class="callout"><ul>$topHtml</ul></div>
  </div>

  <div class="section">
    <h2>Interpretation</h2>
    <div class="callout">
      <p><b>Score:</b> the report starts at 100 and deducts per finding by severity (with caps); any Critical finding caps the score at 49. The current score is <b>$($Score.Score)/100</b> (<b>$($Score.Band)</b>).</p>
      <div class="matrix-wrap"><br>
        <table class="matrix"><thead><tr><th>Band</th><th>Score range</th><th>Interpretation</th></tr></thead><tbody>$($matrixRows -join "`n")</tbody></table>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>Findings by category</h2>
    <table><thead><tr><th style="text-align:left">Category</th><th style="text-align:center">Critical</th><th style="text-align:center">High</th><th style="text-align:center">Medium</th><th style="text-align:center">Low</th><th style="text-align:center">Total</th></tr></thead><tbody>$($catRows -join "`n")</tbody></table>
  </div>

  <div class="section">
    <h2>Findings</h2>
    <div class="toolbar">
      <div class="filters">
        <label><small>Severity</small><br><select id="sevFilter"><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Information</option></select></label>
        <label><small>Search</small><br><input id="search" type="text" placeholder="Search title/evidence..."></label>
      </div>
      <div><small>Visible: <span id="visibleCount">0</span> / $(@($Items).Count)</small></div>
    </div>
    <table id="findings"><thead><tr><th data-sort="severity">Severity</th><th data-sort="title">Finding</th><th>Evidence</th><th>Details</th></tr></thead><tbody id="findings-body">$($tableRows -join "`n")</tbody></table>
  </div>

  <div class="footer">Generated by $($script:Version) &mdash; read-only Microsoft Graph audit. This score is an index based on the findings in this report; validate scope and license coverage (P1/P2-gated checks may be skipped).</div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
}

function Write-PostureSummaryReport {
    param([string]$Path, [string]$TenantName, [string]$GeneratedOn, [hashtable]$Stats)

    $statusRows = foreach ($k in $script:CheckStatus.Keys) {
        $s = $script:CheckStatus[$k]
        $cls = switch -Regex ($s.Status) { '^Pass' {'ok'} '^Findings' {'find'} '^Skipped' {'skip'} '^Error' {'err'} default {'skip'} }
        "<tr><td class='mono'>$(HtmlEncode $k)</td><td>$(HtmlEncode $s.Title)</td><td><span class='pill $cls'>$(HtmlEncode $s.Status)</span></td></tr>"
    }
    $pass = @($script:CheckStatus.Values | Where-Object { $_.Status -eq 'Pass' }).Count
    $withFindings = @($script:CheckStatus.Values | Where-Object { $_.Status -like 'Findings*' }).Count
    $skipped = @($script:CheckStatus.Values | Where-Object { $_.Status -like 'Skipped*' }).Count
    $errored = @($script:CheckStatus.Values | Where-Object { $_.Status -eq 'Error' }).Count

    $css = Get-EntraRiskCss
    $nav = Get-EntraPrimaryNav 'posture'
    $js  = Get-EntraRiskJs2

    $licNote = @()
    if (-not $script:HasP2) { $licNote += 'Entra ID P2 not detected - PIM eligibility, Identity Protection (risky users) and risk-based checks may be license-gated.' }
    if (-not $script:HasP1) { $licNote += 'Entra ID P1 not detected - sign-in activity (stale users / legacy auth) may be unavailable.' }
    $licHtml = if ($licNote.Count -gt 0) { '<ul>' + (($licNote | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join '') + '</ul>' } else { '<p>Premium licensing (P1/P2) detected - all checks available.</p>' }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Audit - Posture Summary</title>
$css
</head>
<body>
<div class="container">
$nav
  <div class="header">
    <div class="h-title">
      <div>
        <h1>Microsoft Entra ID Audit - Posture Summary</h1>
        <div class="meta">Tenant: <span class="mono">$(HtmlEncode $TenantName)</span> | Generated: $(HtmlEncode $GeneratedOn) | Auth: <span class="mono">$($script:AuthType)</span></div>
        <div class="meta" style="margin-top:4px">Licensing: P1=$($script:HasP1) | P2=$($script:HasP2) | Workload Identities Premium=$($script:WorkloadIdP)</div>
      </div>
      <button id="themeToggle" type="button" class="theme-toggle">Toggle theme</button>
    </div>
    <div class="grid">
      <div class="card span-3"><div class="k">Checks passed</div><div class="v">$pass</div><div class="s">No findings</div></div>
      <div class="card span-3"><div class="k">With findings</div><div class="v">$withFindings</div><div class="s">Action needed</div></div>
      <div class="card span-3"><div class="k">Skipped</div><div class="v">$skipped</div><div class="s">No scope / license</div></div>
      <div class="card span-3"><div class="k">Errored</div><div class="v">$errored</div><div class="s">See console</div></div>
      <div class="card span-4"><div class="k">Users</div><div class="v">$($Stats.Users)</div><div class="s">Members + guests</div></div>
      <div class="card span-4"><div class="k">Guests</div><div class="v">$($Stats.Guests)</div><div class="s">External</div></div>
      <div class="card span-4"><div class="k">Applications</div><div class="v">$($Stats.Apps)</div><div class="s">App registrations</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Licensing &amp; coverage</h2>
    <div class="callout">$licHtml<p style="margin-top:8px"><small>Skipped checks are coverage gaps, not clean results.</small></p></div>
  </div>

  <div class="section">
    <h2>Checks performed</h2>
    <table><thead><tr><th style="text-align:left">Check</th><th style="text-align:left">Title</th><th style="text-align:left">Status</th></tr></thead><tbody>$($statusRows -join "`n")</tbody></table>
  </div>

  <div class="footer">Generated by $($script:Version) &mdash; read-only Microsoft Graph audit.</div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
}

function Write-RawDataIndexReport {
    param([string]$Path, [string]$TenantName, [string]$GeneratedOn)
    $css = Get-EntraMainCss
    $nav = Get-EntraPrimaryNav 'raw'
    $js  = Get-EntraRawJs
    $rows = foreach ($d in $script:RawDatasets) {
        "<tr><td>$(HtmlEncode $d.Title)</td><td class='mono'>$(HtmlEncode $d.BaseName)</td><td style='text-align:right'>$($d.Rows)</td><td><a href='$(HtmlAttrEncode $d.HtmlHref)'>HTML</a> &middot; <a href='$(HtmlAttrEncode $d.CsvHref)' download>CSV</a> &middot; <a href='$(HtmlAttrEncode $d.TxtHref)' download>TXT</a></td></tr>"
    }
    $total = @($script:RawDatasets).Count
    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Audit - Raw Data</title>
$css
</head>
<body data-theme="light">
<div class="container">
$nav
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>Raw Data &mdash; Evidence Index</h1>
        <div class="meta">
          Tenant: <span class="mono">$(HtmlEncode $TenantName)</span><br>
          Generated: $(HtmlEncode $GeneratedOn)<br>
          Every check writes its full evidence as CSV (data), TXT (plain) and a styled HTML table. $total dataset(s) below.
        </div>
      </div>
      <div class="hero-actions"><button type="button" class="theme-toggle" id="themeToggle">Dark mode</button></div>
    </div>
  </section>
  <section class="toolbar"><div class="toolbar-row"><div class="filter"><label for="rawSearch">Filter datasets</label><input id="rawSearch" type="text" placeholder="Type to filter..."></div></div></section>
  <table class="status-table result-table">
    <thead><tr><th>Dataset</th><th>File</th><th style="text-align:right">Rows</th><th>Open / download</th></tr></thead>
    <tbody>
      $($rows -join "`n")
    </tbody>
  </table>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
}

# Posture page needs only the theme toggle (no findings table) - reuse a trimmed JS.
function Get-EntraRiskJs2 {
@'
<script>
(function(){
  function q(s){return document.querySelector(s);}
  function currentTheme(){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(e){}if(s==='light'||s==='dark')return s;if(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)return 'dark';return 'light';}
  function applyTheme(t){document.documentElement.setAttribute('data-theme',t);var b=q('#themeToggle');if(b){b.innerText=(t==='dark')?'Light mode':'Dark mode';}try{localStorage.setItem('entraaudit-theme',t);}catch(e){}}
  applyTheme(currentTheme());
  var tb=q('#themeToggle');if(tb){tb.addEventListener('click',function(){var n=(document.documentElement.getAttribute('data-theme')==='dark')?'light':'dark';applyTheme(n);});}
})();
</script>
'@
}

# ===========================================================================
# CHECK REGISTRY + MAIN
# ===========================================================================
$script:Registry = [ordered]@{
    'tenant-info'      = @{ Func='Invoke-Check-TenantInfo';     Title='Tenant / Organization Overview';        Scopes=@('Organization.Read.All') }
    'privileged-roles' = @{ Func='Invoke-Check-PrivRoles';      Title='Privileged Roles - Permanent vs Eligible'; Scopes=@('RoleManagement.Read.Directory') }
    'directory-roles'  = @{ Func='Invoke-Check-DirectoryRoles'; Title='Privileged Assignment Volume';           Scopes=@('RoleManagement.Read.Directory') }
    'accounts'         = @{ Func='Invoke-Check-Accounts';       Title='Account Hygiene';                        Scopes=@('User.Read.All') }
    'staleusers'       = @{ Func='Invoke-Check-StaleUsers';     Title='Stale / Inactive Users';                 Scopes=@('User.Read.All','AuditLog.Read.All'); P1=$true }
    'guests'           = @{ Func='Invoke-Check-Guests';         Title='Guest / External Governance';            Scopes=@('User.Read.All') }
    'mfa'              = @{ Func='Invoke-Check-Mfa';            Title='MFA Capability & Method Strength';       Scopes=@('AuditLog.Read.All') }
    'legacyauth'       = @{ Func='Invoke-Check-LegacyAuth';     Title='Legacy Authentication Usage';            Scopes=@('AuditLog.Read.All'); P1=$true }
    'tenantposture'    = @{ Func='Invoke-Check-TenantPosture';  Title='Security Defaults & Consent Settings';   Scopes=@('Policy.Read.All') }
    'capolicies'       = @{ Func='Invoke-Check-CAPolicies';     Title='Conditional Access Posture';             Scopes=@('Policy.Read.All') }
    'riskyusers'       = @{ Func='Invoke-Check-RiskyUsers';     Title='Identity Protection (Risky Users)';      Scopes=@('IdentityRiskyUser.Read.All'); P2=$true }
    'apps'             = @{ Func='Invoke-Check-Apps';           Title='App / Service Principal Hygiene';        Scopes=@('Application.Read.All') }
    'consentgrants'    = @{ Func='Invoke-Check-ConsentGrants';  Title='OAuth2 Consent Grants';                  Scopes=@('DelegatedPermissionGrant.Read.All') }
    'devices'          = @{ Func='Invoke-Check-Devices';        Title='Stale / Unmanaged Devices';              Scopes=@('Device.Read.All') }
    'trusts'           = @{ Func='Invoke-Check-Trusts';         Title='Cross-Tenant Access & B2B Trust';        Scopes=@('Policy.Read.All') }
    'recentchanges'    = @{ Func='Invoke-Check-RecentChanges';  Title='Recently Created Users / Groups';        Scopes=@('User.Read.All','AuditLog.Read.All') }
    'tenanthealth'     = @{ Func='Invoke-Check-TenantHealth';   Title='Directory-Sync / PHS Health';            Scopes=@('Organization.Read.All') }
    'pimpolicies'      = @{ Func='Invoke-Check-PimPolicies';    Title='PIM Role-Management Policy Quality';     Scopes=@('RoleManagementPolicy.Read.Directory'); P2=$true }
    'breakglass'       = @{ Func='Invoke-Check-BreakGlass';     Title='Emergency-Access (Break-Glass) Health';  Scopes=@('User.Read.All','RoleManagement.Read.Directory') }
    'authmethodpolicy' = @{ Func='Invoke-Check-AuthMethodPolicy'; Title='Authentication Methods Policy';        Scopes=@('Policy.Read.All') }
    'accesspaths'      = @{ Func='Invoke-Check-AccessPaths';    Title='Effective Access / Attack Paths';        Scopes=@('RoleManagement.Read.Directory','Group.Read.All') }
}

$script:AppCount = '-'

function Invoke-EntraAudit {
    Write-Host ""
    Write-Host "  $($script:Version) - read-only Microsoft Entra ID security audit" -ForegroundColor White
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor DarkGray

    # Map check id -> its individual -switch value
    $individual = [ordered]@{
        'tenant-info'=$tenantinfo; 'privileged-roles'=$privroles; 'directory-roles'=$directoryroles;
        'accounts'=$accounts; 'staleusers'=$staleusers; 'guests'=$guests; 'mfa'=$mfa; 'legacyauth'=$legacyauth;
        'tenantposture'=$tenantposture; 'capolicies'=$capolicies; 'riskyusers'=$riskyusers; 'apps'=$apps;
        'consentgrants'=$consentgrants; 'devices'=$devices; 'trusts'=$trusts; 'recentchanges'=$recentchanges;
        'tenanthealth'=$tenanthealth; 'pimpolicies'=$pimpolicies; 'breakglass'=$breakglass;
        'authmethodpolicy'=$authmethodpolicy; 'accesspaths'=$accesspaths
    }
    $anySelected = $all -or ($select -and $select.Count) -or (@($individual.Values | Where-Object { $_ }).Count -gt 0)

    if ($installdeps) {
        Install-EntraModules
        if (-not $anySelected) { Write-Good "Dependencies installed. Re-run with -all (or specific checks) to audit."; return }
    }

    Import-EntraModules

    # Decide which checks to run. -select/-exclude accept both registry ids
    # (privileged-roles) and switch-style aliases (privroles, the form the GUI emits),
    # comma- or semicolon-separated.
    if ($select -and $select.Count) {
        $sel = Resolve-CheckIds -Values $select
        $toRun = @($script:Registry.Keys | Where-Object { $sel -contains $_ })
    } elseif ($all -or -not $anySelected) {
        $exc = if ($exclude) { Resolve-CheckIds -Values $exclude } else { @() }
        $toRun = @($script:Registry.Keys | Where-Object { $exc -notcontains $_ })
    } else {
        $toRun = @($script:Registry.Keys | Where-Object { $individual[$_] })
    }
    if ($toRun.Count -eq 0) { Write-Err2 "No checks selected."; return }

    # Connect (read-only)
    $ctx = Connect-EntraAuditGraph

    # Tenant + license detection
    try { $script:Tenant = Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}
    # License detection from enabled SERVICE PLANS (not just SKU part number) - many
    # tenants get Entra P1/P2 bundled inside other SKUs (e.g. EMS, M365 E3/E5).
    try {
        foreach ($sku in @(Get-MgSubscribedSku -All -ErrorAction SilentlyContinue)) {
            $enabledPlans = @($sku.ServicePlans | Where-Object { $_.ProvisioningStatus -eq 'Success' } | ForEach-Object { $_.ServicePlanName })
            if ($sku.SkuPartNumber -eq 'AAD_PREMIUM_P2' -or $enabledPlans -contains 'AAD_PREMIUM_P2') { $script:HasP2 = $true }
            if ($sku.SkuPartNumber -eq 'AAD_PREMIUM'    -or $enabledPlans -contains 'AAD_PREMIUM')    { $script:HasP1 = $true }
            if ($enabledPlans -match 'WorkloadIdentit') { $script:WorkloadIdP = $true }
        }
        if ($script:HasP2) { $script:HasP1 = $true }
    } catch {}

    $tenantName = if ($script:Tenant -and $script:Tenant.DisplayName) { $script:Tenant.DisplayName } else { [string]$ctx.TenantId }
    Write-Good ("Tenant: {0} | Licensing P1={1} P2={2}" -f $tenantName, $script:HasP1, $script:HasP2)

    # Output folders (mirrors the AD audit layout)
    $safeTenant = ((($tenantName -replace '[^\w\.\- ]','_')).Trim()) -replace '\s+','_'
    if ([string]::IsNullOrWhiteSpace($safeTenant)) { $safeTenant = 'tenant' }
    $ts = Get-Date -Format 'yyyyMMdd-HHmm'
    $root = if ($OutputRoot) { $OutputRoot } else { $PSScriptRoot }
    $script:RunRoot = Join-Path $root ("{0}-EntraAudit-{1}" -f $safeTenant, $ts)
    $script:HtmlDir = Join-Path $script:RunRoot 'HTML Reports'
    $script:RawDir  = Join-Path $script:RunRoot 'Raw Data\Source'
    New-Item -ItemType Directory -Force -Path $script:HtmlDir | Out-Null
    New-Item -ItemType Directory -Force -Path $script:RawDir  | Out-Null

    # Run the selected checks
    Write-Host ""
    Write-Info ("Running {0} check(s)..." -f $toRun.Count)
    foreach ($id in $toRun) {
        $c = $script:Registry[$id]
        Invoke-AuditCheck -CheckId $id -Title $c.Title -Scopes $c.Scopes -NeedP1:([bool]$c.P1) -NeedP2:([bool]$c.P2) -Action ([scriptblock]::Create($c.Func))
    }

    # Build reports
    Write-Host ""
    Write-Info "Generating reports..."
    $counts = @{ Critical=0; High=0; Medium=0; Low=0; Information=0 }
    foreach ($f in $script:Findings) { $counts[(Normalize-Severity $f.Severity)]++ }
    $score = Get-EntraRiskScore $script:Findings
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'

    $stats = @{
        Users  = if ($script:UsersCache) { @($script:UsersCache).Count } else { '-' }
        Guests = if ($script:UsersCache) { @($script:UsersCache | Where-Object { $_.UserType -eq 'Guest' }).Count } else { '-' }
        Apps   = $script:AppCount
    }
    $subtitle = ("Read-only Microsoft Graph audit &mdash; {0} check(s) | overall risk: {1} ({2}/100)" -f $toRun.Count, $score.Band, $score.Score)

    $resultsPath = Join-Path $script:HtmlDir 'EntraAudit-Results.html'
    $riskPath    = Join-Path $script:HtmlDir 'Risk-Report.html'
    $posturePath = Join-Path $script:HtmlDir 'Posture-Summary.html'

    Write-EntraResultsReport -Path $resultsPath -Items $script:Findings.ToArray() -Counts $counts -TenantName $tenantName -GeneratedOn $now -Subtitle $subtitle
    Write-EntraRiskReport    -Path $riskPath    -Items $script:Findings.ToArray() -Counts $counts -TenantName $tenantName -GeneratedOn $now -Score $score -Stats $stats
    Write-PostureSummaryReport -Path $posturePath -TenantName $tenantName -GeneratedOn $now -Stats $stats
    Write-RawDataIndexReport -Path (Join-Path $script:HtmlDir 'Raw-Data.html') -TenantName $tenantName -GeneratedOn $now

    # Machine-readable exports (automation / trend comparison) with a stable finding id.
    $tenantId = [string]$ctx.TenantId
    $exportRows = foreach ($f in $script:Findings) {
        [pscustomobject]@{
            FindingId         = (New-FindingKey -TenantId $tenantId -CheckId $f.CheckId -Title $f.Title -AffectedPrincipal $f.AffectedPrincipal)
            Severity          = $f.Severity
            Category          = $f.Category
            CheckId           = $f.CheckId
            Title             = $f.Title
            AffectedPrincipal = $f.AffectedPrincipal
            Evidence          = $f.Evidence
            WhyItMatters      = $f.WhyItMatters
            RecommendedAction = $f.RecommendedAction
            SourceFile        = $f.SourceFile
        }
    }
    try {
        @($exportRows) | Export-Csv -LiteralPath (Join-Path $script:RunRoot 'Findings.csv') -NoTypeInformation -Encoding UTF8
        @($exportRows) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $script:RunRoot 'Findings.json') -Encoding UTF8
    } catch { Write-Warn2 "Could not write Findings.json/csv: $($_.Exception.Message)" }

    # Summary
    Write-Host ""
    Write-Good "Audit complete."
    Write-Host ("  Overall risk : {0} ({1}/100)" -f $score.Band, $score.Score) -ForegroundColor White
    Write-Host ("  Findings     : Critical={0} High={1} Medium={2} Low={3} Info={4}" -f $counts.Critical,$counts.High,$counts.Medium,$counts.Low,$counts.Information)
    Write-Host ("  Reports      : {0}" -f $script:HtmlDir)
    Write-Host ("  Raw evidence : {0}" -f $script:RawDir)

    if (-not $NoLaunch) {
        try { Invoke-Item $resultsPath -ErrorAction SilentlyContinue } catch {}
    }
}

# ===========================================================================
# Entry point
# ===========================================================================
try {
    Invoke-EntraAudit
} catch {
    Write-Err2 "Audit failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
} finally {
    try {
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
            if (Get-MgContext) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null; Write-Info "Disconnected from Microsoft Graph." }
        }
    } catch {}
}




