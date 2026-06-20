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
    'UserAuthenticationMethod.Read.All'
    'DelegatedPermissionGrant.Read.All'
    'Device.Read.All'
    'IdentityRiskyUser.Read.All'
    'IdentityRiskEvent.Read.All'
    'IdentityRiskyServicePrincipal.Read.All'
    'CrossTenantInformation.ReadBasic.All'
    'OnPremDirectorySynchronization.Read.All'
    'Reports.Read.All'
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

# Writes tabular evidence to CSV + a readable TXT header; returns the relative
# href (from HTML Reports\) so findings can link to their source file.
function Write-Evidence {
    param(
        [string]$BaseName,          # e.g. 'privileged_roles'
        [object[]]$Rows,
        [string]$Title,
        [string[]]$Notes
    )
    $rel = $null
    try {
        $csvPath = Join-Path $script:RawDir ($BaseName + '.csv')
        $txtPath = Join-Path $script:RawDir ($BaseName + '.txt')

        $header = @()
        $header += $Title
        $header += ('Generated: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'))
        if ($Notes) { $Notes | ForEach-Object { $header += $_ } }
        $header += ('Rows: {0}' -f (@($Rows).Count))
        $header += ''

        if ($Rows -and @($Rows).Count -gt 0) {
            @($Rows) | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
            $table = @($Rows) | Format-Table -AutoSize | Out-String -Width 4096
            Set-Content -LiteralPath $txtPath -Value (($header -join "`r`n") + "`r`n" + $table) -Encoding UTF8
        } else {
            $header += '(no matching objects)'
            Set-Content -LiteralPath $txtPath -Value ($header -join "`r`n") -Encoding UTF8
        }
        # Reports live in HTML Reports\, raw data in Raw Data\Source\
        $rel = '../Raw Data/Source/' + (Split-Path $txtPath -Leaf)
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

    Write-Good ("Connected. Auth: {0} | Tenant: {1} | Account: {2}" -f $script:AuthType, $ctx.TenantId, ($ctx.Account ?? $ctx.AppName))
    return $ctx
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
    if ($NeedP2 -and -not $script:HasP2) {
        Write-Warn2 "  (license-gated: Entra ID P2 not detected - attempting anyway, results may be empty)"
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
               'OnPremisesSyncEnabled','CreatedDateTime')
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

    $bg = @(); if ($BreakGlassUpns) { $bg = @($BreakGlassUpns | ForEach-Object { $_.ToLowerInvariant() }) }
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
    $cut = (Get-Date).ToUniversalTime().AddDays(-$InactiveDays)
    $cut180 = (Get-Date).ToUniversalTime().AddDays(-180)
    $created30 = (Get-Date).ToUniversalTime().AddDays(-30)

    $rows = @()
    foreach ($u in $users) {
        if ($u.UserType -eq 'Guest') { continue }
        $sa = $u.SignInActivity
        $last = $null
        if ($sa) {
            $cands = @($sa.LastSignInDateTime, $sa.LastNonInteractiveSignInDateTime) | Where-Object { $_ }
            if ($cands) { $last = ($cands | Sort-Object -Descending | Select-Object -First 1) }
        }
        $rows += [pscustomobject]@{
            UserPrincipalName=$u.UserPrincipalName; Enabled=$u.AccountEnabled; Created=$u.CreatedDateTime
            LastSignIn=$last; NeverSignedIn=($null -eq $last)
        }
    }
    $src = Write-Evidence -BaseName 'stale_users' -Rows $rows -Title ("Stale / Inactive Users (> {0} days)" -f $InactiveDays)

    $never = @($rows | Where-Object { $_.NeverSignedIn -and $_.Enabled -and $_.Created -and $_.Created -lt $created30 })
    $stale = @($rows | Where-Object { -not $_.NeverSignedIn -and $_.Enabled -and $_.LastSignIn -lt $cut })
    $stale180 = @($stale | Where-Object { $_.LastSignIn -lt $cut180 })

    if ($stale.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'staleusers' -Category 'Identity Hygiene' `
            -Title ("{0} enabled account(s) inactive > {1} days" -f $stale.Count, $InactiveDays) `
            -Evidence ("{0} enabled users have not signed in for over {1} days ({2} over 180 days)." -f $stale.Count, $InactiveDays, $stale180.Count) `
            -WhyItMatters 'Inactive but enabled accounts are prime password-spray targets and usually fall outside normal monitoring. Mirrors the AD inactive-account review.' `
            -RecommendedAction 'Disable accounts inactive beyond the threshold after confirmation, and delete after a retention window. Use non-interactive sign-in to avoid false-positiving service-style accounts.' `
            -SourceFile $src -ResultRows @($stale | Select-Object UserPrincipalName,LastSignIn,Enabled | Sort-Object LastSignIn)
    }
    if ($never.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'staleusers' -Category 'Identity Hygiene' `
            -Title ("{0} enabled account(s) have never signed in" -f $never.Count) `
            -Evidence ("{0} enabled accounts older than 30 days with no recorded sign-in." -f $never.Count) `
            -WhyItMatters 'Never-used accounts indicate provisioning errors or dormant accounts that can be used as backdoors.' `
            -RecommendedAction 'Verify each never-signed-in account is required; disable and remove the unneeded ones.' `
            -SourceFile $src -ResultRows @($never | Select-Object UserPrincipalName,Created)
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
        @{n='ExternalUserState';e={ (Get-Ap $_ 'externalUserState') }}
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
    $staleGuests = @($guestUsers | Where-Object { (Get-Ap $_ 'externalUserState') -eq 'PendingAcceptance' })
    if ($staleGuests.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'guests' -Category 'External Access' `
            -Title ("{0} guest invitation(s) never redeemed" -f $staleGuests.Count) `
            -Evidence ("PendingAcceptance guests: {0}" -f $staleGuests.Count) `
            -WhyItMatters 'Never-redeemed guest objects are clutter that can hide stale external access.' `
            -RecommendedAction 'Remove guest objects whose invitations were never accepted after a reasonable window.' `
            -SourceFile $src -ResultRows @($staleGuests | Select-Object UserPrincipalName,CreatedDateTime)
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

    $rows = $reg | Select-Object UserPrincipalName, IsAdmin, IsMfaCapable, IsMfaRegistered, IsSsprRegistered,
        @{n='Methods';e={ ($_.MethodsRegistered -join ',') }}
    $src = Write-Evidence -BaseName 'mfa_registration' -Rows $rows -Title 'MFA Capability & Authentication Method Strength'

    $adminNoMfa = @($reg | Where-Object { ($_.IsAdmin -or ($_.Id -and $privIds.ContainsKey($_.Id))) -and -not $_.IsMfaCapable })
    $weak = @($reg | Where-Object { ($_.IsAdmin -or ($_.Id -and $privIds.ContainsKey($_.Id))) -and $_.IsMfaCapable -and `
        -not (@($_.MethodsRegistered) | Where-Object { $_ -match 'fido2|windowsHelloForBusiness|passwordless|microsoftAuthenticator' }) })
    $memberNoMfa = @($reg | Where-Object { -not $_.IsAdmin -and -not $_.IsMfaCapable })

    if ($adminNoMfa.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId 'mfa' -Category 'Authentication' `
            -Title ("{0} privileged account(s) are NOT MFA-capable" -f $adminNoMfa.Count) `
            -Evidence ("Admins without MFA capability: {0}" -f (($adminNoMfa | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'An admin that is not MFA-capable is effectively password-only and cannot be challenged - the single highest-value credential-theft target in the tenant.' `
            -RecommendedAction 'Require phishing-resistant MFA (FIDO2 / Windows Hello / passwordless) for every privileged account before any standing or eligible role use.' `
            -SourceFile $src -ResultRows @($adminNoMfa | Select-Object UserPrincipalName,IsAdmin,IsMfaCapable)
    }
    if ($weak.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'mfa' -Category 'Authentication' `
            -Title ("{0} privileged account(s) rely on weak MFA methods only" -f $weak.Count) `
            -Evidence ("Admins with only weak methods (SMS/voice/email): {0}" -f (($weak | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'SMS/voice/email factors are phishable and SIM-swappable; admins need phishing-resistant methods.' `
            -RecommendedAction 'Register FIDO2 / Windows Hello for Business / passwordless for privileged users and retire SMS/voice as a primary factor.' `
            -SourceFile $src -ResultRows @($weak | Select-Object UserPrincipalName,@{n='Methods';e={$_.MethodsRegistered -join ','}})
    }
    if ($memberNoMfa.Count -gt 0) {
        $sev = if ($reg.Count -gt 0 -and ($memberNoMfa.Count / [double]$reg.Count) -gt 0.25) { 'Medium' } else { 'Low' }
        Add-EntraFinding -Severity $sev -CheckId 'mfa' -Category 'Authentication' `
            -Title ("{0} non-admin account(s) are not MFA-capable" -f $memberNoMfa.Count) `
            -Evidence ("Members without MFA capability: {0} of {1} reported." -f $memberNoMfa.Count, $reg.Count) `
            -WhyItMatters 'Accounts that cannot be MFA-challenged are password-only and vulnerable to spray and replay.' `
            -RecommendedAction 'Drive MFA registration / capability to 100% for enabled members via registration campaigns and Conditional Access.' `
            -SourceFile $src
    }
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
        ($_.GrantControls.BuiltInControls -contains 'mfa') -and
        ($_.Conditions.Users.IncludeRoles -and @($_.Conditions.Users.IncludeRoles).Count -gt 0)
    }
    $mfaForAll = _Has {
        ($_.GrantControls.BuiltInControls -contains 'mfa') -and
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
    $apps = @(Get-MgApplication -All -ErrorAction Stop)
    $sps  = @(Get-MgServicePrincipal -All -ErrorAction Stop)
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

    # --- over-privileged app-role (application) permissions ---
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    $graphSp = $sps | Where-Object { $_.AppId -eq $graphAppId } | Select-Object -First 1
    $appRoleNameById = @{}
    if ($graphSp) { foreach ($r in @($graphSp.AppRoles)) { $appRoleNameById[$r.Id] = $r.Value } }

    $permRows = @()
    foreach ($sp in $sps) {
        $asn = @()
        try { $asn = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue) } catch {}
        foreach ($x in $asn) {
            $permName = $appRoleNameById[$x.AppRoleId]; if (-not $permName) { $permName = $x.AppRoleId }
            $dangerous = ($permName -in $script:DangerousAppPermissions)
            if ($dangerous) {
                $permRows += [pscustomobject]@{ ServicePrincipal=$sp.DisplayName; AppId=$sp.AppId; Permission=$permName; Resource=$x.ResourceDisplayName }
            }
        }
    }
    $permSrc = Write-Evidence -BaseName 'app_permissions' -Rows $permRows -Title 'Over-Privileged Application Permissions'
    if ($permRows.Count -gt 0) {
        $spNames = @($permRows.ServicePrincipal | Select-Object -Unique)
        Add-EntraFinding -Severity 'Critical' -CheckId 'apps' -Category 'Applications' `
            -Title ("{0} service principal(s) hold tier-0 Graph application permissions" -f $spNames.Count) `
            -Evidence ("Over-privileged apps: {0}" -f (($spNames | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Application permissions need no signed-in user and are fully exercised by a single leaked secret - the cloud equivalent of dangerous directory ACLs plus Kerberoastable service accounts combined. A permission like RoleManagement.ReadWrite.Directory or full mailbox access is a tenant-takeover primitive.' `
            -RecommendedAction 'Remove tier-0 application permissions that are not justified, replace with least-privilege scoped permissions, and rotate the apps to certificate credentials.' `
            -SourceFile $permSrc -ResultRows $permRows
    }

    # --- owners (non-admin owner on a privileged or credentialed app) ---
    $ownerRows = @()
    foreach ($a in $apps) {
        $owners = @(); try { $owners = @(Get-MgApplicationOwner -ApplicationId $a.Id -All -ErrorAction SilentlyContinue) } catch {}
        if (@($a.PasswordCredentials).Count -gt 0 -or @($a.KeyCredentials).Count -gt 0) {
            if ($owners.Count -eq 0) {
                $ownerRows += [pscustomobject]@{ App=$a.DisplayName; Owners='(none)'; Note='Orphaned credentialed app' }
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
# REPORT ENGINE  (HTML/CSS/JS reused verbatim from the AD audit for an
# identical look: light/dark theme, severity badges, filterable finding
# cards, executive risk report with score band matrix.)
# ===========================================================================

function New-FindingAnchor([object]$f) {
    'finding-' + (New-Slug ('{0}-{1}' -f $f.Title, $f.CheckId))
}

function Get-EntraPrimaryNav([string]$Active) {
    $links = @(
        @{ Key='audit';   Href='EntraAudit-Results.html'; Label='Audit Results' }
        @{ Key='risk';    Href='Risk-Report.html';        Label='Risk Report' }
        @{ Key='posture'; Href='Posture-Summary.html';    Label='Posture Summary' }
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
        [void]$sb.Append("<a class='$cls' href='$($l.Href)'>$($l.Label)</a>")
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
    if ($arr.Count -gt $maxRows) { [void]$sb.Append("<div class='result-note'>Showing $maxRows of $($arr.Count) rows. Full data in the linked source file.</div>") }
    $sb.ToString()
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
    'privileged-roles' = @{ Func='Invoke-Check-PrivRoles';      Title='Privileged Roles - Permanent vs Eligible'; Scopes=@('RoleManagement.Read.Directory'); P2=$true }
    'directory-roles'  = @{ Func='Invoke-Check-DirectoryRoles'; Title='Privileged Assignment Volume';           Scopes=@('RoleManagement.Read.Directory') }
    'accounts'         = @{ Func='Invoke-Check-Accounts';       Title='Account Hygiene';                        Scopes=@('User.Read.All') }
    'staleusers'       = @{ Func='Invoke-Check-StaleUsers';     Title='Stale / Inactive Users';                 Scopes=@('User.Read.All','AuditLog.Read.All') }
    'guests'           = @{ Func='Invoke-Check-Guests';         Title='Guest / External Governance';            Scopes=@('User.Read.All') }
    'mfa'              = @{ Func='Invoke-Check-Mfa';            Title='MFA Capability & Method Strength';       Scopes=@('AuditLog.Read.All') }
    'legacyauth'       = @{ Func='Invoke-Check-LegacyAuth';     Title='Legacy Authentication Usage';            Scopes=@('AuditLog.Read.All') }
    'tenantposture'    = @{ Func='Invoke-Check-TenantPosture';  Title='Security Defaults & Consent Settings';   Scopes=@('Policy.Read.All') }
    'capolicies'       = @{ Func='Invoke-Check-CAPolicies';     Title='Conditional Access Posture';             Scopes=@('Policy.Read.All') }
    'riskyusers'       = @{ Func='Invoke-Check-RiskyUsers';     Title='Identity Protection (Risky Users)';      Scopes=@('IdentityRiskyUser.Read.All'); P2=$true }
    'apps'             = @{ Func='Invoke-Check-Apps';           Title='App / Service Principal Hygiene';        Scopes=@('Application.Read.All') }
    'consentgrants'    = @{ Func='Invoke-Check-ConsentGrants';  Title='OAuth2 Consent Grants';                  Scopes=@('DelegatedPermissionGrant.Read.All') }
    'devices'          = @{ Func='Invoke-Check-Devices';        Title='Stale / Unmanaged Devices';              Scopes=@('Device.Read.All') }
    'trusts'           = @{ Func='Invoke-Check-Trusts';         Title='Cross-Tenant Access & B2B Trust';        Scopes=@('Policy.Read.All') }
    'recentchanges'    = @{ Func='Invoke-Check-RecentChanges';  Title='Recently Created Users / Groups';        Scopes=@('User.Read.All','AuditLog.Read.All') }
    'tenanthealth'     = @{ Func='Invoke-Check-TenantHealth';   Title='Directory-Sync / PHS Health';            Scopes=@('Organization.Read.All') }
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
        'tenanthealth'=$tenanthealth
    }
    $anySelected = $all -or ($select -and $select.Count) -or (@($individual.Values | Where-Object { $_ }).Count -gt 0)

    if ($installdeps) {
        Install-EntraModules
        if (-not $anySelected) { Write-Good "Dependencies installed. Re-run with -all (or specific checks) to audit."; return }
    }

    Import-EntraModules

    # Decide which checks to run
    if ($select -and $select.Count) {
        $toRun = @($script:Registry.Keys | Where-Object { $select -contains $_ })
        $badSel = @($select | Where-Object { $_ -notin $script:Registry.Keys })
        if ($badSel.Count) { Write-Warn2 "Unknown check id(s) ignored: $($badSel -join ', ')" }
    } elseif ($all -or -not $anySelected) {
        $toRun = @($script:Registry.Keys | Where-Object { $exclude -notcontains $_ })
    } else {
        $toRun = @($script:Registry.Keys | Where-Object { $individual[$_] })
    }
    if ($toRun.Count -eq 0) { Write-Err2 "No checks selected."; return }

    # Connect (read-only)
    $ctx = Connect-EntraAuditGraph

    # Tenant + license detection
    try { $script:Tenant = Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}
    try {
        foreach ($s in @(Get-MgSubscribedSku -All -ErrorAction SilentlyContinue)) {
            if ($s.SkuPartNumber -match 'AAD_PREMIUM_P2') { $script:HasP2 = $true }
            if ($s.SkuPartNumber -match 'AAD_PREMIUM')    { $script:HasP1 = $true }
            if (@($s.ServicePlans.ServicePlanName) -match 'WorkloadIdentity') { $script:WorkloadIdP = $true }
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
        $needP2 = [bool]($c.P2)
        Invoke-AuditCheck -CheckId $id -Title $c.Title -Scopes $c.Scopes -NeedP2:$needP2 -Action ([scriptblock]::Create($c.Func))
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




