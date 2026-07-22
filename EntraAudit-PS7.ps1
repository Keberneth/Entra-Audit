<#
.SYNOPSIS
  EntraAudit-PS7.ps1 - Read-only Microsoft Entra ID (Azure AD) security audit.

  A PowerShell 7 + Microsoft Graph audit tool that mirrors the on-prem AdAudit-PS7
  audit and produces the same style of severity-grouped HTML reports. Its flagship
  capability is classifying every privileged role assignment as PERMANENT (standing)
  vs ELIGIBLE (PIM) vs TIME-BOUND ACTIVE - a permanent Global Administrator is a risk
  and is flagged; the same role held as PIM-eligible is the desired posture and is not.

.DESCRIPTION
  STRICTLY READ-ONLY DATA COLLECTION. The script requests only documented Graph read
  permissions, issues only GET requests to Graph and optional Azure Resource Manager,
  and aborts at startup if any write-capable Graph permission is granted. Audit checks
  never create, modify, activate, revoke or delete tenant resources. First-time OAuth
  consent is a separate operator-authorized authentication setup grant; pre-consent the
  read permissions when a literal no-setup-change audit window is required. All
  remediation text in the reports is advisory guidance for a human operator.

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
    [switch]$riskyusers,        # Identity Protection: risky users / detections
    [switch]$riskyserviceprincipals, # Identity Protection: risky service principals (Workload ID Premium)
    [switch]$apps,              # App / service principal hygiene & over-privilege
    [switch]$appcredentials,    # App registration secret/certificate expiry (expired -> Medium)
    [switch]$consentgrants,     # OAuth2 delegated consent grants (illicit consent)
    [switch]$devices,           # Stale / unmanaged / non-compliant devices
    [switch]$trusts,            # Cross-tenant access & B2B trust
    [switch]$recentchanges,     # Recently created users/groups & directory audit
    [switch]$tenanthealth,      # Directory-sync / PHS platform health
    [switch]$pimpolicies,       # PIM role-management policy quality (activation MFA/approval/duration)
    [switch]$breakglass,        # Emergency-access (break-glass) account health
    [switch]$authmethodpolicy,  # Tenant authentication-methods policy
    [switch]$accesspaths,       # Effective-access / attack-path correlation
    [switch]$staleapps,         # Stale / unused applications (by service-principal sign-in activity)
    [switch]$recommendations,   # Microsoft Entra recommendations
    [switch]$securescore,       # Microsoft Identity Secure Score
    [switch]$accessreviews,     # Access-review configuration and coverage
    [switch]$identitygovernance,# Entitlement management, lifecycle, Terms of Use, PIM for Groups
    [switch]$authrecovery,      # SSPR / authentication recovery readiness
    [switch]$groupgovernance,   # Group ownership, lifecycle, settings and activity
    [switch]$externaldelegation,# GDAP, partner trust and guest sponsorship
    [switch]$federationhealth,  # Federation certificates, endpoints and hybrid posture
    [switch]$workloadcredentials,# Application/SP credentials and federated identities
    [switch]$enterpriseapps,    # Enterprise-app ownership, assignments and permissions
    [switch]$monitoring,        # Graph logs plus optional read-only Azure monitoring inventory
    [switch]$changemonitoring,  # Security-sensitive directory changes

    # ---- Auth (app-only certificate; omit for interactive) ----
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [switch]$UseDeviceCode,

    # ---- Tuning ----
    [string]$OutputRoot,
    [string[]]$BreakGlassUpns,
    [ValidateRange(1, 3650)][int]$InactiveDays = 90,
    [ValidateRange(1, 3650)][int]$ExpiringCredentialDays = 30,
    [ValidateRange(1, 3650)][int]$RecentChangeDays = 30,
    [ValidateRange(1, 3650)][int]$StaleAppDays = 90,
    [string]$ModulesPath,       # offline: folder containing Save-Module output
    [switch]$NoLaunch           # do not open the report when finished
)

$ErrorActionPreference = 'Continue'
$script:Version = 'EntraAudit-PS7 v2.0'

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
    'Device.Read.All'
    'IdentityRiskyUser.Read.All'
    'IdentityRiskEvent.Read.All'
    'IdentityRiskyServicePrincipal.Read.All'
    'CrossTenantInformation.ReadBasic.All'
    'OnPremDirectorySynchronization.Read.All'
    'Reports.Read.All'
    'RoleManagementPolicy.Read.Directory'
    'Member.Read.Hidden'
    'DirectoryRecommendations.Read.All'
    'SecurityEvents.Read.All'
    'SecurityAlert.Read.All'
    'AccessReview.Read.All'
    'EntitlementManagement.Read.All'
    'LifecycleWorkflows.Read.All'
    'Agreement.Read.All'
    'PrivilegedAssignmentSchedule.Read.AzureADGroup'
    'PrivilegedEligibilitySchedule.Read.AzureADGroup'
    'RoleManagementPolicy.Read.AzureADGroup'
    'DelegatedAdminRelationship.Read.All'
    'Domain.Read.All'
    'Domain-InternalFederation.Read.All'
)

# Supported Microsoft Graph SDK major version - the single line to bump for SDK v3.
$script:GraphModuleMajor = 2

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
$script:GlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
# Tier-0 roles: a standing assignment to one of these is Critical regardless of the
# principal - GA plus the two roles that can take over GA (grant any role / reset any
# admin's credentials). Every other privileged role caps at High, with the escalation
# reasons (SP/group principal, not MFA-capable, synced) noted on the finding instead
# of inflating its severity - otherwise one systemic gap (e.g. group-assigned workload
# admin roles) floods the report with Criticals and dominates the risk score.
$script:Tier0RoleTemplateIds = @(
    '62e90394-69f5-4237-9190-012177145e10'   # Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814'   # Privileged Role Administrator
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'   # Privileged Authentication Administrator
)
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
$script:StaticPrivilegedRoleTemplateIds = @($script:PrivilegedRoleTemplates.Keys)

# Graph application permissions considered tier-0 dangerous on an app/SP.
$script:DangerousAppPermissions = @(
    'RoleManagement.ReadWrite.Directory','AppRoleAssignment.ReadWrite.All',
    'Application.ReadWrite.All','Directory.ReadWrite.All','full_access_as_app',
    'Mail.ReadWrite','Mail.Read','Mail.Send','Files.ReadWrite.All','Sites.FullControl.All',
    'User.ReadWrite.All','Group.ReadWrite.All','GroupMember.ReadWrite.All',
    'PrivilegedAccess.ReadWrite.AzureAD','RoleManagementPolicy.ReadWrite.Directory'
)

# ===========================================================================
# Shared state
# ===========================================================================
$script:Findings    = New-Object System.Collections.Generic.List[object]
$script:CheckStatus = [ordered]@{}
$script:AuthType    = 'Delegated'
$script:GraphConnectedByScript = $false   # only disconnect sessions this script created
$script:HasP1       = $false
$script:HasP2       = $false
$script:LicenseKnown = $true              # false when the SKU read itself failed (license UNKNOWN, not absent)
$script:WorkloadIdP = $false
$script:Tenant      = $null
$script:UsersCache  = $null
$script:UsersCacheHasSignIn = $false   # whether $UsersCache was fetched WITH signInActivity
$script:SignInFetchError = $null       # remembered failure of the signInActivity superset fetch
$script:UserById    = @{}
$script:RegCache    = $null
$script:AppsCache   = $null
$script:SpsCache    = $null
$script:MfaCapableById = @{}
$script:RoleDefById = @{}
$script:RolePrivilegedById = @{}
$script:RolePrivilegedMetadataKnown = $false
$script:AppOnlyGrantedPermissions = @()
$script:RawDatasets = New-Object System.Collections.Generic.List[object]
$script:PrivAssignments = $null
$script:PrivAssignmentsFailed = $false   # true when the assignment fetch itself failed (unknown, not empty)
$script:PrivEligibilityAssignmentsFailed = $false
$script:PrivilegedUserMap = $null
$script:PrivilegedUserMapIncomplete = $false
$script:CaPoliciesCache = $null

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
    if ($obj -and $obj.AdditionalProperties) {
        $properties = $obj.AdditionalProperties
        if ($properties.ContainsKey($key)) { return $properties[$key] }
        # Graph SDK AdditionalProperties dictionaries are case-sensitive even
        # though their JSON field names are not consistently cased by callers.
        foreach ($candidate in $properties.Keys) {
            if ([string]::Equals([string]$candidate, $key, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $properties[$candidate]
            }
        }
    }
    return $null
}

# Read a value from any of the shapes returned by the Graph SDK/raw-request mix used
# throughout this script: typed models, IDictionary JSON objects, or AdditionalProperties.
function Get-EAField {
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($candidate in $Object.Keys) {
            if ([string]::Equals([string]$candidate, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $Object[$candidate]
            }
        }
    }
    if ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return (Get-Ap $Object $Name)
}

# Raw Graph pagination is used where the SDK has no stable cmdlet. Keep every
# request on Microsoft's HTTPS Graph endpoint so an unexpected/malicious
# @odata.nextLink can never redirect the audit token to another host.
function Assert-EAGraphReadUri {
    param([Parameter(Mandatory)][string]$Uri)
    $absolute = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$absolute) -or
        -not [string]::Equals($absolute.Scheme, 'https', [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($absolute.GetLeftPart([UriPartial]::Authority), 'https://graph.microsoft.com', [System.StringComparison]::OrdinalIgnoreCase) -or
        $absolute.AbsolutePath -notmatch '^/(v1\.0|beta)(?:/|$)' -or
        $absolute.Fragment) {
        throw "Refusing unsafe Microsoft Graph pagination URI: $Uri"
    }
    return $absolute.AbsoluteUri
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

# Stable rule discriminator for TREND IDS: an explicit RuleId when set, else a
# digit-stripped title slug so a changing COUNT ("5 stale users" -> "7") does not change
# the id. (The risk score buckets similarly but additionally strips per-object title
# suffixes - see Get-EntraRiskScore - so ids stay per-object while scoring is per-issue.)
function Get-FindingRule {
    param([object]$Finding)
    if ($Finding.RuleId) { return [string]$Finding.RuleId }
    (([string]$Finding.Title -replace '\d+','') -replace '[^A-Za-z]+','-').Trim('-').ToLowerInvariant()
}

# Stable finding key: strip digits from the title so a changing COUNT
# ("5 stale users" -> "7 stale users") does not change the id; the rule slug plus the
# affected object identify the finding across runs (for new/resolved/trend comparison).
function New-FindingKey {
    param([string]$TenantId, [object]$Finding)
    $checkId = [string]$Finding.CheckId
    $rule = Get-FindingRule $Finding
    $objType = if ($Finding.ObjectType) { [string]$Finding.ObjectType } else { '' }
    $objId = if ($Finding.ObjectId) { $Finding.ObjectId } elseif ($Finding.AffectedPrincipal) { $Finding.AffectedPrincipal } else { 'tenant' }
    $path = if ($Finding.PathHash) { [string]$Finding.PathHash } else { '' }
    (@($TenantId, $checkId, $rule, $objType, ([string]$objId).ToLowerInvariant(), $path) -join '|')
}

# A CA policy enforces MFA if it uses the built-in 'mfa' grant OR an authentication
# strength (passwordless / phishing-resistant). Recognising auth strengths avoids
# false "no MFA policy" findings on modern tenants.
function Test-CaPolicyRequiresMfaOrStrength {
    param($Policy)
    $grant = $Policy.GrantControls
    if (-not $grant) { return $false }
    $builtIns = @($grant.BuiltInControls | Where-Object { $_ })
    $hasMfa = ($builtIns -contains 'mfa')
    $hasStrength = [bool]($grant.AuthenticationStrength -and $grant.AuthenticationStrength.Id)
    if (-not ($hasMfa -or $hasStrength)) { return $false }

    # With OR, MFA/auth strength is not mandatory when another grant (for example a
    # compliant device) can satisfy the policy. Count only policies where every OR
    # alternative is itself an MFA control. Missing Operator is treated as AND, which is
    # the Graph default and makes the MFA/auth-strength requirement mandatory.
    if ([string]$grant.Operator -match '^(?i)OR$') {
        $nonMfaAlternatives = @($builtIns | Where-Object { $_ -ne 'mfa' })
        if ($nonMfaAlternatives.Count -gt 0) { return $false }
    }
    return $true
}

function Test-CaPolicyRequiresPhishingResistantStrength {
    param($Policy)
    $grant = $Policy.GrantControls
    $strength = if ($grant) { $grant.AuthenticationStrength } else { $null }
    if (-not $strength) { return $false }

    # Built-in phishing-resistant MFA strength. Custom strengths are accepted only when
    # every advertised allowed combination is one of the phishing-resistant methods; if
    # Graph omits the combinations, fail closed instead of trusting a display name alone.
    $strengthId = [string](Get-EAField $strength 'Id')
    $isPhish = ($strengthId -eq '00000000-0000-0000-0000-000000000004')
    if (-not $isPhish) {
        $combos = @((Get-EAField $strength 'AllowedCombinations') | Where-Object { $_ })
        if ($combos.Count -gt 0) {
            $notResistant = @($combos | Where-Object { [string]$_ -notmatch '^(?i)(fido2|windowsHelloForBusiness|x509CertificateMultiFactor)$' })
            $isPhish = ($notResistant.Count -eq 0)
        }
    }
    if (-not $isPhish) { return $false }

    # An OR policy containing built-in MFA (or any other built-in grant) still permits a
    # weaker alternative to the phishing-resistant strength.
    if ([string]$grant.Operator -match '^(?i)OR$' -and @($grant.BuiltInControls | Where-Object { $_ }).Count -gt 0) { return $false }
    return $true
}

# --- Conditional Access applicability (shared by the break-glass and CA-coverage checks) ---
# Transitive group + directory-role-template membership for a user, cached.
function Get-EAUserScopeIds {
    param([string]$UserId)
    if (-not $script:UserScopeCache) { $script:UserScopeCache = @{} }
    if ($script:UserScopeCache.ContainsKey($UserId)) { return $script:UserScopeCache[$UserId] }
    $gids = New-Object System.Collections.Generic.HashSet[string]
    $rtids = New-Object System.Collections.Generic.HashSet[string]
    # Surface fetch failures and do NOT cache them - a silently-cached empty scope would
    # make every later CA-applicability answer for this user wrong for the whole run.
    $ok = $true
    try {
        foreach ($m in @(Get-MgUserTransitiveMemberOf -UserId $UserId -All -ErrorAction Stop)) {
            $t = [string](Get-Ap $m '@odata.type')
            if ($t -eq '#microsoft.graph.group') { [void]$gids.Add($m.Id) }
            elseif ($t -eq '#microsoft.graph.directoryRole') { $rt = Get-Ap $m 'roleTemplateId'; if ($rt) { [void]$rtids.Add([string]$rt) } }
        }
    } catch {
        $ok = $false
        Write-Warn2 "  Could not resolve memberships for user $UserId ($($_.Exception.Message)) - CA applicability may be incomplete."
    }
    $r = [pscustomobject]@{ Groups = $gids; Roles = $rtids; Known = $ok }
    if ($ok) { $script:UserScopeCache[$UserId] = $r }
    return $r
}

# True only if the policy is in scope for the user AND the user is not excluded.
function Test-CaPolicyAppliesToUser {
    param($Policy, [string]$UserId, $GroupIds, $RoleTemplateIds)
    $cu = $Policy.Conditions.Users
    $inc = (@($cu.IncludeUsers) -contains 'All') -or (@($cu.IncludeUsers) -contains $UserId)
    if (-not $inc) { foreach ($gid in @($cu.IncludeGroups)) { if ($gid -and $GroupIds -and $GroupIds.Contains($gid)) { $inc = $true; break } } }
    if (-not $inc) { foreach ($rid in @($cu.IncludeRoles)) { if ($rid -and $RoleTemplateIds -and $RoleTemplateIds.Contains($rid)) { $inc = $true; break } } }
    if (-not $inc) { return $false }
    if (@($cu.ExcludeUsers) -contains $UserId) { return $false }
    foreach ($gid in @($cu.ExcludeGroups)) { if ($gid -and $GroupIds -and $GroupIds.Contains($gid)) { return $false } }
    foreach ($rid in @($cu.ExcludeRoles)) { if ($rid -and $RoleTemplateIds -and $RoleTemplateIds.Contains($rid)) { return $false } }
    return $true
}

# Does the policy target all cloud apps (vs a scoped set)?
function Test-CaPolicyTargetsAllApps {
    param($Policy)
    return (Test-CaPolicyTargetsAllResources $Policy)
}

# "All resources" is not merely includeApplications=All: application exclusions and
# user-action/authentication-context scopes punch holes in that coverage.
function Test-CaPolicyTargetsAllResources {
    param($Policy)
    $apps = $Policy.Conditions.Applications
    if (-not $apps -or @($apps.IncludeApplications) -notcontains 'All') { return $false }
    if (@($apps.ExcludeApplications | Where-Object { $_ -and $_ -ne 'None' }).Count -gt 0) { return $false }
    $appFilter = Get-EAField $apps 'ApplicationFilter'
    if ($appFilter -and ((Get-EAField $appFilter 'Mode') -or (Get-EAField $appFilter 'Rule'))) { return $false }
    if (@((Get-EAField $apps 'IncludeUserActions') | Where-Object { $_ }).Count -gt 0) { return $false }
    if (@((Get-EAField $apps 'IncludeAuthenticationContextClassReferences') | Where-Object { $_ }).Count -gt 0) { return $false }
    return $true
}

# Strict tenant baseline scope. Direct exclusions are allowed only for the explicitly
# designated emergency-access accounts; group/role/guest exclusions are mutable or broad
# bypasses and therefore cannot qualify as an "all users" baseline.
function Test-CaPolicyTargetsAllUsers {
    param($Policy, [string[]]$AllowedExcludedUserIds = @())
    $cu = $Policy.Conditions.Users
    if (-not $cu -or @($cu.IncludeUsers) -notcontains 'All') { return $false }
    $allowed = @($AllowedExcludedUserIds | Where-Object { $_ })
    foreach ($uid in @($cu.ExcludeUsers | Where-Object { $_ -and $_ -ne 'None' })) {
        if ($uid -notin $allowed) { return $false }
    }
    if (@($cu.ExcludeGroups | Where-Object { $_ -and $_ -ne 'None' }).Count -gt 0) { return $false }
    if (@($cu.ExcludeRoles  | Where-Object { $_ -and $_ -ne 'None' }).Count -gt 0) { return $false }
    if (Get-EAField $cu 'ExcludeGuestsOrExternalUsers') { return $false }
    return $true
}

# Conditions other than the one a baseline is intentionally testing make a policy
# conditional rather than universal. Callers name the intentional condition(s) to ignore.
function Test-CaPolicyHasNarrowingConditions {
    param($Policy, [string[]]$Ignore = @())
    $c = $Policy.Conditions
    if (-not $c) { return $false }

    if ('ClientApps' -notin $Ignore) {
        $clients = @($c.ClientAppTypes | Where-Object { $_ })
        if ($clients.Count -gt 0 -and $clients -notcontains 'all') { return $true }
    }
    foreach ($spec in @(
        @{ Name='UserRiskLevels'; Tag='UserRisk' },
        @{ Name='SignInRiskLevels'; Tag='SignInRisk' },
        @{ Name='ServicePrincipalRiskLevels'; Tag='ServicePrincipalRisk' },
        @{ Name='InsiderRiskLevels'; Tag='InsiderRisk' }
    )) {
        if ($spec.Tag -notin $Ignore -and @((Get-EAField $c $spec.Name) | Where-Object { $_ -and $_ -ne 'none' }).Count -gt 0) { return $true }
    }

    foreach ($spec in @(
        @{ Name='Platforms'; Include='IncludePlatforms'; Exclude='ExcludePlatforms' },
        @{ Name='Locations'; Include='IncludeLocations'; Exclude='ExcludeLocations' }
    )) {
        if ($spec.Name -in $Ignore) { continue }
        $obj = Get-EAField $c $spec.Name
        if (-not $obj) { continue }
        $inc = @((Get-EAField $obj $spec.Include) | Where-Object { $_ -and $_ -ne 'None' })
        $exc = @((Get-EAField $obj $spec.Exclude) | Where-Object { $_ -and $_ -ne 'None' })
        if ($exc.Count -gt 0 -or ($inc.Count -gt 0 -and $inc -notcontains 'All')) { return $true }
    }

    $devices = Get-EAField $c 'Devices'
    if ($devices) {
        $filter = Get-EAField $devices 'DeviceFilter'
        if ($filter -and ((Get-EAField $filter 'Mode') -or (Get-EAField $filter 'Rule'))) { return $true }
        if (@((Get-EAField $devices 'IncludeDeviceStates') | Where-Object { $_ }).Count -gt 0 -or
            @((Get-EAField $devices 'ExcludeDeviceStates') | Where-Object { $_ }).Count -gt 0) { return $true }
    }
    if ('AuthenticationFlows' -notin $Ignore) {
        $flows = Get-EAField $c 'AuthenticationFlows'
        if ($flows -and @((Get-EAField $flows 'TransferMethods') | Where-Object { $_ -and $_ -ne 'none' }).Count -gt 0) { return $true }
    }
    if ('ClientApplications' -notin $Ignore) {
        $clientApps = Get-EAField $c 'ClientApplications'
        if ($clientApps -and (@((Get-EAField $clientApps 'IncludeServicePrincipals') | Where-Object { $_ }).Count -gt 0 -or
            @((Get-EAField $clientApps 'ExcludeServicePrincipals') | Where-Object { $_ }).Count -gt 0)) { return $true }
    }
    return $false
}

# --- App-only EXACT least-privilege allowlist. Read-only is not enough: broad read
# permissions (e.g. Mail.Read) still over-expose data, so only the documented audit
# permissions are approved; anything else (incl. unknown/custom roles) fails closed. ---
$script:ApprovedAppOnlyPermissions = @(
    'Directory.Read.All','RoleManagement.Read.Directory','Policy.Read.All','AuditLog.Read.All',
    'Application.Read.All','User.Read.All','Group.Read.All','Organization.Read.All',
    'Device.Read.All','IdentityRiskyUser.Read.All',
    'IdentityRiskEvent.Read.All','IdentityRiskyServicePrincipal.Read.All','CrossTenantInformation.ReadBasic.All',
    'OnPremDirectorySynchronization.Read.All','Reports.Read.All','RoleManagementPolicy.Read.Directory','Member.Read.Hidden',
    'DirectoryRecommendations.Read.All','SecurityEvents.Read.All','SecurityAlert.Read.All','AccessReview.Read.All',
    'EntitlementManagement.Read.All','LifecycleWorkflows.Read.All',
    'PrivilegedAssignmentSchedule.Read.AzureADGroup','PrivilegedEligibilitySchedule.Read.AzureADGroup',
    'RoleManagementPolicy.Read.AzureADGroup','DelegatedAdminRelationship.Read.All','Domain.Read.All',
    'Domain-InternalFederation.Read.All',
    # Read-only PIM schedule scopes. Not required (RoleManagement.Read.Directory already covers
    # PIM reads), but accepted so an app provisioned from the delegated list (PREREQUISITE A.2)
    # does not fail closed. Both are *.Read.Directory - the read-only guarantee is unchanged.
    'RoleEligibilitySchedule.Read.Directory','RoleAssignmentSchedule.Read.Directory'
)
function Test-AppRoleIsApprovedForAudit {
    param([Parameter(Mandatory)][string]$Value)
    return ($script:ApprovedAppOnlyPermissions -contains $Value)
}

# ===========================================================================
# Finding emission + raw evidence
# ===========================================================================
function Add-EntraFinding {
    param(
        [string]$Severity, [string]$Title, [string]$Category, [string]$CheckId,
        [string]$Evidence, [string]$WhyItMatters, [string]$RecommendedAction,
        [string]$SourceFile, [string]$AffectedPrincipal, [object[]]$ResultRows,
        # Optional stable-identity fields. When -RuleId is supplied the finding id is built
        # from RuleId + ObjectType + ObjectId (+ PathHash) and is fully stable across wording
        # and count changes; otherwise it falls back to a digit-stripped title slug.
        [string]$RuleId, [string]$ObjectType, [string]$ObjectId, [string]$PathHash,
        [switch]$CoverageGap
    )
    $Severity = Normalize-Severity $Severity
    $script:Findings.Add([pscustomobject]@{
        # Unique per finding (index prefix): two findings sharing Title+CheckId would
        # otherwise collide on the same HTML id and break index/priority anchors.
        Anchor            = ('finding-{0}-{1}' -f $script:Findings.Count, (New-Slug ('{0}-{1}' -f $Title, $CheckId)))
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
        RuleId            = $RuleId
        ObjectType        = $ObjectType
        ObjectId          = $ObjectId
        PathHash          = $PathHash
        CoverageGap       = [bool]$CoverageGap
    }) | Out-Null
}

# A coverage failure is materially different from an ordinary Information baseline:
# it means the check did not have enough evidence to conclude that the control is clean.
# Generated findings mark this explicitly. The conservative text/rule fallback is
# reserved for imported/property-less legacy objects; tenant-controlled text must not
# be able to reclassify a current finding.
function Test-EntraCoverageGap {
    param([Parameter(Mandatory)][object]$Finding)

    if ($Finding.PSObject.Properties['CoverageGap']) { return [bool]$Finding.CoverageGap }
    $rule = [string]$Finding.RuleId
    if ($rule -match '(?i)(^|[-_])(coverage|unknown|incomplete|unreadable|not-assessed|not-available)($|[-_])') { return $true }
    $text = ('{0} {1} {2}' -f $Finding.Title, $Finding.Evidence, $Finding.WhyItMatters)
    return ($text -match '(?i)(coverage\s+(gap|is\s+unknown)|unknown\s+coverage|\b(is|are)\s+unknown\b|could\s+not\s+be\s+(fully\s+)?(read|retrieved|fetched|evaluated|assessed|verified)|cannot\s+be\s+(fully\s+)?(evaluated|assessed|verified)|not\s+assessed|not\s+a\s+clean\s+result|coverage\s+is\s+incomplete|result\s+is\s+unknown|status\s+is\s+unknown|unknown[,/]?\s+not\s+(clean|confirmed))')
}

# Defend exported CSVs against spreadsheet formula injection. Tenant/display/app/group
# names and UPN-like fields are attacker-influencable; a value that begins with =, +, -, @
# or a control character can be interpreted as a formula when the CSV is opened in Excel /
# LibreOffice. Prefixing with a single quote neutralises it without changing the visible text.
# (Raw JSON keeps the unmodified values - only the spreadsheet-bound CSVs are sanitised.)
function ConvertTo-SafeCsvValue {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    # Only STRING values are a formula-injection vector. Pass typed values (DateTime,
    # numbers, bools) through unchanged so Export-Csv formats them exactly as before -
    # casting a [datetime] to [string] here would silently change the date format.
    if ($Value -isnot [string]) { return $Value }
    if ($Value -match '^[=+\-@\t\r\n]') { return "'" + $Value }
    return $Value
}
function ConvertTo-SafeCsvRows {
    param([object[]]$Rows)
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }
        $out = [ordered]@{}
        foreach ($p in $row.PSObject.Properties) { $out[$p.Name] = ConvertTo-SafeCsvValue $p.Value }
        [pscustomobject]$out
    }
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
            # utf8BOM: Excel misdecodes BOM-less UTF-8 CSVs with non-ASCII names/UPNs
            ConvertTo-SafeCsvRows $Rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8BOM
            $table = @($Rows) | Format-Table -AutoSize | Out-String -Width 4096
            Set-Content -LiteralPath $txtPath -Value (($header -join "`r`n") + "`r`n" + $table) -Encoding UTF8
        } else {
            # Always write the CSV (even with no rows) so automation can rely on the file
            # existing and can distinguish "pass / no data" from "CSV generation failed".
            [pscustomobject]@{ Status = 'NoData'; Message = 'No rows returned for this check.' } | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8BOM
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
# Microsoft.Graph sub-modules must share a single major version - mixing majors (e.g. a v1
# and a v2 module side by side) is a known cause of obscure runtime failures in the SDK.
function Assert-GraphModuleVersions {
    $installed = foreach ($m in $script:RequiredModules) {
        Get-Module -ListAvailable -Name $m | Sort-Object Version -Descending | Select-Object -First 1 Name, Version
    }
    $installed = @($installed | Where-Object { $_ })
    if ($installed.Count -eq 0) { return }
    $majors = @($installed | Group-Object { $_.Version.Major })
    if ($majors.Count -gt 1) {
        $detail = ($installed | ForEach-Object { "$($_.Name)=$($_.Version)" }) -join ', '
        throw "Microsoft.Graph modules have mixed major versions: $detail. Align them to one major version (uninstall the older majors) before running the audit."
    }
}

function Install-EntraModules {
    Write-Info "Installing Microsoft Graph SDK sub-modules (CurrentUser scope)..."
    $prevPolicy = $null   # restore PSGallery trust afterwards - do not leave it permanently trusted
    try {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }
        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
            $prevPolicy = $repo.InstallationPolicy
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        foreach ($m in $script:RequiredModules) {
            # Pin to the supported major so a fresh -installdeps cannot mix majors
            # (Assert-GraphModuleVersions would otherwise fail right after installing).
            $existing = Get-Module -ListAvailable -Name $m | Sort-Object Version -Descending | Select-Object -First 1
            if ($existing -and $existing.Version.Major -eq $script:GraphModuleMajor) { Write-Good "$m already installed ($($existing.Version))."; continue }
            Write-Info "Installing $m ..."
            Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -Repository PSGallery `
                -MinimumVersion "$($script:GraphModuleMajor).0.0" -MaximumVersion "$($script:GraphModuleMajor).999.999" -ErrorAction Stop
            Write-Good "$m installed."
        }
        Assert-GraphModuleVersions
    } catch {
        throw "Module installation failed: $($_.Exception.Message)"
    } finally {
        # Restore the PSGallery installation policy we changed, so running the audit does not
        # silently leave PSGallery trusted for the user's whole session/profile.
        if ($prevPolicy) { try { Set-PSRepository -Name PSGallery -InstallationPolicy $prevPolicy } catch {} }
    }
}

# Prepend the offline modules folder to PSModulePath (idempotent). Called before BOTH
# install and import so `-installdeps -ModulesPath <x>` sees the offline modules and
# does not needlessly download from the gallery.
function Add-EAOfflineModulesPath {
    if ($ModulesPath -and (Test-Path $ModulesPath)) {
        $resolved = (Resolve-Path $ModulesPath).Path
        if (-not (($env:PSModulePath -split [IO.Path]::PathSeparator) -contains $resolved)) {
            $env:PSModulePath = $resolved + [IO.Path]::PathSeparator + $env:PSModulePath
            Write-Info "Prepended offline modules path: $ModulesPath"
        }
    }
}

function Import-EntraModules {
    Add-EAOfflineModulesPath
    $missing = @()
    foreach ($m in $script:RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $m)) { $missing += $m; continue }
        try { Import-Module $m -ErrorAction Stop }
        catch { $missing += $m; Write-Warn2 "Module $m is installed but failed to import: $($_.Exception.Message)" }
    }
    if ($missing.Count -gt 0) {
        throw "Required module(s) not available: $($missing -join ', '). Run with -installdeps (online) or see PREREQUISITE.md for offline install."
    }
    # Warn (do not abort) on mixed Graph module majors - the audit may still work, but this is
    # the most common cause of confusing downstream SDK errors.
    try { Assert-GraphModuleVersions } catch { Write-Warn2 $_.Exception.Message }
}

function Connect-EntraAuditGraph {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    # Half an app-only pair must not silently fall back to an interactive prompt -
    # that surprises unattended runs and signs in as the wrong identity.
    if (([bool]$ClientId) -ne ([bool]$CertificateThumbprint)) {
        throw 'App-only authentication requires BOTH -ClientId and -CertificateThumbprint; only one was supplied. Provide both for unattended runs, or neither for interactive sign-in.'
    }
    $appOnly = ($ClientId -and $CertificateThumbprint)
    if ($appOnly) {
        Write-Info "Connecting to Microsoft Graph (app-only, certificate)..."
        $cp = @{ ClientId = $ClientId; CertificateThumbprint = $CertificateThumbprint; NoWelcome = $true }
        if ($TenantId) { $cp.TenantId = $TenantId }
        Connect-MgGraph @cp -ErrorAction Stop
        $script:GraphConnectedByScript = $true
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
        $script:GraphConnectedByScript = $true
        $script:AuthType = 'Delegated'
    }

    $ctx = Get-MgContext
    if (-not $ctx) { throw 'Not connected to Microsoft Graph.' }

    # --- READ-ONLY SELF-CHECK: refuse to run if any write/action scope is present ---
    # Match true write/action tokens only. Deliberately NOT bare 'Manage' - it is a substring
    # of the legitimate read scope 'RoleManagement(Policy).Read.Directory' and would abort every run.
    # '\.Manage' (dot-prefixed, no \b so fused forms like User.ManageIdentities.All match)
    # and 'PrivilegedOperations' close write-capable scopes the older list missed
    # (Sites.Manage.All, DeviceManagementManagedDevices.PrivilegedOperations.All).
    $bad = @($ctx.Scopes | Where-Object { $_ -match '(?i)(ReadWrite|\.Write\b|\.Send\b|\.Create\b|\.Delete\b|\.Update\b|\.Invite\b|\.Manage|PrivilegedOperations|ManageAsApp|AccessAsUser|FullControl|full_access|Impersonation)' })
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
# and refuse to run unless EVERY one is a clear read-only permission.
function Assert-AppOnlyReadOnly {
    param([Parameter(Mandatory)][string]$ClientId)
    $self = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ConsistencyLevel eventual -CountVariable c -Property 'id,appId,displayName' -ErrorAction Stop | Select-Object -First 1
    if (-not $self) { throw "Cannot verify app-only read-only posture: no service principal found for ClientId $ClientId." }
    $assignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $self.Id -All -ErrorAction Stop)

    # Resolve only the resource service principals actually referenced by the assignments.
    $roleMapByResourceId = @{}
    $resourceAppIdById = @{}
    foreach ($rid in (@($assignments | ForEach-Object { $_.ResourceId }) | Where-Object { $_ } | Select-Object -Unique)) {
        try {
            $rsp = Get-MgServicePrincipal -ServicePrincipalId $rid -Property 'id,appId,appRoles' -ErrorAction Stop
            $m = @{}; foreach ($role in @($rsp.AppRoles)) { if ($role.Id) { $m[[string]$role.Id] = $role.Value } }
            $roleMapByResourceId[$rid] = $m
            $resourceAppIdById[$rid] = [string]$rsp.AppId
        } catch { $roleMapByResourceId[$rid] = @{}; $resourceAppIdById[$rid] = $null }
    }

    $unapproved = @(); $unresolved = @(); $resolvedValues = @()
    foreach ($a in $assignments) {
        $value = $null
        if ($roleMapByResourceId.ContainsKey($a.ResourceId)) { $value = $roleMapByResourceId[$a.ResourceId][[string]$a.AppRoleId] }
        if (-not $value) { $unresolved += ("{0}:appRole {1}" -f $a.ResourceDisplayName, $a.AppRoleId); continue }   # cannot verify -> unsafe
        if ($resourceAppIdById[$a.ResourceId] -ne '00000003-0000-0000-c000-000000000000') {
            $unapproved += ("{0}:{1} (non-Microsoft-Graph resource)" -f $a.ResourceDisplayName, $value)
            continue
        }
        $resolvedValues += [string]$value
        if (-not (Test-AppRoleIsApprovedForAudit -Value $value)) { $unapproved += ("{0}:{1}" -f $a.ResourceDisplayName, $value) }
    }
    if ($unapproved.Count -gt 0 -or $unresolved.Count -gt 0) {
        # Exact-allowlist, fail-closed: refuse anything not on the documented audit list -
        # including broad-but-read permissions (e.g. Mail.Read) that over-expose data, and
        # any unresolvable/custom app role. Distinguish the two so operators can tell which.
        $msg = "Refusing app-only run. Unapproved application permission detected - the audit app must contain ONLY the documented read-only audit permissions."
        if ($unapproved.Count -gt 0) { $msg += " Unapproved (write-capable or excessive read): $($unapproved -join ', ')." }
        if ($unresolved.Count -gt 0) { $msg += " Could NOT verify (resource app-role not readable) - treated as unsafe: $($unresolved -join ', ')." }
        throw $msg
    }
    # Retain the values we just resolved so every later check can perform the same
    # permission gate in app-only mode. Without this, Test-MgScope unconditionally passed
    # and missing application permissions surfaced only as inconsistent 403s mid-check.
    $script:AppOnlyGrantedPermissions = @($resolvedValues | Sort-Object -Unique)
    Write-Good ("App-only read-only verified: {0} application permission(s) granted, all on the approved audit allowlist." -f $assignments.Count)
}

# Permission gate for delegated and app-only runs. Directory.Read.All implicitly covers
# only the narrower directory-object reads listed here; policy, logs, reports, risk and
# governance permissions still require their explicit application role.
function Test-MgScope {
    param([string[]]$Required, [switch]$Quiet)
    $have = if ($script:AuthType -eq 'AppOnly') {
        @($script:AppOnlyGrantedPermissions)
    } else {
        @((Get-MgContext).Scopes)
    }
    if ($have -contains 'Directory.Read.All') {
        $have += @('User.Read.All','Group.Read.All','Organization.Read.All','Device.Read.All','Application.Read.All')
    }
    $missing = @($Required | Where-Object { $_ -notin $have })
    if ($missing.Count -gt 0) {
        if (-not $Quiet) { Write-Warn2 "Skipping - missing $($script:AuthType.ToLowerInvariant()) permission(s): $($missing -join ', ')" }
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
    # When the SKU read itself failed the license state is UNKNOWN - report that
    # distinctly instead of a false 'NoLicense' (the tenant may well be licensed).
    if ($NeedP1 -and -not $script:HasP1) {
        $status = if ($script:LicenseKnown) { 'Skipped-NoLicense' } else { 'Skipped-LicenseUnknown' }
        $script:CheckStatus[$CheckId] = [pscustomobject]@{ Title=$Title; Status=$status; Count=0 }
        Write-Warn2 "  $Title -> $status (Entra ID P1 required)"
        return
    }
    if ($NeedP2 -and -not $script:HasP2) {
        $status = if ($script:LicenseKnown) { 'Skipped-NoLicense' } else { 'Skipped-LicenseUnknown' }
        $script:CheckStatus[$CheckId] = [pscustomobject]@{ Title=$Title; Status=$status; Count=0 }
        Write-Warn2 "  $Title -> $status (Entra ID P2 required)"
        return
    }

    try {
        & $Action
        # Many checks intentionally add Information-level baselines (population overviews, MFA
        # adoption, "desired posture" notes) even when nothing is wrong. Count only non-Information
        # severities as risk findings so a clean check is not mislabelled as noisy.
        $newFindings = @($script:Findings | Select-Object -Skip $before)
        # Coverage findings can carry a risk-bearing severity because the visibility gap
        # is operationally important, but they are not proof of an adverse tenant fact.
        # Keep them out of RiskFindings(n); they are counted independently as Incomplete.
        $riskAdded = @($newFindings | Where-Object {
            $_.Severity -ne 'Information' -and -not (Test-EntraCoverageGap $_)
        }).Count
        $infoAdded = @($newFindings | Where-Object { $_.Severity -eq 'Information' }).Count
        $coverageAdded = @($newFindings | Where-Object { Test-EntraCoverageGap $_ }).Count
        $status = if ($riskAdded -gt 0 -and $coverageAdded -gt 0) { "RiskFindings($riskAdded)+Incomplete($coverageAdded)" } `
            elseif ($riskAdded -gt 0) { "RiskFindings($riskAdded)" } `
            elseif ($coverageAdded -gt 0) { "Incomplete($coverageAdded)" } `
            elseif ($infoAdded -gt 0) { "InfoOnly($infoAdded)" } `
            else { 'Pass' }
        $script:CheckStatus[$CheckId] = [pscustomobject]@{
            Title=$Title; Status=$status; Count=$riskAdded; InfoCount=$infoAdded; CoverageCount=$coverageAdded
        }
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
    # The property set is decided by the LICENSE/SCOPE GATE, not the caller switch: when
    # P1 + AuditLog.Read.All are present the very first fetch already includes
    # signInActivity, so later sign-in callers (staleusers/breakglass) hit the cache
    # instead of re-downloading the entire directory a second time. If the superset
    # fetch fails anyway (app-only without the AuditLog app permission - Test-MgScope
    # cannot see that), the failure is remembered: base callers degrade once to the
    # plain property set, sign-in callers keep today's throw/Skipped-NoPermission path.
    # -IncludeSignInActivity remains for call-site compatibility.
    param([switch]$IncludeSignInActivity)

    $gateSignIn = $script:HasP1 -and (Test-MgScope @('AuditLog.Read.All') -Quiet)
    if ($IncludeSignInActivity -and $gateSignIn -and $script:SignInFetchError) { throw $script:SignInFetchError }
    $wantSignIn = $gateSignIn -and -not $script:SignInFetchError

    # Serve from cache when the cached population already satisfies the request. The
    # sign-in variant is a superset of properties, so a base caller can reuse it freely.
    if ($wantSignIn) {
        if ($script:UsersCacheHasSignIn) { return $script:UsersCache }
    } elseif ($null -ne $script:UsersCache) {
        return $script:UsersCache
    }

    $props = @('Id','UserPrincipalName','DisplayName','AccountEnabled','UserType',
               'AssignedLicenses','LicenseAssignmentStates','PasswordPolicies',
               'OnPremisesSyncEnabled','CreatedDateTime',
               'ExternalUserState','ExternalUserStateChangeDateTime')
    if ($wantSignIn) {
        try {
            $script:UsersCache = @(Get-MgUser -All -Property ($props + 'SignInActivity') -ErrorAction Stop)
            $script:UsersCacheHasSignIn = $true
        } catch {
            $script:SignInFetchError = $_.Exception
            if ($IncludeSignInActivity) { throw }   # sign-in caller: same failure path as before
            $script:UsersCache = @(Get-MgUser -All -Property $props -ErrorAction Stop)   # base caller: degrade once
            $script:UsersCacheHasSignIn = $false
        }
    } else {
        $script:UsersCache = @(Get-MgUser -All -Property $props -ErrorAction Stop)
        $script:UsersCacheHasSignIn = $false
    }
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
    $definitions = @(Get-MgRoleManagementDirectoryRoleDefinition -All -Property 'id,templateId,displayName,isBuiltIn,isEnabled,rolePermissions' -ErrorAction Stop)
    foreach ($rd in $definitions) {
        $script:RoleDefById[$rd.Id] = $rd
        # Built-in policy/assignment APIs sometimes return the template id rather than the
        # tenant role-definition id. Index both without losing support for custom roles,
        # whose TemplateId is normally empty.
        if ($rd.TemplateId) { $script:RoleDefById[[string]$rd.TemplateId] = $rd }
    }
    # isPrivileged is currently exposed on the beta unifiedRoleDefinition shape. Read it
    # separately (GET only) and retain v1.0 objects for every other operation. If beta is
    # unavailable, custom/unlisted roles fall back to conservative action inspection.
    try {
        $u = 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,templateId,isPrivileged'; $guard = 0
        while ($u -and $guard -lt 50) {
            $u = Assert-EAGraphReadUri $u
            $resp = Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop
            foreach ($brd in @($resp['value'])) {
                $bid = [string]$brd['id']; $btid = [string]$brd['templateId']
                if ($bid -and $brd.ContainsKey('isPrivileged')) { $script:RolePrivilegedById[$bid] = [bool]$brd['isPrivileged'] }
                if ($btid -and $brd.ContainsKey('isPrivileged')) { $script:RolePrivilegedById[$btid] = [bool]$brd['isPrivileged'] }
            }
            $u = $resp['@odata.nextLink']; $guard++
        }
        if ($u) { throw 'Microsoft Graph role-definition pagination exceeded the 50-page safety limit.' }
        $script:RolePrivilegedMetadataKnown = $true
    } catch { $script:RolePrivilegedMetadataKnown = $false }
    # Prime the dynamic privileged map. Existing well-known IDs remain the fail-safe
    # fallback, while Graph's isPrivileged flag and custom role actions catch new/unlisted
    # roles without waiting for this script's static list to be updated.
    foreach ($rd in $definitions) { Get-EARoleInfo -RoleDefinitionId ([string]$rd.Id) | Out-Null }
    return $script:RoleDefById
}

function Get-EARoleInfo {
    param([Parameter(Mandatory)][string]$RoleDefinitionId)
    $rd = $script:RoleDefById[$RoleDefinitionId]
    if (-not $rd -and $script:RoleDefById.Count -gt 0) {
        $rd = $script:RoleDefById.Values | Where-Object { $_.Id -eq $RoleDefinitionId -or $_.TemplateId -eq $RoleDefinitionId } | Select-Object -First 1
    }
    $templateId = if ($rd -and $rd.TemplateId) { [string]$rd.TemplateId } else { $RoleDefinitionId }
    $definitionId = if ($rd -and $rd.Id) { [string]$rd.Id } else { $RoleDefinitionId }
    $name = if ($rd -and $rd.DisplayName) { [string]$rd.DisplayName }
            elseif ($script:PrivilegedRoleTemplates.ContainsKey($templateId)) { [string]$script:PrivilegedRoleTemplates[$templateId] }
            else { $RoleDefinitionId }

    $fallback = ($templateId -in $script:StaticPrivilegedRoleTemplateIds)
    $rawPrivileged = if ($script:RolePrivilegedById.ContainsKey($definitionId)) { $script:RolePrivilegedById[$definitionId] }
                     elseif ($script:RolePrivilegedById.ContainsKey($templateId)) { $script:RolePrivilegedById[$templateId] }
                     elseif ($rd) { Get-EAField $rd 'IsPrivileged' } else { $null }
    if ($null -eq $rawPrivileged -and $rd) { $rawPrivileged = Get-EAField $rd 'isPrivileged' }
    $explicitKnown = ($null -ne $rawPrivileged)
    $explicitPrivileged = ($explicitKnown -and [bool]$rawPrivileged)
    $isBuiltInRaw = if ($rd) { Get-EAField $rd 'IsBuiltIn' } else { $null }

    $allowedActions = @()
    if ($rd) {
        foreach ($perm in @((Get-EAField $rd 'RolePermissions'))) {
            $allowedActions += @((Get-EAField $perm 'AllowedResourceActions') | Where-Object { $_ })
        }
    }
    # A custom/unclassified role with any non-read action is privileged. This is
    # deliberately broad and fail-safe: credential, membership, policy and assignment
    # actions use many different path names, whereas read actions consistently end /read.
    $writeActions = @($allowedActions | Where-Object {
        $s = [string]$_
        $s -eq '*' -or $s -notmatch '(?i)/(read|readBasic)$'
    })
    $actionPrivileged = ($writeActions.Count -gt 0 -and -not $explicitKnown)
    $unresolved = (-not $rd)
    $isPrivileged = ($fallback -or $explicitPrivileged -or $actionPrivileged -or $unresolved)
    $isTier0 = (($templateId -in $script:Tier0RoleTemplateIds) -or @($writeActions | Where-Object {
        [string]$_ -match '(?i)^microsoft\.directory/(roleAssignments|roleDefinitions)/.*(allTasks|create|update)$' -or
        [string]$_ -match '(?i)^microsoft\.directory/users/(authenticationMethods|password)/.*(allTasks|create|update)$'
    }).Count -gt 0)
    $source = if ($fallback) { 'static-fallback' } elseif ($explicitPrivileged) { 'role-definition-isPrivileged' } elseif ($actionPrivileged) { 'custom-role-write-actions' } elseif ($unresolved) { 'unresolved-fail-closed' } else { 'role-definition-nonprivileged' }

    if ($isPrivileged -and -not $script:PrivilegedRoleTemplates.ContainsKey($templateId)) {
        $script:PrivilegedRoleTemplates[$templateId] = $name
    }
    return [pscustomobject]@{
        Name=$name; TemplateId=$templateId; RoleDefinitionId=$definitionId
        IsPrivileged=$isPrivileged; IsGA=($templateId -eq $script:GlobalAdminTemplateId); IsTier0=$isTier0
        IsBuiltIn=$(if ($null -eq $isBuiltInRaw) { $null } else { [bool]$isBuiltInRaw })
        ClassificationSource=$source; WriteActions=($writeActions -join '; ')
    }
}

# Application objects with credential metadata, cached so the apps and app-credential
# checks share a single Get-MgApplication call. keyCredentials/passwordCredentials require
# an explicit $select.
function Get-EAApplications {
    if ($null -ne $script:AppsCache) { return $script:AppsCache }
    $appProps = 'id,appId,displayName,passwordCredentials,keyCredentials,signInAudience,verifiedPublisher,createdDateTime'
    # owners expanded (ids only) in the same enumeration: the apps check tests only
    # "has NO owner", which would otherwise cost one Graph call per credentialed app.
    $script:AppsCache = @(Get-MgApplication -All -Property $appProps -ExpandProperty 'owners($select=id)' -ErrorAction Stop)
    return $script:AppsCache
}

# Service principals with the union of the properties the apps and staleapps checks
# need, cached so a full -all run enumerates the (potentially huge) SP list once.
function Get-EAServicePrincipals {
    if ($null -ne $script:SpsCache) { return $script:SpsCache }
    $spProps = 'id,appId,displayName,appRoles,servicePrincipalType,accountEnabled,passwordCredentials,keyCredentials,appOwnerOrganizationId,createdDateTime'
    $script:SpsCache = @(Get-MgServicePrincipal -All -Property $spProps -ErrorAction Stop)
    return $script:SpsCache
}

# Conditional Access policies, cached - four checks (tenantposture, capolicies,
# breakglass, accesspaths) otherwise each download the full policy set. Throws on
# failure so callers keep their own error semantics; only a successful fetch is
# cached, so a transient failure in one check does not blind the later ones.
function Get-EACaPolicies {
    if ($null -ne $script:CaPoliciesCache) { return $script:CaPoliciesCache }
    $script:CaPoliciesCache = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
    return $script:CaPoliciesCache
}

# ===========================================================================
# CHECK 1 - tenant-info
# ===========================================================================
function Invoke-Check-TenantInfo {
    $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
    $script:Tenant = $org
    $skus = @(Get-MgSubscribedSku -All -ErrorAction SilentlyContinue)

    $verified = @($org.VerifiedDomains | ForEach-Object { "$($_.Name)$(if($_.IsDefault){' (default)'})$(if($_.Type -eq 'Federated'){' [FEDERATED]'})" })
    # Filter empties: @($null) has Count 1, which would hide the "not configured" finding.
    $techMails = @($org.TechnicalNotificationMails | Where-Object { $_ })
    $secMails  = @()
    try { $secMails = @($org.SecurityComplianceNotificationMails | Where-Object { $_ }) } catch {}

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
        return (Get-EARoleInfo -RoleDefinitionId $roleDefId)
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
                Role=$ri.Name; RoleTemplateId=$ri.TemplateId; RoleDefinitionId=$ri.RoleDefinitionId; IsPrivileged=$ri.IsPrivileged; IsGA=$ri.IsGA; IsTier0=$ri.IsTier0
                State=$state; EndDateTime=$i.EndDateTime; MemberType=$i.MemberType; AssignmentType=$i.AssignmentType
                DirectoryScopeId=$i.DirectoryScopeId; AppScopeId=$i.AppScopeId; RoleClassification=$ri.ClassificationSource; Synced=$pr.Synced; MfaCapable=$pr.MfaCapable
            })
        }
    } catch {
        $pimAvailable = $false
        Write-Warn2 "  PIM active-schedule endpoint unavailable - falling back to classic role assignments."
    }

    # --- Model B: ELIGIBLE schedule instances (PIM) ---
    $eligibleCount = 0; $eligibilityKnown = $true
    try {
        foreach ($i in @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)) {
            $ri = _RoleInfo $i.RoleDefinitionId
            $pr = _Principal $i.Principal
            $eligibleCount++
            $assignments.Add([pscustomobject]@{
                PrincipalId=$pr.Id; Principal=($pr.Upn ?? $pr.Name); PrincipalType=$pr.Type
                Role=$ri.Name; RoleTemplateId=$ri.TemplateId; RoleDefinitionId=$ri.RoleDefinitionId; IsPrivileged=$ri.IsPrivileged; IsGA=$ri.IsGA; IsTier0=$ri.IsTier0
                State='Eligible'; EndDateTime=$i.EndDateTime; MemberType=$i.MemberType; AssignmentType='Eligible'
                DirectoryScopeId=$i.DirectoryScopeId; AppScopeId=$i.AppScopeId; RoleClassification=$ri.ClassificationSource; Synced=$pr.Synced; MfaCapable=$pr.MfaCapable
            })
        }
    } catch {
        $eligibilityKnown = $false
        Write-Warn2 "  PIM eligibility endpoint unavailable (requires Entra ID P2)."
    }

    # --- Fallback: classic roleAssignments when PIM is not in use/licensed ---
    $fetchErr = $null
    if (-not $pimAvailable -or $assignments.Count -eq 0) {
        try {
            foreach ($a in @(Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop)) {
                $ri = _RoleInfo $a.RoleDefinitionId
                $pr = _Principal $a.Principal
                $assignments.Add([pscustomobject]@{
                    PrincipalId=$pr.Id; Principal=($pr.Upn ?? $pr.Name); PrincipalType=$pr.Type
                    Role=$ri.Name; RoleTemplateId=$ri.TemplateId; RoleDefinitionId=$ri.RoleDefinitionId; IsPrivileged=$ri.IsPrivileged; IsGA=$ri.IsGA; IsTier0=$ri.IsTier0
                    State='Permanent'; EndDateTime=$null; MemberType='Direct'; AssignmentType='Assigned'
                    DirectoryScopeId=$a.DirectoryScopeId; AppScopeId=$a.AppScopeId; RoleClassification=$ri.ClassificationSource; Synced=$pr.Synced; MfaCapable=$pr.MfaCapable
                })
            }
        } catch {
            $fetchErr = $_
            # last resort: classic directoryRoles + members (errors recorded, not hidden -
            # a failed fetch must surface as Error/Skipped, never as a clean 'Pass')
            try {
                foreach ($dr in @(Get-MgDirectoryRole -All -ErrorAction Stop)) {
                    $ri = _RoleInfo $dr.RoleTemplateId
                    foreach ($m in @(Get-MgDirectoryRoleMember -DirectoryRoleId $dr.Id -All -ErrorAction Stop)) {
                        $pr = _Principal $m
                        $assignments.Add([pscustomobject]@{
                            PrincipalId=$pr.Id; Principal=($pr.Upn ?? $pr.Name); PrincipalType=$pr.Type
                            Role=$ri.Name; RoleTemplateId=$ri.TemplateId; RoleDefinitionId=$ri.RoleDefinitionId; IsPrivileged=$ri.IsPrivileged; IsGA=$ri.IsGA; IsTier0=$ri.IsTier0
                            State='Permanent'; EndDateTime=$null; MemberType='Direct'; AssignmentType='Assigned'
                            DirectoryScopeId='/'; AppScopeId=$null; RoleClassification=$ri.ClassificationSource; Synced=$pr.Synced; MfaCapable=$pr.MfaCapable
                        })
                    }
                }
                $fetchErr = $null
            } catch { if (-not $fetchErr) { $fetchErr = $_ } }
        }
    }

    # De-duplicate by principal, role and BOTH assignment scopes. App-scoped/custom-role
    # grants must not collapse into a tenant- or Administrative-Unit-scoped grant.
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $rows = @(foreach ($a in $assignments) {
        $k = '{0}|{1}|{2}|{3}|{4}' -f $a.PrincipalId,$a.RoleTemplateId,$a.DirectoryScopeId,$a.AppScopeId,$a.State
        if ($seen.Add($k)) { $a }
    })

    # Every real tenant has at least one active role assignment - an EMPTY result with
    # every fetch failed is "UNKNOWN", not "no standing admins". Throw so Invoke-AuditCheck
    # classifies the check Error/Skipped-NoPermission instead of a false clean 'Pass'.
    if ($rows.Count -eq 0 -and -not $pimAvailable) {
        if ($fetchErr) { throw $fetchErr }
        throw "Privileged role assignments could not be retrieved from any endpoint (PIM, classic roleAssignments, directoryRoles) - result is UNKNOWN, not clean."
    }

    $src = Write-Evidence -BaseName 'privileged_roles' -Rows $rows `
        -Title 'Privileged Role Assignments - Permanent vs Eligible vs Time-Bound' `
        -Notes @("PIM endpoints available: $pimAvailable", "Eligible assignments: $eligibleCount")

    $bg = Normalize-StringList -Values $BreakGlassUpns
    $permanentPriv = @($rows | Where-Object { $_.IsPrivileged -and $_.State -eq 'Permanent' })
    $permanentGA   = @($permanentPriv | Where-Object { $_.IsGA })

    # Index rows by principal once - re-scanning all rows per permanent assignment is
    # O(n*m) with hundreds of standing assignments (the systemic case this check exists for).
    $rowsByPrincipal = @{}
    foreach ($r in $rows) {
        $pid0 = [string]$r.PrincipalId
        if (-not $rowsByPrincipal.ContainsKey($pid0)) { $rowsByPrincipal[$pid0] = New-Object System.Collections.Generic.List[object] }
        $rowsByPrincipal[$pid0].Add($r) | Out-Null
    }

    # Per-assignment findings for permanent privileged roles
    foreach ($a in $permanentPriv) {
        $isBreakGlass = ($a.Principal -and ($a.Principal.ToLowerInvariant() -in $bg) -and -not $a.Synced -and $a.PrincipalType -eq 'user')
        if ($isBreakGlass -and $a.IsGA) { continue }   # permanent GA on a break-glass account is the expected posture
        if ($isBreakGlass -and -not $a.IsGA) {
            # A break-glass account should be permanent ONLY for Global Administrator. Any
            # extra standing privileged role widens its blast radius beyond emergency recovery
            # and is still worth reporting (just not at the full standing-privilege severity).
            Add-EntraFinding -Severity 'Medium' -CheckId 'privileged-roles' -Category 'Privileged Access' `
                -Title ("Break-glass account has an extra permanent privileged role: {0} -> {1}" -f $a.Principal, $a.Role) `
                -Evidence ("Designated break-glass account {0} (object id {1}) holds permanent {2}, not only Global Administrator." -f $a.Principal, $a.PrincipalId, $a.Role) `
                -WhyItMatters 'Emergency-access accounts should be minimal and predictable. Extra standing roles increase blast radius and make exception handling (CA exclusions, monitoring, credential storage) unclear.' `
                -RecommendedAction 'Keep the break-glass account permanent only for Global Administrator unless there is a documented recovery requirement for the extra role.' `
                -SourceFile $src -AffectedPrincipal $a.Principal -ObjectType $a.PrincipalType -ObjectId $a.PrincipalId `
                -ResultRows @($rowsByPrincipal[[string]$a.PrincipalId])
            continue
        }

        # Severity follows the role TIER, not the principal type: tier-0 roles are
        # Critical, every other privileged role caps at High. The risk factors are
        # recorded as reasons on the finding instead of escalating its severity - a
        # guest (external) holder is the one exception, because a foreign-tenant
        # credential with standing admin rights is a takeover path regardless of role.
        $isTier0 = [bool]$a.IsTier0
        $sev = if ($isTier0) { 'Critical' } else { 'High' }
        $reasons = @()
        if ($a.MfaCapable -eq $false) { $reasons += 'not MFA-capable' }
        if ($a.Synced)                { $reasons += 'on-prem synced admin' }
        if ($a.PrincipalType -in @('servicePrincipal','group')) { $reasons += "$($a.PrincipalType) principal" }
        if ($a.Principal -like '*#EXT#*') { $sev = 'Critical'; $reasons += 'guest/external' }

        $extra = if ($reasons.Count) { ' (' + ($reasons -join ', ') + ')' } else { '' }
        # Include the directory object id so two findings for similarly-named but DISTINCT
        # accounts (e.g. niclas@contoso.se vs niclas@contoso.onmicrosoft.com) are clearly
        # separate objects, not a double-count - and so each gets a stable per-object id.
        Add-EntraFinding -Severity $sev -CheckId 'privileged-roles' -Category 'Privileged Access' `
            -Title ("Permanent (standing) {0}: {1}" -f $a.Role, $a.Principal) `
            -Evidence ("{0} (object id {1}) holds {2} as a PERMANENT/standing assignment{3}." -f $a.Principal, $a.PrincipalId, $a.Role, $extra) `
            -WhyItMatters 'Standing privileged access is the largest cloud attack surface - the credential is always active. PIM-eligible (just-in-time) access is the target posture; permanent high-value roles, synced admins, and SP/guest admins defeat the boundaries PIM enforces.' `
            -RecommendedAction 'Convert this assignment to PIM-eligible (JIT) and remove the standing grant. Keep only two cloud-only break-glass Global Admins permanent. Require phishing-resistant MFA on every privileged principal.' `
            -SourceFile $src -AffectedPrincipal $a.Principal -ObjectType $a.PrincipalType -ObjectId $a.PrincipalId `
            -ResultRows @($rowsByPrincipal[[string]$a.PrincipalId])
    }

    # Redundant: principal is BOTH eligible AND permanently active for the same role
    $byPrincipalRole = $rows | Group-Object PrincipalId, RoleTemplateId, DirectoryScopeId, AppScopeId
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
    if ($eligibleCount -eq 0 -and $permanentPriv.Count -gt 0 -and ($eligibilityKnown -or -not $script:HasP2)) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'privileged-roles' -Category 'Privileged Access' `
            -Title 'PIM/just-in-time access is not in use - over-reliance on standing privilege' `
            -Evidence ("{0} permanent privileged assignment(s), 0 eligible (PIM) assignments." -f $permanentPriv.Count) `
            -WhyItMatters 'Without PIM-eligible assignments every admin right is standing access. Eligible/JIT activation with approval and time limits is the recommended posture and requires Entra ID P2.' `
            -RecommendedAction 'License Entra ID P2 and onboard privileged roles to PIM, converting standing assignments to eligible with activation requirements.' `
            -SourceFile $src
    }
    if (-not $eligibilityKnown -and $script:HasP2) {
        Add-EntraFinding -Severity 'Information' -CheckId 'privileged-roles' -Category 'Privileged Access' `
            -Title 'PIM-eligible role assignments could not be evaluated' `
            -Evidence 'The roleEligibilityScheduleInstances read failed on an Entra ID P2 tenant; eligible administrators are unknown, not zero.' `
            -WhyItMatters 'Eligible role holders remain privileged identities for MFA, lifecycle and risk hygiene even when their role is not currently activated.' `
            -RecommendedAction 'Verify RoleManagement.Read.Directory / RoleEligibilitySchedule.Read.Directory and re-run.' -SourceFile $src -CoverageGap
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
    # Shared assignment cache (one Graph download per run instead of a private re-fetch).
    $active = @((Get-EAPrivAssignments) | Where-Object { $_.State -eq 'Active' })
    if ($active.Count -eq 0 -and $script:PrivAssignmentsFailed) {
        # Both role-assignment fetches failed - the volume is UNKNOWN, not confirmed low.
        Add-EntraFinding -Severity 'Information' -CheckId 'directory-roles' -Category 'Privileged Access' `
            -Title 'Privileged role assignment volume could not be evaluated' `
            -Evidence 'Both role-assignment fetches failed - Global Admin and privileged-assignment volume is unknown, not confirmed low.' `
            -WhyItMatters 'A failed fetch must not be reported as a low-admin-count pass; the volume was not assessed.' `
            -RecommendedAction 'Re-run the directory-roles check; verify Graph connectivity/throttling and the RoleManagement.Read.Directory permission.' -CoverageGap
        return
    }

    # Key by role TEMPLATE id (not display name, which can be localized/renamed) so the
    # privileged classification and GA count are robust.
    $byRole = @{}        # templateId -> HashSet[principalId]
    $roleName = @{}      # templateId -> display name
    $rolePrivileged = @{}
    foreach ($a in $active) {
        $tmpl = $a.RoleTemplateId
        $roleName[$tmpl] = $a.RoleName
        $rolePrivileged[$tmpl] = [bool]$a.IsPrivileged
        if (-not $byRole.ContainsKey($tmpl)) { $byRole[$tmpl] = [System.Collections.Generic.HashSet[string]]::new() }
        if ($a.PrincipalId) { [void]$byRole[$tmpl].Add($a.PrincipalId) }
    }
    foreach ($tmpl in ($byRole.Keys | Sort-Object { $roleName[$_] })) {
        $rows += [pscustomobject]@{ Role=$roleName[$tmpl]; DistinctPrincipals=$byRole[$tmpl].Count; Privileged=[bool]$rolePrivileged[$tmpl] }
    }
    $src = Write-Evidence -BaseName 'directory_role_counts' -Rows $rows -Title 'Active Privileged Role Assignment Volume'

    $gaCount = if ($byRole.ContainsKey($script:GlobalAdminTemplateId)) { $byRole[$script:GlobalAdminTemplateId].Count } else { 0 }
    $totalPriv = 0
    foreach ($tmpl in $byRole.Keys) { if ($rolePrivileged[$tmpl]) { $totalPriv += $byRole[$tmpl].Count } }

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

    # Resolve manager in one expanded, paged GET rather than one request per user. Keep
    # this separate from the shared user cache so a tenant/API that rejects the expansion
    # loses only this sub-check, not every user-based audit check.
    $managerKnown = $true; $managerRows = @()
    try {
        $managerUsers = @(Get-MgUser -All -Property 'id,userPrincipalName,displayName,accountEnabled,userType' -ExpandProperty 'manager($select=id)' -ErrorAction Stop)
        $managerRows = @(foreach ($mu in $managerUsers) {
            if (-not $mu.AccountEnabled -or $mu.UserType -eq 'Guest') { continue }
            $manager = Get-EAField $mu 'Manager'; if ($null -eq $manager) { $manager = Get-Ap $mu 'manager' }
            $managerId = if ($manager) { Get-EAField $manager 'Id' } else { $null }; if ($null -eq $managerId -and $manager) { $managerId = Get-EAField $manager 'id' }
            [pscustomobject]@{ UserPrincipalName=$mu.UserPrincipalName; DisplayName=$mu.DisplayName; Enabled=[bool]$mu.AccountEnabled; HasManager=[bool]$managerId }
        })
    } catch { $managerKnown = $false }
    $noManager = @($managerRows | Where-Object { -not $_.HasManager })
    $managerSrc = $null
    if ($managerRows.Count -gt 0) { $managerSrc = Write-Evidence -BaseName 'account_managers' -Rows $managerRows -Title 'Enabled Member Manager Coverage' }

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
    if (-not $managerKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'accounts' -Category 'Identity Hygiene' `
            -Title 'Manager assignment coverage could not be evaluated' `
            -Evidence 'The read-only users-with-manager expansion failed; managerless-account status is unknown, not confirmed clean.' `
            -WhyItMatters 'Manager metadata supports ownership, access reviews and reliable joiner/mover/leaver workflows.' `
            -RecommendedAction 'Verify User.Read.All and re-run, or review manager assignments manually.' -SourceFile $src -CoverageGap
    } elseif ($noManager.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'accounts' -Category 'Identity Hygiene' `
            -Title ("{0} enabled member account(s) have no manager assigned" -f $noManager.Count) `
            -Evidence ("Enabled non-guest users without a manager: {0}" -f (($noManager | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Missing manager ownership weakens access reviews and automated joiner/mover/leaver decisions; legitimate executive/service-account exceptions should be documented.' `
            -RecommendedAction 'Assign managers to workforce accounts and document/exclude legitimate top-level or service-account exceptions in the governance process.' `
            -SourceFile $managerSrc -ResultRows $noManager
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
            -RecommendedAction 'Grant AuditLog.Read.All and ensure Entra ID P1+ so sign-in activity is available.' -SourceFile $null -CoverageGap
        return
    }
    $users = Get-EAUsers -IncludeSignInActivity

    # Privileged principals get a tighter inactivity bar (escalated severity).
    # Shared assignment cache (one Graph download per run instead of a private re-fetch).
    $privIds = @{}
    try { foreach ($id in (Get-EAPrivilegedUserMap).Keys) { $privIds[$id] = $true } } catch {}
    $privCoverageIncomplete = ($script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)

    $now0      = (Get-Date).ToUniversalTime()
    $cut       = $now0.AddDays(-$InactiveDays)
    $cut180    = $now0.AddDays(-180)
    $created30 = $now0.AddDays(-30)
    $privCut   = $now0.AddDays(-([Math]::Min($InactiveDays, 45)))   # admins held to <= 45 days

    # Collected as a single foreach expression: array += per user is O(n^2) at 50k users.
    $rows = @(foreach ($u in $users) {
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
        [pscustomobject]@{
            UserPrincipalName       = $u.UserPrincipalName
            Enabled                 = $u.AccountEnabled
            Privileged              = [bool]($u.Id -and $privIds.ContainsKey($u.Id))
            Created                 = $u.CreatedDateTime
            LastSuccessfulOrAttempt = $eff
            Confidence              = $conf
        }
    })
    $src = Write-Evidence -BaseName 'stale_users' -Rows $rows -Title ("Stale / Inactive Users (> {0} days)" -f $InactiveDays) `
        -Notes @('Activity prefers lastSuccessfulSignInDateTime. Confidence "AttemptOnly" = only failed/attempted sign-ins were recorded (no successful sign-in).')

    if ($privCoverageIncomplete) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleusers' -Category 'Identity Hygiene' `
            -Title 'Privileged stale-user classification is incomplete' `
            -Evidence 'Active/eligible role assignments or a privileged-group membership expansion could not be fully read; some stale users may be classified as non-admin.' `
            -WhyItMatters 'Eligible and group-based administrators should receive the tighter privileged-account inactivity threshold.' `
            -RecommendedAction 'Restore role/group read access and re-run the stale-user check.' -SourceFile $src -CoverageGap
    }

    # Never-seen admins only count once the account is older than the 30-day grace window,
    # matching the non-privileged rule - a GA created yesterday is not a dormant admin.
    $privStale  = @($rows | Where-Object { $_.Privileged -and $_.Enabled -and ((($_.Confidence -eq 'NeverSeen') -and $_.Created -and $_.Created -lt $created30) -or ($_.Confidence -ne 'NeverSeen' -and $_.LastSuccessfulOrAttempt -lt $privCut)) })
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

    # privileged guests (cross-ref active AND eligible role assignments via the shared cache, which
    # also tracks fetch failure so silence here is never mistaken for "no privileged guests").
    # A THROW from the cache helper (e.g. the role-definition read 403s before its own
    # failure tracking) must count as a failed cross-reference too.
    $privGuestUpns = @()
    $privXrefFailed = $false
    try {
        foreach ($uid in (Get-EAPrivilegedUserMap).Keys) {
            if ($script:UserById.ContainsKey($uid)) {
                $pu = $script:UserById[$uid]
                if ($pu.UserType -eq 'Guest' -or $pu.UserPrincipalName -like '*#EXT#*') { $privGuestUpns += $pu.UserPrincipalName }
            }
        }
        $privGuestUpns = @($privGuestUpns | Sort-Object -Unique)
    } catch { $privXrefFailed = $true }

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
    } elseif ($script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete -or $privXrefFailed) {
        # The role-assignment fetch failed - "no privileged guests" is UNKNOWN, not clean.
        Add-EntraFinding -Severity 'Information' -CheckId 'guests' -Category 'External Access' `
            -Title 'Privileged-guest cross-reference could not be evaluated' `
            -Evidence 'Role assignments could not be read, so whether any guest holds a directory role is unknown - not confirmed clean.' `
            -WhyItMatters 'Silence here must not read as a pass; a privileged guest is a High finding when visible.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory (or retry on transient failure) and re-run the guests check.' -SourceFile $src -CoverageGap
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
    # privileged principals (shared assignment cache - one Graph download per run)
    $privIds = @{}
    try { foreach ($id in (Get-EAPrivilegedUserMap).Keys) { $privIds[$id] = $true } } catch {}
    $privCoverageIncomplete = ($script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)

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

    # Collected as a single foreach expression: array += per user is O(n^2) at 50k rows.
    $rows = @(foreach ($r in $reg) {
        $methods = @($r.MethodsRegistered)
        $hasPhish  = (@($methods | Where-Object { $_ -match $phishRx }).Count -gt 0)
        $hasStrong = (@($methods | Where-Object { $_ -match $strongRx }).Count -gt 0)
        $isPriv = ([bool]$r.IsAdmin -or ($r.Id -and $privIds.ContainsKey($r.Id)))
        $enabled = if ($r.Id -and $enabledById.ContainsKey($r.Id)) { $enabledById[$r.Id] } else { $true }
        [pscustomobject]@{
            UserPrincipalName=$r.UserPrincipalName; Privileged=$isPriv; Enabled=$enabled
            MfaRegistered=[bool]$r.IsMfaRegistered; MfaCapable=[bool]$r.IsMfaCapable
            StrongMethod=$hasStrong; PhishingResistant=$hasPhish; Methods=($methods -join ',')
        }
    })
    $src = Write-Evidence -BaseName 'mfa_registration' -Rows $rows -Title 'MFA Posture - Registered / Capable / Strong / Phishing-Resistant'

    if ($privCoverageIncomplete) {
        Add-EntraFinding -Severity 'Information' -CheckId 'mfa' -Category 'Authentication' `
            -Title 'Privileged MFA classification is incomplete' `
            -Evidence 'Active/eligible role assignments or a privileged-group membership expansion could not be fully read; some administrators may be absent from privileged MFA findings.' `
            -WhyItMatters 'Eligible and group-based administrators need the same phishing-resistant MFA posture as standing administrators.' `
            -RecommendedAction 'Restore role/group read access and re-run the MFA check.' -SourceFile $src -CoverageGap
    }

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
    # InvariantCulture: ':' in a format string is the CULTURE time separator, so e.g.
    # fi-FI/da-DK render '14.35.12' - an invalid OData timestamp that 400s the query.
    $since = (Get-Date).ToUniversalTime().AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $legacyClients = 'Exchange ActiveSync|Authenticated SMTP|IMAP4|POP3|MAPI Over HTTP|Other clients|AutoDiscover|Exchange Online PowerShell|Exchange Web Services|Outlook Anywhere'
    # Filter clientAppUsed SERVER-SIDE: downloading every sign-in for 30 days and
    # filtering locally pulls millions of rows on real tenants (hours / throttling).
    # The regex Where-Object stays as a defensive post-filter.
    $legacyList = @('Exchange ActiveSync','Authenticated SMTP','IMAP4','POP3','MAPI Over HTTP','Other clients','AutoDiscover','Exchange Online PowerShell','Exchange Web Services','Outlook Anywhere (RPC over HTTP)')
    $clientFilter = (($legacyList | ForEach-Object { "clientAppUsed eq '$_'" }) -join ' or ')
    $signins = @(Get-MgAuditLogSignIn -All -Filter "createdDateTime ge $since and ($clientFilter)" -ErrorAction Stop |
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
    # Track read success per source: a swallowed read must not evaluate as "setting is
    # fine" (false clean) or as "zero CA policies" (false High).
    $sd = $null;    $sdKnown = $true;    try { $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop } catch { $sdKnown = $false }
    $authz = $null; $authzKnown = $true; try { $authz = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop } catch { $authzKnown = $false }
    $caCount = 0;   $caKnown = $true;    try { $caCount = @(Get-EACaPolicies | Where-Object { $_.State -eq 'enabled' }).Count } catch { $caKnown = $false }

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

    if ($sd -and -not $sd.IsEnabled -and $caKnown -and $caCount -eq 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'tenantposture' -Category 'Tenant Posture' `
            -Title 'Security Defaults are OFF and zero Conditional Access policies are enabled' `
            -Evidence 'IsEnabled=false on Security Defaults with zero enabled Conditional Access policies - the tenant can be password-only.' `
            -WhyItMatters 'With neither Security Defaults nor Conditional Access, there is no baseline MFA enforcement at all - the most common cause of account takeover.' `
            -RecommendedAction 'Enable Conditional Access MFA policies (preferred on licensed tenants) or turn on Security Defaults as an interim baseline.' -SourceFile $src
    } elseif ($sd -and -not $sd.IsEnabled -and -not $caKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'tenantposture' -Category 'Tenant Posture' `
            -Title 'Conditional Access posture unknown - Security Defaults are off but CA policies could not be read' `
            -Evidence 'Security Defaults are disabled and the Conditional Access policy read failed, so whether baseline MFA enforcement exists is UNKNOWN - not confirmed either way.' `
            -WhyItMatters 'A failed CA read must not be reported as "zero CA policies" (false alarm) or as covered (false clean).' `
            -RecommendedAction 'Verify Policy.Read.All is granted and re-run the tenantposture check.' -SourceFile $src -CoverageGap
    } elseif ($sd -and $sd.IsEnabled -and $caKnown -and $caCount -gt 0) {
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
    if (-not $sdKnown -or -not $authzKnown) {
        $failed = @(); if (-not $sdKnown) { $failed += 'Security Defaults policy' }; if (-not $authzKnown) { $failed += 'authorization policy' }
        Add-EntraFinding -Severity 'Information' -CheckId 'tenantposture' -Category 'Tenant Posture' `
            -Title 'Tenant posture settings could not be fully assessed' `
            -Evidence ("Could not read: {0}. The unread settings are UNKNOWN, not confirmed clean." -f ($failed -join ', ')) `
            -WhyItMatters 'A swallowed policy read must not be reported as "no permissive defaults detected".' `
            -RecommendedAction 'Verify Policy.Read.All is granted and re-run the tenantposture check.' -SourceFile $src -CoverageGap
    } elseif ($script:Findings.Where({$_.CheckId -eq 'tenantposture'}).Count -eq 0) {
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
    $pols = @(Get-EACaPolicies)
    $named = @(); $namedKnown = $true; $namedError = $null
    try { $named = @(Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop) }
    catch { $namedKnown = $false; $namedError = $_.Exception.Message }

    $rows = $pols | Select-Object DisplayName, State,
        @{n='IncludeUsers';e={ ($_.Conditions.Users.IncludeUsers -join ',') }},
        @{n='ExcludeUsers';e={ ($_.Conditions.Users.ExcludeUsers -join ',') }},
        @{n='IncludeGroups';e={ ($_.Conditions.Users.IncludeGroups -join ',') }},
        @{n='ExcludeGroups';e={ ($_.Conditions.Users.ExcludeGroups -join ',') }},
        @{n='IncludeRoles';e={ ($_.Conditions.Users.IncludeRoles -join ',') }},
        @{n='ExcludeRoles';e={ ($_.Conditions.Users.ExcludeRoles -join ',') }},
        @{n='IncludeResources';e={ ($_.Conditions.Applications.IncludeApplications -join ',') }},
        @{n='ExcludeResources';e={ ($_.Conditions.Applications.ExcludeApplications -join ',') }},
        @{n='Controls';e={ ($_.GrantControls.BuiltInControls -join ',') }},
        @{n='GrantOperator';e={ $_.GrantControls.Operator }},
        @{n='AuthenticationStrength';e={ $_.GrantControls.AuthenticationStrength.Id }},
        @{n='ClientApps';e={ ($_.Conditions.ClientAppTypes -join ',') }},
        @{n='UserRisk';e={ ($_.Conditions.UserRiskLevels -join ',') }},
        @{n='SignInRisk';e={ ($_.Conditions.SignInRiskLevels -join ',') }}
    $src = Write-Evidence -BaseName 'conditional_access' -Rows $rows -Title 'Conditional Access Policies'
    if ($named.Count -gt 0) {
        $nrows = $named | Select-Object DisplayName, @{n='Trusted';e={ (Get-EAField $_ 'IsTrusted') }}, @{n='Type';e={ (Get-EAField $_ '@odata.type') }}
        Write-Evidence -BaseName 'named_locations' -Rows $nrows -Title 'Named Locations' | Out-Null
    }
    if (-not $namedKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Conditional Access named-location coverage is unknown' `
            -Evidence ("Named locations could not be read: {0}. Location-based policy trust could not be fully verified." -f $namedError) `
            -WhyItMatters 'Without the named-location inventory, an excluded location ID cannot be proven to represent a trusted network and location-based baselines may be overstated.' `
            -RecommendedAction 'Verify Policy.Read.All and Conditional Access reader access, then re-run the audit.' `
            -SourceFile $src -RuleId 'capolicies-named-location-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }

    $enabled = @($pols | Where-Object { $_.State -eq 'enabled' })

    $bg = Normalize-StringList -Values $BreakGlassUpns
    $allowedBgIds = @()
    try {
        foreach ($u in @(Get-EAUsers)) {
            if ($u.Id -and $u.UserPrincipalName -and $u.UserPrincipalName.ToLowerInvariant() -in $bg) { $allowedBgIds += [string]$u.Id }
        }
    } catch {}

    function _GrantBlocks($p) { return (@($p.GrantControls.BuiltInControls) -contains 'block') }
    function _GrantRequiresBuiltIn($p, [string]$control) {
        $built = @($p.GrantControls.BuiltInControls | Where-Object { $_ })
        if ($built -notcontains $control) { return $false }
        if ([string]$p.GrantControls.Operator -match '^(?i)OR$' -and @($built | Where-Object { $_ -ne $control }).Count -gt 0) { return $false }
        return $true
    }
    function _UniversalUserResourcePolicy($p, [string[]]$ignore = @()) {
        return ((Test-CaPolicyTargetsAllUsers $p $allowedBgIds) -and
                (Test-CaPolicyTargetsAllResources $p) -and
                -not (Test-CaPolicyHasNarrowingConditions $p $ignore))
    }

    $mfaForAllPolicies = @($enabled | Where-Object {
        (Test-CaPolicyRequiresMfaOrStrength $_) -and (_UniversalUserResourcePolicy $_)
    })
    $legacyPolicies = @($enabled | Where-Object {
        (_GrantBlocks $_) -and
        (@($_.Conditions.ClientAppTypes) -contains 'exchangeActiveSync') -and
        (@($_.Conditions.ClientAppTypes) -contains 'other') -and
        (_UniversalUserResourcePolicy -p $_ -ignore @('ClientApps'))
    })

    if ($pols.Count -eq 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No Conditional Access policies are configured' `
            -Evidence 'Zero CA policies returned.' `
            -WhyItMatters 'Conditional Access is the cloud control plane (the GPO analog). With no policies, MFA, legacy-auth blocking and device compliance are not enforced.' `
            -RecommendedAction 'Create baseline CA policies: MFA for admins, MFA for all users, block legacy auth, require compliant/hybrid-joined devices.' -SourceFile $src
        return
    }
    if ($mfaForAllPolicies.Count -eq 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No effective all-users, all-resources Conditional Access MFA baseline' `
            -Evidence 'No enabled policy both mandates MFA/authentication strength (including safe AND/OR evaluation), covers all resources without app exclusions, covers all users except designated break-glass users, and has no narrowing platform/location/risk/device conditions.' `
            -WhyItMatters 'Without tenant-wide MFA, any single password compromise grants access. This is the baseline cloud identity control.' `
            -RecommendedAction 'Create an enabled CA policy requiring MFA for all users and all resources, with only direct break-glass exclusions and no alternative OR grant.' -SourceFile $src
    }
    if ($legacyPolicies.Count -eq 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No effective all-users, all-resources legacy-authentication block' `
            -Evidence 'No enabled block policy covers both exchangeActiveSync and other legacy clients across all users/resources without application, user/group/role, platform, location or device-condition gaps.' `
            -WhyItMatters 'Legacy auth bypasses MFA; without a block, password-spray against legacy protocols defeats Conditional Access.' `
            -RecommendedAction 'Create an enabled block policy for exchangeActiveSync and other legacy clients covering all users and all resources (except direct break-glass users).' -SourceFile $src
    }

    # Additional modern CA baselines. Risk policies are P2-only and workload-identity CA
    # is checked only when its own premium entitlement was detected.
    if ($script:HasP2) {
        $signInRisk = @($enabled | Where-Object {
            $riskLevels = @((Get-EAField $_.Conditions 'SignInRiskLevels'))
            (Test-CaPolicyRequiresMfaOrStrength $_) -and
            ($riskLevels -contains 'high') -and ($riskLevels -contains 'medium') -and
            (_UniversalUserResourcePolicy -p $_ -ignore @('SignInRisk'))
        })
        if ($signInRisk.Count -eq 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'No effective medium/high sign-in-risk Conditional Access policy' `
                -Evidence 'Entra ID P2 is present, but no enabled all-users/all-resources policy mandates MFA/authentication strength for both medium and high sign-in risk without scope exclusions or unrelated narrowing conditions.' `
                -WhyItMatters 'Identity Protection sign-in risk is a live compromise signal; requiring MFA at high risk blocks password-only takeover attempts automatically.' `
                -RecommendedAction 'Create an enabled sign-in-risk CA policy covering all users/resources and requiring MFA for medium and high risk.' -SourceFile $src
        }

        $userRisk = @($enabled | Where-Object {
            (Test-CaPolicyRequiresMfaOrStrength $_) -and
            (_GrantRequiresBuiltIn $_ 'passwordChange') -and
            ([string]$_.GrantControls.Operator -notmatch '^(?i)OR$') -and
            (@((Get-EAField $_.Conditions 'UserRiskLevels')) -contains 'high') -and
            (_UniversalUserResourcePolicy -p $_ -ignore @('UserRisk'))
        })
        if ($userRisk.Count -eq 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'No effective high user-risk secure password-change policy' `
                -Evidence 'Entra ID P2 is present, but no enabled all-users/all-resources high-user-risk policy requires both MFA and password change with AND semantics.' `
                -WhyItMatters 'A risky user represents likely credential compromise. Secure password change with MFA remediates the compromised credential without accepting password-only self-remediation.' `
                -RecommendedAction 'Create an enabled high-user-risk policy requiring MFA AND password change for all users/resources.' -SourceFile $src
        }
    }

    $deviceCodePolicies = @($enabled | Where-Object {
        $flows = Get-EAField $_.Conditions 'AuthenticationFlows'
        (_GrantBlocks $_) -and
        (@((Get-EAField $flows 'TransferMethods')) -contains 'deviceCodeFlow') -and
        (_UniversalUserResourcePolicy -p $_ -ignore @('AuthenticationFlows'))
    })
    if ($deviceCodePolicies.Count -eq 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No effective Conditional Access block for device code flow' `
            -Evidence 'No enabled all-users/all-resources block policy targets the deviceCodeFlow authentication flow without unrelated narrowing conditions.' `
            -WhyItMatters 'Device-code phishing can trick a user into authorizing an attacker-controlled session without the victim entering credentials into the attacker site.' `
            -RecommendedAction 'Block device code flow tenant-wide, then create narrowly scoped exceptions only for documented workloads that require it.' -SourceFile $src
    }

    $deviceCompliancePolicies = @($enabled | Where-Object {
        (_GrantRequiresBuiltIn $_ 'compliantDevice') -and (_UniversalUserResourcePolicy $_)
    })
    if ($deviceCompliancePolicies.Count -eq 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No universal compliant-device Conditional Access baseline' `
            -Evidence 'No enabled all-users/all-resources policy makes compliantDevice mandatory without an OR alternative, application exclusions, or other narrowing conditions.' `
            -WhyItMatters 'Authentication alone does not establish device health; unmanaged or non-compliant endpoints remain a common token and data theft path.' `
            -RecommendedAction 'Require compliant devices for supported access paths and document narrowly scoped exceptions for unmanaged/BYOD scenarios.' -SourceFile $src
    }

    if ($script:WorkloadIdP) {
        function _TargetsAllTenantServicePrincipals($p) {
            $ca = Get-EAField $p.Conditions 'ClientApplications'
            $incSp = @((Get-EAField $ca 'IncludeServicePrincipals') | Where-Object { $_ })
            $excSp = @((Get-EAField $ca 'ExcludeServicePrincipals') | Where-Object { $_ })
            $spFilter = Get-EAField $ca 'ServicePrincipalFilter'
            return (($incSp -contains 'ServicePrincipalsInMyTenant' -or $incSp -contains 'All') -and
                $excSp.Count -eq 0 -and
                -not ($spFilter -and ((Get-EAField $spFilter 'Mode') -or (Get-EAField $spFilter 'Rule'))))
        }

        # Prove the exclusions used by the location baseline are actually trusted.
        # An arbitrary excluded named location is a bypass, not a trusted-network design.
        $trustedNamedLocationIds = @($named | Where-Object { (Get-EAField $_ 'IsTrusted') -eq $true } | ForEach-Object { [string]$_.Id })
        $workloadLocationPolicies = if (-not $namedKnown -or $trustedNamedLocationIds.Count -eq 0) { @() } else { @($enabled | Where-Object {
            $locations = Get-EAField $_.Conditions 'Locations'
            $includeLocations = @((Get-EAField $locations 'IncludeLocations') | Where-Object { $_ })
            $excludeLocations = @((Get-EAField $locations 'ExcludeLocations') | Where-Object { $_ })
            $untrustedExclusions = @($excludeLocations | Where-Object {
                $_ -ne 'AllTrusted' -and [string]$_ -notin $trustedNamedLocationIds
            })
            (_GrantBlocks $_) -and (Test-CaPolicyTargetsAllResources $_) -and
            (_TargetsAllTenantServicePrincipals $_) -and
            ($includeLocations -contains 'All') -and $excludeLocations.Count -gt 0 -and $untrustedExclusions.Count -eq 0 -and
            -not (Test-CaPolicyHasNarrowingConditions $_ @('ClientApplications','Locations'))
        }) }

        $workloadRiskPolicies = @($enabled | Where-Object {
            $riskLevels = @((Get-EAField $_.Conditions 'ServicePrincipalRiskLevels') | Where-Object { $_ })
            (_GrantBlocks $_) -and (Test-CaPolicyTargetsAllResources $_) -and
            (_TargetsAllTenantServicePrincipals $_) -and ($riskLevels -contains 'high') -and
            -not (Test-CaPolicyHasNarrowingConditions $_ @('ClientApplications','ServicePrincipalRisk'))
        })

        if ($workloadLocationPolicies.Count -eq 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'No effective trusted-location workload-identity Conditional Access policy' `
                -Evidence 'Workload ID Premium is present, but no enabled all-resources policy blocks all tenant service principals from every location except AllTrusted or named locations verified as trusted, without unrelated narrowing conditions.' `
                -WhyItMatters 'Service principals cannot perform user MFA. Stolen credentials can operate from attacker infrastructure unless workload access is constrained to trusted networks.' `
                -RecommendedAction 'Create a workload-identity CA policy covering all tenant service principals/resources and block access outside verified trusted locations; document narrow exceptions separately.' -SourceFile $src
        }
        if ($workloadRiskPolicies.Count -eq 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'No effective high-risk workload-identity Conditional Access policy' `
                -Evidence 'Workload ID Premium is present, but no enabled all-resources policy blocks all tenant service principals at high service-principal risk without exclusions or unrelated narrowing conditions.' `
                -WhyItMatters 'A high service-principal risk signal indicates likely workload-credential compromise and should stop token issuance automatically.' `
                -RecommendedAction 'Create a workload-identity CA policy covering all tenant service principals/resources and block high service-principal risk; include medium risk where operationally appropriate.' -SourceFile $src
        }
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
        $isTrusted = (Get-EAField $n 'IsTrusted')
        $ranges = (Get-EAField $n 'IpRanges')
        if ($isTrusted -and $ranges) {
            # ipRanges elements are raw dictionaries (no AdditionalProperties member), so
            # Get-Ap always returned $null here and this finding could never fire.
            $broad = @($ranges | Where-Object {
                $cidr = if ($_ -is [System.Collections.IDictionary]) { $_['cidrAddress'] } else { Get-Ap $_ 'cidrAddress' }
                "$cidr" -match '/(?:[0-9]|1[0-6])$'
            })
            if ($broad.Count -gt 0) {
                Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                    -Title ("Trusted named location '{0}' contains a very broad IP range" -f $n.DisplayName) `
                    -Evidence 'A trusted location with a wide CIDR can be used to bypass MFA from large address space.' `
                    -WhyItMatters 'Trusted locations are commonly used as MFA exclusions; an over-broad trusted range turns into a Conditional Access bypass primitive.' `
                    -RecommendedAction 'Restrict trusted named locations to specific corporate egress IPs only; never use them to broadly exclude MFA.' -SourceFile $src
            }
        }
    }
    # EFFECTIVE admin coverage uses the full active+eligible population, including users
    # reached through role-assignable groups. A policy counts only if it covers all resources,
    # has no app exclusions/narrowing conditions and makes its grant mandatory under OR.
    $mfaPolicies = @($enabled | Where-Object {
        (Test-CaPolicyRequiresMfaOrStrength $_) -and (Test-CaPolicyTargetsAllResources $_) -and
        -not (Test-CaPolicyHasNarrowingConditions $_)
    })
    $phishPolicies = @($enabled | Where-Object {
        (Test-CaPolicyRequiresPhishingResistantStrength $_) -and (Test-CaPolicyTargetsAllResources $_) -and
        -not (Test-CaPolicyHasNarrowingConditions $_)
    })
    $privUserIds = @{}
    try { $privUserIds = Get-EAPrivilegedUserMap } catch { $script:PrivilegedUserMapIncomplete = $true }
    if (($script:PrivAssignmentsFailed -or $script:PrivilegedUserMapIncomplete) -and $privUserIds.Count -eq 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Effective admin MFA coverage could not be evaluated' `
            -Evidence 'The privileged-role assignment list or a privileged-group membership expansion failed, so per-admin CA applicability was not assessed - coverage is unknown, not confirmed.' `
            -WhyItMatters 'Without the admin population the report cannot tell whether every privileged account is effectively covered by an MFA policy; silence here must not read as a pass.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory plus group membership read permissions (or retry on transient failure) and re-run the capolicies check.' -SourceFile $src -CoverageGap
    }
    elseif ($script:PrivilegedUserMapIncomplete) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Effective admin CA coverage is incomplete for one or more privileged groups' `
            -Evidence 'At least one role-assignable group could not be expanded; direct and readable group-based administrators were evaluated, but the full privileged population is unknown.' `
            -WhyItMatters 'An unreadable privileged group can contain administrators outside MFA or authentication-strength coverage.' `
            -RecommendedAction 'Grant Group.Read.All/Member.Read.Hidden as appropriate and re-run the CA check.' -SourceFile $src -CoverageGap
    }
    $uncovered = @(); $uncoveredPhish = @(); $unknownScope = @(); $evaluated = 0
    foreach ($uid in $privUserIds.Keys) {
        $upn = if ($script:UserById.ContainsKey($uid)) { $script:UserById[$uid].UserPrincipalName } else { $uid }
        if ($upn -and $upn.ToLowerInvariant() -in $bg) { continue }   # break-glass expected to be excluded
        $evaluated++   # count only non-break-glass admins, so the all-uncovered test below is correct
        $scope = Get-EAUserScopeIds $uid
        $adminRoles = [System.Collections.Generic.HashSet[string]]::new($scope.Roles)
        foreach ($a in @($privUserIds[$uid])) { if ($a.RoleTemplateId) { [void]$adminRoles.Add([string]$a.RoleTemplateId) } }

        $covered = $false; $phishCovered = $false; $mfaMembershipUnknown = $false; $phishMembershipUnknown = $false
        foreach ($p in $mfaPolicies) {
            $cu = $p.Conditions.Users
            if (-not $scope.Known -and (@($cu.IncludeGroups | Where-Object { $_ }).Count -gt 0 -or @($cu.ExcludeGroups | Where-Object { $_ }).Count -gt 0)) { $mfaMembershipUnknown = $true; continue }
            if (Test-CaPolicyAppliesToUser $p $uid $scope.Groups $adminRoles) { $covered = $true; break }
        }
        foreach ($p in $phishPolicies) {
            $cu = $p.Conditions.Users
            if (-not $scope.Known -and (@($cu.IncludeGroups | Where-Object { $_ }).Count -gt 0 -or @($cu.ExcludeGroups | Where-Object { $_ }).Count -gt 0)) { $phishMembershipUnknown = $true; continue }
            if (Test-CaPolicyAppliesToUser $p $uid $scope.Groups $adminRoles) { $phishCovered = $true; break }
        }
        $unknownFor = @()
        if ($mfaMembershipUnknown -and -not $covered) { $unknownFor += 'MFA' }
        if ($phishMembershipUnknown -and -not $phishCovered) { $unknownFor += 'phishing-resistant MFA' }
        if ($unknownFor.Count -gt 0) { $unknownScope += [pscustomobject]@{ Account=$upn; Reason=("group membership could not be resolved for {0}" -f ($unknownFor -join ' and ')) } }
        if (-not $covered -and -not $mfaMembershipUnknown) { $uncovered += [pscustomobject]@{ Account = $upn } }
        if (-not $phishCovered -and -not $phishMembershipUnknown) { $uncoveredPhish += [pscustomobject]@{ Account = $upn } }
    }
    if ($unknownScope.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("{0} privileged account(s) have unknown CA coverage due to unreadable membership" -f $unknownScope.Count) `
            -Evidence ("Coverage could not be determined for: {0}" -f (($unknownScope.Account | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Group-scoped includes/exclusions cannot be evaluated without membership data; unknown coverage must not be reported as protected.' `
            -RecommendedAction 'Restore transitive membership read access and re-run.' -SourceFile $src -ResultRows $unknownScope -CoverageGap
    }
    if ($evaluated -gt 0 -and ($mfaPolicies.Count -eq 0 -or $uncovered.Count -eq $evaluated)) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No effective Conditional Access MFA coverage for administrators' `
            -Evidence ("No enabled MFA/auth-strength CA policy effectively applies to any of the {0} privileged account(s) evaluated (after include/exclude evaluation)." -f $evaluated) `
            -WhyItMatters 'Admins are the highest-value targets; if no MFA/authentication-strength policy actually applies to them once include/exclude scope is evaluated, their accounts can be taken over with a stolen password. An "All users + MFA" policy DOES count here.' `
            -RecommendedAction 'Create an enabled CA policy requiring MFA (preferably a phishing-resistant authentication strength) that effectively covers all privileged roles/users.' -SourceFile $src `
            -RuleId 'ENTRA-CA-ADMIN-MFA-NONE' -ObjectType 'Tenant'
    }
    elseif ($uncovered.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("{0} privileged account(s) have no effective MFA Conditional Access coverage" -f $uncovered.Count) `
            -Evidence ("Admins to whom no enabled MFA/auth-strength policy effectively applies (excluded from all, or never in scope): {0}" -f (($uncovered | Select-Object -First 10 -ExpandProperty Account) -join ', ')) `
            -WhyItMatters 'These privileged accounts can sign in with a password alone because every MFA policy either excludes them or does not target them. Being excluded from one policy is fine only if another MFA policy still covers them - here none does.' `
            -RecommendedAction 'Ensure every privileged account (except the two break-glass accounts) is effectively covered by an enabled MFA/auth-strength CA policy; remove unnecessary exclusions.' `
            -SourceFile $src -ResultRows $uncovered -RuleId 'ENTRA-CA-ADMIN-MFA-NOT-EFFECTIVE' -ObjectType 'Tenant'
    }

    if ($evaluated -gt 0 -and ($phishPolicies.Count -eq 0 -or $uncoveredPhish.Count -eq $evaluated)) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No effective phishing-resistant Conditional Access coverage for administrators' `
            -Evidence ("No mandatory phishing-resistant authentication-strength policy covering all resources effectively applies to the {0} privileged account(s) evaluated." -f $evaluated) `
            -WhyItMatters 'Ordinary MFA remains vulnerable to token relay and MFA fatigue. Privileged sessions should require phishing-resistant authentication.' `
            -RecommendedAction 'Apply a phishing-resistant authentication strength to every privileged user, including eligible administrators, excluding only emergency-access accounts.' -SourceFile $src `
            -RuleId 'ENTRA-CA-ADMIN-PHISH-RESISTANT-NONE' -ObjectType 'Tenant'
    } elseif ($uncoveredPhish.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("{0} privileged account(s) lack effective phishing-resistant CA coverage" -f $uncoveredPhish.Count) `
            -Evidence ("Admins without an applicable all-resources phishing-resistant strength: {0}" -f (($uncoveredPhish.Account | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'A single privileged account left on phishable MFA can become the weakest path to tenant takeover.' `
            -RecommendedAction 'Remove scope gaps/exclusions and require a phishing-resistant authentication strength for these administrators.' `
            -SourceFile $src -ResultRows $uncoveredPhish -RuleId 'ENTRA-CA-ADMIN-PHISH-RESISTANT-PARTIAL' -ObjectType 'Tenant'
    }

    if ($script:Findings.Where({$_.CheckId -eq 'capolicies'}).Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("{0} Conditional Access policy/policies enforce baseline controls" -f $enabled.Count) `
            -Evidence 'Effective all-resources MFA, administrator phishing-resistant authentication, legacy-authentication, device-flow/device-compliance and applicable risk/workload baselines were detected.' `
            -WhyItMatters 'A healthy CA baseline is the cloud control plane equivalent of well-managed GPOs.' `
            -RecommendedAction 'Maintain and extend CA coverage (device compliance, risk-based policies on P2).' -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 11 - riskyusers (Identity Protection)
# ===========================================================================
function Invoke-Check-RiskyUsersOnly {
    # Filter server-side: without it every HISTORICALLY risky user (remediated/dismissed,
    # years of history) is downloaded just to be discarded client-side.
    $risky = @(Get-MgRiskyUser -All -Filter "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'" -ErrorAction Stop)
    $detections = @()
    # 30-day window server-side, consistent with the other log-based checks. ('gt' - the
    # documented detectedDateTime filter operators are eq/gt/lt, not ge.)
    $dsince = (Get-Date).ToUniversalTime().AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    try { $detections = @(Get-MgRiskDetection -All -Filter "detectedDateTime gt $dsince" -ErrorAction SilentlyContinue) } catch {}
    $rows = $risky | Select-Object UserPrincipalName, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime
    $src = Write-Evidence -BaseName 'risky_users' -Rows $rows -Title 'Identity Protection - Risky Users'
    if ($detections.Count -gt 0) {
        $drows = $detections | Select-Object UserPrincipalName, RiskEventType, RiskLevel, RiskState, DetectedDateTime, IPAddress
        Write-Evidence -BaseName 'risk_detections' -Rows $drows -Title 'Identity Protection - Risk Detections (last 30 days)' | Out-Null
    }

    # privileged cross-ref (shared assignment cache - one Graph download per run)
    $privIds = @{}
    try { foreach ($id in (Get-EAPrivilegedUserMap).Keys) { $privIds[$id] = $true } } catch {}
    if ($script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyusers' -Category 'Threat Signals' `
            -Title 'Privileged risky-user classification is incomplete' `
            -Evidence 'Active/eligible assignments or privileged-group membership could not be fully read; a risky administrator may be reported at the ordinary-user severity.' `
            -WhyItMatters 'Risk on any active or eligible administrator is a tenant-takeover incident and must receive privileged severity.' `
            -RecommendedAction 'Restore role/group read access and re-run the risky-user correlation.' -SourceFile $src -CoverageGap
    }

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
}

# ===========================================================================
# CHECK 11b - riskyserviceprincipals (Identity Protection - risky workload identities)
#   Split from riskyusers: risky service principals are licensed under Microsoft Entra
#   Workload ID Premium, NOT Entra ID P2, so a Workload-ID-Premium tenant without P2 must
#   still be able to evaluate them. The check is gated internally on $script:WorkloadIdP.
# ===========================================================================
function Invoke-Check-RiskyServicePrincipals {
    # Risky service principals (v1.0, best-effort). Track read SUCCESS separately from
    # result count: an errored read must surface as a coverage gap, never as "clean".
    $rspFound = $false
    $readOk = $true
    $rsp = @()
    try {
        if (Get-Command Get-MgRiskyServicePrincipal -ErrorAction SilentlyContinue) {
            $rsp = @(Get-MgRiskyServicePrincipal -All -ErrorAction Stop | Where-Object { $_.RiskState -in @('atRisk','confirmedCompromised') })
        } else {
            # Raw fallback: paginate (first page only would under-report) against v1.0.
            $uri = 'https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals'
            $acc = @(); $guard = 0
            while ($uri -and $guard -lt 50) {
                $uri = Assert-EAGraphReadUri $uri
                $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                if ($resp['value']) { $acc += @($resp['value']) }
                $uri = $resp['@odata.nextLink']; $guard++
            }
            if ($uri) { throw 'Microsoft Graph risky-service-principal pagination exceeded the 50-page safety limit.' }
            $rsp = @($acc | Where-Object { $_.riskState -in @('atRisk','confirmedCompromised') })
        }
    } catch {
        # Permission failures should land in the posture summary as Skipped-NoPermission.
        if ($_.Exception.Response.StatusCode.value__ -in 401,403 -or $_ -match 'Authorization_RequestDenied|Insufficient privileges') { throw }
        $readOk = $false
    }
    if ($readOk -and $rsp.Count -gt 0) {
        $rspFound = $true
        $rsprows = $rsp | Select-Object @{n='DisplayName';e={ $_.DisplayName ?? $_.displayName }}, @{n='RiskState';e={ $_.RiskState ?? $_.riskState }}
        $rspsrc = Write-Evidence -BaseName 'risky_serviceprincipals' -Rows $rsprows -Title 'Identity Protection - Risky Service Principals'
        Add-EntraFinding -Severity 'High' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title ("{0} risky service principal(s) flagged" -f $rsp.Count) `
            -Evidence 'A workload identity (app/service principal) is flagged as risky/compromised.' `
            -WhyItMatters 'A compromised workload identity often holds application permissions exercised without any user interaction - a high-impact, stealthy foothold.' `
            -RecommendedAction 'Investigate the flagged service principals, rotate their credentials, and review their granted application permissions.' -SourceFile $rspsrc -ResultRows $rsprows
    }

    if ($rspFound) { return }

    # Risky service principals are licensed separately from P2 risky users (they need
    # Microsoft Entra Workload ID Premium). Report coverage explicitly: a tenant without
    # Workload ID Premium is license-gated (not clean), while one WITH it and no flags is clean.
    if (-not $script:WorkloadIdP) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'Risky service principals not assessed (Workload Identities Premium required)' `
            -Evidence 'Risky workload identities require Microsoft Entra Workload ID Premium, which was not detected - this check is license-gated, not clean.' `
            -WhyItMatters 'Risky service principals surface compromised workload identities; without Workload ID Premium they cannot be evaluated even when Entra ID P2 is present.' `
            -RecommendedAction 'License Microsoft Entra Workload ID Premium to enable risky service principal detection.' -SourceFile $null -CoverageGap
    } elseif (-not $readOk) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'Risky service principals could NOT be read (coverage gap, not clean)' `
            -Evidence 'Workload Identities Premium is present but the risky-service-principal read failed (throttling / transient Graph error). This result is UNKNOWN, not "no risky workload identities".' `
            -WhyItMatters 'A failed read must not be mistaken for a clean result - compromised workload identities may exist unseen.' `
            -RecommendedAction 'Re-run the audit (or just -riskyserviceprincipals) when the service is reachable.' -SourceFile $null -CoverageGap
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'No risky service principals flagged by Identity Protection' `
            -Evidence 'Workload Identities Premium is present and no workload identity is currently flagged at-risk/compromised.' `
            -WhyItMatters 'Risky service principals surface compromised workload identities exercising application permissions without user interaction.' `
            -RecommendedAction 'Maintain risk-based Conditional Access for workload identities and review flagged service principals promptly.' -SourceFile $null
    }
}

# ===========================================================================
# CHECK 12 - apps (app / service principal hygiene & over-privilege)
# ===========================================================================
function Invoke-Check-Apps {
    $apps = Get-EAApplications
    $sps  = @(Get-EAServicePrincipals)
    $script:AppCount = $apps.Count
    # NB: secret/certificate credential EXPIRY is reported by the dedicated 'appcredentials'
    # check (Invoke-Check-AppCredentials), which shares the cached Get-EAApplications call.

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

    # Enumerate assignments from the RESOURCE side: only SPs that define named app roles
    # (the APIs - Graph, Exchange, SharePoint, custom) can grant application permissions,
    # and there are far fewer APIs than client SPs. One Get-...AppRoleAssignedTo per API
    # replaces one Get-...AppRoleAssignment per service principal (N+1 at tenant scale).
    $permRows = @()
    $spPermErrors = @()
    $resourceSps = @($sps | Where-Object { @($_.AppRoles | Where-Object { $_.Id -and $_.Value }).Count -gt 0 })
    foreach ($res in $resourceSps) {
        $asn = @()
        try { $asn = @(Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $res.Id -All -ErrorAction Stop) }
        catch { $spPermErrors += [pscustomobject]@{ ServicePrincipal=$res.DisplayName; AppId=$res.AppId; Error=("(resource API read) " + $_.Exception.Message) }; continue }
        foreach ($x in $asn) {
            # appRoleAssignedTo also lists user/group app assignments (gallery apps) - only
            # service principals HOLD application permissions.
            if ([string]$x.PrincipalType -ne 'ServicePrincipal') { continue }
            $permName = _ResolveAppRoleValue $x.ResourceId $x.AppRoleId
            $isTier0 = ($permName -in $script:DangerousAppPermissions)
            $isWrite = ($permName -match $writeRx)
            if (-not ($isTier0 -or $isWrite)) { continue }
            $tier = if ($isTier0) { 'Tier0' } else { 'Write/High' }
            $client = $spById[[string]$x.PrincipalId]
            $permRows += [pscustomobject]@{
                ServicePrincipal=($client.DisplayName ?? [string]$x.PrincipalDisplayName); AppId=$client.AppId; SpId=[string]$x.PrincipalId
                Permission=$permName; Resource=$x.ResourceDisplayName; Tier=$tier
            }
        }
    }
    $permSrc = Write-Evidence -BaseName 'app_permissions' -Rows $permRows -Title 'Application Permissions (write / high-privilege, all resource APIs)'
    if ($spPermErrors.Count -gt 0) {
        # The absence of dangerous app permissions is only trustworthy if collection was complete.
        $errSrc = Write-Evidence -BaseName 'app_permission_collection_errors' -Rows $spPermErrors -Title 'Application Permission Collection Errors'
        Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Applications' `
            -Title ("Application permission collection was incomplete ({0} service principal(s) could not be read)" -f $spPermErrors.Count) `
            -Evidence ("App-role assignments could not be read for {0} service principal(s) (throttling / permission / transient Graph error)." -f $spPermErrors.Count) `
            -WhyItMatters 'If app-role assignment collection failed for some service principals, a "no dangerous app permissions" result is not trustworthy - this is a coverage gap, not a clean result.' `
            -RecommendedAction 'Re-run the audit (or just the -apps check) when not throttled, and confirm the audit identity can read service principal app-role assignments.' `
            -SourceFile $errSrc -ResultRows $spPermErrors -CoverageGap
    }

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
    # When the privileged set is unknown, "owner is not an admin" cannot be concluded.
    $privKnown = -not $script:PrivAssignmentsFailed
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
            if ($disabled -or ($privKnown -and -not $isPriv)) { $nonAdminOwner = $true }
        }
        $app = $appById[$sp.AppId]
        # Both multi-org audiences: AzureADandPersonalMicrosoftAccount is also multi-tenant.
        $multiTenant = [bool]($app -and $app.SignInAudience -match 'AzureADMultipleOrgs|AzureADandPersonalMicrosoftAccount')
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
    # Owners come pre-expanded on the cached application objects (Get-EAApplications),
    # so this is a pure in-memory filter instead of one Graph call per credentialed app.
    $ownerRows = @($apps |
        Where-Object { (@($_.PasswordCredentials).Count -gt 0 -or @($_.KeyCredentials).Count -gt 0) -and @($_.Owners).Count -eq 0 } |
        ForEach-Object { [pscustomobject]@{ App=$_.DisplayName; AppId=$_.AppId; Note='Orphaned credentialed app' } })
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
# CHECK 12b - appcredentials (App Registration secret / certificate expiry)
#   Models the Zabbix "App Registrations by Graph" credential-expiry monitor: every
#   passwordCredential (secret) and keyCredential (certificate) is classified Expired /
#   ExpiringSoon / Valid. Expired -> Medium (the integration has likely already failed, or a
#   stale credential was never cleaned up); expiring within -ExpiringCredentialDays -> Low.
# ===========================================================================
function Invoke-Check-AppCredentials {
    $apps = Get-EAApplications
    $now  = (Get-Date).ToUniversalTime()
    $warnDays = $ExpiringCredentialDays
    $soon = $now.AddDays($warnDays)

    $rows = @()
    foreach ($a in $apps) {
        $creds = @()
        foreach ($c in @($a.PasswordCredentials)) { $creds += [pscustomobject]@{ C=$c; T='Secret' } }
        foreach ($c in @($a.KeyCredentials)) {
            $t = if ($c.Usage) { 'Certificate/' + $c.Usage } else { 'Certificate' }
            $creds += [pscustomobject]@{ C=$c; T=$t }
        }
        foreach ($cc in $creds) {
            $c = $cc.C
            if (-not $c.EndDateTime) { continue }            # skip credentials with no expiry (e.g. some FIC)
            $end = [datetime]$c.EndDateTime
            $daysLeft = [int][math]::Round(($end - $now).TotalDays)
            $state = if ($end -lt $now) { 'Expired' } elseif ($end -lt $soon) { 'ExpiringSoon' } else { 'Valid' }
            $rows += [pscustomobject]@{
                App         = $a.DisplayName
                AppId       = $a.AppId
                AppObjectId = $a.Id
                CredType    = $cc.T
                CredName    = (@($c.DisplayName, [string]$c.KeyId) | Where-Object { $_ } | Select-Object -First 1)
                KeyId       = $c.KeyId
                End         = $c.EndDateTime
                DaysLeft    = $daysLeft
                State       = $state
            }
        }
    }
    $src = Write-Evidence -BaseName 'app_credentials' -Rows $rows `
        -Title 'App Registration Credentials - Secret & Certificate Expiry' `
        -Notes @(("Expiry warning window: {0} days (-ExpiringCredentialDays)" -f $warnDays), 'DaysLeft below 0 means the credential has already expired.')

    if ($rows.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'appcredentials' -Category 'Applications' `
            -Title 'No application registration credentials with an expiry date found' `
            -Evidence 'No app registration carries a password (secret) or certificate credential that has an endDateTime.' `
            -WhyItMatters 'Apps may instead use federated/workload-identity credentials, or none are provisioned yet - there is simply nothing to expire.' `
            -RecommendedAction 'No action; revisit if integrations are expected to authenticate with secrets or certificates.' -SourceFile $src
        return
    }

    $expired  = @($rows | Where-Object { $_.State -eq 'Expired' })
    $expiring = @($rows | Where-Object { $_.State -eq 'ExpiringSoon' })

    # Apps whose EVERY dated credential is expired (no valid one left) - the strongest
    # "integration is broken / nobody cleaned it up" signal.
    $deadApps = @($rows | Group-Object AppId | Where-Object {
        @($_.Group | Where-Object { $_.State -eq 'Expired' }).Count -gt 0 -and
        @($_.Group | Where-Object { $_.State -ne 'Expired' }).Count -eq 0
    })

    if ($expired.Count -gt 0) {
        $expApps = @($expired.App | Select-Object -Unique)
        $worst = @($expired | Sort-Object DaysLeft | Select-Object -First 10 |
            ForEach-Object { "{0} [{1}] expired {2}d ago" -f $_.App, $_.CredType, [math]::Abs($_.DaysLeft) })
        $deadNote = if ($deadApps.Count -gt 0) { " {0} app(s) have NO remaining valid credential (integration is likely broken)." -f $deadApps.Count } else { '' }
        Add-EntraFinding -Severity 'Medium' -CheckId 'appcredentials' -Category 'Applications' `
            -Title ("{0} app registration credential(s) have EXPIRED across {1} app(s)" -f $expired.Count, $expApps.Count) `
            -Evidence ("Expired credentials (oldest first): {0}.{1}" -f ($worst -join '; '), $deadNote) `
            -WhyItMatters 'An expired secret/certificate means the integration using it has very likely already failed - or, if the integration is gone, that nobody removed the stale credential. Either way it is an operational and lifecycle gap: dead credentials accumulate, obscure which credential an app really uses, and indicate app registrations are not being actively managed.' `
            -RecommendedAction 'For each app: confirm whether the integration is still required. If yes, roll a fresh credential (prefer a certificate with a short, tracked lifetime) and update the consumer. If no, delete the expired credential and decommission the unused app.' `
            -SourceFile $src -RuleId 'app-credential-expired' -ObjectType 'application' `
            -ResultRows @($expired | Select-Object App,AppId,CredType,CredName,End,DaysLeft | Sort-Object DaysLeft)
    }
    if ($expiring.Count -gt 0) {
        $expApps = @($expiring.App | Select-Object -Unique)
        $next = @($expiring | Sort-Object DaysLeft | Select-Object -First 10 |
            ForEach-Object { "{0} [{1}] {2}d left" -f $_.App, $_.CredType, $_.DaysLeft })
        Add-EntraFinding -Severity 'Low' -CheckId 'appcredentials' -Category 'Applications' `
            -Title ("{0} app registration credential(s) expire within {1} days across {2} app(s)" -f $expiring.Count, $warnDays, $expApps.Count) `
            -Evidence ("Credentials expiring soon (soonest first): {0}." -f ($next -join '; ')) `
            -WhyItMatters 'A credential that lapses without a planned rotation causes a surprise integration outage. Catching it inside the warning window lets operations roll it before anything breaks.' `
            -RecommendedAction 'Schedule rotation for each expiring credential before its end date; prefer certificates with a defined rotation process and remove credentials that are no longer used.' `
            -SourceFile $src -RuleId 'app-credential-expiring' -ObjectType 'application' `
            -ResultRows @($expiring | Select-Object App,AppId,CredType,CredName,End,DaysLeft | Sort-Object DaysLeft)
    }
    if ($expired.Count -eq 0 -and $expiring.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'appcredentials' -Category 'Applications' `
            -Title ("All {0} application credential(s) are valid beyond the {1}-day window" -f $rows.Count, $warnDays) `
            -Evidence 'No expired credentials, and none expiring within the warning window.' `
            -WhyItMatters 'Current secrets/certificates are within their validity period; continued rotation tracking keeps integrations healthy.' `
            -RecommendedAction 'Maintain a rotation calendar and re-run periodically to catch upcoming expiries.' -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 13 - consentgrants (OAuth2 delegated grants)
# ===========================================================================
function Invoke-Check-ConsentGrants {
    $grants = @(Get-MgOauth2PermissionGrant -All -ErrorAction Stop)
    # Resolve SP display names from the shared cache when a check already populated it;
    # otherwise ONE paged list call (id,displayName) replaces the previous per-id lookups
    # (two Graph calls per grant on tenants with thousands of grants).
    $spById = @{}
    if ($null -ne $script:SpsCache) {
        foreach ($sp in $script:SpsCache) { if ($sp.Id) { $spById[$sp.Id] = $sp } }
    } else {
        try { foreach ($sp in @(Get-MgServicePrincipal -All -Property 'id,displayName' -PageSize 999 -ErrorAction Stop)) { if ($sp.Id) { $spById[$sp.Id] = $sp } } } catch {}
    }
    # offline_access alone is routine (it only lengthens token lifetime) and User.ReadWrite
    # (self-profile) is not high-impact - flagging them alone made nearly every ordinary
    # admin-consented app a High finding. Only data/directory-write scopes count as high.
    $highScopes = 'Mail\.|Files\.ReadWrite|Directory\.ReadWrite|User\.ReadWrite\.All|full_access|Sites\.ReadWrite|Sites\.FullControl'
    $rows = @(foreach ($g in $grants) {
        $client = if ($spById.ContainsKey($g.ClientId)) { $spById[$g.ClientId] } else { $null }
        [pscustomobject]@{
            Client=($client.DisplayName ?? $g.ClientId); ConsentType=$g.ConsentType
            Resource=(($spById[$g.ResourceId]).DisplayName ?? $g.ResourceId); Scope=$g.Scope
            High=($g.Scope -match $highScopes)
        }
    })
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

    # Partner configs override the default only for the NAMED tenants - the default
    # policy still applies to every other tenant, so partner entries must not suppress
    # this finding.
    if ($def -and $def.InboundTrust.IsMfaAccepted) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'trusts' -Category 'External Access' `
            -Title 'Default cross-tenant policy trusts external MFA claims for all tenants' `
            -Evidence ("InboundTrust.IsMfaAccepted = true on the default (all tenants) policy. {0} partner-specific configuration(s) exist, but the default still applies to every tenant without one." -f $partners.Count) `
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
    # A failed/empty DEFAULT-policy read means the trust posture was NOT evaluated -
    # never fall through to 'reviewed, nothing flagged', even when partner configs
    # were readable.
    if (-not $def) {
        Add-EntraFinding -Severity 'Information' -CheckId 'trusts' -Category 'External Access' `
            -Title 'Cross-tenant access policy not assessed' `
            -Evidence 'The default cross-tenant access policy could not be read (default configuration or missing scope) - external-trust posture was not evaluated.' `
            -WhyItMatters 'Cross-tenant access governs B2B trust with other tenants.' `
            -RecommendedAction 'Review cross-tenant access settings in the Entra portal.' -SourceFile $src -CoverageGap
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
    # InvariantCulture: see Invoke-Check-LegacyAuth - culture time separators break OData.
    $sinceStr = $since.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
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
        $rcsrc = Write-Evidence -BaseName 'recent_role_changes' -Rows $rcrows -Title 'Recent Role-Management Changes'
        Add-EntraFinding -Severity 'Medium' -CheckId 'recentchanges' -Category 'Change Monitoring' `
            -Title ("{0} role-management change(s) in the last {1} days" -f $roleChanges.Count, $RecentChangeDays) `
            -Evidence 'Privileged role assignments/removals occurred recently and should be verified against change records.' `
            -WhyItMatters 'New role grants in the recent window are where rogue-admin or compromised-provisioning activity first appears. Direct equivalent of the AD recent-changes review.' `
            -RecommendedAction 'Verify each recent role change against an approved change record and investigate any unexpected initiator.' `
            -SourceFile $rcsrc -ResultRows @($rcrows | Select-Object -First 50)
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
    if ($org.OnPremisesSyncEnabled -and -not $sync) {
        # Hybrid tenant, but the on-prem sync configuration could not be read - do NOT fall
        # through to the "healthy" baseline, which would be a false sense of coverage.
        Add-EntraFinding -Severity 'Medium' -CheckId 'tenanthealth' -Category 'Platform Health' `
            -Title 'Directory synchronization details could not be assessed' `
            -Evidence 'Tenant is hybrid (OnPremisesSyncEnabled=true), but Get-MgDirectoryOnPremiseSynchronization returned no data or failed.' `
            -WhyItMatters 'Password Hash Sync, soft-match blocking and sync feature posture cannot be validated without this data, so an apparently healthy result would be misleading.' `
            -RecommendedAction 'Grant OnPremDirectorySynchronization.Read.All and re-run the tenanthealth check.' -SourceFile $src -CoverageGap
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
    if ($sync -and $sync.Features.PasswordSyncEnabled) {
        $cloudPwdPolicy = Get-EAField $sync.Features 'CloudPasswordPolicyForPasswordSyncedUsersEnabled'
        if ($null -eq $cloudPwdPolicy) {
            Add-EntraFinding -Severity 'Information' -CheckId 'tenanthealth' -Category 'Platform Health' `
                -Title 'Cloud password-policy behavior for password-synced users is unknown' `
                -Evidence 'CloudPasswordPolicyForPasswordSyncedUsersEnabled was not returned; the recorded setting is unknown, not assumed enabled.' `
                -WhyItMatters 'This feature controls whether the tenant cloud password policy is applied to password-hash-synchronized users.' `
                -RecommendedAction 'Re-run with OnPremDirectorySynchronization.Read.All and verify the synchronization feature setting.' -SourceFile $src -CoverageGap
        } elseif (-not [bool]$cloudPwdPolicy) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'tenanthealth' -Category 'Platform Health' `
                -Title 'Cloud password policy is not applied to password-synced users' `
                -Evidence 'PasswordSyncEnabled=true and CloudPasswordPolicyForPasswordSyncedUsersEnabled=false.' `
                -WhyItMatters 'Password-synced users can retain cloud-side DisablePasswordExpiration behavior and may not follow the tenant cloud password policy when authenticating directly to Entra.' `
                -RecommendedAction 'Review the hybrid password-expiration design and enable CloudPasswordPolicyForPasswordSyncedUsers when cloud password-policy enforcement is intended; verify the change against on-prem policy and federation/PTA behavior first.' -SourceFile $src
        }
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
        $ri = Get-EARoleInfo -RoleDefinitionId ([string]$a.RoleDefinitionId)
        $p = $a.Principal
        $id = if ($a.PrincipalId) { $a.PrincipalId } elseif ($p) { $p.Id } else { $null }
        $odt = Get-Ap $p '@odata.type'
        if (-not $odt -and $p -and $p.PSObject.Properties['OdataType']) { $odt = $p.OdataType }
        $upn = Get-Ap $p 'userPrincipalName'
        $pname = Get-Ap $p 'displayName'
        if (-not $upn -and $id -and $script:UserById.ContainsKey($id)) { $upn = $script:UserById[$id].UserPrincipalName }
        $ptype = if ($odt) { ($odt -replace '#microsoft.graph.','') }
                 elseif ($upn) { 'user' }
                 elseif ($id -and $script:UserById.ContainsKey($id)) { 'user' }
                 elseif ($p -and $p.GetType().Name -match '(?i)Group') { 'group' }
                 elseif ($p -and $p.GetType().Name -match '(?i)ServicePrincipal') { 'servicePrincipal' }
                 elseif ((Get-Ap $p 'groupTypes') -or $null -ne (Get-Ap $p 'securityEnabled')) { 'group' }
                 elseif (Get-Ap $p 'appId') { 'servicePrincipal' }
                 else { 'unknown' }

        # 'State' stays the COARSE Active/Eligible distinction the access-path correlation
        # relies on. 'ActivationModel' is the fine-grained classification needed to tell a
        # PERMANENT standing assignment apart from a time-bound or JIT-activated one - the
        # break-glass check needs "permanent active GA", not merely "currently active GA".
        $assignmentType = $null
        if ($a.PSObject.Properties['AssignmentType']) { $assignmentType = [string]$a.AssignmentType }
        $endDateTime = $null
        if ($a.PSObject.Properties['EndDateTime']) { $endDateTime = $a.EndDateTime }
        $activationModel =
            if ($state -eq 'Eligible')              { 'Eligible' }
            elseif ($assignmentType -eq 'Activated') { 'TimeBound-Active-JIT' }
            elseif ($null -eq $endDateTime)          { 'Permanent' }
            else                                     { 'TimeBound-Assigned' }

        $list.Add([pscustomobject]@{
            PrincipalId=$id; PrincipalType=$ptype; PrincipalUpn=$upn; PrincipalName=$pname
            RoleTemplateId=$ri.TemplateId; RoleDefinitionId=$ri.RoleDefinitionId; RoleName=$ri.Name; State=$state
            ActivationModel=$activationModel; AssignmentType=$assignmentType; EndDateTime=$endDateTime
            DirectoryScopeId=$a.DirectoryScopeId; AppScopeId=$a.AppScopeId
            ScopeKey=('{0}~{1}' -f ([string]$a.DirectoryScopeId),([string]$a.AppScopeId))
            IsPrivileged=$ri.IsPrivileged; IsGA=$ri.IsGA; IsTier0=$ri.IsTier0; RoleClassification=$ri.ClassificationSource
        }) | Out-Null
    }

    $active = @(); $fetchErr = $null
    try { $active += @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop) } catch { $fetchErr = $_ }
    if ($active.Count -eq 0) {
        try { $active += @(Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop); $fetchErr = $null } catch { if (-not $fetchErr) { $fetchErr = $_ } }
    }
    foreach ($a in $active) { _Add $a 'Active' }
    # Eligibility is P2-gated; on a licensed tenant a failed read is a coverage gap, not
    # evidence that no eligible administrators exist.
    try {
        foreach ($a in @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)) { _Add $a 'Eligible' }
        $script:PrivEligibilityAssignmentsFailed = $false
    } catch {
        $script:PrivEligibilityAssignmentsFailed = [bool]$script:HasP2
        if ($script:HasP2) { Write-Warn2 "  Privileged eligibility-assignment fetch failed: $($_.Exception.Message)" }
    }

    if ($active.Count -eq 0 -and $fetchErr) {
        # Both ACTIVE-assignment fetches FAILED - this is "unknown", not "no admins",
        # even when the eligibility fetch above returned rows. Do not cache (a later
        # check may retry successfully) and flag the failure so consumers report
        # "could not validate" instead of findings built on blindness.
        $script:PrivAssignmentsFailed = $true
        Write-Warn2 "  Privileged-assignment fetch failed: $($fetchErr.Exception.Message)"
        return $list
    }
    $script:PrivAssignmentsFailed = $false
    $script:PrivAssignments = $list
    return $list
}

# Effective privileged-user population shared by MFA, stale/risk/guest hygiene and CA.
# It includes eligible assignments and expands role-assignable groups transitively. The
# map value is the list of role assignments that make that user privileged, preserving
# role/scope/state context for consumers that need role-targeted CA applicability.
function Get-EAPrivilegedUserMap {
    if ($null -ne $script:PrivilegedUserMap) { return $script:PrivilegedUserMap }
    try { Get-EAUsers | Out-Null } catch {}
    $map = @{}
    $script:PrivilegedUserMapIncomplete = $false

    function _AddUserPrivilege([string]$UserId, $Assignment) {
        if (-not $UserId) { return }
        if (-not $map.ContainsKey($UserId)) { $map[$UserId] = New-Object System.Collections.Generic.List[object] }
        $map[$UserId].Add($Assignment) | Out-Null
    }

    foreach ($a in @(Get-EAPrivAssignments)) {
        if (-not $a.IsPrivileged -or -not $a.PrincipalId) { continue }
        if ($a.PrincipalType -eq 'user') {
            _AddUserPrivilege ([string]$a.PrincipalId) $a
            continue
        }
        if ($a.PrincipalType -ne 'group') {
            if ($a.PrincipalType -eq 'unknown') { $script:PrivilegedUserMapIncomplete = $true }
            continue
        }
        try {
            foreach ($m in @(Get-MgGroupTransitiveMember -GroupId $a.PrincipalId -All -ErrorAction Stop)) {
                $mtype = [string](Get-Ap $m '@odata.type')
                $upn = Get-Ap $m 'userPrincipalName'
                if ($mtype -eq '#microsoft.graph.user' -or $upn -or ($m.Id -and $script:UserById.ContainsKey($m.Id))) {
                    _AddUserPrivilege ([string]$m.Id) $a
                }
            }
        } catch {
            $script:PrivilegedUserMapIncomplete = $true
            Write-Warn2 "  Could not expand privileged group $($a.PrincipalName ?? $a.PrincipalId): $($_.Exception.Message)"
        }
    }
    if ($script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed) { $script:PrivilegedUserMapIncomplete = $true }
    $script:PrivilegedUserMap = $map
    return $map
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
            $u = Assert-EAGraphReadUri $u
            $r = Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop
            if ($r['value']) { $acc += @($r['value']) }
            $u = $r['@odata.nextLink']; $g++
        }
        if ($u) { throw 'Microsoft Graph PIM-policy pagination exceeded the 50-page safety limit.' }
        return $acc
    }
    $scopeUsed = 'DirectoryRole'
    $assignments = @()
    $firstScopeError = $null
    try { $assignments = @(_FetchPim 'DirectoryRole') } catch { $firstScopeError = $_ }
    if ($assignments.Count -eq 0) {
        $scopeUsed = 'Directory'
        try { $assignments = @(_FetchPim 'Directory') } catch { if ($firstScopeError) { throw $firstScopeError }; throw }
    }

    # Authentication context is a valid MFA substitute only when the referenced context is
    # available AND an enabled CA policy actually protects that context with mandatory MFA /
    # authentication strength. Merely seeing isEnabled=true on the PIM rule is insufficient.
    $authContextDefinitions = @{}; $authContextDefinitionsKnown = $true
    try {
        $u = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences'; $guard = 0
        while ($u -and $guard -lt 20) {
            $u = Assert-EAGraphReadUri $u
            $resp = Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop
            foreach ($d in @($resp['value'])) { if ($d['id']) { $authContextDefinitions[[string]$d['id']] = $d } }
            $u = $resp['@odata.nextLink']; $guard++
        }
        if ($u) { throw 'Microsoft Graph authentication-context pagination exceeded the 20-page safety limit.' }
    } catch { $authContextDefinitionsKnown = $false }
    $caKnown = $true; $enabledCa = @()
    try { $enabledCa = @(Get-EACaPolicies | Where-Object { $_.State -eq 'enabled' }) } catch { $caKnown = $false }
    $pimBgIds = @(); $pimBg = Normalize-StringList -Values $BreakGlassUpns
    try { foreach ($u0 in @(Get-EAUsers)) { if ($u0.Id -and $u0.UserPrincipalName -and $u0.UserPrincipalName.ToLowerInvariant() -in $pimBg) { $pimBgIds += [string]$u0.Id } } } catch {}

    function _ValidateAuthContext([string]$claimValue) {
        if (-not $claimValue) { return 'Invalid-NoClaimValue' }
        if (-not $authContextDefinitionsKnown -or -not $caKnown) { return 'Unknown' }
        if (-not $authContextDefinitions.ContainsKey($claimValue) -or -not [bool]$authContextDefinitions[$claimValue]['isAvailable']) { return 'Invalid-Unavailable' }
        $matchingScopedPolicy = $false
        foreach ($p in $enabledCa) {
            $refs = @((Get-EAField $p.Conditions.Applications 'IncludeAuthenticationContextClassReferences') | Where-Object { $_ })
            if ($refs -contains $claimValue -and
                (Test-CaPolicyRequiresMfaOrStrength $p) -and
                -not (Test-CaPolicyHasNarrowingConditions $p)) {
                if (Test-CaPolicyTargetsAllUsers -Policy $p -AllowedExcludedUserIds $pimBgIds) { return 'Valid' }
                $matchingScopedPolicy = $true
            }
        }
        if ($matchingScopedPolicy) { return 'Unknown-ScopedUserCoverage' }
        return 'Invalid-NoProtectingCAPolicy'
    }

    $rows = @()
    $noMfaCrit = @(); $noMfaHigh = @(); $noJust = @(); $noApproval = @(); $longDur = @(); $permActiveRoles = @(); $permEligRoles = @()
    $unknownRules = @(); $badAuthContexts = @()

    foreach ($pa in $assignments) {
        $rdId = [string]$pa['roleDefinitionId']
        $ri = Get-EARoleInfo -RoleDefinitionId $rdId
        if (-not $ri.IsPrivileged) { continue }
        $roleName = $ri.Name
        $isGAorPRA = ($ri.IsTier0 -or $roleName -match 'Privileged Role Administrator|Privileged Authentication')

        $rules = @()
        if ($pa['policy'] -and $pa['policy']['rules']) { $rules = @($pa['policy']['rules']) }
        $mfa = $null; $just = $null; $appr = $null; $maxH = $null; $permA = $null; $permE = $null
        $authCtxEnabled = $null; $authCtxClaim = $null
        foreach ($r in $rules) {
            $rid = [string]$r['id']
            switch -Regex ($rid) {
                'Enablement_EndUser_Assignment' {
                    if ($r.ContainsKey('enabledRules') -and $null -ne $r['enabledRules']) {
                        $en = @($r['enabledRules']); $mfa = ($en -contains 'MultiFactorAuthentication'); $just = ($en -contains 'Justification')
                    }
                }
                # Requiring a Conditional Access AUTHENTICATION CONTEXT on activation is
                # mutually exclusive with the MultiFactorAuthentication enablement value
                # (the portal removes MFA from the enablement rule when auth context is
                # selected) and is typically the STRONGER control - it must not be
                # reported as "can be activated without MFA".
                'AuthenticationContext_EndUser_Assignment' {
                    if ($r.ContainsKey('isEnabled')) { $authCtxEnabled = [bool]$r['isEnabled'] }
                    $authCtxClaim = [string]$r['claimValue']
                }
                'Approval_EndUser_Assignment'   { if ($r['setting']) { $appr = [bool]$r['setting']['isApprovalRequired'] } }
                'Expiration_EndUser_Assignment' {
                    # ISO-8601 durations also come in day form (P1D) and mixed form
                    # (P1DT2H / PT8H30M) - XmlConvert parses them all; the regex stays
                    # as a fallback only.
                    $d = [string]$r['maximumDuration']
                    if ($d) {
                        try { $maxH = [math]::Round(([System.Xml.XmlConvert]::ToTimeSpan($d)).TotalHours, 1) }
                        catch {
                            if ($d -match 'PT(\d+)H') { $maxH = [int]$matches[1] } elseif ($d -match 'PT(\d+)M') { $maxH = [math]::Round(([int]$matches[1]/60),1) }
                        }
                    }
                }
                'Expiration_Admin_Assignment'   { if ($r.ContainsKey('isExpirationRequired')) { $permA = (-not [bool]$r['isExpirationRequired']) } }
                'Expiration_Admin_Eligibility'  { if ($r.ContainsKey('isExpirationRequired')) { $permE = (-not [bool]$r['isExpirationRequired']) } }
            }
        }
        $authCtxStatus = if ($authCtxEnabled -eq $true) { _ValidateAuthContext $authCtxClaim } elseif ($authCtxEnabled -eq $false) { 'Disabled' } else { 'NotConfigured' }
        $authCtxValid = ($authCtxStatus -eq 'Valid')
        $rows += [pscustomobject]@{
            Role=$roleName; RoleDefinitionId=$ri.RoleDefinitionId; RoleTemplateId=$ri.TemplateId
            MfaOnActivation=$mfa; AuthContextEnabled=$authCtxEnabled; AuthContextClaim=$authCtxClaim; AuthContextValidation=$authCtxStatus
            JustificationRequired=$just; ApprovalRequired=$appr; MaxActivationHours=$maxH
            PermanentActiveAllowed=$permA; PermanentEligibleAllowed=$permE
        }

        if ($authCtxEnabled -eq $true -and $authCtxStatus -ne 'Valid' -and $authCtxStatus -notlike 'Unknown*') { $badAuthContexts += ("{0} ({1}: {2})" -f $roleName, ($authCtxClaim ?? 'no claim'), $authCtxStatus) }
        if ($mfa -eq $false -and -not $authCtxValid -and $authCtxStatus -notlike 'Unknown*') { if ($isGAorPRA) { $noMfaCrit += $roleName } else { $noMfaHigh += $roleName } }
        if ($isGAorPRA -and $just -eq $false) { $noJust += $roleName }
        if ($isGAorPRA -and $appr -eq $false) { $noApproval += $roleName }
        if ($maxH -and $maxH -gt 8) { $longDur += ("{0} ({1}h)" -f $roleName, $maxH) }
        if ($permA -eq $true) { $permActiveRoles += $roleName }
        if ($permE -eq $true) { $permEligRoles += $roleName }
        $unknown = @()
        if ($null -eq $mfa -and -not $authCtxValid) { $unknown += 'MFA/auth-context requirement' }
        if ($authCtxStatus -like 'Unknown*') { $unknown += 'authentication-context availability/CA enforcement' }
        if ($isGAorPRA -and $null -eq $just) { $unknown += 'justification' }
        if ($isGAorPRA -and $null -eq $appr) { $unknown += 'approval' }
        if ($null -eq $maxH) { $unknown += 'maximum activation duration' }
        if ($null -eq $permA) { $unknown += 'active-assignment expiration' }
        if ($null -eq $permE) { $unknown += 'eligible-assignment expiration' }
        if ($unknown.Count -gt 0) { $unknownRules += ("{0}: {1}" -f $roleName, ($unknown -join ', ')) }
    }
    $src = Write-Evidence -BaseName 'pim_policies' -Rows $rows -Title 'PIM Role-Management Policy Rules (privileged roles)' -Notes @("Policy scopeType used: $scopeUsed")

    if ($rows.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title 'PIM role-management policies not assessed' `
            -Evidence 'No privileged-role PIM policies returned (requires Entra ID P2 and RoleManagementPolicy.Read.Directory).' `
            -WhyItMatters 'PIM activation policy rules (MFA on activation, approval, justification, max duration, permanent-allowed) are the controls that make eligible access safe.' `
            -RecommendedAction 'License Entra ID P2 and grant RoleManagementPolicy.Read.Directory to assess PIM policy quality.' -SourceFile $src -CoverageGap
        return
    }
    if ($badAuthContexts.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} PIM authentication-context rule(s) are not effectively protected" -f $badAuthContexts.Count) `
            -Evidence ("Enabled PIM authentication contexts without an available context plus an enabled, mandatory-MFA CA policy for all users: {0}" -f ($badAuthContexts -join '; ')) `
            -WhyItMatters 'An enabled authentication-context switch does not itself enforce MFA. The referenced context must exist and an applicable Conditional Access policy must protect it.' `
            -RecommendedAction 'Make the authentication context available and bind it to an enabled all-users CA policy requiring MFA or a phishing-resistant authentication strength; otherwise require MFA directly in PIM.' -SourceFile $src
    }
    if ($unknownRules.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} privileged PIM role policy/policies have missing or unreadable rules" -f $unknownRules.Count) `
            -Evidence ("Unknown controls (not treated as secure defaults): {0}" -f (($unknownRules | Select-Object -First 12) -join '; ')) `
            -WhyItMatters 'A missing/null rule is unknown, not false and not proof of enforcement. Reporting it explicitly prevents incomplete Graph responses from producing a clean PIM result.' `
            -RecommendedAction 'Verify the role-management policy assignment and its expanded rules, then configure explicit activation and expiration requirements.' -SourceFile $src -CoverageGap
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
    $users = Get-EAUsers -IncludeSignInActivity
    $byUpn = @{}; foreach ($u in $users) { if ($u.UserPrincipalName) { $byUpn[$u.UserPrincipalName.ToLowerInvariant()] = $u } }

    # PERMANENT Global Administrators, and every user's privileged role-template ids (active AND
    # eligible) - eligible roles must feed the CA-applicability check because an eligible-only
    # role does not appear in transitiveMemberOf. A break-glass account must hold GA as a
    # PERMANENT standing assignment (not a time-bound / JIT-activated one), so $gaIds is keyed
    # on ActivationModel -eq 'Permanent', not merely "currently active".
    $gaIds = @{}
    $privRolesByUser = @{}
    $gaExpandFailed = $false; $gaExpandFailedGroups = @()
    foreach ($a in (Get-EAPrivAssignments)) {
        if ($a.IsGA -and $a.ActivationModel -eq 'Permanent' -and $a.PrincipalId) {
            $gaIds[$a.PrincipalId] = $true
            # GA held via a role-assignable GROUP is still permanent standing GA for
            # every member - expand so a break-glass account whose GA comes through a
            # group is not falsely reported as "not a permanent Global Administrator".
            # A FAILED expansion makes GA-via-group status UNKNOWN, not "not GA".
            if ($a.PrincipalType -eq 'group') {
                try { foreach ($m in @(Get-MgGroupTransitiveMember -GroupId $a.PrincipalId -All -ErrorAction Stop)) { if ($m.Id) { $gaIds[$m.Id] = $true } } }
                catch { $gaExpandFailed = $true; $gaExpandFailedGroups += ($a.PrincipalName ?? $a.PrincipalId) }
            }
        }
        if ($a.PrincipalId -and $a.PrincipalType -eq 'user' -and $a.RoleTemplateId) {
            if (-not $privRolesByUser.ContainsKey($a.PrincipalId)) { $privRolesByUser[$a.PrincipalId] = New-Object System.Collections.Generic.HashSet[string] }
            [void]$privRolesByUser[$a.PrincipalId].Add($a.RoleTemplateId)
        }
    }
    # Merge group-expanded and eligible assignments so role-targeted CA applicability for
    # a designated account is not understated.
    try {
        $effectivePrivUsers = Get-EAPrivilegedUserMap
        foreach ($uid in $effectivePrivUsers.Keys) {
            if (-not $privRolesByUser.ContainsKey($uid)) { $privRolesByUser[$uid] = New-Object System.Collections.Generic.HashSet[string] }
            foreach ($pa in @($effectivePrivUsers[$uid])) { if ($pa.RoleTemplateId) { [void]$privRolesByUser[$uid].Add([string]$pa.RoleTemplateId) } }
        }
    } catch {}
    # When the assignment fetch itself failed, GA status is UNKNOWN - report that
    # instead of a false "not a permanent Global Administrator" Critical.
    $gaKnown = -not $script:PrivAssignmentsFailed

    # Conditional Access lockout evaluation context. A failed policy read means the CA
    # exposure is UNKNOWN - it must not silently evaluate as "no policies apply".
    $caKnown = $true
    $enabledCa = @(); try { $enabledCa = @(Get-EACaPolicies | Where-Object { $_.State -eq 'enabled' }) } catch { $caKnown = $false }
    # signInActivity is only populated when P1+ is licensed AND AuditLog.Read.All is granted -
    # mirror Get-EAUsers' gate so an unlicensed tenant reports "could not validate" rather than
    # a false "no successful sign-in in 90 days".
    $signinKnown = ($script:HasP1 -and (Test-MgScope @('AuditLog.Read.All') -Quiet))

    # (CA applicability uses the shared Get-EAUserScopeIds / Test-CaPolicyAppliesToUser helpers.)
    $bg = Normalize-StringList -Values $BreakGlassUpns

    if ($bg.Count -eq 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'breakglass' -Category 'Privileged Access' `
            -Title 'No emergency-access (break-glass) accounts have been designated for validation' `
            -Evidence 'Run with -BreakGlassUpns "bg1@tenant.onmicrosoft.com;bg2@tenant.onmicrosoft.com" so the script can validate them.' `
            -WhyItMatters 'Microsoft recommends two cloud-only emergency-access Global Admins, excluded from Conditional Access, to avoid total lockout if MFA/federation/PIM breaks. Without designated accounts this control cannot be validated.' `
            -RecommendedAction 'Create two cloud-only break-glass Global Admin accounts on the .onmicrosoft.com domain, exclude them from CA lockout policies, store credentials offline, monitor their sign-ins, and re-run with -BreakGlassUpns.' -SourceFile $null
        return
    }
    # Per-account findings are QUEUED and only emitted after Write-Evidence, so every
    # one of them links to the break_glass evidence file (which can only be written
    # once the loop has built the rows).
    $pending = New-Object System.Collections.Generic.List[object]
    if ($bg.Count -lt 2) {
        $pending.Add(@{ Severity='Critical'
            Title='Fewer than two emergency-access accounts configured'
            Evidence=("Only {0} break-glass account designated." -f $bg.Count)
            WhyItMatters='A single emergency-access account is a single point of failure; if it is lost or locked out, recovery from a tenant-wide lockout may be impossible.'
            RecommendedAction='Maintain at least two cloud-only break-glass Global Admin accounts.' }) | Out-Null
    }

    $rows = @()
    foreach ($upn in $bg) {
        $u = $byUpn[$upn.ToLowerInvariant()]
        if (-not $u) {
            $pending.Add(@{ Severity='High'
                Title=("Designated break-glass account not found: {0}" -f $upn)
                Evidence='The UPN passed to -BreakGlassUpns does not resolve to a user.'
                WhyItMatters='A misconfigured emergency-access reference means the account you think protects you may not exist.'
                RecommendedAction='Verify the break-glass UPN is correct and the account exists.' }) | Out-Null
            continue
        }
        $enabled   = [bool]$u.AccountEnabled
        $isGA      = [bool]($u.Id -and $gaIds.ContainsKey($u.Id))
        $cloudOnly = -not [bool]$u.OnPremisesSyncEnabled
        $onmsft    = ($u.UserPrincipalName -like '*.onmicrosoft.com')
        $licensed  = (@($u.AssignedLicenses).Count -gt 0)
        $lastSucc  = $null
        if ($u.SignInActivity -and $u.SignInActivity.LastSuccessfulSignInDateTime) { $lastSucc = [datetime]$u.SignInActivity.LastSuccessfulSignInDateTime }

        # Which enabled blocking / MFA-requiring CA policies apply, and at what APP scope?
        # A policy that only targets a single workload app is far less of a lockout risk than
        # one covering all cloud apps (which includes the admin portals / Graph / Azure mgmt).
        $scope = Get-EAUserScopeIds $u.Id
        # Copy the cached role set before adding eligible roles - mutating the shared cache
        # entry would pollute it for any later consumer of this user's scope.
        $bgRoles = [System.Collections.Generic.HashSet[string]]::new($scope.Roles)
        if ($u.Id -and $privRolesByUser.ContainsKey($u.Id)) { foreach ($rt in $privRolesByUser[$u.Id]) { [void]$bgRoles.Add($rt) } }
        $blockAll = @(); $blockScoped = @(); $mfaAll = @(); $mfaScoped = @()
        foreach ($p in $enabledCa) {
            if (-not (Test-CaPolicyAppliesToUser $p $u.Id $scope.Groups $bgRoles)) { continue }
            $allApps = Test-CaPolicyTargetsAllApps $p
            if (@($p.GrantControls.BuiltInControls) -contains 'block') {
                if ($allApps) { $blockAll += $p.DisplayName } else { $blockScoped += $p.DisplayName }
            } elseif (Test-CaPolicyRequiresMfaOrStrength $p) {
                if ($allApps) { $mfaAll += $p.DisplayName } else { $mfaScoped += $p.DisplayName }
            }
        }

        $rows += [pscustomobject]@{
            Account=$u.UserPrincipalName; Enabled=$enabled
            GlobalAdmin=$(if (-not $gaKnown) { 'unknown' } elseif ($isGA) { $isGA } elseif ($gaExpandFailed) { 'unknown' } else { $isGA })
            CloudOnly=$cloudOnly; OnMicrosoftDomain=$onmsft
            Licensed=$licensed; LastSuccessfulSignIn=$lastSucc
            BlockAllApps=$(if ($caKnown) { $blockAll -join '; ' } else { 'unknown' }); BlockScoped=$(if ($caKnown) { $blockScoped -join '; ' } else { 'unknown' })
            MfaAllApps=$(if ($caKnown) { $mfaAll -join '; ' } else { 'unknown' }); MfaScoped=$(if ($caKnown) { $mfaScoped -join '; ' } else { 'unknown' })
        }

        if (-not $enabled) {
            $pending.Add(@{ Severity='Critical'; AffectedPrincipal=$u.UserPrincipalName
                Title=("Break-glass account is disabled: {0}" -f $u.UserPrincipalName)
                Evidence='accountEnabled = false on the emergency-access account.'
                WhyItMatters='A disabled emergency-access account cannot be used to recover the tenant - the control is non-functional exactly when it is needed.'
                RecommendedAction='Enable the break-glass account and verify it can sign in.' }) | Out-Null
        }
        if ($blockAll.Count -gt 0) {
            $pending.Add(@{ Severity='Critical'; AffectedPrincipal=$u.UserPrincipalName
                Title=("Break-glass account is caught by a blocking CA policy covering ALL cloud apps: {0}" -f $u.UserPrincipalName)
                Evidence=("Applies (in scope, not excluded) to all-cloud-apps blocking policy/policies: {0}" -f ($blockAll -join '; '))
                WhyItMatters='A blocking policy that covers all cloud apps will block the emergency-access account from the admin portals, Graph and Azure management - locking it out during the very incident it exists to resolve.'
                RecommendedAction='Exclude the break-glass accounts (directly, or via a dedicated exclusion group) from all blocking Conditional Access policies.' }) | Out-Null
        }
        if ($blockScoped.Count -gt 0) {
            $pending.Add(@{ Severity='Medium'; AffectedPrincipal=$u.UserPrincipalName
                Title=("Break-glass account is caught by an app-scoped blocking CA policy: {0}" -f $u.UserPrincipalName)
                Evidence=("Applies to blocking policy/policies scoped to specific apps (not all cloud apps): {0}" -f ($blockScoped -join '; '))
                WhyItMatters='A blocking policy scoped to a specific workload app is worth knowing but does not lock the account out of the admin portals / Graph the way an all-cloud-apps block does.'
                RecommendedAction='Review whether the break-glass account needs the blocked app; exclude it if it could impede recovery.' }) | Out-Null
        }
        if ($mfaAll.Count -gt 0) {
            $pending.Add(@{ Severity='High'; AffectedPrincipal=$u.UserPrincipalName
                Title=("Break-glass account is subject to an all-cloud-apps MFA Conditional Access policy: {0}" -f $u.UserPrincipalName)
                Evidence=("Applies (in scope, not excluded) to all-cloud-apps MFA/auth-strength policy/policies: {0}" -f ($mfaAll -join '; '))
                WhyItMatters='If the emergency-access account must satisfy MFA / an authentication strength (across all cloud apps) that it may be unable to meet during an outage, it can be locked out. Microsoft recommends excluding break-glass accounts from such policies, with compensating sign-in monitoring.'
                RecommendedAction='Exclude break-glass accounts from MFA-requiring CA policies (or ensure they hold a resilient phishing-resistant method), and monitor their sign-ins closely.' }) | Out-Null
        }
        if ($mfaScoped.Count -gt 0) {
            $pending.Add(@{ Severity='Low'; AffectedPrincipal=$u.UserPrincipalName
                Title=("Break-glass account is subject to an app-scoped MFA Conditional Access policy: {0}" -f $u.UserPrincipalName)
                Evidence=("Applies to MFA/auth-strength policy/policies scoped to specific apps: {0}" -f ($mfaScoped -join '; '))
                WhyItMatters='An MFA policy scoped to a specific app is a minor lockout consideration compared with one covering all cloud apps.'
                RecommendedAction='Confirm the break-glass account does not need the scoped app, or exclude it.' }) | Out-Null
        }

        if ($gaKnown -and -not $isGA) {
            if ($gaExpandFailed) {
                # A GA-granting group could not be expanded - the account may hold GA
                # through it, so "not a GA" cannot be concluded (a false Critical).
                $pending.Add(@{ Severity='Medium'; AffectedPrincipal=$u.UserPrincipalName
                    Title=("Break-glass GA status could not be fully validated: {0}" -f $u.UserPrincipalName)
                    Evidence=("Global-Administrator-granting group(s) could not be expanded ({0}), so whether this account holds permanent GA through a group is UNKNOWN." -f ((@($gaExpandFailedGroups | Select-Object -Unique | Select-Object -First 5)) -join ', '))
                    WhyItMatters='A break-glass account must have standing Global Admin; this could not be confirmed or ruled out because group membership was unreadable.'
                    RecommendedAction='Re-run when group membership is readable (Group.Read.All / Member.Read.Hidden), or verify the account''s GA assignment manually.' }) | Out-Null
            } else {
                $pending.Add(@{ Severity='Critical'; AffectedPrincipal=$u.UserPrincipalName
                    Title=("Break-glass account is not a permanent Global Administrator: {0}" -f $u.UserPrincipalName)
                    Evidence='The emergency-access account does not hold Global Administrator as a PERMANENT (standing) assignment - directly or via a role-assignable group. An eligible/time-bound or JIT-activated GA does not count, because PIM activation may itself be unavailable during the emergency.'
                    WhyItMatters='A break-glass account must have standing Global Admin so it can recover the tenant when all other access fails.'
                    RecommendedAction='Assign permanent Global Administrator to the break-glass account.' }) | Out-Null
            }
        }
        if (-not $cloudOnly) {
            $pending.Add(@{ Severity='Critical'; AffectedPrincipal=$u.UserPrincipalName
                Title=("Break-glass account is synced/federated, not cloud-only: {0}" -f $u.UserPrincipalName)
                Evidence='onPremisesSyncEnabled is true on the emergency-access account.'
                WhyItMatters='A synced/federated break-glass account depends on on-prem AD / federation - exactly the systems that may be down during an emergency.'
                RecommendedAction='Recreate the break-glass account as a cloud-only account.' }) | Out-Null
        }
        if (-not $onmsft) {
            $pending.Add(@{ Severity='High'; AffectedPrincipal=$u.UserPrincipalName
                Title=("Break-glass account does not use the .onmicrosoft.com domain: {0}" -f $u.UserPrincipalName)
                Evidence='Emergency-access accounts should use the tenant .onmicrosoft.com domain to avoid dependency on custom/federated domains.'
                WhyItMatters='A custom or federated domain can become unavailable; the .onmicrosoft.com domain is always present and cloud-resolved.'
                RecommendedAction='Use a UPN on the tenant .onmicrosoft.com domain for break-glass accounts.' }) | Out-Null
        }
        if (-not $signinKnown) {
            $pending.Add(@{ Severity='Medium'; AffectedPrincipal=$u.UserPrincipalName
                Title=("Break-glass sign-in test could not be validated (no sign-in activity data): {0}" -f $u.UserPrincipalName)
                Evidence='signInActivity is unavailable (AuditLog.Read.All / Entra ID P1 required) - test status is Unknown, not "never tested".'
                WhyItMatters='Emergency-access accounts must be periodically tested, but without sign-in data the test status cannot be confirmed either way - reporting it as a coverage gap avoids a false "never tested" conclusion.'
                RecommendedAction='Grant AuditLog.Read.All and ensure Entra ID P1+, then re-run to validate the documented break-glass test.' }) | Out-Null
        }
        elseif ($null -eq $lastSucc -or $lastSucc -lt (Get-Date).ToUniversalTime().AddDays(-90)) {
            $pending.Add(@{ Severity='Medium'; AffectedPrincipal=$u.UserPrincipalName
                Title=("Break-glass account has no successful sign-in in 90 days: {0}" -f $u.UserPrincipalName)
                Evidence=("Last successful sign-in: {0}" -f ($lastSucc ?? 'none on record'))
                WhyItMatters='Emergency-access accounts must be periodically tested so you know they work and that alerting fires before a real emergency.'
                RecommendedAction='Perform a documented emergency-access test: verify sign-in succeeds, verify alerting fires, and record the test date and owner.' }) | Out-Null
        }
        if ($licensed) {
            $pending.Add(@{ Severity='Low'; AffectedPrincipal=$u.UserPrincipalName
                Title=("Break-glass account is licensed like a normal user: {0}" -f $u.UserPrincipalName)
                Evidence='Emergency-access accounts should carry minimal licensing.'
                WhyItMatters='Excess licensing on a break-glass account increases its footprint and exposure.'
                RecommendedAction='Keep break-glass licensing to the minimum required for sign-in and logging.' }) | Out-Null
        }
    }
    $src = Write-Evidence -BaseName 'break_glass' -Rows $rows -Title 'Emergency-Access (Break-Glass) Account Health'

    # Coverage gaps discovered before/during the loop are reported once, tenant-level.
    if ($rows.Count -gt 0 -and -not $caKnown) {
        $pending.Add(@{ Severity='Medium'
            Title='Break-glass Conditional Access lockout exposure could not be validated'
            Evidence='Conditional Access policies could not be read (Policy.Read.All missing or the request failed) - the CA lockout columns are reported as unknown, not clean.'
            WhyItMatters='Whether a break-glass account is caught by a blocking or MFA-requiring CA policy is a core part of the emergency-access baseline; without the policy set this cannot be confirmed either way.'
            RecommendedAction='Grant Policy.Read.All (or retry on transient failure) and re-run the breakglass check.' }) | Out-Null
    }
    if ($rows.Count -gt 0 -and -not $gaKnown) {
        $pending.Add(@{ Severity='Medium'
            Title='Break-glass Global Administrator status could not be validated'
            Evidence='The privileged-role assignment list could not be fetched, so whether the designated accounts hold permanent Global Administrator is unknown.'
            WhyItMatters='Standing GA is the defining property of an emergency-access account; without the assignment data the baseline cannot be confirmed.'
            RecommendedAction='Grant RoleManagement.Read.Directory (or retry on transient failure) and re-run the breakglass check.' }) | Out-Null
    }
    foreach ($p in $pending) { Add-EntraFinding -CheckId 'breakglass' -Category 'Privileged Access' -SourceFile $src @p }

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

    $privMap = @{}; $privPopulationKnown = $true
    try { $privMap = Get-EAPrivilegedUserMap; if ($script:PrivilegedUserMapIncomplete) { $privPopulationKnown = $false } } catch { $privPopulationKnown = $false }
    $privScopes = @{}

    function _TargetIds($obj, [string]$propertyName) {
        $rawValue = Get-EAField $obj $propertyName
        if ($null -eq $rawValue) { $rawValue = Get-EAField $obj ($propertyName.Substring(0,1).ToLowerInvariant() + $propertyName.Substring(1)) }
        $raw = @($rawValue)
        $ids = @()
        foreach ($t in @($raw)) {
            if ($null -eq $t) { continue }
            $id = Get-EAField $t 'Id'; if ($null -eq $id) { $id = Get-EAField $t 'id' }
            if ($id) { $ids += [string]$id }
        }
        return @($ids | Select-Object -Unique)
    }

    # Resolve a method's state AND its include-target scope. A method is only "tenant-wide"
    # if it targets all_users; targeting a specific group (e.g. a migration pilot) is far
    # lower risk. Handle both typed (.IncludeTargets) and AdditionalProperties shapes.
    function _Method([string]$id) {
        $cfg = $configs | Where-Object { $_.Id -eq $id } | Select-Object -First 1
        if (-not $cfg) { return [pscustomobject]@{ Present=$false; State='not-present'; TenantWide=$false; IncludeIds=@(); ExcludeIds=@(); Targets=''; Exclusions=''; Cfg=$null } }
        $incIds = @(_TargetIds $cfg 'IncludeTargets')
        $excIds = @(_TargetIds $cfg 'ExcludeTargets')
        return [pscustomobject]@{
            Present=$true; State=[string]$cfg.State
            TenantWide=(($incIds -contains 'all_users') -and $excIds.Count -eq 0)
            IncludeIds=$incIds; ExcludeIds=$excIds; Targets=($incIds -join ','); Exclusions=($excIds -join ','); Cfg=$cfg
        }
    }

    function _CoversPrivilegedUser($m, [string]$uid) {
        if (-not $m.Present -or $m.State -ne 'enabled') { return $false }
        if (-not $privScopes.ContainsKey($uid)) { $privScopes[$uid] = Get-EAUserScopeIds $uid }
        $scope = $privScopes[$uid]
        $includeByGroup = @($m.IncludeIds | Where-Object { $_ -notin @('all_users',$uid) })
        $excludeByGroup = @($m.ExcludeIds | Where-Object { $_ -notin @('all_users',$uid) })
        if (-not $scope.Known -and ($includeByGroup.Count -gt 0 -or $excludeByGroup.Count -gt 0)) { return $null }
        $included = ($m.IncludeIds -contains 'all_users') -or ($m.IncludeIds -contains $uid)
        if (-not $included) { foreach ($gid in $includeByGroup) { if ($scope.Groups.Contains($gid)) { $included = $true; break } } }
        if (-not $included) { return $false }
        if ($m.ExcludeIds -contains 'all_users' -or $m.ExcludeIds -contains $uid) { return $false }
        foreach ($gid in $excludeByGroup) { if ($scope.Groups.Contains($gid)) { return $false } }
        return $true
    }

    function _PrivCoverage($methods) {
        $covered = 0; $unknown = 0; $missing = @()
        foreach ($uid in $privMap.Keys) {
            $yes = $false; $unk = $false
            foreach ($m in @($methods)) {
                $r = _CoversPrivilegedUser $m $uid
                if ($r -eq $true) { $yes = $true; break }
                if ($null -eq $r) { $unk = $true }
            }
            if ($yes) { $covered++ } elseif ($unk) { $unknown++ } else { $missing += $uid }
        }
        return [pscustomobject]@{ Covered=$covered; Unknown=$unknown; Missing=$missing; Total=$privMap.Count }
    }

    $methodIds = @('Sms','Voice','Fido2','WindowsHelloForBusiness','MicrosoftAuthenticator','TemporaryAccessPass','Email','SoftwareOath','X509Certificate')
    $rows = @()
    foreach ($mid in $methodIds) {
        $m = _Method $mid; $cov = _PrivCoverage -methods @($m)
        $details = ''
        if ($mid -eq 'TemporaryAccessPass' -and $m.Cfg) {
            $details = 'oneTime={0}; min={1}; default={2}; max={3} minutes' -f
                ((Get-EAField $m.Cfg 'IsUsableOnce') ?? (Get-EAField $m.Cfg 'isUsableOnce')),
                ((Get-EAField $m.Cfg 'MinimumLifetimeInMinutes') ?? (Get-EAField $m.Cfg 'minimumLifetimeInMinutes')),
                ((Get-EAField $m.Cfg 'DefaultLifetimeInMinutes') ?? (Get-EAField $m.Cfg 'defaultLifetimeInMinutes')),
                ((Get-EAField $m.Cfg 'MaximumLifetimeInMinutes') ?? (Get-EAField $m.Cfg 'maximumLifetimeInMinutes'))
        }
        $rows += [pscustomobject]@{ MethodId=$mid; State=$m.State; TenantWide=$m.TenantWide; IncludeTargets=$m.Targets; ExcludeTargets=$m.Exclusions; PrivilegedCoverage=("{0}/{1} (+{2} unknown)" -f $cov.Covered,$cov.Total,$cov.Unknown); Details=$details }
    }

    $sms = _Method 'Sms'; $voice = _Method 'Voice'; $fido2 = _Method 'Fido2'; $whfb = _Method 'WindowsHelloForBusiness'; $tap = _Method 'TemporaryAccessPass'
    $x509 = _Method 'X509Certificate'   # certificate-based auth is also phishing-resistant
    $phishCoverage = _PrivCoverage -methods @($fido2,$whfb,$x509)

    $migrationState = Get-EAField $pol 'PolicyMigrationState'; if ($null -eq $migrationState) { $migrationState = Get-EAField $pol 'policyMigrationState' }
    $registrationEnforcement = Get-EAField $pol 'RegistrationEnforcement'; if ($null -eq $registrationEnforcement) { $registrationEnforcement = Get-EAField $pol 'registrationEnforcement' }
    $campaign = Get-EAField $registrationEnforcement 'AuthenticationMethodsRegistrationCampaign'
    if ($null -eq $campaign) { $campaign = Get-EAField $registrationEnforcement 'authenticationMethodsRegistrationCampaign' }
    $campaignState = if ($campaign) { [string](Get-EAField $campaign 'State') } else { 'not-present' }
    if (-not $campaignState -and $campaign) { $campaignState = [string](Get-EAField $campaign 'state') }
    $campaignInc = if ($campaign) { @(_TargetIds $campaign 'IncludeTargets') } else { @() }
    $campaignExc = if ($campaign) { @(_TargetIds $campaign 'ExcludeTargets') } else { @() }
    $campaignScope = [pscustomobject]@{
        Present=[bool]$campaign; State=$campaignState; IncludeIds=$campaignInc; ExcludeIds=$campaignExc
        TenantWide=(($campaignInc -contains 'all_users') -and $campaignExc.Count -eq 0)
        Targets=($campaignInc -join ','); Exclusions=($campaignExc -join ','); Cfg=$campaign
    }
    # systemCredentialPreferences is a TOP-LEVEL policy property, not an
    # authenticationMethodConfiguration entry.
    $systemPreferredRaw = Get-EAField $pol 'SystemCredentialPreferences'
    if ($null -eq $systemPreferredRaw) { $systemPreferredRaw = Get-EAField $pol 'systemCredentialPreferences' }
    $systemInc = if ($systemPreferredRaw) { @(_TargetIds $systemPreferredRaw 'IncludeTargets') } else { @() }
    $systemExc = if ($systemPreferredRaw) { @(_TargetIds $systemPreferredRaw 'ExcludeTargets') } else { @() }
    $systemState = if ($systemPreferredRaw) { Get-EAField $systemPreferredRaw 'State' } else { $null }
    if ($null -eq $systemState -and $systemPreferredRaw) { $systemState = Get-EAField $systemPreferredRaw 'state' }
    $systemPreferred = [pscustomobject]@{
        Present=[bool]$systemPreferredRaw; State=$(if ($systemPreferredRaw) { [string]$systemState } else { 'not-present' })
        IncludeIds=$systemInc; ExcludeIds=$systemExc; TenantWide=(($systemInc -contains 'all_users') -and $systemExc.Count -eq 0)
        Targets=($systemInc -join ','); Exclusions=($systemExc -join ','); Cfg=$systemPreferredRaw
    }
    $campaignCoverage = _PrivCoverage -methods @($campaignScope)
    $systemPreferredCoverage = _PrivCoverage -methods @($systemPreferred)
    $rows += [pscustomobject]@{ MethodId='PolicyMigrationState'; State=[string]$migrationState; TenantWide=$null; IncludeTargets=''; ExcludeTargets=''; PrivilegedCoverage=''; Details='' }
    $rows += [pscustomobject]@{ MethodId='RegistrationCampaign'; State=$campaignState; TenantWide=$campaignScope.TenantWide; IncludeTargets=$campaignScope.Targets; ExcludeTargets=$campaignScope.Exclusions; PrivilegedCoverage=("{0}/{1} (+{2} unknown)" -f $campaignCoverage.Covered,$campaignCoverage.Total,$campaignCoverage.Unknown); Details='' }
    $rows += [pscustomobject]@{ MethodId='SystemCredentialPreferences'; State=$systemPreferred.State; TenantWide=$systemPreferred.TenantWide; IncludeTargets=$systemPreferred.Targets; ExcludeTargets=$systemPreferred.Exclusions; PrivilegedCoverage=("{0}/{1} (+{2} unknown)" -f $systemPreferredCoverage.Covered,$systemPreferredCoverage.Total,$systemPreferredCoverage.Unknown); Details='' }
    $src = Write-Evidence -BaseName 'auth_method_policy' -Rows $rows -Title 'Authentication Methods Policy (state, include/exclude targets, privileged coverage)'

    if ([string]$migrationState -ne 'migrationComplete') {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Authentication-method policy migration is not complete' `
            -Evidence ("policyMigrationState = {0}." -f ($migrationState ?? 'unknown')) `
            -WhyItMatters 'Until migration is complete, legacy MFA/SSPR settings can remain authoritative or overlap the unified authentication-method policy, so this policy alone does not describe effective method availability.' `
            -RecommendedAction 'Complete migration to the unified Authentication methods policy and verify legacy MFA/SSPR method settings are retired.' -SourceFile $src
    }
    if (-not $campaign -or $campaignState -ne 'enabled') {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Microsoft Authenticator registration campaign is not enabled' `
            -Evidence ("Registration campaign state: {0}." -f $campaignState) `
            -WhyItMatters 'The registration campaign prompts capable users to register a stronger method during sign-in and accelerates migration away from SMS/voice.' `
            -RecommendedAction 'Enable the registration campaign and target all users, with only documented temporary exclusions.' -SourceFile $src
    } elseif ($privMap.Count -gt 0 -and ($campaignCoverage.Covered -lt $campaignCoverage.Total -or $campaignCoverage.Unknown -gt 0)) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Registration campaign does not effectively cover every privileged user' `
            -Evidence ("Privileged coverage: {0}/{1}; unknown: {2}; include={3}; exclude={4}." -f $campaignCoverage.Covered,$campaignCoverage.Total,$campaignCoverage.Unknown,$campaignScope.Targets,$campaignScope.Exclusions) `
            -WhyItMatters 'Eligible and active administrators omitted from stronger-method registration can remain dependent on phishable factors.' `
            -RecommendedAction 'Remove privileged-user/group exclusions and include all privileged users in the registration campaign.' -SourceFile $src
    }
    if (-not $systemPreferred.Present -or $systemPreferred.State -ne 'enabled') {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'System-preferred multifactor authentication is not enabled' `
            -Evidence ("SystemCredentialPreferences state: {0}." -f $systemPreferred.State) `
            -WhyItMatters 'Without system-preferred MFA, users can select a weaker registered method even when a stronger method is available.' `
            -RecommendedAction 'Enable system-preferred MFA and target all users.' -SourceFile $src
    } elseif ($privMap.Count -gt 0 -and ($systemPreferredCoverage.Covered -lt $systemPreferredCoverage.Total -or $systemPreferredCoverage.Unknown -gt 0)) {
        Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'System-preferred MFA does not effectively cover every privileged user' `
            -Evidence ("Privileged coverage: {0}/{1}; unknown: {2}; exclusions: {3}." -f $systemPreferredCoverage.Covered,$systemPreferredCoverage.Total,$systemPreferredCoverage.Unknown,$systemPreferred.Exclusions) `
            -WhyItMatters 'Administrators outside system-preferred MFA can choose a weaker phishable factor despite having a stronger method registered.' `
            -RecommendedAction 'Target all privileged users, including eligible role holders, and remove unnecessary exclusions.' -SourceFile $src
    }
    if (-not $privPopulationKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Privileged authentication-method targeting could not be fully evaluated' `
            -Evidence 'One or more privileged assignments/group memberships could not be read; include/exclude target effectiveness is incomplete, not confirmed clean.' `
            -WhyItMatters 'A method may look tenant-wide while an unreadable exclusion leaves an administrator outside the intended control.' `
            -RecommendedAction 'Restore role/group read access and re-run the authentication-method policy check.' -SourceFile $src -CoverageGap
    }

    foreach ($weak in @(@{ n='SMS'; m=$sms }, @{ n='Voice'; m=$voice })) {
        if ($weak.m.State -ne 'enabled') { continue }
        $weakCoverage = _PrivCoverage -methods @($weak.m)
        if ($weak.m.TenantWide -or $weakCoverage.Covered -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title ("Phishable method {0} is broadly enabled or reaches privileged users" -f $weak.n) `
                -Evidence ("{0}: all-users-without-exclusions={1}; privileged coverage={2}/{3}; include={4}; exclude={5}." -f $weak.n,$weak.m.TenantWide,$weakCoverage.Covered,$weakCoverage.Total,$weak.m.Targets,$weak.m.Exclusions) `
                -WhyItMatters 'SMS/voice are phishable and SIM-swappable. Availability to every account or any administrator leaves a weak factor on a high-value authentication path.' `
                -RecommendedAction 'Phase out SMS/voice; exclude privileged identities immediately and restrict any migration exception to a small, time-bound group.' -SourceFile $src
        } else {
            Add-EntraFinding -Severity 'Low' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title ("Phishable method {0} is enabled for a scoped group" -f $weak.n) `
                -Evidence ("{0} include targets: {1}; exclude targets: {2}; privileged coverage: {3}/{4} (+{5} unknown)." -f $weak.n,$weak.m.Targets,$weak.m.Exclusions,$weakCoverage.Covered,$weakCoverage.Total,$weakCoverage.Unknown) `
                -WhyItMatters 'Scoped SMS/voice (e.g. a temporary migration group) is far lower risk than tenant-wide enablement, but is still a weak factor.' `
                -RecommendedAction 'Confirm the scope is intentional and time-bound; remove when migration completes.' -SourceFile $src
        }
    }

    $phishEnabled = (($fido2.Present -and $fido2.State -eq 'enabled') -or ($whfb.Present -and $whfb.State -eq 'enabled') -or ($x509.Present -and $x509.State -eq 'enabled'))
    if (-not $phishEnabled) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'No phishing-resistant method (FIDO2 / Windows Hello / certificate-based) is enabled' `
            -Evidence ("FIDO2 state: {0}; Windows Hello state: {1}; Certificate-based state: {2}." -f $fido2.State, $whfb.State, $x509.State) `
            -WhyItMatters 'Phishing-resistant authentication is the strongest defence for privileged accounts; if it is not enabled, admins cannot register it.' `
            -RecommendedAction 'Enable FIDO2 security keys / passkeys, Windows Hello for Business or certificate-based authentication and require them for privileged users.' -SourceFile $src
    } elseif ($privMap.Count -gt 0 -and ($phishCoverage.Covered -lt $phishCoverage.Total -or $phishCoverage.Unknown -gt 0)) {
        Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Phishing-resistant methods do not effectively cover every privileged user' `
            -Evidence ("Combined FIDO2/WHfB/CBA privileged coverage: {0}/{1}; unknown: {2}. FIDO2 include/exclude={3}/{4}; WHfB={5}/{6}; CBA={7}/{8}." -f $phishCoverage.Covered,$phishCoverage.Total,$phishCoverage.Unknown,$fido2.Targets,$fido2.Exclusions,$whfb.Targets,$whfb.Exclusions,$x509.Targets,$x509.Exclusions) `
            -WhyItMatters 'A method being enabled somewhere in the tenant is insufficient if active or eligible administrators are excluded or outside its target groups.' `
            -RecommendedAction 'Make at least one phishing-resistant method available to every privileged user and remove privileged exclusions.' -SourceFile $src
    } elseif (-not ($fido2.TenantWide -or $whfb.TenantWide -or $x509.TenantWide)) {
        Add-EntraFinding -Severity 'Low' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Phishing-resistant methods cover administrators but are not tenant-wide' `
            -Evidence ("FIDO2 targets/exclusions: {0}/{1}; WHfB: {2}/{3}; Certificate-based: {4}/{5}." -f $fido2.Targets,$fido2.Exclusions,$whfb.Targets,$whfb.Exclusions,$x509.Targets,$x509.Exclusions) `
            -WhyItMatters 'Privileged coverage is the first priority, but wider phishing-resistant availability reduces the tenant-wide credential-phishing surface.' `
            -RecommendedAction 'Expand phishing-resistant method availability from privileged users to the wider population.' -SourceFile $src
    }

    if ($tap.Present -and $tap.State -eq 'enabled') {
        $cfg = $tap.Cfg
        $oneTime = $null; $minLife = $null; $defaultLife = $null; $maxLife = $null
        try {
            if ($cfg.PSObject.Properties['IsUsableOnce']) { $oneTime = [bool]$cfg.IsUsableOnce } elseif ($cfg.AdditionalProperties -and $cfg.AdditionalProperties.ContainsKey('isUsableOnce')) { $oneTime = [bool]$cfg.AdditionalProperties['isUsableOnce'] }
            $maxLife = Get-Ap $cfg 'maximumLifetimeInMinutes'; if ($null -eq $maxLife -and $cfg.PSObject.Properties['MaximumLifetimeInMinutes']) { $maxLife = $cfg.MaximumLifetimeInMinutes }
            $minLife = Get-Ap $cfg 'minimumLifetimeInMinutes'; if ($null -eq $minLife -and $cfg.PSObject.Properties['MinimumLifetimeInMinutes']) { $minLife = $cfg.MinimumLifetimeInMinutes }
            $defaultLife = Get-Ap $cfg 'defaultLifetimeInMinutes'; if ($null -eq $defaultLife -and $cfg.PSObject.Properties['DefaultLifetimeInMinutes']) { $defaultLife = $cfg.DefaultLifetimeInMinutes }
        } catch {}
        if ($oneTime -eq $false -and $tap.TenantWide) {
            Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title 'Temporary Access Pass is reusable AND broadly targeted' `
                -Evidence ("TAP isUsableOnce=false, targeted at all users; max lifetime {0} min." -f ($maxLife ?? 'default')) `
                -WhyItMatters 'A reusable, broadly-available Temporary Access Pass is a long-lived bypass credential that can be abused if intercepted.' `
                -RecommendedAction 'Make TAP one-time use with a short lifetime and scope it to a controlled onboarding/helpdesk process.' -SourceFile $src
        } elseif ($oneTime -eq $false) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title 'Temporary Access Pass is reusable (not one-time)' `
                -Evidence ("TAP isUsableOnce=false; targets: {0}." -f $tap.Targets) `
                -WhyItMatters 'A reusable Temporary Access Pass is a longer-lived bypass credential than a one-time pass.' `
                -RecommendedAction 'Configure Temporary Access Pass as one-time use with a short lifetime.' -SourceFile $src
        }
        if ($null -eq $oneTime -or $null -eq $defaultLife -or $null -eq $maxLife) {
            Add-EntraFinding -Severity 'Information' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title 'Temporary Access Pass reuse/lifetime settings could not be fully read' `
                -Evidence ("isUsableOnce={0}; minimum={1}; default={2}; maximum={3} minutes. Null values are unknown, not safe defaults." -f ($oneTime ?? 'unknown'),($minLife ?? 'unknown'),($defaultLife ?? 'unknown'),($maxLife ?? 'unknown')) `
                -WhyItMatters 'TAP is a bootstrap credential. Its reuse and lifetime determine how long an intercepted pass can be replayed.' `
                -RecommendedAction 'Verify TAP policy details in Entra and configure one-time use with a short default and maximum lifetime.' -SourceFile $src -CoverageGap
        }
        if (($defaultLife -as [int]) -gt 60 -or ($maxLife -as [int]) -gt 480) {
            $sev = if (($defaultLife -as [int]) -gt 480 -or ($maxLife -as [int]) -gt 1440) { 'High' } else { 'Medium' }
            Add-EntraFinding -Severity $sev -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title 'Temporary Access Pass lifetime is longer than the hardened baseline' `
                -Evidence ("TAP minimum={0}, default={1}, maximum={2} minutes; baseline is default <=60 and maximum <=480 minutes." -f ($minLife ?? 'unknown'),($defaultLife ?? 'unknown'),($maxLife ?? 'unknown')) `
                -WhyItMatters 'Long-lived TAPs behave like temporary passwords and widen the replay window if copied, logged or disclosed.' `
                -RecommendedAction 'Set the default TAP lifetime to 60 minutes or less and maximum to 8 hours or less; issue shorter one-time passes whenever possible.' -SourceFile $src
        }
    }

    if ($script:Findings.Where({$_.CheckId -eq 'authmethodpolicy'}).Count -eq 0) {
        $f2scope = if ($fido2.TenantWide) { 'all' } else { 'scoped' }
        $whscope = if ($whfb.TenantWide) { 'all' } else { 'scoped' }
        $cbscope = if ($x509.TenantWide) { 'all' } else { 'scoped' }
        Add-EntraFinding -Severity 'Information' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Authentication methods policy reviewed' `
            -Evidence ("FIDO2={0}/{1}, WHfB={2}/{3}, CBA={4}/{5}; SMS={6}, Voice={7}." -f $fido2.State,$f2scope,$whfb.State,$whscope,$x509.State,$cbscope,$sms.State,$voice.State) `
            -WhyItMatters 'The method policy decides which factors users can register and use, and at what scope.' `
            -RecommendedAction 'Prefer phishing-resistant methods tenant-wide; minimise SMS/voice.' -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 21 - accesspaths (effective-access / attack-path correlation)
# ===========================================================================
function Invoke-Check-AccessPaths {
    $assignments = Get-EAPrivAssignments
    if ($script:PrivAssignmentsFailed -and @($assignments).Count -eq 0) {
        # An empty result caused by a FAILED fetch must not fall through as a silent
        # "no duplicate paths / no escalation" pass.
        Add-EntraFinding -Severity 'Medium' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'Effective-access / attack-path analysis could not be performed' `
            -Evidence 'The privileged-role assignment list could not be fetched, so duplicate-path and ownership-escalation analysis was skipped - status is unknown, not clean.' `
            -WhyItMatters 'Attack-path findings are only as good as the assignment data behind them; reporting nothing here would look like a pass.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory (or retry on transient failure) and re-run the accesspaths check.' -CoverageGap
        return
    }
    try { Get-EAUsers | Out-Null } catch {}

    # Direct (user) privileged assignments, tracking activation state (Active wins).
    $directKey = @{}   # "userId|roleTemplateId|scope" -> 'Active' | 'Eligible'
    foreach ($a in $assignments) {
        if ($a.IsPrivileged -and $a.PrincipalType -eq 'user' -and $a.PrincipalId) {
            $k = '{0}|{1}|{2}' -f $a.PrincipalId, $a.RoleTemplateId, $a.ScopeKey
            if ($a.State -eq 'Active' -or -not $directKey.ContainsKey($k)) { $directKey[$k] = $a.State }
        }
    }

    # Group-based privileged assignments -> expand to user members (carrying the group's state).
    $groupAssign = @($assignments | Where-Object { $_.IsPrivileged -and $_.PrincipalType -eq 'group' -and $_.PrincipalId })
    $pathByUserRole = @{}     # "userId|roleTemplateId|scope" -> list of @{Group;State}
    $hiddenGaps = @()
    $hiddenGapIds = New-Object System.Collections.Generic.HashSet[string]   # dedup by ID, not name ($groupAssign repeats a group once per state)
    $ownerGaps = @()
    foreach ($g in $groupAssign) {
        $members = @()
        try { $members = @(Get-MgGroupTransitiveMember -GroupId $g.PrincipalId -All -ErrorAction Stop) } catch {
            if ($hiddenGapIds.Add([string]$g.PrincipalId)) { $hiddenGaps += ($g.PrincipalName ?? $g.PrincipalId) }
            continue
        }
        foreach ($m in $members) {
            $mid = $m.Id
            $mtype = [string](Get-Ap $m '@odata.type')
            $upn = Get-Ap $m 'userPrincipalName'
            if (-not $upn -and $mtype -ne '#microsoft.graph.user') { continue }   # count only user members (incl. UPN-less user objects)
            $key = '{0}|{1}|{2}' -f $mid, $g.RoleTemplateId, $g.ScopeKey
            if (-not $pathByUserRole.ContainsKey($key)) { $pathByUserRole[$key] = New-Object System.Collections.Generic.List[object] }
            # Carry the group ID: display names are not unique in Entra, so de-duplicating
            # paths by name would collapse two distinct same-named groups into one path.
            $pathByUserRole[$key].Add([pscustomobject]@{ Group=($g.PrincipalName ?? 'group'); GroupId=$g.PrincipalId; State=$g.State }) | Out-Null
        }
    }

    # Duplicate / parallel paths, classified by activation model: a duplicate that
    # involves an ACTIVE (standing) path is more serious than eligible-only duplication.
    $dupRows = @()
    foreach ($key in $pathByUserRole.Keys) {
        $paths = @($pathByUserRole[$key])
        # De-duplicate by group ID (a group can appear once per assignment state); the
        # same display name appearing twice then correctly signals two DISTINCT groups.
        $uniqPaths = @($paths | Group-Object GroupId | ForEach-Object { $_.Group[0] })
        $parts = $key -split '\|', 3; $uid = $parts[0]; $rtid = $parts[1]; $assignmentScope = $parts[2]
        $directS = if ($directKey.ContainsKey($key)) { $directKey[$key] } else { $null }
        $pathCount = $uniqPaths.Count + [int]([bool]$directS)
        if ($pathCount -le 1) { continue }
        $involvesActive = ($directS -eq 'Active') -or (@($paths | Where-Object { $_.State -eq 'Active' }).Count -gt 0)
        $activationModel = if ($involvesActive) { 'Active path' } else { 'Eligible-only' }
        $upn = if ($script:UserById.ContainsKey($uid)) { $script:UserById[$uid].UserPrincipalName } else { $uid }
        $dupRows += [pscustomobject]@{
            User=$upn; Role=$script:PrivilegedRoleTemplates[$rtid]; AssignmentScope=$assignmentScope; ViaGroups=(@($uniqPaths | ForEach-Object { $_.Group }) -join ', ')
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

    # Effective holders of each EXACT role (direct + group-reachable), keyed "userId|roleTemplateId".
    # Suppress an owner-escalation path ONLY when the owner already holds the SAME role the
    # group grants as ACTIVE standing access. Two refinements:
    #  - "privileged via some OTHER role" must NOT suppress (Exchange Admin owning a GA group).
    #  - holding the same role only as ELIGIBLE must NOT suppress: owning a group with the role
    #    ACTIVE lets the owner self-add and bypass the PIM activation workflow.
    $sameRoleActiveKey = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in $directKey.Keys) { if ($directKey[$k] -eq 'Active') { [void]$sameRoleActiveKey.Add($k) } }
    foreach ($key in $pathByUserRole.Keys) { if (@($pathByUserRole[$key] | Where-Object { $_.State -eq 'Active' }).Count -gt 0) { [void]$sameRoleActiveKey.Add($key) } }

    # Ownership-based escalation: owners of groups assigned a privileged role.
    # $groupAssign holds one row per (group, role, STATE) - dedup on (group, role) so
    # owners are neither double-counted nor fetched twice, and treat a failed owner
    # read as a coverage gap rather than "no owners".
    $ownEscRows = @()
    $seenGroupRole = New-Object System.Collections.Generic.HashSet[string]
    foreach ($g in $groupAssign) {
        if (-not $seenGroupRole.Add(('{0}|{1}|{2}' -f $g.PrincipalId, $g.RoleTemplateId, $g.ScopeKey))) { continue }
        $grantsGAorPRA = ([bool]$g.IsTier0 -or $g.RoleTemplateId -eq $script:GlobalAdminTemplateId -or ($script:PrivilegedRoleTemplates[$g.RoleTemplateId] -match 'Privileged Role Administrator|Privileged Authentication'))
        $owners = @(); try { $owners = @(Get-MgGroupOwner -GroupId $g.PrincipalId -All -ErrorAction Stop) } catch { $ownerGaps += ($g.PrincipalName ?? $g.PrincipalId) }
        foreach ($o in $owners) {
            $oid   = $o.Id
            $otype = [string](Get-Ap $o '@odata.type')
            $oupn  = Get-Ap $o 'userPrincipalName'
            $oname = Get-Ap $o 'displayName'
            $label = if ($oupn) { $oupn } elseif ($oname) { $oname } else { $oid }
            $isUser = (($otype -eq '#microsoft.graph.user') -or [bool]$oupn)
            $ownerType = if ($otype) { ($otype -replace '#microsoft.graph.','') } elseif ($isUser) { 'user' } else { 'unknown' }

            $isGuest = $false; $disabled = $false; $hasSameRole = $false
            if ($isUser) {
                $isGuest = ($oupn -like '*#EXT#*')
                if ($oid -and $script:UserById.ContainsKey($oid)) { $disabled = -not [bool]$script:UserById[$oid].AccountEnabled }
                $hasSameRole = ($oid -and $sameRoleActiveKey.Contains(('{0}|{1}|{2}' -f $oid, $g.RoleTemplateId, $g.ScopeKey)))
                # Suppress ONLY when the owner already holds this exact role and is a normal
                # (non-guest, enabled) account - then ownership grants nothing new.
                if ($hasSameRole -and -not $isGuest -and -not $disabled) { continue }
            }
            # Gaining GA/PRA, or any guest/disabled owner, is Critical; gaining another role is High.
            $rowSev = if ($isGuest -or $disabled -or $grantsGAorPRA) { 'Critical' } else { 'High' }
            $ownEscRows += [pscustomobject]@{
                Owner=$label; OwnerType=$ownerType; Group=($g.PrincipalName ?? $g.PrincipalId); GrantsRole=$g.RoleName
                AssignmentScope=$g.ScopeKey; Severity=$rowSev; OwnerGuest=$isGuest; OwnerDisabled=$disabled; OwnerAlreadyHasSameRole=$hasSameRole
            }
        }
    }
    if ($ownEscRows.Count -gt 0) {
        $osrc = Write-Evidence -BaseName 'access_paths_ownership' -Rows $ownEscRows -Title 'Effective Access - Ownership-Based Escalation'
        $critEsc = @($ownEscRows | Where-Object { $_.Severity -eq 'Critical' })
        $highEsc = @($ownEscRows | Where-Object { $_.Severity -eq 'High' })
        if ($critEsc.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'accesspaths' -Category 'Privileged Access' `
                -Title ("{0} critical ownership-based privilege-escalation path(s)" -f $critEsc.Count) `
                -Evidence ("Owners who can self-add to gain a top-tier role, or guest/disabled owners of privileged groups: {0}" -f (($critEsc | Select-Object -First 8 | ForEach-Object { "$($_.Owner)->$($_.GrantsRole)" }) -join '; ')) `
                -WhyItMatters 'An owner of a group assigned a privileged role can add themselves and inherit that role. Gaining Global Admin / Privileged Role Admin this way - or a guest/disabled owner of any privileged group - is a direct tenant-takeover-class escalation. Note: holding a DIFFERENT privileged role does not make this safe.' `
                -RecommendedAction 'Remove guest, disabled and non-administrative owners from groups assigned privileged roles; for GA/PRA-granting groups restrict ownership to the most trusted admins and manage membership via PIM for Groups with approval.' `
                -SourceFile $osrc -ResultRows $critEsc
        }
        if ($highEsc.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'accesspaths' -Category 'Privileged Access' `
                -Title ("{0} ownership-based privilege-escalation path(s) to a privileged role" -f $highEsc.Count) `
                -Evidence ("Owners who can self-add to gain a privileged role they do not already hold: {0}" -f (($highEsc | Select-Object -First 8 | ForEach-Object { "$($_.Owner)->$($_.GrantsRole)" }) -join '; ')) `
                -WhyItMatters 'An owner of a group assigned a privileged role can add themselves and inherit a role they do not currently hold - an indirect escalation that bypasses the role-assignment model (the cloud analog of a dangerous WriteOwner/AddMember ACL).' `
                -RecommendedAction 'Remove non-administrative owners from groups assigned privileged roles; manage membership via PIM for Groups with approval.' `
                -SourceFile $osrc -ResultRows $highEsc
        }
    }

    # Owners of groups EXCLUDED from Conditional Access policies (especially MFA-enforcing
    # ones) can add themselves to the group and thereby exempt their own account.
    $caExcl = @{}   # groupId -> pscustomobject{ Policies=List; EnforcesMfa }
    try {
        foreach ($p in @(Get-EACaPolicies | Where-Object { $_.State -eq 'enabled' })) {
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
        $owners = @(); try { $owners = @(Get-MgGroupOwner -GroupId $gid -All -ErrorAction Stop) } catch { $ownerGaps += $gname }
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
            -RecommendedAction 'Grant Member.Read.Hidden (read-only) to evaluate hidden-membership groups, or review those groups manually.' -SourceFile $src -CoverageGap
    }
    $ownerGaps = @($ownerGaps | Select-Object -Unique)
    if ($ownerGaps.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ("{0} group(s) whose owners could not be read (coverage gap)" -f $ownerGaps.Count) `
            -Evidence ("Owner lists could not be read for: {0}" -f (($ownerGaps | Select-Object -First 8) -join ', ')) `
            -WhyItMatters 'If group owners cannot be read, ownership-based escalation paths through those groups cannot be evaluated - "no unsafe owners" is unknown, not confirmed.' `
            -RecommendedAction 'Verify the audit identity can read group owners (Group.Read.All) and re-run, or review those groups'' owners manually.' -SourceFile $src -CoverageGap
    }

    if ($dupRows.Count -eq 0 -and $ownEscRows.Count -eq 0 -and $caOwnRows.Count -eq 0 -and $hiddenGaps.Count -eq 0 -and $ownerGaps.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'No duplicate privilege paths or ownership-escalation paths detected' `
            -Evidence 'Each privileged role is reached through a single reviewed path, and role-granting groups have no unsafe owners.' `
            -WhyItMatters 'Single, reviewed privilege paths make de-provisioning reliable and reduce hidden standing access.' `
            -RecommendedAction 'Maintain single-path privileged assignments and safe group ownership.' -SourceFile $src
    }
}

# ===========================================================================
# CHECK 22 - staleapps (unused applications, by service-principal sign-in activity)
# ===========================================================================
function Invoke-Check-StaleApps {
    $cut = (Get-Date).ToUniversalTime().AddDays(-$StaleAppDays)
    # BOTH Microsoft first-party owner tenants - built-in SPs are owned by either.
    $msftTenants = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a'   # Microsoft services
        '72f988bf-86f1-41af-91ab-2d7cd011db47'   # Microsoft corporate
    )

    # Service-principal sign-in activity (beta report; covers interactive + app-only sign-ins).
    # lastSignInDateTime is a persisted "last seen" timestamp, so it surfaces sign-ins older
    # than the 30-day raw-log window.
    $lastByAppId = @{}
    $coverageOk = $true
    try {
        $uri = 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities'
        $guard = 0
        while ($uri -and $guard -lt 500) {
            $uri = Assert-EAGraphReadUri $uri
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            foreach ($r in @($resp['value'])) {
                $appId = [string]$r['appId']
                if (-not $appId) { continue }
                $dates = @()
                foreach ($k in @('lastSignInActivity','delegatedClientSignInActivity','applicationAuthenticationClientSignInActivity')) {
                    $sub = $r[$k]
                    if ($sub -and $sub['lastSignInDateTime']) { try { $dates += [datetime]$sub['lastSignInDateTime'] } catch {} }
                }
                if ($dates.Count -gt 0) {
                    $mx = ($dates | Sort-Object -Descending | Select-Object -First 1)
                    if (-not $lastByAppId.ContainsKey($appId) -or $mx -gt $lastByAppId[$appId]) { $lastByAppId[$appId] = $mx }
                }
            }
            $uri = $resp['@odata.nextLink']; $guard++
        }
        if ($uri) { throw 'Microsoft Graph service-principal activity pagination exceeded the 500-page safety limit.' }
    } catch { $coverageOk = $false }

    if (-not $coverageOk) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
            -Title 'Stale-application analysis not available (service principal sign-in activity could not be read)' `
            -Evidence 'The beta servicePrincipalSignInActivities report could not be read (needs AuditLog.Read.All and Entra ID P1+). This is a coverage gap, not "all apps are in use".' `
            -WhyItMatters 'Without service-principal sign-in activity, unused applications cannot be identified for cleanup.' `
            -RecommendedAction 'Grant AuditLog.Read.All and ensure Entra ID P1+, then re-run.' -SourceFile $null -CoverageGap
        return
    }

    $sps = @(Get-EAServicePrincipals)
    # Reuse the shared application cache (it carries createdDateTime + credentials),
    # preserving the original ignore-on-failure semantics of this enrichment step.
    $appCreated = @{}; $appCreds = @{}
    $appsAll = @(); try { $appsAll = @(Get-EAApplications) } catch {}
    foreach ($a in $appsAll) {
        if ($a.AppId) {
            $appCreated[$a.AppId] = $a.CreatedDateTime
            $appCreds[$a.AppId] = ((@($a.PasswordCredentials).Count + @($a.KeyCredentials).Count) -gt 0)
        }
    }

    $rows = @(); $unknownRows = @()
    $reviewed = 0
    foreach ($sp in $sps) {
        # Real applications only (skip managed identities etc.) and skip Microsoft first-party
        # service principals - those are built-in and are not the customer's to remove.
        if ($sp.ServicePrincipalType -and $sp.ServicePrincipalType -notin @('Application','Legacy')) { continue }
        if ($sp.AppOwnerOrganizationId -and (([string]$sp.AppOwnerOrganizationId) -in $msftTenants)) { continue }
        $reviewed++
        $appId = [string]$sp.AppId
        $last = if ($lastByAppId.ContainsKey($appId)) { $lastByAppId[$appId] } else { $null }
        # Multi-tenant/third-party service principals have no local application object.
        # Fall back to the enterprise application's own creation time before declaring
        # no-sign-in activity stale; if neither timestamp exists, report UNKNOWN.
        $created = if ($appCreated.ContainsKey($appId)) { $appCreated[$appId] } elseif ($sp.CreatedDateTime) { $sp.CreatedDateTime } else { $null }
        $hasCred = ((@($sp.PasswordCredentials).Count + @($sp.KeyCredentials).Count) -gt 0) -or ($appCreds.ContainsKey($appId) -and $appCreds[$appId])

        $stale = $false; $reason = ''
        if ($null -ne $last) {
            if ($last -lt $cut) { $stale = $true; $reason = ("Last sign-in {0}" -f $last.ToString('yyyy-MM-dd')) }
        } elseif ($created -and ([datetime]$created) -lt $cut) {
            # No sign-in on record AND the app is older than the window (avoids flagging brand-new apps).
            $stale = $true; $reason = 'No sign-in on record'
        }
        if ($stale) {
            $rows += [pscustomobject]@{ Application=$sp.DisplayName; AppId=$appId; LastSignIn=$last; Reason=$reason; HasCredentials=$hasCred; Enabled=$sp.AccountEnabled }
        } elseif ($null -eq $last -and $null -eq $created) {
            $unknownRows += [pscustomobject]@{ Application=$sp.DisplayName; AppId=$appId; LastSignIn=$null; Created=$null; Reason='No sign-in record and no creation timestamp'; HasCredentials=$hasCred; Enabled=$sp.AccountEnabled; OwnerTenant=$sp.AppOwnerOrganizationId }
        }
    }
    $src = Write-Evidence -BaseName 'stale_applications' -Rows $rows -Title ("Stale / Unused Applications (no sign-in > {0} days)" -f $StaleAppDays) `
        -Notes @("Reviewed $reviewed non-Microsoft application service principal(s).", "Unknown-age/no-sign-in service principals: $($unknownRows.Count)")
    $unknownSrc = $null
    if ($unknownRows.Count -gt 0) { $unknownSrc = Write-Evidence -BaseName 'stale_applications_unknown' -Rows $unknownRows -Title 'Applications with Unknown Usage/Age' }

    $staleCred = @($rows | Where-Object { $_.HasCredentials })
    $staleNoCred = @($rows | Where-Object { -not $_.HasCredentials })
    if ($staleCred.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'staleapps' -Category 'Applications' `
            -Title ("{0} stale application(s) with live credentials (> {1} days unused)" -f $staleCred.Count, $StaleAppDays) `
            -Evidence ("Unused apps that still hold a secret/certificate: {0}" -f (($staleCred | Select-Object -First 10 -ExpandProperty Application) -join ', ')) `
            -WhyItMatters 'An application unused for a long time but still holding live credentials is unmonitored attack surface - a forgotten secret nobody is watching that may never be missed if abused.' `
            -RecommendedAction 'Confirm whether each app is still needed; if not, remove it. If retained, remove unused credentials and document the owner.' `
            -SourceFile $src -ResultRows @($staleCred | Select-Object Application,LastSignIn,Reason,Enabled)
    }
    if ($staleNoCred.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'staleapps' -Category 'Applications' `
            -Title ("{0} stale application(s) with no recent sign-in (> {1} days)" -f $staleNoCred.Count, $StaleAppDays) `
            -Evidence ("Cleanup candidates (no sign-in in the window): {0}" -f (($staleNoCred | Select-Object -First 10 -ExpandProperty Application) -join ', ')) `
            -WhyItMatters 'Unused applications and service principals are directory clutter that widens the attack surface and complicates review. Removing what is not needed reduces risk and noise.' `
            -RecommendedAction 'Review each unused application with its owner and remove the ones that are no longer required.' `
            -SourceFile $src -ResultRows @($staleNoCred | Select-Object Application,LastSignIn,Reason,Enabled)
    }
    if ($unknownRows.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
            -Title ("{0} application service principal(s) have unknown age and no sign-in record" -f $unknownRows.Count) `
            -Evidence ("These third-party/legacy service principals have neither report activity nor a readable application/service-principal creation timestamp: {0}." -f (($unknownRows | Select-Object -First 10 -ExpandProperty Application) -join ', ')) `
            -WhyItMatters 'No sign-in record cannot be interpreted as recent use when the object age is also unknown; treating these objects as clean hides unreviewed application access.' `
            -RecommendedAction 'Review the enterprise applications manually, establish owner/purpose/creation history, and remove those no longer required.' `
            -SourceFile $unknownSrc -ResultRows $unknownRows -CoverageGap
    }
    if ($rows.Count -eq 0 -and $unknownRows.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
            -Title ("No applications met the stale threshold ({0} days)" -f $StaleAppDays) `
            -Evidence ("All {0} reviewed non-Microsoft application service principal(s) either have recent sign-in activity or were created within the review window." -f $reviewed) `
            -WhyItMatters 'Keeping only actively-used applications reduces attack surface.' `
            -RecommendedAction 'Continue periodic review of application usage.' -SourceFile $src
    }
}

# ===========================================================================
# REPORT ENGINE  (HTML/CSS/JS reused verbatim from the AD audit for an
# identical look: light/dark theme, severity badges, filterable finding
# cards, executive risk report with score band matrix.)
# ===========================================================================

function New-FindingAnchor([object]$f) {
    # Anchor is assigned once at Add-EntraFinding time so every report writer resolves
    # the same finding to the same id; fall back for objects created outside it.
    if ($f.PSObject.Properties['Anchor'] -and $f.Anchor) { return $f.Anchor }
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
  function applyFilters(){var sev=q('#severityFilter').value;var cf=q('#categoryFilter');var cat=cf?cf.value:'All';var query=(q('#searchFilter').value||'').toLowerCase().trim();var visible=0;findings().forEach(function(it){var s=it.getAttribute('data-sev');var c=it.getAttribute('data-category')||'';var text=(it.innerText||'').toLowerCase();var show=(sev==='All'||s===sev)&&(cat==='All'||c===cat)&&(!query||text.indexOf(query)>=0);it.style.display=show?'':'none';if(show)visible++;});var el=q('#visibleFindings');if(el)el.value=visible;}
  var b=q('#themeToggle');if(b){b.addEventListener('click',function(){var n=document.body.getAttribute('data-theme')==='dark'?'light':'dark';applyTheme(n);});}
  applyTheme(currentTheme());
  if(window.matchMedia){var mq=window.matchMedia('(prefers-color-scheme: dark)');var h=function(e){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(_){}if(s!=='light'&&s!=='dark')applyTheme(e.matches?'dark':'light');};if(mq.addEventListener)mq.addEventListener('change',h);else if(mq.addListener)mq.addListener(h);}
  var sf=q('#severityFilter');if(sf)sf.addEventListener('change',applyFilters);
  var cft=q('#categoryFilter');if(cft)cft.addEventListener('change',applyFilters);
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
.pill.ok{background:var(--low-bg);color:var(--low-text)}
.pill.info{background:var(--info-bg);color:var(--info-text)}
.pill.find{background:var(--high-bg);color:var(--high-text)}
.pill.skip{background:var(--info-bg);color:var(--info-text)}
.pill.err{background:var(--critical-bg);color:var(--critical-text)}
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
td.title{font-weight:700}
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

$script:RiskPoints = @{ Critical = 25; High = 10; Medium = 4; Low = 1; Information = 0 }

# Risk bands, worst-first. Defined ONCE and used for both the band computation and the
# matrix rendered in the Risk Report, so code and report can never drift apart.
$script:RiskBands = @(
    [pscustomobject]@{ Level='Critical'; Min=150; Meaning='Severe and/or broad exposure across multiple checks. Treat as a priority workstream with owners and timelines.' }
    [pscustomobject]@{ Level='High';     Min=60;  Meaning='Significant exposure; prompt remediation with assigned owners.' }
    [pscustomobject]@{ Level='Moderate'; Min=20;  Meaning='Material findings to remediate in the next hardening cycle.' }
    [pscustomobject]@{ Level='Low';      Min=1;   Meaning='Minor issues; address during routine maintenance.' }
    [pscustomobject]@{ Level='Clean';    Min=0;   Meaning='No risk-bearing findings (Information items only). Maintain and monitor.' }
)

function Get-EntraRiskScore($findings) {
    # ACCUMULATING risk with DIMINISHING RETURNS: higher = worse. Findings are grouped
    # into (check, RULE, severity) buckets - the same rule discriminator the stable
    # finding ids use - and each bucket contributes points * sqrt(count). So volume
    # still raises the score - 28 permanent Global Admins score well above 8
    # (sqrt 28 vs sqrt 8) - but ONE systemic issue repeated across many objects cannot
    # drown out every other signal, while DISTINCT issues inside the same check still
    # add up instead of sharing one bucket (bucketing by check alone under-counted a
    # check that surfaces several different problems at the same severity).
    # Unbounded on purpose, so magnitude stays visible.
    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0 }
    $buckets = [ordered]@{}
    foreach ($f in $findings) {
        $sev = Normalize-Severity $f.Severity
        $counts[$sev]++
        if ($sev -eq 'Information') { continue }
        # Bucket rule: explicit RuleId when set; otherwise the digit-stripped title slug.
        # PER-OBJECT findings title as "issue: object" - strip the object suffix so 28
        # permanent Global Admins share ONE bucket (25 x sqrt(28)) instead of becoming 28
        # single-count buckets, which would defeat the diminishing returns entirely.
        # (Scoring only - the stable trend ids in New-FindingKey keep the full rule.)
        $bucketTitle = [string]$f.Title
        if (($f.AffectedPrincipal -or $f.ObjectId) -and $bucketTitle.Contains(':')) { $bucketTitle = (($bucketTitle -split ':', 2)[0]).Trim() }
        $rule = if ($f.RuleId) { [string]$f.RuleId } else { (($bucketTitle -replace '\d+','') -replace '[^A-Za-z]+','-').Trim('-').ToLowerInvariant() }
        $k = '{0}|{1}|{2}' -f [string]$f.CheckId, $rule, $sev
        if ($buckets.Contains($k)) { $buckets[$k].Count++ }
        else { $buckets[$k] = @{ Severity = $sev; Count = 1; CheckId = [string]$f.CheckId; Title = $bucketTitle } }
    }
    $raw = 0.0
    $drivers = foreach ($b in $buckets.Values) {
        $pts = $script:RiskPoints[$b.Severity] * [math]::Sqrt($b.Count)
        $raw += $pts
        [pscustomobject]@{ Severity = $b.Severity; CheckId = $b.CheckId; Title = $b.Title; Count = $b.Count; Points = [math]::Round($pts, 1) }
    }
    $score = [int][math]::Round($raw)
    $band = 'Clean'
    foreach ($bd in $script:RiskBands) { if ($score -ge $bd.Min) { $band = $bd.Level; break } }
    [pscustomobject]@{
        Score = $score; Band = $band
        Critical = $counts.Critical; High = $counts.High; Medium = $counts.Medium; Low = $counts.Low; Information = $counts.Information
        # Per-bucket contributions, largest first, so the report can show WHAT drives the score.
        Drivers = @($drivers | Sort-Object Points -Descending)
    }
}

# Higher score = worse, so map the risk band to the matching severity colour.
function Get-BandBadgeClass([string]$band) {
    switch ($band) { 'Clean' { 'Low' } 'Low' { 'Low' } 'Moderate' { 'Medium' } 'High' { 'High' } 'Critical' { 'Critical' } default { 'Information' } }
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

    # Category filter options from the categories actually present in this run.
    $catOptions = @('<option>All</option>') + @($Items | ForEach-Object { [string]$_.Category } | Where-Object { $_ } |
        Sort-Object -Unique | ForEach-Object { "<option>$(HtmlEncode $_)</option>" })

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
          <div class="filter"><label for="categoryFilter">Category</label>
            <select id="categoryFilter">$($catOptions -join '')</select></div>
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
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Write-EntraRiskReport {
    param([string]$Path, [object[]]$Items, [hashtable]$Counts, [string]$TenantName, [string]$GeneratedOn, [pscustomobject]$Score, [hashtable]$Stats)

    $bandClass = Get-BandBadgeClass $Score.Band
    # Higher score = worse. Ranges derive from the single $script:RiskBands definition
    # (worst-first), so this matrix always matches the thresholds the code applied.
    $bands = for ($i = 0; $i -lt $script:RiskBands.Count; $i++) {
        $b = $script:RiskBands[$i]
        $range = if ($i -eq 0) { "$($b.Min)+" }
                 elseif ($b.Min -eq ($script:RiskBands[$i-1].Min - 1)) { "$($b.Min)" }
                 else { "$($b.Min) - $($script:RiskBands[$i-1].Min - 1)" }
        [pscustomobject]@{ Level=$b.Level; Range=$range; Meaning=$b.Meaning }
    }
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

    # Score drivers: the per-issue buckets behind the score (points = severity x sqrt(count)),
    # largest contribution first, so the score is explainable instead of a black box.
    $driverRows = foreach ($d in @($Score.Drivers | Select-Object -First 10)) {
        $pct = if ($Score.Score -gt 0) { [math]::Round(100 * $d.Points / $Score.Score) } else { 0 }
        "<tr><td><span class='pill sev-$($d.Severity)'>$($d.Severity)</span></td><td class='title'>$(HtmlEncode $d.Title)</td><td class='mono'>$(HtmlEncode $d.CheckId)</td><td style='text-align:right'>$($d.Count)</td><td style='text-align:right' class='mono'>$($d.Points)</td><td style='text-align:right' class='mono'>$pct%</td></tr>"
    }
    if (-not $driverRows) { $driverRows = @("<tr><td colspan='6'>No risk-bearing findings - nothing contributes to the score.</td></tr>") }
    $driverNote = if (@($Score.Drivers).Count -gt 10) { "<div style='margin-top:6px'><small>Top 10 of $(@($Score.Drivers).Count) issue buckets shown; the full list is in the findings below.</small></div>" } else { '' }

    $catGroups = $Items | ForEach-Object { [pscustomobject]@{ Category=$_.Category; Severity=(Normalize-Severity $_.Severity) } } |
        Group-Object Category | Sort-Object Name
    $catRows = foreach ($cg in $catGroups) {
        $cc=@($cg.Group|?{$_.Severity -eq 'Critical'}).Count; $ch=@($cg.Group|?{$_.Severity -eq 'High'}).Count
        $cm=@($cg.Group|?{$_.Severity -eq 'Medium'}).Count; $cl=@($cg.Group|?{$_.Severity -eq 'Low'}).Count
        # Total counts only the four risk columns shown - Information findings have no
        # column here, and including them made rows appear not to sum.
        $ct = $cc + $ch + $cm + $cl
        if ($ct -eq 0) { continue }   # Information-only category: nothing risk-scored to show
        "<tr><td>$(HtmlEncode $cg.Name)</td><td style='text-align:center'>$(if($cc){"<span class='pill sev-Critical'>$cc</span>"}else{'-'})</td><td style='text-align:center'>$(if($ch){"<span class='pill sev-High'>$ch</span>"}else{'-'})</td><td style='text-align:center'>$(if($cm){"<span class='pill sev-Medium'>$cm</span>"}else{'-'})</td><td style='text-align:center'>$(if($cl){"<span class='pill sev-Low'>$cl</span>"}else{'-'})</td><td style='text-align:center;font-weight:700'>$ct</td></tr>"
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
          <div><div class="grade">Risk score (higher = worse)</div><div class="value">$($Score.Score)</div></div>
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
    <h2>What drives the score</h2>
    <table><thead><tr><th>Severity</th><th style="text-align:left">Issue</th><th style="text-align:left">Check</th><th style="text-align:right">Findings</th><th style="text-align:right">Points</th><th style="text-align:right">Share</th></tr></thead><tbody>$($driverRows -join "`n")</tbody></table>
    $driverNote
  </div>

  <div class="section">
    <h2>Interpretation</h2>
    <div class="callout">
      <p><b>Score:</b> each finding adds points by severity (Critical $($script:RiskPoints.Critical), High $($script:RiskPoints.High), Medium $($script:RiskPoints.Medium), Low $($script:RiskPoints.Low); Information $($script:RiskPoints.Information)), with <b>diminishing returns for repeats of the same issue</b>: findings are grouped per issue (rule) and severity, and each group contributes points &times; &radic;count. So <b>a higher score is worse</b> and volume still raises it (28 permanent Global Admins score well above 8), but one systemic issue repeated across many objects cannot drown out every other signal, while distinct issues each add their own weight. Low/Medium incomplete-evidence findings can contribute operational blind-spot risk to the score, but they are not proof of an adverse tenant fact. The score is unbounded. The current score is <b>$($Score.Score)</b> (<b>$($Score.Band)</b>).</p>
      <div class="matrix-wrap"><br>
        <table class="matrix"><thead><tr><th>Band</th><th>Score range</th><th>Interpretation</th></tr></thead><tbody>$($matrixRows -join "`n")</tbody></table>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>Findings by category</h2>
    <table><thead><tr><th style="text-align:left">Category</th><th style="text-align:center">Critical</th><th style="text-align:center">High</th><th style="text-align:center">Medium</th><th style="text-align:center">Low</th><th style="text-align:center">Total</th></tr></thead><tbody>$($catRows -join "`n")</tbody></table>
    <div style="margin-top:6px"><small>Information-level findings carry no points and are excluded from this table.</small></div>
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

  <div class="footer">Generated by $($script:Version) &mdash; read-only Microsoft Graph and optional Azure Resource Manager audit. This score is an index based on the findings in this report; validate scope and license coverage (gated checks may be skipped or incomplete).</div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Write-PostureSummaryReport {
    param([string]$Path, [string]$TenantName, [string]$GeneratedOn, [hashtable]$Stats)

    $statusRows = foreach ($k in $script:CheckStatus.Keys) {
        $s = $script:CheckStatus[$k]
        $cls = switch -Regex ($s.Status) { '^Pass' {'ok'} '^InfoOnly' {'info'} '^RiskFindings' {'find'} '^Incomplete' {'skip'} '^Skipped' {'skip'} '^Error' {'err'} default {'skip'} }
        "<tr><td class='mono'>$(HtmlEncode $k)</td><td>$(HtmlEncode $s.Title)</td><td><span class='pill $cls'>$(HtmlEncode $s.Status)</span></td></tr>"
    }
    # "Clean" excludes every skipped, errored or incomplete check. Incomplete can overlap
    # with risk findings when a check found a problem but could not read every data source.
    $pass = @($script:CheckStatus.Values | Where-Object { $_.Status -eq 'Pass' -or $_.Status -like 'InfoOnly*' }).Count
    $withFindings = @($script:CheckStatus.Values | Where-Object { $_.Status -like 'RiskFindings*' }).Count
    $incomplete = @($script:CheckStatus.Values | Where-Object { $_.Status -like '*Incomplete*' }).Count
    $skipped = @($script:CheckStatus.Values | Where-Object { $_.Status -like 'Skipped*' }).Count
    $errored = @($script:CheckStatus.Values | Where-Object { $_.Status -eq 'Error' }).Count

    $css = Get-EntraRiskCss
    $nav = Get-EntraPrimaryNav 'posture'
    $js  = Get-EntraRiskJs2

    $licNote = @()
    if (-not $script:LicenseKnown) { $licNote += 'License detection FAILED (the subscribed-SKU read errored) - the tenant may hold P1/P2; gated checks were skipped as license-unknown, not because the license is absent.' }
    if (-not $script:HasP2) { $licNote += ("Entra ID P2 not {0} - PIM eligibility, Identity Protection (risky users) and risk-based checks may be license-gated." -f ($(if ($script:LicenseKnown) { 'detected' } else { 'confirmed (detection failed)' }))) }
    if (-not $script:HasP1) { $licNote += ("Entra ID P1 not {0} - sign-in activity (stale users / legacy auth) may be unavailable." -f ($(if ($script:LicenseKnown) { 'detected' } else { 'confirmed (detection failed)' }))) }
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
      <div class="card span-3"><div class="k">Checks clean</div><div class="v">$pass</div><div class="s">Fully evaluated; no risk findings</div></div>
      <div class="card span-3"><div class="k">With risk findings</div><div class="v">$withFindings</div><div class="s">Action needed</div></div>
      <div class="card span-3"><div class="k">Skipped</div><div class="v">$skipped</div><div class="s">No scope / license</div></div>
      <div class="card span-3"><div class="k">Errored</div><div class="v">$errored</div><div class="s">See console</div></div>
      <div class="card span-3"><div class="k">Incomplete</div><div class="v">$incomplete</div><div class="s">Coverage gaps (may overlap risk)</div></div>
      <div class="card span-3"><div class="k">Users</div><div class="v">$($Stats.Users)</div><div class="s">Members + guests</div></div>
      <div class="card span-3"><div class="k">Guests</div><div class="v">$($Stats.Guests)</div><div class="s">External</div></div>
      <div class="card span-3"><div class="k">Applications</div><div class="v">$($Stats.Apps)</div><div class="s">App registrations</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Licensing &amp; coverage</h2>
    <div class="callout">$licHtml<p style="margin-top:8px"><small>Skipped, errored and incomplete checks are coverage gaps, not clean results. A risk-bearing check can also be incomplete when another required data source was unavailable.</small></p></div>
  </div>

  <div class="section">
    <h2>Checks performed</h2>
    <table><thead><tr><th style="text-align:left">Check</th><th style="text-align:left">Title</th><th style="text-align:left">Status</th></tr></thead><tbody>$($statusRows -join "`n")</tbody></table>
  </div>

  <div class="footer">Generated by $($script:Version) &mdash; read-only Microsoft Graph and optional Azure Resource Manager audit.</div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Write-RawDataIndexReport {
    param([string]$Path, [string]$TenantName, [string]$GeneratedOn)
    $css = Get-EntraMainCss
    $nav = Get-EntraPrimaryNav 'raw'
    $js  = Get-EntraRawJs
    $rows = foreach ($d in $script:RawDatasets) {
        "<tr><td>$(HtmlEncode $d.Title)</td><td class='mono'>$(HtmlEncode $d.BaseName)</td><td style='text-align:right'>$($d.Rows)</td><td><a href='$(HtmlAttrEncode $d.HtmlHref)'>HTML</a> &middot; <a href='$(HtmlAttrEncode $d.CsvHref)' download>CSV</a> &middot; <a href='$(HtmlAttrEncode $d.TxtHref)' download>TXT</a></td></tr>"
    }
    # NB: use .Count directly - on PowerShell 7.6.x, wrapping a generic List in @() throws
    # "Argument types do not match" (@($genericList) regression). $list.Count is always safe.
    $total = $script:RawDatasets.Count
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
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
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
    'riskyusers'       = @{ Func='Invoke-Check-RiskyUsersOnly'; Title='Identity Protection (Risky Users)';      Scopes=@('IdentityRiskyUser.Read.All'); P2=$true }
    'riskyserviceprincipals' = @{ Func='Invoke-Check-RiskyServicePrincipals'; Title='Identity Protection (Risky Service Principals)'; Scopes=@('IdentityRiskyServicePrincipal.Read.All') }
    'apps'             = @{ Func='Invoke-Check-Apps';           Title='App / Service Principal Hygiene';        Scopes=@('Application.Read.All') }
    'appcredentials'   = @{ Func='Invoke-Check-AppCredentials'; Title='App Registration Credential Expiry';     Scopes=@('Application.Read.All') }
    'consentgrants'    = @{ Func='Invoke-Check-ConsentGrants';  Title='OAuth2 Consent Grants';                  Scopes=@('Directory.Read.All') }
    'devices'          = @{ Func='Invoke-Check-Devices';        Title='Stale / Unmanaged Devices';              Scopes=@('Device.Read.All') }
    'trusts'           = @{ Func='Invoke-Check-Trusts';         Title='Cross-Tenant Access & B2B Trust';        Scopes=@('Policy.Read.All') }
    'recentchanges'    = @{ Func='Invoke-Check-RecentChanges';  Title='Recently Created Users / Groups';        Scopes=@('User.Read.All','AuditLog.Read.All') }
    'tenanthealth'     = @{ Func='Invoke-Check-TenantHealth';   Title='Directory-Sync / PHS Health';            Scopes=@('Organization.Read.All','OnPremDirectorySynchronization.Read.All') }
    'pimpolicies'      = @{ Func='Invoke-Check-PimPolicies';    Title='PIM Role-Management Policy Quality';     Scopes=@('RoleManagementPolicy.Read.Directory'); P2=$true }
    'breakglass'       = @{ Func='Invoke-Check-BreakGlass';     Title='Emergency-Access (Break-Glass) Health';  Scopes=@('User.Read.All','RoleManagement.Read.Directory') }
    'authmethodpolicy' = @{ Func='Invoke-Check-AuthMethodPolicy'; Title='Authentication Methods Policy';        Scopes=@('Policy.Read.All') }
    'accesspaths'      = @{ Func='Invoke-Check-AccessPaths';    Title='Effective Access / Attack Paths';        Scopes=@('RoleManagement.Read.Directory','Group.Read.All') }
    'staleapps'        = @{ Func='Invoke-Check-StaleApps';      Title='Stale / Unused Applications';            Scopes=@('Application.Read.All','AuditLog.Read.All'); P1=$true }
    'recommendations'  = @{ Func='Invoke-Check-EntraRecommendations'; Title='Microsoft Entra Recommendations';  Scopes=@('DirectoryRecommendations.Read.All') }
    'securescore'      = @{ Func='Invoke-Check-SecureScore';    Title='Microsoft Identity Secure Score';         Scopes=@('SecurityEvents.Read.All') }
    'accessreviews'    = @{ Func='Invoke-Check-AccessReviews';  Title='Access Review Governance';                Scopes=@('AccessReview.Read.All') }
    # Composite checks intentionally self-gate their optional data sources and emit
    # explicit coverage findings. Requiring every scope here would skip useful partial
    # evidence and hide which individual governance source was unavailable.
    'identitygovernance' = @{ Func='Invoke-Check-IdentityGovernance'; Title='Identity Governance Controls';      Scopes=@() }
    'authrecovery'     = @{ Func='Invoke-Check-AuthRecovery';   Title='Authentication Recovery Readiness';       Scopes=@() }
    'groupgovernance'  = @{ Func='Invoke-Check-GroupGovernance'; Title='Group Governance';                       Scopes=@('Group.Read.All') }
    'externaldelegation' = @{ Func='Invoke-Check-ExternalDelegation'; Title='External Delegation & Partner Trust'; Scopes=@() }
    'federationhealth' = @{ Func='Invoke-Check-FederationHealth'; Title='Federation & Hybrid Authentication Health'; Scopes=@('Domain.Read.All') }
    'workloadcredentials' = @{ Func='Invoke-Check-WorkloadCredentials'; Title='Workload Identity Credentials';  Scopes=@('Application.Read.All') }
    'enterpriseapps'   = @{ Func='Invoke-Check-EnterpriseAppGovernance'; Title='Enterprise Application Governance'; Scopes=@('Application.Read.All') }
    'monitoring'       = @{ Func='Invoke-Check-Monitoring';     Title='Identity Monitoring & Alert Coverage';     Scopes=@('AuditLog.Read.All') }
    'changemonitoring' = @{ Func='Invoke-Check-ChangeMonitoring'; Title='Security-Sensitive Change Monitoring'; Scopes=@('AuditLog.Read.All') }
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
        'tenantposture'=$tenantposture; 'capolicies'=$capolicies; 'riskyusers'=$riskyusers;
        'riskyserviceprincipals'=$riskyserviceprincipals; 'apps'=$apps; 'appcredentials'=$appcredentials;
        'consentgrants'=$consentgrants; 'devices'=$devices; 'trusts'=$trusts; 'recentchanges'=$recentchanges;
        'tenanthealth'=$tenanthealth; 'pimpolicies'=$pimpolicies; 'breakglass'=$breakglass;
        'authmethodpolicy'=$authmethodpolicy; 'accesspaths'=$accesspaths; 'staleapps'=$staleapps;
        'recommendations'=$recommendations; 'securescore'=$securescore; 'accessreviews'=$accessreviews;
        'identitygovernance'=$identitygovernance; 'authrecovery'=$authrecovery; 'groupgovernance'=$groupgovernance;
        'externaldelegation'=$externaldelegation; 'federationhealth'=$federationhealth;
        'workloadcredentials'=$workloadcredentials; 'enterpriseapps'=$enterpriseapps;
        'monitoring'=$monitoring; 'changemonitoring'=$changemonitoring
    }
    $anySelected = $all -or ($select -and $select.Count) -or (@($individual.Values | Where-Object { $_ }).Count -gt 0)

    if ($installdeps) {
        Add-EAOfflineModulesPath   # so an offline -ModulesPath is honored by the install too
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
    # A FAILED read must not masquerade as 'no license': track it so gated checks are
    # reported as 'license unknown' instead of a false 'Skipped-NoLicense'.
    try {
        foreach ($sku in @(Get-MgSubscribedSku -All -ErrorAction Stop)) {
            $enabledPlans = @($sku.ServicePlans | Where-Object { $_.ProvisioningStatus -eq 'Success' } | ForEach-Object { $_.ServicePlanName })
            if ($sku.SkuPartNumber -eq 'AAD_PREMIUM_P2' -or $enabledPlans -contains 'AAD_PREMIUM_P2') { $script:HasP2 = $true }
            if ($sku.SkuPartNumber -eq 'AAD_PREMIUM'    -or $enabledPlans -contains 'AAD_PREMIUM')    { $script:HasP1 = $true }
            if ($enabledPlans -match 'WorkloadIdentit') { $script:WorkloadIdP = $true }
        }
        if ($script:HasP2) { $script:HasP1 = $true }
    } catch {
        $script:LicenseKnown = $false
        Write-Warn2 "License (SKU) detection failed: $($_.Exception.Message) - license-gated checks will be reported as 'license unknown', not 'no license'."
    }

    $tenantName = if ($script:Tenant -and $script:Tenant.DisplayName) { $script:Tenant.DisplayName } else { [string]$ctx.TenantId }
    Write-Good ("Tenant: {0} | Licensing P1={1} P2={2}" -f $tenantName, $script:HasP1, $script:HasP2)

    # Output folders (mirrors the AD audit layout)
    $safeTenant = ((($tenantName -replace '[^\w\.\- ]','_')).Trim()) -replace '\s+','_'
    if ([string]::IsNullOrWhiteSpace($safeTenant)) { $safeTenant = 'tenant' }
    $ts = Get-Date -Format 'yyyyMMdd-HHmm'
    $root = if ($OutputRoot) { $OutputRoot } else { $PSScriptRoot }
    $script:RunRoot = Join-Path $root ("{0}-EntraAudit-{1}" -f $safeTenant, $ts)
    $script:HtmlDir = Join-Path $script:RunRoot 'HTML Reports'
    $script:RawDir  = Join-Path $script:RunRoot 'Raw Data' 'Source'   # segment-wise: '\' is a literal filename char on non-Windows pwsh
    # Fail fast: if the output folders cannot be created, every later write fails too -
    # do not run the whole audit only to print 'Audit complete' over a missing report.
    New-Item -ItemType Directory -Force -Path $script:HtmlDir -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Force -Path $script:RawDir  -ErrorAction Stop | Out-Null

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
    # Get-EntraRiskScore normalizes and counts every severity in one pass - reuse its
    # counts so the report cards and the score can never disagree.
    $score = Get-EntraRiskScore $script:Findings
    $counts = @{ Critical=$score.Critical; High=$score.High; Medium=$score.Medium; Low=$score.Low; Information=$score.Information }
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'

    $stats = @{
        Users  = if ($script:UsersCache) { $script:UsersCache.Count } else { '-' }
        Guests = if ($script:UsersCache) { @($script:UsersCache | Where-Object { $_.UserType -eq 'Guest' }).Count } else { '-' }
        Apps   = $script:AppCount
    }
    $subtitle = ("Read-only Microsoft Graph and optional Azure Resource Manager audit &mdash; {0} check(s) | overall risk: {1} (score {2}, higher = worse)" -f $toRun.Count, $score.Band, $score.Score)

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
            FindingId         = (New-FindingKey -TenantId $tenantId -Finding $f)
            Severity          = $f.Severity
            Category          = $f.Category
            CheckId           = $f.CheckId
            RuleId            = $f.RuleId
            ObjectType        = $f.ObjectType
            ObjectId          = $f.ObjectId
            Title             = $f.Title
            AffectedPrincipal = $f.AffectedPrincipal
            Evidence          = $f.Evidence
            WhyItMatters      = $f.WhyItMatters
            RecommendedAction = $f.RecommendedAction
            SourceFile        = $f.SourceFile
            CoverageGap       = [bool](Test-EntraCoverageGap $f)
        }
    }
    try {
        # utf8BOM so Excel decodes non-ASCII display names / UPNs correctly; -InputObject
        # keeps Findings.json a JSON ARRAY even when the run produced exactly one finding.
        ConvertTo-SafeCsvRows $exportRows | Export-Csv -LiteralPath (Join-Path $script:RunRoot 'Findings.csv') -NoTypeInformation -Encoding utf8BOM
        ConvertTo-Json -InputObject @($exportRows) -Depth 5 | Set-Content -LiteralPath (Join-Path $script:RunRoot 'Findings.json') -Encoding UTF8
    } catch { Write-Warn2 "Could not write Findings.json/csv: $($_.Exception.Message)" }

    # Summary
    Write-Host ""
    Write-Good "Audit complete."
    Write-Host ("  Overall risk : {0} (score {1}, higher = worse)" -f $score.Band, $score.Score) -ForegroundColor White
    Write-Host ("  Findings     : Critical={0} High={1} Medium={2} Low={3} Info={4}" -f $counts.Critical,$counts.High,$counts.Medium,$counts.Low,$counts.Information)
    Write-Host ("  Reports      : {0}" -f $script:HtmlDir)
    Write-Host ("  Raw evidence : {0}" -f $script:RawDir)
    Write-Warn2 "Reports contain sensitive identity/security data (users, admins, apps, sign-in & risk signals). Store the output in a restricted folder and avoid sharing the raw CSV/JSON broadly."

    if (-not $NoLaunch) {
        try { Invoke-Item $resultsPath -ErrorAction SilentlyContinue } catch {}
    }
}

# ===========================================================================
# Entry point
# ===========================================================================
$script:AuditFailed = $false
try {
    # Keep the large check families in definition-only companion libraries. Loading
    # occurs inside the guarded entry point so a missing/mismatched package fails with
    # a clear audit error before any tenant connection or check execution begins.
    foreach ($libraryName in @('EntraAudit-Checks-Governance.ps1','EntraAudit-Checks-Applications.ps1')) {
        $libraryPath = Join-Path $PSScriptRoot $libraryName
        if (-not (Test-Path -LiteralPath $libraryPath -PathType Leaf)) {
            throw "Required check library is missing: $libraryPath. Keep all EntraAudit scripts together."
        }
        . $libraryPath
    }
    Invoke-EntraAudit
} catch {
    Write-Err2 "Audit failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    $script:AuditFailed = $true
} finally {
    # Only tear down a session this script created - never a pre-existing one the
    # operator connected themselves before running the audit.
    try {
        if ($script:GraphConnectedByScript -and (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
            if (Get-MgContext) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null; Write-Info "Disconnected from Microsoft Graph." }
        }
    } catch {}
}
if ($script:AuditFailed) { exit 1 }




