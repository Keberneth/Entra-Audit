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
                               By default this uses Microsoft's shared "Microsoft Graph
                               Command Line Tools" app; -DelegatedClientId <appId> (with
                               -TenantId) signs in through your own read-only app
                               registration instead.
    - App-only (certificate) : unattended runs via a dedicated read-only app
                               registration (-ClientId / -TenantId / -CertificateThumbprint).

  The run stops before any check if the sign-in holds a permission that is not clearly
  read-only (delegated: every consented scope must be a Read / ReadBasic scope or a
  sign-in scope such as openid; app-only: every application permission must be on the
  documented audit allowlist).

  Output (mirrors the AD audit layout):
    <TenantName>-EntraAudit-<yyyyMMdd-HHmmss>\      (a -2, -3 ... suffix is added if it exists)
      HTML Reports\     EntraAudit-Results.html, Risk-Report.html, Posture-Summary.html,
                        Raw-Data.html
      Raw Data\Source\  one or more datasets per check, each as .html + .csv + .txt
      Findings.json / Findings.csv   all findings with stable ids (automation / trend)
      EntraAudit-Run.log             everything the run printed (warnings, errors, skips)

  Exit code: 1 when the run fails (sign-in refused, unknown -select id, nothing selected,
  run folder not writable, or an unexpected error); 0 otherwise. Individual checks that
  were skipped or stopped with an error do not fail the run - they are listed with the
  reason in Posture-Summary.html and in the run log.

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
  .\EntraAudit-PS7.ps1 -select privileged-roles,capolicies -OutputRoot D:\Audits
  Run two checks by id and write the run folder under D:\Audits. An unknown -select id
  stops the run with exit code 1 (so a typo in a scheduled task cannot pass silently).

.EXAMPLE
  .\EntraAudit-PS7.ps1 -all -TenantId contoso.onmicrosoft.com -DelegatedClientId <appid>
  Interactive sign-in through your own read-only app registration (public client,
  redirect URI http://localhost) instead of the shared Graph Command Line Tools app.
  -TenantId is required with -DelegatedClientId: app registrations are single-tenant by
  default, and Microsoft refuses a single-tenant app on the shared sign-in endpoint.

.EXAMPLE
  .\EntraAudit-PS7.ps1 -all -NoLaunch -TenantId contoso.onmicrosoft.com -ClientId <appid> -CertificateThumbprint <thumb>
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
    # Interactive (delegated) sign-in through your OWN read-only app registration (public
    # client, redirect URI http://localhost) instead of the shared "Microsoft Graph Command
    # Line Tools" app, whose consented permissions accumulate across everything the admin
    # ever ran with it. Requires -TenantId (app registrations are single-tenant by default).
    # Not combinable with -ClientId / -CertificateThumbprint.
    [string]$DelegatedClientId,

    # ---- Tuning ----
    [string]$OutputRoot,
    [string[]]$BreakGlassUpns,
    [ValidateRange(1, 3650)][int]$InactiveDays = 90,
    [ValidateRange(1, 3650)][int]$ExpiringCredentialDays = 30,
    [ValidateRange(1, 3650)][int]$RecentChangeDays = 30,
    [ValidateRange(1, 3650)][int]$StaleAppDays = 90,
    [string]$ModulesPath,       # offline: folder containing Save-Module output
    [switch]$NoLaunch           # do not open the report when finished (auto-open is also skipped in non-interactive sessions)
)

$ErrorActionPreference = 'Continue'
$script:Version = 'EntraAudit-PS7 v2.0'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7 (pwsh.exe). Current version: $($PSVersionTable.PSVersion)"
    exit 1
}
# A pasted application id with stray spaces must not fail the GUID check at sign-in.
if ($DelegatedClientId) { $DelegatedClientId = $DelegatedClientId.Trim() }

# ===========================================================================
# Read-only Graph scopes (delegated). The script NEVER requests a write scope.
# ===========================================================================
$script:ScopesRO = @(
    'Directory.Read.All'
    'AuditLog.Read.All'
    'Policy.Read.All'
    # RoleManagement.Read.Directory also covers the PIM roleAssignment/roleEligibility
    # schedule-instance reads, so the narrower RoleEligibilitySchedule.Read.Directory /
    # RoleAssignmentSchedule.Read.Directory scopes are no longer requested (nothing gated on
    # them). They stay accepted in the app-only allowlist below for older app registrations.
    'RoleManagement.Read.Directory'
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
    # Microsoft.Graph.DirectoryObjects is intentionally NOT required: none of the audit
    # scripts call a cmdlet from it, so it only made offline installs larger.
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
$script:TenantReadError = $null            # message when the organization read failed (tenant name unknown)
$script:RolePrivilegedMetadataError = $null
$script:LicenseSkus  = @()                 # per-SKU detail from license detection (see Invoke-EntraAudit)
$script:LicenseNotes = @()                 # plain-language notes, e.g. a P2 SKU present but suspended
# Run context for the reports and the machine-readable export. Invoke-EntraAudit fills it;
# report writers must tolerate a missing or partial RunInfo (e.g. offline rendering).
$script:RunInfo = [ordered]@{ ToolVersion = $script:Version }
# Run log: every Write-Info/Good/Warn2/Err2 line is also kept here so the messages printed
# before the run folder exists can be written into EntraAudit-Run.log (the transcript
# started in Invoke-EntraAudit captures everything after that point).
$script:RunLog = New-Object System.Collections.Generic.List[string]
$script:RunLogWritten = 0                  # RunLog lines already written to the log file
$script:EAPageSizeRejected = @{}           # list cmdlets that refused -PageSize and worked without it (see Invoke-EAListAll)
$script:LogPath = $null
$script:TranscriptStarted = $false

# ===========================================================================
# Small helpers
# ===========================================================================
function Add-EARunLog {
    param([string]$Level, [string]$Message)
    if ($null -ne $script:RunLog) { $script:RunLog.Add(('{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message)) }
}
function Write-Info  { param([string]$m) Add-EARunLog 'INFO' $m; Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Good  { param([string]$m) Add-EARunLog 'OK' $m;   Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Add-EARunLog 'WARN' $m; Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err2  { param([string]$m) Add-EARunLog 'ERROR' $m; Write-Host "[x] $m" -ForegroundColor Red }

# Run log (EntraAudit-Run.log in the run folder), so warnings, skips and errors survive
# when the run folder is zipped and handed to someone else. The messages printed before
# the folder existed (sign-in, license detection) are written first; a transcript then
# captures everything else the run prints. If the transcript cannot start, this script's
# own messages are still written when the run ends (Close-EARunLog). Returns the log
# path relative to the run folder, or $null when no log could be created.
function Open-EARunLog {
    param([Parameter(Mandatory)][string]$Folder)
    $path = Join-Path $Folder 'EntraAudit-Run.log'
    try {
        $head = @(
            ('{0} run log - started {1}' -f $script:Version, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'))
            ''
            'Messages printed before the run folder was created:'
        ) + $script:RunLog.ToArray() + @('')
        Set-Content -LiteralPath $path -Value $head -Encoding utf8 -ErrorAction Stop
        $script:LogPath = $path
        $script:RunLogWritten = $script:RunLog.Count
    } catch {
        Write-Warn2 "Could not create the run log '$path': $($_.Exception.Message)"
        return $null
    }
    try {
        Start-Transcript -LiteralPath $path -Append -UseMinimalHeader -ErrorAction Stop | Out-Null
        $script:TranscriptStarted = $true
    } catch {
        Write-Warn2 "Could not start the run transcript ($($_.Exception.Message)) - the run log will contain this script's own messages only."
    }
    return 'EntraAudit-Run.log'
}

# Finish the run log: stop the transcript, or (when it never started) append the buffered
# messages written since Open-EARunLog. Safe to call when no log was opened.
function Close-EARunLog {
    if ($script:TranscriptStarted) {
        $script:TranscriptStarted = $false
        try { Stop-Transcript -ErrorAction Stop | Out-Null }
        catch { Write-Warn2 "Could not stop the run transcript: $($_.Exception.Message)" }
        return
    }
    if (-not $script:LogPath) { return }
    $unwritten = @($script:RunLog | Select-Object -Skip $script:RunLogWritten)
    if ($unwritten.Count -eq 0) { return }
    try {
        Add-Content -LiteralPath $script:LogPath -Value $unwritten -Encoding utf8 -ErrorAction Stop
        $script:RunLogWritten = $script:RunLog.Count
    } catch { Write-Warn2 "Could not write the run log '$($script:LogPath)': $($_.Exception.Message)" }
}

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

# HTTP status of a failed Graph call (0 when the error carries no HTTP response).
function Get-EAHttpStatus {
    param($ErrorRecord)
    $code = 0
    try { $code = [int]$ErrorRecord.Exception.Response.StatusCode } catch { $code = 0 }
    return $code
}

# True when a failed Graph call was refused for lack of permission (401/403 or a Graph
# access-denied error code), as opposed to a transient, throttling or query error. The
# Graph SDK puts the service error code in FullyQualifiedErrorId and Invoke-MgGraphRequest
# puts the JSON body in ErrorDetails, so all three texts are inspected.
function Test-EAAccessDenied {
    param($ErrorRecord)
    if (-not $ErrorRecord) { return $false }
    if ((Get-EAHttpStatus $ErrorRecord) -in 401, 403) { return $true }
    $details = if ($ErrorRecord.ErrorDetails) { [string]$ErrorRecord.ErrorDetails.Message } else { '' }
    $text = '{0} {1} {2}' -f [string]$ErrorRecord.Exception.Message, $details, [string]$ErrorRecord.FullyQualifiedErrorId
    return ($text -match '(?i)Authorization_RequestDenied|Insufficient privileges|does not have the required|Forbidden|Unauthorized')
}

# True when a failed list call looks like a refusal of the requested page size itself
# (HTTP 400 / BadRequest, an unsupported-query or $top error, or a cmdlet without a
# -PageSize parameter) - as opposed to a deleted object (404), throttling (429 after the
# SDK's own retries), a service error (5xx) or a permission problem, which a smaller page
# would not fix. The error text is only consulted when no HTTP status is available.
function Test-EAPageSizeRejection {
    param($ErrorRecord)
    if (-not $ErrorRecord) { return $false }
    if (Test-EAAccessDenied $ErrorRecord) { return $false }
    $status = Get-EAHttpStatus $ErrorRecord
    if ($status -eq 400) { return $true }
    if ($status -gt 0) { return $false }
    $details = if ($ErrorRecord.ErrorDetails) { [string]$ErrorRecord.ErrorDetails.Message } else { '' }
    $text = '{0} {1} {2}' -f [string]$ErrorRecord.Exception.Message, $details, [string]$ErrorRecord.FullyQualifiedErrorId
    return ($text -match '(?i)\$top|Top query|PageSize|page size|Request_UnsupportedQuery|\bBadRequest\b')
}

# Run a Graph SDK list cmdlet with -All and a large page size. Without -PageSize the SDK
# pages at the service default (usually 100 items), so a 50k-user directory costs ~500
# sequential requests instead of ~51. Only when the paged call is refused in a way that
# points at the page size (Test-EAPageSizeRejection) is it retried ONCE without -PageSize;
# if that retry works, the command keeps the default page size for the rest of the run.
# Every other error (access denied, a deleted object, throttling, a service error) is
# passed straight to the caller - one transient failure must not switch large pages off
# for the whole run. When the retry also fails, the retry's error is what callers see.
# Results are collected before being returned, so a failed first attempt can never leak
# duplicate items into the caller's pipeline.
function Invoke-EAListAll {
    param(
        [Parameter(Mandatory)][string]$Command,
        [hashtable]$Parameters = @{},
        [int]$PageSize = 999
    )
    $p = @{}
    foreach ($k in $Parameters.Keys) { $p[$k] = $Parameters[$k] }
    $p['All'] = $true
    $p['ErrorAction'] = 'Stop'
    if ($null -eq $script:EAPageSizeRejected) { $script:EAPageSizeRejected = @{} }
    if ($PageSize -gt 0 -and -not $script:EAPageSizeRejected.ContainsKey($Command)) {
        $paged = @{}
        foreach ($k in $p.Keys) { $paged[$k] = $p[$k] }
        $paged['PageSize'] = $PageSize
        try {
            $items = @(& $Command @paged)
            return $items
        } catch {
            if (-not (Test-EAPageSizeRejection $_)) { throw }
            $firstError = $_.Exception.Message
        }
        Write-Warn2 "  $Command failed with a query error at page size $PageSize ($firstError) - retrying once with the default page size, in case the large page caused it."
        $items = @(& $Command @p)
        # The default page size worked, so the page size was the problem: remember it, so a
        # per-object call (e.g. one per user) does not pay twice every time.
        $script:EAPageSizeRejected[$Command] = $true
        Write-Info "  $Command worked with the default page size, which is used for this command for the rest of the run."
        return $items
    }
    $items = @(& $Command @p)
    return $items
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
    param(
        [string[]]$Values,
        [string]$ParameterName = '-select',
        # Fail closed (throw) on any unknown id: used for -select, where a typo in a scheduled
        # task would otherwise run nothing (or less than intended) and still exit 0.
        [switch]$FailOnUnknown
    )
    $out = @(); $unknown = @()
    foreach ($raw in (Normalize-StringList -Values $Values)) {
        if ($script:Registry.Contains($raw)) { $out += $raw; continue }
        if ($script:CheckAliases.ContainsKey($raw)) { $out += $script:CheckAliases[$raw]; continue }
        $unknown += $raw
    }
    if ($unknown.Count -gt 0) {
        $valid = @($script:Registry.Keys) -join ', '
        if ($FailOnUnknown) {
            throw ("Unknown check id(s) in {0}: {1}. Nothing was run. Valid ids: {2} (switch-style names such as privroles also work)." -f $ParameterName, ($unknown -join ', '), $valid)
        }
        Write-Warn2 ("Unknown check id(s) in {0} ignored: {1}. Valid ids: {2}" -f $ParameterName, ($unknown -join ', '), $valid)
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
        foreach ($m in @(Invoke-EAListAll -Command 'Get-MgUserTransitiveMemberOf' -Parameters @{ UserId = $UserId })) {
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
        # 'ModernClients': browser + mobileAppsAndDesktopClients is equivalent to 'all' for an
        # MFA/strength grant, because legacy clients cannot satisfy that grant anyway.
        $modernComplete = ('ModernClients' -in $Ignore) -and ($clients -contains 'browser') -and ($clients -contains 'mobileAppsAndDesktopClients')
        if ($clients.Count -gt 0 -and $clients -notcontains 'all' -and -not $modernComplete) { return $true }
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
    # the PIM schedule-instance reads), but accepted so an app provisioned from an older
    # version of the delegated scope list does not fail closed. Both are *.Read.Directory -
    # the read-only guarantee is unchanged.
    'RoleEligibilitySchedule.Read.Directory','RoleAssignmentSchedule.Read.Directory'
)
function Test-AppRoleIsApprovedForAudit {
    param([Parameter(Mandatory)][string]$Value)
    return ($script:ApprovedAppOnlyPermissions -contains $Value)
}

# Write/action tokens that must never appear in a granted permission. Used as a second
# filter in both modes. Word-boundary-free where fused forms exist (User.DeleteRestore.All,
# User.ManageIdentities.All); deliberately NOT bare 'Manage' (substring of the legitimate
# read scope RoleManagement.Read.Directory).
$script:WriteScopePattern = '(?i)(ReadWrite|\.Write\b|\.Send\b|\.Create\b|\.Delete|\.Update\b|\.Invite\b|\.Manage|PrivilegedOperations|ManageAsApp|AccessAsUser|FullControl|full_access|Impersonation|\.EnableDisableAccount\b|\.RevokeSessions\b|\.Command\b|\.Export\b|\.Selected$|\.Restore\b|\.Assign|\.Migrate|\.Submit|\.Execute|\.Invoke|\.Remove|\.Reset|\.Approve)'

# Delegated read-only gate (fail closed). A delegated scope is accepted only when it is
# RECOGNISABLY read-only - one of its dot-separated segments is exactly Read / ReadBasic /
# ReadFor<User|Team|Chat> (Directory.Read.All, Member.Read.Hidden,
# CrossTenantInformation.ReadBasic.All, Domain-InternalFederation.Read.All ...) - and it
# carries no write/action token - or it is one of the OpenID Connect sign-in scopes.
# Anything else (User.DeleteRestore.All, User.EnableDisableAccount.All, Sites.Selected,
# Device.Command, Directory.AccessAsUser.All, unknown shapes) is refused, because a deny
# list can never enumerate every current and future write-capable permission.
function Test-EAReadOnlyScope {
    param([string]$Scope)
    $s = ([string]$Scope).Trim()
    if (-not $s) { return $false }
    if ($s -in @('openid','profile','email','offline_access')) { return $true }
    if ($s -match $script:WriteScopePattern) { return $false }
    $readSegments = @($s -split '\.' | Where-Object { $_ -match '^(?i)(Read|ReadBasic|ReadFor(User|Team|Chat))$' })
    return ($readSegments.Count -gt 0)
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
        [switch]$CoverageGap,
        # Optional Microsoft Learn link for the control; reports render it as a clickable link.
        [string]$DocumentationUrl
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
        DocumentationUrl  = $DocumentationUrl
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
# Each file is written separately with -ErrorAction Stop, so a failed write can never
# hide behind a working-looking link: the failure is warned about, recorded on the
# dataset entry (Errors) and shown on the Raw Data index. When only the HTML page fails,
# the CSV href is returned instead, so findings still point at evidence that exists.
# The entry also records WHICH check produced the dataset (CheckId), its notes, and
# whether it is empty, so the Raw Data index / Posture Summary / Findings.json can link
# datasets, checks and findings together.
function Write-Evidence {
    param(
        [string]$BaseName,          # e.g. 'privileged_roles'
        [object[]]$Rows,
        [string]$Title,
        [string[]]$Notes
    )
    $rel = $null
    $errors = New-Object System.Collections.Generic.List[string]
    try {
        $csvPath  = Join-Path $script:RawDir ($BaseName + '.csv')
        $txtPath  = Join-Path $script:RawDir ($BaseName + '.txt')
        $htmlPath = Join-Path $script:RawDir ($BaseName + '.html')
        # A $null argument must count as zero rows (@($null).Count is 1), and null
        # entries inside the array are not rows.
        $rowArr = if ($null -eq $Rows) { @() } else { @($Rows.Where({ $null -ne $_ })) }
        $count = $rowArr.Count
        $noteList = @($Notes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $checkId = Get-EntraEvidenceCheckId
        $checkTitle = if ($checkId -and $script:Registry -and $script:Registry.Contains($checkId)) { [string]$script:Registry[$checkId].Title } else { $null }

        $header = @($Title, ('Generated: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')))
        if ($checkId) { $header += ('Produced by check: {0}{1}' -f $checkId, $(if ($checkTitle) { " ($checkTitle)" } else { '' })) }
        foreach ($n in $noteList) { $header += $n }
        $header += ('Rows: {0}' -f $count)

        $csvOk = $false; $txtOk = $false; $htmlOk = $false
        if ($count -gt 0) {
            # utf8BOM: Excel misdecodes BOM-less UTF-8 CSVs with non-ASCII names/UPNs
            try {
                ConvertTo-SafeCsvRows $rowArr | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8BOM -ErrorAction Stop
                $csvOk = $true
            } catch { $errors.Add("CSV file could not be written: $($_.Exception.Message)") | Out-Null }
            # Plain-text view. Format-Table | Out-String -Width N silently truncated values
            # and DROPPED trailing columns on wide rows; this keeps every column and value
            # (the union of all rows' properties) and switches to one block per row when
            # the table would be too wide to read as plain text.
            try {
                $txt = ConvertTo-EntraEvidenceText -Rows $rowArr
                $header += ('Columns: {0} ({1})' -f $txt.Columns.Count, ($txt.Columns -join ', '))
                if ($txt.Layout -eq 'List') { $header += 'Layout: one block per row, because the table is too wide for plain text. Nothing is truncated.' }
                $header += ''
                Set-Content -LiteralPath $txtPath -Value (($header -join "`r`n") + "`r`n" + $txt.Text) -Encoding UTF8 -ErrorAction Stop
                $txtOk = $true
            } catch { $errors.Add("TXT file could not be written: $($_.Exception.Message)") | Out-Null }
        } else {
            # Always write the CSV (even with no rows) so automation can rely on the file
            # existing and can distinguish "pass / no data" from "CSV generation failed".
            try {
                [pscustomobject]@{ Status = 'NoData'; Message = 'No rows returned for this check.' } | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8BOM -ErrorAction Stop
                $csvOk = $true
            } catch { $errors.Add("CSV file could not be written: $($_.Exception.Message)") | Out-Null }
            try {
                $header += ''
                $header += '(no matching objects)'
                Set-Content -LiteralPath $txtPath -Value ($header -join "`r`n") -Encoding UTF8 -ErrorAction Stop
                $txtOk = $true
            } catch { $errors.Add("TXT file could not be written: $($_.Exception.Message)") | Out-Null }
        }

        try {
            New-RawDataHtml -Path $htmlPath -Title $Title -Rows $rowArr -Notes $noteList -CsvName ($BaseName + '.csv') -TxtName ($BaseName + '.txt') `
                -CheckId $checkId -CheckTitle $checkTitle -CsvAvailable $csvOk -TxtAvailable $txtOk
            $htmlOk = $true
        } catch { $errors.Add("HTML page could not be written: $($_.Exception.Message)") | Out-Null }

        foreach ($e in $errors) { Write-Warn2 "Evidence '$BaseName': $e" }

        # Reports live in HTML Reports\, raw data in Raw Data\Source\
        $htmlHref = if ($htmlOk) { '../Raw Data/Source/' + $BaseName + '.html' } else { $null }
        $csvHref  = if ($csvOk)  { '../Raw Data/Source/' + $BaseName + '.csv' } else { $null }
        $txtHref  = if ($txtOk)  { '../Raw Data/Source/' + $BaseName + '.txt' } else { $null }
        $rel = if ($htmlHref) { $htmlHref } elseif ($csvHref) { $csvHref } else { $null }
        $script:RawDatasets.Add([pscustomobject]@{
            BaseName   = $BaseName; Title = $Title; Rows = $count; Empty = ($count -eq 0)
            CheckId    = $checkId; CheckTitle = $checkTitle
            Notes      = $noteList
            HtmlHref   = $htmlHref
            CsvHref    = $csvHref
            TxtHref    = $txtHref
            SourceHref = $rel          # the value findings carry as SourceFile
            Errors     = $errors.ToArray()
        }) | Out-Null
    } catch {
        Write-Warn2 "Could not write evidence '$BaseName': $($_.Exception.Message)"
    }
    return $rel
}

# Which check is writing this dataset? Invoke-AuditCheck publishes the running check
# id in $script:CurrentCheckId. When that is not set (a check function called directly,
# e.g. from a test harness) the call stack is searched for a registered check function
# or an Invoke-AuditCheck frame. $null when unknown - the dataset is then listed
# without a check link (and inherits one from the findings that cite it, if any).
function Get-EntraEvidenceCheckId {
    if ($script:CurrentCheckId) { return [string]$script:CurrentCheckId }
    try {
        $funcMap = @{}
        if ($script:Registry) {
            foreach ($k in $script:Registry.Keys) { $fn = [string]$script:Registry[$k].Func; if ($fn) { $funcMap[$fn] = [string]$k } }
        }
        foreach ($frame in @(Get-PSCallStack)) {
            $fname = [string]$frame.FunctionName
            if ($funcMap.ContainsKey($fname)) { return $funcMap[$fname] }
            if ($fname -eq 'Invoke-AuditCheck') {
                $bp = $frame.InvocationInfo.BoundParameters
                if ($bp -and $bp.ContainsKey('CheckId') -and $bp['CheckId']) { return [string]$bp['CheckId'] }
            }
        }
    } catch { Write-Verbose "Could not resolve the check that produced this dataset: $($_.Exception.Message)" }
    return $null
}

# One evidence cell as a single line of text: lists are joined (never shown as
# "{a, b, c...}"), dates use a sortable format, line breaks are flattened.
function ConvertTo-EntraEvidenceCell {
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = if ($Value -is [string]) { $Value }
         elseif ($Value -is [datetime]) { $Value.ToString('yyyy-MM-dd HH:mm:ss') }
         elseif ($Value -is [datetimeoffset]) { $Value.ToString('yyyy-MM-dd HH:mm:ss zzz') }
         elseif ($Value -is [System.Collections.IDictionary]) { (@(foreach ($k in $Value.Keys) { '{0}={1}' -f $k, $Value[$k] }) -join '; ') }
         elseif ($Value -is [System.Collections.IEnumerable]) { (@(foreach ($i in $Value) { if ($null -eq $i) { '' } else { [string]$i } }) -join ', ') }
         else { [string]$Value }
    if ($s.IndexOfAny([char[]]"`r`n`t") -ge 0) { $s = ($s -replace "\r\n|\r|\n", ' / ') -replace "\t", ' ' }
    return $s
}

# Plain-text rendering of an evidence dataset for the TXT file. Plain
# Format-Table | Out-String -Width 4096 silently truncated values and DROPPED trailing
# columns once a row was wider than 4096 characters, used only the FIRST row's
# properties as columns, and cut collections after 4 items ("{a, b, c, d...}"). Here:
#  - the columns are the union of every row's properties (-Property, wildcard-escaped);
#  - $FormatEnumerationLimit is lifted for the duration (the formatter only honours the
#    global value) and restored afterwards, so collections are printed in full;
#  - the output width is effectively unlimited and -Wrap keeps multi-line values;
#  - a table wider than -MaxTableWidth characters is written as a list (one block per
#    row) instead, which is equally complete but readable.
# Format-Table/Format-List are compiled cmdlets, so this stays fast on large datasets.
function ConvertTo-EntraEvidenceText {
    param([object[]]$Rows, [int]$MaxTableWidth = 1000)
    $cols = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        foreach ($n in $r.PSObject.Properties.Name) { if ($seen.Add($n)) { $cols.Add($n) } }
    }
    $colNames = $cols.ToArray()
    if ($colNames.Count -eq 0) { return [pscustomobject]@{ Text = ''; Columns = $colNames; Layout = 'Table' } }
    $props = @($colNames | ForEach-Object { [System.Management.Automation.WildcardPattern]::Escape($_) })
    $prevLimit = Get-Variable -Name FormatEnumerationLimit -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    # NB: typed value - a bare '-Value -1' binds the STRING '-1', which the formatter ignores.
    Set-Variable -Name FormatEnumerationLimit -Scope Global -Value ([int]-1)
    try {
        $layout = 'Table'
        $text = $Rows | Format-Table -Property $props -AutoSize -Wrap | Out-String -Width 100000
        $body = $text.TrimStart("`r", "`n")
        $nl = $body.IndexOf("`n")
        $header = if ($nl -ge 0) { $body.Substring(0, $nl) } else { $body }
        if ($header.TrimEnd().Length -gt $MaxTableWidth) {
            $layout = 'List'
            $text = $Rows | Format-List -Property $props | Out-String -Width 100000
        }
    } finally {
        Set-Variable -Name FormatEnumerationLimit -Scope Global -Value $(if ($null -ne $prevLimit) { $prevLimit } else { [int]4 })
    }
    [pscustomobject]@{ Text = $text; Columns = $colNames; Layout = $layout }
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
        if ($prevPolicy) {
            try { Set-PSRepository -Name PSGallery -InstallationPolicy $prevPolicy -ErrorAction Stop }
            catch { Write-Warn2 "Could not restore the PSGallery installation policy to '$prevPolicy' ($($_.Exception.Message)) - PSGallery is still Trusted; reset it with: Set-PSRepository -Name PSGallery -InstallationPolicy $prevPolicy" }
        }
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
        throw 'App-only authentication requires BOTH -ClientId and -CertificateThumbprint; only one was supplied. Provide both for unattended runs, or neither for interactive sign-in (use -DelegatedClientId to sign in interactively through your own app registration).'
    }
    if ($DelegatedClientId) {
        if ($ClientId -or $CertificateThumbprint) {
            throw 'Use EITHER -DelegatedClientId (interactive sign-in through your own read-only app) OR -ClientId with -CertificateThumbprint (unattended app-only), not both.'
        }
        $parsedClientId = [guid]::Empty
        if (-not [guid]::TryParse($DelegatedClientId, [ref]$parsedClientId)) {
            throw "-DelegatedClientId must be the Application (client) ID of your app registration - a GUID. Got: '$DelegatedClientId'."
        }
        # Without a tenant, Connect-MgGraph signs in on the shared multi-tenant endpoint, and
        # Microsoft refuses that for a single-tenant app (the default for a new registration)
        # with AADSTS50194 - and the device-code retry below fails the same way.
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            throw '-DelegatedClientId also needs -TenantId <your tenant ID or domain, e.g. contoso.onmicrosoft.com>, because app registrations are single-tenant by default and Microsoft refuses their sign-in without a tenant.'
        }
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
        $viaApp = if ($DelegatedClientId) { "app $DelegatedClientId" } else { "the shared 'Microsoft Graph Command Line Tools' app" }
        Write-Info "Connecting to Microsoft Graph (interactive, read-only scopes, via $viaApp)..."
        $cp = @{ Scopes = $script:ScopesRO; NoWelcome = $true }
        if ($TenantId)      { $cp.TenantId = $TenantId }
        if ($UseDeviceCode) { $cp.UseDeviceCode = $true }
        # Binding consent to a dedicated read-only app keeps the token free of write scopes
        # the admin once consented to the shared SDK app for unrelated work.
        if ($DelegatedClientId) { $cp.ClientId = $DelegatedClientId }
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

    # --- READ-ONLY SELF-CHECK: refuse to run unless every granted scope is read-only ---
    # Delegated: fail-closed allowlist (Test-EAReadOnlyScope) - a scope must be recognisably
    # read-only; a deny list missed real write-capable scopes (User.DeleteRestore.All,
    # User.EnableDisableAccount.All, User.RevokeSessions.All, Sites.Selected, Device.Command).
    # App-only: Get-MgContext.Scopes is sparse, so only the write-token filter runs here and
    # Assert-AppOnlyReadOnly below enforces the exact permission allowlist.
    $grantedScopes = @($ctx.Scopes | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    if ($appOnly) {
        $bad = @($grantedScopes | Where-Object { $_ -match $script:WriteScopePattern })
    } else {
        if ($grantedScopes.Count -eq 0) {
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { Write-Warn2 "Disconnect after the refused sign-in failed: $($_.Exception.Message)" }
            throw 'Refusing to run: the sign-in returned no permission (scope) list, so the read-only guarantee cannot be verified.'
        }
        $bad = @($grantedScopes | Where-Object { -not (Test-EAReadOnlyScope $_) })
    }
    if ($bad.Count -gt 0) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { Write-Warn2 "Disconnect after the refused sign-in failed: $($_.Exception.Message)" }
        if ($appOnly) {
            throw "Refusing to run: the audit app holds permission(s) that are not read-only -> $($bad -join ', '). Remove them from the app registration (Entra admin center > App registrations > <app> > API permissions) and run again."
        }
        $consentApp = if ($DelegatedClientId) { "your app registration $DelegatedClientId" } else { "the shared 'Microsoft Graph Command Line Tools' app" }
        $fix = if ($DelegatedClientId) {
            "Remove those permissions from that app (Entra admin center > App registrations > <app> > API permissions, and revoke any consent under Enterprise applications > <app> > Permissions), then run again."
        } else {
            "Either revoke them (Entra admin center > Enterprise applications > 'Microsoft Graph Command Line Tools' > Permissions, admin consent and user consent tabs), or register a dedicated read-only app (public client, redirect URI http://localhost, only the scopes in PREREQUISITE.md) and run with -DelegatedClientId <its application id>."
        }
        throw ("Refusing to run: this sign-in holds permission(s) that are not read-only -> {0}. This audit only runs with read-only permissions. Signing in again with fewer scopes does not help, because Microsoft Graph keeps every permission ever consented to {1}. {2}" -f ($bad -join ', '), $consentApp, $fix)
    }

    # App-only: Get-MgContext.Scopes is sparse, so the scope regex above is not a
    # reliable read-only guarantee. Inspect the running app's actual app-role assignments
    # across ALL resource APIs and FAIL CLOSED if any granted permission is write-capable.
    if ($appOnly) {
        try { Assert-AppOnlyReadOnly -ClientId $ClientId }
        catch {
            $refusal = $_
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { Write-Warn2 "Disconnect after the refused sign-in failed: $($_.Exception.Message)" }
            throw $refusal
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
    $assignments = @(Invoke-EAListAll -Command 'Get-MgServicePrincipalAppRoleAssignment' -Parameters @{ ServicePrincipalId = $self.Id })

    # An app with NO application permissions would pass the allowlist vacuously and then skip
    # nearly every check behind a green "verified" message. Refuse it with the real fix.
    if ($assignments.Count -eq 0) {
        throw ("Refusing app-only run: the audit app '{0}' ({1}) has NO Microsoft Graph application permissions granted, so almost every check would be skipped. Grant the documented read-only application permissions (PREREQUISITE.md, section A.2) to the app registration and admin-consent them, then run again." -f $self.DisplayName, $ClientId)
    }

    # Resolve only the resource service principals actually referenced by the assignments.
    $roleMapByResourceId = @{}
    $resourceAppIdById = @{}
    $resourceReadError = @{}
    foreach ($rid in (@($assignments | ForEach-Object { $_.ResourceId }) | Where-Object { $_ } | Select-Object -Unique)) {
        try {
            $rsp = Get-MgServicePrincipal -ServicePrincipalId $rid -Property 'id,appId,appRoles' -ErrorAction Stop
            $m = @{}; foreach ($role in @($rsp.AppRoles)) { if ($role.Id) { $m[[string]$role.Id] = $role.Value } }
            $roleMapByResourceId[$rid] = $m
            $resourceAppIdById[$rid] = [string]$rsp.AppId
        } catch {
            # Unreadable resource -> its assignments stay unresolved below and the run fails closed.
            $roleMapByResourceId[$rid] = @{}; $resourceAppIdById[$rid] = $null
            $resourceReadError[$rid] = $_.Exception.Message
        }
    }

    $unapproved = @(); $unresolved = @(); $resolvedValues = @()
    foreach ($a in $assignments) {
        $value = $null
        if ($roleMapByResourceId.ContainsKey($a.ResourceId)) { $value = $roleMapByResourceId[$a.ResourceId][[string]$a.AppRoleId] }
        if (-not $value) {   # cannot verify -> unsafe
            $why = if ($resourceReadError.ContainsKey($a.ResourceId)) { " [read error: $($resourceReadError[$a.ResourceId])]" } else { '' }
            $unresolved += ("{0}:appRole {1}{2}" -f $a.ResourceDisplayName, $a.AppRoleId, $why)
            continue
        }
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
    # Warn early when the core audit permissions are missing: the checks that need them will
    # be skipped (Invoke-EntraAudit also lists the affected selected checks).
    # Same rule as the real gate (Get-EAMissingScope), so Directory.Read.All counts as covering
    # Application.Read.All here too and the warning never names a permission no check needs.
    $core = @('Directory.Read.All','Policy.Read.All','AuditLog.Read.All','RoleManagement.Read.Directory','Application.Read.All')
    $missingCore = @(Get-EAMissingScope -Required $core -Granted $script:AppOnlyGrantedPermissions)
    if ($missingCore.Count -gt 0) {
        Write-Warn2 ("The audit app is missing core read permission(s): {0}. Checks that need them will be skipped - grant them (PREREQUISITE.md, section A.2) for a complete audit." -f ($missingCore -join ', '))
    }
}

# Which of the required permissions does the current sign-in lack? Directory.Read.All
# implicitly covers only the narrower directory-object reads listed here; policy, logs,
# reports, risk and governance permissions still require their explicit permission.
function Get-EAMissingScope {
    param(
        [string[]]$Required,
        # Optional explicit permission list (used by Assert-AppOnlyReadOnly); by default the
        # current sign-in's permissions are used.
        [string[]]$Granted
    )
    # The outer @() keeps a one-permission list an array: otherwise $have becomes a plain
    # string and "+=" below concatenates text, so even the granted permission looks missing.
    [string[]]$have = @(if ($PSBoundParameters.ContainsKey('Granted')) {
        @($Granted)
    } elseif ($script:AuthType -eq 'AppOnly') {
        @($script:AppOnlyGrantedPermissions)
    } else {
        @((Get-MgContext).Scopes)
    })
    if ($have -contains 'Directory.Read.All') {
        $have += @('User.Read.All','Group.Read.All','Organization.Read.All','Device.Read.All','Application.Read.All')
    }
    return @($Required | Where-Object { $_ -and $_ -notin $have })
}

# Permission gate for delegated and app-only runs (see Get-EAMissingScope).
function Test-MgScope {
    param([string[]]$Required, [switch]$Quiet)
    $missing = @(Get-EAMissingScope -Required $Required)
    if ($missing.Count -gt 0) {
        if (-not $Quiet) { Write-Warn2 "Skipping - missing $($script:AuthType.ToLowerInvariant()) permission(s): $($missing -join ', ')" }
        return $false
    }
    return $true
}

# Plain-language reason for a missing-permission skip (CheckStatus.Reason).
function Get-EAMissingScopeReason {
    param([string[]]$Missing)
    $list = (@($Missing) -join ', ')
    $one = (@($Missing).Count -eq 1)
    $noun = if ($one) { 'permission' } else { 'permissions' }
    $it = if ($one) { 'it' } else { 'them' }
    if ($script:AuthType -eq 'AppOnly') {
        return "Missing $noun`: $list - add $it to the audit app as application $noun, grant admin consent and run again."
    }
    return "Missing $noun`: $list - an administrator must consent to $it for the app used to sign in, then run again."
}

# Counts of the findings a check added since index $Since, classified the same way for a
# completed check and for one that stopped part-way.
function Get-EACheckFindingCount {
    param([int]$Since)
    $total = $script:Findings.Count - $Since
    $new = if ($total -le 0) { @() }
           elseif ($script:Findings -is [System.Collections.Generic.List[object]]) { @($script:Findings.GetRange($Since, $total)) }
           else { @($script:Findings | Select-Object -Skip $Since) }
    # Many checks intentionally add Information-level baselines (population overviews, MFA
    # adoption, "desired posture" notes) even when nothing is wrong. Count only non-Information
    # severities as risk findings so a clean check is not mislabelled as noisy.
    # Coverage findings can carry a risk-bearing severity because the visibility gap
    # is operationally important, but they are not proof of an adverse tenant fact.
    # Keep them out of RiskFindings(n); they are counted independently as Incomplete.
    [pscustomobject]@{
        Total    = $new.Count
        Risk     = @($new | Where-Object { $_.Severity -ne 'Information' -and -not (Test-EntraCoverageGap $_) }).Count
        Info     = @($new | Where-Object { $_.Severity -eq 'Information' }).Count
        Coverage = @($new | Where-Object { Test-EntraCoverageGap $_ }).Count
    }
}

# One uniform CheckStatus record (the contract the report writers consume).
function ConvertTo-EACheckStatus {
    param(
        [string]$Title, [string]$Status, [int]$Count = 0, [int]$InfoCount = 0, [int]$CoverageCount = 0,
        [string]$Reason = '', $ErrorMessage = $null, [string[]]$MissingScopes = @(),
        [double]$DurationSeconds = 0, [switch]$Partial
    )
    [pscustomobject]@{
        Title           = $Title
        Status          = $Status
        Count           = $Count           # risk findings (non-Information, not coverage gaps)
        InfoCount       = $InfoCount
        CoverageCount   = $CoverageCount
        Reason          = $Reason          # one plain-language sentence whenever it is not a plain pass
        ErrorMessage    = $(if ($ErrorMessage) { [string]$ErrorMessage } else { $null })   # raw exception text (Error / Skipped-NoPermission only)
        MissingScopes   = [string[]]@($MissingScopes | Where-Object { $_ })   # Skipped-NoScope only
        Partial         = [bool]$Partial   # stopped part-way after recording findings
        DurationSeconds = [math]::Round($DurationSeconds, 1)
    }
}

# Wraps a check: scope gate, run, classify status for the posture report.
# Produces the $script:CheckStatus contract: Title, Status, Count (risk findings),
# InfoCount, CoverageCount, Reason (plain-language sentence whenever it is not a plain
# pass), ErrorMessage (raw exception text; Error / Skipped-NoPermission only),
# MissingScopes (Skipped-NoScope only), Partial, DurationSeconds.
# A check that throws AFTER recording findings keeps those findings (they are real), is
# recorded as 'Error' with the correct counts and Partial=$true, and every runtime failure
# also adds an Information coverage-gap finding so the Results report shows the gap.
function Invoke-AuditCheck {
    param(
        [string]$CheckId, [string]$Title, [string[]]$Scopes,
        [switch]$NeedP2, [switch]$NeedP1, [scriptblock]$Action
    )
    Write-Info "Running check: $Title"
    $before = $script:Findings.Count
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    if ($Scopes) {
        $missing = @(Get-EAMissingScope -Required $Scopes)
        if ($missing.Count -gt 0) {
            $reason = Get-EAMissingScopeReason -Missing $missing
            $script:CheckStatus[$CheckId] = ConvertTo-EACheckStatus -Title $Title -Status 'Skipped-NoScope' -Reason $reason -MissingScopes $missing
            Write-Warn2 "  $Title -> Skipped-NoScope ($reason)"
            return
        }
    }
    # When the SKU read itself failed the license state is UNKNOWN - report that
    # distinctly instead of a false 'NoLicense' (the tenant may well be licensed).
    foreach ($gate in @(
        @{ Need = [bool]$NeedP1; Has = [bool]$script:HasP1; Tier = 'P1' },
        @{ Need = [bool]$NeedP2; Has = [bool]$script:HasP2; Tier = 'P2' }
    )) {
        if (-not $gate.Need -or $gate.Has) { continue }
        if ($script:LicenseKnown) {
            $status = 'Skipped-NoLicense'
            $reason = "Needs a Microsoft Entra ID $($gate.Tier) license, which was not found in this tenant."
        } else {
            $status = 'Skipped-LicenseUnknown'
            $reason = "Needs a Microsoft Entra ID $($gate.Tier) license; the license check itself failed, so it is unknown whether the tenant has one."
        }
        $script:CheckStatus[$CheckId] = ConvertTo-EACheckStatus -Title $Title -Status $status -Reason $reason
        Write-Warn2 "  $Title -> $status (Entra ID $($gate.Tier) required)"
        return
    }

    try {
        & $Action
        $n = Get-EACheckFindingCount -Since $before
        $status = if ($n.Risk -gt 0 -and $n.Coverage -gt 0) { "RiskFindings($($n.Risk))+Incomplete($($n.Coverage))" } `
            elseif ($n.Risk -gt 0) { "RiskFindings($($n.Risk))" } `
            elseif ($n.Coverage -gt 0) { "Incomplete($($n.Coverage))" } `
            elseif ($n.Info -gt 0) { "InfoOnly($($n.Info))" } `
            else { 'Pass' }
        $issues = if ($n.Risk -eq 1) { '1 issue' } else { "$($n.Risk) issues" }
        $gaps = if ($n.Coverage -eq 1) { '1 data source or object could not be read' } else { "$($n.Coverage) data sources or objects could not be read" }
        $notes = if ($n.Info -eq 1) { '1 informational note' } else { "$($n.Info) informational notes" }
        $reason = if ($n.Risk -gt 0 -and $n.Coverage -gt 0) { "Found $issues that need attention; $gaps, so there may be more." } `
            elseif ($n.Risk -gt 0) { "Found $issues that need attention." } `
            elseif ($n.Coverage -gt 0) { "No problems found in the data that could be read, but $gaps - this is not a clean result." } `
            elseif ($n.Info -gt 0) { "No problems found ($notes recorded)." } `
            else { '' }
        $script:CheckStatus[$CheckId] = ConvertTo-EACheckStatus -Title $Title -Status $status -Count $n.Risk -InfoCount $n.Info `
            -CoverageCount $n.Coverage -Reason $reason -DurationSeconds $sw.Elapsed.TotalSeconds
        Write-Good "  $Title -> $status"
    } catch {
        $err = $_
        $message = [string]$err.Exception.Message
        $details = if ($err.ErrorDetails -and $err.ErrorDetails.Message) { [string]$err.ErrorDetails.Message } else { '' }
        if (-not $message) { $message = $details }
        $code = Get-EAHttpStatus $err
        $denied = Test-EAAccessDenied $err
        $licenseHint = if (('{0} {1}' -f $message, $details) -match '(?i)premium|licen[cs]e') { ' (the message mentions licensing - the tenant may lack the required license)' } else { '' }
        $shortMessage = ($message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
        if (-not $shortMessage) { $shortMessage = $err.Exception.GetType().Name }
        if ($shortMessage.Length -gt 240) { $shortMessage = $shortMessage.Substring(0, 240) + '...' }

        # Findings recorded before the failure stay in the report (they are real); they are
        # counted here so the posture page and the results page agree.
        $prior = Get-EACheckFindingCount -Since $before
        $partial = ($prior.Total -gt 0)
        $priorText = if ($prior.Total -eq 1) { '1 finding' } else { "$($prior.Total) findings" }
        if ($denied -and -not $partial) {
            $status = 'Skipped-NoPermission'
            $reason = "Access denied by Microsoft Graph: the signed-in account or app lacks a permission or admin role this check needs$licenseHint."
            $fTitle = "Check could not run (access denied): $Title"
            $fWhy = 'Nothing in this area was checked, so problems here cannot show up in this report. This is a gap in the audit, not a clean result.'
            $fAction = "Give the audit account or app the missing read permission or admin role (see PREREQUISITE.md), then run this check again with -select $CheckId."
        } elseif ($partial) {
            # 'Skipped' would claim the check never ran; it did, part-way.
            $status = 'Error'
            $cause = if ($denied) { "access was denied by Microsoft Graph$licenseHint" } else { "an error occurred: $shortMessage" }
            $reason = "Stopped part-way after recording $priorText because $cause. The findings shown are real but may not be complete."
            $fTitle = "Check stopped part-way, results are incomplete: $Title"
            $fWhy = 'The check stopped before it had looked at everything. The findings it did record are real, but there may be more problems that were never checked.'
            $fAction = "Fix the cause shown in the evidence (missing permission, throttling or a temporary Microsoft Graph error), then run this check again with -select $CheckId."
        } else {
            $status = 'Error'
            $reason = "Stopped with an error: $shortMessage"
            $fTitle = "Check stopped with an error: $Title"
            $fWhy = 'Nothing in this area was checked, so problems here cannot show up in this report. This is a gap in the audit, not a clean result.'
            $fAction = "Fix the cause shown in the evidence (often throttling or a temporary Microsoft Graph error), then run this check again with -select $CheckId. The run log (EntraAudit-Run.log) has the details."
        }
        $fEvidence = ("Check id: {0}. Status: {1}. Findings recorded before it stopped: {2}. HTTP status: {3}. Error: {4}" -f
            $CheckId, $status, $prior.Total, $(if ($code) { $code } else { 'n/a' }), $message)
        Add-EntraFinding -Severity 'Information' -CheckId $CheckId -Category 'Audit Coverage' -CoverageGap `
            -RuleId ('{0}-check-did-not-finish' -f $CheckId) -Title $fTitle -Evidence $fEvidence `
            -WhyItMatters $fWhy -RecommendedAction $fAction

        $n = Get-EACheckFindingCount -Since $before
        $script:CheckStatus[$CheckId] = ConvertTo-EACheckStatus -Title $Title -Status $status -Count $n.Risk -InfoCount $n.Info `
            -CoverageCount $n.Coverage -Reason $reason -ErrorMessage $message -Partial:$partial -DurationSeconds $sw.Elapsed.TotalSeconds
        if ($status -eq 'Error') { Write-Err2 "  $Title -> $status - $reason" }
        else { Write-Warn2 "  $Title -> $status - $reason Error: $shortMessage" }
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

    # LicenseAssignmentStates is deliberately NOT selected: no check reads it, and it is a
    # nested per-SKU array - one of the largest properties on the largest collection.
    $props = @('Id','UserPrincipalName','DisplayName','AccountEnabled','UserType',
               'AssignedLicenses','PasswordPolicies',
               'OnPremisesSyncEnabled','CreatedDateTime',
               'ExternalUserState','ExternalUserStateChangeDateTime')
    if ($wantSignIn) {
        try {
            # Graph caps list pages that include signInActivity at 120 users (documented
            # limit for $select=signInActivity), so ask for exactly that page size.
            $script:UsersCache = @(Invoke-EAListAll -Command 'Get-MgUser' -Parameters @{ Property = ($props + 'SignInActivity') } -PageSize 120)
            $script:UsersCacheHasSignIn = $true
        } catch {
            $script:SignInFetchError = $_.Exception
            if ($IncludeSignInActivity) { throw }   # sign-in caller: same failure path as before
            Write-Warn2 "  Sign-in activity could not be read with the user list ($($_.Exception.Message)) - continuing with the user list only; sign-in based checks will report the gap."
            $script:UsersCache = @(Invoke-EAListAll -Command 'Get-MgUser' -Parameters @{ Property = $props })   # base caller: degrade once
            $script:UsersCacheHasSignIn = $false
        }
    } else {
        $script:UsersCache = @(Invoke-EAListAll -Command 'Get-MgUser' -Parameters @{ Property = $props })
        $script:UsersCacheHasSignIn = $false
    }
    $script:UserById = @{}
    foreach ($u in $script:UsersCache) { if ($u.Id) { $script:UserById[$u.Id] = $u } }
    return $script:UsersCache
}

function Get-EARegistrationDetails {
    if ($null -ne $script:RegCache) { return $script:RegCache }
    $script:RegCache = @(Invoke-EAListAll -Command 'Get-MgReportAuthenticationMethodUserRegistrationDetail')
    $script:MfaCapableById = @{}
    foreach ($r in $script:RegCache) { if ($r.Id) { $script:MfaCapableById[$r.Id] = [bool]$r.IsMfaCapable } }
    return $script:RegCache
}

function Get-EARoleDefMap {
    if ($script:RoleDefById.Count -gt 0) { return $script:RoleDefById }
    # (No -PageSize: role definitions are a small, unpaged collection.)
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
        $script:RolePrivilegedMetadataError = $null
    } catch {
        # Not a clean result, but not a blind spot either: without Graph's isPrivileged flag
        # every role with any non-read action is treated as privileged (broader, fail-safe).
        $script:RolePrivilegedMetadataKnown = $false
        $script:RolePrivilegedMetadataError = $_.Exception.Message
        Write-Warn2 "  Could not read the 'isPrivileged' flag for directory roles ($($_.Exception.Message)) - roles are classified by the built-in list and their allowed actions instead (may over-count privileged roles)."
    }
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
    # Action-based tier-0 escalation applies to custom roles only. Built-in User/Helpdesk/
    # Password/Authentication Administrator carry users/password/update (non-admin resets)
    # and are tier-1 by the documented model; built-in tier-0 roles are listed by template id.
    $isTier0 = (($templateId -in $script:Tier0RoleTemplateIds) -or (($isBuiltInRaw -ne $true) -and @($writeActions | Where-Object {
        [string]$_ -match '(?i)^microsoft\.directory/(roleAssignments|roleDefinitions)/.*(allTasks|create|update)$' -or
        [string]$_ -match '(?i)^microsoft\.directory/users/(authenticationMethods|password)/.*(allTasks|create|update)$'
    }).Count -gt 0))
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
    $script:AppsCache = @(Invoke-EAListAll -Command 'Get-MgApplication' -Parameters @{ Property = $appProps; ExpandProperty = 'owners($select=id)' })
    return $script:AppsCache
}

# Service principals with the union of the properties the apps and staleapps checks
# need, cached so a full -all run enumerates the (potentially huge) SP list once.
function Get-EAServicePrincipals {
    if ($null -ne $script:SpsCache) { return $script:SpsCache }
    $spProps = 'id,appId,displayName,appRoles,servicePrincipalType,accountEnabled,passwordCredentials,keyCredentials,appOwnerOrganizationId,createdDateTime'
    $script:SpsCache = @(Invoke-EAListAll -Command 'Get-MgServicePrincipal' -Parameters @{ Property = $spProps })
    return $script:SpsCache
}

# Conditional Access policies, cached - four checks (tenantposture, capolicies,
# breakglass, accesspaths) otherwise each download the full policy set. Throws on
# failure so callers keep their own error semantics; only a successful fetch is
# cached, so a transient failure in one check does not blind the later ones.
# (No -PageSize: a tenant holds at most a few hundred policies, which the service returns
# without paging, so a page-size hint would only add a failure mode.)
function Get-EACaPolicies {
    if ($null -ne $script:CaPoliciesCache) { return $script:CaPoliciesCache }
    $script:CaPoliciesCache = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
    return $script:CaPoliciesCache
}

# ===========================================================================
# CHECK 1 - tenant-info
# ===========================================================================
# Count phrase with singular/plural agreement for finding titles:
# Format-EACount -Count 1 -One 'account has' -Many 'accounts have' -> '1 account has'.
function Format-EACount {
    param([int]$Count, [string]$One, [string]$Many)
    if ($Count -eq 1) { return ('1 ' + $One) }
    return ('{0} {1}' -f $Count, $Many)
}

function Invoke-Check-TenantInfo {
    # Finding ids in this region (tenant-info .. tenantposture) use explicit -RuleId values
    # ('<checkid>-<rule>'), introduced together with the plain-language titles as a one-time
    # id migration, so later wording changes can never change a finding id again.
    $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
    if (-not $org) { throw 'The organization object could not be read - the tenant overview is UNKNOWN, not clean.' }
    $script:Tenant = $org
    # The SKU list only enriches the evidence (licensing is detected at start-up), but a
    # failed read must show as "could not be read", never as "no subscriptions".
    $skus = @(); $skuError = $null
    try { $skus = @(Get-MgSubscribedSku -All -ErrorAction Stop) } catch { $skuError = $_.Exception.Message }

    $verified = @($org.VerifiedDomains | ForEach-Object { "$($_.Name)$(if($_.IsDefault){' (default)'})$(if($_.Type -eq 'Federated'){' [FEDERATED]'})" })
    # Filter empties: @($null) has Count 1, which would hide the "not configured" finding.
    $techMails = @($org.TechnicalNotificationMails | Where-Object { $_ })
    $secMails  = @((Get-EAField $org 'SecurityComplianceNotificationMails') | Where-Object { $_ })

    $rows = @()
    $rows += [pscustomobject]@{ Property='Tenant';            Value=$org.DisplayName }
    $rows += [pscustomobject]@{ Property='Tenant Id';         Value=$org.Id }
    $rows += [pscustomobject]@{ Property='Created';           Value=$org.CreatedDateTime }
    $rows += [pscustomobject]@{ Property='Country';           Value=$org.CountryLetterCode }
    $rows += [pscustomobject]@{ Property='Verified domains';  Value=($verified -join '; ') }
    $rows += [pscustomobject]@{ Property='Tech notification'; Value=($techMails -join '; ') }
    $rows += [pscustomobject]@{ Property='Security notification'; Value=($secMails -join '; ') }
    $rows += [pscustomobject]@{ Property='Licensing';         Value=("P1={0}; P2={1}; WorkloadId={2}" -f $script:HasP1,$script:HasP2,$script:WorkloadIdP) }
    if ($skuError) { $rows += [pscustomobject]@{ Property='Subscriptions (SKUs)'; Value=("Could not be read: {0}" -f $skuError) } }
    foreach ($s in $skus) {
        $rows += [pscustomobject]@{ Property=("SKU {0}" -f $s.SkuPartNumber); Value=("{0}/{1} consumed/enabled" -f $s.ConsumedUnits, $s.PrepaidUnits.Enabled) }
    }
    $notes = @()
    if ($skuError) { $notes += ("The subscription (SKU) list could not be read: {0}" -f $skuError) }
    $src = Write-Evidence -BaseName 'tenant_info' -Rows $rows -Title 'Tenant / Organization Overview' -Notes $notes

    if ($techMails.Count -eq 0 -or $secMails.Count -eq 0) {
        $title = if ($techMails.Count -eq 0 -and $secMails.Count -eq 0) { 'No email address is set for Microsoft security and technical notices' }
                 elseif ($secMails.Count -eq 0) { 'No email address is set for Microsoft security notices' }
                 else { 'No email address is set for Microsoft technical notices' }
        Add-EntraFinding -Severity 'Low' -CheckId 'tenant-info' -Category 'Tenant Posture' -RuleId 'tenant-info-notification-contacts-missing' `
            -Title $title `
            -Evidence ("Technical notification addresses (technicalNotificationMails): {0}; security and compliance notification addresses (securityComplianceNotificationMails): {1}." -f $techMails.Count, $secMails.Count) `
            -WhyItMatters 'Microsoft sends service, security and compliance warnings about the tenant to these addresses. If none is set, those warnings reach nobody.' `
            -RecommendedAction 'Set both notification addresses to a monitored shared mailbox or distribution list, not one person. The technical contact is under Entra admin center > Entra ID > Overview > Properties.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/fundamentals/properties-area' `
            -SourceFile $src -ResultRows $rows
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId 'tenant-info' -Category 'Tenant Posture' -RuleId 'tenant-info-overview' `
            -Title 'Tenant overview' `
            -Evidence ("{0} ({1}); verified domains: {2}; Entra ID P1: {3}; P2: {4}; subscriptions (SKUs): {5}." -f $org.DisplayName, $org.Id, $verified.Count, $script:HasP1, $script:HasP2, $(if ($skuError) { 'could not be read' } else { $skus.Count })) `
            -WhyItMatters 'Basic facts about the tenant - its domains and licences - which decide what security features (such as Conditional Access or Privileged Identity Management) it can use.' `
            -RecommendedAction 'No action needed - background for the rest of the report.' `
            -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 2 - privileged-roles  (FLAGSHIP: permanent vs eligible vs time-bound)
# ===========================================================================
function Invoke-Check-PrivRoles {
    Get-EARoleDefMap | Out-Null
    # The user and MFA-registration caches only ANNOTATE assignments (UPN, guest, synced,
    # MFA-capable). A failed read is remembered and reported instead of being swallowed:
    # without the user cache a synced or guest admin can look like a cloud-only member.
    $userError = $null; $regError = $null
    try { Get-EAUsers | Out-Null } catch { $userError = $_.Exception.Message }
    try { Get-EARegistrationDetails | Out-Null } catch { $regError = $_.Exception.Message }

    $assignments = New-Object System.Collections.Generic.List[object]   # one row per (principal, role, state)

    # Resolve a directory-role template id -> our privileged classification
    function _RoleInfo([string]$roleDefId) {
        return (Get-EARoleInfo -RoleDefinitionId $roleDefId)
    }

    function _Principal($p) {
        # Graph frequently omits @odata.type on the default (user) type when a Principal
        # is $expand-ed, and the UPN lives in AdditionalProperties (not as a first-class
        # member). Resolve UPN from the user cache as a fallback, and infer the type from
        # the UPN / known-user cache / group or app markers so the break-glass and
        # guest/synced gates work.
        $id   = if ($p) { $p.Id } else { $null }
        $upn  = (Get-Ap $p 'userPrincipalName')
        $name = (Get-Ap $p 'displayName')
        if (-not $name -and $p -and $p.PSObject.Properties['DisplayName']) { $name = $p.DisplayName }
        if (-not $upn -and $id -and $script:UserById.ContainsKey($id)) { $upn = $script:UserById[$id].UserPrincipalName }

        $odt = Get-Ap $p '@odata.type'
        $type = if ($odt) { ($odt -replace '#microsoft.graph.','') }
                elseif ($upn) { 'user' }
                elseif ($id -and $script:UserById.ContainsKey($id)) { 'user' }
                elseif ((Get-Ap $p 'groupTypes') -or $null -ne (Get-Ap $p 'securityEnabled')) { 'group' }
                elseif (Get-Ap $p 'appId') { 'servicePrincipal' }
                else { '' }

        $synced = $false
        if ($id -and $script:UserById.ContainsKey($id)) { $synced = [bool]$script:UserById[$id].OnPremisesSyncEnabled }
        $mfa = $null
        if ($id -and $script:MfaCapableById.ContainsKey($id)) { $mfa = [bool]$script:MfaCapableById[$id] }
        # External identity: the '#EXT#' UPN marker OR userType Guest (the same rule as the
        # guests check). A renamed UPN can lose the marker, so either signal is enough.
        $isGuest = ([string]$upn -like '*#EXT#*') -or ([string](Get-Ap $p 'userType') -eq 'Guest')
        if (-not $isGuest -and $id -and $script:UserById.ContainsKey($id)) { $isGuest = ([string]$script:UserById[$id].UserType -eq 'Guest') }
        return [pscustomobject]@{ Id=$id; Type=$type; Upn=$upn; Name=$name; Synced=$synced; MfaCapable=$mfa; IsGuest=[bool]$isGuest }
    }

    function _Row {
        param($Principal, $RoleInfo, [string]$State, $EndDateTime, $MemberType, $AssignmentType, $DirectoryScopeId, $AppScopeId)
        return [pscustomobject]@{
            PrincipalId=$Principal.Id; Principal=($Principal.Upn ?? $Principal.Name); PrincipalType=$Principal.Type; IsGuest=$Principal.IsGuest
            Role=$RoleInfo.Name; RoleTemplateId=$RoleInfo.TemplateId; RoleDefinitionId=$RoleInfo.RoleDefinitionId; IsPrivileged=$RoleInfo.IsPrivileged; IsGA=$RoleInfo.IsGA; IsTier0=$RoleInfo.IsTier0
            State=$State; EndDateTime=$EndDateTime; MemberType=$MemberType; AssignmentType=$AssignmentType
            DirectoryScopeId=$DirectoryScopeId; AppScopeId=$AppScopeId; RoleClassification=$RoleInfo.ClassificationSource; Synced=$Principal.Synced; MfaCapable=$Principal.MfaCapable
        }
    }

    $pimAvailable = $true; $pimActiveCount = 0; $pimError = $null

    # --- Model A: ACTIVE assignment schedule instances (PIM-aware) ---
    try {
        foreach ($i in @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)) {
            # Order matters: an Activated (JIT) instance is time-bound even on the rare
            # occasion its EndDateTime is null; only a non-activated null-end is permanent.
            $state = if ($i.AssignmentType -eq 'Activated') { 'TimeBound-Active(JIT)' }
                     elseif ($null -eq $i.EndDateTime) { 'Permanent' }
                     else { 'TimeBound-Assigned' }
            $assignments.Add((_Row -Principal (_Principal $i.Principal) -RoleInfo (_RoleInfo $i.RoleDefinitionId) -State $state `
                -EndDateTime $i.EndDateTime -MemberType $i.MemberType -AssignmentType $i.AssignmentType `
                -DirectoryScopeId $i.DirectoryScopeId -AppScopeId $i.AppScopeId))
            $pimActiveCount++
        }
    } catch {
        $pimAvailable = $false; $pimError = $_.Exception.Message
        Write-Warn2 "  PIM active-schedule endpoint unavailable ($pimError) - falling back to classic role assignments."
    }

    # --- Model B: ELIGIBLE schedule instances (PIM) ---
    $eligibleCount = 0; $eligibilityKnown = $true; $eligibilityError = $null
    try {
        foreach ($i in @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)) {
            $eligibleCount++
            $assignments.Add((_Row -Principal (_Principal $i.Principal) -RoleInfo (_RoleInfo $i.RoleDefinitionId) -State 'Eligible' `
                -EndDateTime $i.EndDateTime -MemberType $i.MemberType -AssignmentType 'Eligible' `
                -DirectoryScopeId $i.DirectoryScopeId -AppScopeId $i.AppScopeId))
        }
    } catch {
        $eligibilityKnown = $false; $eligibilityError = $_.Exception.Message
        Write-Warn2 "  PIM eligibility endpoint unavailable ($eligibilityError) - requires Entra ID P2."
    }

    # --- Fallback: classic roleAssignments when PIM is unavailable OR returned no ACTIVE rows.
    # Keyed on the ACTIVE count, not on all rows: eligible rows must not suppress the
    # fallback, otherwise an empty active read would look like "no standing admins". ---
    $fetchErr = $null
    $activeSource = if ($pimAvailable -and $pimActiveCount -gt 0) { 'PIM role-assignment schedule instances' } else { 'none (every read failed or returned nothing)' }
    if (-not $pimAvailable -or $pimActiveCount -eq 0) {
        try {
            foreach ($a in @(Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop)) {
                $assignments.Add((_Row -Principal (_Principal $a.Principal) -RoleInfo (_RoleInfo $a.RoleDefinitionId) -State 'Permanent' `
                    -EndDateTime $null -MemberType 'Direct' -AssignmentType 'Assigned' `
                    -DirectoryScopeId $a.DirectoryScopeId -AppScopeId $a.AppScopeId))
            }
            $activeSource = 'classic role assignments (roleManagement/directory/roleAssignments)'
        } catch {
            $fetchErr = $_
            # last resort: classic directoryRoles + members (errors recorded, not hidden -
            # a failed fetch must surface as Error/Skipped/coverage gap, never as a clean 'Pass')
            try {
                foreach ($dr in @(Get-MgDirectoryRole -All -ErrorAction Stop)) {
                    $ri = _RoleInfo $dr.RoleTemplateId
                    foreach ($m in @(Get-MgDirectoryRoleMember -DirectoryRoleId $dr.Id -All -ErrorAction Stop)) {
                        $assignments.Add((_Row -Principal (_Principal $m) -RoleInfo $ri -State 'Permanent' `
                            -EndDateTime $null -MemberType 'Direct' -AssignmentType 'Assigned' -DirectoryScopeId '/' -AppScopeId $null))
                    }
                }
                $fetchErr = $null
                $activeSource = 'activated directory roles and their members (directoryRoles)'
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

    # Every real tenant has at least one active role assignment (Entra does not let the last
    # active Global Administrator be removed). An EMPTY result is therefore UNKNOWN, not "no
    # admins" - throw so Invoke-AuditCheck classifies the check Error/Skipped-NoPermission
    # instead of drawing conclusions (e.g. "no break-glass admin") from no data.
    if ($rows.Count -eq 0) {
        if ($fetchErr) { throw $fetchErr }
        $why = @(); if ($pimError) { $why += "PIM: $pimError" }; if ($eligibilityError) { $why += "eligibility: $eligibilityError" }
        throw ("Privileged role assignments could not be retrieved from any endpoint (PIM, classic roleAssignments, directoryRoles){0} - result is UNKNOWN, not clean." -f $(if ($why) { ' [' + ($why -join '; ') + ']' } else { '' }))
    }
    # Zero ACTIVE rows (eligible only) or a failed active read: the standing-access picture
    # is unknown, so no "no permanent admin / no break-glass" conclusion may be drawn.
    $activeRows  = @($rows | Where-Object { $_.State -ne 'Eligible' })
    $activeKnown = ($activeRows.Count -gt 0 -and -not $fetchErr)

    $notes = @(
        ("Active assignments read from: {0}" -f $activeSource)
        ("PIM endpoints available: {0}" -f $pimAvailable)
        ("Eligible (PIM) assignments: {0}" -f $(if ($eligibilityKnown) { $eligibleCount } else { "could not be read ($eligibilityError)" }))
    )
    if ($pimError) { $notes += ("PIM active-assignment read failed: {0}" -f $pimError) }
    if ($fetchErr) { $notes += ("Classic role-assignment read failed: {0}" -f $fetchErr.Exception.Message) }
    if ($userError) { $notes += ("The user directory could not be read ({0}); guest and on-premises-synced status may be missing." -f $userError) }
    if ($regError)  { $notes += ("The MFA registration report could not be read ({0}); MfaCapable is empty (unknown)." -f $regError) }
    $src = Write-Evidence -BaseName 'privileged_roles' -Rows $rows `
        -Title 'Privileged Role Assignments - Permanent vs Eligible vs Time-Bound' -Notes $notes

    if (-not $activeKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-active-unknown' -CoverageGap `
            -Title 'Permanent admin role assignments could not be read - result unknown' `
            -Evidence ("Active role assignments found: {0} (source: {1}).{2} Microsoft Entra always keeps at least one active Global Administrator assignment, so this is a failed or incomplete read, not proof that there are no permanent admins." -f $activeRows.Count, $activeSource, $(if ($fetchErr) { ' Error: ' + $fetchErr.Exception.Message + '.' } else { '' })) `
            -WhyItMatters 'Who holds admin rights all the time is the main question of this check. A failed read must not look like "no permanent admins".' `
            -RecommendedAction 'Check that the audit account or app has RoleManagement.Read.Directory, look for throttling errors in the console output, and run the check again.' `
            -SourceFile $src
    }
    if ($userError) {
        Add-EntraFinding -Severity 'Information' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-account-details-unknown' -CoverageGap `
            -Title 'Admin account details could not be read - guest and on-premises status unknown' `
            -Evidence ("The user directory read failed: {0}. Guest accounts are then only recognised by the #EXT# marker in their sign-in name, and accounts synced from on-premises Active Directory cannot be recognised, so a guest admin may be rated High instead of Critical and a synced account named in -BreakGlassUpns is treated as cloud-only." -f $userError) `
            -WhyItMatters 'These details decide how risky an admin account is - for example a guest admin is always Critical. Without them the result can look better than it is.' `
            -RecommendedAction 'Grant User.Read.All to the audit account or app and run the check again.' `
            -SourceFile $src
    }

    $bg = Normalize-StringList -Values $BreakGlassUpns
    $permanentPriv = @($rows | Where-Object { $_.IsPrivileged -and $_.State -eq 'Permanent' })
    $permanentGA   = @($permanentPriv | Where-Object { $_.IsGA })

    # Index rows by principal once - re-scanning all rows per permanent assignment is
    # O(n*m) with hundreds of standing assignments (the systemic case this check exists for).
    # ::new() rather than New-Object: New-Object returns the list PSObject-wrapped, and
    # @() over a wrapped List throws "Argument types do not match" on some pwsh 7.4 builds.
    $rowsByPrincipal = @{}
    foreach ($r in $rows) {
        $pid0 = [string]$r.PrincipalId
        if (-not $rowsByPrincipal.ContainsKey($pid0)) { $rowsByPrincipal[$pid0] = [System.Collections.Generic.List[object]]::new() }
        $rowsByPrincipal[$pid0].Add($r) | Out-Null
    }

    function _ScopeText($a) {
        $t = if ([string]::IsNullOrEmpty([string]$a.DirectoryScopeId) -or [string]$a.DirectoryScopeId -eq '/') { 'whole tenant' } else { 'directory scope ' + [string]$a.DirectoryScopeId }
        if ($a.AppScopeId -and [string]$a.AppScopeId -ne '/') { $t += ('; app scope {0}' -f $a.AppScopeId) }
        return $t
    }

    # Per-assignment findings for permanent privileged roles. Stable ids: the RuleId carries
    # the role TEMPLATE id (one issue per role, so the risk score and the report keep one
    # bucket per role, as the title prefix did before) and PathHash carries both scopes (the
    # same role at two scopes is two findings, matching the de-duplication key above).
    foreach ($a in $permanentPriv) {
        $roleKey  = ([string]$a.RoleTemplateId).ToLowerInvariant()
        $scopeKey = '{0};{1}' -f $a.DirectoryScopeId, $a.AppScopeId
        $who = if ($a.Principal) { [string]$a.Principal } else { 'unknown principal ' + [string]$a.PrincipalId }

        $isBreakGlass = ($a.Principal -and ($a.Principal.ToLowerInvariant() -in $bg) -and -not $a.Synced -and $a.PrincipalType -eq 'user')
        if ($isBreakGlass -and $a.IsGA) { continue }   # permanent GA on a break-glass account is the expected posture
        if ($isBreakGlass -and -not $a.IsGA) {
            # A break-glass account should be permanent ONLY for Global Administrator. Any
            # extra standing privileged role widens its blast radius beyond emergency recovery
            # and is still worth reporting (just not at the full standing-privilege severity).
            Add-EntraFinding -Severity 'Medium' -CheckId 'privileged-roles' -Category 'Privileged Access' `
                -RuleId 'privileged-roles-breakglass-extra-role' -PathHash ('{0};{1}' -f $roleKey, $scopeKey) `
                -Title ("Break-glass account has an extra permanent admin role: {0} ({1})" -f $who, $a.Role) `
                -Evidence ("Designated break-glass account {0} (object id {1}) permanently holds {2} ({3}). A break-glass account should hold only Global Administrator." -f $who, $a.PrincipalId, $a.Role, (_ScopeText $a)) `
                -WhyItMatters 'Emergency-access (break-glass) accounts are kept outside the normal sign-in rules, so they should be as simple as possible. Every extra permanent role gives an attacker more to misuse and makes the account harder to monitor.' `
                -RecommendedAction 'Remove the extra role from the break-glass account unless a documented recovery procedure needs it (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles).' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
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
        if ($a.MfaCapable -eq $false) { $reasons += 'cannot use multifactor authentication (not MFA-capable)' }
        elseif ($regError -and $a.PrincipalType -eq 'user') { $reasons += 'MFA status unknown (registration report unreadable)' }
        if ($a.Synced) { $reasons += 'synced from on-premises Active Directory' }
        if ($a.PrincipalType -eq 'group') { $reasons += 'assigned to a group - every member gets the role' }
        elseif ($a.PrincipalType -eq 'servicePrincipal') { $reasons += 'assigned to an app (service principal)' }
        if ($a.IsGuest) { $sev = 'Critical'; $reasons += 'guest/external account' }

        $factors = if ($reasons.Count) { ' Risk factors: ' + ($reasons -join '; ') + '.' } else { '' }
        $action = 'Make this role PIM-eligible (just-in-time) and remove the permanent assignment (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles). Only the two cloud-only emergency-access (break-glass) Global Administrators should stay permanent.'
        if ($a.PrincipalType -eq 'servicePrincipal') {
            $action = 'Check whether this app really needs a directory admin role; replace it with the narrowest role or Microsoft Graph permission it needs, or remove it.'
        }
        # Include the directory object id so two findings for similarly-named but DISTINCT
        # accounts (e.g. niclas@contoso.se vs niclas@contoso.onmicrosoft.com) are clearly
        # separate objects, not a double-count - and so each gets a stable per-object id.
        Add-EntraFinding -Severity $sev -CheckId 'privileged-roles' -Category 'Privileged Access' `
            -RuleId ('privileged-roles-permanent-{0}' -f $roleKey) -PathHash $scopeKey `
            -Title ("Permanent {0} role (not just-in-time): {1}" -f $a.Role, $who) `
            -Evidence ("{0} (object id {1}, type {2}) holds {3} as a permanent active assignment with no end date ({4}).{5}" -f $who, $a.PrincipalId, $(if ($a.PrincipalType) { $a.PrincipalType } else { 'unknown' }), $a.Role, (_ScopeText $a), $factors) `
            -WhyItMatters 'The admin role is switched on all the time, so anyone who steals this account''s password or session gets the admin rights at once. With Privileged Identity Management (PIM) the role is only switched on when needed, for a short time and after multifactor authentication (MFA) or approval.' `
            -RecommendedAction $action `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure' `
            -SourceFile $src -AffectedPrincipal $a.Principal -ObjectType $a.PrincipalType -ObjectId $a.PrincipalId `
            -ResultRows @($rowsByPrincipal[[string]$a.PrincipalId])
    }

    # Redundant: principal is BOTH eligible AND permanently active for the same role
    $byPrincipalRole = $rows | Group-Object PrincipalId, RoleTemplateId, DirectoryScopeId, AppScopeId
    foreach ($g in $byPrincipalRole) {
        $states = @($g.Group.State)
        if (($states -contains 'Permanent') -and ($states -contains 'Eligible')) {
            $a = $g.Group | Select-Object -First 1
            $who = if ($a.Principal) { [string]$a.Principal } else { 'unknown principal ' + [string]$a.PrincipalId }
            Add-EntraFinding -Severity 'High' -CheckId 'privileged-roles' -Category 'Privileged Access' `
                -RuleId ('privileged-roles-redundant-{0}' -f ([string]$a.RoleTemplateId).ToLowerInvariant()) -PathHash ('{0};{1}' -f $a.DirectoryScopeId, $a.AppScopeId) `
                -Title ("Permanent {0} role makes the PIM-eligible one pointless: {1}" -f $a.Role, $who) `
                -Evidence ("{0} (object id {1}) is PIM-eligible for {2} and also holds it permanently ({3}), so the role never has to be activated." -f $who, $a.PrincipalId, $a.Role, (_ScopeText $a)) `
                -WhyItMatters 'The account is set up to switch the role on just-in-time through Privileged Identity Management (PIM), but the extra permanent assignment keeps the role on all the time. PIM then only looks like it protects the role.' `
                -RecommendedAction 'Remove the permanent (active) assignment and keep the eligible one (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles > Assignments).' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure' `
                -SourceFile $src -AffectedPrincipal $a.Principal -ObjectType $a.PrincipalType -ObjectId $a.PrincipalId -ResultRows $g.Group
        }
    }

    # Break-glass posture - only on a KNOWN active picture (see $activeKnown above).
    if ($permanentGA.Count -eq 0 -and $pimAvailable -and $activeKnown) {
        $gaEligible  = @($rows | Where-Object { $_.IsGA -and $_.State -eq 'Eligible' }).Count
        $gaTimeBound = @($rows | Where-Object { $_.IsGA -and $_.State -in @('TimeBound-Assigned','TimeBound-Active(JIT)') }).Count
        Add-EntraFinding -Severity 'High' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-no-permanent-breakglass' `
            -Title 'No permanent emergency-access (break-glass) Global Administrator found' `
            -Evidence ("No Global Administrator holds the role permanently. Global Administrator assignments found: {0} PIM-eligible, {1} time-bound or activated just-in-time." -f $gaEligible, $gaTimeBound) `
            -WhyItMatters 'Emergency-access (break-glass) accounts are the way back in when normal admin sign-in fails. If every Global Administrator must first activate the role through Privileged Identity Management (PIM), a problem with PIM, multifactor authentication (MFA) or federation can lock all admins out of the tenant.' `
            -RecommendedAction 'Create two cloud-only emergency-access accounts with a permanent Global Administrator assignment, protect them with phishing-resistant MFA (for example FIDO2 security keys), keep them out of Conditional Access policies that could lock them out, and alert on every sign-in.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
            -SourceFile $src
    }

    # PIM not in use / over-reliance on standing access. A failed eligibility read on a
    # P2 tenant - or on a tenant whose licence state is UNKNOWN - is a coverage gap, not
    # evidence that nobody uses PIM.
    $eligibilityGapMatters = (-not $eligibilityKnown) -and ($script:HasP2 -or -not $script:LicenseKnown)
    if ($eligibleCount -eq 0 -and $permanentPriv.Count -gt 0 -and -not $eligibilityGapMatters) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-pim-not-used' `
            -Title 'Just-in-time admin access (PIM) is not used - admin roles are permanent' `
            -Evidence ("{0} permanent admin role assignment(s) and 0 PIM-eligible assignments. Entra ID P2 detected: {1}." -f $permanentPriv.Count, $script:HasP2) `
            -WhyItMatters 'Without Privileged Identity Management (PIM) every admin right is switched on all the time, so any stolen admin password can be used at once. PIM lets admins switch a role on only when needed, for a limited time and after multifactor authentication (MFA) or approval.' `
            -RecommendedAction 'License Microsoft Entra ID P2 (or Entra ID Governance) for admins, then make admin roles PIM-eligible instead of permanent (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure' `
            -SourceFile $src
    }
    if ($eligibilityGapMatters) {
        Add-EntraFinding -Severity 'Information' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-eligible-unknown' -CoverageGap `
            -Title 'PIM-eligible admin roles could not be read - list of admins is incomplete' `
            -Evidence ("Reading roleEligibilityScheduleInstances failed ({0}); Entra ID P2 detected: {1}. Eligible administrators are unknown, not zero." -f $eligibilityError, $(if ($script:LicenseKnown) { $script:HasP2 } else { 'unknown (licence read failed)' })) `
            -WhyItMatters 'People who can switch an admin role on just-in-time are still admins and need the same multifactor authentication (MFA), lifecycle and risk checks. They are missing from this result.' `
            -RecommendedAction 'Confirm RoleManagement.Read.Directory is consented (it covers the PIM schedule-instance reads), the audit account holds Global Reader, and the tenant is licensed for Microsoft Entra ID P2; then run the check again.' `
            -SourceFile $src
    }

    # Information: eligible assignments (the good posture) listed for visibility
    $eligible = @($rows | Where-Object { $_.State -eq 'Eligible' -and $_.IsPrivileged })
    if ($eligible.Count -gt 0) {
        $byRoleText = ($eligible | Group-Object Role | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) -join '; '
        Add-EntraFinding -Severity 'Information' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-eligible-summary' `
            -Title ((Format-EACount -Count $eligible.Count -One 'admin role assignment is' -Many 'admin role assignments are') + ' PIM-eligible (just-in-time) - good practice') `
            -Evidence ("Eligible assignments by role: {0}. These admins must switch the role on when they need it; this is the recommended setup, not a problem." -f $byRoleText) `
            -WhyItMatters 'Eligible (just-in-time) access means admin rights are only switched on for short periods, which limits how long a stolen account can misuse them.' `
            -RecommendedAction 'No action needed. Keep moving the remaining permanent admin roles to eligible.' `
            -SourceFile $src -ResultRows $eligible
    }
}

# ===========================================================================
# CHECK 3 - directory-roles  (counts / volume)
# ===========================================================================
function Invoke-Check-DirectoryRoles {
    Get-EARoleDefMap | Out-Null
    # Shared assignment cache (one Graph download per run instead of a private re-fetch).
    $all          = @(Get-EAPrivAssignments)
    $active       = @($all | Where-Object { $_.State -eq 'Active' })
    $eligibleRows = @($all | Where-Object { $_.State -eq 'Eligible' })
    # Count STANDING access only. A just-in-time (JIT) activation is an eligible admin who
    # switched the role on for a few hours through PIM: counting it would make the numbers
    # swing with the working day and tell admins who already use PIM to "move to PIM".
    # A missing ActivationModel (classic API / older cache shape) counts as standing.
    $standing  = @($active | Where-Object { [string]$_.ActivationModel -ne 'TimeBound-Active-JIT' })
    $activated = @($active | Where-Object { [string]$_.ActivationModel -eq 'TimeBound-Active-JIT' })
    $notes = @(
        'Counts are distinct principals per role. Standing = permanent or time-bound active assignments; ActivatedJitNow = PIM activations in effect at audit time (not counted); Eligible = PIM-eligible (not counted).'
    )
    if ($script:PrivEligibilityAssignmentsFailed) { $notes += 'The PIM-eligible assignments could not be read; the Eligible column is incomplete.' }

    if ($active.Count -eq 0) {
        # Every tenant has at least one active Global Administrator, so zero active rows
        # means the read failed or returned nothing - the volume is UNKNOWN, not low.
        $src = Write-Evidence -BaseName 'directory_role_counts' -Rows @() -Title 'Privileged Role Assignment Volume' `
            -Notes ($notes + 'No active role assignments were returned - the admin count could not be determined.')
        Add-EntraFinding -Severity 'Information' -CheckId 'directory-roles' -Category 'Privileged Access' -RuleId 'directory-roles-volume-unknown' -CoverageGap `
            -Title 'Number of admins could not be counted - role assignments could not be read' `
            -Evidence ("No active role assignments were returned{0}. Microsoft Entra always has at least one active Global Administrator, so the Global Administrator and admin-role counts are unknown, not zero." -f $(if ($script:PrivAssignmentsFailed) { ' (the role-assignment read failed)' } else { '' })) `
            -WhyItMatters 'A failed read must not be reported as "few admins"; the number of admins was not checked.' `
            -RecommendedAction 'Check that the audit account or app has RoleManagement.Read.Directory, look for throttling errors in the console output, and run the check again.' `
            -SourceFile $src
        return
    }

    # Key by role TEMPLATE id (not display name, which can be localized/renamed) so the
    # privileged classification and GA count are robust.
    $byRole = @{}
    function _CountInto([object[]]$Rows, [string]$Kind) {
        foreach ($a in $Rows) {
            $t = [string]$a.RoleTemplateId
            if (-not $byRole.ContainsKey($t)) {
                $byRole[$t] = @{
                    Name = $a.RoleName; Privileged = [bool]$a.IsPrivileged
                    Standing  = [System.Collections.Generic.HashSet[string]]::new()
                    Activated = [System.Collections.Generic.HashSet[string]]::new()
                    Eligible  = [System.Collections.Generic.HashSet[string]]::new()
                }
            }
            if ($a.PrincipalId) { [void]$byRole[$t][$Kind].Add([string]$a.PrincipalId) }
        }
    }
    _CountInto $standing 'Standing'
    _CountInto $activated 'Activated'
    _CountInto $eligibleRows 'Eligible'
    $rows = @(foreach ($t in ($byRole.Keys | Sort-Object { $byRole[$_].Name })) {
        $e = $byRole[$t]
        [pscustomobject]@{ Role=$e.Name; Privileged=$e.Privileged; StandingPrincipals=$e.Standing.Count; ActivatedJitNow=$e.Activated.Count; EligiblePrincipals=$e.Eligible.Count }
    })

    # Global Administrators are PEOPLE: a role-assignable group holding GA counts as its
    # (transitive) user members, not as one principal. A group whose members cannot be read
    # counts once and makes the number a minimum.
    $gaUserIds = [System.Collections.Generic.HashSet[string]]::new()
    $gaGroups = @{}; $gaOther = @{}
    foreach ($a in @($standing | Where-Object { $_.IsGA })) {
        $id = [string]$a.PrincipalId; if (-not $id) { continue }
        switch ([string]$a.PrincipalType) {
            'user'  { [void]$gaUserIds.Add($id) }
            'group' { $gaGroups[$id] = $(if ($a.PrincipalName) { [string]$a.PrincipalName } else { $id }) }
            default { $gaOther[$id] = $true }
        }
    }
    $gaDirectUsers = $gaUserIds.Count
    $gaGroupErrors = @()
    foreach ($gid in @($gaGroups.Keys)) {
        try {
            foreach ($m in @(Get-MgGroupTransitiveMember -GroupId $gid -All -ErrorAction Stop)) {
                $mtype = [string](Get-Ap $m '@odata.type')
                if ($mtype -eq '#microsoft.graph.user' -or (Get-Ap $m 'userPrincipalName') -or ($m.Id -and $script:UserById.ContainsKey($m.Id))) { [void]$gaUserIds.Add([string]$m.Id) }
            }
        } catch {
            $gaGroupErrors += ('{0} ({1})' -f $gaGroups[$gid], $_.Exception.Message)
        }
    }
    $gaCountIsMinimum = ($gaGroupErrors.Count -gt 0)
    $gaCount = $gaUserIds.Count + $gaOther.Count + $gaGroupErrors.Count
    $gaActivatedNow = @($activated | Where-Object { $_.IsGA } | ForEach-Object { [string]$_.PrincipalId } | Sort-Object -Unique).Count
    $gaEligible     = @($eligibleRows | Where-Object { $_.IsGA } | ForEach-Object { [string]$_.PrincipalId } | Sort-Object -Unique).Count
    if ($gaGroups.Count -gt 0) { $notes += ('Global Administrator is assigned to {0} group(s): {1}. Their members are counted as Global Administrators.' -f $gaGroups.Count, (@($gaGroups.Values) -join ', ')) }
    foreach ($ge in $gaGroupErrors) { $notes += ('Could not read the members of Global Administrator group {0}; the group is counted once, so the Global Administrator count is a minimum.' -f $ge) }
    $src = Write-Evidence -BaseName 'directory_role_counts' -Rows $rows -Title 'Privileged Role Assignment Volume' -Notes $notes

    $totalPriv = 0
    foreach ($t in $byRole.Keys) { if ($byRole[$t].Privileged) { $totalPriv += $byRole[$t].Standing.Count } }
    $totalActivated = 0
    foreach ($t in $byRole.Keys) { if ($byRole[$t].Privileged) { $totalActivated += $byRole[$t].Activated.Count } }

    $gaEvidence = ("Always-on Global Administrators: {0}{1} - {2} directly assigned user(s), {3} more user(s) through {4} group(s), {5} app or other principal(s){6}. Not counted: {7} currently activated just-in-time through PIM and {8} PIM-eligible." -f `
        $gaCount, $(if ($gaCountIsMinimum) { ' (at least)' } else { '' }), $gaDirectUsers, ($gaUserIds.Count - $gaDirectUsers), $gaGroups.Count, $gaOther.Count,
        $(if ($gaCountIsMinimum) { ('; members of {0} group(s) could not be read' -f $gaGroupErrors.Count) } else { '' }), $gaActivatedNow, $gaEligible)
    $raised = $false
    if ($gaCount -ge 5) {
        $raised = $true
        Add-EntraFinding -Severity 'High' -CheckId 'directory-roles' -Category 'Privileged Access' -RuleId 'directory-roles-global-admin-count' `
            -Title ("{0} always-on Global Administrators - Microsoft recommends fewer than 5" -f $gaCount) `
            -Evidence $gaEvidence `
            -WhyItMatters 'A Global Administrator can change everything in the tenant, so every extra one is another account whose stolen password gives an attacker full control.' `
            -RecommendedAction 'Remove Global Administrator from everyone who does not strictly need it: give day-to-day admins a narrower role, and make the remaining Global Administrators PIM-eligible (just-in-time) except the two emergency-access accounts (Entra admin center > Entra ID > Roles & admins).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices' `
            -SourceFile $src -ResultRows $rows
    } elseif ($gaCount -eq 4) {
        $raised = $true
        Add-EntraFinding -Severity 'Medium' -CheckId 'directory-roles' -Category 'Privileged Access' -RuleId 'directory-roles-global-admin-count' `
            -Title '4 always-on Global Administrators - at the upper limit of Microsoft guidance (fewer than 5)' `
            -Evidence $gaEvidence `
            -WhyItMatters 'A Global Administrator can change everything in the tenant. The tenant is at the highest count Microsoft recommends, so one more admin would go over it.' `
            -RecommendedAction 'Check whether every Global Administrator still needs the role; prefer narrower admin roles and PIM-eligible (just-in-time) assignments (Entra admin center > Entra ID > Roles & admins).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices' `
            -SourceFile $src -ResultRows $rows
    }
    if ($totalPriv -ge 10) {
        $raised = $true
        Add-EntraFinding -Severity 'High' -CheckId 'directory-roles' -Category 'Privileged Access' -RuleId 'directory-roles-privileged-assignment-count' `
            -Title ("{0} always-on privileged role assignments - Microsoft recommends fewer than 10" -f $totalPriv) `
            -Evidence ("Always-on assignments across privileged roles: {0} (each principal counted once per role; a group counts once). Not counted: {1} currently activated just-in-time through PIM." -f $totalPriv, $totalActivated) `
            -WhyItMatters 'Every always-on privileged role assignment is an account that can do tenant-wide damage the moment its password or session is stolen.' `
            -RecommendedAction 'Remove privileged roles that are no longer needed and make the rest PIM-eligible (just-in-time) (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices' `
            -SourceFile $src -ResultRows $rows
    }
    if ($gaCountIsMinimum -and $gaCount -lt 5) {
        $raised = $true
        Add-EntraFinding -Severity 'Information' -CheckId 'directory-roles' -Category 'Privileged Access' -RuleId 'directory-roles-global-admin-count-incomplete' -CoverageGap `
            -Title 'Number of Global Administrators could not be fully counted' `
            -Evidence ("{0} The members of these Global Administrator groups could not be read: {1}." -f $gaEvidence, ($gaGroupErrors -join '; ')) `
            -WhyItMatters 'Everyone in a group that holds Global Administrator is a Global Administrator. Without the member list the real number may be above the recommended limit.' `
            -RecommendedAction 'Grant GroupMember.Read.All or Group.Read.All (or Directory.Read.All) to the audit account or app and run the check again.' `
            -SourceFile $src -ResultRows $rows
    }
    if (-not $raised) {
        Add-EntraFinding -Severity 'Information' -CheckId 'directory-roles' -Category 'Privileged Access' -RuleId 'directory-roles-volume-ok' `
            -Title 'Number of admins is within Microsoft''s recommended limits' `
            -Evidence ("{0} Always-on privileged role assignments: {1}." -f $gaEvidence, $totalPriv) `
            -WhyItMatters 'Keeping the number of admins low limits the damage any single stolen admin account can do.' `
            -RecommendedAction 'No action needed. Keep the admin count low and keep moving roles to PIM-eligible (just-in-time).' `
            -SourceFile $src -ResultRows $rows
    }
}

# ===========================================================================
# CHECK 4 - accounts (hygiene)
# ===========================================================================
function Invoke-Check-Accounts {
    $users = @(Get-EAUsers)
    # MFA capability decides whether the non-expiring-password finding is High. A failed
    # registration read must not quietly downgrade it to Medium (see the coverage finding).
    $regError = $null
    try { Get-EARegistrationDetails | Out-Null } catch { $regError = $_.Exception.Message }

    $disabledLicensed = @($users | Where-Object { -not $_.AccountEnabled -and @($_.AssignedLicenses).Count -gt 0 })
    # Entra Connect sets DisablePasswordExpiration on every synced user by default (expiry is
    # governed by on-prem AD), so only enabled cloud-only accounts count toward the finding.
    $neverExpireAll   = @($users | Where-Object { $_.PasswordPolicies -and $_.PasswordPolicies -match 'DisablePasswordExpiration' })
    $neverExpire      = @($neverExpireAll | Where-Object { $_.AccountEnabled -and -not $_.OnPremisesSyncEnabled })
    $neverExpireSkipped = $neverExpireAll.Count - $neverExpire.Count
    $weakPwPolicy     = @($users | Where-Object { $_.PasswordPolicies -and $_.PasswordPolicies -match 'DisableStrongPassword' })
    $rows = $users | Select-Object UserPrincipalName, DisplayName, AccountEnabled, UserType,
        @{n='Licensed';e={ @($_.AssignedLicenses).Count -gt 0 }},
        @{n='PasswordPolicies';e={ $_.PasswordPolicies }},
        @{n='Synced';e={ [bool]$_.OnPremisesSyncEnabled }}, CreatedDateTime
    $notes = @()
    if ($regError) { $notes += ("The MFA registration report could not be read ({0}); MFA capability of accounts with non-expiring passwords is unknown." -f $regError) }
    $src = Write-Evidence -BaseName 'accounts' -Rows $rows -Title 'Account Hygiene' -Notes $notes

    # Manager: when the shared user cache already expanded manager (UsersCacheHasManager),
    # evaluate it in memory; otherwise resolve it in one expanded, paged GET rather than one
    # request per user. The separate read keeps a tenant/API that rejects the expansion from
    # losing every user-based check - it only loses this sub-check (reported, not hidden).
    $managerKnown = $true; $managerError = $null; $managerRows = @()
    try {
        $managerUsers = if ($script:UsersCacheHasManager) { $users } else {
            @(Get-MgUser -All -Property 'id,userPrincipalName,displayName,accountEnabled,userType' -ExpandProperty 'manager($select=id)' -ErrorAction Stop)
        }
        $managerRows = @(foreach ($mu in $managerUsers) {
            if (-not $mu.AccountEnabled -or $mu.UserType -eq 'Guest') { continue }
            $manager = Get-EAField $mu 'Manager'; if ($null -eq $manager) { $manager = Get-Ap $mu 'manager' }
            $managerId = if ($manager) { Get-EAField $manager 'Id' } else { $null }; if ($null -eq $managerId -and $manager) { $managerId = Get-EAField $manager 'id' }
            [pscustomobject]@{ UserPrincipalName=$mu.UserPrincipalName; DisplayName=$mu.DisplayName; Enabled=[bool]$mu.AccountEnabled; HasManager=[bool]$managerId }
        })
    } catch { $managerKnown = $false; $managerError = $_.Exception.Message }
    $noManager = @($managerRows | Where-Object { -not $_.HasManager })
    $managerSrc = $null
    if ($managerRows.Count -gt 0) { $managerSrc = Write-Evidence -BaseName 'account_managers' -Rows $managerRows -Title 'Enabled Member Manager Coverage' }

    if ($disabledLicensed.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-disabled-with-licenses' `
            -Title ((Format-EACount -Count $disabledLicensed.Count -One 'disabled account still has' -Many 'disabled accounts still have') + ' licences assigned') `
            -Evidence ("{0} disabled account(s) with assignedLicenses. First {1}: {2}" -f $disabledLicensed.Count, [Math]::Min(10, $disabledLicensed.Count), (($disabledLicensed | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Licences on disabled accounts cost money, and if such an account is switched back on it immediately gets its mail, files and apps back. Licences may also come from group membership.' `
            -RecommendedAction 'Remove the licences from disabled accounts as part of the leaver process (Microsoft 365 admin center > Users > Active users, or remove the account from the licensing group when the licence comes from a group).' `
            -SourceFile $src -ResultRows @($disabledLicensed | Select-Object UserPrincipalName,DisplayName,AccountEnabled)
    }
    if ($neverExpire.Count -gt 0) {
        $noMfaNeverExpire = @($neverExpire | Where-Object { $_.Id -and $script:MfaCapableById.ContainsKey($_.Id) -and -not $script:MfaCapableById[$_.Id] })
        $sev = if ($noMfaNeverExpire.Count -gt 0) { 'High' } else { 'Medium' }
        $mfaText = if ($regError) { 'MFA capability could not be checked (registration report unreadable), so these accounts could not be rated High' }
                   else { ('{0} of them cannot use multifactor authentication (not MFA-capable)' -f $noMfaNeverExpire.Count) }
        Add-EntraFinding -Severity $sev -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-password-never-expires' `
            -Title (Format-EACount -Count $neverExpire.Count -One 'enabled cloud account has a password that never expires' -Many 'enabled cloud accounts have passwords that never expire') `
            -Evidence ("PasswordPolicies=DisablePasswordExpiration on {0} enabled cloud-only account(s); {1}. {2} synced or disabled account(s) with the same flag are not counted (synced accounts follow the on-premises AD password policy). First {3}: {4}" -f $neverExpire.Count, $mfaText, $neverExpireSkipped, [Math]::Min(10, $neverExpire.Count), (($neverExpire | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'These accounts are exempt from the tenant password policy, usually because they are service or shared accounts. A password that never changes stays valid for years if it leaks, and without multifactor authentication (MFA) that password alone is enough to sign in.' `
            -RecommendedAction 'Make sure each of these accounts is protected by MFA (for service accounts, move to managed identities or certificate sign-in instead of passwords), then remove the per-account never-expire exception.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy' `
            -SourceFile $src -ResultRows @($neverExpire | Select-Object UserPrincipalName,DisplayName,PasswordPolicies)
        if ($regError) {
            Add-EntraFinding -Severity 'Information' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-password-never-expires-mfa-unknown' -CoverageGap `
                -Title 'MFA status of accounts with never-expiring passwords could not be checked' `
                -Evidence ("The MFA registration report could not be read: {0}. {1} account(s) with non-expiring passwords were rated Medium; any of them without MFA would make the finding High." -f $regError, $neverExpire.Count) `
                -WhyItMatters 'A never-expiring password without multifactor authentication (MFA) is the higher-risk case. Because MFA could not be checked, the rating may be too low.' `
                -RecommendedAction 'Grant AuditLog.Read.All to the audit account or app and run the check again.' `
                -SourceFile $src
        }
    }
    if ($weakPwPolicy.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-strong-password-disabled' `
            -Title ((Format-EACount -Count $weakPwPolicy.Count -One 'account is' -Many 'accounts are') + ' allowed to use weak passwords') `
            -Evidence ("PasswordPolicies=DisableStrongPassword on {0} account(s) ({1} enabled). First {2}: {3}" -f $weakPwPolicy.Count, @($weakPwPolicy | Where-Object { $_.AccountEnabled }).Count, [Math]::Min(10, $weakPwPolicy.Count), (($weakPwPolicy | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'These accounts skip the password complexity rules, so short or simple passwords that are easy to guess are accepted.' `
            -RecommendedAction 'Remove the DisableStrongPassword flag from these accounts and use Microsoft Entra Password Protection (banned-password list).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy' `
            -SourceFile $src -ResultRows @($weakPwPolicy | Select-Object UserPrincipalName,PasswordPolicies)
    }
    if (-not $managerKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-manager-unknown' -CoverageGap `
            -Title 'Could not check which accounts have a manager' `
            -Evidence ("Reading users with their manager failed: {0}. Accounts without a manager are unknown, not confirmed absent." -f $managerError) `
            -WhyItMatters 'The manager field is used by access reviews and joiner/mover/leaver processes to decide who approves or removes access.' `
            -RecommendedAction 'Verify User.Read.All for the audit account or app and run the check again, or review manager assignments manually.' -SourceFile $src
    } elseif ($noManager.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-no-manager' `
            -Title ((Format-EACount -Count $noManager.Count -One 'enabled member account has' -Many 'enabled member accounts have') + ' no manager set') `
            -Evidence ("Enabled non-guest users without a manager: {0} of {1}. First {2}: {3}" -f $noManager.Count, $managerRows.Count, [Math]::Min(10, $noManager.Count), (($noManager | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Without a manager, nobody is clearly responsible for approving or removing the account''s access, so access reviews and leaver processes can miss it.' `
            -RecommendedAction 'Set a manager on workforce accounts (usually from the HR system) and document the accepted exceptions such as top executives and service accounts.' `
            -SourceFile $managerSrc -ResultRows $noManager
    }
    # Synced vs cloud-only baseline
    $synced = @($users | Where-Object { $_.OnPremisesSyncEnabled }).Count
    Add-EntraFinding -Severity 'Information' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-population-overview' `
        -Title 'Account population overview' `
        -Evidence ("Total users: {0}; enabled: {1}; synced from on-premises: {2}; cloud-only: {3}; guests: {4}" -f `
            $users.Count, @($users | Where-Object { $_.AccountEnabled }).Count, $synced, ($users.Count - $synced), @($users | Where-Object { $_.UserType -eq 'Guest' }).Count) `
        -WhyItMatters 'How many accounts the tenant has and how many come from on-premises Active Directory - background for the rest of the report.' `
        -RecommendedAction 'No action needed - background information.' -SourceFile $src
}

# ===========================================================================
# CHECK 5 - staleusers
# ===========================================================================
function Invoke-Check-StaleUsers {
    $privDays = [Math]::Min($InactiveDays, 45)   # admins held to <= 45 days
    $noSignInData = {
        param([string]$Reason)
        $s = Write-Evidence -BaseName 'stale_users' -Rows @() -Title ("Stale / Inactive Users (> {0} days)" -f $InactiveDays) -Notes @($Reason)
        Add-EntraFinding -Severity 'Information' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-signin-data-unavailable' -CoverageGap `
            -Title 'Inactive accounts could not be checked - sign-in dates are not available' `
            -Evidence $Reason `
            -WhyItMatters 'Without last-sign-in dates the audit cannot find unused or forgotten accounts, so this is a gap in the audit, not a clean result.' `
            -RecommendedAction 'Grant AuditLog.Read.All to the audit account or app (the tenant also needs Microsoft Entra ID P1 or P2) and run the check again.' -SourceFile $s
    }
    if (-not (Test-MgScope @('AuditLog.Read.All') -Quiet)) {
        & $noSignInData 'Last-sign-in data (signInActivity) needs the AuditLog.Read.All permission and a Microsoft Entra ID P1 licence; the permission is missing.'
        return
    }
    $users = Get-EAUsers -IncludeSignInActivity
    # Without signInActivity every account would look "never signed in" - a false flood.
    # Get-EAUsers only returns sign-in data when the P1 + AuditLog gate is met.
    if (-not $script:UsersCacheHasSignIn) {
        & $noSignInData ('The user list was read without signInActivity (Entra ID P1 detected: {0}; licence state known: {1}), so last-sign-in dates are not available.' -f $script:HasP1, $script:LicenseKnown)
        return
    }

    # Privileged principals get a tighter inactivity bar (escalated severity).
    # Shared assignment cache (one Graph download per run instead of a private re-fetch).
    # A THROW from the helper (e.g. the role-definition read 403s before the helper's own
    # failure tracking runs) must count as an incomplete classification, not as "no admins".
    $privIds = @{}; $privXrefError = $null
    try { foreach ($id in @((Get-EAPrivilegedUserMap).Keys)) { $privIds[[string]$id] = $true } } catch { $privXrefError = $_.Exception.Message }
    $privCoverageIncomplete = ([bool]$privXrefError -or $script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)

    $now0      = (Get-Date).ToUniversalTime()
    $cut       = $now0.AddDays(-$InactiveDays)
    $cut180    = $now0.AddDays(-180)
    $created30 = $now0.AddDays(-30)
    $privCut   = $now0.AddDays(-$privDays)

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
            Privileged              = [bool]($u.Id -and $privIds.ContainsKey([string]$u.Id))
            Created                 = $u.CreatedDateTime
            LastSuccessfulOrAttempt = $eff
            Confidence              = $conf
        }
    })
    $notes = @('Activity prefers lastSuccessfulSignInDateTime. Confidence "AttemptOnly" = only failed/attempted sign-ins were recorded (no successful sign-in).')
    if ($privXrefError) { $notes += ("Admin accounts could not be identified: {0}. Privileged is false for everyone." -f $privXrefError) }
    $src = Write-Evidence -BaseName 'stale_users' -Rows $rows -Title ("Stale / Inactive Users (> {0} days)" -f $InactiveDays) -Notes $notes

    if ($privCoverageIncomplete) {
        $what = if ($privXrefError) { ('The admin list could not be built at all ({0}), so every account was judged with the normal {1}-day rule instead of the {2}-day admin rule.' -f $privXrefError, $InactiveDays, $privDays) }
                else { ('Active or eligible role assignments, or the members of a group that holds an admin role, could not be fully read, so some admins were judged with the normal {0}-day rule instead of the {1}-day admin rule.' -f $InactiveDays, $privDays) }
        Add-EntraFinding -Severity 'Information' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-admin-classification-incomplete' -CoverageGap `
            -Title 'Unused admin accounts could not be fully identified' `
            -Evidence $what `
            -WhyItMatters 'Unused admin accounts are rated High and held to a stricter limit. Admins the audit could not recognise may be missing from that finding.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory and GroupMember.Read.All (or Directory.Read.All) to the audit account or app and run the check again.' `
            -SourceFile $src
    }

    # Never-seen admins only count once the account is older than the 30-day grace window,
    # matching the non-privileged rule - a GA created yesterday is not a dormant admin.
    $privStale  = @($rows | Where-Object { $_.Privileged -and $_.Enabled -and ((($_.Confidence -eq 'NeverSeen') -and $_.Created -and $_.Created -lt $created30) -or ($_.Confidence -ne 'NeverSeen' -and $_.LastSuccessfulOrAttempt -lt $privCut)) })
    $never      = @($rows | Where-Object { -not $_.Privileged -and $_.Confidence -eq 'NeverSeen' -and $_.Enabled -and $_.Created -and $_.Created -lt $created30 })
    $stale      = @($rows | Where-Object { -not $_.Privileged -and $_.Confidence -ne 'NeverSeen' -and $_.Enabled -and $_.LastSuccessfulOrAttempt -lt $cut })
    $stale180   = @($stale | Where-Object { $_.LastSuccessfulOrAttempt -lt $cut180 })
    $attemptOnly= @($rows | Where-Object { -not $_.Privileged -and $_.Confidence -eq 'AttemptOnly' -and $_.Enabled -and $_.LastSuccessfulOrAttempt -lt $cut })

    if ($privStale.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-inactive-admins' `
            -Title ((Format-EACount -Count $privStale.Count -One 'admin account has' -Many 'admin accounts have') + (' not signed in for over {0} days (or never)' -f $privDays)) `
            -Evidence ("Enabled admin accounts with no successful sign-in in the last {0} days, or never (accounts older than 30 days): {1}. First {2}: {3}" -f $privDays, $privStale.Count, [Math]::Min(10, $privStale.Count), (($privStale | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'An admin account that nobody uses still has its admin rights. Nobody notices if someone else signs in with it, which makes it an ideal target for attackers.' `
            -RecommendedAction 'Confirm whether each admin role is still needed; remove it or make it PIM-eligible (just-in-time), or disable the account. Investigate any admin account that has never signed in successfully.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
            -SourceFile $src -ResultRows @($privStale | Select-Object UserPrincipalName,LastSuccessfulOrAttempt,Confidence)
    }
    if ($stale.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-inactive-accounts' `
            -Title ((Format-EACount -Count $stale.Count -One 'enabled account has' -Many 'enabled accounts have') + (' not signed in for over {0} days' -f $InactiveDays)) `
            -Evidence ("{0} enabled non-admin accounts have no successful sign-in for over {1} days ({2} of them for over 180 days)." -f $stale.Count, $InactiveDays, $stale180.Count) `
            -WhyItMatters 'Unused but enabled accounts are easy targets for password-guessing attacks, and a break-in is unlikely to be noticed because nobody uses the account.' `
            -RecommendedAction 'Confirm with the owners, disable accounts that are no longer needed, and delete them after your retention period.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
            -SourceFile $src -ResultRows @($stale | Select-Object UserPrincipalName,LastSuccessfulOrAttempt,Confidence | Sort-Object LastSuccessfulOrAttempt)
    }
    if ($never.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-never-signed-in' `
            -Title ((Format-EACount -Count $never.Count -One 'enabled account has' -Many 'enabled accounts have') + ' never signed in successfully') `
            -Evidence ("{0} enabled non-admin accounts older than 30 days have no successful sign-in on record." -f $never.Count) `
            -WhyItMatters 'Accounts that were never used are often provisioning mistakes or forgotten accounts, and can be taken over and used as a hidden way in.' `
            -RecommendedAction 'Check whether each account is still needed; disable and remove the ones that are not.' `
            -SourceFile $src -ResultRows @($never | Select-Object UserPrincipalName,Created)
    }
    if ($attemptOnly.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-attempts-only' `
            -Title (Format-EACount -Count $attemptOnly.Count -One 'unused account shows only failed sign-in attempts' -Many 'unused accounts show only failed sign-in attempts') `
            -Evidence ("{0} enabled accounts have sign-in attempts but no successful sign-in within {1} days - possible password-guessing on otherwise unused accounts." -f $attemptOnly.Count, $InactiveDays) `
            -WhyItMatters 'Failed attempts can make an unused account look active, and they may mean someone is trying to guess its password.' `
            -RecommendedAction 'Treat these accounts as unused (disable them if not needed) and review their sign-in logs for attack attempts (Entra admin center > Monitoring & health > Sign-in logs).' `
            -SourceFile $src -ResultRows @($attemptOnly | Select-Object UserPrincipalName,LastSuccessfulOrAttempt,Confidence)
    }
}

# ===========================================================================
# CHECK 6 - guests
# ===========================================================================
function Invoke-Check-Guests {
    $users = @(Get-EAUsers)
    $guestUsers = @($users | Where-Object { $_.UserType -eq 'Guest' })

    # Privileged guests: cross-reference active AND eligible role assignments (including roles
    # held through groups) via the shared map, which also tracks fetch failure so silence here
    # is never mistaken for "no privileged guests". A THROW from the helper (e.g. the role-
    # definition read 403s before its own failure tracking) counts as a failed cross-reference.
    $privGuests = @(); $privXrefError = $null
    try {
        $privMap = Get-EAPrivilegedUserMap
        foreach ($uid in @($privMap.Keys)) {
            if (-not $script:UserById.ContainsKey($uid)) { continue }
            $pu = $script:UserById[$uid]
            if ($pu.UserType -ne 'Guest' -and [string]$pu.UserPrincipalName -notlike '*#EXT#*') { continue }
            # foreach, not @(): the map values are PSObject-wrapped Lists (see privileged-roles).
            $via = @(foreach ($v in $privMap[$uid]) { $v })
            # Standing = an active assignment that is not a just-in-time activation; a role
            # that must be activated first (PIM-eligible) is the lesser case.
            $standingVia = @($via | Where-Object { $_.State -eq 'Active' -and [string]$_.ActivationModel -ne 'TimeBound-Active-JIT' })
            $roleRows = @($via | ForEach-Object {
                $how = if ($_.State -eq 'Eligible') { 'eligible (PIM)' }
                       elseif ([string]$_.ActivationModel -eq 'TimeBound-Active-JIT') { 'activated just-in-time' }
                       elseif ([string]$_.ActivationModel -eq 'TimeBound-Assigned') { 'active, time-bound' }
                       else { 'permanent' }
                [pscustomobject]@{
                    Guest = $pu.UserPrincipalName; Role = $_.RoleName; Assignment = $how
                    Through = $(if ($_.PrincipalType -eq 'group') { 'group ' + ($_.PrincipalName ?? $_.PrincipalId) } else { 'direct' })
                    DirectoryScopeId = $_.DirectoryScopeId
                }
            })
            $privGuests += [pscustomobject]@{
                Id = [string]$uid; UserPrincipalName = $pu.UserPrincipalName; Enabled = [bool]$pu.AccountEnabled
                Standing = ($standingVia.Count -gt 0); RoleRows = $roleRows
                RoleText = (@($roleRows | ForEach-Object { '{0} ({1}, {2})' -f $_.Role, $_.Assignment, $_.Through }) | Sort-Object -Unique) -join '; '
            }
        }
    } catch { $privXrefError = $_.Exception.Message }
    $privXrefIncomplete = ([bool]$privXrefError -or $script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)

    # Guest invitation / guest-permission settings. A failed read is a coverage gap: these
    # two rules are evaluated ONLY here, so silence would read as "settings are fine".
    $authz = $null; $authzError = $null
    try { $authz = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop | Select-Object -First 1 } catch { $authzError = $_.Exception.Message }
    if (-not $authz -and -not $authzError) { $authzError = 'the authorization policy read returned no object' }

    $rows = $guestUsers | Select-Object UserPrincipalName, DisplayName, AccountEnabled, CreatedDateTime,
        @{n='ExternalUserState';e={ $_.ExternalUserState }},
        @{n='StateChanged';e={ $_.ExternalUserStateChangeDateTime }}
    $notes = @()
    if ($authz) { $notes += ("AllowInvitesFrom: {0}" -f $authz.AllowInvitesFrom); $notes += ("GuestUserRoleId: {0}" -f $authz.GuestUserRoleId) }
    else { $notes += ("The authorization policy (guest invitation and guest permission settings) could not be read: {0}" -f $authzError) }
    if ($privXrefError) { $notes += ("Guests holding admin roles could not be checked: {0}" -f $privXrefError) }
    $src = Write-Evidence -BaseName 'guests' -Rows $rows -Title 'Guest / External Users' -Notes $notes

    foreach ($g in @($privGuests | Sort-Object UserPrincipalName)) {
        if ($g.Standing) {
            # Critical, the same rating the privileged-roles check gives a guest with a
            # standing admin role, so the two checks never disagree about the same guest.
            Add-EntraFinding -Severity 'Critical' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-admin-role-standing' `
                -Title ("Guest account holds an active admin role: {0}" -f $g.UserPrincipalName) `
                -Evidence ("Guest {0} (object id {1}, enabled: {2}) holds: {3}." -f $g.UserPrincipalName, $g.Id, $g.Enabled, $g.RoleText) `
                -WhyItMatters 'A guest account is controlled by another organization: you do not manage its password, multifactor authentication (MFA) or when it is removed. With an admin role that is already active (no activation step), a break-in at the other organization gives the attacker admin rights in yours.' `
                -RecommendedAction 'Remove the admin role from the guest. If an external person must administer the tenant, give them a member account that your own policies control, with a PIM-eligible (just-in-time) role (Entra admin center > Entra ID > Roles & admins).' `
                -SourceFile $src -AffectedPrincipal $g.UserPrincipalName -ObjectType 'user' -ObjectId $g.Id -ResultRows $g.RoleRows
        } else {
            Add-EntraFinding -Severity 'High' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-admin-role-eligible' `
                -Title ("Guest account can switch on an admin role: {0}" -f $g.UserPrincipalName) `
                -Evidence ("Guest {0} (object id {1}, enabled: {2}) is eligible for or has activated: {3}." -f $g.UserPrincipalName, $g.Id, $g.Enabled, $g.RoleText) `
                -WhyItMatters 'A guest account is controlled by another organization: you do not manage its password, multifactor authentication (MFA) or when it is removed. It can switch the admin role on whenever it needs it.' `
                -RecommendedAction 'Remove the admin role from the guest. If an external person must administer the tenant, give them a member account that your own policies control (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles).' `
                -SourceFile $src -AffectedPrincipal $g.UserPrincipalName -ObjectType 'user' -ObjectId $g.Id -ResultRows $g.RoleRows
        }
    }
    if ($privXrefIncomplete) {
        # Reported whenever the cross-reference is incomplete - also when some privileged
        # guests WERE found, because the list itself may then be incomplete.
        $what = if ($privXrefError) { ('The admin-role list could not be read: {0}.' -f $privXrefError) }
                else { 'Active or eligible role assignments, or the members of a group that holds an admin role, could not be fully read.' }
        Add-EntraFinding -Severity 'Information' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-admin-role-check-incomplete' -CoverageGap `
            -Title 'Could not fully check whether guests hold admin roles' `
            -Evidence ("{0} Guests with admin roles found so far: {1}. Others may be missing - this is not a clean result." -f $what, $privGuests.Count) `
            -WhyItMatters 'A guest with an admin role is a High or Critical finding. If the role list cannot be read, such guests stay hidden.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory and GroupMember.Read.All (or Directory.Read.All) to the audit account or app (or retry after throttling) and run the check again.' `
            -SourceFile $src
    }
    if ($authz) {
        if ($authz.GuestUserRoleId -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') {
            Add-EntraFinding -Severity 'High' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-same-permissions-as-members' `
                -Title 'Guests can see the directory just like employees' `
                -Evidence 'guestUserRoleId = a0b1b346-4d3e-4e8b-98f8-753987be4970 ("Guest users have the same access as members").' `
                -WhyItMatters 'Every invited outsider can list your users, groups, apps and admin roles - a ready-made map for phishing and attacks.' `
                -RecommendedAction 'Set guest user access to "Guest user access is restricted to properties and memberships of their own directory objects" (Entra admin center > Entra ID > External Identities > External collaboration settings).' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions' `
                -SourceFile $src
        }
        if ($authz.AllowInvitesFrom -in @('everyone','adminsGuestInvitersAndAllMembers')) {
            $inviteTitle = if ($authz.AllowInvitesFrom -eq 'everyone') { 'Anyone in the tenant, including guests, can invite new guests' } else { 'Any member user can invite guests' }
            Add-EntraFinding -Severity 'Medium' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-anyone-can-invite' `
                -Title $inviteTitle `
                -Evidence ("allowInvitesFrom = {0}" -f $authz.AllowInvitesFrom) `
                -WhyItMatters 'When anyone can invite outsiders, external accounts get added without review, which widens the attack surface and makes it easier for a phishing attacker to get a foothold.' `
                -RecommendedAction 'Limit guest invitations to admins and users with the Guest Inviter role (Entra admin center > Entra ID > External Identities > External collaboration settings > Guest invite settings).' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure' `
                -SourceFile $src
        }
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-settings-unknown' -CoverageGap `
            -Title 'Could not read who may invite guests or what guests can see' `
            -Evidence ("Reading the authorization policy failed: {0}. The guest-invitation (allowInvitesFrom) and guest-permission (guestUserRoleId) settings are unknown, not confirmed safe." -f $authzError) `
            -WhyItMatters 'These two settings decide whether outsiders can be invited freely and how much of your directory they can see. They were not checked.' `
            -RecommendedAction 'Grant Policy.Read.All to the audit account or app and run the check again.' `
            -SourceFile $src
    }
    $now0 = (Get-Date).ToUniversalTime()
    # Pending since the last state change; an invitation with no state-change time falls back
    # to the account's creation time instead of being silently skipped.
    $pending = @($guestUsers | Where-Object { $_.ExternalUserState -eq 'PendingAcceptance' } | ForEach-Object {
        $since = if ($_.ExternalUserStateChangeDateTime) { [datetime]$_.ExternalUserStateChangeDateTime } elseif ($_.CreatedDateTime) { [datetime]$_.CreatedDateTime } else { $null }
        [pscustomobject]@{ UserPrincipalName = $_.UserPrincipalName; PendingSince = $since; ExternalUserStateChangeDateTime = $_.ExternalUserStateChangeDateTime; CreatedDateTime = $_.CreatedDateTime }
    })
    $pending90 = @($pending | Where-Object { $_.PendingSince -and $_.PendingSince -lt $now0.AddDays(-90) })
    $pending30 = @($pending | Where-Object { $_.PendingSince -and $_.PendingSince -lt $now0.AddDays(-30) -and $_.PendingSince -ge $now0.AddDays(-90) })
    if ($pending90.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-invite-pending-over-90-days' `
            -Title ((Format-EACount -Count $pending90.Count -One 'guest invitation has' -Many 'guest invitations have') + ' not been accepted for over 90 days') `
            -Evidence ("Guests in PendingAcceptance state for over 90 days: {0}. First {1}: {2}" -f $pending90.Count, [Math]::Min(10, $pending90.Count), (($pending90 | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Invitations that were never accepted are leftover external accounts. They clutter the directory and can hide abandoned or mistaken invitations that someone could still redeem.' `
            -RecommendedAction 'Delete guest accounts whose invitation has not been accepted for over 90 days (Entra admin center > Entra ID > Users, filter on invitation state).' `
            -SourceFile $src -ResultRows @($pending90 | Select-Object UserPrincipalName,PendingSince)
    }
    if ($pending30.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-invite-pending-30-90-days' `
            -Title ((Format-EACount -Count $pending30.Count -One 'guest invitation has' -Many 'guest invitations have') + ' not been accepted for 30-90 days') `
            -Evidence ("Guests in PendingAcceptance state for 30-90 days: {0}." -f $pending30.Count) `
            -WhyItMatters 'Invitations that stay unaccepted this long are usually abandoned and should be cleaned up before they become forgotten accounts.' `
            -RecommendedAction 'Follow up with the inviter, or delete invitations that are no longer needed.' `
            -SourceFile $src -ResultRows @($pending30 | Select-Object UserPrincipalName,PendingSince)
    }
    Add-EntraFinding -Severity 'Information' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-population' `
        -Title ((Format-EACount -Count $guestUsers.Count -One 'guest (external) account' -Many 'guest (external) accounts') + ' in the tenant') `
        -Evidence ("Guest accounts: {0} ({1} enabled); invitations not yet accepted: {2}." -f $guestUsers.Count, @($guestUsers | Where-Object { $_.AccountEnabled }).Count, $pending.Count) `
        -WhyItMatters 'Shows how much the tenant is shared with outside people - background for the other guest findings.' `
        -RecommendedAction 'No action needed - background information.' -SourceFile $src
}

# ===========================================================================
# CHECK 7 - mfa
# ===========================================================================
function Invoke-Check-Mfa {
    $reg = @(Get-EARegistrationDetails)
    # Privileged principals (shared assignment cache - one Graph download per run). A THROW
    # from the helper (e.g. the role-definition read 403s before the helper's own failure
    # tracking runs) must count as an incomplete classification, not as "no admins".
    $privIds = @{}; $privXrefError = $null
    try { foreach ($id in @((Get-EAPrivilegedUserMap).Keys)) { $privIds[[string]$id] = $true } } catch { $privXrefError = $_.Exception.Message }
    $privCoverageIncomplete = ([bool]$privXrefError -or $script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)

    # Disabled accounts are excluded from the risk findings (a disabled account that is not
    # MFA-capable is not a live risk). A failed user read keeps every account "enabled" -
    # the finding can then only be too broad, never falsely clean - and is noted.
    $userById = @{}; $userError = $null
    try { foreach ($u in @(Get-EAUsers)) { if ($u.Id) { $userById[[string]$u.Id] = $u } } } catch { $userError = $_.Exception.Message }

    # Method-strength categories from the registration report's methodsRegistered.
    # Phishing-resistant: FIDO2 / Windows Hello / passkeys / certificate-based.
    # Strong (not phishing-resistant): Authenticator app / OTP.
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
        $isPriv = ([bool]$r.IsAdmin -or ($r.Id -and $privIds.ContainsKey([string]$r.Id)))
        $u = if ($r.Id -and $userById.ContainsKey([string]$r.Id)) { $userById[[string]$r.Id] } else { $null }
        $enabled = if ($u) { [bool]$u.AccountEnabled } else { $true }
        # Guests normally satisfy MFA in their HOME tenant and show as not MFA-capable here;
        # userType comes from the report itself, then the user cache, then the #EXT# marker.
        $userType = [string](Get-EAField $r 'UserType')
        if (-not $userType -and $u) { $userType = [string]$u.UserType }
        $isGuest = ($userType -eq 'guest') -or ([string]$r.UserPrincipalName -like '*#EXT#*')
        [pscustomobject]@{
            UserPrincipalName=$r.UserPrincipalName; UserType=$(if ($isGuest) { 'Guest' } elseif ($userType) { 'Member' } else { '' })
            Privileged=$isPriv; Enabled=$enabled
            MfaRegistered=[bool]$r.IsMfaRegistered; MfaCapable=[bool]$r.IsMfaCapable
            StrongMethod=$hasStrong; PhishingResistant=$hasPhish; Methods=($methods -join ',')
        }
    })
    $notes = @('MfaCapable = has registered a strong method that the tenant policy allows. Guests are listed but not counted in the member totals.')
    if ($userError) { $notes += ("The user directory could not be read ({0}); every account is treated as enabled." -f $userError) }
    if ($privXrefError) { $notes += ("Admin accounts could not be identified from role assignments ({0}); only the report's own isAdmin flag was used." -f $privXrefError) }
    $src = Write-Evidence -BaseName 'mfa_registration' -Rows $rows -Title 'MFA Posture - Registered / Capable / Strong / Phishing-Resistant' -Notes $notes

    if ($privCoverageIncomplete) {
        $what = if ($privXrefError) { ('The admin list could not be built ({0}); only accounts the MFA report itself marks as admin were treated as admins.' -f $privXrefError) }
                else { 'Active or eligible role assignments, or the members of a group that holds an admin role, could not be fully read; some admins may be missing from the admin MFA findings.' }
        Add-EntraFinding -Severity 'Information' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-admin-classification-incomplete' -CoverageGap `
            -Title 'MFA of all admin accounts could not be checked - admin list incomplete' `
            -Evidence $what `
            -WhyItMatters 'Admins who can switch a role on just-in-time, or who get it through a group, need the same strong multifactor authentication (MFA) as permanent admins. Missing admins may hide a Critical finding.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory and GroupMember.Read.All (or Directory.Read.All) to the audit account or app and run the check again.' `
            -SourceFile $src
    }

    $priv         = @($rows | Where-Object { $_.Privileged -and $_.Enabled })
    $privNoMfa    = @($priv | Where-Object { -not $_.MfaCapable })
    $privWeakOnly = @($priv | Where-Object { $_.MfaCapable -and -not $_.StrongMethod -and -not $_.PhishingResistant })
    $privNoPhish  = @($priv | Where-Object { $_.MfaCapable -and $_.StrongMethod -and -not $_.PhishingResistant })
    $memberRows   = @($rows | Where-Object { -not $_.Privileged -and $_.Enabled -and $_.UserType -ne 'Guest' })
    $memberNoMfa  = @($memberRows | Where-Object { -not $_.MfaCapable })
    $enabledMembers = @($rows | Where-Object { $_.Enabled -and $_.UserType -ne 'Guest' })
    $enabledGuests  = @($rows | Where-Object { $_.Enabled -and $_.UserType -eq 'Guest' -and -not $_.Privileged })

    if ($privNoMfa.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-admins-without-mfa' `
            -Title ((Format-EACount -Count $privNoMfa.Count -One 'admin account' -Many 'admin accounts') + ' cannot use multifactor authentication (MFA)') `
            -Evidence ("Enabled admin accounts that are not MFA-capable (isMfaCapable = false): {0}. First {1}: {2}" -f $privNoMfa.Count, [Math]::Min(10, $privNoMfa.Count), (($privNoMfa | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'These admins sign in with a password only, because they have no second factor that can be asked for. One phished or leaked password gives an attacker admin control of the tenant.' `
            -RecommendedAction 'Register a phishing-resistant method (FIDO2 security key, Windows Hello for Business or passkey) for each admin, then require it for admins with a Conditional Access authentication strength (Entra admin center > Entra ID > Conditional Access).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa' `
            -SourceFile $src -ResultRows @($privNoMfa | Select-Object UserPrincipalName,MfaCapable,Methods)
    }
    if ($privWeakOnly.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-admins-weak-methods-only' `
            -Title ((Format-EACount -Count $privWeakOnly.Count -One 'admin account only has' -Many 'admin accounts only have') + ' weak MFA methods (text message, phone call or email)') `
            -Evidence ("Admins whose registered methods include no authenticator app, one-time-passcode or phishing-resistant method: {0}. First {1}: {2}" -f $privWeakOnly.Count, [Math]::Min(10, $privWeakOnly.Count), (($privWeakOnly | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Codes sent by text message, phone call or email can be phished or stolen by taking over the phone number (SIM swap). For an admin that means a full account takeover.' `
            -RecommendedAction 'Register FIDO2 security keys, Windows Hello for Business or passkeys for these admins and stop allowing text message and phone call as their sign-in factor.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths' `
            -SourceFile $src -ResultRows @($privWeakOnly | Select-Object UserPrincipalName,Methods)
    }
    if ($privNoPhish.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-admins-not-phishing-resistant' `
            -Title ((Format-EACount -Count $privNoPhish.Count -One 'admin account has' -Many 'admin accounts have') + ' MFA but no phishing-resistant method') `
            -Evidence ("Admins with an authenticator app or one-time passcode but no FIDO2, Windows Hello, passkey or certificate method: {0}. First {1}: {2}" -f $privNoPhish.Count, [Math]::Min(10, $privNoPhish.Count), (($privNoPhish | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'App notifications and one-time codes are much better than a password alone, but a fake sign-in page can still relay them, and repeated push prompts can wear a user down. Admin accounts should use methods that cannot be phished.' `
            -RecommendedAction 'Give all admins FIDO2 security keys, passkeys or Windows Hello for Business and require a phishing-resistant authentication strength for them in Conditional Access.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa' `
            -SourceFile $src -ResultRows @($privNoPhish | Select-Object UserPrincipalName,Methods)
    }
    if ($memberNoMfa.Count -gt 0) {
        $denom = [Math]::Max(1, $memberRows.Count)
        $sev = if (($memberNoMfa.Count / [double]$denom) -gt 0.25) { 'Medium' } else { 'Low' }
        Add-EntraFinding -Severity $sev -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-members-without-mfa' `
            -Title ((Format-EACount -Count $memberNoMfa.Count -One 'enabled non-admin account' -Many 'enabled non-admin accounts') + ' cannot use multifactor authentication (MFA)') `
            -Evidence ("{0} of {1} enabled non-admin member accounts are not MFA-capable ({2}%). {3} enabled guest account(s) are not counted - guests normally use MFA from their own organization." -f $memberNoMfa.Count, $denom, [math]::Round(100 * $memberNoMfa.Count / [double]$denom, 1), $enabledGuests.Count) `
            -WhyItMatters 'Accounts that cannot be asked for a second factor are protected by their password alone, so guessed, sprayed or leaked passwords work.' `
            -RecommendedAction 'Get every enabled user registered for MFA (registration campaign or Conditional Access registration policy) and require MFA for all users with Conditional Access.' `
            -SourceFile $src -ResultRows @($memberNoMfa | Select-Object UserPrincipalName,MfaRegistered,Methods)
    }
    $phishCount = @($enabledMembers | Where-Object { $_.PhishingResistant }).Count
    $prAdopt = if ($enabledMembers.Count) { [math]::Round((100 * $phishCount / $enabledMembers.Count), 1) } else { 0 }
    Add-EntraFinding -Severity 'Information' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-phishing-resistant-adoption' `
        -Title ("Phishing-resistant MFA adoption: {0}% of enabled member accounts" -f $prAdopt) `
        -Evidence ("{0} of {1} enabled member accounts have a phishing-resistant method (FIDO2, Windows Hello, passkey or certificate) registered; {2} enabled admin account(s) reviewed; {3} enabled guest account(s) not counted." -f $phishCount, $enabledMembers.Count, $priv.Count, $enabledGuests.Count) `
        -WhyItMatters 'The share of users with sign-in methods that cannot be phished is the best single measure of how well accounts are protected against phishing.' `
        -RecommendedAction 'Roll out phishing-resistant methods to all admins first, then to everyone else.' -SourceFile $src
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
    $src = Write-Evidence -BaseName 'legacy_auth_signins' -Rows $rows -Title 'Legacy Authentication Sign-ins (last 30 days)' `
        -Notes @('Status 0 = successful sign-in; 53003 = blocked by Conditional Access; any other code = failed for another reason (for example a wrong password).')

    $success = @($signins | Where-Object { $_.Status.ErrorCode -eq 0 })
    $failOnly = @($signins | Where-Object { $_.Status.ErrorCode -ne 0 })

    if ($success.Count -gt 0) {
        $upns = @($success | Select-Object -ExpandProperty UserPrincipalName -Unique)
        Add-EntraFinding -Severity 'High' -CheckId 'legacyauth' -Category 'Authentication' -RuleId 'legacyauth-successful-signins' `
            -Title ((Format-EACount -Count $success.Count -One 'successful sign-in' -Many 'successful sign-ins') + ' used legacy authentication in the last 30 days') `
            -Evidence ("Successful legacy sign-ins by {0} account(s) via {1}. First {2} account(s): {3}" -f $upns.Count, (($success.ClientAppUsed | Select-Object -Unique) -join ', '), [Math]::Min(10, $upns.Count), (($upns | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Legacy authentication (old protocols such as POP, IMAP, SMTP and older Exchange ActiveSync clients) cannot ask for multifactor authentication (MFA). A successful legacy sign-in shows that a password alone still works, which is exactly what password-spray attacks use.' `
            -RecommendedAction 'Block legacy authentication for all users with a Conditional Access policy (Entra admin center > Entra ID > Conditional Access; condition Client apps = Exchange ActiveSync clients + Other clients, grant = Block), after moving the listed users and devices to modern authentication.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication' `
            -SourceFile $src -ResultRows @($success | Select-Object CreatedDateTime,UserPrincipalName,ClientAppUsed | Select-Object -First 50)
    } elseif ($failOnly.Count -gt 0) {
        $caBlocked = @($failOnly | Where-Object { $_.Status.ErrorCode -eq 53003 }).Count
        $codes = ($failOnly | Group-Object { $_.Status.ErrorCode } | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', '
        Add-EntraFinding -Severity 'Low' -CheckId 'legacyauth' -Category 'Authentication' -RuleId 'legacyauth-failed-attempts-only' `
            -Title ('Legacy authentication was tried {0} in 30 days - {1} failed' -f $(if ($failOnly.Count -eq 1) { 'once' } else { '{0} times' -f $failOnly.Count }), $(if ($failOnly.Count -eq 1) { 'the attempt' } else { 'every attempt' })) `
            -Evidence ("{0} failed legacy sign-in attempt(s) by {1} account(s); {2} blocked by Conditional Access (error 53003). Most common error codes: {3}." -f $failOnly.Count, @($failOnly | Select-Object -ExpandProperty UserPrincipalName -Unique).Count, $caBlocked, $codes) `
            -WhyItMatters 'No legacy sign-in succeeded, but devices or attackers are still trying. Failures that are not Conditional Access blocks (for example wrong passwords) do not prove a block exists, and the risk returns if a block is ever removed.' `
            -RecommendedAction 'Confirm a Conditional Access policy blocks legacy authentication for all users, and fix or retire the clients that still try it.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication' `
            -SourceFile $src -ResultRows @($failOnly | Select-Object CreatedDateTime,UserPrincipalName,ClientAppUsed,@{n='Status';e={ $_.Status.ErrorCode }} | Select-Object -First 50)
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId 'legacyauth' -Category 'Authentication' -RuleId 'legacyauth-none-seen' `
            -Title 'No legacy-authentication sign-ins in the last 30 days' `
            -Evidence 'The sign-in logs for the last 30 days contain no sign-ins through legacy protocols.' `
            -WhyItMatters 'No legacy authentication was used in the period the logs cover, which suggests only modern sign-ins (that support MFA) are in use.' `
            -RecommendedAction 'Keep a Conditional Access policy that blocks legacy authentication for all users.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication' -SourceFile $src
    }
}

# ===========================================================================
# CHECK 9 - tenantposture (security defaults, authorization, consent)
# ===========================================================================
function Invoke-Check-TenantPosture {
    # Track read success per source: a swallowed read must not evaluate as "setting is
    # fine" (false clean) or as "zero CA policies" (false High).
    $sd = $null;    $sdError = $null;    try { $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop } catch { $sdError = $_.Exception.Message }
    $authz = $null; $authzError = $null; try { $authz = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop | Select-Object -First 1 } catch { $authzError = $_.Exception.Message }
    $caCount = 0;   $caError = $null;    try { $caCount = @(Get-EACaPolicies | Where-Object { $_.State -eq 'enabled' }).Count } catch { $caError = $_.Exception.Message }
    if (-not $sd -and -not $sdError) { $sdError = 'the read returned no object' }
    if (-not $authz -and -not $authzError) { $authzError = 'the read returned no object' }
    $sdKnown = -not $sdError; $authzKnown = -not $authzError; $caKnown = -not $caError

    $rows = @()
    if ($sd)    { $rows += [pscustomobject]@{ Setting='Security Defaults enabled'; Value=$sd.IsEnabled } }
    if ($caKnown) { $rows += [pscustomobject]@{ Setting='Enabled Conditional Access policies'; Value=$caCount } }
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
    $notes = @()
    if ($sdError)    { $notes += ("Security Defaults could not be read: {0}" -f $sdError) }
    if ($authzError) { $notes += ("Authorization policy could not be read: {0}" -f $authzError) }
    if ($caError)    { $notes += ("Conditional Access policies could not be read: {0}" -f $caError) }
    $src = Write-Evidence -BaseName 'tenant_posture' -Rows $rows -Title 'Security Defaults, Authorization & Consent Settings' -Notes $notes

    if ($sd -and -not $sd.IsEnabled -and $caKnown -and $caCount -eq 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-no-mfa-baseline' `
            -Title 'Security defaults are off and no Conditional Access policy is turned on' `
            -Evidence 'Security Defaults isEnabled = false and 0 Conditional Access policies are in the enabled state.' `
            -WhyItMatters 'Neither security defaults nor Conditional Access (CA) is enforcing multifactor authentication (MFA), so accounts can be signed in to with a password alone - the most common way accounts are taken over.' `
            -RecommendedAction 'Create Conditional Access policies that require MFA (preferred when the tenant has Entra ID P1), or turn on security defaults as a stop-gap (Entra admin center > Entra ID > Overview > Properties > Manage security defaults).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults' -SourceFile $src
    } elseif ($sd -and -not $sd.IsEnabled -and -not $caKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-mfa-baseline-unknown' -CoverageGap `
            -Title 'Could not tell whether MFA is enforced - Conditional Access policies could not be read' `
            -Evidence ("Security Defaults isEnabled = false and the Conditional Access policy read failed: {0}. Whether any baseline MFA enforcement exists is unknown." -f $caError) `
            -WhyItMatters 'With security defaults off, Conditional Access (CA) is the only thing that can enforce multifactor authentication (MFA). Because the policies could not be read, this was not checked.' `
            -RecommendedAction 'Grant Policy.Read.All to the audit account or app and run the check again.' -SourceFile $src
    } elseif ($sd -and $sd.IsEnabled -and $caKnown -and $caCount -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-security-defaults-with-ca' `
            -Title 'Security defaults are on while Conditional Access policies also exist' `
            -Evidence ("Security Defaults isEnabled = true and {0} Conditional Access policies are enabled." -f $caCount) `
            -WhyItMatters 'Security defaults and Conditional Access (CA) are not meant to be used together. Running both suggests the move to CA was never finished, so the fine-grained CA controls may not work as intended.' `
            -RecommendedAction 'Finish the move to Conditional Access: make sure CA policies cover MFA and block legacy authentication, then turn security defaults off.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults' -SourceFile $src
    }
    if ($authz) {
        if ($authz.DefaultUserRolePermissions.AllowedToCreateApps) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-users-can-register-apps' `
                -Title 'Any user can register applications' `
                -Evidence 'defaultUserRolePermissions.allowedToCreateApps = true.' `
                -WhyItMatters 'Every user can create app registrations that nobody reviews. Such apps can be used for phishing that asks for consent to data, or grow into unmanaged "shadow IT".' `
                -RecommendedAction 'Set "Users can register applications" to No (Entra admin center > Entra ID > Users > User settings) and route app registration through a request and approval process.' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions' -SourceFile $src
        }
        if ($authz.AllowEmailVerifiedUsersToJoinOrganization) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-email-verified-self-join' `
                -Title 'People can join the tenant themselves by verifying an email address' `
                -Evidence 'allowEmailVerifiedUsersToJoinOrganization = true.' `
                -WhyItMatters 'Anyone with an email address on one of your domains can create an account in the tenant without being invited or approved.' `
                -RecommendedAction 'Turn off email-verified self-service sign-up unless it is explicitly needed.' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/users/directory-self-service-signup' -SourceFile $src
        }
        $pg = @($authz.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)
        if ($pg -match 'legacy') {
            Add-EntraFinding -Severity 'High' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-user-consent-legacy' `
                -Title 'Users can give any application access to their data' `
                -Evidence ("permissionGrantPoliciesAssigned = {0} (the legacy, unrestricted user-consent policy)." -f ($pg -join ',')) `
                -WhyItMatters 'With unrestricted user consent, a phishing app only needs one click from a user to get lasting access to that user''s mail and files - no password needed.' `
                -RecommendedAction 'Allow user consent only for apps from verified publishers asking for low-risk permissions (or not at all), and turn on the admin consent request workflow (Entra admin center > Entra ID > Enterprise apps > Consent and permissions).' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent' -SourceFile $src
        }
    }
    if (-not $sdKnown -or -not $authzKnown) {
        $failed = @()
        if (-not $sdKnown) { $failed += ('Security Defaults setting ({0})' -f $sdError) }
        if (-not $authzKnown) { $failed += ('authorization policy - app registration, self-service sign-up and user consent ({0})' -f $authzError) }
        if (-not $sdKnown -and -not $caKnown) { $failed += ('Conditional Access policies ({0})' -f $caError) }
        Add-EntraFinding -Severity 'Information' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-settings-unreadable' -CoverageGap `
            -Title 'Some tenant security settings could not be read' `
            -Evidence ("Could not read: {0}. These settings are unknown, not confirmed safe." -f ($failed -join '; ')) `
            -WhyItMatters 'The unread settings decide basic protections such as MFA enforcement and who may register or consent to apps. They were not checked.' `
            -RecommendedAction 'Grant Policy.Read.All to the audit account or app and run the check again.' -SourceFile $src
    } elseif ($script:Findings.Where({$_.CheckId -eq 'tenantposture'}).Count -eq 0) {
        # State only what was read: an enabled CA policy does not by itself prove MFA is
        # required (it may only block a country) - that is the capolicies check's job.
        $baseline = if ($sd.IsEnabled) { 'Security defaults are turned on.' }
                    elseif ($caCount -eq 1) { '1 Conditional Access policy is turned on (whether it requires MFA is checked separately by the Conditional Access Posture check).' }
                    else { '{0} Conditional Access policies are turned on (whether they require MFA is checked separately by the Conditional Access Posture check).' -f $caCount }
        Add-EntraFinding -Severity 'Information' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-defaults-restrictive' `
            -Title 'Tenant default permissions and consent settings are restrictive' `
            -Evidence ('App registration by users, email-verified self-join and unrestricted user consent are all turned off. {0}' -f $baseline) `
            -WhyItMatters 'Restrictive defaults reduce the risk of consent phishing and unmanaged apps.' `
            -RecommendedAction 'No action needed. Review these settings periodically.' -SourceFile $src
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

    # Security Defaults decide how serious a missing admin-MFA policy is: when ON, administrators
    # are still asked for MFA; when OFF, nothing else in Entra forces it. A failed read stays
    # 'Unknown' - never 'Off' (would inflate severity) and never 'On' (would hide risk).
    $sdState = 'Unknown'; $sdError = $null
    try {
        $sdText = [string](Get-EAField (Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop) 'IsEnabled')
        if ($sdText -eq 'True') { $sdState = 'On' } elseif ($sdText -eq 'False') { $sdState = 'Off' } else { $sdError = 'the IsEnabled value was not returned' }
    } catch { $sdError = $_.Exception.Message }
    $sdSentence = switch ($sdState) {
        'On'    { 'Security Defaults is on, so administrators are still asked for MFA through Security Defaults.' }
        'Off'   { 'Security Defaults is off, so nothing else in Entra forces administrators to use MFA (per-user MFA settings were not checked).' }
        default { ("Security Defaults could not be read ({0}), so it is unknown whether it provides MFA for administrators." -f $sdError) }
    }

    # Emergency-access (break-glass) accounts are the ONLY direct user exclusions a tenant-wide
    # baseline may have. Resolve them explicitly: a failed lookup must not silently turn every
    # break-glass exclusion into a baseline gap, nor be mistaken for "no such user".
    $bg = Normalize-StringList -Values $BreakGlassUpns
    $usersKnown = $true; $usersError = $null
    try { Get-EAUsers | Out-Null } catch { $usersKnown = $false; $usersError = $_.Exception.Message }
    $allowedBgIds = @(); $bgUpnById = @{}; $bgNotFound = @(); $bgLookupFailed = @(); $bgLookupError = $usersError
    if ($bg.Count -gt 0) {
        $idByUpn = @{}
        if ($usersKnown) {
            foreach ($u in @($script:UsersCache)) { if ($u.Id -and $u.UserPrincipalName) { $idByUpn[([string]$u.UserPrincipalName).ToLowerInvariant()] = [string]$u.Id } }
        }
        foreach ($b in $bg) {
            if ($idByUpn.ContainsKey($b)) { $allowedBgIds += $idByUpn[$b]; $bgUpnById[$idByUpn[$b]] = $b; continue }
            if ($usersKnown) { $bgNotFound += $b; continue }
            # The directory list could not be read - look the designated account up on its own (GET).
            try {
                $one = Get-MgUser -UserId $b -Property 'id,userPrincipalName' -ErrorAction Stop
                if ($one -and $one.Id) { $allowedBgIds += [string]$one.Id; $bgUpnById[[string]$one.Id] = $b } else { $bgNotFound += $b }
            } catch {
                $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch { $code = $null }
                if ($code -eq 404 -or "$_" -match 'Request_ResourceNotFound') { $bgNotFound += $b } else { $bgLookupFailed += $b; $bgLookupError = $_.Exception.Message }
            }
        }
    } else {
        Write-Warn2 '  -BreakGlassUpns not supplied: users excluded by name from baseline CA policies cannot be recognised as emergency-access accounts.'
    }
    # True when a directly excluded user COULD be an emergency account the audit was not told about.
    $bgUnconfirmed = ($bg.Count -eq 0) -or ($bgLookupFailed.Count -gt 0)
    $bgWhyUnknown = if ($bg.Count -eq 0) { 'No emergency-access accounts were supplied with -BreakGlassUpns' }
                    else { ("The -BreakGlassUpns account(s) {0} could not be looked up ({1})" -f ($bgLookupFailed -join ', '), $bgLookupError) }
    $bgNote = if ($bg.Count -eq 0) { ' No emergency-access accounts were supplied with -BreakGlassUpns, so emergency accounts are not told apart from other users here.' }
              elseif ($bgLookupFailed.Count -gt 0) { (" The -BreakGlassUpns account(s) {0} could not be looked up ({1}), so they are not told apart from other users here." -f ($bgLookupFailed -join ', '), $bgLookupError) }
              elseif ($bgNotFound.Count -gt 0) { (" These -BreakGlassUpns did not match any user: {0}." -f ($bgNotFound -join ', ')) }
              else { '' }

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
        @{n='SignInRisk';e={ ($_.Conditions.SignInRiskLevels -join ',') }},
        @{n='IncludeLocations';e={ (@(Get-EAField (Get-EAField $_.Conditions 'Locations') 'IncludeLocations') -join ',') }},
        @{n='ExcludeLocations';e={ (@(Get-EAField (Get-EAField $_.Conditions 'Locations') 'ExcludeLocations') -join ',') }},
        Id
    $caNotes = @(
        ('Security Defaults: {0}' -f $(if ($sdState -eq 'Unknown') { "unknown (read failed: $sdError)" } else { $sdState })),
        ('Emergency-access accounts supplied with -BreakGlassUpns: {0} (resolved: {1})' -f $bg.Count, $allowedBgIds.Count)
    )
    $src = Write-Evidence -BaseName 'conditional_access' -Rows $rows -Title 'Conditional Access Policies' -Notes $caNotes
    # Always write the named-location evidence: an empty file must be distinguishable from a failed read.
    $nrows = @($named | Select-Object Id, DisplayName,
        @{n='Trusted';e={ (Get-EAField $_ 'IsTrusted') }},
        @{n='Type';e={ (Get-EAField $_ '@odata.type') }},
        @{n='IpRanges';e={ (@(@(Get-EAField $_ 'IpRanges') | ForEach-Object { Get-EAField $_ 'cidrAddress' } | Where-Object { $_ }) -join ', ') }})
    $nNotes = if ($namedKnown) { @() } else { @("READ FAILED: named locations could not be read ($namedError). This list is unknown, not empty.") }
    Write-Evidence -BaseName 'named_locations' -Rows $nrows -Title 'Named Locations' -Notes $nNotes | Out-Null
    if (-not $namedKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Named locations could not be read, so location-based rules were not fully checked' `
            -Evidence ("Reading named locations failed: {0}. Locations excluded from policies could not be matched to trusted networks." -f $namedError) `
            -WhyItMatters 'Without the list of named locations the audit cannot tell whether a location excluded from a policy is a trusted company network or a loophole.' `
            -RecommendedAction 'Check that the audit account has Policy.Read.All (and a role that can read Conditional Access), then re-run the capolicies check.' `
            -SourceFile $src -RuleId 'capolicies-named-location-coverage-unknown' -ObjectType 'tenant' -CoverageGap `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network'
    }

    $enabled = @($pols | Where-Object { $_.State -eq 'enabled' })

    function _GrantBlocks($p) { return (@($p.GrantControls.BuiltInControls) -contains 'block') }
    # True when the grant is OR and offers a choice outside $controls: another built-in control, an
    # authentication strength, terms of use or a custom control. Any of these lets a user satisfy
    # the policy WITHOUT the controls being tested, so they are not mandatory.
    function _GrantHasOtherOrChoice($p, [string[]]$controls) {
        $g = $p.GrantControls
        if ([string](Get-EAField $g 'Operator') -notmatch '^(?i)OR$') { return $false }
        if (@(@(Get-EAField $g 'BuiltInControls') | Where-Object { $_ -and [string]$_ -notin $controls }).Count -gt 0) { return $true }
        if (Get-EAField (Get-EAField $g 'AuthenticationStrength') 'Id') { return $true }
        if (@(@(Get-EAField $g 'TermsOfUse') | Where-Object { $_ }).Count -gt 0) { return $true }
        return (@(@(Get-EAField $g 'CustomAuthenticationFactors') | Where-Object { $_ }).Count -gt 0)
    }
    function _GrantRequiresBuiltIn($p, [string]$control) {
        $built = @($p.GrantControls.BuiltInControls | Where-Object { $_ })
        if ($built -notcontains $control) { return $false }
        return -not (_GrantHasOtherOrChoice $p @($control))
    }
    # A trusted device is mandatory when the grant requires a compliant device and/or a hybrid-joined
    # device with no weaker OR alternative. Microsoft's own template "Require compliant or hybrid
    # joined device" (compliantDevice OR domainJoinedDevice) therefore qualifies; "... or MFA",
    # "... or an authentication strength" and "... or terms of use / a custom control" do not.
    function _GrantRequiresDeviceTrust($p) {
        $built = @($p.GrantControls.BuiltInControls | Where-Object { $_ })
        $deviceControls = @('compliantDevice','domainJoinedDevice')
        if (@($built | Where-Object { $_ -in $deviceControls }).Count -eq 0) { return $false }
        return -not (_GrantHasOtherOrChoice $p $deviceControls)
    }
    function _HasMfaGrant($p) {
        $strength = Get-EAField $p.GrantControls 'AuthenticationStrength'
        return ((@($p.GrantControls.BuiltInControls) -contains 'mfa') -or [bool](Get-EAField $strength 'Id'))
    }
    function _UniversalResourcePolicy($p, [string[]]$ignore = @()) {
        return ((Test-CaPolicyTargetsAllResources $p) -and -not (Test-CaPolicyHasNarrowingConditions $p $ignore))
    }
    function _UserLabel([string]$id) {
        if ($script:UserById -and $script:UserById.ContainsKey($id) -and $script:UserById[$id].UserPrincipalName) { return [string]$script:UserById[$id].UserPrincipalName }
        if ($bgUpnById.ContainsKey($id)) { return [string]$bgUpnById[$id] }
        return $id
    }
    function _ListText([object[]]$items, [int]$max = 10) {
        $all = @($items | Where-Object { $_ })
        $shown = @($all | Select-Object -First $max)
        $text = $shown -join ', '
        if ($all.Count -gt $shown.Count) { $text += (' (+{0} more)' -f ($all.Count - $shown.Count)) }
        return $text
    }

    # Evaluate one tenant-wide baseline. $Match tests everything except WHO the policy covers
    # (grant, resources, narrowing conditions). A match that covers all users (direct exclusions
    # only for the designated break-glass accounts) satisfies the baseline. A match that fails
    # ONLY because of users excluded by name is kept as a candidate, so the report can name those
    # users - or say the baseline could not be confirmed when no break-glass list was supplied.
    function _EvaluateBaseline([scriptblock]$Match) {
        $ok = @(); $candidates = @()
        foreach ($p in $enabled) {
            if (-not (& $Match $p)) { continue }
            if (Test-CaPolicyTargetsAllUsers $p $allowedBgIds) { $ok += $p; continue }
            $direct = @($p.Conditions.Users.ExcludeUsers | Where-Object { $_ -and $_ -ne 'None' } | ForEach-Object { [string]$_ })
            # Only real object ids qualify ('GuestsOrExternalUsers' is a broad exclusion, not a person).
            if ($direct.Count -eq 0 -or @($direct | Where-Object { $_ -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' }).Count -gt 0) { continue }
            if (Test-CaPolicyTargetsAllUsers $p $direct) {
                $candidates += [pscustomobject]@{ Policy = $p; Excluded = @($direct | Where-Object { $_ -notin $allowedBgIds }) }
            }
        }
        return [pscustomobject]@{ Satisfied = @($ok); Candidates = @($candidates | Sort-Object { @($_.Excluded).Count }) }
    }
    # Candidates small enough to plausibly be only emergency accounts (Microsoft guidance: two).
    function _SmallCandidates($eval) { return @($eval.Candidates | Where-Object { @($_.Excluded).Count -le 5 }) }

    # Report a missing baseline. With no (or unresolvable) -BreakGlassUpns and a policy that fails
    # only because a few users are excluded by name, the honest result is "cannot confirm"
    # (coverage gap), not a confirmed gap. With -BreakGlassUpns supplied the original finding and
    # severity stand, now naming the excluded users.
    function _ReportBaseline($eval, [hashtable]$spec) {
        if (@($eval.Satisfied).Count -gt 0) { return }
        $cands = @($eval.Candidates)
        $candRows = @(foreach ($c in $cands) { foreach ($x in @($c.Excluded)) {
            [pscustomobject]@{ Policy = [string]$c.Policy.DisplayName; PolicyId = [string]$c.Policy.Id; ExcludedUser = (_UserLabel $x); ExcludedUserId = $x }
        } })
        $candText = (@($cands | Select-Object -First 3 | ForEach-Object {
            "'{0}' excludes {1} user(s) by name: {2}" -f $_.Policy.DisplayName, @($_.Excluded).Count, (_ListText @($_.Excluded | ForEach-Object { _UserLabel $_ }))
        }) -join '; ')
        $small = @(_SmallCandidates $eval)
        if ($bgUnconfirmed -and $small.Count -gt 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title ("{0} policy excludes users not confirmed as emergency accounts" -f $spec.Label) `
                -Evidence ("{0}. The policy meets every other requirement of this baseline. {1}, so the audit cannot tell whether these users are your emergency (break-glass) accounts or a real gap. Result: not confirmed (neither passed nor failed)." -f $candText, $bgWhyUnknown) `
                -WhyItMatters ("If an excluded user is not an emergency-access (break-glass) account, that person {0}. Microsoft recommends excluding only the emergency accounts." -f $spec.Exposure) `
                -RecommendedAction 'Re-run the audit with -BreakGlassUpns listing your emergency accounts. If an excluded user is not an emergency account, remove the exclusion in Entra admin center > Protection > Conditional Access.' `
                -SourceFile $src -ResultRows $candRows -RuleId ('{0}-unconfirmed-exclusions' -f ($spec.RuleId -replace '^capolicies-no-','capolicies-')) -ObjectType 'tenant' -CoverageGap `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access'
            return
        }
        $ev = $spec.Evidence
        if ($cands.Count -gt 0) { $ev += (" Policies that would qualify except for users excluded by name: {0}." -f $candText) }
        $ev += $bgNote
        $splat = @{
            Severity = $spec.Severity; CheckId = 'capolicies'; Category = 'Tenant Posture'
            Title = $spec.Title; Evidence = $ev; WhyItMatters = $spec.Why; RecommendedAction = $spec.Action
            SourceFile = $src; RuleId = $spec.RuleId; ObjectType = 'tenant'; DocumentationUrl = $spec.Doc
        }
        if ($candRows.Count -gt 0) { $splat.ResultRows = $candRows }
        Add-EntraFinding @splat
    }

    if ($pols.Count -eq 0) {
        # With Security Defaults also OFF nothing requires MFA for anyone, administrators included -
        # at least as bad as the Critical "some administrators have no MFA policy" case below, so
        # the severity matches it. With Security Defaults ON (or unknown) the finding stays High.
        $sevNoPolicies = if ($sdState -eq 'Off') { 'Critical' } else { 'High' }
        $sdNoPolicies = switch ($sdState) {
            'On'    { 'Security Defaults is on, which gives basic protection (MFA registration and prompts, legacy sign-ins blocked) but no per-user, per-app or device control.' }
            'Off'   { 'Security Defaults is also off, so nothing requires MFA for anyone, including administrators (per-user MFA settings were not checked).' }
            default { ("Security Defaults could not be read ({0}), so it is unknown whether basic MFA is enforced." -f $sdError) }
        }
        Add-EntraFinding -Severity $sevNoPolicies -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No Conditional Access policies exist' `
            -Evidence ("The Conditional Access policy list was read successfully and is empty (0 policies). {0}" -f $sdNoPolicies) `
            -WhyItMatters 'Conditional Access (CA) is where Entra enforces sign-in rules such as multifactor authentication (MFA), blocking old sign-in protocols and requiring trusted devices. With no policies, none of these rules are applied.' `
            -RecommendedAction 'Create baseline policies in Entra admin center > Protection > Conditional Access: MFA for administrators and all users, block legacy authentication, require compliant or hybrid-joined devices. Without an Entra ID P1 licence, turn on Security Defaults instead.' `
            -SourceFile $src -RuleId 'capolicies-no-policies' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access'
        return
    }

    # --- Tenant-wide baselines (all users, all resources) ---
    $mfaAllEval = _EvaluateBaseline { param($p) (Test-CaPolicyRequiresMfaOrStrength $p) -and (_UniversalResourcePolicy -p $p -ignore @('ModernClients')) }
    _ReportBaseline $mfaAllEval @{
        Label = 'All-users MFA'; RuleId = 'capolicies-no-mfa-baseline'; Severity = 'High'
        Title = 'No Conditional Access policy requires MFA for all users and all apps'
        Evidence = 'No enabled policy requires MFA or an authentication strength (as a mandatory control, not one of several OR choices) for all users and all resources without app exclusions, group/role/guest exclusions or extra platform, location, risk or device conditions. Users excluded by name are accepted only for the -BreakGlassUpns accounts.'
        Why = 'Without multifactor authentication (MFA) for everyone, one stolen or guessed password is enough to take over an account. Tenant-wide MFA is the most effective single sign-in control.'
        Action = 'Create and enable a policy in Entra admin center > Protection > Conditional Access: all users, all resources, grant "Require multifactor authentication" (or an authentication strength); exclude only the emergency-access accounts.'
        Exposure = 'can sign in with just a password'
        Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength'
    }
    $legacyEval = _EvaluateBaseline { param($p)
        (_GrantBlocks $p) -and
        (@($p.Conditions.ClientAppTypes) -contains 'exchangeActiveSync') -and
        (@($p.Conditions.ClientAppTypes) -contains 'other') -and
        (_UniversalResourcePolicy -p $p -ignore @('ClientApps'))
    }
    _ReportBaseline $legacyEval @{
        Label = 'Legacy-authentication block'; RuleId = 'capolicies-no-legacy-auth-block'; Severity = 'High'
        Title = 'Legacy authentication is not blocked for all users and apps'
        Evidence = 'No enabled block policy covers both legacy client types (exchangeActiveSync and other clients) for all users and all resources without exclusions or extra platform, location or device conditions.'
        Why = 'Legacy authentication (old mail protocols such as POP and IMAP, and older Office clients) cannot do multifactor authentication (MFA), so attackers use it to try stolen or sprayed passwords while skipping MFA.'
        Action = 'Create and enable a Conditional Access policy that blocks the client apps "Exchange ActiveSync clients" and "Other clients" for all users and all resources, excluding only the emergency-access accounts.'
        Exposure = 'can still use old sign-in protocols that skip MFA'
        Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication'
    }

    # Risk policies need Entra ID P2 and workload-identity CA needs Workload ID Premium. When the
    # licence read failed these baselines were not evaluated - say so instead of staying silent.
    if (-not $script:LicenseKnown -and (-not $script:HasP2 -or -not $script:WorkloadIdP)) {
        $skippedParts = @()
        if (-not $script:HasP2) { $skippedParts += 'sign-in-risk and user-risk policies (need Entra ID P2)' }
        if (-not $script:WorkloadIdP) { $skippedParts += 'workload-identity policies (need Workload ID Premium)' }
        Add-EntraFinding -Severity 'Information' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Risk-based and workload-identity policies were not checked (licences could not be read)' `
            -Evidence ("The licence (subscribed SKU) read failed at the start of the audit, so these baselines were not evaluated: {0}. Their result is unknown, not clean." -f ($skippedParts -join '; ')) `
            -WhyItMatters 'These policies react automatically to signs of account or app compromise. The audit cannot say whether they are needed or present without knowing which licences the tenant has.' `
            -RecommendedAction 'Make sure the audit account can read subscriptions (Organization.Read.All) and re-run the capolicies check.' `
            -SourceFile $src -RuleId 'capolicies-risk-baselines-license-unknown' -ObjectType 'tenant' -CoverageGap
    }
    if ($script:HasP2) {
        $signInRiskEval = _EvaluateBaseline { param($p)
            $riskLevels = @((Get-EAField $p.Conditions 'SignInRiskLevels'))
            (Test-CaPolicyRequiresMfaOrStrength $p) -and
            ($riskLevels -contains 'high') -and ($riskLevels -contains 'medium') -and
            (_UniversalResourcePolicy -p $p -ignore @('SignInRisk'))
        }
        _ReportBaseline $signInRiskEval @{
            Label = 'Sign-in-risk'; RuleId = 'capolicies-no-signin-risk-policy'; Severity = 'High'
            Title = 'No policy requires MFA when a sign-in looks risky (medium or high sign-in risk)'
            Evidence = 'Entra ID P2 is licensed, but no enabled policy for all users and all resources requires MFA or an authentication strength at both medium and high sign-in risk (SignInRiskLevels) without exclusions or other narrowing conditions.'
            Why = 'Microsoft Entra ID Protection flags sign-ins that look like an attacker (for example a sign-in from an anonymous IP address or an unfamiliar location). Requiring multifactor authentication (MFA) for those sign-ins stops most password-only takeovers automatically.'
            Action = 'Create and enable a sign-in-risk policy in Conditional Access: all users, all resources, sign-in risk medium and high, grant "Require multifactor authentication".'
            Exposure = 'is not asked for MFA when a sign-in looks risky'
            Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-sign-in'
        }

        $userRiskEval = _EvaluateBaseline { param($p)
            (Test-CaPolicyRequiresMfaOrStrength $p) -and
            (_GrantRequiresBuiltIn $p 'passwordChange') -and
            ([string]$p.GrantControls.Operator -notmatch '^(?i)OR$') -and
            (@((Get-EAField $p.Conditions 'UserRiskLevels')) -contains 'high') -and
            (_UniversalResourcePolicy -p $p -ignore @('UserRisk'))
        }
        _ReportBaseline $userRiskEval @{
            Label = 'User-risk'; RuleId = 'capolicies-no-user-risk-policy'; Severity = 'High'
            Title = 'No policy forces a secure password change for users at high risk of compromise'
            Evidence = 'Entra ID P2 is licensed, but no enabled policy for all users and all resources requires both MFA and password change (AND, not OR) at high user risk (UserRiskLevels).'
            Why = 'High user risk means Microsoft believes the account is probably compromised (for example its password appeared in a leak). An MFA-protected password change removes the attacker without waiting for the help desk.'
            Action = 'Create and enable a user-risk policy in Conditional Access: all users, all resources, user risk high, grant "Require multifactor authentication" AND "Require password change".'
            Exposure = 'is not forced to replace a probably-stolen password'
            Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-user'
        }
    }

    $deviceCodeEval = _EvaluateBaseline { param($p)
        $flows = Get-EAField $p.Conditions 'AuthenticationFlows'
        (_GrantBlocks $p) -and
        (@((Get-EAField $flows 'TransferMethods')) -contains 'deviceCodeFlow') -and
        (_UniversalResourcePolicy -p $p -ignore @('AuthenticationFlows'))
    }
    _ReportBaseline $deviceCodeEval @{
        Label = 'Device-code block'; RuleId = 'capolicies-no-device-code-block'; Severity = 'Medium'
        Title = 'Device code sign-in is not blocked for all users and apps'
        Evidence = 'No enabled block policy for all users and all resources targets the device code flow (AuthenticationFlows.TransferMethods = deviceCodeFlow) without other narrowing conditions.'
        Why = 'In device-code phishing the attacker sends the victim a genuine Microsoft sign-in code; when the victim enters it, the attacker''s device is signed in as the victim, with MFA already completed.'
        Action = 'Block the device code flow for all users and all resources in Conditional Access (Conditions > Authentication flows), then allow narrow exceptions only for documented devices that need it, such as meeting-room devices.'
        Exposure = 'can still be phished through device-code sign-in'
        Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows'
    }

    $deviceTrustEval = _EvaluateBaseline { param($p) (_GrantRequiresDeviceTrust $p) -and (_UniversalResourcePolicy -p $p) }
    _ReportBaseline $deviceTrustEval @{
        Label = 'Compliant or hybrid-joined device'; RuleId = 'capolicies-no-device-compliance-baseline'; Severity = 'Medium'
        Title = 'No policy requires a compliant or hybrid-joined device for all users and apps'
        Evidence = 'No enabled policy for all users and all resources makes a trusted device mandatory - "Require device to be marked as compliant" (compliantDevice) and/or "Require Microsoft Entra hybrid joined device" (domainJoinedDevice) - without another OR choice (such as MFA), application exclusions or narrowing conditions.'
        Why = 'Without a device requirement, a valid password and MFA are enough to sign in from any personal or attacker-controlled computer, where tokens and downloaded data can be stolen.'
        Action = 'Require compliant or hybrid-joined devices for all users and all resources in Conditional Access, and document narrow exceptions for unmanaged (BYOD) scenarios, for example browser-only access with app restrictions.'
        Exposure = 'can sign in from unmanaged devices'
        Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance'
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

        # Prove the exclusions used by the location baseline are actually trusted. An arbitrary
        # excluded named location is a bypass, not a trusted-network design. When the named-location
        # list could not be read, a policy that is otherwise right is "unverified", not missing.
        $trustedNamedLocationIds = @($named | Where-Object { (Get-EAField $_ 'IsTrusted') -eq $true } | ForEach-Object { [string]$_.Id })
        $workloadLocationPolicies = @(); $workloadLocationUnverified = @()
        foreach ($p in $enabled) {
            $locations = Get-EAField $p.Conditions 'Locations'
            $includeLocations = @((Get-EAField $locations 'IncludeLocations') | Where-Object { $_ })
            $excludeLocations = @((Get-EAField $locations 'ExcludeLocations') | Where-Object { $_ })
            if (-not ((_GrantBlocks $p) -and (Test-CaPolicyTargetsAllResources $p) -and
                (_TargetsAllTenantServicePrincipals $p) -and
                ($includeLocations -contains 'All') -and $excludeLocations.Count -gt 0 -and
                -not (Test-CaPolicyHasNarrowingConditions $p @('ClientApplications','Locations')))) { continue }
            if (-not $namedKnown) { $workloadLocationUnverified += $p; continue }
            if ($trustedNamedLocationIds.Count -eq 0) { continue }
            $untrustedExclusions = @($excludeLocations | Where-Object { $_ -ne 'AllTrusted' -and [string]$_ -notin $trustedNamedLocationIds })
            if ($untrustedExclusions.Count -eq 0) { $workloadLocationPolicies += $p }
        }

        $workloadRiskPolicies = @($enabled | Where-Object {
            $riskLevels = @((Get-EAField $_.Conditions 'ServicePrincipalRiskLevels') | Where-Object { $_ })
            (_GrantBlocks $_) -and (Test-CaPolicyTargetsAllResources $_) -and
            (_TargetsAllTenantServicePrincipals $_) -and ($riskLevels -contains 'high') -and
            -not (Test-CaPolicyHasNarrowingConditions $_ @('ClientApplications','ServicePrincipalRisk'))
        })

        if ($workloadLocationPolicies.Count -eq 0 -and $workloadLocationUnverified.Count -gt 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'Workload-identity location policy could not be verified (named locations unreadable)' `
                -Evidence ("Policy/policies {0} block service principals outside excluded locations, but the named-location list could not be read ({1}), so it is unknown whether the excluded locations are really trusted." -f (_ListText @($workloadLocationUnverified | ForEach-Object { "'" + $_.DisplayName + "'" }) 5), $namedError) `
                -WhyItMatters 'If an excluded location is not a trusted company network, stolen app credentials can still be used from there.' `
                -RecommendedAction 'Make sure the audit account can read named locations (Policy.Read.All) and re-run the capolicies check.' `
                -SourceFile $src -RuleId 'capolicies-workload-location-unverified' -ObjectType 'tenant' -CoverageGap `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity'
        } elseif ($workloadLocationPolicies.Count -eq 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'Workload identities (apps) are not restricted to trusted locations' `
                -Evidence ("Workload ID Premium is licensed, but no enabled policy blocks all of this tenant's service principals, for all resources, from every location except trusted ones (AllTrusted or named locations marked trusted) without other narrowing conditions. Trusted named locations found: {0}." -f $trustedNamedLocationIds.Count) `
                -WhyItMatters 'Apps and service accounts (service principals) cannot use multifactor authentication (MFA). If their secret or certificate is stolen, the attacker can use it from anywhere unless access is limited to your own networks.' `
                -RecommendedAction 'Create a Conditional Access policy for workload identities: all service principals in your tenant, all resources, block access from all locations except your trusted named locations.' `
                -SourceFile $src -RuleId 'capolicies-no-workload-location-policy' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity'
        }
        if ($workloadRiskPolicies.Count -eq 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'Risky workload identities (apps) are not blocked automatically' `
                -Evidence 'Workload ID Premium is licensed, but no enabled policy blocks all of this tenant''s service principals, for all resources, at high service-principal risk (ServicePrincipalRiskLevels) without exclusions or other narrowing conditions.' `
                -WhyItMatters 'High service-principal risk means Microsoft has seen signs that an app''s credentials are compromised. Blocking at that point stops the attacker from getting new access tokens.' `
                -RecommendedAction 'Create a Conditional Access policy for workload identities: all service principals in your tenant, all resources, service principal risk high (and medium where practical), grant Block.' `
                -SourceFile $src -RuleId 'capolicies-no-workload-risk-policy' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity'
        }
    }

    # Policies that look like MFA enforcement but are switched off or report-only give a false
    # sense of security. "Looks like MFA" = the grant would require MFA / an authentication
    # strength, or the name says MFA (block policies named "... no MFA" are not MFA policies).
    # Severity depends on whether MFA is actually enforced tenant-wide: without an effective
    # all-users MFA baseline this may be the policy that was meant to provide it (High); with one
    # it is clean-up (Low).
    $mfaBaselinePresent = (@($mfaAllEval.Satisfied).Count -gt 0) -or ($bgUnconfirmed -and @(_SmallCandidates $mfaAllEval).Count -gt 0)
    $inactiveMfa = @($pols | Where-Object {
        $_.State -ne 'enabled' -and (
            (_HasMfaGrant $_) -or
            ([string]$_.DisplayName -match '(?i)mfa|multi.?factor' -and -not (_GrantBlocks $_)))
    })
    foreach ($p in $inactiveMfa) {
        $stateText = if ([string]$p.State -eq 'enabledForReportingButNotEnforced') { 'report-only (Entra only logs what the policy would have done; nobody is asked for MFA)' }
                     elseif ([string]$p.State -eq 'disabled') { 'switched off' } else { [string]$p.State }
        $context = if (@($mfaAllEval.Satisfied).Count -gt 0) {
            ("An enforced all-users MFA policy exists ({0}), so this is clean-up rather than a gap." -f (_ListText @($mfaAllEval.Satisfied | ForEach-Object { "'" + $_.DisplayName + "'" }) 3))
        } elseif ($mfaBaselinePresent) {
            ("An enforced all-users MFA policy exists ({0}; its user exclusions are not yet confirmed as emergency accounts), so this is most likely clean-up rather than a gap." -f (_ListText @(_SmallCandidates $mfaAllEval | ForEach-Object { "'" + $_.Policy.DisplayName + "'" }) 3))
        } else { 'No enforced policy requires MFA for all users and all apps, so this may be the policy that was meant to provide it.' }
        $grantParts = @($p.GrantControls.BuiltInControls | Where-Object { $_ })
        if (Get-EAField (Get-EAField $p.GrantControls 'AuthenticationStrength') 'Id') { $grantParts += 'authentication strength' }
        Add-EntraFinding -Severity $(if ($mfaBaselinePresent) { 'Low' } else { 'High' }) -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("MFA policy is not enforced: {0}" -f $p.DisplayName) `
            -Evidence ("Policy '{0}' is {1} (State = {2}). Grant controls: {3}. {4}" -f $p.DisplayName, $stateText, $p.State, $(if ($grantParts.Count) { $grantParts -join ', ' } else { 'none' }), $context) `
            -WhyItMatters 'A policy that looks like it enforces multifactor authentication (MFA) but is switched off or only in report-only mode protects nobody, while suggesting the protection exists.' `
            -RecommendedAction 'Turn the policy on after checking its report-only results (Entra admin center > Protection > Conditional Access), or delete it if it is no longer needed.' `
            -SourceFile $src -RuleId 'capolicies-mfa-policy-not-enforced' -ObjectType 'policy' -ObjectId ([string]$p.Id) `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only'
    }

    # Trusted named locations that are broad/public
    foreach ($n in $named) {
        $isTrusted = (Get-EAField $n 'IsTrusted')
        $ranges = @((Get-EAField $n 'IpRanges') | Where-Object { $_ })
        if ($isTrusted -and $ranges.Count -gt 0) {
            # ipRanges elements arrive as raw dictionaries, typed objects or AdditionalProperties -
            # Get-EAField reads all three shapes.
            $broad = @($ranges | ForEach-Object { [string](Get-EAField $_ 'cidrAddress') } | Where-Object { $_ -match '/(?:[0-9]|1[0-6])$' })
            if ($broad.Count -gt 0) {
                Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                    -Title ("Trusted network location covers a very large IP range: {0}" -f $n.DisplayName) `
                    -Evidence ("Named location '{0}' is marked trusted and includes {1}. A /16 or wider range covers at least 65,536 addresses." -f $n.DisplayName, (_ListText $broad 10)) `
                    -WhyItMatters 'Trusted locations are often used to skip MFA or other checks. A very wide trusted range gives the same exemption to anyone signing in from that address space, which may include shared or public networks.' `
                    -RecommendedAction 'Narrow the trusted location to your own public (egress) IP addresses in Entra admin center > Protection > Conditional Access > Named locations, and do not use trusted locations to skip MFA.' `
                    -SourceFile $src -RuleId 'capolicies-trusted-location-too-broad' -ObjectType 'policy' -ObjectId ([string]$n.Id) `
                    -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network'
            }
        }
    }

    # EFFECTIVE admin coverage uses the full active+eligible population, including users
    # reached through role-assignable groups. A policy counts only if it covers all resources,
    # has no app exclusions/narrowing conditions and makes its grant mandatory under OR.
    $mfaPolicies = @($enabled | Where-Object {
        (Test-CaPolicyRequiresMfaOrStrength $_) -and (Test-CaPolicyTargetsAllResources $_) -and
        -not (Test-CaPolicyHasNarrowingConditions $_ @('ModernClients'))
    })
    $phishPolicies = @($enabled | Where-Object {
        (Test-CaPolicyRequiresPhishingResistantStrength $_) -and (Test-CaPolicyTargetsAllResources $_) -and
        -not (Test-CaPolicyHasNarrowingConditions $_ @('ModernClients'))
    })
    # Enabled MFA-style policies that were NOT counted, with the plain reason - so the reader can
    # see why an existing "MFA for admins" policy does not satisfy the coverage test.
    $notCountedText = (@($enabled | Where-Object { (_HasMfaGrant $_) -and $mfaPolicies -notcontains $_ } | Select-Object -First 5 | ForEach-Object {
        $reasons = @()
        if (-not (Test-CaPolicyRequiresMfaOrStrength $_)) { $reasons += 'MFA is only one of several OR choices' }
        if (-not (Test-CaPolicyTargetsAllResources $_)) { $reasons += 'does not cover all apps' }
        if (Test-CaPolicyHasNarrowingConditions $_ @('ModernClients')) { $reasons += 'only applies under extra platform, location, risk, device or client-app conditions' }
        "'{0}' ({1})" -f $_.DisplayName, ($reasons -join '; ')
    }) -join '; ')
    $notCountedSentence = if ($notCountedText) { " Enabled MFA policies not counted: $notCountedText." } else { '' }

    $privUserIds = @{}; $privMapError = $null
    try { $privUserIds = Get-EAPrivilegedUserMap } catch { $script:PrivilegedUserMapIncomplete = $true; $privMapError = $_.Exception.Message }
    if ($null -eq $privUserIds) { $privUserIds = @{} }
    $privGapReasons = @()
    if ($privMapError) { $privGapReasons += ("the administrator list could not be built ({0})" -f $privMapError) }
    if ($script:PrivAssignmentsFailed) { $privGapReasons += 'active role assignments could not be read' }
    if ($script:PrivEligibilityAssignmentsFailed) { $privGapReasons += 'eligible (PIM) role assignments could not be read' }
    if ($privGapReasons.Count -eq 0 -and $script:PrivilegedUserMapIncomplete) { $privGapReasons += 'at least one role-assignable group could not be expanded' }
    if (($script:PrivAssignmentsFailed -or $script:PrivilegedUserMapIncomplete) -and $privUserIds.Count -eq 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Could not check whether administrators are covered by MFA policies' `
            -Evidence ("Per-administrator Conditional Access coverage was not assessed because {0}. Coverage is unknown, not confirmed." -f ($privGapReasons -join '; ')) `
            -WhyItMatters 'Without the list of administrators the audit cannot tell whether every privileged account must use multifactor authentication (MFA). A missing result here must not be read as a pass.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory plus group-membership read permissions (or retry after a transient failure) and re-run the capolicies check.' `
            -SourceFile $src -RuleId 'capolicies-admin-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }
    elseif ($script:PrivilegedUserMapIncomplete) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Some administrators could not be checked for MFA policy coverage' `
            -Evidence ("The administrator list is incomplete because {0}. The {1} administrator account(s) that could be read were evaluated; any others are unknown." -f ($privGapReasons -join '; '), $privUserIds.Count) `
            -WhyItMatters 'Administrators the audit cannot see may be outside every multifactor authentication (MFA) or phishing-resistant policy.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory, Group.Read.All and Member.Read.Hidden as appropriate (or retry after a transient failure) and re-run the capolicies check.' `
            -SourceFile $src -RuleId 'capolicies-admin-coverage-incomplete' -ObjectType 'tenant' -CoverageGap
    }
    # True when $p would apply to the user if the user were not in its ExcludeUsers list, i.e. the
    # by-name exclusion is the only thing keeping this policy away from the user.
    function _AppliesIfNotExcludedByName($p, [string]$uid, $groups, $roles) {
        $cu = $p.Conditions.Users
        if (@($cu.ExcludeUsers) -notcontains $uid) { return $false }
        $shadow = [pscustomobject]@{ Conditions = [pscustomobject]@{ Users = [pscustomobject]@{
            IncludeUsers = $cu.IncludeUsers; ExcludeUsers = @($cu.ExcludeUsers | Where-Object { $_ -ne $uid })
            IncludeGroups = $cu.IncludeGroups; ExcludeGroups = $cu.ExcludeGroups
            IncludeRoles = $cu.IncludeRoles; ExcludeRoles = $cu.ExcludeRoles } } }
        return (Test-CaPolicyAppliesToUser -Policy $shadow -UserId $uid -GroupIds $groups -RoleTemplateIds $roles)
    }
    $uncovered = @(); $uncoveredPhish = @(); $unknownScope = @(); $evaluated = 0; $coveredCount = 0; $nameOnlyPolicies = @{}
    foreach ($uid in $privUserIds.Keys) {
        $upn = if ($script:UserById -and $script:UserById.ContainsKey($uid)) { $script:UserById[$uid].UserPrincipalName } else { $uid }
        if (([string]$uid -in $allowedBgIds) -or ($upn -and ([string]$upn).ToLowerInvariant() -in $bg)) { continue }   # break-glass expected to be excluded
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
        if ($unknownFor.Count -gt 0) { $unknownScope += [pscustomobject]@{ Account=$upn; UserId=[string]$uid; Reason=("group membership could not be resolved for {0}" -f ($unknownFor -join ' and ')) } }
        if ($covered) { $coveredCount++ }
        if (-not $covered -and -not $mfaMembershipUnknown) {
            $uncovered += [pscustomobject]@{ Account = $upn; UserId = [string]$uid }
            # Only relevant when emergency accounts are not confirmed: which all-apps MFA policies
            # would cover this administrator if it were not excluded by name?
            if ($bgUnconfirmed) {
                $byName = @($mfaPolicies | Where-Object { _AppliesIfNotExcludedByName -p $_ -uid ([string]$uid) -groups $scope.Groups -roles $adminRoles } | ForEach-Object { "'" + $_.DisplayName + "'" })
                if ($byName.Count -gt 0) { $nameOnlyPolicies[[string]$uid] = $byName }
            }
        }
        if (-not $phishCovered -and -not $phishMembershipUnknown) { $uncoveredPhish += [pscustomobject]@{ Account = $upn; UserId = [string]$uid } }
    }
    # Microsoft's guidance is to exclude the emergency-access (break-glass) accounts - usually Global
    # Administrators - by name from Conditional Access. Without a confirmed -BreakGlassUpns list, an
    # administrator whose ONLY reason for being outside MFA is such a by-name exclusion from an
    # otherwise applicable all-apps MFA policy may be one of them. As for the all-users baselines,
    # a few such accounts are reported as "not confirmed" (a High coverage gap, one step below the
    # Critical they would be if confirmed as ordinary admins - an admin excluded by name is also a
    # known attacker persistence trick) instead of a confirmed Critical. Guards: at most 5 accounts
    # (the same limit as the baselines), and at least one administrator must be covered by MFA - if
    # none is, this is not an emergency-account pattern and every uncovered admin stays Critical.
    $possibleBg = @()
    if ($bgUnconfirmed -and $coveredCount -gt 0 -and $nameOnlyPolicies.Count -gt 0 -and $nameOnlyPolicies.Count -le 5) {
        $possibleBg = @($uncovered | Where-Object { $nameOnlyPolicies.ContainsKey([string]$_.UserId) } | ForEach-Object {
            [pscustomobject]@{ Account = $_.Account; UserId = $_.UserId; ExcludedByNameFrom = ($nameOnlyPolicies[[string]$_.UserId] -join ', ') }
        })
        $uncovered = @($uncovered | Where-Object { -not $nameOnlyPolicies.ContainsKey([string]$_.UserId) })
    }
    $possibleBgIds = @($possibleBg | ForEach-Object { [string]$_.UserId })
    $phishUncoveredAll = $uncoveredPhish.Count
    $possibleBgNoPhish = @($uncoveredPhish | Where-Object { [string]$_.UserId -in $possibleBgIds })
    $uncoveredPhish = @($uncoveredPhish | Where-Object { [string]$_.UserId -notin $possibleBgIds })
    $possibleBgSentence = if ($possibleBg.Count -gt 0) {
        (" Not counted here: {0} administrator account(s) excluded by name that may be emergency accounts ({1}); they are reported separately as not confirmed." -f $possibleBg.Count, (_ListText @($possibleBg.Account) 5))
    } else { '' }
    if ($unknownScope.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("MFA policy coverage is unknown for {0} administrator(s) (group membership unreadable)" -f $unknownScope.Count) `
            -Evidence ("Coverage could not be determined for: {0}. Their group memberships could not be read, and the relevant policies include or exclude groups." -f (_ListText @($unknownScope.Account))) `
            -WhyItMatters 'Policies that include or exclude groups cannot be evaluated without membership data, so these administrators may or may not be required to use multifactor authentication (MFA).' `
            -RecommendedAction 'Restore read access to group memberships (GroupMember.Read.All / Group.Read.All) and re-run the capolicies check.' `
            -SourceFile $src -ResultRows $unknownScope -RuleId 'capolicies-admin-membership-unknown' -ObjectType 'tenant' -CoverageGap
    }
    $adminBgNote = if ($bg.Count -eq 0) { ' No emergency-access accounts were supplied with -BreakGlassUpns, so emergency accounts that hold admin roles (and should be excluded) cannot be told apart from other administrators here; re-run with -BreakGlassUpns to leave them out.' } else { $bgNote }
    # Severity is monotonic in the number of uncovered administrators: some OR all administrators
    # left out of every existing MFA policy is Critical (one rule id, so the trend follows the same
    # issue as it is fixed). Only when NO usable MFA policy exists at all does Security Defaults
    # matter: if it is confirmed OFF nothing forces admin MFA (Critical, same as above); if it is
    # ON (admins still get MFA from it) or unknown, the systemic finding stays High.
    if ($evaluated -gt 0 -and $mfaPolicies.Count -eq 0) {
        Add-EntraFinding -Severity $(if ($sdState -eq 'Off') { 'Critical' } else { 'High' }) -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No Conditional Access policy requires MFA for administrators across all apps' `
            -Evidence ("{0} administrator account(s) were checked (active and eligible, including through groups). No enabled policy that requires MFA or an authentication strength for all apps, without extra conditions, applies to any of them. {1}{2}{3}" -f $evaluated, $sdSentence, $notCountedSentence, $adminBgNote) `
            -WhyItMatters 'Administrators are the most valuable accounts to attackers. Without multifactor authentication (MFA), a stolen or guessed password is enough to take over the account and, with it, the tenant.' `
            -RecommendedAction 'Create and enable a Conditional Access policy that requires MFA (preferably phishing-resistant) for all administrator roles and all apps, excluding only the emergency-access accounts: Entra admin center > Protection > Conditional Access.' `
            -SourceFile $src -RuleId 'ENTRA-CA-ADMIN-MFA-NONE' -ObjectType 'Tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
    }
    elseif ($uncovered.Count -gt 0) {
        $uncoveredTitle = if ($uncovered.Count -eq $evaluated -and $evaluated -eq 1) { 'The only administrator account is outside every MFA policy' }
                          elseif ($uncovered.Count -eq $evaluated) { "All {0} administrator accounts are outside every MFA policy" -f $evaluated }
                          else { "{0} of {1} administrator accounts {2} not covered by any MFA policy" -f $uncovered.Count, $evaluated, $(if ($uncovered.Count -eq 1) { 'is' } else { 'are' }) }
        Add-EntraFinding -Severity 'Critical' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title $uncoveredTitle `
            -Evidence ("Administrators to whom no enabled all-apps MFA policy applies (excluded, or never included): {0}. All-apps MFA policies found: {1}.{2}{3}{4}" -f (_ListText @($uncovered.Account)), $mfaPolicies.Count, $notCountedSentence, $possibleBgSentence, $adminBgNote) `
            -WhyItMatters 'Conditional Access (CA) does not require multifactor authentication (MFA) for these administrator accounts, because every MFA policy either excludes them or does not include them. A stolen password for any of them could lead to tenant takeover.' `
            -RecommendedAction 'Remove these accounts from MFA policy exclusions, or add them to an MFA policy, in Entra admin center > Protection > Conditional Access. Only the emergency-access accounts should be excluded.' `
            -SourceFile $src -ResultRows $uncovered -RuleId 'ENTRA-CA-ADMIN-MFA-NOT-EFFECTIVE' -ObjectType 'Tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
    }
    if ($possibleBg.Count -gt 0) {
        $pbTitle = if ($possibleBg.Count -eq 1) { '1 administrator is excluded from MFA by name and not confirmed as an emergency account' }
                   else { "{0} administrators are excluded from MFA by name and not confirmed as emergency accounts" -f $possibleBg.Count }
        $pbPhish = if ($possibleBgNoPhish.Count -gt 0) { ' They are also left out of the phishing-resistant MFA result.' } else { '' }
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title $pbTitle `
            -Evidence ("Administrators outside every all-apps MFA policy only because a policy excludes them by name: {0}. {1}, so the audit cannot tell whether they are your emergency (break-glass) accounts or administrators who can sign in without MFA. Result: not confirmed (neither passed nor failed). {2} other administrator account(s) are covered by an MFA policy.{3}" -f (_ListText @($possibleBg | ForEach-Object { "{0} (excluded in {1})" -f $_.Account, $_.ExcludedByNameFrom }) 5), $bgWhyUnknown, $coveredCount, $pbPhish) `
            -WhyItMatters 'If one of these accounts is not an emergency-access (break-glass) account, it is an administrator who can sign in with just a password. Excluding an administrator by name is also a known way for attackers to keep access.' `
            -RecommendedAction 'Re-run the audit with -BreakGlassUpns listing your emergency accounts. If an account is not an emergency account, remove its exclusion in Entra admin center > Protection > Conditional Access.' `
            -SourceFile $src -ResultRows $possibleBg -RuleId 'capolicies-admin-mfa-unconfirmed-exclusions' -ObjectType 'tenant' -CoverageGap `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access'
    }

    if ($evaluated -gt 0 -and ($phishPolicies.Count -eq 0 -or $phishUncoveredAll -eq $evaluated)) {
        $pbNone = if ($possibleBgNoPhish.Count -gt 0) { (" {0} of them are excluded from MFA by name and may be emergency accounts (not confirmed)." -f $possibleBgNoPhish.Count) } else { '' }
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No administrator is required to use phishing-resistant MFA' `
            -Evidence ("None of the {0} administrator account(s) checked is covered by an enabled all-apps policy that requires a phishing-resistant authentication strength (FIDO2 security key, Windows Hello for Business or certificate-based MFA). Such policies found: {1}.{2}{3}" -f $evaluated, $phishPolicies.Count, $pbNone, $adminBgNote) `
            -WhyItMatters 'Ordinary MFA (app notifications, codes, text messages) can be defeated by fake sign-in pages that relay the session, or by users approving repeated prompts. Phishing-resistant methods stop this for the accounts that matter most.' `
            -RecommendedAction 'Create a Conditional Access policy for all administrator roles and all apps that requires the built-in "Phishing-resistant MFA" authentication strength, excluding only the emergency-access accounts.' `
            -SourceFile $src -RuleId 'ENTRA-CA-ADMIN-PHISH-RESISTANT-NONE' -ObjectType 'Tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
    } elseif ($uncoveredPhish.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("{0} of {1} administrator accounts {2} not required to use phishing-resistant MFA" -f $uncoveredPhish.Count, $evaluated, $(if ($uncoveredPhish.Count -eq 1) { 'is' } else { 'are' })) `
            -Evidence ("Administrators without an applicable all-apps phishing-resistant authentication-strength policy: {0}.{1}{2}" -f (_ListText @($uncoveredPhish.Account)), $(if ($possibleBgNoPhish.Count -gt 0) { (" Not counted here: {0} administrator account(s) excluded from MFA by name that may be emergency accounts ({1}), reported separately as not confirmed." -f $possibleBgNoPhish.Count, (_ListText @($possibleBgNoPhish.Account) 5)) } else { '' }), $adminBgNote) `
            -WhyItMatters 'A single administrator left on phishable MFA (codes, app notifications, text messages) can become the easiest path to taking over the tenant.' `
            -RecommendedAction 'Remove the scope gaps or exclusions and require the "Phishing-resistant MFA" authentication strength for these administrators in Entra admin center > Protection > Conditional Access.' `
            -SourceFile $src -ResultRows $uncoveredPhish -RuleId 'ENTRA-CA-ADMIN-PHISH-RESISTANT-PARTIAL' -ObjectType 'Tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
    }

    if ($script:Findings.Where({$_.CheckId -eq 'capolicies'}).Count -eq 0) {
        $checkedList = @('MFA for all users','legacy-authentication block','device-code block','compliant or hybrid-joined device','MFA and phishing-resistant MFA for administrators')
        if ($script:HasP2) { $checkedList += 'sign-in-risk and user-risk policies' }
        if ($script:WorkloadIdP) { $checkedList += 'workload-identity location and risk policies' }
        Add-EntraFinding -Severity 'Information' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Conditional Access baseline policies are in place' `
            -Evidence ("{0} enabled policy/policies. Baselines checked and found effective: {1}." -f $enabled.Count, ($checkedList -join ', ')) `
            -WhyItMatters 'A complete Conditional Access (CA) baseline enforces MFA, blocks old sign-in protocols and limits risky sign-ins for everyone.' `
            -RecommendedAction 'Keep the baseline and review policy exclusions regularly; extend coverage (for example risk-based policies with Entra ID P2) as licences allow.' `
            -SourceFile $src -ResultRows $rows -RuleId 'capolicies-baselines-in-place' -ObjectType 'tenant'
    }
}

# ===========================================================================
# CHECK 11 - riskyusers (Identity Protection)
# ===========================================================================
function Invoke-Check-RiskyUsersOnly {
    # Filter server-side: without it every HISTORICALLY risky user (remediated/dismissed,
    # years of history) is downloaded just to be discarded client-side.
    $risky = @(Get-MgRiskyUser -All -Filter "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'" -ErrorAction Stop)
    # Risk detections are supporting detail. Track a failed read explicitly: an absent
    # detections file must never look like "no detections".
    $detections = @(); $detectionsKnown = $true; $detectionsError = $null
    # 30-day window server-side, consistent with the other log-based checks. ('gt' - the
    # documented detectedDateTime filter operators are eq/gt/lt, not ge.)
    $dsince = (Get-Date).ToUniversalTime().AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    try { $detections = @(Get-MgRiskDetection -All -Filter "detectedDateTime gt $dsince" -ErrorAction Stop) }
    catch { $detectionsKnown = $false; $detectionsError = $_.Exception.Message }
    $rows = $risky | Select-Object UserPrincipalName, UserDisplayName, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime, Id
    $src = Write-Evidence -BaseName 'risky_users' -Rows $rows -Title 'Identity Protection - Risky Users'
    $drows = @($detections | Select-Object UserPrincipalName, RiskEventType, RiskLevel, RiskState, DetectedDateTime, IPAddress)
    $dNotes = if ($detectionsKnown) { @() } else { @("READ FAILED: risk detections could not be read ($detectionsError). This list is unknown, not empty.") }
    Write-Evidence -BaseName 'risk_detections' -Rows $drows -Title 'Identity Protection - Risk Detections (last 30 days)' -Notes $dNotes | Out-Null
    if (-not $detectionsKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyusers' -Category 'Threat Signals' `
            -Title 'Recent risk detections could not be read' `
            -Evidence ("Reading risk detections for the last 30 days failed: {0}. The risky-user list was read successfully; only the detection details (what triggered each risk) are missing and unknown." -f $detectionsError) `
            -WhyItMatters 'Risk detections explain why a user was flagged, for example a leaked password or a sign-in from an anonymous IP address. Without them, investigating flagged users takes longer.' `
            -RecommendedAction 'Grant IdentityRiskEvent.Read.All to the audit account or app (or retry after a temporary error) and re-run the riskyusers check.' `
            -SourceFile $src -RuleId 'riskyusers-detections-unreadable' -ObjectType 'tenant' -CoverageGap
    }

    # privileged cross-ref (shared assignment cache - one Graph download per run)
    $privIds = @{}; $privMapError = $null
    try { foreach ($id in (Get-EAPrivilegedUserMap).Keys) { $privIds[$id] = $true } }
    catch { $privMapError = $_.Exception.Message }
    $privIncomplete = [bool]($privMapError -or $script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)

    function _RiskyUserList($list) {
        $items = @($list | ForEach-Object { '{0} ({1} risk, {2})' -f $_.UserPrincipalName, $_.RiskLevel, $_.RiskState })
        $shown = @($items | Select-Object -First 10)
        $text = $shown -join ', '
        if ($items.Count -gt $shown.Count) { $text += (' (+{0} more)' -f ($items.Count - $shown.Count)) }
        return $text
    }

    if ($risky.Count -gt 0) {
        $privRisky = @($risky | Where-Object { $_.Id -and $privIds.ContainsKey($_.Id) })
        $other = @($risky | Where-Object { -not ($_.Id -and $privIds.ContainsKey($_.Id)) })
        # The classification gap matters only for risky users NOT recognised as administrators:
        # with an incomplete administrator list, one of them may be an admin.
        if ($privIncomplete -and $other.Count -gt 0) {
            $why = @()
            if ($privMapError) { $why += ("the administrator list could not be built ({0})" -f $privMapError) }
            if ($script:PrivAssignmentsFailed) { $why += 'active role assignments could not be read' }
            if ($script:PrivEligibilityAssignmentsFailed) { $why += 'eligible (PIM) role assignments could not be read' }
            if ($why.Count -eq 0) { $why += 'at least one privileged group could not be expanded' }
            Add-EntraFinding -Severity 'Information' -CheckId 'riskyusers' -Category 'Threat Signals' `
                -Title 'Could not confirm whether risky users are administrators' `
                -Evidence ("The administrator list is incomplete because {0}. {1} risky user(s) were reported at the normal-user severity but one of them may be an administrator." -f ($why -join '; '), $other.Count) `
                -WhyItMatters 'A risky administrator is a tenant-takeover incident and must be reported as Critical; an incomplete administrator list can hide that.' `
                -RecommendedAction 'Restore read access to role assignments and privileged groups (RoleManagement.Read.Directory, Group.Read.All) and re-run the riskyusers check.' `
                -SourceFile $src -RuleId 'riskyusers-privileged-classification-incomplete' -ObjectType 'tenant' -CoverageGap
        }
        if ($privRisky.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'riskyusers' -Category 'Threat Signals' `
                -Title ("{0} administrator account(s) are flagged as risky or compromised" -f $privRisky.Count) `
                -Evidence ("Risky administrators: {0}." -f (_RiskyUserList $privRisky)) `
                -WhyItMatters 'Microsoft Entra ID Protection believes these administrator accounts may be in an attacker''s hands. An administrator compromise can give control of the whole tenant, so treat this as an active security incident.' `
                -RecommendedAction 'Investigate now: reset each account''s password, revoke its sessions, review its recent sign-ins and audit-log activity, then confirm the compromise or dismiss the risk in Entra admin center > Protection > Identity Protection > Risky users.' `
                -SourceFile $src -ResultRows @($privRisky | Select-Object UserPrincipalName,RiskLevel,RiskState,RiskDetail,RiskLastUpdatedDateTime) `
                -RuleId 'riskyusers-privileged-at-risk' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk'
        }
        if ($other.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'riskyusers' -Category 'Threat Signals' `
                -Title ("{0} user(s) are flagged as risky or compromised by Identity Protection" -f $other.Count) `
                -Evidence ("Risky users: {0}." -f (_RiskyUserList $other)) `
                -WhyItMatters 'Microsoft Entra ID Protection has seen signs that these accounts may be compromised, such as leaked passwords, password-spray attempts or unusual sign-ins.' `
                -RecommendedAction 'Investigate each user and reset passwords or revoke sessions where needed (Entra admin center > Protection > Identity Protection > Risky users). Enable risk-based Conditional Access so new risks are handled automatically.' `
                -SourceFile $src -ResultRows @($other | Select-Object UserPrincipalName,RiskLevel,RiskState,RiskDetail,RiskLastUpdatedDateTime) `
                -RuleId 'riskyusers-users-at-risk' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock'
        }
    } else {
        $detText = if ($detectionsKnown) { ("{0} risk detection(s) were recorded in the last 30 days (see the risk detections evidence)." -f $detections.Count) } else { 'Risk detections could not be read (see the separate finding).' }
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyusers' -Category 'Threat Signals' `
            -Title 'No users are currently flagged as risky' `
            -Evidence ("Identity Protection returned no users in the 'at risk' or 'confirmed compromised' state. {0}" -f $detText) `
            -WhyItMatters 'Microsoft Entra ID Protection flags accounts that show signs of compromise, such as leaked passwords or unusual sign-ins.' `
            -RecommendedAction 'Keep risk-based Conditional Access policies enabled so new risks are handled automatically, and review the Risky users report regularly.' `
            -SourceFile $src -RuleId 'riskyusers-none-flagged' -ObjectType 'tenant'
    }
}

# ===========================================================================
# CHECK 11b - riskyserviceprincipals (Identity Protection - risky workload identities)
#   Split from riskyusers: risky service principals are licensed under Microsoft Entra
#   Workload ID Premium, NOT Entra ID P2, so a Workload-ID-Premium tenant without P2 must
#   still be able to evaluate them. The check is gated internally on $script:WorkloadIdP,
#   and reports an unknown licence (failed SKU read) separately from "not licensed".
# ===========================================================================
function Invoke-Check-RiskyServicePrincipals {
    # Risky service principals (v1.0, best-effort). Track read SUCCESS separately from
    # result count: an errored read must surface as a coverage gap, never as "clean".
    $readOk = $true; $readError = $null; $licenseDenied = $false
    $rsp = @()
    try {
        if (Get-Command Get-MgRiskyServicePrincipal -ErrorAction SilentlyContinue) {
            $rsp = @(Get-MgRiskyServicePrincipal -All -ErrorAction Stop | Where-Object { [string](Get-EAField $_ 'RiskState') -in @('atRisk','confirmedCompromised') })
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
            $rsp = @($acc | Where-Object { [string](Get-EAField $_ 'riskState') -in @('atRisk','confirmedCompromised') })
        }
    } catch {
        $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch { $code = $null }
        $denied = ($code -in 401,403) -or ("$_" -match 'Authorization_RequestDenied|Insufficient privileges')
        # Graph answers 403 "not licensed" when the tenant lacks Workload ID Premium. That is a
        # licence gap reported by the service itself, not a missing permission - report it as
        # "not licensed" (coverage gap) instead of letting it surface as Skipped-NoPermission.
        if ($denied -and "$_" -match '(?i)licen[cs]') { $licenseDenied = $true }
        # Genuine permission failures land in the posture summary as Skipped-NoPermission.
        elseif ($denied) { throw }
        $readOk = $false; $readError = $_.Exception.Message
    }

    $rsprows = @($rsp | Select-Object @{n='DisplayName';e={ Get-EAField $_ 'DisplayName' }},
        @{n='AppId';e={ Get-EAField $_ 'AppId' }},
        @{n='RiskLevel';e={ Get-EAField $_ 'RiskLevel' }},
        @{n='RiskState';e={ Get-EAField $_ 'RiskState' }},
        @{n='RiskDetail';e={ Get-EAField $_ 'RiskDetail' }},
        @{n='RiskLastUpdatedDateTime';e={ Get-EAField $_ 'RiskLastUpdatedDateTime' }},
        @{n='Id';e={ Get-EAField $_ 'Id' }})
    $notes = @()
    if ($licenseDenied) { $notes += "NOT LICENSED: Microsoft Graph refused the read because the tenant is not licensed for risky workload identities ($readError). This list is not assessed, not empty." }
    elseif (-not $readOk) { $notes += "READ FAILED: risky service principals could not be read ($readError). This list is unknown, not empty." }
    if (-not $script:WorkloadIdP) {
        $notes += $(if ($script:LicenseKnown) { 'Workload ID Premium was not detected: an empty list does not mean no risky workload identities.' }
                    else { 'The licence read failed, so it is unknown whether Workload ID Premium is present: an empty list does not mean no risky workload identities.' })
    }
    # Always write the evidence, so an empty list is visible and distinguishable from a failed read.
    $src = Write-Evidence -BaseName 'risky_serviceprincipals' -Rows $rsprows -Title 'Identity Protection - Risky Service Principals' -Notes $notes

    if ($readOk -and $rsp.Count -gt 0) {
        $names = @($rsprows | ForEach-Object { '{0} ({1} risk, {2})' -f $_.DisplayName, $_.RiskLevel, $_.RiskState })
        $shown = @($names | Select-Object -First 10)
        $nameText = ($shown -join ', ') + $(if ($names.Count -gt $shown.Count) { ' (+{0} more)' -f ($names.Count - $shown.Count) } else { '' })
        Add-EntraFinding -Severity 'High' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title $(if ($rsp.Count -eq 1) { '1 app identity (service principal) is flagged as risky or compromised' } else { "{0} app identities (service principals) are flagged as risky or compromised" -f $rsp.Count }) `
            -Evidence ("Risky service principals: {0}." -f $nameText) `
            -WhyItMatters 'A compromised app identity (service principal) can use its granted permissions - often to mail, files or the directory - without any user signing in, so misuse is easy to miss.' `
            -RecommendedAction 'Investigate each flagged service principal: review its recent sign-ins and permissions, remove or rotate its secrets and certificates, then confirm the compromise or dismiss the risk in Entra admin center > Protection > Identity Protection > Risky workload identities.' `
            -SourceFile $src -ResultRows $rsprows -RuleId 'riskyserviceprincipals-at-risk' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk'
        return
    }

    # Risky service principals are licensed separately from P2 risky users (they need
    # Microsoft Entra Workload ID Premium). Report coverage explicitly: a failed read or a missing
    # (or unknown) licence is "not assessed", never clean; only a licensed, successful read is clean.
    if ($licenseDenied) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'Risky workload identities were not checked (needs Workload ID Premium)' `
            -Evidence ("Microsoft Graph refused to list risky service principals because the tenant is not licensed for it: {0}. Licence detection at the start of the audit: Workload ID Premium {1}. The result is not assessed, not clean." -f $readError, $(if ($script:WorkloadIdP) { 'was detected' } elseif ($script:LicenseKnown) { 'was not detected' } else { 'is unknown (the licence read failed)' })) `
            -WhyItMatters 'Risk detection for app identities (service principals) spots stolen app credentials. Entra ID P2 alone does not include it.' `
            -RecommendedAction 'License Microsoft Entra Workload ID Premium if you need automatic risk detection for app identities.' `
            -SourceFile $src -RuleId 'riskyserviceprincipals-not-licensed' -ObjectType 'tenant' -CoverageGap `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk'
    } elseif (-not $readOk) {
        $licText = if ($script:WorkloadIdP) { 'Workload ID Premium is present.' } elseif ($script:LicenseKnown) { 'Workload ID Premium was also not detected.' } else { 'The licence read also failed, so Workload ID Premium status is unknown.' }
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'Risky workload identities could not be read (result unknown, not clean)' `
            -Evidence ("Reading risky service principals failed: {0}. {1} The result is unknown, not ""no risky workload identities""." -f $readError, $licText) `
            -WhyItMatters 'A failed read must not be mistaken for a clean result: compromised app identities (service principals) may exist unseen.' `
            -RecommendedAction 'Re-run the audit (or just -riskyserviceprincipals) when Microsoft Graph is reachable.' `
            -SourceFile $src -RuleId 'riskyserviceprincipals-read-failed' -ObjectType 'tenant' -CoverageGap
    } elseif (-not $script:WorkloadIdP -and $script:LicenseKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'Risky workload identities were not checked (needs Workload ID Premium)' `
            -Evidence 'The tenant''s licences were read and Microsoft Entra Workload ID Premium was not found. Without it Identity Protection does not report risky workload identities, so an empty list is "not assessed", not clean.' `
            -WhyItMatters 'Risk detection for app identities (service principals) spots stolen app credentials. Entra ID P2 alone does not include it.' `
            -RecommendedAction 'License Microsoft Entra Workload ID Premium if you need automatic risk detection for app identities.' `
            -SourceFile $src -RuleId 'riskyserviceprincipals-not-licensed' -ObjectType 'tenant' -CoverageGap `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk'
    } elseif (-not $script:WorkloadIdP) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'Risky workload identities were not checked (licences could not be read)' `
            -Evidence 'The licence (subscribed SKU) read failed at the start of the audit, so it is unknown whether Microsoft Entra Workload ID Premium is present. The empty risky-service-principal list may simply reflect a missing licence; the result is unknown, not clean.' `
            -WhyItMatters 'Risk detection for app identities (service principals) spots stolen app credentials; the audit cannot tell whether it is active in this tenant.' `
            -RecommendedAction 'Make sure the audit account can read subscriptions (Organization.Read.All) and re-run the riskyserviceprincipals check.' `
            -SourceFile $src -RuleId 'riskyserviceprincipals-license-unknown' -ObjectType 'tenant' -CoverageGap
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'No app identities (service principals) are flagged as risky' `
            -Evidence 'Workload ID Premium is present and Identity Protection currently flags no service principal as at risk or confirmed compromised.' `
            -WhyItMatters 'Identity Protection flags app identities (service principals) whose credentials show signs of compromise.' `
            -RecommendedAction 'Keep risk-based Conditional Access for workload identities enabled and review flagged service principals promptly.' `
            -SourceFile $src -RuleId 'riskyserviceprincipals-none-flagged' -ObjectType 'tenant'
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
    # Rule ids: every finding carries an explicit -RuleId (one-time migration from the old
    # title-slug ids) so rewording a title never changes its trend id again.

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

    # Page size 999 cuts Graph round-trips up to 10x on large tenants. If an endpoint
    # rejects the page size (HTTP 400) the read is repeated once with the service default;
    # every other error propagates to the caller, which records it as a coverage gap.
    function _InvokePagedRead([scriptblock]$Read) {
        try { return @(& $Read @{ PageSize = 999 }) }
        catch {
            if ([string]$_.Exception.Message -notmatch '(?i)Status:\s*400|BadRequest|page\s*size|\$top') { throw }
            return @(& $Read @{})
        }
    }

    # Enumerate assignments from the RESOURCE side: only SPs that define named app roles
    # (the APIs - Graph, Exchange, SharePoint, custom) can grant application permissions,
    # and there are far fewer APIs than client SPs. One Get-...AppRoleAssignedTo per API
    # replaces one Get-...AppRoleAssignment per service principal (N+1 at tenant scale).
    # An application permission can only be granted for an app role whose
    # allowedMemberTypes includes 'Application'; APIs that only define USER roles (typical
    # gallery/SaaS apps assigned to thousands of users) are skipped instead of downloading
    # every user assignment just to discard it. A role with no readable allowedMemberTypes
    # is kept (fail-safe: never skip an API because a property is missing).
    $permRows = @()
    $spPermErrors = @()
    $resourceSps = @($sps | Where-Object {
        @($_.AppRoles | Where-Object {
            $_.Id -and $_.Value -and ((@($_.AllowedMemberTypes | Where-Object { $_ }).Count -eq 0) -or (@($_.AllowedMemberTypes) -contains 'Application'))
        }).Count -gt 0
    })
    foreach ($res in $resourceSps) {
        $asn = @()
        try { $asn = @(_InvokePagedRead { param($p) Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $res.Id -All -ErrorAction Stop @p }) }
        catch { $spPermErrors += [pscustomobject]@{ ResourceApi=$res.DisplayName; ApiAppId=$res.AppId; ApiServicePrincipalId=$res.Id; Error=$_.Exception.Message }; continue }
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
    $permSrc = Write-Evidence -BaseName 'app_permissions' -Rows $permRows -Title 'Application Permissions (write / high-privilege, all resource APIs)' `
        -Notes @(
            ("Resource APIs that can grant application permissions: {0}; read successfully: {1}; could not be read: {2}." -f $resourceSps.Count, ($resourceSps.Count - $spPermErrors.Count), $spPermErrors.Count),
            'Tier0 = permission in the tier-0 list (tenant takeover, all mail, all files); Write/High = other write-capable application permission.',
            'The Enterprise Application Governance check (-enterpriseapps) lists the same grants per permission with its own risk rating.'
        )
    if ($spPermErrors.Count -gt 0) {
        # The absence of dangerous app permissions is only trustworthy if collection was complete.
        $errSrc = Write-Evidence -BaseName 'app_permission_collection_errors' -Rows $spPermErrors -Title 'Application Permission Collection Errors'
        Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Applications' `
            -Title ("App permissions could not be read on {0} API(s), so risky apps may be missing" -f $spPermErrors.Count) `
            -Evidence ("The list of apps holding permissions could not be read for {0} of {1} resource API(s): {2}. Typical causes: throttling, a missing permission or a transient Graph error; the exact error per API is in the collection-errors file." -f $spPermErrors.Count, $resourceSps.Count, (($spPermErrors.ResourceApi | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Apps with dangerous permissions on these APIs could not be seen, so they are not reported. The absence of a finding here does not mean the tenant is clean.' `
            -RecommendedAction 'Re-run the apps check when Graph is not throttling, and confirm the audit account can read service principals and their app-role assignments (Application.Read.All).' `
            -SourceFile $errSrc -ResultRows $spPermErrors -RuleId 'apps-permission-read-incomplete' -ObjectType 'tenant' -CoverageGap
    }

    $tier0 = @($permRows | Where-Object { $_.Tier -eq 'Tier0' })
    $writePerms = @($permRows | Where-Object { $_.Tier -eq 'Write/High' })
    if ($tier0.Count -gt 0) {
        $spNames = @($tier0.ServicePrincipal | Select-Object -Unique)
        $permSummary = @($tier0 | Group-Object Permission | Sort-Object Count -Descending | Select-Object -First 8 |
            ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })
        Add-EntraFinding -Severity 'Critical' -CheckId 'apps' -Category 'Applications' `
            -Title ("{0} apps hold top-risk permissions (tenant takeover, all mail or all files)" -f $spNames.Count) `
            -Evidence ("Apps (first 10 of {0}): {1}. Permissions found (number of grants): {2}. Also listed per grant by -enterpriseapps, which may rate some permissions differently." -f $spNames.Count, (($spNames | Select-Object -First 10) -join ', '), ($permSummary -join ', ')) `
            -WhyItMatters 'These application permissions work without any user signing in, so anyone who steals one secret or certificate of the app can, for example, make themselves Global Administrator or read every mailbox. They are among the most common routes to a full tenant compromise.' `
            -RecommendedAction 'Remove every one of these permissions that is not strictly needed (Entra admin center > Enterprise applications > app > Permissions); replace the rest with narrower, resource-scoped permissions, and switch these apps to certificate credentials with a named owner.' `
            -SourceFile $permSrc -ResultRows $tier0 -RuleId 'apps-tier0-app-permissions' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/graph/permissions-reference'
    }
    if ($writePerms.Count -gt 0) {
        $spNames = @($writePerms.ServicePrincipal | Select-Object -Unique)
        $permSummary = @($writePerms | Group-Object Permission | Sort-Object Count -Descending | Select-Object -First 8 |
            ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })
        Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Applications' `
            -Title ("{0} apps can change data or settings tenant-wide without a user signing in" -f $spNames.Count) `
            -Evidence ("Apps (first 10 of {0}): {1}. Write permissions found (number of grants): {2}. Also listed per grant by -enterpriseapps, which may rate some permissions differently." -f $spNames.Count, (($spNames | Select-Object -First 10) -join ', '), ($permSummary -join ', ')) `
            -WhyItMatters 'Application permissions with write access (for example ReadWrite, FullControl or Mail.Send) let the app change data or send mail for the whole organisation. If its secret leaks, an attacker can alter data, send mail as anyone or quietly keep access.' `
            -RecommendedAction 'Confirm each write permission is really needed; switch to read-only or resource-scoped permissions where possible, and make sure these apps use certificates and have a named owner.' `
            -SourceFile $permSrc -ResultRows $writePerms -RuleId 'apps-write-app-permissions' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/graph/permissions-reference'
    }
    if ($resourceSps.Count -eq 0) {
        # Every tenant has at least the Microsoft Graph service principal, which defines
        # application permissions. Finding none means the app-role data was not returned -
        # "no dangerous permissions" would then be an unverified (not a clean) result.
        Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Applications' `
            -Title 'App permissions could not be checked: no API with application permissions was found' `
            -Evidence ("{0} service principal(s) were read, but none returned app roles that can be granted to an application (not even Microsoft Graph), so no application permission could be evaluated." -f $sps.Count) `
            -WhyItMatters 'Apps with dangerous permissions could not be seen, so they are not reported. The absence of a finding here does not mean the tenant is clean.' `
            -RecommendedAction 'Confirm the audit account can read service principals including their app roles (Application.Read.All), then re-run the apps check.' `
            -SourceFile $permSrc -RuleId 'apps-permission-apis-not-found' -ObjectType 'tenant' -CoverageGap
    } elseif ($permRows.Count -eq 0 -and $spPermErrors.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'apps' -Category 'Applications' `
            -Title 'No app holds write-level or top-risk application permissions' `
            -Evidence ("All {0} resource API(s) that can grant application permissions were read; no service principal holds a tier-0 or write-capable application permission." -f $resourceSps.Count) `
            -WhyItMatters 'Application permissions work without a signed-in user, so keeping them read-only and narrowly scoped limits the damage a leaked app secret can do.' `
            -RecommendedAction 'Keep reviewing new application permission grants before they are admin-consented.' `
            -SourceFile $permSrc -RuleId 'apps-no-high-risk-app-permissions' -ObjectType 'tenant'
    }

    # --- over-privileged SP hardening: owners, verified publisher, multi-tenant ---
    $privSpIds = @($permRows.SpId | Where-Object { $_ } | Select-Object -Unique)

    # Owner classification inputs, loaded only when there is something to classify:
    #  - the shared privileged-user map (active + eligible, privileged roles only, role-
    #    assignable groups expanded transitively), so an admin who holds a role through a
    #    group is not mistaken for a regular user and a Directory Readers holder is not
    #    mistaken for an admin;
    #  - the shared user cache (UserById) for disabled / guest state.
    # A failed or partial read is tracked, never treated as "owner is not an admin".
    $privUserIds = @{}; $privKnown = $true; $privError = $null; $privLoaded = $false
    $usersKnown = $true; $usersError = $null
    function _LoadOwnerClassification {
        $r = [pscustomobject]@{ PrivMap=@{}; PrivError=$null; UsersError=$null }
        try { Get-EAUsers | Out-Null } catch { $r.UsersError = $_.Exception.Message }
        try { $m = Get-EAPrivilegedUserMap; if ($null -ne $m) { $r.PrivMap = $m } } catch { $r.PrivError = $_.Exception.Message }
        return $r
    }
    function _OwnerInfo($Owner, [string]$Source) {
        # $Owner: a directoryObject from an /owners read or from the owners expanded on the
        # application list (id + @odata.type only), or a bare id string.
        $oid = if ($Owner -is [string]) { $Owner } else { [string]$Owner.Id }
        $odt = if ($Owner -is [string]) { '' } else { [string](Get-Ap $Owner '@odata.type') }
        $oupn = if ($Owner -is [string]) { $null } else { Get-Ap $Owner 'userPrincipalName' }
        $oname = if ($Owner -is [string]) { $null } else { Get-Ap $Owner 'displayName' }
        $u = if ($oid -and $script:UserById.ContainsKey($oid)) { $script:UserById[$oid] } else { $null }
        if (-not $oupn -and $u) { $oupn = $u.UserPrincipalName }
        $kind = if ($odt -eq '#microsoft.graph.user' -or $oupn -or $u) { 'user' }
                elseif ($odt) { ($odt -replace '#microsoft.graph.','') }
                elseif ($usersKnown) { 'servicePrincipal' }   # id-only owner that is not a user
                else { 'unknown' }
        $isGuest = ($kind -eq 'user') -and (([string]$oupn -like '*#EXT#*') -or ($u -and [string]$u.UserType -eq 'Guest'))
        $disabled = if ($kind -ne 'user') { $false } elseif ($u) { -not [bool]$u.AccountEnabled } else { $null }
        $isAdmin = if ($kind -ne 'user') { $null } elseif ($oid -and $privUserIds.ContainsKey($oid)) { $true } elseif ($privKnown) { $false } else { $null }
        # One verdict per owner; 'Unknown' is never folded into NotAdmin (or into Admin).
        $verdict = if ($kind -eq 'unknown') { 'Unknown' }
                   elseif ($kind -ne 'user') { 'NonUser' }
                   elseif ($isGuest) { 'Guest' }
                   elseif ($disabled -eq $true) { 'Disabled' }
                   elseif ($isAdmin -eq $true) { 'Admin' }
                   elseif ($isAdmin -eq $false) { 'NotAdmin' }
                   else { 'Unknown' }
        [pscustomobject]@{
            Id=$oid; Label=($oupn ?? $oname ?? $oid); Kind=$kind; Source=$Source
            IsGuest=[bool]$isGuest; IsDisabled=$disabled; IsAdmin=$isAdmin; Verdict=$verdict
        }
    }
    if ($privSpIds.Count -gt 0) {
        $cls = _LoadOwnerClassification; $privLoaded = $true
        $privUserIds = $cls.PrivMap; $privError = $cls.PrivError; $usersError = $cls.UsersError
        # Partial map (failed eligibility read, group expansion failure, ...) = unknown.
        $privKnown = (-not $privError) -and -not ($script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)
        $usersKnown = ($script:UserById.Count -gt 0)
    }

    # Tenancy: an over-privileged service principal with no app registration in this
    # tenant belongs to ANOTHER organisation (third-party, multi-tenant by definition);
    # the verified-publisher flag then lives on the service principal itself. Microsoft
    # first-party apps (both Microsoft owner tenants) are excluded - they are not the
    # customer's to verify.
    $msftTenants = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a'   # Microsoft services
        '72f988bf-86f1-41af-91ab-2d7cd011db47'   # Microsoft corporate
    )
    $homeTenantId = if ($script:Tenant -and $script:Tenant.Id) { [string]$script:Tenant.Id } else { $null }
    if (-not $homeTenantId) { try { $homeTenantId = [string](Get-MgContext).TenantId } catch { $homeTenantId = $null } }

    $hardenRows = @()
    $ownerReadErrors = @()
    $publisherReadErrors = @()
    $privUnknownRows = @()
    $hsrc = $null
    foreach ($spId in $privSpIds) {
        $sp = $spById[$spId]
        if (-not $sp) {
            # Holds a permission but is missing from the service-principal snapshot (created
            # during the run?) - its owners/publisher were not assessed: say so.
            $ownerReadErrors += [pscustomobject]@{ ServicePrincipal=(@($permRows | Where-Object { $_.SpId -eq $spId } | Select-Object -First 1).ServicePrincipal); SpId=$spId; Error='Service principal not found in the service-principal list read at the start of the check.' }
            continue
        }
        # Enterprise-app (service principal) owners: a FAILED read is unknown, not "no owner".
        $spOwnersKnown = $true; $spOwners = @()
        try { $spOwners = @(_InvokePagedRead { param($p) Get-MgServicePrincipalOwner -ServicePrincipalId $spId -All -ErrorAction Stop @p }) }
        catch {
            $spOwnersKnown = $false
            $ownerReadErrors += [pscustomobject]@{ ServicePrincipal=$sp.DisplayName; SpId=$spId; Error=$_.Exception.Message }
        }
        $app = $appById[[string]$sp.AppId]
        # App-registration owners (own apps only) can ALSO add a credential and act as the
        # app, so they count as owners for every ownership rule below. They come expanded
        # on the cached application list; an expanded relationship returns at most 20
        # objects, so the full list is read when the expansion may have been cut off.
        $regOwners = @()
        if ($app) {
            $regOwners = @(@($app.Owners) | Where-Object { $_ })
            if ($regOwners.Count -ge 20) {
                try { $regOwners = @(_InvokePagedRead { param($p) Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction Stop @p }) }
                catch {
                    $spOwnersKnown = $false
                    $ownerReadErrors += [pscustomobject]@{ ServicePrincipal=$sp.DisplayName; SpId=$spId; Error=('(app registration owners) ' + $_.Exception.Message) }
                }
            }
        }
        $ownerInfo = @()
        foreach ($o in $spOwners) { $ownerInfo += _OwnerInfo $o 'EnterpriseApp' }
        foreach ($o in $regOwners) {
            $rid = if ($o -is [string]) { $o } else { [string]$o.Id }
            if (-not $rid -or @($ownerInfo | Where-Object { $_.Id -eq $rid }).Count -gt 0) { continue }
            $ownerInfo += _OwnerInfo $o 'AppRegistration'
        }
        # Service-principal owners are not rated here (as before); user owners are.
        $guestOwner = (@($ownerInfo | Where-Object { $_.Verdict -eq 'Guest' }).Count -gt 0)
        $nonAdminOwner = (@($ownerInfo | Where-Object { $_.Verdict -in @('NotAdmin','Disabled') }).Count -gt 0)
        $ownerPrivUnknown = (@($ownerInfo | Where-Object { $_.Verdict -eq 'Unknown' }).Count -gt 0)

        # Tenancy + publisher
        $spType = [string]$sp.ServicePrincipalType
        $ownerTenant = [string]$sp.AppOwnerOrganizationId
        $publisherType = if ($app) { 'This tenant' }
            elseif ($spType -and $spType -notin @('Application','Legacy')) { $spType }          # managed identity etc.
            elseif ($ownerTenant -and $ownerTenant -in $msftTenants) { 'Microsoft' }
            elseif ($ownerTenant -and $homeTenantId -and $ownerTenant -eq $homeTenantId) { 'This tenant (no app registration found)' }
            elseif ($ownerTenant) { 'Other organisation' }
            else { 'Unknown' }
        $multiTenant = $false; $verifiedPub = $null; $publisherName = $null
        if ($app) {
            # Both multi-org audiences: AzureADandPersonalMicrosoftAccount is also multi-tenant.
            $multiTenant = [bool]([string]$app.SignInAudience -match 'AzureADMultipleOrgs|AzureADandPersonalMicrosoftAccount')
            $publisherName = [string](Get-EAField (Get-EAField $app 'VerifiedPublisher') 'DisplayName')
            $verifiedPub = [bool]$publisherName
        } elseif ($publisherType -eq 'Other organisation') {
            $multiTenant = $true
            $publisherName = [string](Get-EAField (Get-EAField $sp 'VerifiedPublisher') 'DisplayName')
            $publisherKnown = [bool]$publisherName
            if (-not $publisherKnown) {
                # The shared service-principal list may not select verifiedPublisher: read
                # it for this (small) set of third-party high-permission apps only. A failed
                # read leaves VerifiedPublisher UNKNOWN (blank), never "unverified".
                try {
                    $spFull = Get-MgServicePrincipal -ServicePrincipalId $spId -Property 'id,verifiedPublisher' -ErrorAction Stop
                    $publisherName = [string](Get-EAField (Get-EAField $spFull 'VerifiedPublisher') 'DisplayName')
                    $publisherKnown = $true
                } catch {
                    $publisherReadErrors += [pscustomobject]@{ ServicePrincipal=$sp.DisplayName; SpId=$spId; OwnerTenant=$ownerTenant; Error=$_.Exception.Message }
                }
            }
            $verifiedPub = if ($publisherKnown) { [bool]$publisherName } else { $null }
        }

        $allOwnerCount = $ownerInfo.Count
        $hardenRows += [pscustomobject]@{
            ServicePrincipal=$sp.DisplayName; AppId=$sp.AppId; SpId=$spId
            Publisher=$publisherType; OwnerTenant=$ownerTenant
            OwnerReadState=$(if ($spOwnersKnown) { 'Known' } else { 'Failed' })
            OwnerCount=$(if ($spOwnersKnown) { $allOwnerCount } else { $null })
            Owners=(@($ownerInfo | ForEach-Object { '{0} [{1}]' -f $_.Label, $_.Source }) -join ', ')
            GuestOwner=$guestOwner; NonAdminOwner=$nonAdminOwner; OwnerAdminStatusUnknown=$ownerPrivUnknown
            MultiTenant=$multiTenant; VerifiedPublisher=$verifiedPub; VerifiedPublisherName=$publisherName
        }
    }
    if ($hardenRows.Count -gt 0 -or $ownerReadErrors.Count -gt 0) {
        $hsrc = Write-Evidence -BaseName 'app_overprivileged_hardening' -Rows $hardenRows -Title 'Over-Privileged App Hardening (owners / publisher / tenancy)' `
            -Notes @(
                'Scope: every service principal that holds a tier-0 or write-level application permission (see app_permissions).',
                'Owners = enterprise-app (service principal) owners plus app-registration owners for apps registered in this tenant; both can add a credential and act as the app.',
                'OwnerReadState=Failed: the owner list could not be read, so OwnerCount is unknown (blank) - never treated as "no owner".',
                'NonAdminOwner: a user owner who holds no privileged role (active, eligible or via a group), or a disabled user owner. OwnerAdminStatusUnknown: the role/user data needed for that decision could not be read.',
                'Publisher=Other organisation: the app is registered in another tenant (third-party); VerifiedPublisher blank = could not be read.',
                'The Enterprise Application Governance check (-enterpriseapps) separately reports every enabled app without an owner; this dataset covers only high-permission apps.'
            )
        $noOwner = @($hardenRows | Where-Object { $_.OwnerReadState -eq 'Known' -and $_.OwnerCount -eq 0 })
        $guestOwned = @($hardenRows | Where-Object { $_.GuestOwner })
        $mtUnverified = @($hardenRows | Where-Object { $_.MultiTenant -and $_.VerifiedPublisher -eq $false })
        $nonAdminOwned = @($hardenRows | Where-Object { $_.NonAdminOwner -and -not $_.GuestOwner })
        $privUnknownRows = @($hardenRows | Where-Object { $_.OwnerAdminStatusUnknown -and -not $_.NonAdminOwner -and -not $_.GuestOwner })
        if ($noOwner.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'apps' -Category 'Applications' `
                -Title ("{0} high-permission apps have no owner" -f $noOwner.Count) `
                -Evidence ("Apps with no enterprise-app or app-registration owner (first 10 of {0}): {1}. -enterpriseapps separately lists every enabled app without an owner; this finding covers only apps with high permissions." -f $noOwner.Count, (($noOwner.ServicePrincipal | Select-Object -First 10) -join ', ')) `
                -WhyItMatters 'Nobody is accountable for these powerful apps: no one reviews their permissions or renews their secrets, so misuse or a leaked secret can go unnoticed.' `
                -RecommendedAction 'Assign a named administrator as owner of each app (Entra admin center > Enterprise applications > app > Owners), or remove apps that are no longer needed.' `
                -SourceFile $hsrc -ResultRows $noOwner -RuleId 'apps-high-permission-app-no-owner' -ObjectType 'tenant'
        }
        if ($guestOwned.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'apps' -Category 'Applications' `
                -Title ("{0} high-permission apps are owned by a guest (external) user" -f $guestOwned.Count) `
                -Evidence ("Guest-owned high-permission apps (first 10 of {0}): {1}." -f $guestOwned.Count, (($guestOwned | Select-Object -First 10 | ForEach-Object { '{0} (owners: {1})' -f $_.ServicePrincipal, $_.Owners }) -join '; ')) `
                -WhyItMatters 'Any owner can add a new secret to the app and then use all of its permissions. When that owner is a guest from another organisation, someone outside your control has a path to take over the tenant.' `
                -RecommendedAction 'Remove guest owners from these apps now (Entra admin center > Enterprise applications or App registrations > app > Owners), then check the app for secrets or certificates you do not recognise.' `
                -SourceFile $hsrc -ResultRows $guestOwned -RuleId 'apps-high-permission-app-guest-owner' -ObjectType 'tenant'
        }
        if ($mtUnverified.Count -gt 0) {
            $thirdParty = @($mtUnverified | Where-Object { $_.Publisher -eq 'Other organisation' }).Count
            Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Applications' `
                -Title ("{0} high-permission third-party or multi-tenant apps have no verified publisher" -f $mtUnverified.Count) `
                -Evidence ("Apps (first 10 of {0}): {1}. Registered in another organisation: {2}; multi-tenant registrations of this tenant: {3}." -f $mtUnverified.Count, (($mtUnverified.ServicePrincipal | Select-Object -First 10) -join ', '), $thirdParty, ($mtUnverified.Count - $thirdParty)) `
                -WhyItMatters 'A verified publisher means Microsoft has confirmed who built the app. Powerful apps from unconfirmed publishers are a common way attackers trick organisations into granting access (consent phishing) or reach many customers at once (supply-chain attack).' `
                -RecommendedAction 'Confirm who publishes each app and that it still needs these permissions; remove the ones you cannot vouch for, and allow user consent only for apps from verified publishers (Entra admin center > Enterprise applications > Consent and permissions).' `
                -SourceFile $hsrc -ResultRows $mtUnverified -RuleId 'apps-high-permission-app-unverified-publisher' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview'
        }
        if ($nonAdminOwned.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Applications' `
                -Title ("{0} high-permission apps are owned by a regular or disabled user" -f $nonAdminOwned.Count) `
                -Evidence ("Apps (first 10 of {0}): {1}. An owner counts as an admin when it holds a privileged directory role, active or eligible, directly or through a group." -f $nonAdminOwned.Count, (($nonAdminOwned | Select-Object -First 10 | ForEach-Object { '{0} (owners: {1})' -f $_.ServicePrincipal, $_.Owners }) -join '; ')) `
                -WhyItMatters 'Any owner can add a new secret to the app and then act with its permissions, so an ordinary user who owns it can quietly gain admin-level access. A disabled owner account that is re-enabled or taken over gives the same path.' `
                -RecommendedAction 'Limit owners of high-permission apps to named administrators; remove regular and disabled user owners (Entra admin center > Enterprise applications or App registrations > app > Owners).' `
                -SourceFile $hsrc -ResultRows $nonAdminOwned -RuleId 'apps-high-permission-app-nonadmin-owner' -ObjectType 'tenant'
        }
        if ($ownerReadErrors.Count -gt 0) {
            $oerrSrc = Write-Evidence -BaseName 'app_owner_collection_errors' -Rows $ownerReadErrors -Title 'High-Permission App Owner Read Errors'
            $oerrApps = @($ownerReadErrors | Group-Object SpId | ForEach-Object { $_.Group[0].ServicePrincipal })
            Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Applications' `
                -Title ("Owners of {0} high-permission apps could not be read, so ownership checks are incomplete" -f $oerrApps.Count) `
                -Evidence ("Owner lists could not be read for (first 10 of {0}): {1}. First error: {2}. Typical causes: throttling, a missing permission or a transient Graph error." -f $oerrApps.Count, (($oerrApps | Select-Object -First 10) -join ', '), [string]$ownerReadErrors[0].Error) `
                -WhyItMatters 'Without the owner list the audit cannot tell whether these apps have no owner, a guest owner or a regular-user owner, each of which can let someone misuse the app. No finding for them is not a clean result.' `
                -RecommendedAction 'Re-run the apps check when Graph is not throttling, or review the owners of these apps manually (Entra admin center > Enterprise applications > app > Owners).' `
                -SourceFile $oerrSrc -ResultRows $ownerReadErrors -RuleId 'apps-high-permission-app-owners-unreadable' -ObjectType 'tenant' -CoverageGap
        }
        if ($publisherReadErrors.Count -gt 0) {
            Add-EntraFinding -Severity 'Low' -CheckId 'apps' -Category 'Applications' `
                -Title ("Publisher of {0} third-party high-permission apps could not be checked" -f $publisherReadErrors.Count) `
                -Evidence ("The verifiedPublisher property could not be read for: {0}. Error: {1}" -f (($publisherReadErrors.ServicePrincipal | Select-Object -First 10) -join ', '), (@($publisherReadErrors.Error | Select-Object -Unique -First 1) -join '')) `
                -WhyItMatters 'Powerful third-party apps from unconfirmed publishers are a common consent-phishing risk; for these apps the audit could not tell whether the publisher is verified.' `
                -RecommendedAction 'Re-run the apps check, or open each app in Entra admin center > Enterprise applications and check its publisher manually.' `
                -SourceFile $hsrc -ResultRows $publisherReadErrors -RuleId 'apps-high-permission-app-publisher-unknown' -ObjectType 'tenant' -CoverageGap
        }
    }

    # --- owners (no-owner credentialed app) ---
    # Owners come pre-expanded on the cached application objects (Get-EAApplications),
    # so this is a pure in-memory filter instead of one Graph call per credentialed app.
    # (@($null).Count is 1 in PowerShell, so null entries are filtered before counting.)
    $credApps = @($apps | Where-Object { @($_.PasswordCredentials | Where-Object { $_ }).Count -gt 0 -or @($_.KeyCredentials | Where-Object { $_ }).Count -gt 0 })
    $ownerRows = @($credApps |
        Where-Object { @($_.Owners | Where-Object { $_ }).Count -eq 0 } |
        ForEach-Object { [pscustomobject]@{ App=$_.DisplayName; AppId=$_.AppId; AppObjectId=$_.Id; Secrets=@($_.PasswordCredentials | Where-Object { $_ }).Count; Certificates=@($_.KeyCredentials | Where-Object { $_ }).Count; Note='Credentialed app registration with no owner' } })
    $ownerSrc = Write-Evidence -BaseName 'app_owners' -Rows $ownerRows -Title 'Application Ownership' `
        -Notes @(("App registrations with at least one secret or certificate: {0}; without an owner: {1}." -f $credApps.Count, $ownerRows.Count),
                 'Owners are read from the app registration (owners expanded on the application list).')
    if ($ownerRows.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Applications' `
            -Title ("{0} app registrations with a secret or certificate have no owner" -f $ownerRows.Count) `
            -Evidence ("{0} of {1} app registrations that hold a secret or certificate have no owner. First 10: {2}." -f $ownerRows.Count, $credApps.Count, (($ownerRows.App | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Nobody is responsible for renewing these credentials or reviewing what the app can do, so a forgotten secret can stay valid and be misused without anyone noticing.' `
            -RecommendedAction 'Assign a named owner to each app registration (Entra admin center > App registrations > app > Owners), or delete apps that are no longer used.' `
            -SourceFile $ownerSrc -ResultRows $ownerRows -RuleId 'apps-credentialed-app-no-owner' -ObjectType 'tenant'
    }

    # --- role-assignable groups + owners ---
    # One owner per fact: owners of role-assignable groups that HOLD a privileged directory
    # role are rated by the accesspaths check (Invoke-Check-AccessPaths - same privileged-
    # assignment cache, refined per-owner severity, same-role suppression), so they are only
    # pointed to here (Information) instead of being scored twice. This check rates the
    # groups accesspaths does not see: role-assignable groups that hold no privileged role
    # today, and - fail-safe - every owned group when the role data could not be read.
    # Failed reads are coverage gaps, never a clean result.
    $raGroups = @(); $raListError = $null; $gsrc = $null; $groupPrivUnknownRows = @()
    try { $raGroups = @(_InvokePagedRead { param($p) Get-MgGroup -Filter 'isAssignableToRole eq true' -All -ConsistencyLevel eventual -CountVariable raCount -Property 'id,displayName' -ErrorAction Stop @p }) }
    catch { $raListError = $_.Exception.Message }

    if ($raListError) {
        # Still write the dataset, so the evidence folder says the read failed instead of
        # simply having no role_assignable_groups file.
        $gsrc = Write-Evidence -BaseName 'role_assignable_groups' -Rows @() -Title 'Role-Assignable Groups' `
            -Notes @("The role-assignable group list could not be read: $raListError")
        Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Privileged Access' `
            -Title 'Role-assignable groups could not be read, so their owners were not checked' `
            -Evidence ("The role-assignable group list (isAssignableToRole eq true) could not be read: {0}" -f $raListError) `
            -WhyItMatters 'Owners of these groups can add members who then receive the group''s admin roles. Because the list could not be read, such owners are not reported - this is not a clean result.' `
            -RecommendedAction 'Confirm the audit account can read groups (Group.Read.All or Directory.Read.All) and re-run the apps check.' `
            -SourceFile $gsrc -RuleId 'apps-role-assignable-groups-unreadable' -ObjectType 'tenant' -CoverageGap
    } else {
        if (-not $privLoaded -and $raGroups.Count -gt 0) {
            $cls = _LoadOwnerClassification; $privLoaded = $true
            $privUserIds = $cls.PrivMap; $privError = $cls.PrivError; $usersError = $cls.UsersError
            $privKnown = (-not $privError) -and -not ($script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)
            $usersKnown = ($script:UserById.Count -gt 0)
        }
        # Which role-assignable groups currently hold a privileged role (active or eligible)?
        # Same predicate as accesspaths (IsPrivileged + group principal) so nothing falls
        # between the two checks.
        $groupRoles = @{}; $rolesKnown = $true; $rolesError = $null
        if ($raGroups.Count -gt 0) {
            try {
                foreach ($pa in @(Get-EAPrivAssignments)) {
                    if (-not $pa.IsPrivileged -or $pa.PrincipalType -ne 'group' -or -not $pa.PrincipalId) { continue }
                    $gk = [string]$pa.PrincipalId
                    if (-not $groupRoles.ContainsKey($gk)) { $groupRoles[$gk] = New-Object System.Collections.Generic.List[string] }
                    $label = '{0} ({1})' -f $pa.RoleName, $pa.State
                    if (-not $groupRoles[$gk].Contains($label)) { $groupRoles[$gk].Add($label) }
                }
                if ($script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed) { $rolesKnown = $false; $rolesError = 'the active or eligible role-assignment read failed' }
            } catch { $rolesKnown = $false; $rolesError = $_.Exception.Message }
        }

        $grows = @(); $groupOwnerErrors = @()
        foreach ($g in $raGroups) {
            $gOwnersKnown = $true; $gOwners = @()
            try { $gOwners = @(_InvokePagedRead { param($p) Get-MgGroupOwner -GroupId $g.Id -All -ErrorAction Stop @p }) }
            catch {
                $gOwnersKnown = $false
                $groupOwnerErrors += [pscustomobject]@{ Group=$g.DisplayName; GroupId=$g.Id; Error=$_.Exception.Message }
            }
            $info = @($gOwners | ForEach-Object { _OwnerInfo $_ 'GroupOwner' })
            # Definitely unsafe: guest, disabled, regular user or non-user (e.g. an app) owner.
            # 'Unknown' owners are a coverage gap, not a risk and not safe.
            $unsafe = @($info | Where-Object { $_.Verdict -in @('Guest','Disabled','NotAdmin','NonUser') })
            $unknownOwners = @($info | Where-Object { $_.Verdict -eq 'Unknown' })
            $holds = if ($groupRoles.ContainsKey([string]$g.Id)) { 'Yes' } elseif ($rolesKnown) { 'No' } else { 'Unknown' }
            $grows += [pscustomobject]@{
                Group=$g.DisplayName; GroupId=$g.Id
                HoldsAdminRole=$holds; AdminRoles=$(if ($groupRoles.ContainsKey([string]$g.Id)) { $groupRoles[[string]$g.Id] -join '; ' } else { '' })
                OwnerReadState=$(if ($gOwnersKnown) { 'Known' } else { 'Failed' })
                OwnerCount=$(if ($gOwnersKnown) { $info.Count } else { $null })
                Owners=(@($info | ForEach-Object { $_.Label }) -join ', ')
                OwnersNotAdmin=(@($unsafe | ForEach-Object {
                    # Capture the owner first: inside the switch, $_ is the verdict string.
                    $o = $_
                    $why = switch ($o.Verdict) { 'Guest' { 'guest' } 'Disabled' { 'disabled' } 'NotAdmin' { 'not an admin' } default { $o.Kind } }
                    '{0} ({1})' -f $o.Label, $why }) -join ', ')
                UnsafeOwnerCount=$unsafe.Count
                OwnersAdminStatusUnknown=(@($unknownOwners | ForEach-Object { $_.Label }) -join ', ')
            }
        }
        # Is the accesspaths check part of this run? Then IT rates the owners of groups that
        # hold an admin role (one owner per fact, no double score). When it is not (e.g. a
        # standalone -apps run), the run selection is unknown, or the role data is incomplete
        # (accesspaths then cannot rate them either), they are rated here, so the finding is
        # never lost.
        $accessPathsInRun = $false
        try { $accessPathsInRun = (@($script:RunInfo.SelectedChecks) -contains 'accesspaths') } catch { $accessPathsInRun = $false }
        $deferToAccessPaths = $accessPathsInRun -and $rolesKnown

        $gsrc = Write-Evidence -BaseName 'role_assignable_groups' -Rows $grows -Title 'Role-Assignable Groups' `
            -Notes @(
                ("Role-assignable groups: {0}; owner list unreadable: {1}; privileged-role data: {2}." -f $raGroups.Count, $groupOwnerErrors.Count, $(if ($rolesKnown) { 'complete' } else { "incomplete ($rolesError)" })),
                ('HoldsAdminRole=Yes: the group holds a privileged directory role (active or eligible). {0}' -f $(if ($deferToAccessPaths) { 'Owners of these groups are rated per owner by the Effective Access / Attack Paths check (-accesspaths) in this run.' } else { 'Owners of these groups are rated here (the Effective Access / Attack Paths check (-accesspaths) was not part of this run, or the role data is incomplete).' })),
                'HoldsAdminRole=Unknown: the role data could not be read, so the group is treated as if it grants an admin role.',
                'OwnersNotAdmin: owners that are guests, disabled, regular (non-admin) users or non-user objects such as apps. OwnersAdminStatusUnknown: owners whose admin status could not be read.'
            )

        $withRole = @($grows | Where-Object { $_.HoldsAdminRole -eq 'Yes' -and $_.OwnerCount -gt 0 })
        $rateHere = @($grows | Where-Object { $_.OwnerCount -gt 0 -and ($_.HoldsAdminRole -eq 'Unknown' -or ($_.HoldsAdminRole -eq 'Yes' -and -not $deferToAccessPaths)) })
        $noRoleUnsafe = @($grows | Where-Object { $_.HoldsAdminRole -eq 'No' -and $_.UnsafeOwnerCount -gt 0 })
        if ($rateHere.Count -gt 0) {
            $heldCount = @($rateHere | Where-Object { $_.HoldsAdminRole -eq 'Yes' }).Count
            $unknownCount = $rateHere.Count - $heldCount
            $unknownNote = if ($unknownCount -gt 0) { (" For {0} group(s) the admin roles could not be read ({1}), so they are treated as if they grant one." -f $unknownCount, $rolesError) } else { '' }
            Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Privileged Access' `
                -Title ("{0} role-assignable groups have owners who can add members and gain admin roles" -f $rateHere.Count) `
                -Evidence ("Groups (first 10 of {0}): {1}. Groups that hold a privileged role: {2}.{3} For a per-owner rating run -accesspaths." -f $rateHere.Count, (($rateHere | Select-Object -First 10 | ForEach-Object { '{0} [{1}] (owners: {2})' -f $_.Group, $(if ($_.AdminRoles) { $_.AdminRoles } else { 'roles unknown' }), $_.Owners }) -join '; '), $heldCount, $unknownNote) `
                -WhyItMatters 'An owner of a role-assignable group can add any account, including their own, to the group, and every member receives the admin roles given to the group. It is a quiet way to become an administrator.' `
                -RecommendedAction 'Remove owners who are not trusted administrators (Entra admin center > Groups > group > Owners), and manage membership through Privileged Identity Management (PIM) for Groups with approval.' `
                -SourceFile $gsrc -ResultRows $rateHere -RuleId 'apps-role-assignable-group-owner' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept'
        }
        if ($noRoleUnsafe.Count -gt 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Privileged Access' `
                -Title ("{0} role-assignable groups have owners who are not admins and can add members" -f $noRoleUnsafe.Count) `
                -Evidence ("Groups that hold no privileged directory role today (first 10 of {0}): {1}." -f $noRoleUnsafe.Count, (($noRoleUnsafe | Select-Object -First 10 | ForEach-Object { '{0} (owners: {1})' -f $_.Group, $_.OwnersNotAdmin }) -join '; ')) `
                -WhyItMatters 'These groups are built to carry admin roles, and their owners can add anyone as a member. If an admin role is later given to the group, or the group already grants access to Azure resources or apps, these owners decide who gets that access.' `
                -RecommendedAction 'Remove regular, guest and disabled owners from role-assignable groups (Entra admin center > Groups > group > Owners), and delete role-assignable groups that are not needed.' `
                -SourceFile $gsrc -ResultRows $noRoleUnsafe -RuleId 'apps-role-assignable-group-nonadmin-owner' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept'
        }
        if ($deferToAccessPaths -and $withRole.Count -gt 0) {
            Add-EntraFinding -Severity 'Information' -CheckId 'apps' -Category 'Privileged Access' `
                -Title ("Owners of {0} groups that hold admin roles are rated by the Effective Access check" -f $withRole.Count) `
                -Evidence ("Role-assignable groups that hold a privileged role and have owners (first 10 of {0}): {1}." -f $withRole.Count, (($withRole | Select-Object -First 10 | ForEach-Object { '{0} [{1}] (owners: {2})' -f $_.Group, $_.AdminRoles, $_.Owners }) -join '; ')) `
                -WhyItMatters 'An owner of a group that holds an admin role can add themselves and receive that role. The Effective Access / Attack Paths check (-accesspaths) rates each such owner in this run, so the risk is not counted twice.' `
                -RecommendedAction 'Act on the ownership findings of the Effective Access / Attack Paths check (-accesspaths).' `
                -SourceFile $gsrc -ResultRows $withRole -RuleId 'apps-role-assignable-group-owner-see-accesspaths' -ObjectType 'tenant'
        }
        $groupPrivUnknownRows = @($grows | Where-Object { $_.HoldsAdminRole -eq 'No' -and $_.OwnersAdminStatusUnknown -and $_.UnsafeOwnerCount -eq 0 })
        if ($groupOwnerErrors.Count -gt 0) {
            Add-EntraFinding -Severity 'Low' -CheckId 'apps' -Category 'Privileged Access' `
                -Title ("Owners of {0} role-assignable groups could not be read" -f $groupOwnerErrors.Count) `
                -Evidence ("Owner lists could not be read for: {0}. First error: {1}" -f (($groupOwnerErrors.Group | Select-Object -First 10) -join ', '), [string]$groupOwnerErrors[0].Error) `
                -WhyItMatters 'If the owners of a role-assignable group are unknown, the audit cannot tell whether someone can add themselves to it. No finding for these groups is not a clean result.' `
                -RecommendedAction 'Confirm the audit account can read group owners (Group.Read.All) and re-run the apps check, or review these groups'' owners manually.' `
                -SourceFile $gsrc -ResultRows $groupOwnerErrors -RuleId 'apps-role-assignable-group-owners-unreadable' -ObjectType 'tenant' -CoverageGap
        }
    }

    # Owners whose admin status could not be decided (role data or user data unreadable)
    # are neither reported as "regular user" nor silently treated as admins: say so.
    $statusUnknownRows = @(
        foreach ($r in $privUnknownRows) { [pscustomobject]@{ Object=$r.ServicePrincipal; ObjectKind='High-permission app'; Owners=$r.Owners } }
        foreach ($r in $groupPrivUnknownRows) { [pscustomobject]@{ Object=$r.Group; ObjectKind='Role-assignable group'; Owners=$r.OwnersAdminStatusUnknown } }
    )
    if ($statusUnknownRows.Count -gt 0) {
        $whyUnknown = @()
        if ($privError) { $whyUnknown += ('the privileged-role list could not be read: {0}' -f $privError) }
        elseif (-not $privKnown) { $whyUnknown += 'the privileged-role data is incomplete (an active or eligible assignment read, or a privileged group expansion, failed)' }
        if ($usersError) { $whyUnknown += ('the user list could not be read: {0}' -f $usersError) }
        if ($whyUnknown.Count -eq 0) { $whyUnknown += 'some owners could not be matched to a user or a privileged role' }
        Add-EntraFinding -Severity 'Information' -CheckId 'apps' -Category 'Applications' `
            -Title ("Could not confirm whether the owners of {0} apps or groups are administrators" -f $statusUnknownRows.Count) `
            -Evidence ("Affected (first 10 of {0}): {1}. Reason: {2}." -f $statusUnknownRows.Count, (($statusUnknownRows | Select-Object -First 10 | ForEach-Object { '{0} [{1}]' -f $_.Object, $_.ObjectKind }) -join ', '), ($whyUnknown -join '; ')) `
            -WhyItMatters 'A regular user who owns a high-permission app or a role-assignable group can use it to gain admin access. For these owners the audit could not tell, so a missing finding here is not a clean result.' `
            -RecommendedAction 'Confirm the audit account can read directory roles, Privileged Identity Management (PIM) eligibility and group members (RoleManagement.Read.Directory, Group.Read.All, User.Read.All), then re-run the apps check.' `
            -SourceFile $(if ($hsrc) { $hsrc } else { $gsrc }) -ResultRows $statusUnknownRows -RuleId 'apps-owner-admin-status-unknown' -ObjectType 'tenant' -CoverageGap
    }
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
    # Rule ids: the expired/expiring findings keep their original RuleId + ObjectType so
    # their trend ids do not change; the two Information baselines got an explicit RuleId
    # (one-time migration from the old title-slug ids).

    $rows = @()
    $noEndCount = 0
    foreach ($a in $apps) {
        $creds = @()
        foreach ($c in @($a.PasswordCredentials | Where-Object { $_ })) { $creds += [pscustomobject]@{ C=$c; T='Secret' } }
        foreach ($c in @($a.KeyCredentials | Where-Object { $_ })) {
            $t = if ($c.Usage) { 'Certificate/' + $c.Usage } else { 'Certificate' }
            $creds += [pscustomobject]@{ C=$c; T=$t }
        }
        foreach ($cc in $creds) {
            $c = $cc.C
            if (-not $c.EndDateTime) { $noEndCount++; continue }   # no expiry date (counted in the evidence notes)
            $end = [datetime]$c.EndDateTime
            # Compare in UTC: a Local-kind value compared with UTC 'now' is off by the
            # machine's UTC offset (hours), which can flip a credential across a boundary.
            if ($end.Kind -eq [System.DateTimeKind]::Local) { $end = $end.ToUniversalTime() }
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
        -Notes @(
            ("Expiry warning window: {0} days (-ExpiringCredentialDays)" -f $warnDays),
            'DaysLeft below 0 means the credential has already expired.',
            ("App registrations read: {0}; secrets/certificates with an expiry date: {1}; without an expiry date (not listed): {2}." -f @($apps).Count, $rows.Count, $noEndCount),
            'Scope: app registrations in this tenant only. The Workload Identity Credentials check (-workloadcredentials) also covers service-principal credentials, credentials without an expiry and long-lived secrets.'
        )

    if ($rows.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'appcredentials' -Category 'Applications' `
            -Title 'No app registration has a secret or certificate with an expiry date' `
            -Evidence ("{0} app registration(s) were read; none carries a secret (password credential) or certificate (key credential) with an end date. Credentials without an end date: {1}." -f @($apps).Count, $noEndCount) `
            -WhyItMatters 'Nothing can expire, so no integration outage is expected from expiring credentials. Apps may sign in with federated (workload identity) credentials instead, or have no credentials yet.' `
            -RecommendedAction 'No action needed. Re-run this check after integrations start using secrets or certificates.' `
            -SourceFile $src -RuleId 'appcredentials-none-with-expiry' -ObjectType 'tenant'
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
            ForEach-Object { "{0} [{1}] expired {2} days ago" -f $_.App, $_.CredType, [math]::Abs($_.DaysLeft) })
        $deadNote = if ($deadApps.Count -gt 0) { " {0} app(s) have NO valid secret or certificate left, so their integration has most likely stopped working." -f $deadApps.Count } else { '' }
        Add-EntraFinding -Severity 'Medium' -CheckId 'appcredentials' -Category 'Applications' `
            -Title ("{0} app secrets or certificates have expired on {1} app registrations" -f $expired.Count, $expApps.Count) `
            -Evidence ("Expired credentials (oldest first, up to 10): {0}.{1} The Workload Identity Credentials check (-workloadcredentials) may list the same credentials." -f ($worst -join '; '), $deadNote) `
            -WhyItMatters 'An expired secret or certificate usually means the connected integration has already stopped working, or that nobody removed a credential the app no longer uses. Either way, these app registrations are not being looked after.' `
            -RecommendedAction 'For each app, check whether the integration is still needed. If it is, create a new credential (preferably a certificate) and update the system that uses it; if not, delete the expired credential or the whole app (Entra admin center > App registrations > app > Certificates & secrets).' `
            -SourceFile $src -RuleId 'app-credential-expired' -ObjectType 'application' `
            -ResultRows @($expired | Select-Object App,AppId,CredType,CredName,End,DaysLeft | Sort-Object DaysLeft)
    }
    if ($expiring.Count -gt 0) {
        $expApps = @($expiring.App | Select-Object -Unique)
        $next = @($expiring | Sort-Object DaysLeft | Select-Object -First 10 |
            ForEach-Object { "{0} [{1}] {2} days left" -f $_.App, $_.CredType, $_.DaysLeft })
        Add-EntraFinding -Severity 'Low' -CheckId 'appcredentials' -Category 'Applications' `
            -Title ("{0} app secrets or certificates expire within {1} days on {2} app registrations" -f $expiring.Count, $warnDays, $expApps.Count) `
            -Evidence ("Credentials expiring soon (soonest first, up to 10): {0}. The Workload Identity Credentials check (-workloadcredentials) may list the same credentials." -f ($next -join '; ')) `
            -WhyItMatters 'When a secret or certificate runs out without a planned renewal, the integration that uses it stops working without warning. Renewing it inside the warning window avoids that outage.' `
            -RecommendedAction 'Plan the renewal of each credential before its end date and update the system that uses it; prefer certificates with a defined renewal process, and delete credentials that are no longer used (Entra admin center > App registrations > app > Certificates & secrets).' `
            -SourceFile $src -RuleId 'app-credential-expiring' -ObjectType 'application' `
            -ResultRows @($expiring | Select-Object App,AppId,CredType,CredName,End,DaysLeft | Sort-Object DaysLeft)
    }
    if ($expired.Count -eq 0 -and $expiring.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'appcredentials' -Category 'Applications' `
            -Title ("All {0} app secrets and certificates are valid for more than {1} days" -f $rows.Count, $warnDays) `
            -Evidence ("{0} dated secret(s)/certificate(s) on {1} app registration(s) were checked: none has expired and none expires within {2} days." -f $rows.Count, @($rows.AppId | Select-Object -Unique).Count, $warnDays) `
            -WhyItMatters 'Current secrets and certificates are within their validity period, so no integration outage from an expiring credential is expected in the warning window.' `
            -RecommendedAction 'Keep a renewal calendar and re-run this check regularly to catch upcoming expiries.' `
            -SourceFile $src -ResultRows $rows -RuleId 'appcredentials-all-valid' -ObjectType 'tenant'
    }
}

# ===========================================================================
# CHECK 13 - consentgrants (OAuth2 delegated grants)
# ===========================================================================
function Invoke-Check-ConsentGrants {
    # Per-user grants are one row per (user, app), so large tenants hold 100k+ grants.
    # Page size 999 (service default 100) cuts round-trips up to 10x; if the service rejects
    # the page size the read is repeated once with the default. Any other failure
    # propagates to Invoke-AuditCheck (Error / Skipped-NoPermission), never a clean result.
    try { $grants = @(Get-MgOauth2PermissionGrant -All -PageSize 999 -ErrorAction Stop) }
    catch {
        if ([string]$_.Exception.Message -notmatch '(?i)Status:\s*400|BadRequest|page\s*size|\$top') { throw }
        $grants = @(Get-MgOauth2PermissionGrant -All -ErrorAction Stop)
    }
    # Rule ids: every finding carries an explicit -RuleId (one-time migration from the old
    # title-slug ids) so rewording a title never changes its trend id again.

    # Resolve SP display names from the shared cache when a check already populated it;
    # otherwise ONE paged list call (id,displayName) replaces the previous per-id lookups
    # (two Graph calls per grant on tenants with thousands of grants). A failed name read
    # only costs readability (ids are shown instead) - the grants are still evaluated.
    $spById = @{}; $nameReadError = $null
    if ($null -ne $script:SpsCache) {
        foreach ($sp in $script:SpsCache) { if ($sp.Id) { $spById[$sp.Id] = $sp } }
    } else {
        try { foreach ($sp in @(Get-MgServicePrincipal -All -Property 'id,displayName' -PageSize 999 -ErrorAction Stop)) { if ($sp.Id) { $spById[$sp.Id] = $sp } } }
        catch { $nameReadError = $_.Exception.Message }
    }
    # offline_access alone is routine (it only lengthens token lifetime) and User.ReadWrite
    # (self-profile) is not high-impact - flagging them alone made nearly every ordinary
    # admin-consented app a High finding. Only data/directory-write scopes count as high.
    $highScopes = 'Mail\.|Files\.ReadWrite|Directory\.ReadWrite|User\.ReadWrite\.All|full_access|Sites\.ReadWrite|Sites\.FullControl'
    $rows = @(foreach ($g in $grants) {
        $client = if ($g.ClientId -and $spById.ContainsKey($g.ClientId)) { $spById[$g.ClientId] } else { $null }
        $resource = if ($g.ResourceId -and $spById.ContainsKey($g.ResourceId)) { $spById[$g.ResourceId] } else { $null }
        $scopeList = @(([string]$g.Scope -split '\s+') | Where-Object { $_ })
        $user = $null
        if ($g.PrincipalId) {
            $user = if ($script:UserById.ContainsKey([string]$g.PrincipalId)) { $script:UserById[[string]$g.PrincipalId].UserPrincipalName } else { [string]$g.PrincipalId }
        }
        [pscustomobject]@{
            Client=($client.DisplayName ?? $g.ClientId); ClientId=$g.ClientId; ConsentType=$g.ConsentType
            User=$user
            Resource=($resource.DisplayName ?? $g.ResourceId); Scope=$g.Scope
            HighImpactScopes=(@($scopeList | Where-Object { $_ -match $highScopes }) -join ' ')
            High=([string]$g.Scope -match $highScopes)
        }
    })
    $notes = @(
        ("Delegated permission grants: {0} (tenant-wide / AllPrincipals: {1}; single user / Principal: {2})." -f $rows.Count, @($rows | Where-Object { $_.ConsentType -eq 'AllPrincipals' }).Count, @($rows | Where-Object { $_.ConsentType -ne 'AllPrincipals' }).Count),
        'High = the grant includes a high-impact scope: any Mail.*, Files.ReadWrite*, Sites.ReadWrite* / Sites.FullControl*, Directory.ReadWrite*, User.ReadWrite.All or full_access*.',
        'User = the user who consented (per-user grants only); shown as an object id when the user list was not loaded in this run.',
        'The Enterprise Application Governance check (-enterpriseapps) also rates delegated grants, with its own permission risk tiers.'
    )
    if ($nameReadError) { $notes += ('App names could not be read, so ids are shown instead: {0}' -f $nameReadError) }
    $src = Write-Evidence -BaseName 'oauth_consent_grants' -Rows $rows -Title 'OAuth2 Delegated Consent Grants' -Notes $notes

    $tenantWideHigh = @($rows | Where-Object { $_.ConsentType -eq 'AllPrincipals' -and $_.High })
    if ($tenantWideHigh.Count -gt 0) {
        $twApps = @($tenantWideHigh.Client | Select-Object -Unique)
        Add-EntraFinding -Severity 'High' -CheckId 'consentgrants' -Category 'Applications' `
            -Title ("{0} apps were approved to access mail, files or directory data for all users" -f $twApps.Count) `
            -Evidence ("{0} tenant-wide (AllPrincipals) grant(s) to {1} app(s) include a high-impact scope. Apps (first 10): {2}. Scopes: {3}. -enterpriseapps also rates these grants." -f $tenantWideHigh.Count, $twApps.Count, (($twApps | Select-Object -First 10) -join ', '), ((@($tenantWideHigh.HighImpactScopes -split ' ') | Where-Object { $_ } | Select-Object -Unique -First 12) -join ', ')) `
            -WhyItMatters 'An admin approved these apps to act as any signed-in user on mail, files or directory data. If one of them is malicious or compromised it can read or change that data for everyone, and the approval stays in place, even after password resets, until someone removes it.' `
            -RecommendedAction 'Review each app (Entra admin center > Enterprise applications > app > Permissions); revoke the grants of apps you do not recognise or no longer need, and allow user consent only for verified publishers and low-risk permissions.' `
            -SourceFile $src -ResultRows $tenantWideHigh -RuleId 'consentgrants-tenant-wide-high-impact' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions'
    }
    $userHigh = @($rows | Where-Object { $_.ConsentType -ne 'AllPrincipals' -and $_.High })
    if ($userHigh.Count -gt 0) {
        $uhApps = @($userHigh.Client | Select-Object -Unique)
        $uhUsers = @($userHigh.User | Where-Object { $_ } | Select-Object -Unique)
        Add-EntraFinding -Severity 'Medium' -CheckId 'consentgrants' -Category 'Applications' `
            -Title ("{0} apps were approved by individual users to access their mail, files or directory data" -f $uhApps.Count) `
            -Evidence ("{0} per-user grant(s) by {1} user(s) to {2} app(s) include a high-impact scope. Apps (first 10): {3}. -enterpriseapps also rates these grants." -f $userHigh.Count, $uhUsers.Count, $uhApps.Count, (($uhApps | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'In consent phishing, an attacker tricks a user into approving a malicious app, which can then read that user''s mail or files without ever needing the password.' `
            -RecommendedAction 'Revoke grants to apps you do not recognise (Entra admin center > Enterprise applications > app > Permissions > User consent), and allow users to consent only to apps from verified publishers with low-risk permissions (Enterprise applications > Consent and permissions).' `
            -SourceFile $src -ResultRows $userHigh -RuleId 'consentgrants-user-consent-high-impact' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent'
    }
    # Admin consent request workflow - if disabled while user consent is permissive,
    # users have no safe path to request apps and may be tempted into risky self-consent.
    # A failed read is a coverage gap, not "the workflow is enabled".
    $acr = $null; $acrError = $null
    try { $acr = Get-MgPolicyAdminConsentRequestPolicy -ErrorAction Stop } catch { $acrError = $_.Exception.Message }
    if (-not $acrError -and $null -eq $acr) { $acrError = 'the policy read returned no data' }
    if ($acrError) {
        Add-EntraFinding -Severity 'Information' -CheckId 'consentgrants' -Category 'Applications' `
            -Title 'Could not check whether users can request admin approval for apps' `
            -Evidence ("The admin consent request policy (adminConsentRequestPolicy) could not be read: {0}" -f $acrError) `
            -WhyItMatters 'If the admin consent workflow is off, users have no safe way to ask for an app, which pushes organisations to leave user consent open. The audit could not tell, so no finding here is not a clean result.' `
            -RecommendedAction 'Grant the audit account Policy.Read.All and re-run the consentgrants check, or check the setting in Entra admin center > Enterprise applications > Consent and permissions > Admin consent settings.' `
            -SourceFile $src -RuleId 'consentgrants-admin-consent-workflow-unreadable' -ObjectType 'tenant' -CoverageGap
    } elseif (-not $acr.IsEnabled) {
        Add-EntraFinding -Severity 'Low' -CheckId 'consentgrants' -Category 'Applications' `
            -Title 'Users cannot ask an admin to approve an app (admin consent workflow is off)' `
            -Evidence 'adminConsentRequestPolicy.isEnabled = false.' `
            -WhyItMatters 'Without a request process, users who need an app either get stuck or push for user consent to stay open - the setting that consent phishing abuses.' `
            -RecommendedAction 'Turn on the admin consent workflow and name reviewers (Entra admin center > Enterprise applications > Consent and permissions > Admin consent settings), so user consent can stay restricted.' `
            -SourceFile $src -RuleId 'consentgrants-admin-consent-workflow-disabled' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow'
    }

    if ($tenantWideHigh.Count -eq 0 -and $userHigh.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'consentgrants' -Category 'Applications' `
            -Title 'No app has been approved for high-impact access to mail, files or directory data' `
            -Evidence ("{0} delegated permission grant(s) reviewed; none includes a high-impact scope (mail, files, SharePoint sites, directory write or all-user write)." -f $rows.Count) `
            -WhyItMatters 'Limiting which apps users and admins can approve prevents consent phishing, where a malicious app is approved and then reads mail or files.' `
            -RecommendedAction 'Keep user consent restricted and review app grants periodically.' `
            -SourceFile $src -RuleId 'consentgrants-no-high-impact-grants' -ObjectType 'tenant'
    }
}

# ===========================================================================
# CHECK 14 - devices
# ===========================================================================
function Invoke-Check-Devices {
    # RegistrationDateTime is needed to age a device that has NO sign-in on record: a device
    # registered yesterday (Autopilot pre-provisioning, a fresh join before its first token
    # refresh) has a null approximateLastSignInDateTime and must not be reported as
    # "no sign-in for 90 days". -PageSize 999: device inventories are among the largest
    # collections in a tenant and the service default page is only 100.
    $devices = @(Get-MgDevice -All -PageSize 999 -Property Id,DeviceId,DisplayName,AccountEnabled,ApproximateLastSignInDateTime,RegistrationDateTime,IsManaged,IsCompliant,TrustType,OperatingSystem,OperatingSystemVersion -ErrorAction Stop)
    $cut = (Get-Date).ToUniversalTime().AddDays(-$InactiveDays)
    $cutText = $cut.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)

    # Classify every device exactly once (Lists, not array +=: inventories can be 100k+).
    #   Stale       - last sign-in older than the window, or no sign-in on record AND
    #                 registered before the window (same rule as the staleapps check).
    #   Unknown age - neither timestamp returned: cannot be judged, never assumed active.
    #   Active      - everything else.
    $stale = New-Object System.Collections.Generic.List[object]
    $unknownAge = New-Object System.Collections.Generic.List[object]
    $activityById = @{}
    foreach ($d in $devices) {
        $last = $d.ApproximateLastSignInDateTime
        $registered = $d.RegistrationDateTime
        $activity = if ($last) { if ($last -lt $cut) { 'Stale' } else { 'Active' } }
                    elseif ($registered) { if ($registered -lt $cut) { 'Stale (never signed in)' } else { 'Active (newly registered)' } }
                    else { 'Unknown age' }
        if ($d.Id) { $activityById[[string]$d.Id] = $activity }
        if ($activity -like 'Stale*') { $stale.Add($d) | Out-Null }
        elseif ($activity -eq 'Unknown age') { $unknownAge.Add($d) | Out-Null }
    }
    $joinTypeText = {
        param($trustType)
        switch ([string]$trustType) {
            'Workplace' { 'Entra registered (personal / BYOD)' }
            'AzureAd'   { 'Entra joined' }
            'ServerAd'  { 'Hybrid joined (synced from on-prem AD)' }
            ''          { 'Unknown' }
            default     { [string]$trustType }
        }
    }
    $rows = @($devices | Select-Object DisplayName, AccountEnabled,
        @{n='Activity';e={ $activityById[[string]$_.Id] }},
        ApproximateLastSignInDateTime, RegistrationDateTime, IsManaged, IsCompliant,
        @{n='JoinType';e={ & $joinTypeText $_.TrustType }}, TrustType, OperatingSystem, OperatingSystemVersion, DeviceId)
    $src = Write-Evidence -BaseName 'devices' -Rows $rows -Title 'Devices' -Notes @(
        ("Stale = last sign-in (approximateLastSignInDateTime) before {0} ({1} days), or no sign-in on record and registered before that date." -f $cutText, $InactiveDays),
        'approximateLastSignInDateTime is only refreshed about every 14 days, so it is an approximate value.',
        'Unknown age = neither a sign-in time nor a registration date was returned for the device.',
        ("Devices: {0}; stale: {1}; unknown age: {2}." -f $devices.Count, $stale.Count, $unknownAge.Count))

    # A stale device is reported once, as stale. Counting it again as "unmanaged" would
    # double-score the same dead object and overstate the live Conditional Access surface.
    $staleIds = @{}
    foreach ($d in $stale) { if ($d.Id) { $staleIds[[string]$d.Id] = $true } }
    $unmanaged = @($devices | Where-Object {
        $_.AccountEnabled -and -not $staleIds.ContainsKey([string]$_.Id) -and ($_.IsManaged -eq $false -or $_.IsCompliant -eq $false)
    })

    if ($stale.Count -gt 0) {
        $staleEnabled = @($stale | Where-Object { $_.AccountEnabled }).Count
        $staleNever = @($stale | Where-Object { -not $_.ApproximateLastSignInDateTime }).Count
        $staleHybrid = @($stale | Where-Object { [string]$_.TrustType -eq 'ServerAd' }).Count
        Add-EntraFinding -Severity 'Medium' -CheckId 'devices' -Category 'Devices' `
            -Title ("{0} device(s) have not signed in for more than {1} days" -f $stale.Count, $InactiveDays) `
            -Evidence ("Stale device records: {0} ({1} still enabled, {2} disabled). {3} of them never signed in and were registered before {4}. {5} are hybrid joined (synced from on-premises AD). Cut-off: no sign-in since {4} ({6} days); the sign-in time is refreshed only about every 14 days." -f `
                $stale.Count, $staleEnabled, ($stale.Count - $staleEnabled), $staleNever, $cutText, $staleHybrid, $InactiveDays) `
            -WhyItMatters 'An old device record that is still enabled keeps counting as a known company device, so a lost, sold or rebuilt laptop can go on satisfying Conditional Access (CA) rules that require a registered or compliant device. Clutter also makes the device inventory hard to trust.' `
            -RecommendedAction ("Disable device records with no sign-in for more than {0} days, then delete them after a grace period (Entra admin center > Devices > All devices, filter on activity). Clean up hybrid-joined devices in on-premises Active Directory first, or sync will bring them back." -f $InactiveDays) `
            -SourceFile $src -ResultRows @($stale | Select-Object DisplayName, AccountEnabled, ApproximateLastSignInDateTime, RegistrationDateTime, @{n='JoinType';e={ & $joinTypeText $_.TrustType }}, OperatingSystem | Select-Object -First 100) `
            -RuleId 'devices-stale' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/devices/manage-stale-devices'
    }
    if ($unmanaged.Count -gt 0) {
        $notManaged = @($unmanaged | Where-Object { $_.IsManaged -eq $false }).Count
        $nonCompliantOther = @($unmanaged | Where-Object { $_.IsManaged -ne $false -and $_.IsCompliant -eq $false }).Count
        $byJoin = (@($unmanaged | Group-Object { & $joinTypeText $_.TrustType } | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) -join '; ')
        # Devices of unknown age are not proven stale, so they stay in this count - but they
        # are not known to be in use either, and the title must not call them "active".
        $unmanagedUnknownAge = @($unmanaged | Where-Object { -not $_.ApproximateLastSignInDateTime -and -not $_.RegistrationDateTime }).Count
        $unmanagedTitle = if ($unmanagedUnknownAge -gt 0) { '{0} device(s) still in use or of unknown age are not managed or fail compliance' -f $unmanaged.Count }
                          else { '{0} active device(s) are not managed or fail compliance' -f $unmanaged.Count }
        $unknownAgeText = if ($unmanagedUnknownAge -gt 0) { ' {0} of them have no sign-in or registration date, so whether they are still in use is unknown (they are also listed in the unknown-age finding).' -f $unmanagedUnknownAge } else { '' }
        Add-EntraFinding -Severity 'Medium' -CheckId 'devices' -Category 'Devices' `
            -Title $unmanagedTitle `
            -Evidence ("Enabled devices that are not stale: {0} reported as not managed (IsManaged=false) and {1} more reported as non-compliant (IsCompliant=false).{2} By join type - {3}. Stale devices are excluded (reported separately); devices that report no management/compliance state at all are not counted." -f $notManaged, $nonCompliantOther, $unknownAgeText, $byJoin) `
            -WhyItMatters 'A device that no management tool controls, or that fails your security baseline (for example no disk encryption or missing updates), can still reach company data unless Conditional Access (CA) requires a compliant device. Compromised personal devices are a common way in.' `
            -RecommendedAction 'Require a compliant or hybrid-joined device in Conditional Access for sensitive apps (Entra admin center > Protection > Conditional Access), then enrol or fix the listed devices in Intune, or remove their access.' `
            -SourceFile $src -ResultRows @($unmanaged | Select-Object DisplayName, IsManaged, IsCompliant, @{n='Activity';e={ $activityById[[string]$_.Id] }}, @{n='JoinType';e={ & $joinTypeText $_.TrustType }}, OperatingSystem, ApproximateLastSignInDateTime | Select-Object -First 100) `
            -RuleId 'devices-unmanaged-or-noncompliant' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance'
    }
    if ($unknownAge.Count -gt 0) {
        $unknownEnabled = @($unknownAge | Where-Object { $_.AccountEnabled }).Count
        Add-EntraFinding -Severity 'Information' -CheckId 'devices' -Category 'Devices' `
            -Title ("{0} device(s) have no sign-in or registration date, so their age is unknown" -f $unknownAge.Count) `
            -Evidence ("Neither approximateLastSignInDateTime nor registrationDateTime was returned for {0} device record(s) ({1} enabled). Whether they are stale could not be assessed - this is not a clean result." -f $unknownAge.Count, $unknownEnabled) `
            -WhyItMatters 'A missing date is not proof that a device is still in use; abandoned devices in this group would otherwise slip past the stale-device check.' `
            -RecommendedAction 'Review these devices in Entra admin center > Devices > All devices and disable or delete the ones nobody can account for.' `
            -SourceFile $src -ResultRows @($unknownAge | Select-Object DisplayName, AccountEnabled, @{n='JoinType';e={ & $joinTypeText $_.TrustType }}, OperatingSystem, DeviceId | Select-Object -First 100) `
            -RuleId 'devices-unknown-age' -ObjectType 'tenant' -CoverageGap
    }
    if ($stale.Count -eq 0 -and $unmanaged.Count -eq 0 -and $unknownAge.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'devices' -Category 'Devices' `
            -Title ("No stale or unmanaged devices found ({0} device(s) checked)" -f $devices.Count) `
            -Evidence ("All {0} device record(s) signed in (or were registered) within the last {1} days, and no enabled device is reported as unmanaged or non-compliant." -f $devices.Count, $InactiveDays) `
            -WhyItMatters 'A clean, current device list is what device-based Conditional Access (CA) rules rely on.' `
            -RecommendedAction 'Keep the scheduled clean-up of old device records and the device compliance policies in place.' -SourceFile $src `
            -RuleId 'devices-baseline' -ObjectType 'tenant'
    }
}

# ===========================================================================
# CHECK 15 - trusts (cross-tenant access)
# ===========================================================================
function Invoke-Check-Trusts {
    $checkId = 'trusts'; $category = 'External Access'
    $crossTenantDoc = 'https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-settings-b2b-collaboration'
    $portalPath = 'Entra admin center > External Identities > Cross-tenant access settings'

    # Both reads are tracked explicitly: a failed read must never surface as "0 partners"
    # or as "reviewed, nothing flagged".
    $def = $null; $defError = $null
    try { $def = Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction Stop } catch { $defError = $_.Exception.Message }
    $partners = @(); $partnersKnown = $true; $partnersError = $null
    try { $partners = @(Get-MgPolicyCrossTenantAccessPolicyPartner -All -ErrorAction Stop) } catch { $partnersKnown = $false; $partnersError = $_.Exception.Message }
    $partnerText = if ($partnersKnown) { '{0} partner-specific configuration(s) exist; they override the default only for those named organizations.' -f $partners.Count }
                   else { 'Partner-specific configurations could not be read, so how many organizations have their own settings is unknown.' }

    # Display-only enrichment: resolve partner tenant names (GET findTenantInformationByTenantId,
    # CrossTenantInformation.ReadBasic.All). A failed lookup only means the tenant id is shown.
    $partnerNames = @{}; $nameLookupFailed = $false
    foreach ($p in @($partners | Select-Object -First 50)) {
        $ptid = [string]$p.TenantId
        if ($nameLookupFailed -or $ptid -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { continue }
        try {
            $info = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='{0}')" -f $ptid) -ErrorAction Stop
            $pname = [string](Get-EAField $info 'displayName')
            if ($pname) { $partnerNames[$ptid] = $pname }
        } catch { $nameLookupFailed = $true }
    }

    # Read a nested setting; $null means "not set": on the DEFAULT policy that is shown as
    # '(not returned)', on a PARTNER entry it means the partner inherits the default.
    function _RawSetting {
        param($Container, [string[]]$Path)
        $v = $Container
        foreach ($segment in $Path) { if ($null -eq $v) { return $null }; $v = Get-EAField $v $segment }
        return $v
    }
    function _Setting {
        param($Container, [string[]]$Path, [string]$NullText)
        $v = _RawSetting -Container $Container -Path $Path
        if ($null -eq $v) { return $NullText }
        return $v
    }
    $settingMap = @(
        @{ Label='B2B collaboration inbound (users/groups)';      Path=@('B2bCollaborationInbound','UsersAndGroups','AccessType') }
        @{ Label='B2B collaboration inbound (applications)';      Path=@('B2bCollaborationInbound','Applications','AccessType') }
        @{ Label='B2B collaboration outbound (users/groups)';     Path=@('B2bCollaborationOutbound','UsersAndGroups','AccessType') }
        @{ Label='B2B direct connect inbound (users/groups)';     Path=@('B2bDirectConnectInbound','UsersAndGroups','AccessType') }
        @{ Label='B2B direct connect inbound (applications)';     Path=@('B2bDirectConnectInbound','Applications','AccessType') }
        @{ Label='B2B direct connect outbound (users/groups)';    Path=@('B2bDirectConnectOutbound','UsersAndGroups','AccessType') }
        @{ Label='Inbound trust: MFA accepted';                   Path=@('InboundTrust','IsMfaAccepted') }
        @{ Label='Inbound trust: compliant device accepted';      Path=@('InboundTrust','IsCompliantDeviceAccepted') }
        @{ Label='Inbound trust: hybrid-joined device accepted';  Path=@('InboundTrust','IsHybridAzureADJoinedDeviceAccepted') }
        @{ Label='Automatic inbound user consent (redemption)';   Path=@('AutomaticUserConsentSettings','InboundAllowed') }
    )

    $rows = New-Object System.Collections.Generic.List[object]
    if ($def) {
        $rows.Add([pscustomobject]@{ Scope='Default (all other organizations)'; Setting='Microsoft default settings unchanged (isServiceDefault)'; Value=(_Setting -Container $def -Path @('IsServiceDefault') -NullText '(not returned)') }) | Out-Null
        foreach ($s in $settingMap) {
            $rows.Add([pscustomobject]@{ Scope='Default (all other organizations)'; Setting=$s.Label; Value=(_Setting -Container $def -Path $s.Path -NullText '(not returned)') }) | Out-Null
        }
    }
    foreach ($p in $partners) {
        $ptid = [string]$p.TenantId
        $scope = if ($partnerNames.ContainsKey($ptid)) { 'Partner {0} ({1})' -f $partnerNames[$ptid], $ptid } else { 'Partner ' + $ptid }
        $rows.Add([pscustomobject]@{ Scope=$scope; Setting='Service provider (e.g. CSP / GDAP partner)'; Value=(_Setting -Container $p -Path @('IsServiceProvider') -NullText '(not returned)') }) | Out-Null
        foreach ($s in $settingMap) {
            $rows.Add([pscustomobject]@{ Scope=$scope; Setting=$s.Label; Value=(_Setting -Container $p -Path $s.Path -NullText '(inherits default)') }) | Out-Null
        }
    }
    $notes = @(
        'Default = the settings that apply to every outside organization that has no partner entry of its own.',
        '(inherits default) = the partner entry does not override that setting.'
    )
    if ($defError) { $notes += ('The default cross-tenant access policy could not be read: {0}' -f $defError) }
    if (-not $partnersKnown) { $notes += ('Partner-specific configurations could not be read: {0}' -f $partnersError) }
    if ($nameLookupFailed) { $notes += 'Partner organization names could not be resolved (CrossTenantInformation.ReadBasic.All); tenant ids are shown instead.' }
    if (@($partners).Count -gt 50) { $notes += 'Organization names were resolved for the first 50 partners only.' }
    $src = Write-Evidence -BaseName 'cross_tenant_access' -Rows $rows.ToArray() -Title 'Cross-Tenant Access & B2B Trust' -Notes $notes

    # A failed/empty DEFAULT-policy read means the trust posture was NOT evaluated -
    # never fall through to 'reviewed, nothing flagged', even when partner configs
    # were readable.
    if (-not $def) {
        $why = if ($defError) { "Reading it failed: $defError" } else { 'Microsoft Graph returned no data for it.' }
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Cross-tenant access settings could not be read, so outside trust was not checked' `
            -Evidence ("The default cross-tenant access policy is unknown. {0} {1} External-trust posture was not evaluated - this is not a clean result." -f $why, $partnerText) `
            -WhyItMatters 'These settings decide which outside organizations can reach your tenant and whose multi-factor authentication (MFA) and device checks you accept. Without them the audit cannot say whether outside access is locked down.' `
            -RecommendedAction 'Grant Policy.Read.All (and Global Reader or Security Reader for a delegated run), then re-run the trusts check.' `
            -SourceFile $src -RuleId 'trusts-policy-not-assessed' -ObjectType 'tenant' -CoverageGap -DocumentationUrl $crossTenantDoc
        return
    }

    # A trust setting the default policy did not return is UNKNOWN, not "off". Only when the
    # policy reports isServiceDefault = true is an absent value known to be the Microsoft
    # default (MFA/device trust off, automatic redemption off, direct connect blocked).
    $isServiceDefault = ((Get-EAField $def 'IsServiceDefault') -eq $true)
    $trustMfa     = _RawSetting -Container $def -Path @('InboundTrust','IsMfaAccepted')
    $trustCompRaw = _RawSetting -Container $def -Path @('InboundTrust','IsCompliantDeviceAccepted')
    $trustHybRaw  = _RawSetting -Container $def -Path @('InboundTrust','IsHybridAzureADJoinedDeviceAccepted')
    $autoInbound  = _RawSetting -Container $def -Path @('AutomaticUserConsentSettings','InboundAllowed')
    $dcUsersRaw   = _RawSetting -Container $def -Path @('B2bDirectConnectInbound','UsersAndGroups','AccessType')
    $unknownSettings = New-Object System.Collections.Generic.List[string]
    if (-not $isServiceDefault) {
        if ($null -eq $trustMfa)     { $unknownSettings.Add('MFA trust (InboundTrust.IsMfaAccepted)') | Out-Null }
        if ($null -eq $trustCompRaw) { $unknownSettings.Add('compliant-device trust (InboundTrust.IsCompliantDeviceAccepted)') | Out-Null }
        if ($null -eq $trustHybRaw)  { $unknownSettings.Add('hybrid-joined device trust (InboundTrust.IsHybridAzureADJoinedDeviceAccepted)') | Out-Null }
        if ($null -eq $autoInbound)  { $unknownSettings.Add('automatic redemption (AutomaticUserConsentSettings.InboundAllowed)') | Out-Null }
        if (-not [string]$dcUsersRaw) { $unknownSettings.Add('B2B direct connect inbound (B2bDirectConnectInbound.UsersAndGroups.AccessType)') | Out-Null }
    }
    $shown = { param($v) if ($null -eq $v) { 'not returned' } else { [string]$v } }

    $flagged = 0
    # Partner configs override the default only for the NAMED tenants - the default
    # policy still applies to every other tenant, so partner entries must not suppress
    # these findings.
    if ($trustMfa) {
        $flagged++
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'MFA completed in any outside organization is trusted by default' `
            -Evidence ("Default cross-tenant access policy (applies to every outside organization without its own entry): InboundTrust.IsMfaAccepted = true. {0}" -f $partnerText) `
            -WhyItMatters "Guests from any organization can satisfy your multi-factor authentication (MFA) rules with MFA done in their home tenant, whose MFA standards you cannot see or control. A weakly protected outside tenant then becomes a way around your Conditional Access (CA) policies." `
            -RecommendedAction ("Turn off MFA trust in the default settings and enable it only for named partner organizations you have vetted ({0} > Default settings > Inbound access > Trust settings)." -f $portalPath) `
            -SourceFile $src -RuleId 'trusts-default-mfa-trust' -ObjectType 'tenant' -DocumentationUrl $crossTenantDoc
    }
    $trustCompliant = [bool]$trustCompRaw
    $trustHybrid = [bool]$trustHybRaw
    if ($trustCompliant -or $trustHybrid) {
        $flagged++
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Device checks done by any outside organization are trusted by default' `
            -Evidence ("Default cross-tenant access policy: InboundTrust.IsCompliantDeviceAccepted = {0}; InboundTrust.IsHybridAzureADJoinedDeviceAccepted = {1}. {2}" -f (& $shown $trustCompRaw), (& $shown $trustHybRaw), $partnerText) `
            -WhyItMatters "Conditional Access (CA) rules that require a compliant or company-joined device are satisfied for a guest whenever any outside organization says the guest's device is fine, although you cannot see how that organization manages its devices." `
            -RecommendedAction ("Turn off compliant-device and hybrid-joined-device trust in the default settings and enable them only for named partner organizations you have vetted ({0} > Default settings > Inbound access > Trust settings)." -f $portalPath) `
            -SourceFile $src -RuleId 'trusts-default-device-trust' -ObjectType 'tenant' -DocumentationUrl $crossTenantDoc
    }
    $dcUsers = [string]$dcUsersRaw
    if ($dcUsers -eq 'allowed') {
        $flagged++
        $dcApps = [string](_Setting -Container $def -Path @('B2bDirectConnectInbound','Applications','AccessType') -NullText '(not returned)')
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Users from any outside organization can use B2B direct connect (Teams shared channels)' `
            -Evidence ("Default cross-tenant access policy: B2bDirectConnectInbound.UsersAndGroups.AccessType = allowed; Applications.AccessType = {0}. The Microsoft default is blocked. {1}" -f $dcApps, $partnerText) `
            -WhyItMatters 'Business-to-business (B2B) direct connect lets outside users reach shared resources (today: Teams shared channels) without a guest account in your directory, so they do not appear in guest lists or access reviews. Allowing it for every organization instead of named partners widens who can reach that data.' `
            -RecommendedAction ("Set B2B direct connect inbound back to blocked in the default settings and allow it only for named partner organizations ({0} > Default settings > Inbound access)." -f $portalPath) `
            -SourceFile $src -RuleId 'trusts-default-direct-connect-inbound' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/external-id/b2b-direct-connect-overview'
    }
    if ($autoInbound) {
        $flagged++
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Invited users from any outside organization can skip the consent prompt' `
            -Evidence ("Default cross-tenant access policy: AutomaticUserConsentSettings.InboundAllowed = true (automatic redemption). The Microsoft default is false. {0}" -f $partnerText) `
            -WhyItMatters 'Normally an invited outside user must accept a consent prompt before first access. With automatic redemption allowed for all organizations, users from any outside organization that also turns it on for its side get access without that prompt, so nobody confirms the access when it starts.' `
            -RecommendedAction ("Turn off automatic redemption in the default settings and enable it only for named partner organizations that need it ({0})." -f $portalPath) `
            -SourceFile $src -RuleId 'trusts-default-auto-redemption' -ObjectType 'tenant' -DocumentationUrl $crossTenantDoc
    }
    if ($unknownSettings.Count -gt 0) {
        # Settings the default policy did not return were not assessed: report them as a
        # coverage gap and never let the baseline below describe them as "off".
        $returnedText = if ($flagged -eq 0) { 'None of the settings that were returned trusts outside organizations broadly.' }
                        else { 'The settings that were returned are covered by the other trusts findings.' }
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title ('{0} cross-tenant trust setting(s) were not returned, so they could not be checked' -f $unknownSettings.Count) `
            -Evidence ("The default cross-tenant access policy was read (isServiceDefault = {0}), but Microsoft Graph returned no value for: {1}. These settings are unknown, not off - this is not a clean result. {2} {3}" -f `
                (& $shown (Get-EAField $def 'IsServiceDefault')), ($unknownSettings -join '; '), $returnedText, $partnerText) `
            -WhyItMatters 'These settings decide whether multi-factor authentication (MFA) and device checks done by any outside organization count as your own, and whether outside users can skip the consent prompt. The audit cannot confirm that they are off.' `
            -RecommendedAction ("Check these settings by hand ({0} > Default settings > Inbound access), then re-run the trusts check; update the Microsoft Graph PowerShell modules if values keep missing." -f $portalPath) `
            -SourceFile $src -RuleId 'trusts-default-settings-unknown' -ObjectType 'tenant' -CoverageGap -DocumentationUrl $crossTenantDoc
    } elseif ($flagged -eq 0) {
        # No unknowns here: an absent value only occurs with isServiceDefault = true, where it
        # is the Microsoft default.
        $defaultText = if ($isServiceDefault) { ' (Microsoft default settings, never changed)' } else { '' }
        $dcText = if ($dcUsers) { $dcUsers } else { 'blocked (Microsoft default)' }
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'No broad trust of outside organizations found in cross-tenant access settings' `
            -Evidence ("Default policy{0}: MFA trust off, compliant/hybrid-joined device trust off, B2B direct connect inbound {1}, automatic redemption off. {2}" -f $defaultText, $dcText, $partnerText) `
            -WhyItMatters 'Keeping trust limited to named partner organizations stops outside tenants from satisfying your own security rules.' `
            -RecommendedAction 'Keep trust settings and direct connect limited to named partner organizations and review the partner list periodically.' `
            -SourceFile $src -RuleId 'trusts-baseline' -ObjectType 'tenant' -DocumentationUrl $crossTenantDoc
    }
}

# ===========================================================================
# CHECK 16 - recentchanges
# ===========================================================================
# PIM just-in-time activation / deactivation / activation-expiry audit events, e.g.
# "Add member to role completed (PIM activation)", "Remove member from role completed
# (PIM deactivate)", "Remove member from role (PIM activation expired)". Activating an
# ELIGIBLE role is the intended PIM posture, not a new grant, so role-change reviews list
# these separately instead of counting them as assignment changes. Shared helper: the
# changemonitoring check can use the same classification.
function Test-EARoleActivationEvent {
    param([string]$ActivityDisplayName)
    return ([string]$ActivityDisplayName -match '(?i)PIM (de)?activat')
}

function Invoke-Check-RecentChanges {
    $checkId = 'recentchanges'; $category = 'Change Monitoring'
    $auditDoc = 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention'
    $auditPortal = 'Entra admin center > Monitoring & health > Audit logs (category RoleManagement)'
    $since = (Get-Date).ToUniversalTime().AddDays(-$RecentChangeDays)
    # InvariantCulture: see Invoke-Check-LegacyAuth - culture time separators break OData.
    $sinceStr = $since.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $sinceDay = $since.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $newUsers = @(Get-MgUser -Filter "createdDateTime ge $sinceStr" -All -PageSize 999 -ConsistencyLevel eventual -CountVariable c -Property Id,UserPrincipalName,CreatedDateTime,UserType,AccountEnabled -ErrorAction Stop)
    # The check is gated on User.Read.All + AuditLog.Read.All only, so a missing
    # Group.Read.All or throttling can fail this read: track it - "0 new groups" must mean zero.
    $newGroups = @(); $groupsKnown = $true; $groupsError = $null
    try { $newGroups = @(Get-MgGroup -Filter "createdDateTime ge $sinceStr" -All -PageSize 999 -ConsistencyLevel eventual -CountVariable c2 -Property Id,DisplayName,CreatedDateTime,GroupTypes,SecurityEnabled,IsAssignableToRole -ErrorAction Stop) }
    catch { $groupsKnown = $false; $groupsError = $_.Exception.Message }

    $rows = @()
    $rows += $newUsers | Select-Object @{n='Type';e={'User'}}, @{n='Name';e={$_.UserPrincipalName}}, CreatedDateTime, @{n='Enabled';e={$_.AccountEnabled}},
        @{n='Detail';e={ if ($_.UserType) { [string]$_.UserType } else { '' } }}
    $rows += $newGroups | Select-Object @{n='Type';e={'Group'}}, @{n='Name';e={$_.DisplayName}}, CreatedDateTime, @{n='Enabled';e={''}},
        @{n='Detail';e={
            $kind = if (@($_.GroupTypes) -contains 'Unified') { 'Microsoft 365 group' } elseif ($_.SecurityEnabled) { 'Security group' } else { 'Distribution group' }
            if ($_.IsAssignableToRole) { $kind + ' (role-assignable)' } else { $kind }
        }}
    $recentNotes = @(("Created on or after {0} (last {1} days)." -f $sinceStr, $RecentChangeDays))
    if (-not $groupsKnown) { $recentNotes += ('New groups could not be read - group rows are missing, not zero: {0}' -f $groupsError) }
    $src = Write-Evidence -BaseName 'recent_changes' -Rows $rows -Title ("Recently Created Users / Groups (last {0} days)" -f $RecentChangeDays) -Notes $recentNotes

    # Native directory-audit retention: 7 days on Entra ID Free, 30 days with P1/P2.
    # A longer window (default 30) cannot be fully covered without P1, and when the licence
    # read failed the covered window is unknown.
    $retentionDays = if (-not $script:LicenseKnown) { $null } elseif ($script:HasP1) { 30 } else { 7 }
    $retentionShort = ($RecentChangeDays -gt 7) -and ($null -eq $retentionDays -or $RecentChangeDays -gt $retentionDays)
    $retentionText = if ($null -eq $retentionDays) { 'unknown (licence detection failed; 7 days on Entra ID Free, 30 days with P1/P2)' } else { '{0} days' -f $retentionDays }

    # Role-management changes from the directory audit log. -ErrorAction Stop: a failed or
    # throttled read is a coverage gap, never "no role changes".
    $roleEvents = @(); $auditKnown = $true; $auditError = $null
    try {
        $roleEvents = @(Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $sinceStr and category eq 'RoleManagement'" -All -PageSize 999 -ErrorAction Stop)
    } catch { $auditKnown = $false; $auditError = $_.Exception.Message }

    # Directory writes that the PIM service itself performs (initiator = the Microsoft
    # first-party "MS-PIM" app) mirror an activation, expiry or PIM assignment whose own
    # PIM audit event - with the real human initiator - is in the same result set. Such a
    # write is listed but not counted ONLY when (a) the initiator is verified as MS-PIM by
    # appId / service-principal id (never by display name, which any app registration
    # could copy) and (b) a PIM-service event for the same principal exists within 15
    # minutes. Anything that cannot be matched both ways is counted as a change (fail-safe).
    $msPimAppId = '01fc33a7-78ba-4d2f-a4b7-768e336e890e'
    $pimServiceTimes = @{}
    foreach ($e in $roleEvents) {
        if ([string]$e.LoggedByService -notmatch '(?i)^(PIM|Privileged Identity Management)$' -or -not $e.ActivityDateTime) { continue }
        foreach ($t in @($e.TargetResources)) {
            if ([string]$t.Type -eq 'Role' -or -not $t.Id) { continue }
            $tk = [string]$t.Id
            if (-not $pimServiceTimes.ContainsKey($tk)) { $pimServiceTimes[$tk] = New-Object System.Collections.Generic.List[datetime] }
            $pimServiceTimes[$tk].Add([datetime]$e.ActivityDateTime) | Out-Null
        }
    }
    function _HasPimServiceTwin($e) {
        if (-not $e.ActivityDateTime) { return $false }
        $at = [datetime]$e.ActivityDateTime
        foreach ($t in @($e.TargetResources)) {
            if ([string]$t.Type -eq 'Role' -or -not $t.Id -or -not $pimServiceTimes.ContainsKey([string]$t.Id)) { continue }
            foreach ($pt in $pimServiceTimes[[string]$t.Id]) { if ([math]::Abs(($pt - $at).TotalMinutes) -le 15) { return $true } }
        }
        return $false
    }
    $msPimSpIds = @{}
    $appInitiated = @($roleEvents | Where-Object { $_.InitiatedBy.App -and ($_.InitiatedBy.App.ServicePrincipalId -or $_.InitiatedBy.App.AppId) })
    if ($appInitiated.Count -gt 0) {
        if ($script:SpsCache) {
            foreach ($sp in @($script:SpsCache | Where-Object { [string]$_.AppId -eq $msPimAppId })) { if ($sp.Id) { $msPimSpIds[[string]$sp.Id] = $true } }
        }
        if ($msPimSpIds.Count -eq 0) {
            try {
                foreach ($sp in @(Get-MgServicePrincipal -Filter "appId eq '$msPimAppId'" -Property 'id,appId' -ErrorAction Stop)) { if ($sp.Id) { $msPimSpIds[[string]$sp.Id] = $true } }
            } catch { Write-Warn2 "  Could not resolve the PIM service principal (PIM service writes will be counted as role changes): $($_.Exception.Message)" }
        }
    }
    function _RoleEventKind($e) {
        if (Test-EARoleActivationEvent ([string]$e.ActivityDisplayName)) { return 'PIM activation' }
        $app = $e.InitiatedBy.App
        if ($app -and -not ($e.InitiatedBy.User -and $e.InitiatedBy.User.Id)) {
            $isMsPim = ([string]$app.AppId -eq $msPimAppId -or ($app.ServicePrincipalId -and $msPimSpIds.ContainsKey([string]$app.ServicePrincipalId)))
            if ($isMsPim -and (_HasPimServiceTwin $e)) { return 'PIM service write' }
        }
        return 'Role change'
    }
    function _RoleName($e) {
        $role = @($e.TargetResources | Where-Object { [string]$_.Type -eq 'Role' -and $_.DisplayName } | Select-Object -First 1)
        if ($role.Count -gt 0) { return [string]$role[0].DisplayName }
        foreach ($t in @($e.TargetResources)) {
            foreach ($mp in @($t.ModifiedProperties)) {
                if ([string]$mp.DisplayName -eq 'Role.DisplayName' -and $mp.NewValue) { return ([string]$mp.NewValue).Trim().Trim('"') }
            }
        }
        return ''
    }
    function _Initiator($e) {
        $u = $e.InitiatedBy.User
        if ($u -and $u.UserPrincipalName) { return [string]$u.UserPrincipalName }
        if ($u -and $u.DisplayName) { return [string]$u.DisplayName }
        $app = $e.InitiatedBy.App
        if ($app -and $app.DisplayName) { return ('{0} (app)' -f $app.DisplayName) }
        if ($app -and $app.ServicePrincipalId) { return ('app {0}' -f $app.ServicePrincipalId) }
        return 'Unknown'
    }
    function _Targets($e) {
        (@($e.TargetResources | Where-Object { [string]$_.Type -ne 'Role' } | ForEach-Object {
            if ($_.UserPrincipalName) { [string]$_.UserPrincipalName } elseif ($_.DisplayName) { [string]$_.DisplayName } else { [string]$_.Id }
        } | Where-Object { $_ }) -join ', ')
    }

    $rcrows = @($roleEvents | Sort-Object ActivityDateTime -Descending | ForEach-Object {
        [pscustomobject]@{
            ActivityDateTime = $_.ActivityDateTime
            Kind             = (_RoleEventKind $_)
            Activity         = [string]$_.ActivityDisplayName
            Role             = (_RoleName $_)
            Target           = (_Targets $_)
            Initiator        = (_Initiator $_)
            Result           = [string]$_.Result
            Service          = [string]$_.LoggedByService
        }
    })
    $changes = @($rcrows | Where-Object { $_.Kind -eq 'Role change' })
    $activations = @($rcrows | Where-Object { $_.Kind -eq 'PIM activation' })
    $pimWrites = @($rcrows | Where-Object { $_.Kind -eq 'PIM service write' })

    $rcNotes = @(("Directory audit, category RoleManagement, since {0} (requested window {1} days; native retention {2})." -f $sinceStr, $RecentChangeDays, $retentionText),
        'Kind: Role change = grant, removal, eligibility or role-setting change (counted); PIM activation = just-in-time activation/deactivation of an eligible role (listed only); PIM service write = directory write made by the PIM service for an activation or PIM assignment that already has its own PIM event (listed only).')
    if (-not $auditKnown) { $rcNotes += ('The directory audit log could not be read - role changes are UNKNOWN, not zero: {0}' -f $auditError) }
    if ($auditKnown -and $appInitiated.Count -gt 0 -and $msPimSpIds.Count -eq 0) { $rcNotes += 'The PIM service principal could not be verified, so PIM service writes (if any) are counted as role changes.' }
    $rcsrc = Write-Evidence -BaseName 'recent_role_changes' -Rows $rcrows -Title ("Recent Role-Management Changes (last {0} days)" -f $RecentChangeDays) -Notes $rcNotes

    if (-not $auditKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Recent admin role changes could not be checked (audit log read failed)' `
            -Evidence ("Reading the directory audit log (category RoleManagement, since {0}) failed: {1}. Role grants in this period are unknown, not zero." -f $sinceDay, $auditError) `
            -WhyItMatters 'A new administrator role grant is often the first sign of a rogue or compromised admin account. Without the audit log this check cannot confirm that no unexpected grants happened.' `
            -RecommendedAction ("Grant AuditLog.Read.All (Reports Reader or Security Reader for a delegated run), wait for any throttling to clear and re-run the recentchanges check. Until then, review {0} by hand." -f $auditPortal) `
            -SourceFile $rcsrc -RuleId 'recentchanges-role-audit-unreadable' -ObjectType 'tenant' -CoverageGap `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs'
    } else {
        if ($changes.Count -gt 0) {
            $failed = @($changes | Where-Object { $_.Result -and $_.Result -ne 'success' }).Count
            $initiators = @($changes | Group-Object Initiator | Sort-Object Count -Descending)
            $topInitiators = (@($initiators | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count }) -join ', ')
            $roles = (@($changes | Where-Object { $_.Role } | Group-Object Role | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count }) -join ', ')
            $evidence = ("Since {0}: {1} role grant, removal, eligibility or role-setting event(s) ({2} not successful) by {3} initiator(s): {4}. Roles most affected: {5}. Not counted: {6} PIM activation/deactivation event(s) and {7} directory write(s) the PIM service made to carry out PIM activations or assignments that are already listed (each PIM assignment is counted once, through its own PIM event). Run the changemonitoring check for a classified timeline of all security-sensitive changes." -f `
                $sinceDay, $changes.Count, $failed, $initiators.Count, $topInitiators, $(if ($roles) { $roles } else { 'not recorded' }), $activations.Count, $pimWrites.Count)
            if ($retentionShort) { $evidence += (' Audit log retention is {0}, so older changes in the {1}-day window are not visible.' -f $retentionText, $RecentChangeDays) }
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title ("{0} admin role grant(s), removal(s) or setting change(s) in the last {1} days" -f $changes.Count, $RecentChangeDays) `
                -Evidence $evidence `
                -WhyItMatters 'A new administrator role grant is often the first sign of a rogue administrator or a compromised provisioning account. Each grant, removal or change to Privileged Identity Management (PIM) role settings should match an approved change.' `
                -RecommendedAction ("Check each listed change against an approved change or access request and investigate any change made by an unexpected person or app. The full list is in the evidence file and in {0}." -f $auditPortal) `
                -SourceFile $rcsrc -ResultRows @($changes | Select-Object -First 50) `
                -RuleId 'recentchanges-role-changes' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs'
        }
        if ($activations.Count -gt 0) {
            $activators = @($activations | Group-Object Initiator | Sort-Object Count -Descending)
            Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
                -Title ("{0} PIM role activation or deactivation event(s) in the last {1} days" -f $activations.Count, $RecentChangeDays) `
                -Evidence ("{0} event(s) by {1} initiator(s); most active: {2}. Activating an eligible role is the intended way to use Privileged Identity Management (PIM); these are listed for visibility and do not count as role changes." -f `
                    $activations.Count, $activators.Count, ((@($activators | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })) -join ', ')) `
                -WhyItMatters 'Just-in-time activation of eligible roles in Privileged Identity Management (PIM) is the desired way to work with admin rights. Unfamiliar people activating roles, or unusual volumes or times, are still worth a look.' `
                -RecommendedAction 'Spot-check activations by unfamiliar users or at unusual times (Entra admin center > Identity Governance > Privileged Identity Management > Microsoft Entra roles > Resource audit).' `
                -SourceFile $rcsrc -ResultRows @($activations | Select-Object -First 50) `
                -RuleId 'recentchanges-pim-activations' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-use-audit-log'
        }
        if ($retentionShort) {
            $coveredTitle = if ($null -eq $retentionDays) { 'Admin role changes older than 7 days may be missing (licence unknown)' }
                            else { 'Admin role changes could only be checked for the last {0} days, not {1}' -f $retentionDays, $RecentChangeDays }
            Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
                -Title $coveredTitle `
                -Evidence ("Requested window: {0} days (-RecentChangeDays). Native directory audit retention: {1}. Detected licence: P1={2}, licence detection {3}. Events older than the retention period are no longer available from Microsoft Graph; external archives (Log Analytics, SIEM) were not queried." -f `
                    $RecentChangeDays, $retentionText, [bool]$script:HasP1, $(if ($script:LicenseKnown) { 'succeeded' } else { 'failed' })) `
                -WhyItMatters 'Role changes made before the retention period cannot be seen, so an unexpected grant from earlier in the window can be missed.' `
                -RecommendedAction ('Send the audit logs to Log Analytics or your security monitoring tool (SIEM) for longer history, or re-run with -RecentChangeDays {0} to match the retention.' -f $(if ($null -eq $retentionDays) { 7 } else { $retentionDays })) `
                -SourceFile $rcsrc -RuleId 'recentchanges-audit-retention-short' -ObjectType 'tenant' -CoverageGap -DocumentationUrl $auditDoc
        }
    }

    $guestCount = @($newUsers | Where-Object { $_.UserType -eq 'Guest' }).Count
    $userText = ('New users: {0} ({1} guest(s), {2} disabled).' -f $newUsers.Count, $guestCount, @($newUsers | Where-Object { $_.AccountEnabled -eq $false }).Count)
    if ($groupsKnown) {
        $roleAssignable = @($newGroups | Where-Object { $_.IsAssignableToRole }).Count
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title ("{0} user(s) and {1} group(s) were created in the last {2} days" -f $newUsers.Count, $newGroups.Count, $RecentChangeDays) `
            -Evidence ("{0} New groups: {1} ({2} role-assignable). Created on or after {3}." -f $userText, $newGroups.Count, $roleAssignable, $sinceDay) `
            -WhyItMatters 'New accounts and groups should match approved onboarding; unexpected ones can point to rogue provisioning. A new role-assignable group can be used to hand out admin roles.' `
            -RecommendedAction 'Spot-check the new accounts and groups against HR / onboarding records, and make sure every new role-assignable group has a known owner and purpose.' `
            -SourceFile $src -ResultRows $rows -RuleId 'recentchanges-new-users-groups' -ObjectType 'tenant'
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title ("{0} user(s) created in the last {1} days; new groups could not be read" -f $newUsers.Count, $RecentChangeDays) `
            -Evidence ("{0} New groups: unknown - the group read failed: {1}. Created on or after {2}." -f $userText, $groupsError, $sinceDay) `
            -WhyItMatters 'New accounts and groups should match approved onboarding; unexpected ones can point to rogue provisioning. Because the group list could not be read, new groups (including role-assignable ones) were not reviewed.' `
            -RecommendedAction 'Grant Group.Read.All (or Directory.Read.All) and re-run the recentchanges check; meanwhile spot-check the new accounts against HR / onboarding records.' `
            -SourceFile $src -ResultRows $rows -RuleId 'recentchanges-new-groups-unreadable' -ObjectType 'tenant' -CoverageGap
    }
}

# ===========================================================================
# CHECK 17 - tenanthealth (directory sync / PHS)
# ===========================================================================
function Invoke-Check-TenantHealth {
    $checkId = 'tenanthealth'; $category = 'Platform Health'
    $featuresDoc = 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-syncservice-features'

    # Organization object: reuse the tenant-info / start-up read when it succeeded. A failed
    # read is tracked - an unreadable organization must never be reported as "cloud-only".
    $orgError = $null
    if (-not $script:Tenant) {
        try { $script:Tenant = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1 } catch { $orgError = $_.Exception.Message }
    }
    $org = $script:Tenant
    $sync = $null; $syncError = $null
    try { $sync = Get-MgDirectoryOnPremiseSynchronization -ErrorAction Stop | Select-Object -First 1 } catch { $syncError = $_.Exception.Message }

    # organization.onPremisesSyncEnabled: true = syncing; false = WAS synced, sync since
    # switched off; null = never synced (cloud-only).
    $syncEnabled = if ($org) { Get-EAField $org 'OnPremisesSyncEnabled' } else { $null }
    $lastSync = if ($org) { Get-EAField $org 'OnPremisesLastSyncDateTime' } else { $null }
    $lastSyncUtc = $null
    if ($lastSync) {
        try {
            $lastSyncUtc = if ($lastSync -is [datetimeoffset]) { $lastSync.UtcDateTime }
                           else { $d = [datetime]$lastSync; if ($d.Kind -eq [System.DateTimeKind]::Local) { $d.ToUniversalTime() } else { $d } }
        } catch { $lastSyncUtc = $null }
    }
    $lastSyncText = if ($lastSyncUtc) { $lastSyncUtc.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { 'not returned' }
    # A $null feature value means "not returned" - it is reported as unknown, never as off.
    $features = if ($sync) { Get-EAField $sync 'Features' } else { $null }
    $phs       = if ($features) { Get-EAField $features 'PasswordSyncEnabled' } else { $null }
    $softBlock = if ($features) { Get-EAField $features 'BlockSoftMatchEnabled' } else { $null }
    $hardBlock = if ($features) { Get-EAField $features 'BlockCloudObjectTakeoverThroughHardMatchEnabled' } else { $null }
    $cloudPwd  = if ($features) { Get-EAField $features 'CloudPasswordPolicyForPasswordSyncedUsersEnabled' } else { $null }

    $rows = New-Object System.Collections.Generic.List[object]
    if ($org) {
        $rows.Add([pscustomobject]@{ Property='OnPremisesSyncEnabled'; Value=$(if ($null -eq $syncEnabled) { '(not set)' } else { $syncEnabled })
            Meaning='true = accounts sync from on-premises AD; false = sync was used but is now switched off; not set = never synced (cloud-only)' }) | Out-Null
        $rows.Add([pscustomobject]@{ Property='OnPremisesLastSyncDateTime'; Value=$lastSyncText; Meaning='Last time Entra Connect / Cloud Sync pushed changes (normally every 30 minutes)' }) | Out-Null
    }
    if ($sync) {
        foreach ($f in @(
            @{ Name='PasswordSyncEnabled'; Value=$phs; Meaning='Password hash sync (needed for leaked-credential detection and as a sign-in fallback)' }
            @{ Name='BlockSoftMatchEnabled'; Value=$softBlock; Meaning='true = on-premises accounts cannot take over cloud accounts by matching email address / UPN' }
            @{ Name='BlockCloudObjectTakeoverThroughHardMatchEnabled'; Value=$hardBlock; Meaning='true = on-premises accounts cannot take over cloud accounts by matching the immutable id' }
            @{ Name='CloudPasswordPolicyForPasswordSyncedUsersEnabled'; Value=$cloudPwd; Meaning='true = the cloud password-expiry policy also applies to password-synced users' }
        )) {
            $rows.Add([pscustomobject]@{ Property=$f.Name; Value=$(if ($null -eq $f.Value) { '(not returned)' } else { $f.Value }); Meaning=$f.Meaning }) | Out-Null
        }
    }
    $notes = @()
    if (-not $org) { $notes += ('The organization object could not be read: {0}' -f $(if ($orgError) { $orgError } else { 'no data returned' })) }
    if ($syncError) { $notes += ('The on-premises synchronization settings could not be read: {0}' -f $syncError) }
    elseif (-not $sync) { $notes += 'The on-premises synchronization settings returned no data.' }
    $src = Write-Evidence -BaseName 'tenant_health' -Rows $rows.ToArray() -Title 'Directory-Sync / PHS Platform Health' -Notes $notes

    if (-not $org) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Directory sync health could not be checked (organization details unreadable)' `
            -Evidence ("Reading the organization object failed: {0}. Whether the tenant syncs accounts from on-premises Active Directory, and how recently, is unknown - this is not a clean result." -f $(if ($orgError) { $orgError } else { 'no data returned' })) `
            -WhyItMatters 'If accounts sync from on-premises Active Directory (AD), a broken or weakly configured sync can leave departed staff active in the cloud or let on-premises accounts take over cloud accounts. None of this could be checked.' `
            -RecommendedAction 'Grant Organization.Read.All (Global Reader for a delegated run) and re-run the tenanthealth check.' `
            -SourceFile $src -RuleId 'tenanthealth-org-unreadable' -ObjectType 'tenant' -CoverageGap
        return
    }
    if ($null -eq $syncEnabled) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'No directory sync from on-premises AD (cloud-only tenant)' `
            -Evidence 'OnPremisesSyncEnabled is not set on the organization: the tenant has never synced from an on-premises directory.' `
            -WhyItMatters 'A cloud-only tenant has no on-premises Active Directory (AD) sync to monitor, so the sync health checks do not apply. This is expected, not an error.' `
            -RecommendedAction 'No action needed.' -SourceFile $src -RuleId 'tenanthealth-cloud-only' -ObjectType 'tenant'
        return
    }
    if ($syncEnabled -eq $false) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Directory sync from on-premises AD has been switched off' `
            -Evidence ("OnPremisesSyncEnabled = false: the tenant used to sync from an on-premises directory, but sync is now off. Last sync: {0}." -f $lastSyncText) `
            -WhyItMatters 'Accounts that came from on-premises Active Directory (AD) are now managed only in the cloud. If sync was switched off by mistake, staff disabled on-premises stay active in Microsoft 365.' `
            -RecommendedAction 'Confirm that switching off sync was a planned change. If it was not, find out who changed it (Entra admin center > Monitoring & health > Audit logs) and restore Entra Connect sync.' `
            -SourceFile $src -RuleId 'tenanthealth-sync-switched-off' -ObjectType 'tenant'
        return
    }

    # Hybrid tenant. The sync age comes from the organization object alone, so it is judged
    # even when the synchronization settings below cannot be read.
    $emitted = 0
    if ($lastSyncUtc) {
        $hoursAgo = ((Get-Date).ToUniversalTime() - $lastSyncUtc).TotalHours
        if ($hoursAgo -gt 3) {
            $emitted++
            $agoText = if ($hoursAgo -ge 48) { '{0} days' -f [int][math]::Floor($hoursAgo / 24) } else { '{0} hours' -f [int][math]::Floor($hoursAgo) }
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title ("Directory sync from on-premises AD has not run for {0}" -f $agoText) `
                -Evidence ("OnPremisesLastSyncDateTime = {0} ({1} ago). Entra Connect normally syncs every 30 minutes; this check flags anything older than 3 hours." -f $lastSyncText, $agoText) `
                -WhyItMatters 'While sync is stuck, accounts disabled or removed in on-premises Active Directory (AD) stay active in the cloud, so a departed employee or a locked-out attacker can keep signing in to Microsoft 365.' `
                -RecommendedAction 'Check the Entra Connect server and its sync service, fix the error it reports and confirm that sync runs every 30 minutes again (Entra admin center > Identity > Hybrid management > Microsoft Entra Connect).' `
                -SourceFile $src -RuleId 'tenanthealth-sync-stale' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler'
        }
    } else {
        $emitted++
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Time of the last directory sync is unknown' `
            -Evidence 'OnPremisesSyncEnabled = true, but OnPremisesLastSyncDateTime was not returned. Whether sync is running could not be assessed - this is not a clean result.' `
            -WhyItMatters 'Without the last sync time the audit cannot tell whether changes made in on-premises Active Directory (AD), such as disabled leavers, still reach the cloud.' `
            -RecommendedAction 'Check the last sync time in Entra admin center > Identity > Hybrid management > Microsoft Entra Connect.' `
            -SourceFile $src -RuleId 'tenanthealth-last-sync-unknown' -ObjectType 'tenant' -CoverageGap
    }

    if (-not $sync) {
        # Hybrid tenant, but the on-prem sync configuration could not be read - do NOT fall
        # through to the "healthy" baseline, which would be a false sense of coverage.
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Directory sync settings could not be read, so sync security was not checked' `
            -Evidence ("Tenant is hybrid (OnPremisesSyncEnabled = true), but Get-MgDirectoryOnPremiseSynchronization {0}. Password hash sync, soft-match blocking and the cloud password policy for synced users are unknown - this is not a clean result." -f $(if ($syncError) { 'failed: ' + $syncError } else { 'returned no data' })) `
            -WhyItMatters 'These settings decide whether leaked passwords can be detected and whether on-premises accounts can take over cloud accounts. Without them a "healthy" result would be misleading.' `
            -RecommendedAction 'Grant OnPremDirectorySynchronization.Read.All and re-run the tenanthealth check.' `
            -SourceFile $src -RuleId 'tenanthealth-sync-settings-unreadable' -ObjectType 'tenant' -CoverageGap
        return
    }

    $unknown = @()
    if ($null -eq $phs) { $unknown += 'PasswordSyncEnabled' }
    elseif (-not [bool]$phs) {
        $emitted++
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Password hash sync is off, so leaked passwords are not detected' `
            -Evidence 'PasswordSyncEnabled = false on a tenant that syncs from on-premises AD (OnPremisesSyncEnabled = true).' `
            -WhyItMatters 'Without password hash sync (PHS), Microsoft cannot warn you when a user password appears in a known leak (leaked-credential detection), and there is no quick backup sign-in method if federation or pass-through authentication servers fail.' `
            -RecommendedAction 'Turn on password hash sync in Entra Connect, even if users sign in through federation or pass-through authentication; it is then used for leaked-credential detection and as a fallback.' `
            -SourceFile $src -RuleId 'tenanthealth-phs-disabled' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-phs'
    }
    if ($null -eq $softBlock) { $unknown += 'BlockSoftMatchEnabled' }
    elseif (-not [bool]$softBlock) {
        $emitted++
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'On-premises accounts can take over cloud accounts (soft-match not blocked)' `
            -Evidence ('BlockSoftMatchEnabled = false. Related: BlockCloudObjectTakeoverThroughHardMatchEnabled = {0}.' -f $(if ($null -eq $hardBlock) { '(not returned)' } else { $hardBlock })) `
            -WhyItMatters 'Anyone who can create or edit accounts in on-premises Active Directory (AD) can create one with the same email address or sign-in name as a cloud-only account. The next sync links the two and hands control of the cloud account to on-premises AD.' `
            -RecommendedAction 'Once the initial account matching is complete, turn on the BlockSoftMatch sync feature (see the Entra Connect sync service features documentation).' `
            -SourceFile $src -RuleId 'tenanthealth-softmatch-not-blocked' -ObjectType 'tenant' -DocumentationUrl $featuresDoc
    }
    if ($phs -ne $false) {
        if ($null -eq $cloudPwd) { $unknown += 'CloudPasswordPolicyForPasswordSyncedUsersEnabled' }
        elseif ($phs -eq $true -and -not [bool]$cloudPwd) {
            $emitted++
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'Synced users can keep signing in with passwords that expired on-premises' `
                -Evidence 'PasswordSyncEnabled = true and CloudPasswordPolicyForPasswordSyncedUsersEnabled = false, so the cloud password of password-synced users is set to never expire (DisablePasswordExpiration).' `
                -WhyItMatters 'When a password expires in on-premises Active Directory (AD), its synced cloud copy does not, so the user can keep signing in to Microsoft 365 with the old password. Forced password changes on-premises therefore do not protect cloud sign-ins.' `
                -RecommendedAction 'Turn on the CloudPasswordPolicyForPasswordSyncedUsersEnabled sync feature after checking the effect on federation / pass-through users, and align the cloud password-expiry policy with on-premises policy.' `
                -SourceFile $src -RuleId 'tenanthealth-cloud-password-policy-off' -ObjectType 'tenant' -DocumentationUrl $featuresDoc
        }
    }
    if ($unknown.Count -gt 0) {
        $emitted++
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Some directory sync settings were not returned, so they could not be checked' `
            -Evidence ("Not returned by Microsoft Graph: {0}. These settings are unknown, not assumed on or off." -f ($unknown -join ', ')) `
            -WhyItMatters 'These settings control password hash sync, whether on-premises accounts can take over cloud accounts, and whether synced passwords expire in the cloud. Unknown values could hide a weak configuration.' `
            -RecommendedAction 'Re-run with OnPremDirectorySynchronization.Read.All and verify the sync features in the Entra Connect configuration.' `
            -SourceFile $src -RuleId 'tenanthealth-sync-settings-unknown' -ObjectType 'tenant' -CoverageGap -DocumentationUrl $featuresDoc
    }
    if ($emitted -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Directory sync is healthy (recent, with password hash sync and soft-match blocking on)' `
            -Evidence ("Last sync: {0}. PasswordSyncEnabled = true; BlockSoftMatchEnabled = true; CloudPasswordPolicyForPasswordSyncedUsersEnabled = {1}." -f $lastSyncText, $(if ($null -eq $cloudPwd) { '(not returned)' } else { $cloudPwd })) `
            -WhyItMatters 'A healthy sync keeps cloud accounts in step with on-premises Active Directory (AD), so leavers are disabled everywhere and leaked passwords can be detected.' `
            -RecommendedAction 'Keep Entra Connect health monitoring and alerting in place.' `
            -SourceFile $src -RuleId 'tenanthealth-baseline' -ObjectType 'tenant'
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
    # evidence that no eligible administrators exist. When the licence read itself failed
    # (LicenseKnown = false) HasP2 is only a default, so the failure is a gap there too.
    try {
        foreach ($a in @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)) { _Add $a 'Eligible' }
        $script:PrivEligibilityAssignmentsFailed = $false
    } catch {
        $script:PrivEligibilityAssignmentsFailed = ([bool]$script:HasP2 -or -not $script:LicenseKnown)
        if ($script:PrivEligibilityAssignmentsFailed) { Write-Warn2 "  Privileged eligibility-assignment fetch failed: $($_.Exception.Message)" }
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

# Transitive members / owners of a group, memoised for the run. The privileged-user map,
# breakglass, accesspaths and apps checks expand the SAME privileged / role-assignable
# groups; reading each group once saves hundreds of sequential Graph calls on large
# tenants. Both helpers THROW on a failed read, so every caller keeps its own "unknown,
# not clean" handling, and only successful reads are cached (like Get-EACaPolicies), so a
# transient failure in one check does not blind the later ones.
function Get-EAGroupTransitiveMember {
    param([Parameter(Mandatory)][string]$GroupId)
    if ($null -eq $script:GroupMembersCache) { $script:GroupMembersCache = @{} }
    $key = $GroupId.ToLowerInvariant()
    if ($script:GroupMembersCache.ContainsKey($key)) { return $script:GroupMembersCache[$key] }
    $members = @(Get-MgGroupTransitiveMember -GroupId $GroupId -All -PageSize 999 -ErrorAction Stop)
    $script:GroupMembersCache[$key] = $members
    return $members
}
function Get-EAGroupOwner {
    param([Parameter(Mandatory)][string]$GroupId)
    if ($null -eq $script:GroupOwnersCache) { $script:GroupOwnersCache = @{} }
    $key = $GroupId.ToLowerInvariant()
    if ($script:GroupOwnersCache.ContainsKey($key)) { return $script:GroupOwnersCache[$key] }
    $owners = @(Get-MgGroupOwner -GroupId $GroupId -All -PageSize 999 -ErrorAction Stop)
    $script:GroupOwnersCache[$key] = $owners
    return $owners
}

# Effective privileged-user population shared by MFA, stale/risk/guest hygiene and CA.
# It includes eligible assignments and expands role-assignable groups transitively. The
# map value is the list of role assignments that make that user privileged, preserving
# role/scope/state context for consumers that need role-targeted CA applicability.
function Get-EAPrivilegedUserMap {
    if ($null -ne $script:PrivilegedUserMap) { return $script:PrivilegedUserMap }
    $usersKnown = $true
    try { Get-EAUsers | Out-Null } catch { $usersKnown = $false }
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
            foreach ($m in @(Get-EAGroupTransitiveMember -GroupId ([string]$a.PrincipalId))) {
                $mtype = [string](Get-Ap $m '@odata.type')
                $upn = Get-Ap $m 'userPrincipalName'
                if ($mtype -eq '#microsoft.graph.user' -or $upn -or ($m.Id -and $script:UserById.ContainsKey([string]$m.Id))) {
                    _AddUserPrivilege ([string]$m.Id) $a
                } elseif (-not $mtype -and -not $usersKnown) {
                    # No type on the member and no user list to look it up in: it may be a
                    # privileged user, so the population is not complete.
                    $script:PrivilegedUserMapIncomplete = $true
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

    # Every reason a PIM rule could come back UNKNOWN is recorded here and repeated in the
    # evidence of the "could not be fully read" finding, so the reader sees WHY.
    $unknownCauses = @()
    $scopeNote = if ($firstScopeError) { ("The scopeType 'DirectoryRole' query failed ({0}); the 'Directory' fallback was used." -f $firstScopeError.Exception.Message) } else { $null }

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
    } catch {
        $authContextDefinitionsKnown = $false
        $unknownCauses += ("authentication contexts could not be read ({0})" -f $_.Exception.Message)
    }
    $caKnown = $true; $enabledCa = @()
    try { $enabledCa = @(Get-EACaPolicies | Where-Object { $_.State -eq 'enabled' }) } catch {
        $caKnown = $false
        $unknownCauses += ("Conditional Access policies could not be read ({0})" -f $_.Exception.Message)
    }
    # Break-glass ids are only used to accept an otherwise all-users CA policy that excludes
    # the designated emergency accounts. If they cannot be resolved such a policy evaluates
    # as 'Unknown-ScopedUserCoverage' (never as valid) - record why.
    $pimBgIds = @(); $pimBg = Normalize-StringList -Values $BreakGlassUpns
    if ($pimBg.Count -gt 0) {
        try { foreach ($u0 in @(Get-EAUsers)) { if ($u0.Id -and $u0.UserPrincipalName -and $u0.UserPrincipalName.ToLowerInvariant() -in $pimBg) { $pimBgIds += [string]$u0.Id } } }
        catch { $unknownCauses += ("break-glass accounts could not be resolved ({0}), so CA policies excluding them count as scoped" -f $_.Exception.Message) }
    }

    function _ValidateAuthContext([string]$claimValue) {
        if (-not $claimValue) { return 'Invalid-NoClaimValue' }
        if (-not $authContextDefinitionsKnown -or -not $caKnown) { return 'Unknown' }
        if (-not $authContextDefinitions.ContainsKey($claimValue) -or -not [bool]$authContextDefinitions[$claimValue]['isAvailable']) { return 'Invalid-Unavailable' }
        $matchingScopedPolicy = $false
        foreach ($p in $enabledCa) {
            $refs = @((Get-EAField $p.Conditions.Applications 'IncludeAuthenticationContextClassReferences') | Where-Object { $_ })
            if ($refs -contains $claimValue -and
                (Test-CaPolicyRequiresMfaOrStrength $p) -and
                -not (Test-CaPolicyHasNarrowingConditions $p @('ModernClients'))) {
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
    $pimNotes = @("Policy scopeType used: $scopeUsed")
    if ($scopeNote) { $pimNotes += $scopeNote }
    if ($unknownCauses.Count -gt 0) { $pimNotes += ('Unknown inputs: ' + ($unknownCauses -join '; ')) }
    $src = Write-Evidence -BaseName 'pim_policies' -Rows $rows -Title 'PIM Role-Management Policy Rules (privileged roles)' -Notes $pimNotes
    $pimDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
    $pimPath = 'Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles > Roles > (role) > Role settings'
    # Short "a, b, c (+N more)" list for Evidence; the full list is always in the evidence file.
    function _ListText([string[]]$Items, [int]$Max = 12) {
        $all = @($Items | Where-Object { $_ })
        $text = (@($all | Select-Object -First $Max)) -join '; '
        if ($all.Count -gt $Max) { $text += (' (+{0} more - see the evidence file)' -f ($all.Count - $Max)) }
        return $text
    }

    if ($rows.Count -eq 0) {
        $whyEmpty = if ($firstScopeError) { (' The scopeType DirectoryRole query failed: {0}.' -f $firstScopeError.Exception.Message) } else { '' }
        Add-EntraFinding -Severity 'Information' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title 'PIM activation settings for admin roles could not be checked' `
            -Evidence ("No PIM role settings (role-management policies) were returned for any privileged role (scopeType tried: DirectoryRole, Directory).{0} Needs Microsoft Entra ID P2 and RoleManagementPolicy.Read.Directory. Status is unknown, not clean." -f $whyEmpty) `
            -WhyItMatters 'Privileged Identity Management (PIM) settings decide whether an admin needs MFA, approval and a time limit before admin rights switch on. Without reading them the audit cannot tell whether those safeguards exist.' `
            -RecommendedAction 'Confirm the tenant has Entra ID P2, grant RoleManagementPolicy.Read.Directory (read-only) to the audit identity, then re-run the pimpolicies check.' `
            -SourceFile $src -RuleId 'pimpolicies-not-assessed' -ObjectType 'tenant' -DocumentationUrl $pimDoc -CoverageGap
        return
    }
    if ($badAuthContexts.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} admin role(s) use a PIM authentication context that does not actually enforce MFA" -f $badAuthContexts.Count) `
            -Evidence ("Roles whose PIM activation relies on an authentication context that is unavailable or not bound to an enabled, all-users Conditional Access policy requiring MFA: {0}" -f (_ListText $badAuthContexts)) `
            -WhyItMatters 'PIM can require a Conditional Access (CA) authentication context instead of MFA. That only protects the role if the context exists and an enabled CA policy demands MFA for it; otherwise the role can be activated without the extra check you intended.' `
            -RecommendedAction 'In Entra admin center > Protection > Conditional Access > Authentication contexts, make the context available and bind it to an enabled all-users CA policy that requires MFA (ideally phishing-resistant). Otherwise turn on "On activation, require multifactor authentication" for the role in PIM.' `
            -SourceFile $src -RuleId 'pimpolicies-auth-context-not-enforced' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($unknownRules.Count -gt 0) {
        $causeText = if ($unknownCauses.Count -gt 0) { (' Why: {0}.' -f ($unknownCauses -join '; ')) } else { '' }
        Add-EntraFinding -Severity 'Medium' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("PIM settings for {0} admin role(s) could not be fully read" -f $unknownRules.Count) `
            -Evidence ("Settings that are missing or unreadable (treated as unknown, not as safe): {0}.{1}" -f (_ListText $unknownRules), $causeText) `
            -WhyItMatters 'When a PIM setting is missing from the Microsoft Graph response, the audit cannot tell whether that safeguard (MFA, approval, time limit) is on. It is reported as unknown so an incomplete read never looks like a pass.' `
            -RecommendedAction ("Open {0} for each listed role and confirm MFA, approval, justification, activation time and expiration are set explicitly; then re-run the pimpolicies check." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-rules-unreadable' -ObjectType 'tenant' -DocumentationUrl $pimDoc -CoverageGap
    }
    if ($noMfaCrit.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} top-level admin role(s) can be activated in PIM without MFA" -f $noMfaCrit.Count) `
            -Evidence ("Top-tier roles whose activation requires neither MFA nor a working authentication context: {0}" -f (_ListText $noMfaCrit)) `
            -WhyItMatters 'Roles such as Global Administrator and Privileged Role Administrator control the whole tenant. If Privileged Identity Management (PIM) lets them be activated without multifactor authentication (MFA), a stolen password alone is enough to take over the tenant.' `
            -RecommendedAction ("In {0}, edit each listed role and turn on ""On activation, require multifactor authentication"" (better: a Conditional Access authentication context that requires phishing-resistant MFA)." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-top-tier-activation-no-mfa' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($noMfaHigh.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} admin role(s) can be activated in PIM without MFA" -f $noMfaHigh.Count) `
            -Evidence ("Privileged roles whose activation requires neither MFA nor a working authentication context: {0}" -f (_ListText $noMfaHigh)) `
            -WhyItMatters 'If Privileged Identity Management (PIM) lets an admin role be activated without multifactor authentication (MFA), anyone who steals an eligible admin''s password can switch on admin rights.' `
            -RecommendedAction ("In {0}, turn on ""On activation, require multifactor authentication"" for every listed role." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-activation-no-mfa' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($noApproval.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} top-level admin role(s) can be activated without anyone approving it" -f $noApproval.Count) `
            -Evidence ("Top-tier roles without activation approval: {0}" -f (_ListText $noApproval)) `
            -WhyItMatters 'Without an approval step in Privileged Identity Management (PIM), one compromised eligible account can make itself Global Administrator (or similar) before anyone notices.' `
            -RecommendedAction ("In {0}, turn on ""Require approval to activate"" for the listed roles and name at least two approvers." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-top-tier-no-approval' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($noJust.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} top-level admin role(s) can be activated without giving a reason" -f $noJust.Count) `
            -Evidence ("Top-tier roles that do not require a justification on activation: {0}" -f (_ListText $noJust)) `
            -WhyItMatters 'Asking for a reason (justification) when admin rights are switched on leaves an audit trail. Without it, investigating misuse of admin rights is much harder.' `
            -RecommendedAction ("In {0}, turn on ""Require justification on activation"" for the listed roles." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-top-tier-no-justification' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($longDur.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} admin role(s) can stay activated for more than 8 hours" -f $longDur.Count) `
            -Evidence ("Roles with a maximum activation time above 8 hours: {0}" -f (_ListText $longDur)) `
            -WhyItMatters 'The longer an activated admin role stays on, the longer a stolen session or token can be used with admin rights.' `
            -RecommendedAction ("In {0}, set ""Activation maximum duration"" to 8 hours or less for the listed roles." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-long-activation' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($permActiveRoles.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} admin role(s) allow permanent, always-on assignments" -f $permActiveRoles.Count) `
            -Evidence ("Roles whose PIM settings allow permanent active assignment (Expiration_Admin_Assignment.isExpirationRequired = false): {0}" -f (_ListText $permActiveRoles)) `
            -WhyItMatters 'Allowing permanent active assignments lets admins keep standing admin rights, which defeats the just-in-time protection of Privileged Identity Management (PIM).' `
            -RecommendedAction ("In {0}, on the Assignment tab, turn off ""Allow permanent active assignment"" for the listed roles and use eligible (just-in-time) assignments instead." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-permanent-active-allowed' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($permEligRoles.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("{0} admin role(s) allow eligible assignments that never expire" -f $permEligRoles.Count) `
            -Evidence ("Roles whose PIM settings allow permanent eligible assignment (Expiration_Admin_Eligibility.isExpirationRequired = false): {0}" -f (_ListText $permEligRoles)) `
            -WhyItMatters 'Eligibility that never expires builds up over time, so people keep the ability to become admin long after they need it.' `
            -RecommendedAction ("In {0}, on the Assignment tab, turn off ""Allow permanent eligible assignment"" and review eligible admins regularly with access reviews." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-permanent-eligible-allowed' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($script:Findings.Where({$_.CheckId -eq 'pimpolicies'}).Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title 'PIM activation settings for admin roles are strong' `
            -Evidence ("{0} privileged role setting(s) reviewed: MFA (or an enforced authentication context) on activation, approval and justification for top-tier roles, activation of 8 hours or less, and expiring assignments are all in place." -f $rows.Count) `
            -WhyItMatters 'Strong Privileged Identity Management (PIM) settings make just-in-time admin access safe to use.' `
            -RecommendedAction 'Keep these settings and re-check them after any PIM change.' `
            -SourceFile $src -ResultRows $rows -RuleId 'pimpolicies-baseline' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
}

# ===========================================================================
# CHECK 19 - breakglass (emergency-access account health)
# ===========================================================================
function Invoke-Check-BreakGlass {
    # signInActivity is OPTIONAL enrichment here: when the users+signInActivity read fails
    # (throttling/timeout on a large directory, or an app-only token without the AuditLog
    # permission) Get-EAUsers -IncludeSignInActivity throws. Degrade to the plain user list so
    # every other emergency-access control is still validated, and report the sign-in test as
    # unknown. (Get-EAUsers remembers the failure, so the retry below reads the base set once.)
    # A failure of the BASE user read is not a sign-in problem - rethrow it so the check is
    # recorded as Error/Skipped instead of retrying the same read.
    $signinFetchError = $null
    try { $users = Get-EAUsers -IncludeSignInActivity }
    catch {
        if (-not $script:SignInFetchError) { throw }
        $signinFetchError = [string]$script:SignInFetchError.Message
        $users = Get-EAUsers
    }
    $byUpn = @{}; foreach ($u in $users) { if ($u.UserPrincipalName) { $byUpn[$u.UserPrincipalName.ToLowerInvariant()] = $u } }
    $bgDoc = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access'

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
    # a designated account is not understated. A failed/incomplete merge is tracked: a
    # role-targeted CA policy could then apply without showing in the CA columns.
    $privRolesKnown = $true; $privRolesError = $null
    try {
        $effectivePrivUsers = Get-EAPrivilegedUserMap
        foreach ($uid in $effectivePrivUsers.Keys) {
            if (-not $privRolesByUser.ContainsKey($uid)) { $privRolesByUser[$uid] = New-Object System.Collections.Generic.HashSet[string] }
            # Plain foreach (no @()): the map values are List objects created with New-Object.
            foreach ($pa in $effectivePrivUsers[$uid]) { if ($pa.RoleTemplateId) { [void]$privRolesByUser[$uid].Add([string]$pa.RoleTemplateId) } }
        }
        if ($script:PrivilegedUserMapIncomplete) { $privRolesKnown = $false }
    } catch { $privRolesKnown = $false; $privRolesError = $_.Exception.Message }
    # When the assignment fetch itself failed, GA status is UNKNOWN - report that
    # instead of a false "not a permanent Global Administrator" Critical.
    $gaKnown = -not $script:PrivAssignmentsFailed

    # Conditional Access lockout evaluation context. A failed policy read means the CA
    # exposure is UNKNOWN - it must not silently evaluate as "no policies apply".
    $caKnown = $true; $caError = $null
    $enabledCa = @(); try { $enabledCa = @(Get-EACaPolicies | Where-Object { $_.State -eq 'enabled' }) } catch { $caKnown = $false; $caError = $_.Exception.Message }
    # Sign-in data is known only when the cached user set really carries signInActivity (P1 +
    # AuditLog.Read.All AND a successful read) - otherwise the test status is unknown, never
    # "no successful sign-in in 90 days".
    $signinKnown = [bool]$script:UsersCacheHasSignIn

    # (CA applicability uses the shared Get-EAUserScopeIds / Test-CaPolicyAppliesToUser helpers.)
    $bg = Normalize-StringList -Values $BreakGlassUpns

    if ($bg.Count -eq 0) {
        # Nothing to validate - but still write the evidence file so the finding has a source
        # and the raw-data index shows the check ran.
        $src0 = Write-Evidence -BaseName 'break_glass' -Rows @() -Title 'Emergency-Access (Break-Glass) Account Health' `
            -Notes @('No accounts were passed with -BreakGlassUpns, so no emergency-access account could be validated.')
        # This is a visibility gap (the audit was not told which accounts to test), not proof
        # that the tenant lacks emergency-access accounts - hence CoverageGap at High.
        Add-EntraFinding -Severity 'High' -CheckId 'breakglass' -Category 'Privileged Access' `
            -Title 'Emergency-access (break-glass) accounts were not checked because none were named' `
            -Evidence 'The audit was run without -BreakGlassUpns, so it does not know which accounts are the emergency-access accounts. Example: -BreakGlassUpns "bg1@tenant.onmicrosoft.com;bg2@tenant.onmicrosoft.com".' `
            -WhyItMatters 'Microsoft recommends two cloud-only emergency-access Global Administrator accounts so you can still get in if MFA, federation or Privileged Identity Management (PIM) breaks. Without their names the audit cannot confirm they exist and work.' `
            -RecommendedAction 'Create two cloud-only break-glass Global Administrator accounts on the .onmicrosoft.com domain (if you do not have them), then re-run the audit with -BreakGlassUpns naming both.' `
            -SourceFile $src0 -RuleId 'breakglass-none-designated' -ObjectType 'tenant' -DocumentationUrl $bgDoc -CoverageGap
        return
    }
    # Per-account findings are QUEUED and only emitted after Write-Evidence, so every
    # one of them links to the break_glass evidence file (which can only be written
    # once the loop has built the rows).
    $pending = New-Object System.Collections.Generic.List[object]
    if ($bg.Count -lt 2) {
        $pending.Add(@{ Severity='Critical'; RuleId='breakglass-fewer-than-two'; ObjectType='tenant'
            Title='Fewer than two emergency-access (break-glass) accounts were named'
            Evidence=("Only {0} account was passed in -BreakGlassUpns: {1}." -f $bg.Count, ($bg -join ', '))
            WhyItMatters='With a single emergency-access account there is no backup: if that one account is lost, locked or broken, nobody may be able to get back into the tenant during an outage.'
            RecommendedAction='Keep at least two cloud-only emergency-access Global Administrator accounts, and name both with -BreakGlassUpns.' }) | Out-Null
    }

    $rows = @()
    foreach ($upn in $bg) {
        $u = $byUpn[$upn.ToLowerInvariant()]
        if (-not $u) {
            $pending.Add(@{ Severity='High'; AffectedPrincipal=$upn; RuleId='breakglass-account-not-found'; ObjectType='user'; ObjectId=$upn
                Title=("Named break-glass account was not found in the directory: {0}" -f $upn)
                Evidence=("The UPN {0} passed to -BreakGlassUpns does not match any user in the tenant." -f $upn)
                WhyItMatters='If the emergency-access account you rely on does not exist (or its name is wrong), you have no tested way back in during a lockout.'
                RecommendedAction='Check the spelling of the UPN passed to -BreakGlassUpns. If the account is really missing, create it: cloud-only, on the .onmicrosoft.com domain, with permanent Global Administrator.' }) | Out-Null
            continue
        }
        $enabled   = [bool]$u.AccountEnabled
        $isGA      = [bool]($u.Id -and $gaIds.ContainsKey($u.Id))
        $cloudOnly = -not [bool]$u.OnPremisesSyncEnabled
        $onmsft    = ($u.UserPrincipalName -like '*.onmicrosoft.com')
        $licenseCount = @($u.AssignedLicenses | Where-Object { $_ }).Count
        $licensed  = ($licenseCount -gt 0)
        $lastSucc  = $null
        if ($signinKnown -and $u.SignInActivity -and $u.SignInActivity.LastSuccessfulSignInDateTime) { $lastSucc = [datetime]$u.SignInActivity.LastSuccessfulSignInDateTime }
        $objKeys = @{ AffectedPrincipal=$u.UserPrincipalName; ObjectType='user'; ObjectId=$(if ($u.Id) { [string]$u.Id } else { $u.UserPrincipalName }) }

        # Which enabled blocking / MFA-requiring CA policies apply, and at what APP scope?
        # A policy that only targets a single workload app is far less of a lockout risk than
        # one covering all cloud apps (which includes the admin portals / Graph / Azure mgmt).
        $scope = Get-EAUserScopeIds $u.Id
        # An unreadable membership hides exclusion groups: evaluating CA with an empty group
        # set would report a correctly excluded account as locked out. Report unknown instead.
        $scopeKnown = [bool]$scope.Known
        $caRowKnown = ($caKnown -and $scopeKnown)
        # Copy the cached role set before adding eligible roles - mutating the shared cache
        # entry would pollute it for any later consumer of this user's scope.
        $bgRoles = [System.Collections.Generic.HashSet[string]]::new($scope.Roles)
        if ($u.Id -and $privRolesByUser.ContainsKey($u.Id)) { foreach ($rt in $privRolesByUser[$u.Id]) { [void]$bgRoles.Add($rt) } }
        $blockAll = @(); $blockScoped = @(); $mfaAll = @(); $mfaScoped = @()
        foreach ($p in $(if ($scopeKnown) { $enabledCa } else { @() })) {
            if (-not (Test-CaPolicyAppliesToUser -Policy $p -UserId $u.Id -GroupIds $scope.Groups -RoleTemplateIds $bgRoles)) { continue }
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
            Licensed=$licensed; LicenseCount=$licenseCount
            LastSuccessfulSignIn=$(if ($signinKnown) { $lastSucc } else { 'unknown' })
            BlockAllApps=$(if ($caRowKnown) { $blockAll -join '; ' } else { 'unknown' }); BlockScoped=$(if ($caRowKnown) { $blockScoped -join '; ' } else { 'unknown' })
            MfaAllApps=$(if ($caRowKnown) { $mfaAll -join '; ' } else { 'unknown' }); MfaScoped=$(if ($caRowKnown) { $mfaScoped -join '; ' } else { 'unknown' })
            UserId=$u.Id
        }
        if ($caKnown -and -not $scopeKnown) {
            $pending.Add(@{ Severity='Medium'; CoverageGap=$true; RuleId='breakglass-ca-membership-unknown'
                Title=("Conditional Access lockout risk is unknown for break-glass account: {0}" -f $u.UserPrincipalName)
                Evidence='The account''s group and role memberships could not be read, so exclusion groups are invisible. The Conditional Access columns in the evidence file show "unknown", not clean.'
                WhyItMatters='Conditional Access (CA) policies that block sign-in or demand MFA can lock an emergency-access account out during an outage. Without its memberships the audit cannot tell whether the account is excluded.'
                RecommendedAction='Make sure the audit identity can read group memberships (GroupMember.Read.All or Directory.Read.All), or retry if the error was temporary, then re-run the breakglass check.' } + $objKeys) | Out-Null
        }

        if (-not $enabled) {
            $pending.Add(@{ Severity='Critical'; RuleId='breakglass-account-disabled'
                Title=("Break-glass account is disabled: {0}" -f $u.UserPrincipalName)
                Evidence='accountEnabled = false on the emergency-access account.'
                WhyItMatters='A disabled emergency-access account cannot be used to get back into the tenant, so the safety net fails exactly when it is needed.'
                RecommendedAction='Enable the account (Entra admin center > Users), then test that it can sign in.' } + $objKeys) | Out-Null
        }
        if ($blockAll.Count -gt 0) {
            $pending.Add(@{ Severity='Critical'; RuleId='breakglass-ca-block-all-apps'
                Title=("Break-glass account is blocked by a Conditional Access policy for all apps: {0}" -f $u.UserPrincipalName)
                Evidence=("In scope of (and not excluded from) blocking policy/policies that cover all cloud apps: {0}" -f ($blockAll -join '; '))
                WhyItMatters='A Conditional Access (CA) policy that blocks all cloud apps also blocks the admin portals, so the emergency-access account would be locked out during the very incident it exists for.'
                RecommendedAction='Exclude the break-glass accounts (directly, or through a dedicated exclusion group) from every blocking policy in Entra admin center > Protection > Conditional Access.' } + $objKeys) | Out-Null
        }
        if ($blockScoped.Count -gt 0) {
            $pending.Add(@{ Severity='Medium'; RuleId='breakglass-ca-block-scoped'
                Title=("Break-glass account is blocked from some apps by Conditional Access: {0}" -f $u.UserPrincipalName)
                Evidence=("In scope of blocking policy/policies limited to specific apps (not all cloud apps): {0}" -f ($blockScoped -join '; '))
                WhyItMatters='A Conditional Access (CA) block on a few specific apps does not stop the account reaching the admin portals, but it could still get in the way during recovery.'
                RecommendedAction='Check whether the break-glass account needs the blocked apps during recovery; exclude it from the policy if it could slow recovery down.' } + $objKeys) | Out-Null
        }
        if ($mfaAll.Count -gt 0) {
            $pending.Add(@{ Severity='High'; RuleId='breakglass-ca-mfa-all-apps'
                Title=("Break-glass account must pass MFA for all apps under Conditional Access: {0}" -f $u.UserPrincipalName)
                Evidence=("In scope of (and not excluded from) all-cloud-apps MFA / authentication-strength policy/policies: {0}" -f ($mfaAll -join '; '))
                WhyItMatters='If the emergency-access account has to pass multifactor authentication (MFA) for every app and cannot do so during an outage (for example the MFA device is lost or the method is unavailable), it is locked out when it is needed most.'
                RecommendedAction='Either exclude the break-glass accounts from MFA-requiring Conditional Access policies, or register a resilient phishing-resistant method (such as a FIDO2 security key) on each of them; monitor and alert on their sign-ins.' } + $objKeys) | Out-Null
        }
        if ($mfaScoped.Count -gt 0) {
            $pending.Add(@{ Severity='Low'; RuleId='breakglass-ca-mfa-scoped'
                Title=("Break-glass account must pass MFA for some apps under Conditional Access: {0}" -f $u.UserPrincipalName)
                Evidence=("In scope of MFA / authentication-strength policy/policies limited to specific apps: {0}" -f ($mfaScoped -join '; '))
                WhyItMatters='An MFA requirement on a few specific apps is a small lockout risk compared with one that covers all apps.'
                RecommendedAction='Confirm the break-glass account does not need those apps during recovery, or exclude it from the policy.' } + $objKeys) | Out-Null
        }

        if ($gaKnown -and -not $isGA) {
            if ($gaExpandFailed) {
                # A GA-granting group could not be expanded - the account may hold GA
                # through it, so "not a GA" cannot be concluded (a false Critical).
                $pending.Add(@{ Severity='Medium'; CoverageGap=$true; RuleId='breakglass-ga-group-expansion-unknown'
                    Title=("Global Administrator status is unknown for break-glass account: {0}" -f $u.UserPrincipalName)
                    Evidence=("Members of Global-Administrator-granting group(s) could not be read ({0}), so whether this account holds permanent Global Administrator through a group is unknown." -f ((@($gaExpandFailedGroups | Select-Object -Unique | Select-Object -First 5)) -join ', '))
                    WhyItMatters='An emergency-access account must hold permanent Global Administrator. The members of a group that grants that role could not be read, so this could neither be confirmed nor ruled out.'
                    RecommendedAction='Grant the audit identity Group.Read.All and Member.Read.Hidden (read-only) and re-run, or check the account''s role assignments manually in Entra admin center > Roles and administrators.' } + $objKeys) | Out-Null
            } else {
                $pending.Add(@{ Severity='Critical'; RuleId='breakglass-not-permanent-ga'
                    Title=("Break-glass account is not a permanent Global Administrator: {0}" -f $u.UserPrincipalName)
                    Evidence='The account does not hold Global Administrator as a PERMANENT (standing) assignment - directly or through a role-assignable group. An eligible, time-bound or just-in-time activated Global Administrator assignment does not count.'
                    WhyItMatters='An emergency-access account must already be Global Administrator so it can fix the tenant when all other admin access fails. Rights that first have to be activated in Privileged Identity Management (PIM) may not work during an outage.'
                    RecommendedAction='Give the account a permanent (active, no end date) Global Administrator assignment in Entra admin center > Roles and administrators.' } + $objKeys) | Out-Null
            }
        }
        if (-not $cloudOnly) {
            $pending.Add(@{ Severity='Critical'; RuleId='breakglass-not-cloud-only'
                Title=("Break-glass account is synced from on-premises AD, not cloud-only: {0}" -f $u.UserPrincipalName)
                Evidence='onPremisesSyncEnabled = true on the emergency-access account.'
                WhyItMatters='A synced account depends on on-premises Active Directory (AD) and directory sync or federation - exactly the systems that may be down during an emergency.'
                RecommendedAction='Create a new cloud-only break-glass account (not synced from AD) and retire this one.' } + $objKeys) | Out-Null
        }
        if (-not $onmsft) {
            $upnDomain = if ($u.UserPrincipalName -match '@(.+)$') { $matches[1] } else { 'unknown' }
            $pending.Add(@{ Severity='High'; RuleId='breakglass-not-onmicrosoft'
                Title=("Break-glass account does not use the .onmicrosoft.com domain: {0}" -f $u.UserPrincipalName)
                Evidence=("UPN domain: {0}. Emergency-access accounts should use the tenant's built-in .onmicrosoft.com domain." -f $upnDomain)
                WhyItMatters='A custom or federated domain can stop working (for example when federation breaks); the built-in .onmicrosoft.com domain always works.'
                RecommendedAction='Change the account''s sign-in name (UPN) to the tenant''s .onmicrosoft.com domain.' } + $objKeys) | Out-Null
        }
        if (-not $signinKnown) {
            $signinWhy = if ($signinFetchError) { ("the users + signInActivity read failed: {0}" -f $signinFetchError) }
                         elseif (-not $script:HasP1) { 'signInActivity needs Entra ID P1 or higher, which was not detected' }
                         else { 'signInActivity needs AuditLog.Read.All, which was not granted' }
            $signinFix = if ($signinFetchError) { 'Re-run the audit (the failure may be temporary throttling); if it keeps failing, confirm AuditLog.Read.All is granted to the audit identity.' }
                         else { 'Grant AuditLog.Read.All and make sure the tenant has Entra ID P1 or higher, then re-run the breakglass check.' }
            $pending.Add(@{ Severity='Medium'; CoverageGap=$true; RuleId='breakglass-signin-unknown'
                Title=("Last test sign-in is unknown for break-glass account: {0}" -f $u.UserPrincipalName)
                Evidence=("No sign-in data is available because {0}. The test status is unknown, not ""never tested""." -f $signinWhy)
                WhyItMatters='Emergency-access accounts should be test-signed-in regularly. Without sign-in data the audit cannot tell when this account last worked, so it is reported as unknown rather than as a failure.'
                RecommendedAction=$signinFix } + $objKeys) | Out-Null
        }
        elseif ($null -eq $lastSucc -or $lastSucc -lt (Get-Date).ToUniversalTime().AddDays(-90)) {
            $pending.Add(@{ Severity='Medium'; RuleId='breakglass-not-tested-90d'
                Title=("Break-glass account has not signed in successfully for 90+ days: {0}" -f $u.UserPrincipalName)
                Evidence=("Last successful sign-in: {0}" -f ($lastSucc ?? 'none on record'))
                WhyItMatters='Emergency-access accounts must be tested regularly (Microsoft recommends at least every 90 days) so you know the password, sign-in method and alerting still work before a real emergency.'
                RecommendedAction='Run a documented break-glass test: sign in with the account, confirm the sign-in alert fires, and record the date and who did it.' } + $objKeys) | Out-Null
        }
        if ($licensed) {
            $pending.Add(@{ Severity='Low'; RuleId='breakglass-licensed'
                Title=("Break-glass account has licences assigned like a normal user: {0}" -f $u.UserPrincipalName)
                Evidence=("{0} licence(s) assigned to the emergency-access account." -f $licenseCount)
                WhyItMatters='Licences switch on a mailbox and other services the emergency account does not need, which adds ways to attack or misuse it.'
                RecommendedAction='Remove every licence the break-glass account does not need for sign-in and logging.' } + $objKeys) | Out-Null
        }
    }
    $bgNotes = @()
    if (-not $signinKnown) { $bgNotes += ('LastSuccessfulSignIn = unknown: sign-in activity was not available for this run.' + $(if ($signinFetchError) { " ($signinFetchError)" } else { '' })) }
    if (-not $caKnown) { $bgNotes += ("Conditional Access columns = unknown: policies could not be read ({0})." -f $caError) }
    if (-not $gaKnown) { $bgNotes += 'GlobalAdmin = unknown: the admin role assignment list could not be read.' }
    $src = Write-Evidence -BaseName 'break_glass' -Rows $rows -Title 'Emergency-Access (Break-Glass) Account Health' -Notes $bgNotes

    # Coverage gaps discovered before/during the loop are reported once, tenant-level.
    if ($rows.Count -gt 0 -and -not $caKnown) {
        $pending.Add(@{ Severity='Medium'; CoverageGap=$true; RuleId='breakglass-ca-unknown'; ObjectType='tenant'
            Title='Conditional Access lockout risk is unknown for the break-glass accounts'
            Evidence=("Conditional Access policies could not be read ({0}), so the Conditional Access columns in the evidence file are ""unknown"", not clean." -f ($caError ?? 'no detail'))
            WhyItMatters='Conditional Access (CA) policies that block sign-in or require MFA can lock emergency-access accounts out. Without the policies the audit cannot check this.'
            RecommendedAction='Grant Policy.Read.All (or retry if the error was temporary) and re-run the breakglass check.' }) | Out-Null
    }
    if ($rows.Count -gt 0 -and -not $gaKnown) {
        $pending.Add(@{ Severity='Medium'; CoverageGap=$true; RuleId='breakglass-ga-assignments-unknown'; ObjectType='tenant'
            Title='Global Administrator status is unknown for the break-glass accounts'
            Evidence='The list of admin role assignments could not be read, so the audit cannot tell whether the named accounts hold permanent Global Administrator.'
            WhyItMatters='Permanent Global Administrator is what makes an emergency-access account useful; without the role assignment data this cannot be confirmed.'
            RecommendedAction='Grant RoleManagement.Read.Directory (or retry if the error was temporary) and re-run the breakglass check.' }) | Out-Null
    }
    # Role-targeted CA policies can apply to a break-glass account through eligible or
    # group-based roles; when those could not be fully read, such a policy may be missing
    # from the CA columns above.
    $roleTargetedCa = @($enabledCa | Where-Object { @($_.Conditions.Users.IncludeRoles | Where-Object { $_ -and $_ -ne 'None' }).Count -gt 0 })
    if ($rows.Count -gt 0 -and $caKnown -and -not $privRolesKnown -and $roleTargetedCa.Count -gt 0) {
        $roleWhy = if ($privRolesError) { (" ({0})" -f $privRolesError) } else { '' }
        $pending.Add(@{ Severity='Low'; CoverageGap=$true; RuleId='breakglass-ca-role-scope-unknown'; ObjectType='tenant'
            Title='Role-targeted Conditional Access for the break-glass accounts could not be fully checked'
            Evidence=("Eligible or group-based admin role assignments could not be fully read{0}, and {1} enabled Conditional Access policy/policies target directory roles: {2}. A policy that applies through such a role may be missing from the CA columns." -f $roleWhy, $roleTargetedCa.Count, ((@($roleTargetedCa | Select-Object -First 5 | ForEach-Object { $_.DisplayName })) -join '; '))
            WhyItMatters='A Conditional Access (CA) policy aimed at admin roles also applies to a break-glass account that holds those roles, so incomplete role data can hide a lockout risk.'
            RecommendedAction='Restore read access to role eligibility and group membership (RoleManagement.Read.Directory, Group.Read.All; Entra ID P2 for eligibility) and re-run the breakglass check.' }) | Out-Null
    }
    foreach ($p in $pending) { Add-EntraFinding -CheckId 'breakglass' -Category 'Privileged Access' -SourceFile $src -DocumentationUrl $bgDoc @p }

    if ($script:Findings.Where({$_.CheckId -eq 'breakglass'}).Count -eq 0 -and $rows.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'breakglass' -Category 'Privileged Access' `
            -Title 'Emergency-access (break-glass) accounts pass every check' `
            -Evidence ("{0} account(s) checked: enabled, cloud-only, on .onmicrosoft.com, permanent Global Administrator, not locked out by Conditional Access, no licences, and signed in within the last 90 days." -f $rows.Count) `
            -WhyItMatters 'Working emergency-access accounts let you get back into the tenant if normal admin sign-in breaks.' `
            -RecommendedAction 'Keep testing the accounts at least every 90 days and alert on every sign-in.' `
            -SourceFile $src -ResultRows $rows -RuleId 'breakglass-baseline' -ObjectType 'tenant' -DocumentationUrl $bgDoc
    }
}

# ===========================================================================
# CHECK 20 - authmethodpolicy (tenant authentication-method policy)
# ===========================================================================
function Invoke-Check-AuthMethodPolicy {
    $pol = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
    $configs = @($pol.AuthenticationMethodConfigurations | Where-Object { $_ })
    # authenticationMethodConfigurations is auto-expanded on this GET. An empty list means the
    # per-method settings were not returned - every method would then look "not present"
    # (SMS/voice off, TAP off), which is a false clean. Track it and skip method conclusions.
    $configsKnown = ($configs.Count -gt 0)
    $ampDocMethods = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-methods-manage'
    $ampPath = 'Entra admin center > Entra ID > Authentication methods > Policies'

    $privMap = @{}; $privPopulationKnown = $true; $privError = $null
    try { $privMap = Get-EAPrivilegedUserMap; if ($script:PrivilegedUserMapIncomplete) { $privPopulationKnown = $false } } catch { $privPopulationKnown = $false; $privError = $_.Exception.Message }
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

    # Empty include/exclude lists read as 'none' in the Evidence text.
    function _T([string]$Value) { if ($Value) { return $Value }; return 'none' }

    # Admins a control does not reach, by UPN where known, for the Evidence text.
    function _MissingText($coverage, [int]$Max = 8) {
        $names = @(@($coverage.Missing) | ForEach-Object { if ($script:UserById.ContainsKey($_)) { $script:UserById[$_].UserPrincipalName } else { $_ } })
        if ($names.Count -eq 0) { return 'none confirmed' }
        $text = (@($names | Select-Object -First $Max)) -join ', '
        if ($names.Count -gt $Max) { $text += (' (+{0} more)' -f ($names.Count - $Max)) }
        return $text
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
        if ($mid -eq 'WindowsHelloForBusiness' -and -not $m.Present) { $details = 'Not part of this policy - Windows Hello for Business is normally configured through Intune / Windows policy.' }
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
    # 'default' is "Microsoft managed" in the portal, and Microsoft documents the managed value
    # of both the registration campaign and system-preferred authentication as ENABLED
    # (learn.microsoft.com/entra/identity/authentication/concept-authentication-default-enablement).
    # Evaluate coverage for it exactly like 'enabled' instead of reporting it as switched off.
    $campaignOn = ($campaignState -in @('enabled','default'))
    $campaignScope = [pscustomobject]@{
        Present=[bool]$campaign; State=$(if ($campaignOn) { 'enabled' } else { $campaignState }); IncludeIds=$campaignInc; ExcludeIds=$campaignExc
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
    $systemStateText = if ($systemPreferredRaw) { [string]$systemState } else { 'not-present' }
    $systemOn = ($systemStateText -in @('enabled','default'))
    $systemPreferred = [pscustomobject]@{
        Present=[bool]$systemPreferredRaw; State=$(if ($systemOn) { 'enabled' } else { $systemStateText })
        IncludeIds=$systemInc; ExcludeIds=$systemExc; TenantWide=(($systemInc -contains 'all_users') -and $systemExc.Count -eq 0)
        Targets=($systemInc -join ','); Exclusions=($systemExc -join ','); Cfg=$systemPreferredRaw
    }
    $campaignCoverage = _PrivCoverage -methods @($campaignScope)
    $systemPreferredCoverage = _PrivCoverage -methods @($systemPreferred)
    $rows += [pscustomobject]@{ MethodId='PolicyMigrationState'; State=[string]$migrationState; TenantWide=$null; IncludeTargets=''; ExcludeTargets=''; PrivilegedCoverage=''; Details='' }
    $rows += [pscustomobject]@{ MethodId='RegistrationCampaign'; State=$campaignState; TenantWide=$campaignScope.TenantWide; IncludeTargets=$campaignScope.Targets; ExcludeTargets=$campaignScope.Exclusions; PrivilegedCoverage=("{0}/{1} (+{2} unknown)" -f $campaignCoverage.Covered,$campaignCoverage.Total,$campaignCoverage.Unknown); Details=$(if ($campaignState -eq 'default') { 'Microsoft managed (currently enabled by Microsoft)' } else { '' }) }
    $rows += [pscustomobject]@{ MethodId='SystemCredentialPreferences'; State=$systemStateText; TenantWide=$systemPreferred.TenantWide; IncludeTargets=$systemPreferred.Targets; ExcludeTargets=$systemPreferred.Exclusions; PrivilegedCoverage=("{0}/{1} (+{2} unknown)" -f $systemPreferredCoverage.Covered,$systemPreferredCoverage.Total,$systemPreferredCoverage.Unknown); Details=$(if ($systemStateText -eq 'default') { 'Microsoft managed (currently enabled by Microsoft)' } else { '' }) }
    $ampNotes = @()
    if (-not $configsKnown) { $ampNotes += 'authenticationMethodConfigurations was empty: per-method states are unknown, not "not present".' }
    if (-not $privPopulationKnown) { $ampNotes += 'Privileged coverage numbers are incomplete: some admin role assignments or group memberships could not be read.' }
    $src = Write-Evidence -BaseName 'auth_method_policy' -Rows $rows -Title 'Authentication Methods Policy (state, include/exclude targets, privileged coverage)' -Notes $ampNotes

    if ($null -eq $migrationState -or [string]$migrationState -eq '') {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Authentication methods policy migration status could not be read' `
            -Evidence 'policyMigrationState was not returned by Microsoft Graph, so whether the legacy MFA/SSPR method settings still apply is unknown.' `
            -WhyItMatters 'Until the migration to the authentication methods policy is finished, the old multifactor authentication (MFA) and self-service password reset (SSPR) settings can still allow methods this policy has turned off. Without the status this cannot be confirmed.' `
            -RecommendedAction ("Check {0} > Manage migration in the portal, and re-run with Policy.Read.All." -f $ampPath) `
            -SourceFile $src -RuleId 'authmethodpolicy-migration-state-unknown' -ObjectType 'tenant' -DocumentationUrl $ampDocMethods -CoverageGap
    } elseif ([string]$migrationState -ne 'migrationComplete') {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Legacy MFA and password-reset method settings still apply (migration not finished)' `
            -Evidence ("policyMigrationState = {0} (finished = migrationComplete)." -f $migrationState) `
            -WhyItMatters 'Until the migration is finished, the old multifactor authentication (MFA) and self-service password reset (SSPR) settings can still allow methods (such as SMS) that this policy has turned off, so this policy alone does not show what people can really use.' `
            -RecommendedAction ("Review the legacy MFA and SSPR method settings, move them into the authentication methods policy, then set the migration to complete in {0} > Manage migration." -f $ampPath) `
            -SourceFile $src -RuleId 'authmethodpolicy-migration-incomplete' -ObjectType 'tenant' -DocumentationUrl $ampDocMethods
    }

    $campaignDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-registration-campaign'
    if (-not $campaign -or -not $campaignState -or $campaignState -notin @('enabled','default','disabled')) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Registration campaign setting could not be read' `
            -Evidence ("registrationEnforcement.authenticationMethodsRegistrationCampaign state: {0}. The setting was missing or had an unexpected value, so it is unknown, not off." -f $(if ($campaignState) { $campaignState } else { 'empty' })) `
            -WhyItMatters 'The registration campaign prompts people to set up a stronger sign-in method; without the setting the audit cannot tell whether it runs.' `
            -RecommendedAction 'Check Entra admin center > Entra ID > Authentication methods > Registration campaign manually, or update the Microsoft.Graph modules and re-run.' `
            -SourceFile $src -RuleId 'authmethodpolicy-registration-campaign-unknown' -ObjectType 'tenant' -DocumentationUrl $campaignDoc -CoverageGap
    } elseif (-not $campaignOn) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Campaign that prompts users to set up stronger sign-in methods is turned off' `
            -Evidence ("Registration campaign state: {0}." -f $campaignState) `
            -WhyItMatters 'The registration campaign asks people to set up a stronger method (such as Microsoft Authenticator or a passkey) when they sign in, which speeds up the move away from SMS and voice calls.' `
            -RecommendedAction 'Set the registration campaign to Microsoft managed or Enabled for all users in Entra admin center > Entra ID > Authentication methods > Registration campaign.' `
            -SourceFile $src -RuleId 'authmethodpolicy-registration-campaign-off' -ObjectType 'tenant' -DocumentationUrl $campaignDoc
    } elseif ($privMap.Count -gt 0 -and ($campaignCoverage.Covered -lt $campaignCoverage.Total -or $campaignCoverage.Unknown -gt 0)) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Registration campaign does not reach every admin' `
            -Evidence ("State {0}; admins covered: {1}/{2}; unknown: {3}; not covered: {4}. include={5}; exclude={6}." -f $campaignState,$campaignCoverage.Covered,$campaignCoverage.Total,$campaignCoverage.Unknown,(_MissingText $campaignCoverage),(_T $campaignScope.Targets),(_T $campaignScope.Exclusions)) `
            -WhyItMatters 'Admins left out of the campaign are never prompted to set up a stronger method and may keep relying on methods that can be phished.' `
            -RecommendedAction 'Include all active and eligible admins in the registration campaign and remove admin exclusions.' `
            -SourceFile $src -RuleId 'authmethodpolicy-registration-campaign-gaps' -ObjectType 'tenant' -DocumentationUrl $campaignDoc
    }

    $systemDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-system-preferred-authentication'
    if (-not $systemPreferred.Present -or -not $systemStateText -or $systemStateText -notin @('enabled','default','disabled')) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'System-preferred authentication setting could not be read' `
            -Evidence ("systemCredentialPreferences state: {0}. The setting was not returned by Microsoft Graph (the installed Graph module may not expose it) or had an unexpected value, so it is unknown, not off." -f $(if ($systemStateText) { $systemStateText } else { 'empty' })) `
            -WhyItMatters 'System-preferred authentication makes Entra ask for the strongest method a person has registered; without the setting the audit cannot tell whether that is on.' `
            -RecommendedAction 'Check Entra admin center > Entra ID > Authentication methods > Settings manually, or update the Microsoft.Graph modules and re-run.' `
            -SourceFile $src -RuleId 'authmethodpolicy-system-preferred-unknown' -ObjectType 'tenant' -DocumentationUrl $systemDoc -CoverageGap
    } elseif (-not $systemOn) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'System-preferred authentication is turned off, so users can pick weaker methods' `
            -Evidence ("systemCredentialPreferences state: {0}." -f $systemStateText) `
            -WhyItMatters 'System-preferred authentication makes Entra ask for the strongest method a person has registered. When it is off, people can keep choosing a weaker method such as SMS even when they have a stronger one.' `
            -RecommendedAction 'Set System-preferred authentication to Microsoft managed or Enabled for all users in Entra admin center > Entra ID > Authentication methods > Settings.' `
            -SourceFile $src -RuleId 'authmethodpolicy-system-preferred-off' -ObjectType 'tenant' -DocumentationUrl $systemDoc
    } elseif ($privMap.Count -gt 0 -and ($systemPreferredCoverage.Covered -lt $systemPreferredCoverage.Total -or $systemPreferredCoverage.Unknown -gt 0)) {
        Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'System-preferred authentication does not cover every admin' `
            -Evidence ("State {0}; admins covered: {1}/{2}; unknown: {3}; not covered: {4}. exclusions: {5}." -f $systemStateText,$systemPreferredCoverage.Covered,$systemPreferredCoverage.Total,$systemPreferredCoverage.Unknown,(_MissingText $systemPreferredCoverage),(_T $systemPreferred.Exclusions)) `
            -WhyItMatters 'Admins outside system-preferred authentication can keep choosing a weaker method that can be phished, even when they have a stronger one registered.' `
            -RecommendedAction 'Target system-preferred authentication at all users (or at least every active and eligible admin) and remove admin exclusions.' `
            -SourceFile $src -RuleId 'authmethodpolicy-system-preferred-gaps' -ObjectType 'tenant' -DocumentationUrl $systemDoc
    }
    if (-not $privPopulationKnown) {
        $privWhy = if ($privError) { (" ({0})" -f $privError) } else { '' }
        Add-EntraFinding -Severity 'Information' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Could not fully check which admins the sign-in method settings reach' `
            -Evidence ("Some admin role assignments or group memberships could not be read{0}, so the admin coverage numbers are incomplete, not confirmed clean." -f $privWhy) `
            -WhyItMatters 'A method can look enabled for everyone while an unreadable exclusion group leaves an admin outside it.' `
            -RecommendedAction 'Restore read access to roles and groups (RoleManagement.Read.Directory, Group.Read.All) and re-run the authmethodpolicy check.' `
            -SourceFile $src -RuleId 'authmethodpolicy-privileged-targeting-unknown' -ObjectType 'tenant' -CoverageGap
    }

    if (-not $configsKnown) {
        # Without the per-method settings SMS/voice/TAP would all read as "not present" -
        # report the gap and skip every method-level conclusion instead of a false clean.
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Sign-in method settings (SMS, voice, passkeys, Temporary Access Pass) could not be read' `
            -Evidence 'The authentication methods policy was read but its authenticationMethodConfigurations list was empty, so the state of each sign-in method is unknown.' `
            -WhyItMatters 'Without the per-method settings the audit cannot tell whether weak methods such as SMS are on, or whether phishing-resistant methods are available to admins.' `
            -RecommendedAction ("Check the methods in {0} manually, confirm Policy.Read.All is granted, and re-run the authmethodpolicy check." -f $ampPath) `
            -SourceFile $src -RuleId 'authmethodpolicy-method-settings-unknown' -ObjectType 'tenant' -DocumentationUrl $ampDocMethods -CoverageGap
    } else {
        $phoneDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-phone-options'
        foreach ($weak in @(@{ n='SMS'; id='Sms'; m=$sms }, @{ n='Voice'; id='Voice'; m=$voice })) {
            if ($weak.m.State -ne 'enabled') { continue }
            $weakCoverage = _PrivCoverage -methods @($weak.m)
            if ($weak.m.TenantWide -or $weakCoverage.Covered -gt 0) {
                Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title ("Weak phone-based sign-in method is on for everyone or for admins: {0}" -f $weak.n) `
                    -Evidence ("{0}: all users without exclusions={1}; admins covered={2}/{3} (+{4} unknown); include={5}; exclude={6}." -f $weak.n,$weak.m.TenantWide,$weakCoverage.Covered,$weakCoverage.Total,$weakCoverage.Unknown,(_T $weak.m.Targets),(_T $weak.m.Exclusions)) `
                    -WhyItMatters 'SMS and voice-call codes can be phished or stolen by taking over the phone number (SIM swapping). Leaving them on for everyone, or for any admin, keeps an easy way into high-value accounts.' `
                    -RecommendedAction ("Turn off {0} in {1}, or at least exclude every admin now and limit it to a small, time-limited group." -f $weak.n, $ampPath) `
                    -SourceFile $src -RuleId 'authmethodpolicy-phishable-method-broad' -ObjectType 'policy' -ObjectId $weak.id -DocumentationUrl $phoneDoc
            } else {
                Add-EntraFinding -Severity 'Low' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title ("Weak phone-based sign-in method is on for a limited group: {0}" -f $weak.n) `
                    -Evidence ("{0} include targets: {1}; exclude targets: {2}; admins covered: {3}/{4} (+{5} unknown)." -f $weak.n,(_T $weak.m.Targets),(_T $weak.m.Exclusions),$weakCoverage.Covered,$weakCoverage.Total,$weakCoverage.Unknown) `
                    -WhyItMatters 'SMS or voice for a small group (for example during a migration) is much lower risk than for everyone, but it is still a weak method that can be phished.' `
                    -RecommendedAction 'Confirm the group is intentional and time-limited, and turn the method off when the migration ends.' `
                    -SourceFile $src -RuleId 'authmethodpolicy-phishable-method-scoped' -ObjectType 'policy' -ObjectId $weak.id -DocumentationUrl $phoneDoc
            }
        }

        $passkeyDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passkeys-fido2'
        $phishEnabled = (($fido2.Present -and $fido2.State -eq 'enabled') -or ($whfb.Present -and $whfb.State -eq 'enabled') -or ($x509.Present -and $x509.State -eq 'enabled'))
        if (-not $phishEnabled) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title 'No phishing-resistant sign-in method (passkey/FIDO2 or certificate) is turned on' `
                -Evidence ("Passkey (FIDO2) state: {0}; certificate-based authentication state: {1}; Windows Hello for Business in this policy: {2} (normally configured through Intune / Windows policy instead)." -f $fido2.State, $x509.State, $whfb.State) `
                -WhyItMatters 'Phishing-resistant methods such as passkeys (FIDO2) and certificate-based authentication stop fake sign-in pages and stolen codes from working. If none is turned on, admins cannot register one.' `
                -RecommendedAction ("Turn on Passkey (FIDO2) - and optionally certificate-based authentication - in {0}, then require it for admins with a Conditional Access authentication strength." -f $ampPath) `
                -SourceFile $src -RuleId 'authmethodpolicy-no-phishing-resistant-method' -ObjectType 'tenant' -DocumentationUrl $passkeyDoc
        } elseif ($privMap.Count -gt 0 -and ($phishCoverage.Covered -lt $phishCoverage.Total -or $phishCoverage.Unknown -gt 0)) {
            Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title 'Phishing-resistant sign-in methods are not available to every admin' `
                -Evidence ("Admins covered by passkey (FIDO2) / Windows Hello / certificate-based: {0}/{1}; unknown: {2}; not covered: {3}. FIDO2 include/exclude={4}/{5}; WHfB={6}/{7}; CBA={8}/{9}." -f $phishCoverage.Covered,$phishCoverage.Total,$phishCoverage.Unknown,(_MissingText $phishCoverage),(_T $fido2.Targets),(_T $fido2.Exclusions),(_T $whfb.Targets),(_T $whfb.Exclusions),(_T $x509.Targets),(_T $x509.Exclusions)) `
                -WhyItMatters 'A method that is on somewhere in the tenant does not help admins who are excluded from it or outside its target groups; they are left with methods that can be phished.' `
                -RecommendedAction 'Make at least one phishing-resistant method (passkey/FIDO2 or certificate) available to every active and eligible admin and remove admin exclusions.' `
                -SourceFile $src -RuleId 'authmethodpolicy-phishing-resistant-gaps' -ObjectType 'tenant' -DocumentationUrl $passkeyDoc
        } elseif (-not ($fido2.TenantWide -or $whfb.TenantWide -or $x509.TenantWide)) {
            Add-EntraFinding -Severity 'Low' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title 'Phishing-resistant sign-in methods cover admins but not all users' `
                -Evidence ("FIDO2 targets/exclusions: {0}/{1}; WHfB: {2}/{3}; certificate-based: {4}/{5}." -f (_T $fido2.Targets),(_T $fido2.Exclusions),(_T $whfb.Targets),(_T $whfb.Exclusions),(_T $x509.Targets),(_T $x509.Exclusions)) `
                -WhyItMatters 'Admins come first, but making passkeys available to everyone lowers the phishing risk for the whole organisation.' `
                -RecommendedAction ("Widen the passkey (FIDO2) or certificate-based authentication target to all users in {0}." -f $ampPath) `
                -SourceFile $src -RuleId 'authmethodpolicy-phishing-resistant-not-tenant-wide' -ObjectType 'tenant' -DocumentationUrl $passkeyDoc
        }

        if ($tap.Present -and $tap.State -eq 'enabled') {
            $tapDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass'
            $cfg = $tap.Cfg
            $oneTime = $null; $minLife = $null; $defaultLife = $null; $maxLife = $null; $tapReadError = $null
            try {
                if ($cfg.PSObject.Properties['IsUsableOnce']) { $oneTime = [bool]$cfg.IsUsableOnce } elseif ($cfg.AdditionalProperties -and $cfg.AdditionalProperties.ContainsKey('isUsableOnce')) { $oneTime = [bool]$cfg.AdditionalProperties['isUsableOnce'] }
                $maxLife = Get-Ap $cfg 'maximumLifetimeInMinutes'; if ($null -eq $maxLife -and $cfg.PSObject.Properties['MaximumLifetimeInMinutes']) { $maxLife = $cfg.MaximumLifetimeInMinutes }
                $minLife = Get-Ap $cfg 'minimumLifetimeInMinutes'; if ($null -eq $minLife -and $cfg.PSObject.Properties['MinimumLifetimeInMinutes']) { $minLife = $cfg.MinimumLifetimeInMinutes }
                $defaultLife = Get-Ap $cfg 'defaultLifetimeInMinutes'; if ($null -eq $defaultLife -and $cfg.PSObject.Properties['DefaultLifetimeInMinutes']) { $defaultLife = $cfg.DefaultLifetimeInMinutes }
            } catch { $tapReadError = $_.Exception.Message }   # values stay null -> reported as unknown below
            if ($oneTime -eq $false -and $tap.TenantWide) {
                Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title 'Temporary Access Pass can be reused and is available to all users' `
                    -Evidence ("TAP isUsableOnce=false, targeted at all users; maximum lifetime {0} minutes." -f ($maxLife ?? 'default')) `
                    -WhyItMatters 'A Temporary Access Pass (TAP) is a time-limited passcode that can sign someone in and set up new sign-in methods. If it can be reused and anyone can be given one, an intercepted pass works like a password for its whole lifetime.' `
                    -RecommendedAction ("In {0} > Temporary Access Pass, turn on one-time use, shorten the lifetime and limit it to a controlled onboarding/helpdesk group." -f $ampPath) `
                    -SourceFile $src -RuleId 'authmethodpolicy-tap-reusable-broad' -ObjectType 'tenant' -DocumentationUrl $tapDoc
            } elseif ($oneTime -eq $false) {
                Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title 'Temporary Access Pass can be reused (not one-time)' `
                    -Evidence ("TAP isUsableOnce=false; targets: {0}." -f (_T $tap.Targets)) `
                    -WhyItMatters 'A reusable Temporary Access Pass (TAP) can be replayed for its whole lifetime if it is intercepted, unlike a one-time pass.' `
                    -RecommendedAction ("In {0} > Temporary Access Pass, turn on one-time use and keep the lifetime short." -f $ampPath) `
                    -SourceFile $src -RuleId 'authmethodpolicy-tap-reusable' -ObjectType 'tenant' -DocumentationUrl $tapDoc
            }
            if ($null -eq $oneTime -or $null -eq $defaultLife -or $null -eq $maxLife) {
                $tapWhy = if ($tapReadError) { (" Read error: {0}." -f $tapReadError) } else { '' }
                Add-EntraFinding -Severity 'Information' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title 'Temporary Access Pass reuse and lifetime settings could not be fully read' `
                    -Evidence ("isUsableOnce={0}; minimum={1}; default={2}; maximum={3} minutes. Missing values are unknown, not safe defaults.{4}" -f ($oneTime ?? 'unknown'),($minLife ?? 'unknown'),($defaultLife ?? 'unknown'),($maxLife ?? 'unknown'),$tapWhy) `
                    -WhyItMatters 'A Temporary Access Pass (TAP) can set up new sign-in methods; whether it is one-time and how long it lives decide how long an intercepted pass could be misused.' `
                    -RecommendedAction ("Check {0} > Temporary Access Pass and set one-time use with a short default and maximum lifetime." -f $ampPath) `
                    -SourceFile $src -RuleId 'authmethodpolicy-tap-settings-unknown' -ObjectType 'tenant' -DocumentationUrl $tapDoc -CoverageGap
            }
            if (($defaultLife -as [int]) -gt 60 -or ($maxLife -as [int]) -gt 480) {
                $sev = if (($defaultLife -as [int]) -gt 480 -or ($maxLife -as [int]) -gt 1440) { 'High' } else { 'Medium' }
                Add-EntraFinding -Severity $sev -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title 'Temporary Access Pass can stay valid longer than recommended' `
                    -Evidence ("TAP minimum={0}, default={1}, maximum={2} minutes; hardened baseline is default <=60 and maximum <=480 minutes." -f ($minLife ?? 'unknown'),($defaultLife ?? 'unknown'),($maxLife ?? 'unknown')) `
                    -WhyItMatters 'A long-lived Temporary Access Pass (TAP) behaves like a temporary password: if it is copied, logged or overheard, it can be misused for longer.' `
                    -RecommendedAction ("In {0} > Temporary Access Pass, set the default lifetime to 60 minutes or less and the maximum to 8 hours or less." -f $ampPath) `
                    -SourceFile $src -RuleId 'authmethodpolicy-tap-lifetime-long' -ObjectType 'tenant' -DocumentationUrl $tapDoc
            }
        }
    }

    if ($script:Findings.Where({$_.CheckId -eq 'authmethodpolicy'}).Count -eq 0) {
        $f2scope = if ($fido2.TenantWide) { 'all' } else { 'scoped' }
        $whscope = if ($whfb.TenantWide) { 'all' } else { 'scoped' }
        $cbscope = if ($x509.TenantWide) { 'all' } else { 'scoped' }
        Add-EntraFinding -Severity 'Information' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Authentication methods policy reviewed - no weak settings found' `
            -Evidence ("FIDO2={0}/{1}, WHfB={2}/{3}, CBA={4}/{5}; SMS={6}, Voice={7}; registration campaign={8}; system-preferred={9}." -f $fido2.State,$f2scope,$whfb.State,$whscope,$x509.State,$cbscope,$sms.State,$voice.State,$campaignState,$systemStateText) `
            -WhyItMatters 'This policy decides which sign-in methods people can register and use, and for whom.' `
            -RecommendedAction 'Keep phishing-resistant methods available to everyone and keep SMS/voice to a minimum.' `
            -SourceFile $src -ResultRows $rows -RuleId 'authmethodpolicy-baseline' -ObjectType 'tenant' -DocumentationUrl $ampDocMethods
    }
}

# ===========================================================================
# CHECK 21 - accesspaths (effective-access / attack-path correlation)
# ===========================================================================
function Invoke-Check-AccessPaths {
    $apDoc = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept'
    $caDoc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access'
    $allAssignments = @(Get-EAPrivAssignments)
    # Get-EAPrivAssignments returns whatever it managed to read: when BOTH active-assignment
    # reads failed it still returns the ELIGIBLE rows, so a non-empty list is not proof that
    # the data is complete. Without the active (standing) assignments, "Active path"
    # duplicates cannot be detected and the "owner already holds this role" suppression is
    # empty, so every such owner would be reported as an escalation path and a quiet run
    # would end in a false "nothing found" baseline. Skip the role-path analysis in that
    # case; the Conditional Access exclusion-owner analysis below does not depend on it.
    $activeKnown   = -not $script:PrivAssignmentsFailed
    $eligibleKnown = -not $script:PrivEligibilityAssignmentsFailed
    $assignments   = if ($activeKnown) { $allAssignments } else { @() }
    # The user list only enriches labels and the "owner is disabled" test; remember a failure
    # so a disabled owner is shown as unknown instead of silently as enabled.
    $usersKnown = $true; $usersError = $null
    try { Get-EAUsers | Out-Null } catch { $usersKnown = $false; $usersError = $_.Exception.Message }

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
            if (-not $pathByUserRole.ContainsKey($key)) { $pathByUserRole[$key] = [System.Collections.Generic.List[object]]::new() }
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
            User=$upn; UserId=$uid; Role=$script:PrivilegedRoleTemplates[$rtid]; AssignmentScope=$assignmentScope; ViaGroups=(@($uniqPaths | ForEach-Object { $_.Group }) -join ', ')
            AlsoDirect=[bool]$directS; DirectState=$directS; ActivationModel=$activationModel; PathCount=$pathCount
        }
    }
    $apNotes = @()
    if (-not $activeKnown) { $apNotes += ('Role-path analysis skipped: active admin role assignments could not be read ({0} eligible assignment(s) were read).' -f $allAssignments.Count) }
    if ($activeKnown -and -not $eligibleKnown) { $apNotes += 'Eligible (PIM) role assignments could not be read: only paths through active assignments were analysed.' }
    if (-not $usersKnown) { $apNotes += ("The user list could not be read ({0}): users are shown by id and owner account status is unknown." -f $usersError) }
    $src = Write-Evidence -BaseName 'access_paths' -Rows $dupRows -Title 'Effective Access - Duplicate / Parallel Privileged Paths' -Notes $apNotes

    # "a -> b; c -> d (+N more)" for Evidence text; the full list is in the evidence file.
    function _PairText($items, [scriptblock]$Label, [int]$Max = 8) {
        $all = @($items)
        $text = (@($all | Select-Object -First $Max | ForEach-Object $Label)) -join '; '
        if ($all.Count -gt $Max) { $text += (' (+{0} more - see the evidence file)' -f ($all.Count - $Max)) }
        return $text
    }

    $dupActive = @($dupRows | Where-Object { $_.ActivationModel -eq 'Active path' })
    $dupElig   = @($dupRows | Where-Object { $_.ActivationModel -ne 'Active path' })
    if ($dupActive.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ("{0} case(s) of a user holding the same admin role through several active paths" -f $dupActive.Count) `
            -Evidence ("Same admin role reached through more than one standing path (several active groups, or an active direct assignment plus a group), shown as user -> role: {0}" -f (_PairText $dupActive { "$($_.User) -> $($_.Role)" })) `
            -WhyItMatters 'When someone gets the same admin role in more than one way, removing one assignment does not remove the access. Hidden duplicate paths make it easy to leave admin rights behind when a person changes job or leaves.' `
            -RecommendedAction 'Keep one reviewed path per user and role: remove the extra group memberships or direct assignments (Entra admin center > Roles and administrators) and prefer a single eligible assignment in Privileged Identity Management (PIM).' `
            -SourceFile $src -ResultRows $dupActive -RuleId 'accesspaths-duplicate-active-paths' -ObjectType 'tenant' -DocumentationUrl $apDoc
    }
    if ($dupElig.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ("{0} case(s) of a user being eligible for the same admin role through several paths" -f $dupElig.Count) `
            -Evidence ("Same admin role reachable through more than one eligible path (several eligible groups, or an eligible direct assignment plus a group), shown as user -> role: {0}" -f (_PairText $dupElig { "$($_.User) -> $($_.Role)" })) `
            -WhyItMatters 'Several eligible paths to the same admin role make access reviews and removal harder, even though the role still has to be activated in Privileged Identity Management (PIM) before use.' `
            -RecommendedAction 'Keep one reviewed eligible path per user and role and remove the extra group memberships or assignments.' `
            -SourceFile $src -ResultRows $dupElig -RuleId 'accesspaths-duplicate-eligible-paths' -ObjectType 'tenant' -DocumentationUrl $apDoc
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

            $isGuest = $false; $disabled = $false; $disabledKnown = $true; $hasSameRole = $false
            if ($isUser) {
                $isGuest = ($oupn -like '*#EXT#*')
                if ($oid -and $script:UserById.ContainsKey($oid)) { $disabled = -not [bool]$script:UserById[$oid].AccountEnabled }
                elseif (-not $usersKnown) { $disabledKnown = $false }
                $hasSameRole = ($oid -and $sameRoleActiveKey.Contains(('{0}|{1}|{2}' -f $oid, $g.RoleTemplateId, $g.ScopeKey)))
                # Suppress ONLY when the owner already holds this exact role and is a normal
                # (non-guest, enabled) account - then ownership grants nothing new.
                if ($hasSameRole -and -not $isGuest -and -not $disabled) { continue }
            }
            # Gaining GA/PRA, or any guest/disabled owner, is Critical; gaining another role is High.
            $rowSev = if ($isGuest -or $disabled -or $grantsGAorPRA) { 'Critical' } else { 'High' }
            $ownEscRows += [pscustomobject]@{
                Owner=$label; OwnerId=$oid; OwnerType=$ownerType; Group=($g.PrincipalName ?? $g.PrincipalId); GroupId=$g.PrincipalId; GrantsRole=$g.RoleName; GroupAssignmentState=$g.State
                AssignmentScope=$g.ScopeKey; Severity=$rowSev; OwnerGuest=$isGuest; OwnerDisabled=$(if ($disabledKnown) { $disabled } else { 'unknown' }); OwnerAlreadyHasSameRole=$hasSameRole
            }
        }
    }
    if ($ownEscRows.Count -gt 0) {
        $osrc = Write-Evidence -BaseName 'access_paths_ownership' -Rows $ownEscRows -Title 'Effective Access - Ownership-Based Escalation' -Notes $apNotes
        $critEsc = @($ownEscRows | Where-Object { $_.Severity -eq 'Critical' })
        $highEsc = @($ownEscRows | Where-Object { $_.Severity -eq 'High' })
        $statusNote = if ($usersKnown) { '' } else { ' Owner account status could not be read, so disabled owners may be under-rated.' }
        if ($critEsc.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'accesspaths' -Category 'Privileged Access' `
                -Title ("{0} critical path(s) where a group owner can add themselves to gain admin rights" -f $critEsc.Count) `
                -Evidence ("Critical because the group grants a top-tier role (such as Global Administrator or Privileged Role Administrator) or the owner is a guest or disabled account. Owner -> role the group grants: {0}.{1}" -f (_PairText $critEsc { "$($_.Owner) -> $($_.GrantsRole)$(if ($_.OwnerGuest -eq $true) { ' [guest owner]' })$(if ($_.OwnerDisabled -eq $true) { ' [disabled owner]' })" }), $statusNote) `
                -WhyItMatters 'The owner of a group that holds an admin role can add themselves (or anyone) to the group and get that role. For top-tier roles, or when the owner is a guest or a disabled account, this is a direct route to taking over the tenant. Holding a different admin role does not make it safe.' `
                -RecommendedAction 'Remove guest, disabled and non-admin owners from groups that hold admin roles (Entra admin center > Groups > the group > Owners). For groups that grant top-tier roles, keep ownership with a few trusted admins and manage membership with PIM for Groups and approval.' `
                -SourceFile $osrc -ResultRows $critEsc -RuleId 'accesspaths-owner-escalation-critical' -ObjectType 'tenant' -DocumentationUrl $apDoc
        }
        if ($highEsc.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'accesspaths' -Category 'Privileged Access' `
                -Title ("{0} path(s) where a group owner can add themselves to gain an admin role" -f $highEsc.Count) `
                -Evidence ("Owners who do not already hold (as active) the admin role the group grants. Owner -> role the group grants: {0}.{1}" -f (_PairText $highEsc { "$($_.Owner) -> $($_.GrantsRole)" }), $statusNote) `
                -WhyItMatters 'The owner of a group that holds an admin role can add themselves to the group and get a role they do not have today. This goes around the normal, reviewed way of handing out admin roles.' `
                -RecommendedAction 'Remove non-admin owners from groups that hold admin roles (Entra admin center > Groups > the group > Owners) and manage membership with PIM for Groups and approval.' `
                -SourceFile $osrc -ResultRows $highEsc -RuleId 'accesspaths-owner-escalation' -ObjectType 'tenant' -DocumentationUrl $apDoc
        }
    }

    # Owners of groups EXCLUDED from Conditional Access policies (especially MFA-enforcing
    # ones) can add themselves to the group and thereby exempt their own account. A failed
    # policy read is UNKNOWN, not "no exclusion groups" - track it.
    $caExcl = @{}   # groupId -> pscustomobject{ Policies=List; EnforcesMfa }
    $caKnown = $true; $caError = $null
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
    } catch { $caKnown = $false; $caError = $_.Exception.Message }
    $caOwnRows = @()
    foreach ($gid in $caExcl.Keys) {
        $info = $caExcl[$gid]
        # The display name is only a label - on failure the group id is shown instead.
        $gname = $gid
        try { $gg = Get-MgGroup -GroupId $gid -Property 'id,displayName' -ErrorAction Stop; if ($gg -and $gg.DisplayName) { $gname = $gg.DisplayName } } catch { $gname = $gid }
        $owners = @(); try { $owners = @(Get-MgGroupOwner -GroupId $gid -All -ErrorAction Stop) } catch { $ownerGaps += $gname }
        foreach ($o in $owners) {
            $oupn = Get-Ap $o 'userPrincipalName'; $oname = Get-Ap $o 'displayName'
            $label = if ($oupn) { $oupn } elseif ($oname) { $oname } else { $o.Id }
            $caOwnRows += [pscustomobject]@{ Owner=$label; OwnerId=$o.Id; ExcludedGroup=$gname; ExcludedGroupId=$gid; EnforcesMfa=$info.EnforcesMfa; Policies=(($info.Policies | Select-Object -Unique) -join '; ') }
        }
    }
    if ($caOwnRows.Count -gt 0) {
        $csrc = Write-Evidence -BaseName 'access_paths_ca_exclusions' -Rows $caOwnRows -Title 'Effective Access - CA Exclusion Group Ownership'
        $mfaExcl = @($caOwnRows | Where-Object { $_.EnforcesMfa })
        $otherExcl = @($caOwnRows | Where-Object { -not $_.EnforcesMfa })
        if ($mfaExcl.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'accesspaths' -Category 'Privileged Access' `
                -Title ("{0} owner(s) of MFA-exclusion groups can add themselves and skip MFA" -f $mfaExcl.Count) `
                -Evidence ("Owners of groups excluded from an enabled Conditional Access policy that requires MFA, shown as owner -> excluded group: {0}" -f (_PairText $mfaExcl { "$($_.Owner) -> $($_.ExcludedGroup)" })) `
                -WhyItMatters 'Conditional Access (CA) exclusion groups are left out of a policy. The owner of a group excluded from an MFA policy can add their own account to it and no longer be asked for multifactor authentication (MFA) - no admin role needed.' `
                -RecommendedAction 'Remove non-admin and guest owners from Conditional Access exclusion groups (Entra admin center > Groups > the group > Owners), keep their membership minimal (ideally only the break-glass accounts), and manage membership with PIM for Groups.' `
                -SourceFile $csrc -ResultRows $mfaExcl -RuleId 'accesspaths-ca-mfa-exclusion-owner' -ObjectType 'tenant' -DocumentationUrl $caDoc
        }
        if ($otherExcl.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'accesspaths' -Category 'Privileged Access' `
                -Title ("{0} owner(s) of Conditional Access exclusion groups can exempt themselves from policies" -f $otherExcl.Count) `
                -Evidence ("Owners of groups excluded from enabled Conditional Access policies that do not require MFA (for example block, device or location rules), shown as owner -> excluded group: {0}" -f (_PairText $otherExcl { "$($_.Owner) -> $($_.ExcludedGroup)" })) `
                -WhyItMatters 'The owner of a group that is excluded from a Conditional Access (CA) policy can add their own account to the group and escape that policy, such as a block or a device or location rule.' `
                -RecommendedAction 'Limit who owns Conditional Access exclusion groups to a few trusted admins and review the groups'' members regularly.' `
                -SourceFile $csrc -ResultRows $otherExcl -RuleId 'accesspaths-ca-exclusion-owner' -ObjectType 'tenant' -DocumentationUrl $caDoc
        }
    }

    # Coverage gaps - every one of them keeps the "nothing found" baseline from appearing.
    if (-not $activeKnown) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'Admin access paths could not be checked: active role assignments could not be read' `
            -Evidence ("Both reads of active (standing) admin role assignments failed; {0} eligible assignment(s) were read. Duplicate-path and group-owner escalation analysis needs the active assignments too, so it was skipped. Status is unknown, not clean. (Conditional Access exclusion-group owners were still checked.)" -f $allAssignments.Count) `
            -WhyItMatters 'This check finds hidden ways to become an admin, such as the same role through several groups or a group owner who can add themselves. Without the list of active admin role assignments those paths cannot be seen.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory (read-only) to the audit identity, or re-run if the error was temporary, then re-run the accesspaths check.' `
            -SourceFile $src -RuleId 'accesspaths-role-paths-not-assessed' -ObjectType 'tenant' -DocumentationUrl $apDoc -CoverageGap
    } elseif (-not $eligibleKnown) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'Eligible (PIM) admin role assignments could not be read, so access paths are incomplete' `
            -Evidence 'The tenant has Entra ID P2, but the eligible role assignments could not be read. Duplicate paths and group-owner escalation through eligible assignments (including groups that are eligible for a role) are unknown; only active assignments were analysed.' `
            -WhyItMatters 'Eligible assignments in Privileged Identity Management (PIM) are admin rights that can be switched on at any time. Paths through them - for example an owner who can add themselves to a group that is eligible for Global Administrator - are hidden when they cannot be read.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory (read-only) to the audit identity, or re-run if the error was temporary, then re-run the accesspaths check.' `
            -SourceFile $src -RuleId 'accesspaths-eligible-assignments-unknown' -ObjectType 'tenant' -DocumentationUrl $apDoc -CoverageGap
    }
    if (-not $caKnown) {
        # Without Entra ID P1 there are normally no Conditional Access policies to exclude
        # anyone from, so the gap matters less there.
        $caGapSev = if ($script:LicenseKnown -and -not $script:HasP1) { 'Low' } else { 'Medium' }
        Add-EntraFinding -Severity $caGapSev -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'Owners of Conditional Access exclusion groups could not be checked' `
            -Evidence ("Conditional Access policies could not be read ({0}), so it is unknown which groups are excluded from them and whether their owners could add themselves. Status is unknown, not clean." -f $caError) `
            -WhyItMatters 'A group owner who can add themselves to a Conditional Access (CA) exclusion group can switch off MFA or other sign-in rules for their own account. Without the policies this cannot be checked.' `
            -RecommendedAction 'Grant Policy.Read.All (read-only) to the audit identity, or re-run if the error was temporary, then re-run the accesspaths check.' `
            -SourceFile $src -RuleId 'accesspaths-ca-policies-unknown' -ObjectType 'tenant' -DocumentationUrl $caDoc -CoverageGap
    }
    if ($hiddenGaps.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ("Members of {0} admin-role group(s) could not be read" -f $hiddenGaps.Count) `
            -Evidence ("Membership could not be read (hidden membership or missing permission) for: {0}" -f (_PairText $hiddenGaps { $_ })) `
            -WhyItMatters 'Without the member list the audit cannot see who gets admin rights through these groups, so duplicate or hidden admin paths may be missed. This is a gap in the audit, not a clean result.' `
            -RecommendedAction 'Grant the audit identity Member.Read.Hidden (read-only) and re-run, or review the members of these groups manually.' `
            -SourceFile $src -RuleId 'accesspaths-group-members-unreadable' -ObjectType 'tenant' -DocumentationUrl $apDoc -CoverageGap
    }
    $ownerGaps = @($ownerGaps | Select-Object -Unique)
    if ($ownerGaps.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ("Owners of {0} group(s) could not be read" -f $ownerGaps.Count) `
            -Evidence ("Owner lists could not be read for these admin-role or Conditional Access exclusion groups: {0}" -f (_PairText $ownerGaps { $_ })) `
            -WhyItMatters 'Group owners can add members. If the owners cannot be read, the audit cannot tell whether someone could add themselves to gain admin rights or to skip Conditional Access.' `
            -RecommendedAction 'Make sure the audit identity has Group.Read.All (read-only) and re-run, or review the owners of these groups manually.' `
            -SourceFile $src -RuleId 'accesspaths-group-owners-unreadable' -ObjectType 'tenant' -DocumentationUrl $apDoc -CoverageGap
    }

    if ($activeKnown -and $eligibleKnown -and $caKnown -and
        $dupRows.Count -eq 0 -and $ownEscRows.Count -eq 0 -and $caOwnRows.Count -eq 0 -and $hiddenGaps.Count -eq 0 -and $ownerGaps.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'No duplicate admin role paths or risky group owners found' `
            -Evidence ("{0} admin role assignment(s) analysed: each admin role is reached through a single path, and no group that holds an admin role or is excluded from Conditional Access has an owner who could add themselves." -f $assignments.Count) `
            -WhyItMatters 'One reviewed path per admin role makes removing access reliable and leaves no hidden standing admin rights.' `
            -RecommendedAction 'Keep single-path admin assignments and keep group ownership limited to trusted admins.' `
            -SourceFile $src -RuleId 'accesspaths-baseline' -ObjectType 'tenant' -DocumentationUrl $apDoc
    }
}

# ===========================================================================
# CHECK 22 - staleapps (unused applications, by service-principal sign-in activity)
# ===========================================================================
function Invoke-Check-StaleApps {
    $cut = (Get-Date).ToUniversalTime().AddDays(-$StaleAppDays)
    $now = (Get-Date).ToUniversalTime()
    $staleDoc = 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/recommendation-remove-unused-apps'
    # BOTH Microsoft first-party owner tenants - built-in SPs are owned by either.
    $msftTenants = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a'   # Microsoft services
        '72f988bf-86f1-41af-91ab-2d7cd011db47'   # Microsoft corporate
    )

    # Service-principal sign-in activity (beta report; covers interactive + app-only sign-ins).
    # lastSignInDateTime is a persisted "last seen" timestamp, so it surfaces sign-ins older
    # than the 30-day raw-log window.
    $lastByAppId = @{}
    $coverageOk = $true; $activityError = $null; $badDates = 0
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
                    if ($sub -and $sub['lastSignInDateTime']) {
                        # An unparsable timestamp is counted (and noted in the evidence) instead of
                        # being dropped silently; the app then falls back to its creation date.
                        try { $dates += [datetime]$sub['lastSignInDateTime'] } catch { $badDates++ }
                    }
                }
                if ($dates.Count -gt 0) {
                    $mx = ($dates | Sort-Object -Descending | Select-Object -First 1)
                    if (-not $lastByAppId.ContainsKey($appId) -or $mx -gt $lastByAppId[$appId]) { $lastByAppId[$appId] = $mx }
                }
            }
            $uri = $resp['@odata.nextLink']; $guard++
        }
        if ($uri) { throw 'Microsoft Graph service-principal activity pagination exceeded the 500-page safety limit.' }
    } catch { $coverageOk = $false; $activityError = $_.Exception.Message }

    if (-not $coverageOk) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
            -Title 'Unused applications could not be identified because app sign-in activity could not be read' `
            -Evidence ("The beta servicePrincipalSignInActivities report could not be read ({0}). It needs AuditLog.Read.All and Entra ID P1 or higher. This is a gap in the audit, not proof that all apps are in use." -f $activityError) `
            -WhyItMatters 'Without app sign-in activity the audit cannot tell which applications are no longer used and could be removed.' `
            -RecommendedAction 'Grant AuditLog.Read.All (read-only) to the audit identity, confirm the tenant has Entra ID P1 or higher, then re-run the staleapps check.' `
            -SourceFile $null -RuleId 'staleapps-signin-activity-unknown' -ObjectType 'tenant' -DocumentationUrl $staleDoc -CoverageGap
        return
    }

    $sps = @(Get-EAServicePrincipals)
    # The shared application cache carries createdDateTime + credentials for the apps
    # registered in THIS tenant. A failed read is tracked: without it, secrets and
    # certificates held on app registrations are unknown (not "none").
    $appCreated = @{}; $appKinds = @{}
    $appsKnown = $true; $appsError = $null
    $appsAll = @(); try { $appsAll = @(Get-EAApplications) } catch { $appsKnown = $false; $appsError = $_.Exception.Message }

    # What counts as a LIVE credential - something that lets a caller sign in AS the app:
    # unexpired client secrets, certificates and symmetric keys. Not counted:
    #  - SAML token-signing certificates. Entra adds them to the service principal of every
    #    SAML-federated app (a Sign key, its Verify half and a password protecting the private
    #    key, all sharing one customKeyIdentifier). Entra uses them to SIGN tokens for the app;
    #    nobody can use them to authenticate as the app.
    #  - Encryption keys and expired credentials (Entra rejects expired secrets/certificates).
    function _KeyIdText($value) {
        if ($null -eq $value) { return $null }
        if ($value -is [byte[]]) { if ($value.Length -eq 0) { return $null }; return [Convert]::ToBase64String($value) }
        $t = [string]$value
        if ($t) { return $t }
        return $null
    }
    function _CredentialKinds($obj) {
        $keys = @(@($obj.KeyCredentials) | Where-Object { $_ })
        $pwds = @(@($obj.PasswordCredentials) | Where-Object { $_ })
        $signIds = New-Object System.Collections.Generic.HashSet[string]
        foreach ($k in $keys) { if ([string]$k.Usage -eq 'Sign') { $kid = _KeyIdText $k.CustomKeyIdentifier; if ($kid) { [void]$signIds.Add($kid) } } }
        $out = @()
        foreach ($k in $keys) {
            $kid = _KeyIdText $k.CustomKeyIdentifier
            $usage = [string]$k.Usage
            $kind = if ($usage -eq 'Sign' -or ($kid -and $signIds.Contains($kid))) { 'SamlSigningCert' }
                    elseif ($usage -eq 'Verify' -and [string]$k.Type -eq 'Symmetric') { 'SymmetricKey' }
                    elseif ($usage -eq 'Verify') { 'Certificate' }
                    else { 'Key/' + $(if ($usage) { $usage } else { 'unknown' }) }
            $expired = [bool]($k.EndDateTime -and ([datetime]$k.EndDateTime).ToUniversalTime() -lt $now)
            $out += [pscustomobject]@{ Kind=$kind; Expired=$expired; Live=(($kind -in @('Certificate','SymmetricKey')) -and -not $expired) }
        }
        foreach ($pc in $pwds) {
            $kid = _KeyIdText $pc.CustomKeyIdentifier
            $kind = if ($kid -and $signIds.Contains($kid)) { 'SamlSigningKeyPassword' } else { 'Secret' }
            $expired = [bool]($pc.EndDateTime -and ([datetime]$pc.EndDateTime).ToUniversalTime() -lt $now)
            $out += [pscustomobject]@{ Kind=$kind; Expired=$expired; Live=(($kind -eq 'Secret') -and -not $expired) }
        }
        return $out
    }
    # "Secret, Certificate (expired), SamlSigningCert x2" for the evidence columns.
    function _KindsText($kinds) {
        # Drop nulls: an empty array passed through parameter binding arrives as $null, and
        # @($null) has Count 1, which would print '' instead of 'none'.
        $all = @($kinds | Where-Object { $_ })
        if ($all.Count -eq 0) { return 'none' }
        return ((@($all | Group-Object { if ($_.Expired) { '{0} (expired)' -f $_.Kind } else { $_.Kind } } | ForEach-Object {
            if ($_.Count -gt 1) { '{0} x{1}' -f $_.Name, $_.Count } else { $_.Name }
        })) -join ', ')
    }

    foreach ($a in $appsAll) {
        if ($a.AppId) {
            $appCreated[$a.AppId] = $a.CreatedDateTime
            $appKinds[$a.AppId] = @(_CredentialKinds $a)
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
        # Prefer the local application object's creation time, but fall back to the service
        # principal's when the app has none: Graph returns a NULL createdDateTime for old
        # registrations - exactly the oldest, most likely unused apps. Multi-tenant/third-party
        # service principals have no local application object at all. Only when neither
        # timestamp exists is the age UNKNOWN.
        $created = $appCreated[$appId]; $createdFrom = 'application'
        if (-not $created) { $created = $sp.CreatedDateTime; $createdFrom = 'servicePrincipal' }
        if (-not $created) { $created = $null; $createdFrom = $null }

        $spKinds = @(_CredentialKinds $sp)
        # @(if ...) - an if-statement that outputs an empty array yields AutomationNull, not @().
        $localKinds = @(if ($appKinds.ContainsKey($appId)) { $appKinds[$appId] })
        $liveCred = (@($spKinds | Where-Object { $_.Live }).Count + @($localKinds | Where-Object { $_.Live }).Count) -gt 0
        # With the application list unreadable, a registration's own secrets are unknown: the
        # app is only known to be credential-free if the service principal shows a live one.
        $credKnown = ($liveCred -or $appsKnown)
        $credText = 'ServicePrincipal: {0}; AppRegistration: {1}' -f (_KindsText $spKinds), $(if ($appKinds.ContainsKey($appId)) { _KindsText $localKinds } elseif ($appsKnown) { 'no local app registration' } else { 'unknown (could not be read)' })

        $stale = $false; $reason = ''
        if ($null -ne $last) {
            if ($last -lt $cut) { $stale = $true; $reason = ("Last sign-in {0}" -f $last.ToString('yyyy-MM-dd')) }
        } elseif ($created -and ([datetime]$created) -lt $cut) {
            # No sign-in on record AND the app is older than the window (avoids flagging brand-new apps).
            $stale = $true; $reason = ("No sign-in on record (created {0}, {1} timestamp)" -f ([datetime]$created).ToString('yyyy-MM-dd'), $createdFrom)
        }
        if ($stale) {
            $rows += [pscustomobject]@{
                Application=$sp.DisplayName; AppId=$appId; ServicePrincipalId=$sp.Id; LastSignIn=$last; Created=$created; CreatedFrom=$createdFrom; Reason=$reason
                HasCredentials=$(if ($credKnown) { $liveCred } else { 'unknown' }); CredentialKinds=$credText; Enabled=$sp.AccountEnabled
            }
        } elseif ($null -eq $last -and $null -eq $created) {
            $unknownRows += [pscustomobject]@{ Application=$sp.DisplayName; AppId=$appId; ServicePrincipalId=$sp.Id; LastSignIn=$null; Created=$null; Reason='No sign-in record and no creation timestamp'; HasCredentials=$(if ($credKnown) { $liveCred } else { 'unknown' }); CredentialKinds=$credText; Enabled=$sp.AccountEnabled; OwnerTenant=$sp.AppOwnerOrganizationId }
        }
    }
    $saNotes = @(
        "Reviewed $reviewed non-Microsoft application service principal(s).",
        "Unknown-age/no-sign-in service principals: $($unknownRows.Count)",
        'HasCredentials counts only unexpired client secrets, certificates and symmetric keys. SAML token-signing certificates (and the password Entra stores with them), encryption keys and expired credentials are listed in CredentialKinds but are not counted.'
    )
    if (-not $appsKnown) { $saNotes += ("App registrations could not be read ({0}): their secrets/certificates and creation dates are unknown (HasCredentials = unknown where the service principal has no live credential)." -f $appsError) }
    if ($badDates -gt 0) { $saNotes += ("{0} sign-in timestamp(s) in the activity report could not be parsed and were ignored." -f $badDates) }
    $src = Write-Evidence -BaseName 'stale_applications' -Rows $rows -Title ("Stale / Unused Applications (no sign-in > {0} days)" -f $StaleAppDays) -Notes $saNotes
    $unknownSrc = $null
    if ($unknownRows.Count -gt 0) { $unknownSrc = Write-Evidence -BaseName 'stale_applications_unknown' -Rows $unknownRows -Title 'Applications with Unknown Usage/Age' -Notes $saNotes }

    # "a, b, c (+N more)" for Evidence text; the full list is in the evidence file.
    function _AppList($items, [int]$Max = 10) {
        $all = @($items)
        $text = (@($all | Select-Object -First $Max | ForEach-Object { $_.Application })) -join ', '
        if ($all.Count -gt $Max) { $text += (' (+{0} more - see the evidence file)' -f ($all.Count - $Max)) }
        return $text
    }

    $staleCred = @($rows | Where-Object { $_.HasCredentials -is [bool] -and $_.HasCredentials })
    $staleNoCred = @($rows | Where-Object { -not ($_.HasCredentials -is [bool] -and $_.HasCredentials) })
    $staleCredUnknown = @($rows | Where-Object { $_.HasCredentials -isnot [bool] })
    $cols = @('Application','LastSignIn','Created','Reason','CredentialKinds','Enabled')
    if ($staleCred.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'staleapps' -Category 'Applications' `
            -Title ("{0} unused application(s) still have valid secrets or certificates (no sign-in for {1}+ days)" -f $staleCred.Count, $StaleAppDays) `
            -Evidence ("Applications with no sign-in in the last {0} days that still hold an unexpired client secret, certificate or key: {1}" -f $StaleAppDays, (_AppList $staleCred)) `
            -WhyItMatters 'An application nobody has used for months that still has a valid secret or certificate is a forgotten way into your tenant: if that secret leaks, an attacker can sign in as the app and nobody is likely to notice.' `
            -RecommendedAction 'Ask each app''s owner whether it is still needed and delete unused apps (Entra admin center > Entra ID > App registrations or Enterprise applications). If an app must stay, remove its unused secrets and certificates and record an owner.' `
            -SourceFile $src -ResultRows @($staleCred | Select-Object $cols) -RuleId 'staleapps-unused-with-credentials' -ObjectType 'tenant' -DocumentationUrl $staleDoc
    }
    if ($staleNoCred.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'staleapps' -Category 'Applications' `
            -Title ("{0} application(s) have not been used for {1}+ days" -f $staleNoCred.Count, $StaleAppDays) `
            -Evidence ("Cleanup candidates with no sign-in in the last {0} days and no valid secret or certificate (SAML token-signing certificates and expired credentials are not counted){1}: {2}" -f $StaleAppDays, $(if ($staleCredUnknown.Count -gt 0) { ('; for {0} of them the app registration could not be read, see the separate finding' -f $staleCredUnknown.Count) } else { '' }), (_AppList $staleNoCred)) `
            -WhyItMatters 'Unused applications keep their permissions and consent grants, clutter the directory and make reviews harder. Removing what is no longer needed reduces risk and noise.' `
            -RecommendedAction 'Review each unused application with its owner and delete the ones that are no longer needed (Entra admin center > Entra ID > Enterprise applications).' `
            -SourceFile $src -ResultRows @($staleNoCred | Select-Object $cols) -RuleId 'staleapps-unused' -ObjectType 'tenant' -DocumentationUrl $staleDoc
    }
    if ($staleCredUnknown.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'staleapps' -Category 'Applications' `
            -Title ("Could not check whether {0} unused application(s) still have secrets" -f $staleCredUnknown.Count) `
            -Evidence ("App registrations could not be read ({0}), so secrets or certificates stored on these apps' registrations are unknown. They are listed with the unused apps above, but some may belong in the higher-risk ""still have valid secrets"" group: {1}" -f $appsError, (_AppList $staleCredUnknown)) `
            -WhyItMatters 'An unused app that still has a valid secret is a bigger risk than one without. When the registrations cannot be read, the audit cannot tell which case applies.' `
            -RecommendedAction 'Make sure the audit identity has Application.Read.All (read-only) and re-run the staleapps check, or check these apps'' Certificates & secrets pages manually.' `
            -SourceFile $src -ResultRows @($staleCredUnknown | Select-Object $cols) -RuleId 'staleapps-app-credentials-unknown' -ObjectType 'tenant' -DocumentationUrl $staleDoc -CoverageGap
    }
    if ($unknownRows.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
            -Title ("{0} application(s) have no sign-in record and no known creation date" -f $unknownRows.Count) `
            -Evidence ("These third-party or legacy service principals have no entry in the sign-in activity report and no readable creation date on the application or service principal, so their usage is unknown: {0}." -f (_AppList $unknownRows)) `
            -WhyItMatters 'No sign-in record does not prove an app is in use or unused when its age is also unknown; treating these apps as clean would hide unreviewed application access.' `
            -RecommendedAction 'Review these enterprise applications manually, find an owner and purpose for each, and delete those no longer needed.' `
            -SourceFile $unknownSrc -ResultRows $unknownRows -RuleId 'staleapps-unknown-age' -ObjectType 'tenant' -DocumentationUrl $staleDoc -CoverageGap
    }
    if ($rows.Count -eq 0 -and $unknownRows.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
            -Title ("No unused applications found (no sign-in for {0}+ days)" -f $StaleAppDays) `
            -Evidence ("All {0} reviewed non-Microsoft application service principal(s) either signed in within the last {1} days or were created within that window." -f $reviewed, $StaleAppDays) `
            -WhyItMatters 'Keeping only applications that are actually used keeps the attack surface small.' `
            -RecommendedAction 'Keep reviewing application usage periodically.' `
            -SourceFile $src -RuleId 'staleapps-baseline' -ObjectType 'tenant' -DocumentationUrl $staleDoc
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
    # Fallback (objects built outside Add-EntraFinding): include the affected object so two
    # per-object findings with the same title and check do not share one HTML id.
    $obj = if ($f.ObjectId) { [string]$f.ObjectId } elseif ($f.AffectedPrincipal) { [string]$f.AffectedPrincipal } else { '' }
    'finding-' + (New-Slug ('{0}-{1}-{2}' -f $f.Title, $f.CheckId, $obj))
}

# ---------------------------------------------------------------------------
# Results-page helpers. Everything a finding carries (titles, evidence, principal names,
# result rows) can contain tenant-controlled text, so every value is HTML-encoded where it
# is written; only fixed markup and allow-listed Microsoft documentation links are raw.
# ---------------------------------------------------------------------------

# Sort key that orders embedded numbers numerically ("9 users" before "10 users").
function Format-EntraNaturalSortKey([string]$Value) {
    if ($null -eq $Value) { return '' }
    [regex]::Replace($Value.ToLowerInvariant(), '\d+', { param($m) $m.Value.PadLeft(12, '0') })
}

# A documentation URL is rendered as a link only when it points at Microsoft (https,
# learn/docs/*.microsoft.com or aka.ms). Anything else stays plain text, so tenant-
# controlled text can never become a clickable link.
function Test-EntraDocumentationUrl([string]$Url) {
    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
    $u = $null
    if (-not [uri]::TryCreate($Url.Trim(), [UriKind]::Absolute, [ref]$u)) { return $false }
    if ($u.Scheme -ne 'https' -or $u.UserInfo) { return $false }
    $h = $u.Host.ToLowerInvariant()
    return ($h -eq 'aka.ms' -or $h -eq 'microsoft.com' -or $h.EndsWith('.microsoft.com'))
}

# HTML-encodes tool-written prose (Why it matters / Recommended action) and turns
# Microsoft documentation URLs inside it into links. Other text stays inert.
function ConvertTo-EntraLinkedText([string]$Text) {
    $enc = HtmlEncode $Text
    if (-not $enc) { return '' }
    $pattern = 'https://(?:learn\.microsoft\.com|docs\.microsoft\.com|aka\.ms)/(?:(?!&quot;|&#39;|&lt;|&gt;)[^\s<>"''])+'
    [regex]::Replace($enc, $pattern, {
        param($m)
        $url = $m.Value
        $tail = ''
        while ($url.Length -gt 0 -and '.,;:)'.Contains($url[-1])) { $tail = [string]$url[-1] + $tail; $url = $url.Substring(0, $url.Length - 1) }
        "<a href='$url' target='_blank' rel='noopener noreferrer'>$url</a>$tail"
    })
}

# Plain-language label, pill class and explanation for one check's status. Reads the
# $script:CheckStatus contract (Title, Status, Count, Reason, ErrorMessage, MissingScopes)
# and tolerates older entries that only carry Title/Status/Count.
function Get-EntraCheckStatusView {
    param([string]$CheckId, $Entry, [bool]$Selected = $true)
    $reg = if ($script:Registry -and $script:Registry.Contains($CheckId)) { $script:Registry[$CheckId] } else { $null }
    $tier = if ($reg -and $reg.P2) { 'P2' } elseif ($reg -and $reg.P1) { 'P1' } else { 'P1 or P2' }
    $status = if ($Entry) { [string]$Entry.Status } else { '' }
    $reason = if ($Entry -and $Entry.PSObject.Properties['Reason'] -and $Entry.Reason) { [string]$Entry.Reason } else { '' }
    $errMsg = if ($Entry -and $Entry.PSObject.Properties['ErrorMessage'] -and $Entry.ErrorMessage) { [string]$Entry.ErrorMessage } else { '' }
    $missing = if ($Entry -and $Entry.PSObject.Properties['MissingScopes']) { @($Entry.MissingScopes | Where-Object { $_ }) } else { @() }
    $riskCount = 0
    if ($status -match '^RiskFindings\((\d+)\)') { $riskCount = [int]$Matches[1] } elseif ($Entry -and $Entry.Count) { $riskCount = [int]$Entry.Count }
    $partly = $status -like '*Incomplete*'

    if (-not $Entry) {
        if ($Selected) { $kind = 'NoResult'; $label = 'No result'; $cls = 'err'; $default = 'The check was selected but no result was recorded (the run may have stopped early).' }
        else { $kind = 'NotRun'; $label = 'Not run'; $cls = 'none'; $default = 'Not selected for this run, so it says nothing about the tenant.' }
    } elseif ($status -match '(?i)error') {
        $kind = 'Error'; $label = 'Error'; $cls = 'err'; $default = 'The check stopped with an error, so its area was not fully checked.'
    } elseif ($status -like 'Skipped*') {
        $kind = 'Skipped'; $cls = 'skip'
        switch -Regex ($status) {
            'NoScope' {
                $label = 'Skipped - missing permission'
                $default = if ($missing.Count) { 'Missing permission: ' + ($missing -join ', ') + '.' } else { 'The sign-in did not have a permission this check needs.' }
                break
            }
            'LicenseUnknown' { $label = 'Skipped - license unknown'; $default = "Needs a Microsoft Entra ID $tier license; the license lookup failed, so it is unknown whether the tenant has one."; break }
            'NoLicense' { $label = 'Skipped - no license'; $default = "Needs a Microsoft Entra ID $tier license, which was not found in this tenant."; break }
            'NoPermission' { $label = 'Skipped - access denied'; $default = 'Microsoft Graph denied access (the account lacks a permission or directory role).'; break }
            default { $label = 'Skipped'; $default = 'The check was skipped.' }
        }
    } elseif ($status -like 'RiskFindings*') {
        $kind = 'Findings'; $cls = 'find'
        $label = ('{0} risk finding{1}' -f $riskCount, $(if ($riskCount -eq 1) { '' } else { 's' }))
        if ($partly) { $label += ', partly not assessed' }
        $default = if ($partly) { 'Found problems, and part of the data could not be read (see the "Not assessed" findings).' } else { '' }
    } elseif ($status -like 'Incomplete*') {
        $kind = 'Incomplete'; $label = 'Partly not assessed'; $cls = 'skip'; $default = 'Part of the data could not be read, so this area is only partly checked (see the "Not assessed" findings).'
    } elseif ($status -eq 'Pass') {
        $kind = 'Clean'; $label = 'Passed'; $cls = 'ok'; $default = 'Checked; no problem found.'
    } elseif ($status -like 'InfoOnly*') {
        $kind = 'Clean'; $label = 'Passed (information only)'; $cls = 'ok'; $default = 'Checked; no problem found (informational notes only).'
    } else {
        $kind = 'NoResult'; $label = $status; $cls = 'err'; $default = 'Unrecognised check status.'
    }
    [pscustomobject]@{
        CheckId = $CheckId; Kind = $kind; Label = $label; Class = $cls; Status = $status
        Partly = $partly; Reason = $(if ($reason) { $reason } else { $default }); ErrorMessage = $errMsg
        Title = $(if ($Entry -and $Entry.Title) { [string]$Entry.Title } elseif ($reg) { [string]$reg.Title } else { $CheckId })
    }
}

# Check coverage for the Results page, from $script:CheckStatus, $script:Registry and
# $script:RunInfo.SelectedChecks. Counts follow the Posture Summary definitions: Clean =
# Pass/InfoOnly, WithFindings = RiskFindings*, Incomplete = *Incomplete*, Skipped =
# Skipped*, Errored = Error (plus selected checks with no recorded result). Checks that
# were not selected are 'Not run' and are not counted as gaps. Ran = Selected - Skipped -
# Errored. IsComplete is true only when status data exists and nothing was skipped,
# errored or incomplete - the report never calls a run clean otherwise.
function Get-EntraCheckCoverage {
    $statusMap = if ($script:CheckStatus -is [System.Collections.IDictionary]) { $script:CheckStatus } else { @{} }
    $registryIds = if ($script:Registry -is [System.Collections.IDictionary]) { @($script:Registry.Keys) } else { @() }
    $selected = @()
    if ($null -ne $script:RunInfo) { $selected = @(Get-EAField $script:RunInfo 'SelectedChecks' | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
    $known = ($statusMap.Count -gt 0 -or $selected.Count -gt 0)
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($id in @($registryIds) + @($selected) + @($statusMap.Keys)) { if ($id -and -not $ids.Contains([string]$id)) { $ids.Add([string]$id) } }
    $rows = foreach ($id in $ids) {
        $entry = if ($statusMap.Contains($id)) { $statusMap[$id] } else { $null }
        # Without an explicit selection list, a status entry is the proof the check was selected.
        $isSelected = if ($selected.Count -gt 0) { ($selected -contains $id) -or ($null -ne $entry) } else { $null -ne $entry }
        Get-EntraCheckStatusView -CheckId $id -Entry $entry -Selected $isSelected
    }
    $rows = @($rows)
    $cnt = { param($k) @($rows | Where-Object { $_.Kind -eq $k }).Count }
    $sel = @($rows | Where-Object { $_.Kind -ne 'NotRun' }).Count
    $skipped = & $cnt 'Skipped'
    $errored = (& $cnt 'Error') + (& $cnt 'NoResult')
    $incomplete = @($rows | Where-Object { $_.Kind -eq 'Incomplete' -or $_.Partly }).Count
    [pscustomobject]@{
        Known        = $known
        Rows         = $rows
        Selected     = $sel
        Clean        = & $cnt 'Clean'
        WithFindings = & $cnt 'Findings'
        Incomplete   = $incomplete
        Skipped      = $skipped
        Errored      = $errored
        NotRun       = & $cnt 'NotRun'
        Ran          = ($sel - $skipped - $errored)
        IsComplete   = ($known -and $sel -gt 0 -and ($skipped + $errored + $incomplete) -eq 0)
    }
}

# Lower-cased search text for a card or table row (the page search reads data-search, so
# it also matches text inside collapsed cards). Capped so huge groups stay small.
function Get-EntraSearchText {
    param([object[]]$Parts, [int]$Max = 20000)
    $s = ((@($Parts) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ }) -join ' ') -replace '\s+', ' '
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) }
    $s.ToLowerInvariant()
}

# Plain text of result rows for the search index (first rows only).
function Get-EntraRowText {
    param($Rows, [int]$MaxRows = 50)
    $out = New-Object System.Text.StringBuilder
    foreach ($r in @($Rows | Select-Object -First $MaxRows)) {
        if ($null -eq $r) { continue }
        if ($r -is [System.Collections.IDictionary]) { foreach ($k in $r.Keys) { [void]$out.Append([string]$r[$k]).Append(' ') } }
        elseif ($r -is [string] -or $r -is [ValueType]) { [void]$out.Append([string]$r).Append(' ') }
        else { foreach ($p in $r.PSObject.Properties) { [void]$out.Append([string]$p.Value).Append(' ') } }
    }
    $out.ToString()
}

# First sentence of a recommended action (for the Priority actions list).
function Get-EntraFirstSentence([string]$Text, [int]$Max = 240) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    $m = [regex]::Match($t, '^.+?[.!?](?=\s|$)')
    $s = if ($m.Success) { $m.Value } else { $t }
    if ($s.Length -gt $Max) { $cut = $s.Substring(0, $Max); $sp = $cut.LastIndexOf(' '); if ($sp -gt 40) { $cut = $cut.Substring(0, $sp) }; $s = $cut.TrimEnd(',', ';', ':') + '...' }
    $s
}

# Title for a grouped issue whose members carry different issue titles under one rule
# (e.g. one rule for every standing admin role): keeps the shared words and lists what
# differs - "Permanent (standing) Security / User Administrator" - so the heading is true
# for every member instead of naming only the first one.
function Get-EntraGroupTitle {
    param([hashtable]$TitleCounts)
    $titles = @($TitleCounts.GetEnumerator() | Sort-Object @{ e = { $_.Value }; Descending = $true }, @{ e = { Format-EntraNaturalSortKey $_.Key } } | ForEach-Object { [string]$_.Key })
    if ($titles.Count -le 1) { return [string]($titles | Select-Object -First 1) }
    $lists = New-Object System.Collections.Generic.List[object]
    foreach ($t in $titles) { $lists.Add([string[]]($t.Trim() -split '\s+')) }
    $min = [int]::MaxValue
    foreach ($w in $lists) { if ($w.Count -lt $min) { $min = $w.Count } }
    # Shared leading / trailing words, always leaving at least one differing word per title.
    $p = 0
    while ($p -lt ($min - 1)) {
        $same = $true
        foreach ($w in $lists) { if ($w[$p] -cne $lists[0][$p]) { $same = $false; break } }
        if (-not $same) { break }
        $p++
    }
    $sfx = 0
    while ($sfx -lt ($min - 1 - $p)) {
        $same = $true
        foreach ($w in $lists) { if ($w[$w.Count - 1 - $sfx] -cne $lists[0][$lists[0].Count - 1 - $sfx]) { $same = $false; break } }
        if (-not $same) { break }
        $sfx++
    }
    $middles = @(foreach ($w in $lists) { ($w[$p..($w.Count - 1 - $sfx)]) -join ' ' })
    $shown = @($middles | Select-Object -First 3)
    $mid = ($shown -join ' / ') + $(if ($middles.Count -gt 3) { " / +$($middles.Count - 3) more" } else { '' })
    $head = if ($p -gt 0) { ($lists[0][0..($p - 1)]) -join ' ' } else { '' }
    $tail = if ($sfx -gt 0) { ($lists[0][($lists[0].Count - $sfx)..($lists[0].Count - 1)]) -join ' ' } else { '' }
    (@($head, $mid, $tail) | Where-Object { $_ }) -join ' '
}

# Groups findings into ONE entry per issue (Get-EntraIssueKey: check + rule + severity), so
# 40 standing admins are one card with an affected-objects table instead of 40 cards.
# Coverage gaps ("could not read / not assessed") are grouped separately from confirmed
# findings of the same rule so they never count as risk. The group anchor is the finding's
# own anchor for single findings (old links keep working); groups get 'issue-<key>' and
# every member row keeps its finding anchor.
function Get-EntraResultGroup {
    param([object[]]$Items)
    $groups = [ordered]@{}
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }
        $issue = Get-EntraIssueKey $it
        $gap = [bool](Test-EntraCoverageGap -Finding $it)
        $key = if ($gap) { $issue.Key + '|not-assessed' } else { $issue.Key }
        if (-not $groups.Contains($key)) {
            $groups[$key] = [pscustomobject]@{
                Key = $key; Severity = $issue.Severity; CheckId = [string]$it.CheckId; Rule = $issue.Rule
                CoverageGap = $gap; Members = (New-Object System.Collections.Generic.List[object]); IssueTitles = @{}
                Title = ''; Anchor = ''; PerObject = $true; Points = 0.0
            }
        }
        $g = $groups[$key]
        $g.Members.Add($it)
        $t = [string]$issue.IssueTitle
        $g.IssueTitles[$t] = 1 + $(if ($g.IssueTitles.ContainsKey($t)) { $g.IssueTitles[$t] } else { 0 })
        if (-not ($it.AffectedPrincipal -or $it.ObjectId)) { $g.PerObject = $false }
    }
    $usedAnchors = @{}
    foreach ($g in $groups.Values) {
        $n = $g.Members.Count
        if ($n -eq 1) {
            $g.Title = [string]$g.Members[0].Title
            $g.Anchor = New-FindingAnchor $g.Members[0]
        } else {
            $g.Title = Get-EntraGroupTitle -TitleCounts $g.IssueTitles
            $base = 'issue-' + (New-Slug $g.Key)
            $a = $base; $i = 2
            while ($usedAnchors.ContainsKey($a)) { $a = "$base-$i"; $i++ }
            $g.Anchor = $a
        }
        $usedAnchors[$g.Anchor] = $true
        $pts = if ($script:RiskPoints -and $script:RiskPoints.ContainsKey($g.Severity)) { [double]$script:RiskPoints[$g.Severity] } else { 0 }
        $g.Points = if ($g.CoverageGap) { 0 } else { $pts * [math]::Sqrt($n) }
    }
    @($groups.Values)
}

# One finding card (single finding or a grouped issue). Returns the HTML string.
function ConvertTo-EntraFindingCardHtml {
    param([Parameter(Mandatory)][object]$Group, [string]$TenantId, [hashtable]$CheckTitles = @{})
    # NB: .ToArray() rather than @($list) - wrapping a generic List in @() throws
    # "Argument types do not match" on some PowerShell 7 builds.
    $members = if ($Group.Members -is [System.Collections.IList] -and $Group.Members.GetType().IsGenericType) { $Group.Members.ToArray() } else { @($Group.Members) }
    $first = $members[0]
    $n = $members.Count
    $sev = Normalize-Severity $first.Severity
    $gap = [bool]$Group.CoverageGap
    $checkId = [string]$first.CheckId
    $checkTitle = if ($CheckTitles.ContainsKey($checkId)) { [string]$CheckTitles[$checkId] } else { '' }
    $category = [string]$first.Category
    $rule = Get-FindingRule $first
    $noun = if ($Group.PerObject) { 'object' } else { 'finding' }
    $countLabel = '{0} {1}{2}' -f $n, $noun, $(if ($n -eq 1) { '' } else { 's' })

    # --- summary line (always visible) ---
    $gapBadge = if ($gap) { "<span class='badge gap' title='The audit could not read or evaluate this area. It is not a pass and is not counted as risk.'>Not assessed</span>" } else { '' }
    $countPill = if ($n -gt 1) { "<span class='count-pill'>$countLabel</span>" } else { '' }
    if ($n -gt 1) {
        $names = @($members | ForEach-Object { if ($_.AffectedPrincipal) { [string]$_.AffectedPrincipal } elseif ($_.ObjectId) { [string]$_.ObjectId } else { [string]$_.Title } } |
            Sort-Object { Format-EntraNaturalSortKey $_ } -Unique)
        $shown = @($names | Select-Object -First 4)
        $more = $names.Count - $shown.Count
        $preview = 'Affects: ' + ($shown -join ', ') + $(if ($more -gt 0) { " and $more more" } else { '' }) + '.'
        if ($Group.IssueTitles.Count -gt 1) {
            $variants = @($Group.IssueTitles.GetEnumerator() | Sort-Object @{ e = { $_.Value }; Descending = $true } | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value })
            $preview = 'Includes: ' + ($variants -join '; ') + '. ' + $preview
        }
    } else {
        $preview = [string]$first.Evidence
    }

    # --- identifiers line ---
    $meta = New-Object System.Collections.Generic.List[string]
    $checkLabel = "<a href='#check-$(HtmlAttrEncode $checkId)'><b>$(HtmlEncode $checkId)</b></a>" + $(if ($checkTitle) { " ($(HtmlEncode $checkTitle))" } else { '' })
    $meta.Add("Check: $checkLabel")
    $meta.Add("Rule: <b>$(HtmlEncode $rule)</b>")
    if ($n -eq 1) {
        if ($first.ObjectId -or $first.ObjectType) {
            $meta.Add(('Object: {0}<b>{1}</b>' -f $(if ($first.ObjectType) { (HtmlEncode $first.ObjectType) + ' ' } else { '' }), (HtmlEncode $first.ObjectId)))
        }
        if ($TenantId) {
            $fid = New-FindingKey -TenantId $TenantId -Finding $first
            $meta.Add("Finding id: <span class='fid' title='Stable id; matches FindingId in Findings.json / Findings.csv'>$(HtmlEncode $fid)</span>")
        }
    } else {
        $meta.Add("$countLabel (one finding id per row below)")
    }
    $meta.Add("Re-run only this check: <code>-select $(HtmlEncode $checkId)</code>")
    $metaHtml = "<div class='finding-meta'>" + ($meta -join ' &middot; ') + '</div>'

    # --- panels ---
    $distinct = {
        param([string]$Prop)
        @($members | ForEach-Object { [string]$_.$Prop } | Where-Object { $_ } | Select-Object -Unique)
    }
    $docUrls = @(& $distinct 'DocumentationUrl')
    $whyHtml = (@(& $distinct 'WhyItMatters' | Select-Object -First 5) | ForEach-Object { "<p>$(ConvertTo-EntraLinkedText $_)</p>" }) -join ''
    $actions = @(& $distinct 'RecommendedAction' | Select-Object -First 5 | ForEach-Object {
        $txt = $_
        # Older governance findings also append "Microsoft source: <url>" to the text; the
        # link below carries the same URL, so drop the duplicate from the prose only.
        foreach ($u in $docUrls) { $txt = $txt.Replace(" Microsoft source: $u", '').Replace("Microsoft source: $u", '') }
        "<p>$(ConvertTo-EntraLinkedText $txt.Trim())</p>"
    })
    $docHtml = (@($docUrls | ForEach-Object {
        if (Test-EntraDocumentationUrl $_) { "<div class='doc-link'><a href='$(HtmlAttrEncode $_)' target='_blank' rel='noopener noreferrer'>Microsoft documentation</a> <span class='doc-url'>$(HtmlEncode $_)</span></div>" }
        else { "<div class='doc-link'>Reference: <span class='mono'>$(HtmlEncode $_)</span></div>" }
    })) -join ''
    $sources = @(& $distinct 'SourceFile')
    $srcHtml = if ($sources.Count -gt 0) {
        (@($sources | ForEach-Object {
            $href = Resolve-SourceHref $_
            $leaf = ($_ -split '[\\/]')[-1]
            if ($href) { "<a class='download-link' href='$(HtmlAttrEncode $href)' target='_blank' rel='noopener'>Open source evidence</a><div class='result-note mono'>$(HtmlEncode $leaf)</div>" }
            else { "<div class='result-note mono'>$(HtmlEncode $leaf)</div>" }
        })) -join ''
    } else { "<span class='result-note'>No separate evidence file for this finding.</span>" }

    $foundHeading = if ($gap) { 'Why this could not be assessed' } else { 'What was found' }
    $grid = New-Object System.Collections.Generic.List[string]
    if ($n -eq 1) { $grid.Add("<div class='panel'><h4>$foundHeading</h4><p>$(HtmlEncode $first.Evidence)</p></div>") }
    $grid.Add("<div class='panel'><h4>Why it matters</h4>$whyHtml</div>")
    $grid.Add("<div class='panel'><h4>Recommended action</h4>$($actions -join '')$docHtml</div>")
    $grid.Add("<div class='panel'><h4>Source evidence</h4>$srcHtml</div>")

    # --- affected objects (groups) / affected object (single) ---
    $membersHtml = ''
    $affectedHtml = ''
    if ($n -gt 1) {
        $previewRows = 25
        $sorted = @($members | Sort-Object { Format-EntraNaturalSortKey ([string]$(if ($_.AffectedPrincipal) { $_.AffectedPrincipal } elseif ($_.ObjectId) { $_.ObjectId } else { $_.Title })) })
        $sb = New-Object System.Text.StringBuilder
        $headObj = if ($Group.PerObject) { 'Affected object' } else { 'Finding' }
        [void]$sb.Append("<div class='panel evidence members'><h4>$(if ($gap) { 'Areas not assessed' } else { 'Affected objects' }) <span class='section-count'>($n)</span></h4>")
        [void]$sb.Append("<div class='filter-note'>Showing only the rows that match the search.</div>")
        [void]$sb.Append("<div class='result-block'><div class='result-scroll'><table class='result-table members-table'><thead><tr><th>#</th><th>$headObj</th><th>Object id</th><th>$(if ($gap) { 'Why it could not be assessed' } else { 'What was found' })</th></tr></thead><tbody>")
        $i = 0
        foreach ($m in $sorted) {
            $i++
            $ma = New-FindingAnchor $m
            $fid = if ($TenantId) { New-FindingKey -TenantId $TenantId -Finding $m } else { '' }
            $label = if ($m.AffectedPrincipal) { [string]$m.AffectedPrincipal } elseif ($m.ObjectId) { [string]$m.ObjectId } else { [string]$m.Title }
            # Finding id before the (possibly long) evidence so the cap never cuts it off.
            $rowSearch = Get-EntraSearchText -Parts @($label, $m.ObjectType, $m.ObjectId, $fid, $m.Title, $m.Evidence) -Max 4000
            $cls = if ($i -gt $previewRows) { " class='extra'" } else { '' }
            $fidTitle = if ($fid) { " title='Finding id: $(HtmlAttrEncode $fid)'" } else { '' }
            [void]$sb.Append("<tr id='$(HtmlAttrEncode $ma)'$cls data-search='$(HtmlAttrEncode $rowSearch)'><td class='nw'$fidTitle>$i</td><td>$(HtmlEncode $label)$(if ($m.ObjectType) { "<span class='idx-check'>$(HtmlEncode $m.ObjectType)</span>" })</td><td class='nw oid'>$(HtmlEncode $m.ObjectId)</td><td>$(HtmlEncode $m.Evidence)</td></tr>")
        }
        [void]$sb.Append('</tbody></table></div>')
        if ($n -gt $previewRows) { [void]$sb.Append("<button type='button' class='show-more' data-more='Show all $n rows' data-less='Show the first $previewRows rows only'>Show all $n rows</button>") }
        [void]$sb.Append('</div></div>')
        $membersHtml = $sb.ToString()
    } elseif ($first.AffectedPrincipal -or $first.ObjectId) {
        $affectedHtml = "<div class='result-note'>Affected object: <span class='mono'>$(HtmlEncode $(if ($first.AffectedPrincipal) { $first.AffectedPrincipal } else { $first.ObjectId }))</span>$(if ($first.ObjectType) { ' (' + (HtmlEncode $first.ObjectType) + ')' })</div>"
    }

    # --- result rows (merged across members; the linked CSV/TXT holds every row) ---
    $allRows = New-Object System.Collections.Generic.List[object]
    foreach ($m in $members) { foreach ($r in @($m.ResultRows)) { if ($null -ne $r) { $allRows.Add($r) } } }
    $rowCount = $allRows.Count
    $maxRows = 200
    $rowNote = if ($rowCount -gt $maxRows) { ", first $maxRows shown - the source evidence file has all rows" } else { '' }
    $rowsHeading = if ($rowCount -gt 0) { "Result details <span class='section-count'>$rowCount row$(if ($rowCount -ne 1) { 's' })$rowNote</span>" } else { 'Result details' }
    # .result-rows + .hits-note: when only these rows explain a search match, the page shows
    # just the matching rows with this note (Get-EntraMainJs revealHits).
    $tableHtml = if ($rowCount -gt 0) { "<div class='result-rows'><div class='hits-note'>Showing only the result rows that match the search.</div>" + (New-EvidenceTableHtml -rows $allRows.ToArray() -maxRows $maxRows -PreviewRows 25) + '</div>' } else { "<div class='result-empty'>No row-level details were recorded for this finding.</div>" }
    $resultHtml = if ($n -gt 1) {
        if ($rowCount -gt 0) { "<details class='sub-details'><summary>$rowsHeading</summary>$tableHtml</details>" } else { '' }
    } else {
        "<div class='panel evidence'><h4>$rowsHeading</h4>$affectedHtml $tableHtml</div>"
    }

    # --- search index (includes text inside the collapsed body) ---
    # Capped (Get-EntraSearchText), so card-level facts go first, then member identifiers,
    # then member titles/evidence, then result rows. Whatever falls past the cap is still
    # found: the page search (Get-EntraMainJs) also checks every member row's own index and
    # the rendered text of the card (evidence, result tables), so a big group never hides
    # a member that is on the page.
    $searchParts = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($Group.Title, $category, $checkId, $checkTitle, $rule, $sev, $(if ($gap) { 'not assessed coverage gap' }))) { $searchParts.Add($x) }
    if ($n -eq 1 -and $TenantId) { $searchParts.Add((New-FindingKey -TenantId $TenantId -Finding $first)) }
    $whyAll = @(& $distinct 'WhyItMatters'); $actAll = @(& $distinct 'RecommendedAction')
    foreach ($x in @($whyAll | Select-Object -First 5) + @($actAll | Select-Object -First 5) + $docUrls + @($sources | ForEach-Object { ($_ -split '[\\/]')[-1] })) { $searchParts.Add($x) }
    foreach ($m in $members) { foreach ($x in @($m.AffectedPrincipal, $m.ObjectId, $m.ObjectType)) { $searchParts.Add($x) } }
    foreach ($m in $members) { foreach ($x in @($m.Title, $m.Evidence)) { $searchParts.Add($x) } }
    foreach ($x in @($whyAll | Select-Object -Skip 5) + @($actAll | Select-Object -Skip 5)) { $searchParts.Add($x) }
    $searchParts.Add((Get-EntraRowText -Rows $allRows.ToArray() -MaxRows 50))
    $search = Get-EntraSearchText -Parts $searchParts.ToArray()

    $gapClass = if ($gap) { ' coverage-gap' } else { '' }
    $checkChip = if ($checkId) { "<span class='category check mono' title='Check id'>$(HtmlEncode $checkId)</span>" } else { '' }
    $sevBadge = "<span class='badge sev-$sev'>$sev</span>"
@"
<details class="finding sev-$sev$gapClass" data-sev="$sev" data-gap="$([int]$gap)" data-check="$(HtmlAttrEncode $checkId)" data-category="$(HtmlAttrEncode $category)" data-count="$n" data-search="$(HtmlAttrEncode $search)" id="$(HtmlAttrEncode $Group.Anchor)">
  <summary>
    <div class="finding-head">
      <div class="finding-title-wrap">
        $sevBadge$gapBadge<span class="category">$(HtmlEncode $category)</span>$checkChip
        <span class="finding-title">$(HtmlEncode $Group.Title)</span>$countPill
      </div>
      <div class="finding-summary">$(HtmlEncode $preview)</div>
    </div>
  </summary>
  <div class="finding-body">
    $metaHtml
    <div class="finding-grid">
      $($grid -join "`n      ")
    </div>
    $membersHtml
    $resultHtml
  </div>
</details>
"@
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
@media print{.primary-nav{display:none}}
</style>
'@
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($css)
    [void]$sb.Append("<nav class='primary-nav' aria-label='Audit reports'>")
    foreach ($l in $links) {
        $cls = if ($l.Key -eq $Active) { 'primary-nav-link active' } else { 'primary-nav-link' }
        $current = if ($l.Key -eq $Active) { " aria-current='page'" } else { '' }
        [void]$sb.Append("<a class='$cls' href='$(HtmlAttrEncode ($HrefPrefix + $l.Href))'$current>$(HtmlEncode $l.Label)</a>")
    }
    [void]$sb.Append('</nav>')
    $sb.ToString()
}

# Renders result rows as an HTML table. Every header and cell is HTML-encoded: row values
# (names, UPNs, policy names) are tenant-controlled. -maxRows caps what is written into the
# page; the linked CSV/TXT always holds every row, and a note ABOVE the table says so.
# -PreviewRows > 0 (Results page) shows only the first rows and hides the rest behind a
# "Show all" button handled by Get-EntraMainJs; the default 0 keeps every row visible
# (the raw-data pages load a different script). Columns are the union of the rendered
# rows' properties, so merged per-object rows with slightly different shapes lose nothing.
function New-EvidenceTableHtml {
    param($rows, [int]$maxRows = 200, [int]$PreviewRows = 0)
    $empty = "<div class='result-empty'>No matching objects were found for this check.</div>"
    if ($null -eq $rows) { return $empty }
    $arr = @(foreach ($r in @($rows)) {
        if ($null -eq $r) { continue }
        if ($r -is [System.Collections.IDictionary]) { [pscustomobject]$r }
        elseif ($r -is [string] -or $r -is [ValueType]) { [pscustomobject]@{ Value = $r } }
        else { $r }
    })
    if ($arr.Count -eq 0) { return $empty }
    if ($maxRows -lt 1) { $maxRows = 1 }
    $shownRows = @($arr | Select-Object -First $maxRows)

    $cols = New-Object System.Collections.Generic.List[string]
    $seenCols = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $shownRows) { foreach ($p in $r.PSObject.Properties) { if ($seenCols.Add($p.Name)) { $cols.Add($p.Name) } } }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='result-block'>")
    if ($arr.Count -gt $maxRows) {
        [void]$sb.Append("<div class='result-note'>Showing the first $maxRows of $($arr.Count) rows. The linked source evidence file (CSV/TXT) has all rows.</div>")
    }
    [void]$sb.Append("<div class='result-scroll'><table class='result-table'><thead><tr>")
    foreach ($c in $cols) { [void]$sb.Append("<th>$(HtmlEncode $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    $i = 0
    foreach ($r in $shownRows) {
        $rowCls = if ($PreviewRows -gt 0 -and $i -ge $PreviewRows) { " class='extra'" } else { '' }
        [void]$sb.Append("<tr$rowCls>")
        foreach ($c in $cols) {
            $prop = $r.PSObject.Properties[$c]
            $v = if ($prop) { $prop.Value } else { $null }
            $s = if ($null -eq $v) { '' }
                 elseif ($v -is [string]) { $v }
                 elseif ($v -is [datetime]) { $v.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture) }
                 elseif ($v -is [datetimeoffset]) { $v.ToString('yyyy-MM-dd HH:mm:ss zzz', [System.Globalization.CultureInfo]::InvariantCulture) }
                 elseif ($v -is [System.Collections.IDictionary]) { (@($v.Keys) | ForEach-Object { '{0}={1}' -f $_, $v[$_] }) -join '; ' }
                 elseif ($v -is [System.Collections.IEnumerable]) { (@($v) | ForEach-Object { [string]$_ }) -join ', ' }
                 elseif ($v -is [System.Management.Automation.PSCustomObject]) { (@($v.PSObject.Properties) | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; ' }
                 else { [string]$v }
            # Keep identifiers, dates and other short single tokens (GUIDs, UPNs) on one line
            # instead of wrapping them over several; long text wraps normally.
            $nw = ($s.Length -gt 0 -and $s.Length -le 64 -and ($s -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-' -or $s -match '^\d{4}-\d{2}-\d{2}' -or ($s -notmatch '\s' -and $s.Length -le 48)))
            $tdCls = if ($nw) { " class='nw'" } else { '' }
            [void]$sb.Append("<td$tdCls>$(HtmlEncode $s)</td>")
        }
        [void]$sb.Append('</tr>'); $i++
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($PreviewRows -gt 0 -and $shownRows.Count -gt $PreviewRows) {
        $n = $shownRows.Count
        [void]$sb.Append("<button type='button' class='show-more' data-more='Show all $n rows' data-less='Show the first $PreviewRows rows only'>Show all $n rows</button>")
    }
    [void]$sb.Append('</div>')
    $sb.ToString()
}

# Theme toggle, live row filter with an "N of M shown" count, click-to-sort columns and
# an optional ?check=<id> pre-filter, for the standalone raw-data pages and the Raw Data
# index. Targets BODY data-theme to match Get-EntraMainCss (the risk pages target <html>).
# Sorting is numeric/date-aware (a cell's data-sort attribute overrides its text) and
# always keeps empty cells last.
function Get-EntraRawJs {
@'
<script>
(function(){
  function q(s){return document.querySelector(s);}
  function qa(s){return Array.prototype.slice.call(document.querySelectorAll(s));}
  function cur(){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(e){}if(s==='light'||s==='dark')return s;return (window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light';}
  function ap(t){document.body.setAttribute('data-theme',t);var b=q('#themeToggle');if(b)b.innerText=t==='dark'?'Light mode':'Dark mode';try{localStorage.setItem('entraaudit-theme',t);}catch(e){}}
  ap(cur());
  var b=q('#themeToggle');if(b)b.addEventListener('click',function(){ap(document.body.getAttribute('data-theme')==='dark'?'light':'dark');});
  var table=q('table.sortable');var body=(table&&table.tBodies.length)?table.tBodies[0]:null;
  function dataRows(){return body?Array.prototype.slice.call(body.rows).filter(function(r){return !r.classList.contains('no-data');}):[];}
  var checkFilter=null;try{var m=/[?&]check=([^&#]*)/.exec(location.search||'');if(m&&m[1])checkFilter=decodeURIComponent(m[1].replace(/\+/g,' '));}catch(e){}
  function apply(){var inp=q('#rawSearch');var v=((inp&&inp.value)||'').toLowerCase().trim();var shown=0,total=0;dataRows().forEach(function(r){total++;var ok=(!v||(r.textContent||'').toLowerCase().indexOf(v)>=0)&&(!checkFilter||r.getAttribute('data-check')===checkFilter);r.style.display=ok?'':'none';if(ok)shown++;});var c=q('#rawCount');if(c)c.textContent=shown+' of '+total+' '+(c.getAttribute('data-noun')||'rows')+' shown';}
  var note=q('#checkFilterNote');
  if(note&&checkFilter){note.style.display='';var nm=q('#checkFilterName');if(nm)nm.textContent=checkFilter;}
  var clr=q('#clearCheckFilter');if(clr)clr.addEventListener('click',function(e){e.preventDefault();checkFilter=null;if(note)note.style.display='none';try{history.replaceState(null,'',location.pathname+location.hash);}catch(_){}apply();});
  function val(r,i){var c=r.cells[i];if(!c)return '';var s=c.getAttribute('data-sort');return (s!==null?s:(c.textContent||'')).trim();}
  function kind(vals){var num=true,date=true,any=false;vals.forEach(function(x){if(x==='')return;any=true;if(num&&!/^-?\d+(\.\d+)?%?$/.test(x))num=false;if(date&&(!/^\d{4}-\d{2}-\d{2}/.test(x)||isNaN(Date.parse(x.replace(' ','T')))))date=false;});if(!any)return 'text';return num?'num':(date?'date':'text');}
  function sortCol(th,i){var dir=th.getAttribute('data-sort-dir')==='asc'?'desc':'asc';qa('table.sortable thead th').forEach(function(o){o.removeAttribute('data-sort-dir');o.removeAttribute('aria-sort');});th.setAttribute('data-sort-dir',dir);th.setAttribute('aria-sort',dir==='asc'?'ascending':'descending');var rows=dataRows();var vals=rows.map(function(r){return val(r,i);});var k=kind(vals);var idx=rows.map(function(r,j){return j;});idx.sort(function(a,b){var x=vals[a],y=vals[b];if(x===''&&y==='')return a-b;if(x==='')return 1;if(y==='')return -1;var c;if(k==='num'){c=parseFloat(x)-parseFloat(y);}else if(k==='date'){c=Date.parse(x.replace(' ','T'))-Date.parse(y.replace(' ','T'));}else{c=x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});}if(c===0)return a-b;return dir==='asc'?c:-c;});var frag=document.createDocumentFragment();idx.forEach(function(j){frag.appendChild(rows[j]);});body.appendChild(frag);}
  if(table&&body){qa('table.sortable thead th').forEach(function(th,i){th.setAttribute('title','Click to sort');th.setAttribute('tabindex','0');th.addEventListener('click',function(){sortCol(th,i);});th.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();sortCol(th,i);}});});}
  var inp=q('#rawSearch');if(inp)inp.addEventListener('input',apply);
  apply();
})();
</script>
'@
}

# Extra styles for the raw-data pages and the Raw Data index, layered on top of
# Get-EntraMainCss. The dataset table is NOT a fixed-height scroll box (the page itself
# scrolls and the header row stays visible), and long values wrap instead of widening
# the page.
function Get-EntraRawCss {
@'
<style>
.container.raw-page{max-width:none}
.raw-table-wrap{border:1px solid var(--line);border-radius:10px;background:var(--panel);margin-top:8px}
.raw-table td{overflow-wrap:anywhere;white-space:pre-line}
.raw-table th{cursor:pointer;user-select:none;white-space:normal}
.raw-table th:hover{color:var(--text)}
.raw-table th[data-sort-dir="asc"]::after{content:" \25B2";font-size:10px}
.raw-table th[data-sort-dir="desc"]::after{content:" \25BC";font-size:10px}
.raw-status{margin-top:10px;font-size:13px;color:var(--muted);line-height:1.6}
.raw-status b{color:var(--text)}
.raw-notes{margin:8px 0 0;padding-left:18px;color:var(--muted);font-size:14px;line-height:1.6}
.raw-used{margin-top:14px;border-top:1px solid var(--line);padding-top:12px;font-size:14px;line-height:1.5}
.raw-used ul{margin:6px 0 0;padding-left:18px}.raw-used li{margin:4px 0}
.raw-used .badge{padding:2px 8px;font-size:11px}
.raw-err{color:var(--critical);font-size:13px;margin-top:4px}
.raw-empty{background:var(--panel);border:1px dashed var(--line);border-radius:14px;padding:16px;color:var(--muted);margin-top:8px;line-height:1.5}
.sub{display:block;color:var(--muted);font-size:12px;margin-top:2px}
.check-note{background:var(--accent-soft);border-radius:10px;padding:8px 12px;margin-top:10px;font-size:13px}
body[data-theme="dark"] .check-note{background:rgba(59,130,246,.22)}
.num,.raw-table td.num,.raw-table th.num{text-align:right;white-space:nowrap}
.raw-page .toolbar{margin-top:16px}
.raw-used summary{cursor:pointer;font-weight:700}
</style>
'@
}

# Standalone, styled HTML view of one raw dataset (same design as the reports). Shows up
# to -MaxRows rows (the CSV/TXT always hold every row) in a full-height sortable table.
# Writes with -ErrorAction Stop so a failed page surfaces in Write-Evidence instead of
# leaving findings linked to a missing file. The <!--EA-USEDBY--> marker is replaced at
# report time with the findings that cite this dataset (Write-EntraDatasetUsage), which
# cannot be known yet while the check is still running.
function New-RawDataHtml {
    param([string]$Path, [string]$Title, [object[]]$Rows, [string[]]$Notes, [string]$CsvName, [string]$TxtName,
          [string]$CheckId, [string]$CheckTitle, [bool]$CsvAvailable = $true, [bool]$TxtAvailable = $true, [int]$MaxRows = 2000)
    $css = (Get-EntraMainCss) + "`n" + (Get-EntraRawCss)
    $nav = Get-EntraPrimaryNav 'raw' '../../HTML Reports/'
    $js  = Get-EntraRawJs
    $arr = if ($null -eq $Rows) { @() } else { @($Rows.Where({ $null -ne $_ })) }
    $count = $arr.Count
    $shownCount = [math]::Min($count, $MaxRows)
    $truncated = $count -gt $MaxRows

    $tableHtml = ''
    if ($count -eq 0) {
        $tableHtml = "<div class='raw-empty'><b>This dataset has no rows.</b> The check found no matching objects - unless a &quot;Not assessed&quot; finding (listed above when there is one) says the data could not be read. A failed read is always reported that way and on the Posture Summary, never only as an empty table.</div>"
    } else {
        $shown = if ($truncated) { $arr[0..($MaxRows - 1)] } else { $arr }
        # Columns = union of every shown row's properties (the first row alone can miss some).
        $cols = New-Object System.Collections.Generic.List[string]
        $seen = @{}
        foreach ($r in $shown) { foreach ($p in $r.PSObject.Properties) { if (-not $seen.ContainsKey($p.Name)) { $seen[$p.Name] = $true; $cols.Add($p.Name) | Out-Null } } }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append("<div class='raw-table-wrap'><table class='result-table raw-table sortable' id='rawTable'><thead><tr>")
        foreach ($c in $cols) { [void]$sb.Append("<th scope='col'>$(HtmlEncode $c)</th>") }
        [void]$sb.Append('</tr></thead><tbody>')
        foreach ($r in $shown) {
            [void]$sb.Append('<tr>')
            foreach ($c in $cols) {
                $p = $r.PSObject.Properties[$c]
                $s = if (-not $p -or $null -eq $p.Value) { '' }
                     elseif ($p.Value -is [string]) { $p.Value }
                     else { ConvertTo-EntraEvidenceCell $p.Value }
                [void]$sb.Append("<td>$(HtmlEncode $s)</td>")
            }
            [void]$sb.Append('</tr>')
        }
        [void]$sb.Append('</tbody></table></div>')
        $tableHtml = $sb.ToString()
    }

    $capNote = if ($truncated) { "<br><b>This page shows the first $MaxRows of $count rows.</b> Download the CSV or TXT file for every row." } else { '' }
    $notesHtml = if ($Notes.Count -gt 0) { "<ul class='raw-notes'>" + (($Notes | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join '') + '</ul>' } else { '' }
    $checkHtml = if ($CheckId) {
        $label = if ($CheckTitle) { "$(HtmlEncode $CheckTitle) (<span class='mono'>$(HtmlEncode $CheckId)</span>)" } else { "<span class='mono'>$(HtmlEncode $CheckId)</span>" }
        "Produced by check: <a href='../../HTML Reports/Posture-Summary.html#check-$(HtmlAttrEncode $CheckId)'>$label</a><br>"
    } else { '' }
    $dl = @()
    if ($CsvAvailable) { $dl += "<a href='$(HtmlAttrEncode $CsvName)' download>CSV</a>" }
    if ($TxtAvailable) { $dl += "<a href='$(HtmlAttrEncode $TxtName)' download>TXT</a>" }
    $dlHtml = if ($dl.Count -gt 0) { 'Download all rows: ' + ($dl -join ' &middot; ') } else { "<span class='raw-err'>The CSV and TXT files for this dataset could not be written.</span>" }
    if ($dl.Count -eq 1) { $dlHtml += " <span class='raw-err'>($(if ($CsvAvailable) { 'TXT' } else { 'CSV' }) file could not be written.)</span>" }
    $gen = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
    $toolbar = if ($count -gt 0) {
@"
  <section class="toolbar">
    <div class="toolbar-row">
      <div class="filter"><label for="rawSearch">Filter rows</label><input id="rawSearch" type="text" placeholder="Type to filter the table..."></div>
    </div>
    <div class="raw-status"><span id="rawCount" data-noun="rows">$shownCount of $shownCount rows shown</span> &middot; Click a column heading to sort.$capNote</div>
  </section>
"@
    } else { '' }
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
<div class="container raw-page">
$nav
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>$(HtmlEncode $Title)</h1>
        <div class="meta">
          Raw evidence &mdash; <b>$count</b> row(s) &middot; Generated: $(HtmlEncode $gen)<br>
          $checkHtml$dlHtml &middot; <a href="../../HTML Reports/Raw-Data.html">All datasets</a> &middot; <a href="../../HTML Reports/EntraAudit-Results.html">Audit results</a>
        </div>
        $notesHtml
        <!--EA-USEDBY-->
      </div>
      <div class="hero-actions"><button type="button" class="theme-toggle" id="themeToggle">Dark mode</button></div>
    </div>
  </section>
$toolbar
  $tableHtml
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Get-EntraMainCss {
@'
<style>
:root{
  --bg:#f5f7fb;--panel:#ffffff;--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;
  --shadow:0 10px 24px rgba(15,23,42,.08);
  --critical:#c62828;--high:#ef6c00;--medium:#0277bd;--low:#2e7d32;--information:#6c757d;
  --critical-soft:#fdecec;--high-soft:#fff2e5;--medium-soft:#e8f4fd;--low-soft:#edf8ee;--information-soft:#f2f4f6;
  --result-panel:#ffffff;--accent:#3b82f6;--accent-soft:#dbeafe;--accent-text:#1e40af;
}
body[data-theme="dark"]{
  --bg:#0f172a;--panel:#111827;--text:#e5e7eb;--muted:#94a3b8;--line:#334155;
  --shadow:0 10px 24px rgba(0,0,0,.35);
  --critical:#f87171;--high:#fb923c;--medium:#60a5fa;--low:#4ade80;--information:#cbd5e1;
  --critical-soft:rgba(248,113,113,.15);--high-soft:rgba(251,146,60,.14);--medium-soft:rgba(96,165,250,.14);
  --low-soft:rgba(74,222,128,.14);--information-soft:rgba(203,213,225,.12);--result-panel:#0b1220;
  --accent-soft:rgba(59,130,246,.22);--accent-text:#bfdbfe;
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
.result-scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel);}
.result-table{width:100%;border-collapse:collapse;font-size:13px;}
.result-table th,.result-table td{border-bottom:1px solid var(--line);padding:10px 12px;vertical-align:top;text-align:left;overflow-wrap:break-word;}
.result-table th{position:sticky;top:0;background:#eef2f7;z-index:1;}
body[data-theme="dark"] .result-table th{background:#0b1220}
.result-table td.nw{white-space:nowrap}
.result-block tr.extra{display:none}
.result-block.show-all tr.extra{display:table-row}
.result-empty{color:var(--muted);line-height:1.5}
.status-table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.status-table th,.status-table td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;font-size:14px}
.status-table th{color:var(--muted);text-transform:uppercase;font-size:12px;letter-spacing:.06em}
.pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:800;border:1px solid var(--line)}
.pill.ok{background:var(--low-soft);color:var(--low)}
.pill.info{background:var(--information-soft);color:var(--information)}
.pill.find{background:var(--high-soft);color:var(--high)}
.pill.skip{background:var(--information-soft);color:var(--information)}
.pill.err{background:var(--critical-soft);color:var(--critical)}
.pill.none{background:transparent;color:var(--muted);border-style:dashed}
/* Results page: coverage, grouping, filters, print */
.risk-line{margin-top:6px;font-size:15px;color:var(--text)}
.risk-line .band{font-weight:800}
.callout{border:1px solid var(--line);border-left:6px solid var(--accent);border-radius:14px;padding:14px 16px;background:var(--panel);margin-top:18px;line-height:1.55;box-shadow:var(--shadow)}
.callout.warn{border-left-color:var(--high);background:var(--high-soft)}
.callout.ok{border-left-color:var(--low);background:var(--low-soft)}
.callout b{color:var(--text)}
button.metric{font:inherit;color:inherit;text-align:left;cursor:pointer;width:100%}
button.metric:hover{transform:translateY(-1px)}
.metric.active{outline:3px solid var(--accent);outline-offset:1px}
.metric.gap{background:var(--information-soft);border-style:dashed}
.metric-sub{font-size:12px;color:var(--muted);margin-top:4px}
.metrics-caption{margin:18px 0 0;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
.metrics.small{margin-top:8px;grid-template-columns:repeat(auto-fit,minmax(118px,1fr))}
.metrics.small .metric{padding:10px 12px}
.metrics.small .metric-value{font-size:22px;margin-top:2px}
.metrics.small a.metric,body[data-theme="dark"] .metrics.small a.metric{color:var(--text);text-decoration:none}
.metric.warn{background:var(--high-soft)}
.metric.bad{background:var(--critical-soft)}
.badge.gap{background:var(--information-soft);color:var(--information);border:1px dashed var(--information)}
.finding.coverage-gap{border-left-style:dashed;border-left-color:var(--information)}
.finding.coverage-gap>summary{background:repeating-linear-gradient(135deg,transparent 0 14px,var(--information-soft) 14px 16px)}
.count-pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:800;background:var(--accent-soft);color:var(--accent-text);border:1px solid rgba(59,130,246,.3)}
.category.check{font-size:11px}
.finding-summary{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.finding[open] .finding-summary{display:none}
.finding{scroll-margin-top:16px}
.finding-meta{font-size:12px;color:var(--muted);margin:0 0 12px;line-height:1.8;overflow-wrap:anywhere}
.finding-meta b{color:var(--text)}
.finding-meta code,.howto code{font-family:Consolas,Menlo,Monaco,monospace;background:var(--information-soft);border-radius:6px;padding:1px 6px}
.panel p{overflow-wrap:break-word}
.panel p+p{margin-top:8px}
.doc-link{margin-top:10px;font-size:13px;overflow-wrap:anywhere}
.doc-link .doc-url{display:none}
.members-table td:first-child{color:var(--muted);width:1%}
.members-table td:nth-child(2){min-width:150px}
.members-table td.oid{font-size:12px;color:var(--muted)}
.members-table td:last-child{min-width:300px}
.filter-note{display:none;font-size:13px;color:var(--accent-text);background:var(--accent-soft);border-radius:8px;padding:6px 10px;margin:0 0 8px}
.finding.rows-filtered .filter-note{display:block}
.finding.rows-filtered tr[data-search]{display:none}
.finding.rows-filtered tr[data-search].row-match{display:table-row}
.finding.rows-filtered .show-more{display:none}
.result-table tr.row-target td{background:var(--accent-soft)}
.result-table tr.row-hit td{background:var(--accent-soft)}
.hits-note{display:none;font-size:13px;color:var(--accent-text);background:var(--accent-soft);border-radius:8px;padding:6px 10px;margin:0 0 8px}
.finding.reveal-hits .result-rows .hits-note{display:block}
.finding.reveal-hits .result-rows tbody tr{display:none}
.finding.reveal-hits .result-rows tbody tr.row-hit{display:table-row}
.finding.reveal-hits .result-rows .show-more{display:none}
.show-more,.btn{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:10px;padding:8px 12px;font-size:13px;font-weight:700;cursor:pointer}
.show-more{margin-top:8px}
.show-more:hover,.btn:hover{border-color:var(--accent)}
.sub-details{margin-top:12px;border:1px solid var(--line);border-radius:12px;padding:10px 14px;background:#f8fafc}
body[data-theme="dark"] .sub-details{background:var(--result-panel)}
.sub-details>summary{cursor:pointer;font-weight:700;font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:0;display:list-item;list-style:disclosure-closed inside}
.sub-details[open]>summary{margin-bottom:10px;list-style-type:disclosure-open}
.toolbar-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px}
.visible-count{margin-left:auto;color:var(--muted);font-size:13px;font-weight:700}
.howto,.checks{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:16px 18px;margin-bottom:18px}
.howto>summary,.checks>summary{cursor:pointer;font-weight:800;font-size:18px}
.howto ul{margin:10px 0 0;padding-left:18px;line-height:1.6}
.howto li{margin:6px 0}
.checks .status-table{margin-top:12px}
.checks .status-table td{vertical-align:top}
.checks .status-table tr:target td,.checks .status-table tr.row-target td{background:var(--accent-soft)}
.check-reason{color:var(--muted);font-size:13px;line-height:1.5}
.check-error{font-size:12px;color:var(--critical);margin-top:4px;overflow-wrap:anywhere}
.idx-check{display:block;font-size:11px;color:var(--muted)}
.print-only{display:none}
@media (max-width: 980px){.layout{grid-template-columns:1fr}.sidebar{position:static}.hero-actions{align-items:flex-start}}
@media print{
  body,body[data-theme="dark"]{--bg:#fff;--panel:#fff;--text:#111;--muted:#444;--line:#ccc;--result-panel:#fff;--shadow:none;--accent-soft:#e8f0fe;--accent-text:#1e40af;background:#fff;color:#111}
  .sidebar,.toolbar,.theme-toggle,.show-more,.no-print{display:none!important}
  .container{max-width:none;padding:0}
  .layout{display:block;margin-top:12px}
  .hero,.priority,.finding,.howto,.checks,.callout{box-shadow:none}
  .finding summary{cursor:auto}
  .finding[open] .finding-summary{display:none}
  .panel,.metric,.priority li,.result-table tr{break-inside:avoid}
  .finding summary{break-after:avoid}
  .result-block tr.extra{display:table-row}
  .result-scroll{overflow:visible}
  .doc-link .doc-url{display:inline;color:#444}
  .print-only{display:block}
}
</style>
'@
}

function Get-EntraMainJs {
@'
<script>
(function(){
  function q(s){return document.querySelector(s);}
  function qa(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s));}
  function findings(){return qa('.finding');}
  function osPrefersDark(){return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);}
  function currentTheme(){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(_){}if(s==='light'||s==='dark')return s;return osPrefersDark()?'dark':'light';}
  function applyTheme(t){document.body.setAttribute('data-theme',t);var b=q('#themeToggle');if(b){b.innerText=t==='dark'?'Light mode':'Dark mode';}try{localStorage.setItem('entraaudit-theme',t);}catch(e){}}
  var b=q('#themeToggle');if(b){b.addEventListener('click',function(){var n=document.body.getAttribute('data-theme')==='dark'?'light':'dark';applyTheme(n);});}
  applyTheme(currentTheme());
  if(window.matchMedia){var mq=window.matchMedia('(prefers-color-scheme: dark)');var h=function(e){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(_){}if(s!=='light'&&s!=='dark')applyTheme(e.matches?'dark':'light');};if(mq.addEventListener)mq.addEventListener('change',h);else if(mq.addListener)mq.addListener(h);}
  var sf=q('#severityFilter'),cf=q('#categoryFilter'),kf=q('#checkFilter'),se=q('#searchFilter');
  function val(el){return el?el.value:'All';}
  // Search text: lower case, whitespace collapsed (data-search attributes are built the same way).
  function norm(s){return (s||'').toLowerCase().replace(/\s+/g,' ');}
  // The pre-built data-search text also matches content inside closed cards. It is capped,
  // so a card also matches on any affected-object row (own index + cell text) and on the
  // rendered data in its body (evidence, result tables); headings and buttons are not searched.
  function hay(el){return el.getAttribute('data-search')||norm(el.textContent);}
  function cached(el,k,fn){k='__search_'+k;if(el[k]===undefined)el[k]=fn();return el[k];}
  function cellText(tr){return cached(tr,'cells',function(){var member=tr.hasAttribute('data-search');return norm(qa('td',tr).filter(function(td,i){return !(member&&i===0);}).map(function(td){return td.textContent;}).join(' '));});}
  function memberRows(it){return qa('tr[data-search]',it);}
  function resultRows(it){return qa('.result-rows tbody tr',it);}
  function rowHit(r,query){return hay(r).indexOf(query)>=0||cellText(r).indexOf(query)>=0;}
  function bodyText(it){return cached(it,'body',function(){return norm(qa('.finding-body .panel p,.finding-body .doc-url,.finding-body .mono',it).map(function(e){return e.textContent;}).join(' '));});}
  function cardHit(it,query){return !query||hay(it).indexOf(query)>=0||memberRows(it).some(function(r){return rowHit(r,query);})||resultRows(it).some(function(r){return cellText(r).indexOf(query)>=0;})||bodyText(it).indexOf(query)>=0;}
  function sevMatch(it,sev){var s=it.getAttribute('data-sev');var gap=it.getAttribute('data-gap')==='1';if(sev==='All')return true;if(sev==='Gap')return gap;if(gap)return false;if(sev==='Risk')return s!=='Information';return s===sev;}
  function filterRows(it,query){var rows=memberRows(it);if(!rows.length)return;var m=rows.map(function(r){return !!query&&rowHit(r,query);});var on=m.indexOf(true)>=0;it.classList.toggle('rows-filtered',on);rows.forEach(function(r,i){r.classList.toggle('row-match',on&&m[i]);});}
  // Result rows holding the search text are highlighted. When the visible summary and the
  // affected-objects table do not explain the match (reveal), the result table shows only
  // the matching rows (with a note) and a closed "Result details" section is opened. Undone
  // when the search changes or is cleared, unless the reader opened or closed it by hand.
  function revealHits(it,query,reveal){
    var any=false;resultRows(it).forEach(function(r){var h=!!query&&cellText(r).indexOf(query)>=0;r.classList.toggle('row-hit',h);if(h)any=true;});
    reveal=!!(reveal&&any);it.classList.toggle('reveal-hits',reveal);
    qa('.sub-details',it).forEach(function(d){var want=reveal&&!!d.querySelector('tr.row-hit');if(want&&!d.open){d.open=true;d.setAttribute('data-auto-open','1');}else if(!want&&d.getAttribute('data-auto-open')==='1'){d.open=false;d.removeAttribute('data-auto-open');}});
  }
  function isShown(el){while(el&&el!==document.body){if(el.style&&el.style.display==='none')return false;el=el.parentElement;}return true;}
  function applyFilters(){
    var sev=val(sf),cat=val(cf),chk=val(kf),query=norm((se&&se.value)||'').trim();
    var active=sev!=='All'||cat!=='All'||chk!=='All'||!!query;var cards=0,items=0,allCards=0,allItems=0;
    findings().forEach(function(it){
      var n=parseInt(it.getAttribute('data-count')||'1',10)||1;allCards++;allItems+=n;
      var show=sevMatch(it,sev)&&(cat==='All'||it.getAttribute('data-category')===cat)&&(chk==='All'||it.getAttribute('data-check')===chk)&&cardHit(it,query);
      it.style.display=show?'':'none';if(show){cards++;items+=n;}
      var hit=show&&!!query;
      filterRows(it,hit?query:'');
      var sm=it.querySelector('summary');var inSummary=hit&&!!sm&&norm(sm.textContent).indexOf(query)>=0;var memberHit=it.classList.contains('rows-filtered');
      revealHits(it,hit?query:'',hit&&!inSummary&&!memberHit);
      if(hit){if((!inSummary||memberHit)&&!it.open){it.open=true;it.setAttribute('data-auto-open','1');}}
      else if(it.getAttribute('data-auto-open')==='1'){it.open=false;it.removeAttribute('data-auto-open');}
    });
    qa('.severity-section').forEach(function(sec){var cs=qa('.finding',sec);var n=cs.filter(function(c){return c.style.display!=='none';}).length;var sc=sec.querySelector('.section-count');if(sc){if(!sc.hasAttribute('data-base'))sc.setAttribute('data-base',sc.textContent);sc.textContent=active?(n+' of '+cs.length+' shown'):sc.getAttribute('data-base');}sec.style.display=(active&&n===0)?'none':'';});
    var vc=q('#visibleFindings');if(vc)vc.textContent=active?('Showing '+cards+' of '+allCards+' cards ('+items+' of '+allItems+' findings)'):('Showing all '+allCards+' cards ('+allItems+' findings)');
    var nr=q('#noResults');if(nr)nr.style.display=(active&&cards===0)?'':'none';
    var pn=q('#printFilterNote');if(pn){var parts=[];if(sev!=='All')parts.push('severity = '+(sf.options[sf.selectedIndex]||{}).text);if(chk!=='All')parts.push('check = '+chk);if(cat!=='All')parts.push('category = '+cat);if(query)parts.push('search = "'+query+'"');pn.textContent=parts.length?('Printed with filters applied: '+parts.join(', ')+'. Some findings are not shown.'):'';}
    qa('.metric[data-sev-filter]').forEach(function(m){if(active&&m.getAttribute('data-sev-filter')===sev)m.classList.add('active');else m.classList.remove('active');});
  }
  function resetFilters(){if(sf)sf.value='All';if(cf)cf.value='All';if(kf)kf.value='All';if(se)se.value='';applyFilters();}
  function setOption(sel,v){if(!sel||v===null||v===undefined)return false;for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===v){sel.value=v;return true;}}return false;}
  if(sf)sf.addEventListener('change',applyFilters);
  if(cf)cf.addEventListener('change',applyFilters);
  if(kf)kf.addEventListener('change',applyFilters);
  if(se)se.addEventListener('input',applyFilters);
  var rs=q('#resetFilters');if(rs)rs.addEventListener('click',resetFilters);
  function visibleCards(){return findings().filter(function(d){return d.style.display!=='none';});}
  // A card or "Result details" section the reader opens or closes by hand stays that way when the search is cleared.
  document.addEventListener('click',function(e){var s=e.target&&e.target.closest?e.target.closest('summary'):null;if(s&&s.parentNode&&s.parentNode.removeAttribute)s.parentNode.removeAttribute('data-auto-open');},true);
  var ea=q('#expandAll');if(ea)ea.addEventListener('click',function(){visibleCards().forEach(function(d){d.open=true;d.removeAttribute('data-auto-open');});});
  var ca=q('#collapseAll');if(ca)ca.addEventListener('click',function(){visibleCards().forEach(function(d){d.open=false;d.removeAttribute('data-auto-open');});});
  qa('.metric[data-sev-filter]').forEach(function(m){m.addEventListener('click',function(){var v=m.getAttribute('data-sev-filter');if(!sf)return;sf.value=(sf.value===v)?'All':v;applyFilters();var t=q('#findings-start');if(t)t.scrollIntoView({block:'start'});});});
  qa('[data-filter-check]').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();resetFilters();setOption(kf,a.getAttribute('data-filter-check'));applyFilters();var t=q('#findings-start');if(t)t.scrollIntoView({block:'start'});});});
  qa('.show-more').forEach(function(btn){btn.addEventListener('click',function(){var blk=btn.closest('.result-block');if(!blk)return;var on=!blk.classList.contains('show-all');if(on)blk.classList.add('show-all');else blk.classList.remove('show-all');btn.textContent=on?btn.getAttribute('data-less'):btn.getAttribute('data-more');});});
  // Deep links: open the target card (and a grouped card's row), clearing filters that hide it.
  function openTarget(){var id='';try{id=decodeURIComponent((location.hash||'').slice(1));}catch(e){id=(location.hash||'').slice(1);}if(!id)return;var t=document.getElementById(id);if(!t)return;
    if(!isShown(t))resetFilters();
    var p=t;while(p&&p!==document.body){if(p.tagName==='DETAILS')p.open=true;p=p.parentElement;}
    qa('.row-target').forEach(function(r){r.classList.remove('row-target');});
    if(t.tagName==='TR'){var blk=t.closest('.result-block');if(blk){blk.classList.add('show-all');var btn=blk.querySelector('.show-more');if(btn)btn.textContent=btn.getAttribute('data-less');}t.classList.add('row-target');}
    setTimeout(function(){t.scrollIntoView({block:(t.tagName==='TR'?'center':'start')});},0);}
  window.addEventListener('hashchange',openTarget);
  document.addEventListener('click',function(e){var a=e.target&&e.target.closest?e.target.closest('a[href^="#"]'):null;if(!a||a.hasAttribute('data-filter-check'))return;var id=a.getAttribute('href').slice(1);if(id&&('#'+id)===location.hash){e.preventDefault();openTarget();}});
  // Printing: expand every visible card and show all table rows, then restore.
  var printState=null;
  window.addEventListener('beforeprint',function(){printState={cards:findings().map(function(d){return d.open;}),subs:qa('.sub-details').map(function(d){return d.open;})};visibleCards().forEach(function(d){d.open=true;});qa('.sub-details').forEach(function(d){d.open=true;});});
  window.addEventListener('afterprint',function(){if(!printState)return;var s=printState;printState=null;findings().forEach(function(d,i){d.open=!!s.cards[i];});qa('.sub-details').forEach(function(d,i){d.open=!!s.subs[i];});});
  // URL parameters (?check=<id>&sev=<severity>&q=<text>) preselect the filters.
  try{var ps=new URLSearchParams(location.search);setOption(kf,ps.get('check'));setOption(sf,ps.get('sev'));if(se&&ps.get('q'))se.value=ps.get('q');}catch(e){}
  applyFilters();
  openTarget();
})();
</script>
'@
}

function Get-EntraRiskCss {
@'
<style>
:root{--bg:#f5f7fb;--bg-glow1:rgba(105,177,255,.10);--bg-glow2:rgba(255,169,64,.10);--panel:#ffffff;--panel-soft:rgba(15,23,42,.04);--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;--shadow:0 10px 24px rgba(15,23,42,.08);--radius:14px;--critical-bg:#fdecec;--critical-text:#c62828;--high-bg:#fff2e5;--high-text:#ef6c00;--medium-bg:#e8f4fd;--medium-text:#0277bd;--low-bg:#edf8ee;--low-text:#2e7d32;--info-bg:#f2f4f6;--info-text:#6c757d;--link:#0f5cb8;--pre-bg:#f8fafc;--pre-text:#1b2430;--accent:#3b82f6;--accent-soft:#dbeafe;}
@media (prefers-color-scheme: dark){:root{--bg:#0b1220;--bg-glow1:rgba(105,177,255,.18);--bg-glow2:rgba(255,169,64,.16);--panel:#111827;--panel-soft:rgba(255,255,255,.06);--text:#e8edf6;--muted:#b7c0d6;--line:rgba(255,255,255,.10);--shadow:0 10px 30px rgba(0,0,0,.35);--critical-bg:rgba(255,77,79,.18);--critical-text:#fecaca;--high-bg:rgba(255,169,64,.18);--high-text:#fed7aa;--medium-bg:rgba(105,177,255,.18);--medium-text:#bfdbfe;--low-bg:rgba(149,222,100,.18);--low-text:#bbf7d0;--info-bg:rgba(160,160,160,.18);--info-text:#e2e8f0;--link:#cfe1ff;--pre-bg:rgba(0,0,0,.25);--pre-text:#dbe6ff;--accent-soft:rgba(59,130,246,.22);}}
html[data-theme="light"]{--bg:#f5f7fb;--panel:#ffffff;--panel-soft:rgba(15,23,42,.04);--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;--shadow:0 10px 24px rgba(15,23,42,.08);--critical-bg:#fdecec;--critical-text:#c62828;--high-bg:#fff2e5;--high-text:#ef6c00;--medium-bg:#e8f4fd;--medium-text:#0277bd;--low-bg:#edf8ee;--low-text:#2e7d32;--info-bg:#f2f4f6;--info-text:#6c757d;--link:#0f5cb8;--pre-bg:#f8fafc;--pre-text:#1b2430;--accent-soft:#dbeafe;}
html[data-theme="dark"]{--bg:#0b1220;--panel:#111827;--panel-soft:rgba(255,255,255,.06);--text:#e8edf6;--muted:#b7c0d6;--line:rgba(255,255,255,.10);--shadow:0 10px 30px rgba(0,0,0,.35);--critical-bg:rgba(255,77,79,.18);--critical-text:#fecaca;--high-bg:rgba(255,169,64,.18);--high-text:#fed7aa;--medium-bg:rgba(105,177,255,.18);--medium-text:#bfdbfe;--low-bg:rgba(149,222,100,.18);--low-text:#bbf7d0;--info-bg:rgba(160,160,160,.18);--info-text:#e2e8f0;--link:#cfe1ff;--pre-bg:rgba(0,0,0,.25);--pre-text:#dbe6ff;--accent-soft:rgba(59,130,246,.22);}
*{box-sizing:border-box}
body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:radial-gradient(1200px 700px at 20% 10%,var(--bg-glow1),transparent 60%),radial-gradient(1200px 700px at 80% 0%,var(--bg-glow2),transparent 55%),var(--bg);color:var(--text);}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
.container{max-width:1200px;margin:0 auto;padding:28px 20px 60px}
.header{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:22px 22px 18px;}
.h-title{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;flex-wrap:wrap}
.h-main{flex:1 1 520px;min-width:0}
.h-side{flex:0 0 auto;margin-left:auto;display:flex;flex-direction:column;align-items:flex-end;gap:10px}
h1{font-size:22px;margin:0 0 6px;letter-spacing:.2px}
.meta{color:var(--muted);font-size:13px;line-height:1.5}
.theme-toggle{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:999px;padding:8px 14px;font-size:13px;font-weight:700;cursor:pointer;margin-bottom:10px;}
.theme-toggle:hover{filter:brightness(1.05)}
.badge{display:inline-flex;align-items:center;gap:10px;padding:10px 12px;border-radius:999px;border:1px solid var(--line);background:var(--panel-soft);font-weight:700;}
.badge .grade{font-size:13px;color:var(--muted);font-weight:600}
.badge .value{font-size:15px}
.badge.Critical{background:var(--critical-bg);color:var(--critical-text)}
.badge.High{background:var(--high-bg);color:var(--high-text)}
.badge.Medium{background:var(--medium-bg);color:var(--medium-text)}
.badge.Low{background:var(--low-bg);color:var(--low-text)}
.badge.Information{background:var(--info-bg);color:var(--info-text);border-style:dashed}
.badge-note{font-size:12px;color:var(--muted);text-align:right;max-width:340px;line-height:1.4}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin-top:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:14px 14px 12px;min-height:88px;}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em}
.card .v{font-size:22px;font-weight:800;margin-top:6px}
.card .s{margin-top:4px;color:var(--muted);font-size:12px;line-height:1.4}
.card.warn{border-color:var(--high-text);background:var(--high-bg)}
.card.warn .k,.card.warn .s{color:var(--text)}
.span-2{grid-column:span 2}.span-3{grid-column:span 3}.span-4{grid-column:span 4}.span-6{grid-column:span 6}.span-12{grid-column:span 12}
@media (max-width:900px){.grid>.card{grid-column:span 6}}
@media (max-width:520px){.grid>.card{grid-column:span 12}}
.pill{display:inline-flex;align-items:center;justify-content:center;padding:4px 10px;border-radius:999px;font-weight:800;font-size:12px;border:1px solid var(--line);min-width:86px;}
.pill.mini{min-width:0;padding:2px 8px;font-size:11px;margin:1px 3px 1px 0;white-space:nowrap}
.pill.ok{background:var(--low-bg);color:var(--low-text)}
.pill.info{background:var(--info-bg);color:var(--info-text)}
.pill.find{background:var(--high-bg);color:var(--high-text)}
.pill.skip{background:var(--info-bg);color:var(--info-text)}
.pill.err{background:var(--critical-bg);color:var(--critical-text)}
.pill.gap{background:var(--info-bg);color:var(--info-text);border-style:dashed}
.pill.notrun{background:transparent;color:var(--muted);border-style:dotted}
.sev-Critical{background:var(--critical-bg);color:var(--critical-text)}
.sev-High{background:var(--high-bg);color:var(--high-text)}
.sev-Medium{background:var(--medium-bg);color:var(--medium-text)}
.sev-Low{background:var(--low-bg);color:var(--low-text)}
.sev-Information{background:var(--info-bg);color:var(--info-text)}
.section{margin-top:18px}.section h2{margin:0 0 10px;font-size:16px}
.section-lead{margin:-4px 0 10px;color:var(--muted);font-size:13px;line-height:1.5}
.callout{border:1px solid var(--line);border-radius:var(--radius);padding:14px;background:var(--panel)}
.callout p{margin:0;line-height:1.5}.callout p+p{margin-top:8px}.callout ul{margin:10px 0 0 18px}.callout li{margin:6px 0}
.callout ol{margin:8px 0 0 20px;padding:0}.callout ol li{margin:6px 0;line-height:1.45}
.callout.warn{border-left:5px solid var(--high-text)}
.callout.ok{border-left:5px solid var(--low-text)}
.callout h3{margin:14px 0 4px;font-size:14px}
.summary-lead{font-size:15px}
.risk-list{list-style:none;margin:0 !important;padding:0}
.risk-list li{display:flex;gap:10px;align-items:flex-start;padding:9px 0;border-bottom:1px solid var(--line);margin:0 !important}
.risk-list li:last-child{border-bottom:0}
.risk-list .pill{flex:0 0 auto}
.li-sub{display:block;color:var(--muted);font-size:12px;margin-top:2px;line-height:1.4}
.muted{color:var(--muted)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin:10px 0}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
select,input{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:8px 10px;outline:none;}
input{min-width:240px}
small{color:var(--muted)}
table{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;background:var(--panel)}
th,td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em;background:var(--panel-soft);text-align:left}
th[data-sort]{cursor:pointer;user-select:none}
tr:hover td{background:var(--panel-soft)}
tr:target td{background:var(--accent-soft)}
#checkTable td{font-size:14px;line-height:1.45}
#checkTable th:nth-child(1){width:21%}#checkTable th:nth-child(2){width:15%}#checkTable th:nth-child(3){width:13%}#checkTable th:nth-child(4){width:32%}#checkTable th:nth-child(5){width:19%}
td.title{font-weight:700}
td .sub{display:block;color:var(--muted);font-size:12px;margin-top:3px;font-weight:400}
td.num{text-align:right;white-space:nowrap}
table.kv th{width:230px;text-align:left;text-transform:none;letter-spacing:0;font-size:13px;color:var(--muted);font-weight:600}
table.kv td{font-size:13px;line-height:1.5}
.chip{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:1px 6px;margin:2px 4px 2px 0;font-size:12px;background:var(--panel-soft)}
.status-code{display:block;font-size:11px;color:var(--muted);margin-top:4px}
.err-msg{display:block;font-size:12px;color:var(--muted);margin-top:4px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;overflow-wrap:anywhere}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
td.source .mono{font-size:12px;color:var(--link)}
details.more>summary{cursor:pointer;color:var(--link);margin:10px 0;font-weight:600}
details.all-findings>summary{cursor:pointer;font-size:16px;font-weight:700;margin:0 0 10px}
details.all-findings>summary small{font-weight:400}
.footer{margin-top:16px;color:var(--muted);font-size:12px;line-height:1.5}
.matrix-wrap{margin-top:10px}
table.matrix{table-layout:fixed;}
table.matrix th,table.matrix td{padding:14px 18px;}
table.matrix th{cursor:default;}
table.matrix th:nth-child(1),table.matrix td:nth-child(1){width:22%;padding-left:22px;}
table.matrix th:nth-child(2),table.matrix td:nth-child(2){width:16%;text-align:center;}
table.matrix th:nth-child(3),table.matrix td:nth-child(3){width:62%;padding-left:22px;}
.matrix-row.active td{background:var(--panel-soft);font-weight:600}
@media (max-width:700px){table{display:block;overflow-x:auto}}
</style>
'@
}

# Risk Report script: theme toggle, and the (collapsed) all-findings table's severity
# filter - including a "Not assessed" option for coverage-gap findings - search and sort.
# Every element lookup is null-safe so a page without the table cannot throw.
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
  var sf=q('#sevFilter'),se=q('#search'),vc=q('#visibleCount');
  function applyFilters(){var sev=sf?sf.value:'All';var s=((se&&se.value)||'').toLowerCase().trim();var visible=0;rows().forEach(function(r){var rs=r.getAttribute('data-sev');var gap=r.getAttribute('data-gap')==='1';var okSev=(sev==='All')||(sev==='Not assessed'?gap:rs===sev);var text=(r.textContent||'').toLowerCase();var show=okSev&&((!s)||(text.indexOf(s)>=0));r.style.display=show?'':'none';if(show)visible++;});if(vc)vc.innerText=visible;}
  var sortCol=null,sortAsc=false;var order=['Critical','High','Medium','Low','Information'];
  function sortBy(col){var tbody=q('#findings-body');if(!tbody)return;sortAsc=(sortCol===col)?!sortAsc:true;sortCol=col;var arr=rows().slice().sort(function(a,b){var ka,kb;if(col==='severity'){ka=order.indexOf(a.getAttribute('data-sev'));kb=order.indexOf(b.getAttribute('data-sev'));}else if(col==='title'){ka=((a.querySelector('.title')||{}).textContent||'').toLowerCase();kb=((b.querySelector('.title')||{}).textContent||'').toLowerCase();}else{ka=a.textContent;kb=b.textContent;}if(ka<kb)return sortAsc?-1:1;if(ka>kb)return sortAsc?1:-1;return 0;});arr.forEach(function(r){tbody.appendChild(r);});applyFilters();}
  if(sf)sf.addEventListener('change',applyFilters);
  if(se)se.addEventListener('input',applyFilters);
  qa('th[data-sort]').forEach(function(th){th.addEventListener('click',function(){sortBy(th.getAttribute('data-sort'));});});
  applyFilters();sortBy('severity');
})();
</script>
'@
}

$script:RiskPoints = @{ Critical = 25; High = 10; Medium = 4; Low = 1; Information = 0 }

# Risk bands, worst-first. Defined ONCE and used for both the band computation and the
# matrix rendered in the Risk Report, so code and report can never drift apart.
# The Meaning texts are written for a non-specialist reader.
$script:RiskBands = @(
    [pscustomobject]@{ Level='Critical'; Min=150; Meaning='Serious weaknesses in several areas. Treat the fixes as a priority project with named owners and deadlines.' }
    [pscustomobject]@{ Level='High';     Min=60;  Meaning='Significant weaknesses. Fix them promptly and give each one an owner.' }
    [pscustomobject]@{ Level='Moderate'; Min=20;  Meaning='Real problems to fix in the next hardening cycle.' }
    [pscustomobject]@{ Level='Low';      Min=1;   Meaning='Minor problems; fix them during routine maintenance.' }
    [pscustomobject]@{ Level='Clean';    Min=0;   Meaning='No problems found, and every selected check ran and read all of its data. Keep monitoring.' }
)

# Score-0 labels used instead of 'Clean' when the audit did not see everything, so an
# unknown is never presented as clean (see Get-EntraRiskScore). Rendered as extra rows of
# the band matrix; they are not thresholds.
$script:RiskCoverageBands = @(
    [pscustomobject]@{ Level='Not fully assessed'; Meaning='No problems were found in the data that could be read, but some checks were skipped, stopped with an error or could not read all of their data. This is NOT a clean result.' }
    [pscustomobject]@{ Level='Not assessed';       Meaning='None of the selected checks gave a result (all were skipped or stopped with an error). Nothing can be concluded about the tenant.' }
)

# The "same issue" key shared by risk scoring and report grouping: (check, rule, severity).
# Rule = explicit RuleId when set; otherwise the digit-stripped title slug. PER-OBJECT
# findings title as "issue: object" - the object suffix is stripped so 28 permanent Global
# Admins share ONE issue instead of becoming 28 single-object issues.
# (Grouping/scoring only - the stable trend ids in New-FindingKey keep the full rule.)
function Get-EntraIssueKey([object]$f) {
    $sev = Normalize-Severity $f.Severity
    $issueTitle = [string]$f.Title
    if (($f.AffectedPrincipal -or $f.ObjectId) -and $issueTitle.Contains(':')) { $issueTitle = (($issueTitle -split ':', 2)[0]).Trim() }
    $rule = if ($f.RuleId) { [string]$f.RuleId } else { (($issueTitle -replace '\d+','') -replace '[^A-Za-z]+','-').Trim('-').ToLowerInvariant() }
    [pscustomobject]@{ Key = ('{0}|{1}|{2}' -f [string]$f.CheckId, $rule, $sev); Rule = $rule; Severity = $sev; IssueTitle = $issueTitle }
}

# Classifies every check for the executive pages from $script:CheckStatus (what actually
# ran), $script:RunInfo.SelectedChecks (what the operator selected) and $script:Registry
# (everything the tool can do). Checks that were not selected have no CheckStatus entry
# and are reported as 'Not run' - never as clean. One row per registry check (plus any
# unknown CheckStatus key), with a plain-language Label and Reason; Reason falls back to
# a derived sentence when the CheckStatus entry has none (older callers / offline tests).
# Group: clean | findings | incomplete | skipped | error | noresult | notrun.
function Get-EntraRunCoverage {
    param(
        [System.Collections.IDictionary]$CheckStatus = $script:CheckStatus,
        [object]$RunInfo = $script:RunInfo,
        [System.Collections.IDictionary]$Registry = $script:Registry
    )
    if ($null -eq $CheckStatus) { $CheckStatus = [ordered]@{} }
    if ($null -eq $Registry) { $Registry = [ordered]@{} }
    $selected = @()
    $runSel = if ($RunInfo) { Get-EAField $RunInfo 'SelectedChecks' } else { $null }
    if ($runSel) { $selected = @($runSel | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
    foreach ($k in $CheckStatus.Keys) { if ($selected -notcontains [string]$k) { $selected += [string]$k } }

    $ids = @($Registry.Keys | ForEach-Object { [string]$_ })
    foreach ($k in $selected) { if ($ids -notcontains $k) { $ids += $k } }

    $rows = foreach ($id in $ids) {
        $reg = if ($Registry.Contains($id)) { $Registry[$id] } else { $null }
        $st = if ($CheckStatus.Contains($id)) { $CheckStatus[$id] } else { $null }
        $isSelected = $selected -contains $id
        $title = if ($st -and $st.Title) { [string]$st.Title } elseif ($reg) { [string]$reg.Title } else { $id }
        $status = if ($st) { [string]$st.Status } elseif ($isSelected) { 'NoResult' } else { 'NotRun' }
        $count = if ($st -and $null -ne $st.Count) { [int]$st.Count } else { 0 }
        $info = if ($st -and $st.PSObject.Properties['InfoCount'] -and $null -ne $st.InfoCount) { [int]$st.InfoCount } else { 0 }
        $cov = if ($st -and $st.PSObject.Properties['CoverageCount'] -and $null -ne $st.CoverageCount) { [int]$st.CoverageCount } else { 0 }
        $partial = [bool]($st -and $st.PSObject.Properties['Partial'] -and $st.Partial)
        $missing = if ($st -and $st.PSObject.Properties['MissingScopes']) { @($st.MissingScopes | Where-Object { $_ } | ForEach-Object { [string]$_ }) } else { @() }
        $err = if ($st -and $st.PSObject.Properties['ErrorMessage'] -and $st.ErrorMessage) { [string]$st.ErrorMessage } else { $null }
        $reason = if ($st -and $st.PSObject.Properties['Reason'] -and $st.Reason) { [string]$st.Reason } else { '' }
        $incomplete = $status -match 'Incomplete'
        $tier = if ($reg -and $reg.P2) { 'P2' } elseif ($reg -and $reg.P1) { 'P1' } else { 'P1/P2' }

        $group = switch -Regex ($status) {
            '^NotRun$'       { 'notrun'; break }
            '^NoResult$'     { 'noresult'; break }
            '^Error'         { 'error'; break }
            '^Skipped'       { 'skipped'; break }
            '^RiskFindings'  { 'findings'; break }
            'Incomplete'     { 'incomplete'; break }
            '^(Pass|InfoOnly)' { 'clean'; break }
            default          { 'error' }
        }
        $issues = if ($count -eq 1) { '1 issue' } else { "$count issues" }
        $label = switch ($group) {
            'notrun'     { 'Not run' }
            'noresult'   { 'No result' }
            'error'      { if ($partial) { 'Stopped part-way' } else { 'Error' } }
            'skipped'    {
                switch ($status) {
                    'Skipped-NoScope'        { 'Skipped: missing permission' }
                    'Skipped-NoPermission'   { 'Skipped: access denied' }
                    'Skipped-NoLicense'      { 'Skipped: no license' }
                    'Skipped-LicenseUnknown' { 'Skipped: license unknown' }
                    default                  { 'Skipped' }
                }
            }
            'findings'   { if ($incomplete) { "$issues found, incomplete" } else { "$issues found" } }
            'incomplete' { 'Incomplete' }
            default      { if ($info -gt 0) { 'Passed (notes only)' } else { 'Passed' } }
        }
        if (-not $reason) {
            $reason = switch ($group) {
                'notrun'     { 'Not selected for this run, so this area was not checked.' }
                'noresult'   { 'Was selected but did not record a result, so this area was not checked.' }
                'error'      { if ($err) { "Stopped with an error: $err" } else { 'Stopped with an error, so this area was not fully checked.' } }
                'skipped'    {
                    switch ($status) {
                        'Skipped-NoScope' {
                            $need = if ($missing.Count -gt 0) { $missing } elseif ($reg -and $reg.Scopes) { @($reg.Scopes) } else { @() }
                            if ($need.Count -gt 0) { "Missing permission: $($need -join ', ')." } else { 'A required permission was not granted.' }
                        }
                        'Skipped-NoPermission'   { 'Access denied by Microsoft Graph: the audit account or app lacks a permission or admin role this check needs.' }
                        'Skipped-NoLicense'      { "Needs a Microsoft Entra ID $tier license, which was not found in this tenant." }
                        'Skipped-LicenseUnknown' { "Needs a Microsoft Entra ID $tier license; the license check itself failed, so it is unknown whether the tenant has one." }
                        default                  { 'Skipped, so this area was not checked.' }
                    }
                }
                'findings'   { $verb = if ($count -eq 1) { 'needs' } else { 'need' }; if ($incomplete) { "Found $issues that $verb attention; some data could not be read, so there may be more." } else { "Found $issues that $verb attention." } }
                'incomplete' { 'No problems found in the data that could be read, but some data could not be read - this is not a clean result.' }
                default      { '' }
            }
        }
        $order = switch ($group) { 'error' { 0 } 'noresult' { 0 } 'skipped' { 1 } 'incomplete' { 2 } 'findings' { if ($incomplete) { 2 } else { 3 } } 'clean' { 4 } default { 5 } }
        [pscustomobject]@{
            CheckId = $id; Title = $title; Selected = $isSelected; Status = $status; Group = $group; Label = $label
            Reason = $reason; ErrorMessage = $err; MissingScopes = $missing
            Count = $count; InfoCount = $info; CoverageCount = $cov; Incomplete = $incomplete; Partial = $partial; SortOrder = $order
            DurationSeconds = $(if ($st -and $st.PSObject.Properties['DurationSeconds']) { $st.DurationSeconds } else { $null })
        }
    }
    $rows = @($rows)
    $sel = @($rows | Where-Object { $_.Selected })
    $clean = @($sel | Where-Object { $_.Group -eq 'clean' }).Count
    $withFindings = @($sel | Where-Object { $_.Group -eq 'findings' }).Count
    $incompleteN = @($sel | Where-Object { $_.Incomplete }).Count
    $skipped = @($sel | Where-Object { $_.Group -eq 'skipped' }).Count
    $errored = @($sel | Where-Object { $_.Group -in @('error','noresult') }).Count
    $evaluated = @($sel | Where-Object { $_.Group -in @('clean','findings','incomplete') }).Count
    [pscustomobject]@{
        Rows = $rows
        Total = $Registry.Count
        Selected = $sel.Count
        Evaluated = $evaluated                          # ran to the end (possibly with data gaps)
        FullyEvaluated = $evaluated - $incompleteN      # ran to the end and read all of its data
        Clean = $clean; WithFindings = $withFindings; Incomplete = $incompleteN
        Skipped = $skipped; Errored = $errored
        NotRun = @($rows | Where-Object { $_.Group -eq 'notrun' }).Count
        Complete = ($sel.Count -gt 0 -and ($skipped + $errored + $incompleteN) -eq 0)
    }
}

function Get-EntraRiskScore {
    param([object[]]$findings, [System.Collections.IDictionary]$CheckStatus = $script:CheckStatus)
    # ACCUMULATING risk with DIMINISHING RETURNS: higher = worse. Findings are grouped
    # into (check, RULE, severity) buckets - the same rule discriminator the stable
    # finding ids use - and each bucket contributes points * sqrt(count). So volume
    # still raises the score - 28 permanent Global Admins score well above 8
    # (sqrt 28 vs sqrt 8) - but ONE systemic issue repeated across many objects cannot
    # drown out every other signal, while DISTINCT issues inside the same check still
    # add up instead of sharing one bucket (bucketing by check alone under-counted a
    # check that surfaces several different problems at the same severity).
    # Unbounded on purpose, so magnitude stays visible.
    #
    # DESIGN CHOICE - coverage gaps DO contribute to the score. A CoverageGap finding means
    # "the audit could not read/assess this", not "the tenant is misconfigured", but a
    # check author gives it a risk-bearing severity only when the blind spot is itself
    # operationally important (e.g. unverifiable log export). Dropping those points would
    # let missing audit permissions LOWER the score. They are, however, never mixed into
    # the confirmed picture: their points are reported separately (NotAssessedPoints /
    # ConfirmedScore, NotAssessedDrivers) and every report labels them "Not assessed".
    # SCORING stays one bucket per issue key, exactly as before the gap split: a gap and a
    # confirmed finding with the same issue key (check|rule|severity) are the SAME issue
    # and share one points * sqrt(count) bucket, so the total score is unchanged by the
    # split (High confirmed + High gap, same rule = 10 x sqrt(2) = 14, not 10 + 10).
    # Only the ATTRIBUTION is split: the confirmed part scores what it would score alone
    # (points * sqrt(confirmed)) and the gap part gets the marginal rest (points *
    # (sqrt(total) - sqrt(confirmed))), so a blind spot never lowers ConfirmedScore and
    # ConfirmedScore + NotAssessedPoints = Score (up to rounding).
    # Checks that were skipped or errored add no points (there is nothing to score) -
    # instead Band never says 'Clean' while anything was skipped, errored or incomplete,
    # so an unknown is never presented as clean.
    # Critical..Information count EVERY finding (they match the Results page); the
    # ConfirmedCounts / NotAssessedCounts split them by CoverageGap.
    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0 }
    $confirmedCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0 }
    $gapCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0 }
    $buckets = [ordered]@{}
    $issueTotals = @{}   # issue key -> finding count (confirmed + gap): the scoring bucket
    foreach ($f in $findings) {
        if ($null -eq $f) { continue }
        $sev = Normalize-Severity $f.Severity
        $counts[$sev]++
        $isGap = [bool](Test-EntraCoverageGap $f)
        if ($isGap) { $gapCounts[$sev]++ } else { $confirmedCounts[$sev]++ }
        if ($sev -eq 'Information') { continue }
        # One scoring bucket per issue (see Get-EntraIssueKey): 28 permanent Global Admins
        # score 25 x sqrt(28) instead of 28 single-count buckets, which would defeat the
        # diminishing returns entirely. The confirmed and the not-assessed findings of an
        # issue are tracked as two report parts (internal key only - the published issue
        # key is unchanged) but scored together, see DESIGN CHOICE above.
        $issue = Get-EntraIssueKey $f
        $issueTotals[$issue.Key] = 1 + $(if ($issueTotals.ContainsKey($issue.Key)) { $issueTotals[$issue.Key] } else { 0 })
        $k = $issue.Key + $(if ($isGap) { '|gap' } else { '' })
        if ($buckets.Contains($k)) {
            $buckets[$k].Count++
            if ($f.AffectedPrincipal -and $buckets[$k].Principals.Count -lt 5) { $buckets[$k].Principals.Add([string]$f.AffectedPrincipal) | Out-Null }
        } else {
            $pr = New-Object System.Collections.Generic.List[string]
            if ($f.AffectedPrincipal) { $pr.Add([string]$f.AffectedPrincipal) | Out-Null }
            $buckets[$k] = @{
                Key = $issue.Key; Rule = $issue.Rule; Severity = $sev; Count = 1; CheckId = [string]$f.CheckId
                Title = $issue.IssueTitle; FirstTitle = [string]$f.Title; FirstAnchor = (New-FindingAnchor $f)
                RecommendedAction = [string]$f.RecommendedAction; WhyItMatters = [string]$f.WhyItMatters
                SourceFile = [string]$f.SourceFile; DocumentationUrl = [string]$f.DocumentationUrl
                CoverageGap = $isGap; Principals = $pr
            }
        }
    }
    $raw = 0.0; $gapRaw = 0.0
    foreach ($b in $buckets.Values) {
        # Both parts of an issue share its severity (it is part of the key), so the parts
        # add up to points * sqrt(total) - the single-bucket score.
        $unit = $script:RiskPoints[$b.Severity]
        $b.Points = if ($b.CoverageGap) {
            $issueN = [int]$issueTotals[$b.Key]
            $unit * ([math]::Sqrt($issueN) - [math]::Sqrt($issueN - $b.Count))
        } else { $unit * [math]::Sqrt($b.Count) }
        $raw += $b.Points
        if ($b.CoverageGap) { $gapRaw += $b.Points }
    }
    $drivers = foreach ($b in $buckets.Values) {
        $pts = $b.Points
        [pscustomobject]@{
            Key = $b.Key; Rule = $b.Rule; Severity = $b.Severity; CheckId = $b.CheckId; Title = $b.Title; Count = $b.Count
            Points = [math]::Round($pts, 1)
            Share = $(if ($raw -gt 0) { [int][math]::Round(100 * $pts / $raw) } else { 0 })
            CoverageGap = [bool]$b.CoverageGap
            FirstTitle = $b.FirstTitle; FirstAnchor = $b.FirstAnchor
            RecommendedAction = $b.RecommendedAction; WhyItMatters = $b.WhyItMatters
            SourceFile = $b.SourceFile; DocumentationUrl = $b.DocumentationUrl
            Principals = $b.Principals.ToArray()
        }
    }
    $drivers = @($drivers | Sort-Object @{e={$_.Points};Descending=$true}, @{e={Get-SeverityRank $_.Severity};Descending=$true}, @{e={$_.Count};Descending=$true}, Title)
    $score = [int][math]::Round($raw)
    $scoreBand = 'Clean'
    foreach ($bd in $script:RiskBands) { if ($score -ge $bd.Min) { $scoreBand = $bd.Level; break } }

    # Coverage-aware band: a zero score is only 'Clean' when every selected check ran and
    # read all of its data. Without any check status (e.g. a caller scoring a finding list
    # on its own) the coverage is unknown and the threshold band is returned unchanged.
    $coverage = if ($CheckStatus -and $CheckStatus.Count -gt 0) { Get-EntraRunCoverage -CheckStatus $CheckStatus } else { $null }
    $gapTotal = 0; foreach ($v in $gapCounts.Values) { $gapTotal += $v }
    $band = $scoreBand
    if ($scoreBand -eq 'Clean') {
        if ($coverage -and $coverage.Evaluated -eq 0) { $band = 'Not assessed' }
        elseif (($coverage -and -not $coverage.Complete) -or $gapTotal -gt 0) { $band = 'Not fully assessed' }
    }
    [pscustomobject]@{
        Score = $score; Band = $band; ScoreBand = $scoreBand
        ConfirmedScore = [int][math]::Round($raw - $gapRaw)
        NotAssessedPoints = [int][math]::Round($gapRaw)
        Critical = $counts.Critical; High = $counts.High; Medium = $counts.Medium; Low = $counts.Low; Information = $counts.Information
        ConfirmedCounts = $confirmedCounts
        NotAssessedCounts = $gapCounts
        NotAssessedFindings = $gapTotal
        CoverageComplete = $(if ($coverage) { [bool]($coverage.Complete -and $gapTotal -eq 0) } else { $gapTotal -eq 0 })
        Coverage = $coverage
        # Per-issue contributions, largest first, so the report can show WHAT drives the score.
        Drivers = $drivers
        ConfirmedDrivers = @($drivers | Where-Object { -not $_.CoverageGap })
        NotAssessedDrivers = @($drivers | Where-Object { $_.CoverageGap })
    }
}

# Higher score = worse, so map the risk band to the matching severity colour. The
# coverage labels ('Not assessed' / 'Not fully assessed') render grey, never green.
function Get-BandBadgeClass([string]$band) {
    switch ($band) { 'Clean' { 'Low' } 'Low' { 'Low' } 'Moderate' { 'Medium' } 'High' { 'High' } 'Critical' { 'Critical' } default { 'Information' } }
}

function Resolve-SourceHref([string]$src) {
    if ([string]::IsNullOrWhiteSpace($src)) { return '' }
    # Evidence paths are relative ('../Raw Data/Source/x.html'). Anything with a URI scheme
    # or a rooted path is refused so a stored value can never become a javascript: or remote
    # link; each segment is percent-encoded so spaces, '#', '%' and '?' resolve correctly.
    $s = $src.Trim() -replace '\\', '/'
    if ($s -match '^[A-Za-z][A-Za-z0-9+.\-]*:' -or $s.StartsWith('/')) { return '' }
    (@($s -split '/') | ForEach-Object { if ($_ -eq '..' -or $_ -eq '.') { $_ } else { [uri]::EscapeDataString($_) } }) -join '/'
}

function Write-EntraResultsReport {
    param([string]$Path, [object[]]$Items, [hashtable]$Counts, [string]$TenantName, [string]$GeneratedOn, [string]$Subtitle, [string]$TenantId)
    # Every parameter and finding field is treated as untrusted text and HTML-encoded where
    # it is written (tenant, principal and policy names are tenant-controlled).

    $severityOrder = @('Critical','High','Medium','Low','Information')
    $all = @($Items | Where-Object { $null -ne $_ })
    $total = $all.Count
    $runInfo = $script:RunInfo
    $ri = { param($k) if ($null -ne $runInfo) { Get-EAField $runInfo $k } else { $null } }
    if (-not $TenantId) { $TenantId = [string](& $ri 'TenantId') }
    if (-not $TenantId -and $script:Tenant -and $script:Tenant.Id) { $TenantId = [string]$script:Tenant.Id }

    # Check titles for labels and the check filter.
    $checkTitles = @{}
    if ($script:Registry -is [System.Collections.IDictionary]) { foreach ($k in $script:Registry.Keys) { $checkTitles[[string]$k] = [string]$script:Registry[$k].Title } }
    if ($script:CheckStatus -is [System.Collections.IDictionary]) { foreach ($k in $script:CheckStatus.Keys) { if (-not $checkTitles.ContainsKey([string]$k) -and $script:CheckStatus[$k].Title) { $checkTitles[[string]$k] = [string]$script:CheckStatus[$k].Title } } }

    # One entry per issue; coverage gaps separate from confirmed findings.
    $groups = @(Get-EntraResultGroup -Items $all)
    $riskGroups = @($groups | Where-Object { -not $_.CoverageGap })
    $gapGroups = @($groups | Where-Object { $_.CoverageGap } | Sort-Object @{ e = { Get-SeverityRank $_.Severity }; Descending = $true }, @{ e = { $_.Members.Count }; Descending = $true }, @{ e = { Format-EntraNaturalSortKey $_.Title } })
    $sumMembers = { param($gs) [int](@($gs | ForEach-Object { $_.Members.Count }) | Measure-Object -Sum).Sum }
    $gapCount = & $sumMembers $gapGroups
    $sevCounts = @{}; $sevIssues = @{}
    foreach ($sev in $severityOrder) {
        $gs = @($riskGroups | Where-Object { $_.Severity -eq $sev })
        $sevIssues[$sev] = $gs.Count
        $sevCounts[$sev] = & $sumMembers $gs
    }
    # Counts supplied without findings (older callers): show them rather than zeros.
    if ($null -eq $Items -and $Counts) { foreach ($sev in $severityOrder) { if ($Counts.ContainsKey($sev)) { $sevCounts[$sev] = [int]$Counts[$sev] } } }
    $riskTotal = $sevCounts.Critical + $sevCounts.High + $sevCounts.Medium + $sevCounts.Low
    $infoTotal = $sevCounts.Information

    # Check coverage: the header never says "Clean" when checks were skipped, errored or
    # only partly assessed, or when the report cannot tell which checks ran.
    $cov = Get-EntraCheckCoverage
    $score = Get-EntraRiskScore $all
    $partial = (-not $cov.IsComplete) -or ($gapCount -gt 0)
    $bandLabel = [string]$score.Band
    if ($score.Band -eq 'Clean' -and $partial) { $bandLabel = if ($cov.Known -and $cov.Ran -le 0) { 'Not assessed' } else { 'Not fully assessed' } }
    $bandClass = if ($bandLabel -eq [string]$score.Band) { Get-BandBadgeClass $score.Band } else { 'Information' }
    $riskNote = if ($partial -and $bandLabel -eq [string]$score.Band) { ' &mdash; covers only what could be checked; see <a href="#check-coverage">Check coverage</a>' }
                elseif ($partial) { ' &mdash; see <a href="#check-coverage">Check coverage</a>' } else { '' }
    $riskLine = "<div class='risk-line'>Overall risk: <span class='badge sev-$bandClass band'>$(HtmlEncode $bandLabel)</span> score $([int]$score.Score) (higher = worse)$riskNote</div>"

    $notFull = $cov.Skipped + $cov.Errored + $cov.Incomplete
    $covParts = @()
    if ($cov.Skipped) { $covParts += "$($cov.Skipped) skipped" }
    if ($cov.Errored) { $covParts += "$($cov.Errored) stopped with an error" }
    if ($cov.Incomplete) { $covParts += "$($cov.Incomplete) only partly assessed" }
    $coverageCallout = if (-not $cov.Known) {
        "<div class='callout warn'><b>Check status unknown.</b> This report did not receive the list of checks that ran, so it cannot confirm what was checked. Treat a missing finding as unknown, not as a pass. See <a href='Posture-Summary.html'>Posture Summary</a>.</div>"
    } elseif ($cov.Selected -gt 0 -and $cov.Ran -le 0) {
        "<div class='callout warn'><b>Nothing was assessed:</b> none of the $($cov.Selected) selected checks could run ($($covParts -join ', ')). This is <b>not</b> a clean result. <a href='#check-coverage'>See why each check did not run</a>.</div>"
    } elseif ($notFull -gt 0) {
        "<div class='callout warn'><b>Partial result:</b> $notFull of $($cov.Selected) selected checks did not fully run ($($covParts -join ', ')). The findings below cover only what could be read &mdash; no finding for those areas does <b>not</b> mean the controls are in place. <a href='#check-coverage'>See which checks and why</a>.</div>"
    } elseif ($gapCount -gt 0) {
        "<div class='callout warn'><b>Some areas were not assessed:</b> $gapCount item(s) could not be read or evaluated. They are listed under <a href='#section-not-assessed'>Not assessed</a> and are not counted as risk findings.</div>"
    } else {
        $notRunText = if ($cov.NotRun -gt 0) { " $($cov.NotRun) other available check(s) were not selected for this run and say nothing about the tenant." } else { '' }
        "<div class='callout ok'><b>All $($cov.Selected) selected checks completed.</b>$notRunText</div>"
    }

    # --- hero metrics ---
    $countCards = foreach ($sev in $severityOrder) {
        $issuesText = if ($sev -eq 'Information') { 'context, no action' } else { '{0} issue{1}' -f $sevIssues[$sev], $(if ($sevIssues[$sev] -eq 1) { '' } else { 's' }) }
        "<button type='button' class='metric sev-$sev' data-sev-filter='$sev' title='Show only $sev findings'><div class='metric-label'>$sev</div><div class='metric-value'>$($sevCounts[$sev])</div><div class='metric-sub'>$issuesText</div></button>"
    }
    $countCards += "<button type='button' class='metric gap' data-sev-filter='Gap' title='Show only the areas that could not be assessed'><div class='metric-label'>Not assessed</div><div class='metric-value'>$gapCount</div><div class='metric-sub'>could not be checked</div></button>"
    $covCards = if ($cov.Known) {
        $cc = @(
            @{ L = 'Checks selected'; V = $cov.Selected; C = '' }
            @{ L = 'Passed'; V = $cov.Clean; C = '' }
            @{ L = 'With findings'; V = $cov.WithFindings; C = '' }
            @{ L = 'Partly assessed'; V = $cov.Incomplete; C = $(if ($cov.Incomplete) { 'warn' } else { '' }) }
            @{ L = 'Skipped'; V = $cov.Skipped; C = $(if ($cov.Skipped) { 'warn' } else { '' }) }
            @{ L = 'Errors'; V = $cov.Errored; C = $(if ($cov.Errored) { 'bad' } else { '' }) }
        )
        if ($cov.NotRun -gt 0) { $cc += @{ L = 'Not run'; V = $cov.NotRun; C = '' } }
        "<div class='metrics-caption'>Check coverage</div><div class='metrics small'>" + (($cc | ForEach-Object { "<a class='metric $($_.C)' href='#check-coverage'><div class='metric-label'>$($_.L)</div><div class='metric-value'>$($_.V)</div></a>" }) -join '') + '</div>'
    } else { '' }

    # --- run details (RunInfo is optional) ---
    $runBits = @()
    $account = [string](& $ri 'Account'); $authMode = [string](& $ri 'AuthMode')
    if ($account -or $authMode) { $runBits += ('Signed in as: <span class="mono">{0}</span>{1}' -f (HtmlEncode $account), $(if ($authMode) { ' (' + (HtmlEncode $authMode) + ')' } else { '' })) }
    $toolVersion = [string](& $ri 'ToolVersion'); if (-not $toolVersion) { $toolVersion = [string]$script:Version }
    $dur = & $ri 'DurationSeconds'
    $durText = ''
    if ($null -ne $dur -and "$dur" -ne '') { $d = [double]$dur; $durText = if ($d -ge 60) { ' &middot; run time {0} min {1} s' -f [int][math]::Floor($d / 60), [int]($d % 60) } else { ' &middot; run time {0} s' -f [int][math]::Round($d) } }
    if ($toolVersion) { $runBits += "Tool: $(HtmlEncode $toolVersion)$durText" }
    $runHtml = if ($runBits.Count) { ($runBits -join '<br>') + '<br>' } else { '' }
    $tenantIdHtml = if ($TenantId) { " <span class='mono'>($(HtmlEncode $TenantId))</span>" } else { '' }
    # The caller's subtitle is only shown when this report has no check status of its own.
    $subtitleHtml = if (-not $cov.Known -and $Subtitle) { (HtmlEncode ([System.Net.WebUtility]::HtmlDecode($Subtitle))) + '<br>' } else { '' }

    # --- priority actions: distinct issues, not individual findings ---
    $sortIssues = { param($gs) @($gs | Sort-Object @{ e = { Get-SeverityRank $_.Severity }; Descending = $true }, @{ e = { $_.Members.Count }; Descending = $true }, @{ e = { Format-EntraNaturalSortKey $_.Title } }) }
    $prioIntro = ''
    $prioTier = 'Critical/High'
    $prioPool = & $sortIssues @($riskGroups | Where-Object { $_.Severity -in @('Critical','High') })
    if ($prioPool.Count -eq 0) {
        $prioTier = 'Medium/Low'
        $prioPool = & $sortIssues @($riskGroups | Where-Object { $_.Severity -in @('Medium','Low') })
        if ($prioPool.Count -gt 0) { $prioIntro = "<p class='result-note'>No Critical or High issues were found. The most important remaining issues:</p>" }
    }
    $prio = @($prioPool | Select-Object -First 8)
    $priorityHtml = if ($prio.Count -gt 0) {
        $li = @(foreach ($g in $prio) {
            $m0 = $g.Members[0]
            $n = $g.Members.Count
            $pill = if ($n -gt 1) { " <span class='count-pill'>$n $(if ($g.PerObject) { 'objects' } else { 'findings' })</span>" } else { '' }
            $act = Get-EntraFirstSentence ([string]$m0.RecommendedAction)
            $actHtml = if ($act) { "<span class='priority-evidence'>What to do: $(HtmlEncode $act)</span>" } else { '' }
            "<li><span class='badge sev-$($g.Severity)'>$($g.Severity)</span><a class='priority-title' href='#$(HtmlAttrEncode $g.Anchor)'>$(HtmlEncode $g.Title)</a>$pill$actHtml</li>"
        })
        $rest = @($prioPool).Count - $prio.Count
        if ($rest -gt 0) { $li += "<li class='result-note'>... and $rest more $prioTier issue(s) in the sections below.</li>" }
        $li -join "`n"
    } elseif ($riskGroups.Count -gt 0) {
        '<li>Only informational findings were recorded; no action is required from them.</li>'
    } elseif ($cov.Known -and $cov.Selected -gt 0 -and $cov.Ran -le 0) {
        '<li>Nothing could be assessed, so there are no priority actions yet. Fix the problems listed under Check coverage and run the audit again.</li>'
    } else {
        if ($partial) { '<li>No risk findings in the checks that could run. This is not a clean result while checks are missing or only partly assessed &mdash; see Check coverage.</li>' }
        else { '<li>No risk findings were identified.</li>' }
    }

    # --- sections, index, cards ---
    $sectionDefs = @(foreach ($sev in $severityOrder) {
        [pscustomobject]@{ Key = $sev; Id = 'section-' + (New-Slug $sev); Heading = $sev; Groups = (& $sortIssues @($riskGroups | Where-Object { $_.Severity -eq $sev })); Gap = $false }
    }) + @([pscustomobject]@{ Key = 'Not assessed'; Id = 'section-not-assessed'; Heading = 'Not assessed'; Groups = $gapGroups; Gap = $true })

    $indexHtml = New-Object System.Collections.Generic.List[string]
    $sectionHtml = New-Object System.Collections.Generic.List[string]
    foreach ($sd in $sectionDefs) {
        $gs = @($sd.Groups)
        $nFind = & $sumMembers $gs
        if ($gs.Count -gt 0) {
            $rows = foreach ($g in $gs) {
                $cnt = if ($g.Members.Count -gt 1) { " <span class='count-pill'>$($g.Members.Count)</span>" } else { '' }
                "<li><a href='#$(HtmlAttrEncode $g.Anchor)'>$(HtmlEncode $g.Title)</a>$cnt<span class='idx-check mono'>$(HtmlEncode $g.CheckId)</span></li>"
            }
            $indexHtml.Add("<details class='index-detail'><summary>$(HtmlEncode $sd.Heading) ($nFind)</summary><ol>$($rows -join "`n")</ol></details>") | Out-Null
        }
        $cards = New-Object System.Collections.Generic.List[string]
        if ($gs.Count -eq 0) {
            $emptyText = if ($sd.Gap) {
                if ($cov.Skipped + $cov.Errored -gt 0) { "The checks that ran reported no unreadable areas. $($cov.Skipped + $cov.Errored) selected check(s) did not run at all &mdash; see <a href='#check-coverage'>Check coverage</a>." }
                else { 'Every area the selected checks looked at could be read.' }
            } elseif ($partial) { 'No findings in this severity band from the checks that ran.' } else { 'No findings in this severity band.' }
            $cards.Add("<div class='empty'>$emptyText</div>") | Out-Null
        } else {
            foreach ($g in $gs) { $cards.Add((ConvertTo-EntraFindingCardHtml -Group $g -TenantId $TenantId -CheckTitles $checkTitles)) | Out-Null }
        }
        $countText = if ($gs.Count -eq 0) { '0 findings' } elseif ($gs.Count -eq $nFind) { "$nFind finding$(if ($nFind -ne 1) { 's' })" } else { "$($gs.Count) issue$(if ($gs.Count -ne 1) { 's' }) &middot; $nFind findings" }
        $intro = if ($sd.Gap) { "<p class='result-note'>Areas the audit could not read or evaluate (missing permission, license, or an error). They are <b>not</b> passes and are not counted as risk findings. Fix the access problem and run the audit again.</p>" } else { '' }
        $sectionHtml.Add("<section class='severity-section' id='$($sd.Id)'><div class='section-header'><h2>$(HtmlEncode $sd.Heading)</h2><div class='section-count'>$countText</div></div>$intro$($cards -join "`n")</section>") | Out-Null
    }
    if ($indexHtml.Count -eq 0) { $indexHtml.Add("<div class='empty'>No findings.</div>") | Out-Null }

    # --- check coverage table (every available check, worst first) ---
    $kindOrder = @{ Error = 0; NoResult = 0; Skipped = 1; Incomplete = 2; Findings = 3; Clean = 4; NotRun = 5 }
    $findingsByCheck = @{}
    foreach ($it in $all) { $cid = [string]$it.CheckId; $findingsByCheck[$cid] = 1 + $(if ($findingsByCheck.ContainsKey($cid)) { $findingsByCheck[$cid] } else { 0 }) }
    $isProblem = { param($v) $v.Kind -in @('Error','NoResult','Skipped','Incomplete') -or $v.Partly }
    $problemRows = @($cov.Rows | Where-Object { & $isProblem $_ }).Count
    $i = 0
    $covRows = foreach ($r in @($cov.Rows | ForEach-Object { $i++; [pscustomobject]@{ R = $_; O = $i } } |
            Sort-Object @{ e = { $k = $_.R.Kind; if ($k -eq 'Findings' -and $_.R.Partly) { 2 } elseif ($kindOrder.ContainsKey($k)) { $kindOrder[$k] } else { 0 } } }, O)) {
        $v = $r.R
        # With problems present, only those rows show until "Show all checks" is clicked.
        $rowCls = if ($problemRows -gt 0 -and -not (& $isProblem $v)) { " class='extra'" } else { '' }
        $nf = if ($findingsByCheck.ContainsKey($v.CheckId)) { $findingsByCheck[$v.CheckId] } else { 0 }
        $link = if ($nf -gt 0) { "<a href='#findings-start' data-filter-check='$(HtmlAttrEncode $v.CheckId)'>Show $nf</a>" } else { "<span class='result-note'>none</span>" }
        $err = if ($v.ErrorMessage) { $m = $v.ErrorMessage; if ($m.Length -gt 400) { $m = $m.Substring(0, 400) + '...' }; "<div class='check-error mono'>$(HtmlEncode $m)</div>" } else { '' }
        $statusTitle = if ($v.Status) { " title='Status: $(HtmlAttrEncode $v.Status)'" } else { '' }
        "<tr id='check-$(HtmlAttrEncode $v.CheckId)'$rowCls><td><b>$(HtmlEncode $v.Title)</b><div class='idx-check mono'>$(HtmlEncode $v.CheckId)</div></td><td><span class='pill $($v.Class)'$statusTitle>$(HtmlEncode $v.Label)</span></td><td><div class='check-reason'>$(HtmlEncode $v.Reason)</div>$err</td><td>$link</td></tr>"
    }
    $checksSummary = if (-not $cov.Known) { 'Check coverage: unknown' } else { "Check coverage: $($cov.Selected - $notFull) of $($cov.Selected) selected checks fully completed" }
    $checksOpen = if ($total -eq 0 -or $problemRows -gt 0 -or -not $cov.Known) { ' open' } else { '' }
    $nCov = @($covRows).Count
    $moreBtn = if ($problemRows -gt 0 -and $nCov -gt $problemRows) { "<button type='button' class='show-more' data-more='Show all $nCov checks' data-less='Show only the checks with problems'>Show all $nCov checks</button>" } else { '' }
    $covIntro = if ($problemRows -gt 0) { "Below: the $problemRows check(s) that did not fully run, and why. " } else { '' }
    $checksBody = if ($nCov -gt 0) {
        "<p class='result-note'>$($covIntro)Skipped, errored and partly assessed checks are gaps in the audit, not passes. Checks marked 'Not run' were not selected for this run.</p><div class='result-block'><table class='status-table'><thead><tr><th>Check</th><th>Result</th><th>Details</th><th>Findings</th></tr></thead><tbody>$($covRows -join "`n")</tbody></table>$moreBtn</div>"
    } else { "<p class='result-note'>No check status was recorded. See <a href='Posture-Summary.html'>Posture Summary</a>.</p>" }

    # --- filter options ---
    $sevOptions = "<option value='All'>All severities</option><option value='Risk'>Risk findings only (Critical to Low)</option>" +
        (($severityOrder | ForEach-Object { "<option value='$_'>$_</option>" }) -join '') + "<option value='Gap'>Not assessed</option>"
    $catOptions = @("<option value='All'>All categories</option>") + @($all | ForEach-Object { [string]$_.Category } | Where-Object { $_ } |
        Sort-Object -Unique | ForEach-Object { "<option value='$(HtmlAttrEncode $_)'>$(HtmlEncode $_)</option>" })
    $regOrder = @{}; $o = 0
    if ($script:Registry -is [System.Collections.IDictionary]) { foreach ($k in $script:Registry.Keys) { $regOrder[[string]$k] = $o++ } }
    $checkOptions = @("<option value='All'>All checks</option>") + @($all | ForEach-Object { [string]$_.CheckId } | Where-Object { $_ } | Select-Object -Unique |
        Sort-Object { if ($regOrder.ContainsKey($_)) { $regOrder[$_] } else { 1000 } }, { $_ } |
        ForEach-Object { $t = if ($checkTitles.ContainsKey($_)) { "$($checkTitles[$_]) ($_)" } else { $_ }; "<option value='$(HtmlAttrEncode $_)'>$(HtmlEncode $t)</option>" })

    $findingsLine = "Findings: <b>$total</b> ($riskTotal risk &middot; $infoTotal information &middot; $gapCount not assessed)"

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
          Tenant: <span class="mono">$(HtmlEncode $TenantName)</span>$tenantIdHtml<br>
          Generated: $(HtmlEncode $GeneratedOn)<br>
          $runHtml$subtitleHtml
          Read-only audit &mdash; no changes were made to the tenant. Raw evidence is written to the <span class="mono">Raw Data\Source</span> folder.
        </div>
        $riskLine
      </div>
      <div class="hero-actions">
        <button type="button" class="theme-toggle" id="themeToggle">Dark mode</button>
        <div class="meta">$findingsLine<br>Executive view: <a href="Risk-Report.html">Risk-Report.html</a><br>All checks: <a href="Posture-Summary.html">Posture-Summary.html</a></div>
      </div>
    </div>
    <div class="metrics">$($countCards -join "`n")</div>
    $covCards
  </section>
  $coverageCallout
  <div class="layout">
    <aside class="sidebar">
      <h3>Navigate</h3>
      <ul>
        <li><a href="#how-to-read">How to read this report</a></li>
        <li><a href="#priority-actions">Priority actions</a></li>
        <li><a href="#check-coverage">Check coverage</a></li>
        <li><a href="#section-critical">Critical findings</a></li>
        <li><a href="#section-high">High findings</a></li>
        <li><a href="#section-medium">Medium findings</a></li>
        <li><a href="#section-low">Low findings</a></li>
        <li><a href="#section-information">Information</a></li>
        <li><a href="#section-not-assessed">Not assessed</a></li>
      </ul>
      <div class="index-group"><h4>Finding index</h4>$($indexHtml -join "`n")</div>
    </aside>
    <main class="content">
      <details class="howto" id="how-to-read" open>
        <summary>How to read this report</summary>
        <ul>
          <li><b>One card per issue.</b> When the same problem affects several users, apps or policies, they share one card with a count (for example &quot;10 objects&quot;). Open the card to see every affected object.</li>
          <li><b>Severity:</b> Critical &ndash; fix now, it can lead to takeover of the tenant or its admin accounts. High &ndash; fix soon. Medium &ndash; plan a fix. Low &ndash; minor hygiene. Information &ndash; context only, no action needed.</li>
          <li><b>Not assessed</b> (dashed cards) means the audit could not read or evaluate that area, for example because of a missing permission, license or an error. It is not a pass and is not counted as a risk finding.</li>
          <li>Open a card for <b>why it matters</b>, the <b>recommended action</b> and the <b>evidence</b>. Search also looks inside closed cards; the severity boxes at the top act as filters. Printing expands every card.</li>
          <li>The grey line inside each card shows the check, the rule and the finding id used in <span class="mono">Findings.json</span> / <span class="mono">Findings.csv</span>, and how to re-run only that check.</li>
        </ul>
      </details>
      <section class="priority" id="priority-actions">
        <div class="section-header"><h2>Priority actions</h2><div class="section-count">Distinct issues, most severe first; then the most widespread</div></div>
        $prioIntro
        <ul>$priorityHtml</ul>
      </section>
      <details class="checks" id="check-coverage"$checksOpen>
        <summary>$(HtmlEncode $checksSummary)</summary>
        $checksBody
      </details>
      <section class="toolbar" id="findings-start">
        <div class="toolbar-row">
          <div class="filter"><label for="severityFilter">Severity</label>
            <select id="severityFilter">$sevOptions</select></div>
          <div class="filter"><label for="checkFilter">Check</label>
            <select id="checkFilter">$($checkOptions -join '')</select></div>
          <div class="filter"><label for="categoryFilter">Category</label>
            <select id="categoryFilter">$($catOptions -join '')</select></div>
          <div class="filter"><label for="searchFilter">Search</label><input id="searchFilter" type="search" placeholder="Title, evidence, recommendation, user, object id"></div>
        </div>
        <div class="toolbar-actions">
          <button type="button" class="btn" id="expandAll">Expand all</button>
          <button type="button" class="btn" id="collapseAll">Collapse all</button>
          <button type="button" class="btn" id="resetFilters">Reset filters</button>
          <span class="visible-count" id="visibleFindings" aria-live="polite"></span>
        </div>
      </section>
      <div class="empty" id="noResults" style="display:none">No findings match these filters. Use <b>Reset filters</b> to show everything.</div>
      <div class="print-only result-note" id="printFilterNote"></div>
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
    param([string]$Path, [object[]]$Items, [hashtable]$Counts, [string]$TenantName, [string]$GeneratedOn, [pscustomobject]$Score, [hashtable]$Stats,
          [object]$RunInfo = $script:RunInfo)

    if ($null -eq $Items) { $Items = @() }
    if ($null -eq $Score -or -not $Score.PSObject.Properties['ConfirmedDrivers']) { $Score = Get-EntraRiskScore $Items }
    if ($null -eq $Stats) { $Stats = Get-EntraReportStatistic }
    $cov = if ($Score.Coverage) { $Score.Coverage } else { Get-EntraRunCoverage -RunInfo $RunInfo }
    $bandClass = Get-BandBadgeClass $Score.Band
    $confirmed = @($Score.ConfirmedDrivers)
    $gapDrivers = @($Score.NotAssessedDrivers)
    $cc = $Score.ConfirmedCounts; $gc = $Score.NotAssessedCounts
    $resultsHref = 'EntraAudit-Results.html'
    $checkTitle = { param($id) if ($id -and $script:Registry -and $script:Registry.Contains([string]$id)) { [string]$script:Registry[[string]$id].Title } else { [string]$id } }
    $plural = { param([int]$n, [string]$one, [string]$many) if ($n -eq 1) { "1 $one" } else { "$n $many" } }
    $docLink = { param($u) if ([string]$u -match '^https://') { " <a href='$(HtmlAttrEncode $u)' target='_blank' rel='noopener'>Microsoft guidance</a>" } else { '' } }

    # Higher score = worse. Ranges derive from the single $script:RiskBands definition
    # (worst-first), so this matrix always matches the thresholds the code applied. The
    # coverage labels are appended as score-0 rows that replace 'Clean' when the audit
    # did not see everything.
    $bands = for ($i = 0; $i -lt $script:RiskBands.Count; $i++) {
        $b = $script:RiskBands[$i]
        $range = if ($i -eq 0) { "$($b.Min)+" }
                 elseif ($b.Min -eq ($script:RiskBands[$i-1].Min - 1)) { "$($b.Min)" }
                 else { "$($b.Min) - $($script:RiskBands[$i-1].Min - 1)" }
        [pscustomobject]@{ Level=$b.Level; Range=$range; Meaning=$b.Meaning }
    }
    $bands = @($bands) + @($script:RiskCoverageBands | ForEach-Object { [pscustomobject]@{ Level=$_.Level; Range='0'; Meaning=$_.Meaning } })
    $matrixRows = foreach ($b in $bands) {
        $bc = Get-BandBadgeClass $b.Level
        $cls = if ($b.Level -eq $Score.Band) { "matrix-row active sev-$bc" } else { "matrix-row sev-$bc" }
        "<tr class='$cls'><td><span class='pill sev-$bc'>$(HtmlEncode $b.Level)</span></td><td class='mono'>$($b.Range)</td><td>$(HtmlEncode $b.Meaning)</td></tr>"
    }

    # ---- plain-language summary (what the score means, what drives it, what to do first) ----
    $confFindings = @($Items | Where-Object { (Normalize-Severity $_.Severity) -ne 'Information' -and -not (Test-EntraCoverageGap $_) })
    $confChecks = @($confFindings | ForEach-Object { [string]$_.CheckId } | Select-Object -Unique).Count
    $issueName = { param($d) if ($d.Count -gt 1) { '{0} ({1} findings)' -f $d.Title, $d.Count } else { $d.FirstTitle } }
    $summary = New-Object System.Collections.Generic.List[string]
    if ($confirmed.Count -gt 0) {
        $top = @($confirmed | Select-Object -First 3)
        $share = 0; foreach ($d in $top) { $share += $d.Share }
        $names = @($top | ForEach-Object { '<b>' + (HtmlEncode (& $issueName $_)) + '</b>' })
        $nameList = if ($names.Count -le 1) { $names -join '' } else { ($names[0..($names.Count - 2)] -join ', ') + ' and ' + $names[-1] }
        $lead = if ($top.Count -eq 1) { "The biggest issue accounts for $share% of the score: $nameList." } else { "The $($top.Count) biggest issues account for $share% of the score: $nameList." }
        $summary.Add("<p class='summary-lead'>Overall risk is <b>$(HtmlEncode $Score.Band)</b> with a score of <b>$($Score.Score)</b> (higher is worse). $lead</p>") | Out-Null
        if ($Score.NotAssessedPoints -gt 0) {
            $summary.Add("<p>$($Score.NotAssessedPoints) of the $($Score.Score) points come from areas the audit could not check (marked <span class='pill mini gap'>Not assessed</span> below). Not knowing is itself a risk, but these are not confirmed problems.</p>") | Out-Null
        }
        $distinct = $confirmed.Count
        $counted = "The audit confirmed <b>$($cc.Critical)</b> critical, <b>$($cc.High)</b> high, <b>$($cc.Medium)</b> medium and <b>$($cc.Low)</b> low findings ($(& $plural $distinct 'distinct issue' 'distinct issues')) in $(& $plural $confChecks 'check' 'checks')."
        if ($cc.Information -gt 0) { $counted += " $(& $plural $cc.Information 'informational note is' 'informational notes are') listed in the detailed results but do not affect the score." }
        $summary.Add("<p>$counted</p>") | Out-Null
    } elseif ($gapDrivers.Count -gt 0 -or $Score.NotAssessedFindings -gt 0) {
        $summary.Add("<p class='summary-lead'>Overall risk is <b>$(HtmlEncode $Score.Band)</b> (score <b>$($Score.Score)</b>; higher is worse). No problems were confirmed, but the audit could not check everything - $(if ($Score.Score -gt 0) { 'the whole score comes from areas that could not be checked. ' } else { '' })see <a href='#not-assessed'>Not assessed</a> below.</p>") | Out-Null
    } elseif ($cov.Selected -gt 0 -and $cov.Evaluated -eq 0) {
        $summary.Add("<p class='summary-lead'>Overall risk is <b>$(HtmlEncode $Score.Band)</b>. None of the selected checks gave a result, so nothing can be said about this tenant's risk yet. See <a href='#not-assessed'>Not assessed</a> for the reasons.</p>") | Out-Null
    } else {
        $summary.Add("<p class='summary-lead'>Overall risk is <b>$(HtmlEncode $Score.Band)</b> (score <b>$($Score.Score)</b>). No problems were found in the checks that ran.</p>") | Out-Null
    }
    # Coverage sentence - always stated, so a reader never mistakes a partial audit for a full one.
    if ($cov.Selected -gt 0) {
        if ($cov.Complete) {
            $covText = "All $($cov.Selected) selected checks ran and read all of their data."
        } else {
            $parts = @()
            if ($cov.Skipped -gt 0)    { $parts += "$($cov.Skipped) $(if ($cov.Skipped -eq 1) { 'was' } else { 'were' }) skipped (missing permission or license)" }
            if ($cov.Errored -gt 0)    { $parts += "$($cov.Errored) stopped with an error" }
            if ($cov.Incomplete -gt 0) { $parts += "$($cov.Incomplete) could not read all of their data" }
            $partText = if ($parts.Count -le 1) { $parts -join '' } else { ($parts[0..($parts.Count - 2)] -join ', ') + ' and ' + $parts[-1] }
            $covText = if ($cov.FullyEvaluated -eq 0) {
                "None of the $($cov.Selected) selected checks gave a full result: $partText. Problems in those areas cannot show up in this report. <a href='Posture-Summary.html#checks'>See which checks</a>."
            } else {
                "Only <b>$($cov.FullyEvaluated) of $($cov.Selected)</b> selected checks gave a full result: $partText. Problems in those areas cannot show up in this report, so treat the score as a minimum. <a href='Posture-Summary.html#checks'>See which checks</a>."
            }
        }
        if ($cov.NotRun -gt 0) { $covText += " $(& $plural $cov.NotRun 'other check was' 'other checks were') not selected for this run, so $(if ($cov.NotRun -eq 1) { 'that area was' } else { 'those areas were' }) not checked." }
        $summary.Add("<p>$covText</p>") | Out-Null
    }
    # "Do first": the recommended action of the biggest confirmed issues, one per distinct action.
    $doFirst = New-Object System.Collections.Generic.List[string]
    $seenActions = @{}
    foreach ($d in $confirmed) {
        if ($doFirst.Count -ge 3) { break }
        $act = ([string]$d.RecommendedAction).Trim()
        if (-not $act -or $seenActions.ContainsKey($act)) { continue }
        $seenActions[$act] = $true
        $doFirst.Add("<li><b>$(HtmlEncode $d.Title)</b> &mdash; $(HtmlEncode $act) <a href='$resultsHref#$(HtmlAttrEncode $d.FirstAnchor)'>Details</a>$(& $docLink $d.DocumentationUrl)</li>") | Out-Null
    }
    if (-not $cov.Complete -and $cov.Selected -gt 0 -and ($cov.Skipped + $cov.Errored) -gt 0) {
        $doFirst.Add("<li><b>Close the gaps in this audit</b> &mdash; give the audit account the missing permissions or licenses listed under <a href='#not-assessed'>Not assessed</a>, then run the skipped checks again.</li>") | Out-Null
    }
    $doFirstHtml = if ($doFirst.Count -gt 0) { "<h3>Do first</h3><ol>$($doFirst -join "`n")</ol>" } else { '' }
    $calloutCls = if ($cov.Complete -and $Score.NotAssessedFindings -eq 0) { 'callout' } else { 'callout warn' }

    # ---- top risks: DISTINCT confirmed issues (not one line per affected object), biggest first ----
    $topHtml = if ($confirmed.Count -gt 0) {
        $li = foreach ($d in @($confirmed | Select-Object -First 8)) {
            $who = ''
            $pr = @($d.Principals)
            if ($d.Count -gt 1 -and $pr.Count -gt 0) {
                $more = $d.Count - $pr.Count
                $who = ' &middot; e.g. ' + (($pr | ForEach-Object { HtmlEncode $_ }) -join ', ') + $(if ($more -gt 0) { " and $more more" } else { '' })
            }
            $name = if ($d.Count -gt 1) { HtmlEncode $d.Title } else { HtmlEncode $d.FirstTitle }
            $cnt = if ($d.Count -gt 1) { " <span class='muted'>&times; $($d.Count)</span>" } else { '' }
            "<li><span class='pill sev-$($d.Severity)'>$($d.Severity)</span><div><a href='$resultsHref#$(HtmlAttrEncode $d.FirstAnchor)'><b>$name</b></a>$cnt<span class='li-sub'>$(& $plural $d.Count 'finding' 'findings') in $(HtmlEncode (& $checkTitle $d.CheckId)) &middot; $($d.Points) points ($($d.Share)% of the score)$who</span></div></li>"
        }
        $extra = if ($confirmed.Count -gt 8) { "<p class='muted' style='margin-top:8px'>$($confirmed.Count - 8) more issue(s) are listed under <a href='#drivers'>What drives the score</a>.</p>" } else { '' }
        "<ul class='risk-list'>$($li -join "`n")</ul>$extra"
    } elseif ($cov.Complete -and $Score.NotAssessedFindings -eq 0) {
        "<p>No problems were found in the checks that ran.</p>"
    } elseif ($cov.Selected -gt 0 -and $cov.Evaluated -eq 0) {
        "<p>Nothing could be checked, so there is nothing to list here. This is <b>not</b> a clean result - see <a href='#not-assessed'>Not assessed</a>.</p>"
    } else {
        "<p>No problems were confirmed in the data the audit could read. This is <b>not</b> a clean result: part of the tenant could not be checked - see <a href='#not-assessed'>Not assessed</a>.</p>"
    }

    # ---- not assessed: checks that did not run completely + data that could not be read ----
    $gapItems = @($Items | Where-Object { Test-EntraCoverageGap $_ })
    $gapGroups = [ordered]@{}
    foreach ($f in $gapItems) {
        $k = (Get-EntraIssueKey $f).Key
        if ($gapGroups.Contains($k)) { $gapGroups[$k].Count++ }
        else { $gapGroups[$k] = @{ Finding = $f; Count = 1; Severity = (Normalize-Severity $f.Severity) } }
    }
    $gapPoints = @{}; foreach ($d in $gapDrivers) { $gapPoints[$d.Key] = $d.Points }
    $gapLis = foreach ($k in $gapGroups.Keys) {
        $g = $gapGroups[$k]; $f = $g.Finding
        $pts = if ($gapPoints.ContainsKey($k)) { " &middot; adds $($gapPoints[$k]) points" } else { '' }
        $t = if ($g.Count -gt 1) { "$(HtmlEncode (Get-EntraIssueKey $f).IssueTitle) <span class='muted'>&times; $($g.Count)</span>" } else { HtmlEncode $f.Title }
        "<li><span class='pill sev-$($g.Severity)'>$($g.Severity)</span><div><a href='$resultsHref#$(HtmlAttrEncode (New-FindingAnchor $f))'><b>$t</b></a> <span class='pill mini gap'>Not assessed</span><span class='li-sub'>$(HtmlEncode (& $checkTitle $f.CheckId))$pts</span></div></li>"
    }
    $checkLis = foreach ($r in @($cov.Rows | Where-Object { $_.Selected -and $_.Group -in @('skipped','error','noresult') })) {
        $pc = if ($r.Group -eq 'skipped') { 'skip' } else { 'err' }
        "<li><span class='pill $pc'>$(HtmlEncode $r.Label)</span><div><a href='Posture-Summary.html#check-$(HtmlAttrEncode $r.CheckId)'><b>$(HtmlEncode $r.Title)</b></a><span class='li-sub'>$(HtmlEncode $r.Reason)</span></div></li>"
    }
    $notAssessedHtml = ''
    if (@($gapLis).Count -gt 0 -or @($checkLis).Count -gt 0) {
        $parts = @()
        if (@($checkLis).Count -gt 0) { $parts += "<h3>Checks that did not give a result</h3><ul class='risk-list'>$(@($checkLis) -join "`n")</ul>" }
        if (@($gapLis).Count -gt 0) { $parts += "<h3>Data that could not be read</h3><ul class='risk-list'>$(@($gapLis) -join "`n")</ul>" }
        $notAssessedHtml = @"
  <div class="section" id="not-assessed">
    <h2>Not assessed</h2>
    <p class="section-lead">These areas could not be checked. They are gaps in the audit, not clean results: a problem there would not show up anywhere in this report.</p>
    <div class="callout warn">$($parts -join "`n")</div>
  </div>
"@
    }

    # ---- score drivers: every issue behind the score, biggest first; coverage gaps flagged ----
    $driverRow = {
        param($d)
        $pct = if ($Score.Score -gt 0) { [math]::Round(100 * $d.Points / $Score.Score) } else { 0 }
        $gap = if ($d.CoverageGap) { " <span class='pill mini gap'>Not assessed</span>" } else { '' }
        "<tr><td><span class='pill sev-$($d.Severity)'>$($d.Severity)</span></td><td class='title'><a href='$resultsHref#$(HtmlAttrEncode $d.FirstAnchor)'>$(HtmlEncode $d.Title)</a>$gap</td><td>$(HtmlEncode (& $checkTitle $d.CheckId))<span class='sub mono'>$(HtmlEncode $d.CheckId)</span></td><td class='num'>$($d.Count)</td><td class='num mono'>$($d.Points)</td><td class='num mono'>$pct%</td></tr>"
    }
    $allDrivers = @($Score.Drivers)
    $driverRows = @($allDrivers | Select-Object -First 10 | ForEach-Object { & $driverRow $_ })
    $moreRows = @($allDrivers | Select-Object -Skip 10 | ForEach-Object { & $driverRow $_ })
    if ($driverRows.Count -eq 0) { $driverRows = @("<tr><td colspan='6'>Nothing adds to the score: no Critical, High, Medium or Low findings.</td></tr>") }
    $driverHead = "<thead><tr><th>Severity</th><th style='text-align:left'>Issue</th><th style='text-align:left'>Check</th><th style='text-align:right'>Findings</th><th style='text-align:right'>Points</th><th style='text-align:right'>Share</th></tr></thead>"
    $moreHtml = if ($moreRows.Count -gt 0) { "<details class='more'><summary>Show all $($allDrivers.Count) issues</summary><table>$driverHead<tbody>$($moreRows -join "`n")</tbody></table></details>" } else { '' }
    $gapNote = if ($Score.NotAssessedPoints -gt 0) { "<div style='margin-top:6px'><small>$($Score.NotAssessedPoints) of the $($Score.Score) points come from issues marked Not assessed (areas that could not be checked).</small></div>" } else { '' }

    # ---- findings by category (confirmed counts; coverage gaps in their own column) ----
    $catGroups = $Items | ForEach-Object { [pscustomobject]@{ Category=[string]$_.Category; Severity=(Normalize-Severity $_.Severity); Gap=[bool](Test-EntraCoverageGap $_) } } |
        Group-Object Category | Sort-Object Name
    $catRows = foreach ($cg in $catGroups) {
        $conf = @($cg.Group | Where-Object { -not $_.Gap })
        $ncC=@($conf|Where-Object{$_.Severity -eq 'Critical'}).Count; $ncH=@($conf|Where-Object{$_.Severity -eq 'High'}).Count
        $ncM=@($conf|Where-Object{$_.Severity -eq 'Medium'}).Count; $ncL=@($conf|Where-Object{$_.Severity -eq 'Low'}).Count
        $ncG=@($cg.Group | Where-Object { $_.Gap }).Count
        # Total counts only the confirmed risk columns - Information findings have no
        # column here, and including them made rows appear not to sum.
        $ct = $ncC + $ncH + $ncM + $ncL
        if ($ct -eq 0 -and $ncG -eq 0) { continue }   # Information-only category: nothing to show
        $cell = { param($n, $sev) if ($n) { "<span class='pill sev-$sev'>$n</span>" } else { '-' } }
        $gapCell = if ($ncG) { "<span class='pill gap'>$ncG</span>" } else { '-' }
        "<tr><td>$(HtmlEncode $cg.Name)</td><td style='text-align:center'>$(& $cell $ncC 'Critical')</td><td style='text-align:center'>$(& $cell $ncH 'High')</td><td style='text-align:center'>$(& $cell $ncM 'Medium')</td><td style='text-align:center'>$(& $cell $ncL 'Low')</td><td style='text-align:center;font-weight:700'>$ct</td><td style='text-align:center'>$gapCell</td></tr>"
    }
    if (-not $catRows) { $catRows = @("<tr><td colspan='7'>No findings that carry risk.</td></tr>") }

    # ---- all findings (collapsed; the Results page is the full view) ----
    $sorted = $Items | Sort-Object @{e={Get-SeverityRank $_.Severity};Descending=$true}, Title
    $tableRows = foreach ($f in $sorted) {
        $sev = Normalize-Severity $f.Severity
        $isGap = [bool](Test-EntraCoverageGap $f)
        $href = Resolve-SourceHref $f.SourceFile
        $links = "<a href='$resultsHref#$(HtmlAttrEncode (New-FindingAnchor $f))'>Details</a>"
        if ($href) { $links += " &middot; <a href='$(HtmlAttrEncode $href)' target='_blank' rel='noopener'>Evidence</a>" }
        $gapTag = if ($isGap) { " <span class='pill mini gap'>Not assessed</span>" } else { '' }
        "<tr data-sev='$sev' data-gap='$(if ($isGap) { '1' } else { '0' })'><td><span class='pill sev-$sev'>$sev</span></td><td class='title'>$(HtmlEncode $f.Title)$gapTag</td><td class='evidence'>$(HtmlEncode $f.Evidence)</td><td class='source'>$links</td></tr>"
    }

    # ---- header cards ----
    $sevCard = {
        param([string]$sev, [string]$hint)
        $n = [int]$cc[$sev]; $g = [int]$gc[$sev]
        $sub = if ($g -gt 0) { "$hint<br>+$g not assessed" } else { $hint }
        "<div class='card span-3'><div class='k'>$sev</div><div class='v'>$n</div><div class='s'>$sub</div></div>"
    }
    $covSub = @()
    if ($cov.Incomplete -gt 0) { $covSub += "$($cov.Incomplete) incomplete" }
    if ($cov.Skipped -gt 0)    { $covSub += "$($cov.Skipped) skipped" }
    if ($cov.Errored -gt 0)    { $covSub += "$($cov.Errored) error" }
    if ($cov.NotRun -gt 0)     { $covSub += "$($cov.NotRun) not selected" }
    $covSubText = if ($covSub.Count -gt 0) { ($covSub -join ' &middot; ') + " &middot; <a href='Posture-Summary.html#checks'>details</a>" } else { "Every selected check ran fully &middot; <a href='Posture-Summary.html#checks'>details</a>" }
    $covCardCls = if ($cov.Complete) { 'card span-6' } else { 'card span-6 warn' }
    $covValue = if ($cov.Selected -gt 0) { "$($cov.FullyEvaluated) of $($cov.Selected)" } else { '-' }
    $badgeNote = if ($Score.Band -in @('Not assessed','Not fully assessed')) { 'Not a clean result: some areas could not be checked.' }
                 elseif (-not $cov.Complete -and $cov.Selected -gt 0) { 'Coverage is incomplete, so the real risk may be higher.' }
                 else { '' }
    $badgeNoteHtml = if ($badgeNote) { "<div class='badge-note'>$badgeNote</div>" } else { '' }

    # ---- one-line run context (full details are on the Posture Summary) ----
    $runBits = @()
    $tid = Get-EntraRunValue $RunInfo 'TenantId'
    if ($tid) { $runBits += "Tenant id: <span class='mono'>$(HtmlEncode $tid)</span>" }
    $acct = Get-EntraRunValue $RunInfo 'Account'
    $mode = Get-EntraRunValue $RunInfo 'AuthMode'; if (-not $mode) { $mode = $script:AuthType }
    if ($acct) { $runBits += "Signed in as: <span class='mono'>$(HtmlEncode $acct)</span> ($(HtmlEncode $mode))" } else { $runBits += "Auth: <span class='mono'>$(HtmlEncode $mode)</span>" }
    $dur = Get-EntraRunDurationText $RunInfo
    if ($dur) { $runBits += "Run time: $(HtmlEncode $dur)" }
    $ver = Get-EntraRunValue $RunInfo 'ToolVersion'; if (-not $ver) { $ver = $script:Version }
    $runBits += "$(HtmlEncode $ver) &middot; <a href='Posture-Summary.html#run-details'>Run details</a>"

    $css = Get-EntraRiskCss
    $js  = Get-EntraRiskJs
    $nav = Get-EntraPrimaryNav 'risk'
    $total = @($Items).Count
    # Totals per severity as on the Results page (confirmed + not assessed).
    $allCounts = if ($Counts -and $Counts.ContainsKey('Critical')) { $Counts } else { @{ Critical = $Score.Critical; High = $Score.High; Medium = $Score.Medium; Low = $Score.Low; Information = $Score.Information } }
    # A severity filter shows every row of that severity, not-assessed ones included, so the
    # number here must match what the filter shows; the not-assessed part is named in brackets.
    $allText = (@('Critical','High','Medium','Low','Information') | ForEach-Object {
        $g = if ($gc) { [int]$gc[$_] } else { 0 }
        '{0} {1}{2}' -f [int]$allCounts[$_], $_.ToLowerInvariant(), $(if ($g -gt 0) { " (incl. $g not assessed)" } else { '' })
    }) -join ', '

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
      <div class="h-main">
        <h1>Microsoft Entra ID Audit - Risk Report</h1>
        <div class="meta">Tenant: <span class="mono">$(HtmlEncode $TenantName)</span> | Generated: $(HtmlEncode $GeneratedOn) | <a href="$resultsHref">Detailed findings</a></div>
        <div class="meta" style="margin-top:4px">$($runBits -join ' | ')</div>
        <div class="meta" style="margin-top:4px">Licensing: Entra ID P1=$($script:HasP1) | P2=$($script:HasP2)$(if (-not $script:LicenseKnown) { ' (license detection failed)' })</div>
      </div>
      <div class="h-side">
        <button id="themeToggle" type="button" class="theme-toggle">Toggle theme</button>
        <div class="badge $bandClass">
          <div><div class="grade">Overall risk</div><div class="value">$(HtmlEncode $Score.Band)</div></div>
          <div style="width:1px;height:28px;background:var(--line)"></div>
          <div><div class="grade">Risk score (higher = worse)</div><div class="value">$($Score.Score)</div></div>
        </div>
        $badgeNoteHtml
      </div>
    </div>
    <div class="grid">
      $(& $sevCard 'Critical' 'Fix immediately')
      $(& $sevCard 'High' 'Fix promptly')
      $(& $sevCard 'Medium' 'Plan the fix')
      $(& $sevCard 'Low' 'Routine clean-up')
      <div class="$covCardCls"><div class="k">Checks with a full result</div><div class="v">$covValue</div><div class="s">$covSubText</div></div>
      <div class="card span-2"><div class="k">Users</div><div class="v">$($Stats.Users)</div><div class="s">Members + guests</div></div>
      <div class="card span-2"><div class="k">Guests</div><div class="v">$($Stats.Guests)</div><div class="s">External identities</div></div>
      <div class="card span-2"><div class="k">Applications</div><div class="v">$($Stats.Apps)</div><div class="s">App registrations</div></div>
    </div>
  </div>

  <div class="section" id="summary">
    <h2>Summary</h2>
    <div class="$calloutCls">$($summary -join "`n")$doFirstHtml</div>
  </div>

  <div class="section" id="top-risks">
    <h2>Top risks</h2>
    <p class="section-lead">Distinct problems, biggest contribution to the score first. Each line is one issue, however many objects it affects.</p>
    <div class="callout">$topHtml</div>
  </div>
$notAssessedHtml
  <div class="section" id="drivers">
    <h2>What drives the score</h2>
    <table>$driverHead<tbody>$($driverRows -join "`n")</tbody></table>
    $moreHtml
    $gapNote
  </div>

  <div class="section" id="how-scored">
    <h2>How the score works</h2>
    <div class="callout">
      <p>Every problem adds points by severity: Critical $($script:RiskPoints.Critical), High $($script:RiskPoints.High), Medium $($script:RiskPoints.Medium) and Low $($script:RiskPoints.Low). Information notes add $($script:RiskPoints.Information). <b>A higher score is worse</b>, and there is no upper limit.</p>
      <p>The same problem found on many objects adds less for each repeat: an issue found on N objects adds its points &times; &radic;N. For example, 9 permanent Global Administrators count 3 times as much as one, not 9 times. So a widespread problem still raises the score, but it cannot hide every other problem.</p>
      <p>Areas the audit could not check (<span class='pill mini gap'>Not assessed</span>) also add points at their severity, because not being able to see something is a risk in itself. They are always shown separately from confirmed problems. When the same problem is confirmed on some objects and could not be checked on others, they still count as one problem: the part that could not be checked only adds the extra points on top. Checks that were skipped or stopped with an error add no points; instead the risk level is never shown as Clean while any selected check was skipped, failed or could not read all of its data.</p>
      <p>The current score is <b>$($Score.Score)</b> (<b>$(HtmlEncode $Score.Band)</b>).</p>
      <div class="matrix-wrap"><br>
        <table class="matrix"><thead><tr><th>Risk level</th><th>Score</th><th>What it means</th></tr></thead><tbody>$($matrixRows -join "`n")</tbody></table>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>Findings by category</h2>
    <table><thead><tr><th style="text-align:left">Category</th><th style="text-align:center">Critical</th><th style="text-align:center">High</th><th style="text-align:center">Medium</th><th style="text-align:center">Low</th><th style="text-align:center">Total</th><th style="text-align:center">Not assessed</th></tr></thead><tbody>$($catRows -join "`n")</tbody></table>
    <div style="margin-top:6px"><small>Counts confirmed problems only; Information notes carry no points and are left out. &quot;Not assessed&quot; counts findings about data that could not be read.</small></div>
  </div>

  <div class="section" id="all-findings">
    <details class="all-findings">
      <summary>All findings ($total) <small>- $allText; the same findings as the <a href="$resultsHref">detailed results</a>, as one sortable list</small></summary>
      <div class="toolbar">
        <div class="filters">
          <label><small>Severity</small><br><select id="sevFilter"><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Information</option><option>Not assessed</option></select></label>
          <label><small>Search</small><br><input id="search" type="text" placeholder="Search title/evidence..."></label>
        </div>
        <div><small>Visible: <span id="visibleCount">0</span> / $total</small></div>
      </div>
      <table id="findings"><thead><tr><th data-sort="severity">Severity</th><th data-sort="title">Finding</th><th>Evidence</th><th>Links</th></tr></thead><tbody id="findings-body">$($tableRows -join "`n")</tbody></table>
    </details>
  </div>

  <div class="footer">Generated by $(HtmlEncode $ver) &mdash; read-only Microsoft Graph and optional Azure Resource Manager audit. The score is an index of the findings in this report; it covers only the checks that ran (see the Posture Summary for coverage).</div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Write-PostureSummaryReport {
    param([string]$Path, [string]$TenantName, [string]$GeneratedOn, [hashtable]$Stats,
          [object]$RunInfo = $script:RunInfo, [object[]]$Items)

    if ($null -eq $Items) { $Items = Get-EntraFindingList }
    if ($null -eq $Stats) { $Stats = Get-EntraReportStatistic }
    $cov = Get-EntraRunCoverage -RunInfo $RunInfo
    $datasets = @(Get-EntraDatasetIndex -Items $Items)

    # Per-check finding breakdown (confirmed by severity + coverage gaps) and first anchor.
    $byCheck = @{}
    foreach ($f in $Items) {
        $id = [string]$f.CheckId
        if (-not $byCheck.ContainsKey($id)) { $byCheck[$id] = @{ Critical=0; High=0; Medium=0; Low=0; Information=0; Gap=0; GapTitles=(New-Object System.Collections.Generic.List[string]); First=$null; FirstRank=-1 } }
        $e = $byCheck[$id]
        $sev = Normalize-Severity $f.Severity
        if (Test-EntraCoverageGap $f) {
            $e.Gap++
            if ($e.GapTitles.Count -lt 5) { $e.GapTitles.Add([string]$f.Title) | Out-Null }
        } else { $e[$sev]++ }
        $rank = Get-SeverityRank $sev
        if ($rank -gt $e.FirstRank) { $e.First = $f; $e.FirstRank = $rank }
    }
    $dsByCheck = @{}
    foreach ($d in $datasets) {
        if (-not $d.CheckId) { continue }
        if (-not $dsByCheck.ContainsKey($d.CheckId)) { $dsByCheck[$d.CheckId] = New-Object System.Collections.Generic.List[object] }
        $dsByCheck[$d.CheckId].Add($d) | Out-Null
    }

    $regOrder = @{}; $i = 0; foreach ($r in $cov.Rows) { $regOrder[$r.CheckId] = $i++ }
    $rowsSorted = @($cov.Rows | Sort-Object @{e={$_.SortOrder}}, @{e={$regOrder[$_.CheckId]}})
    $statusRows = foreach ($r in $rowsSorted) {
        $cls = switch ($r.Group) { 'clean' { 'ok' } 'findings' { 'find' } 'incomplete' { 'gap' } 'skipped' { 'skip' } 'notrun' { 'notrun' } default { 'err' } }
        $e = if ($byCheck.ContainsKey($r.CheckId)) { $byCheck[$r.CheckId] } else { $null }
        $pills = ''
        $link = ''
        if ($e) {
            foreach ($sev in @('Critical','High','Medium','Low','Information')) {
                if ($e[$sev] -gt 0) { $pills += "<span class='pill mini sev-$sev' title='$sev'>$($e[$sev]) $($sev.Substring(0, $(if ($sev -eq 'Information') { 4 } else { 1 })))</span>" }
            }
            if ($e.Gap -gt 0) { $pills += "<span class='pill mini gap'>$($e.Gap) not assessed</span>" }
            if ($e.First) {
                $link = "<br><a href='EntraAudit-Results.html?check=$([uri]::EscapeDataString($r.CheckId))#$(HtmlAttrEncode (New-FindingAnchor $e.First))'>View findings</a>"
            }
        }
        if (-not $pills) { $pills = if ($r.Group -in @('clean')) { "<span class='muted'>None</span>" } else { "<span class='muted'>-</span>" } }
        $detail = if ($r.Reason) { HtmlEncode $r.Reason } elseif ($r.Group -eq 'clean') { "<span class='muted'>No problems found.</span>" } else { '' }
        if ($e -and $e.GapTitles.Count -gt 0) {
            $detail += "<span class='sub'>Could not assess: " + (($e.GapTitles | ForEach-Object { HtmlEncode $_ }) -join '; ') + $(if ($e.Gap -gt $e.GapTitles.Count) { " (+$($e.Gap - $e.GapTitles.Count) more)" } else { '' }) + '</span>'
        }
        if (@($r.MissingScopes).Count -gt 0) { $detail += "<span class='sub'>Needed: " + ((@($r.MissingScopes) | ForEach-Object { "<span class='chip mono'>$(HtmlEncode $_)</span>" }) -join '') + '</span>' }
        if ($r.ErrorMessage -and $r.Group -in @('error','skipped')) {
            $msg = [string]$r.ErrorMessage; if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }
            $detail += "<span class='err-msg'>$(HtmlEncode $msg)</span>"
        }
        $ev = ''
        if ($dsByCheck.ContainsKey($r.CheckId)) {
            $list = $dsByCheck[$r.CheckId]
            $ev = (@($list | Select-Object -First 3 | ForEach-Object {
                $h = if ($_.HtmlHref) { $_.HtmlHref } elseif ($_.CsvHref) { $_.CsvHref } else { $null }
                $lbl = "$(HtmlEncode $_.Title) <span class='muted'>($($_.Rows))</span>"
                if ($h) { "<a href='$(HtmlAttrEncode (Resolve-SourceHref $h))' target='_blank' rel='noopener'>$lbl</a>" } else { $lbl }
            }) -join '<br>')
            if ($list.Count -gt 3) { $ev += "<br><a href='Raw-Data.html?check=$([uri]::EscapeDataString($r.CheckId))'>All $($list.Count) datasets</a>" }
        } elseif ($r.Group -notin @('notrun','skipped')) { $ev = "<span class='muted'>-</span>" }
        $code = if ($r.Group -ne 'notrun') { "<span class='status-code mono'>$(HtmlEncode $r.Status)</span>" } else { '' }
        $dataGroup = switch ($r.Group) { 'clean' { 'pass' } 'findings' { if ($r.Incomplete) { 'findings gaps' } else { 'findings' } } 'notrun' { 'notrun' } default { 'gaps' } }
        "<tr id='check-$(HtmlAttrEncode $r.CheckId)' data-group='$dataGroup'><td><b>$(HtmlEncode $r.Title)</b><span class='sub mono'>$(HtmlEncode $r.CheckId)</span></td><td><span class='pill $cls'>$(HtmlEncode $r.Label)</span>$code</td><td>$pills$link</td><td>$detail</td><td>$ev</td></tr>"
    }

    # ---- licensing: which checks each license gates, derived from the registry ----
    $licState  = if ($script:LicenseKnown) { 'detected' } else { 'confirmed (license detection failed)' }
    $skipLabel = if ($script:LicenseKnown) { 'Skipped: no license' } else { 'Skipped: license unknown' }
    $p1Ids = @($script:Registry.Keys | Where-Object { $script:Registry[$_].P1 }) -join ', '
    $p2Ids = @($script:Registry.Keys | Where-Object { $script:Registry[$_].P2 }) -join ', '
    $wipIds = @($script:Registry.Keys | Where-Object { $script:Registry[$_].WIP })
    if ($wipIds.Count -eq 0 -and $script:Registry.Contains('riskyserviceprincipals')) { $wipIds = @('riskyserviceprincipals') }
    $licNote = @()
    if ($script:LicenseKnown -and $script:HasP1 -and $script:HasP2) { $licNote += 'Microsoft Entra ID P1 and P2 detected: no P1- or P2-gated check is blocked by licensing.' }
    if (-not $script:LicenseKnown) { $licNote += 'License detection FAILED (the subscribed-license read returned an error). The tenant may well have P1/P2; license-gated checks show as "Skipped: license unknown", not as missing a license.' }
    if (-not $script:HasP1) { $licNote += ("Microsoft Entra ID P1 not {0}. The P1-gated checks ({1}) cannot run and show as ""{2}"" below. Checks that use sign-in activity (guest, break-glass, enterprise-app and monitoring evidence) report that part as Incomplete, not clean." -f $licState, $p1Ids, $skipLabel) }
    if (-not $script:HasP2) { $licNote += ("Microsoft Entra ID P2 not {0}. The P2-gated checks ({1}) cannot run and show as ""{2}"" below. Privileged-roles still runs but without Privileged Identity Management (PIM) eligibility data, so every privileged assignment is treated as permanent." -f $licState, $p2Ids, $skipLabel) }
    if (-not $script:WorkloadIdP -and $wipIds.Count -gt 0) { $licNote += ("Workload Identities Premium not {0}. {1} (risky workload identities) needs it and reports a coverage gap instead of a result. This is a separate license from P2." -f $licState, ($wipIds -join ', ')) }
    foreach ($n in @($script:LicenseNotes)) { if ($n) { $licNote += [string]$n } }
    $licHtml = if ($licNote.Count -gt 0) { '<ul>' + (($licNote | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join '') + '</ul>' } else { '<p>Microsoft Entra ID P1 and P2 detected: no check is blocked by licensing.</p>' }
    $skuHtml = ConvertTo-EntraLicenseSkuHtml -RunInfo $RunInfo

    $runHtml = ConvertTo-EntraRunDetailsHtml -RunInfo $RunInfo -TenantName $TenantName -Coverage $cov

    $css = Get-EntraRiskCss
    $nav = Get-EntraPrimaryNav 'posture'
    $js  = Get-EntraRiskJs2
    $mode = Get-EntraRunValue $RunInfo 'AuthMode'; if (-not $mode) { $mode = $script:AuthType }
    $ver = Get-EntraRunValue $RunInfo 'ToolVersion'; if (-not $ver) { $ver = $script:Version }
    $checkLine = "Checks: <b>$($cov.FullyEvaluated) of $($cov.Selected)</b> selected checks gave a full result"
    $extra = @()
    if ($cov.Incomplete -gt 0) { $extra += "$($cov.Incomplete) incomplete" }
    if ($cov.Skipped -gt 0) { $extra += "$($cov.Skipped) skipped" }
    if ($cov.Errored -gt 0) { $extra += "$($cov.Errored) error" }
    $extra += "$($cov.NotRun) of $($cov.Total) not run"
    $checkLine += ' | ' + ($extra -join ' | ')

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
      <div class="h-main">
        <h1>Microsoft Entra ID Audit - Posture Summary</h1>
        <div class="meta">Tenant: <span class="mono">$(HtmlEncode $TenantName)</span> | Generated: $(HtmlEncode $GeneratedOn) | Auth: <span class="mono">$(HtmlEncode $mode)</span> | <a href="#run-details">Run details</a></div>
        <div class="meta" style="margin-top:4px">$checkLine</div>
        <div class="meta" style="margin-top:4px">Licensing: P1=$($script:HasP1) | P2=$($script:HasP2) | Workload Identities Premium=$($script:WorkloadIdP)$(if (-not $script:LicenseKnown) { ' | detection failed' })</div>
      </div>
      <button id="themeToggle" type="button" class="theme-toggle">Toggle theme</button>
    </div>
    <div class="grid">
      <div class="card span-4"><div class="k">Passed</div><div class="v">$($cov.Clean)</div><div class="s">Ran fully; no problems found</div></div>
      <div class="card span-4"><div class="k">Problems found</div><div class="v">$($cov.WithFindings)</div><div class="s">Action needed</div></div>
      <div class="card span-4$(if ($cov.Incomplete -gt 0) { ' warn' })"><div class="k">Incomplete</div><div class="v">$($cov.Incomplete)</div><div class="s">Some data could not be read (can overlap &quot;problems found&quot;)</div></div>
      <div class="card span-4$(if ($cov.Skipped -gt 0) { ' warn' })"><div class="k">Skipped</div><div class="v">$($cov.Skipped)</div><div class="s">Missing permission or license</div></div>
      <div class="card span-4$(if ($cov.Errored -gt 0) { ' warn' })"><div class="k">Errors</div><div class="v">$($cov.Errored)</div><div class="s">Stopped before finishing</div></div>
      <div class="card span-4"><div class="k">Not run</div><div class="v">$($cov.NotRun)</div><div class="s">Not selected for this run</div></div>
      <div class="card span-4"><div class="k">Users</div><div class="v">$($Stats.Users)</div><div class="s">Members + guests</div></div>
      <div class="card span-4"><div class="k">Guests</div><div class="v">$($Stats.Guests)</div><div class="s">External identities</div></div>
      <div class="card span-4"><div class="k">Applications</div><div class="v">$($Stats.Apps)</div><div class="s">App registrations</div></div>
    </div>
  </div>

  <div class="section" id="licensing">
    <h2>Licensing &amp; coverage</h2>
    <div class="callout">$licHtml$skuHtml<p style="margin-top:8px"><small>Skipped, failed and incomplete checks are gaps in the audit, not clean results. A check that found problems can also be incomplete when another data source was unavailable. Checks marked &quot;Not run&quot; were not selected for this run and say nothing about the tenant.</small></p></div>
  </div>

  <div class="section" id="checks">
    <h2>Check results</h2>
    <p class="section-lead">One row per check, problems and gaps first. &quot;Findings&quot; counts confirmed problems by severity (C = Critical, H = High, M = Medium, L = Low, Info = notes) plus findings that could not be assessed.</p>
    <div class="toolbar"><div class="filters"><label><small>Show</small><br><select id="checkFilter"><option value="all">All checks</option><option value="attention">Needs attention</option><option value="findings">Problems found</option><option value="gaps">Gaps (incomplete, skipped, errors)</option><option value="pass">Passed</option><option value="notrun">Not run</option></select></label></div><div><small>Showing <span id="checkCount">$($cov.Rows.Count)</span> of $($cov.Rows.Count)</small></div></div>
    <table id="checkTable"><thead><tr><th style="text-align:left">Check</th><th style="text-align:left">Result</th><th style="text-align:left">Findings</th><th style="text-align:left">Why / details</th><th style="text-align:left">Evidence</th></tr></thead><tbody>$($statusRows -join "`n")</tbody></table>
  </div>

  <div class="section" id="run-details">
    <h2>Run details</h2>
    $runHtml
  </div>

  <div class="footer">Generated by $(HtmlEncode $ver) &mdash; read-only Microsoft Graph and optional Azure Resource Manager audit.</div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Write-RawDataIndexReport {
    param([string]$Path, [string]$TenantName, [string]$GeneratedOn, [object[]]$Items)
    if ($null -eq $Items) { $Items = Get-EntraFindingList }
    $css = (Get-EntraMainCss) + "`n" + (Get-EntraRawCss)
    $nav = Get-EntraPrimaryNav 'raw'
    $js  = Get-EntraRawJs
    $datasets = @(Get-EntraDatasetIndex -Items $Items)
    # The "used by findings" list on each dataset page can only be filled in now that
    # every check has finished.
    Write-EntraDatasetUsage -Datasets $datasets

    $rows = foreach ($d in $datasets) {
        $checkCell = if ($d.CheckId) { "<a href='Posture-Summary.html#check-$(HtmlAttrEncode $d.CheckId)'>$(HtmlEncode $(if ($d.CheckTitle) { $d.CheckTitle } else { $d.CheckId }))</a><span class='sub mono'>$(HtmlEncode $d.CheckId)</span>" } else { "<span class='muted'>-</span>" }
        $notes = if (@($d.Notes).Count -gt 0) { "<span class='sub'>$((@($d.Notes) | ForEach-Object { HtmlEncode $_ }) -join ' &middot; ')</span>" } else { '' }
        $errs = if (@($d.Errors).Count -gt 0) { "<div class='raw-err'>$((@($d.Errors) | ForEach-Object { HtmlEncode $_ }) -join '<br>')</div>" } else { '' }
        $rowsCell = if ($d.Rows -eq 0) { "0 <span class='muted'>(no data)</span>" } else { [string]$d.Rows }
        $used = $d.UsedBy.Count
        $usedCell = if ($used -gt 0) {
            $first = $d.UsedBy[0]
            "<a href='EntraAudit-Results.html#$(HtmlAttrEncode (New-FindingAnchor $first))'>$used finding$(if ($used -ne 1) { 's' })</a>"
        } else { "<span class='muted'>none</span>" }
        $links = @()
        foreach ($l in @(@{ H = $d.HtmlHref; L = 'HTML'; D = $false }, @{ H = $d.CsvHref; L = 'CSV'; D = $true }, @{ H = $d.TxtHref; L = 'TXT'; D = $true })) {
            if ($l.H) { $links += "<a href='$(HtmlAttrEncode (Resolve-SourceHref $l.H))'$(if ($l.D) { ' download' })>$($l.L)</a>" }
            else { $links += "<span class='raw-err' title='This file could not be written'>$($l.L) missing</span>" }
        }
        "<tr data-check='$(HtmlAttrEncode $d.CheckId)'><td><b>$(HtmlEncode $d.Title)</b><span class='sub mono'>$(HtmlEncode $d.BaseName)</span>$notes$errs</td><td>$checkCell</td><td class='num' data-sort='$($d.Rows)'>$rowsCell</td><td class='num' data-sort='$used'>$usedCell</td><td>$($links -join ' &middot; ')</td></tr>"
    }
    if (-not $rows) { $rows = @("<tr class='no-data'><td colspan='5'>No evidence datasets were written in this run.</td></tr>") }
    $total = $datasets.Count
    $empty = @($datasets | Where-Object { $_.Rows -eq 0 }).Count
    $failed = @($datasets | Where-Object { @($_.Errors).Count -gt 0 }).Count
    $failedText = if ($failed -gt 0) { " <b class='raw-err'>$failed dataset(s) could not be written completely - see the red notes below.</b>" } else { '' }
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
          Every check writes its full evidence as a styled HTML table, a CSV (data) and a TXT (plain text). <b>$total</b> dataset(s), $empty of them empty (the check found no matching objects).$failedText
        </div>
      </div>
      <div class="hero-actions"><button type="button" class="theme-toggle" id="themeToggle">Dark mode</button></div>
    </div>
  </section>
  <section class="toolbar">
    <div class="toolbar-row"><div class="filter"><label for="rawSearch">Filter datasets</label><input id="rawSearch" type="text" placeholder="Type to filter by name, check or note..."></div></div>
    <div class="raw-status"><span id="rawCount" data-noun="datasets">$total of $total datasets shown</span> &middot; Click a column heading to sort.</div>
    <div class="check-note" id="checkFilterNote" style="display:none">Showing only datasets from check <b class="mono" id="checkFilterName"></b>. <a href="#" id="clearCheckFilter">Show all datasets</a></div>
  </section>
  <div class="raw-table-wrap">
  <table class="result-table raw-table sortable">
    <thead><tr><th>Dataset</th><th>Produced by check</th><th class="num">Rows</th><th class="num">Used by</th><th>Open / download</th></tr></thead>
    <tbody>
      $($rows -join "`n")
    </tbody>
  </table>
  </div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

# The findings as an array, whatever collection type $script:Findings is. NB: never wrap
# a generic List in @() - on PowerShell 7.6.x that throws "Argument types do not match".
function Get-EntraFindingList {
    if ($null -eq $script:Findings) { return ,@() }
    if ($script:Findings -is [System.Collections.Generic.List[object]]) { return ,$script:Findings.ToArray() }
    return ,@($script:Findings | ForEach-Object { $_ })
}

# Users / Guests / Applications tiles. Counts come from the shared caches whenever they
# were filled by ANY check (e.g. appcredentials fills the app cache even when the apps
# check was excluded); '-' means the population was never read in this run.
function Get-EntraReportStatistic {
    $users = $script:UsersCache
    $apps = if ($null -ne $script:AppsCache) { $script:AppsCache.Count }
            elseif ($null -ne $script:AppCount -and [string]$script:AppCount -match '^\d+$') { [int]$script:AppCount }
            else { '-' }
    @{
        Users  = $(if ($null -ne $users) { $users.Count } else { '-' })
        Guests = $(if ($null -ne $users) { ($users | Where-Object { $_.UserType -eq 'Guest' } | Measure-Object).Count } else { '-' })
        Apps   = $apps
    }
}

# Tolerant read of one $script:RunInfo field (RunInfo may be missing or partial, e.g. in
# offline rendering or when the run stopped early).
function Get-EntraRunValue {
    param([object]$RunInfo, [string]$Name)
    if ($null -eq $RunInfo) { return $null }
    try { return (Get-EAField $RunInfo $Name) } catch { return $null }
}

function Format-EntraRunTime {
    param($Value)
    if ($null -eq $Value -or '' -eq [string]$Value) { return '' }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }
    if ($Value -is [datetime]) {
        $v = if ($Value.Kind -eq [System.DateTimeKind]::Local) { $Value.ToUniversalTime() } else { $Value }
        return $v.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    }
    return [string]$Value
}

function Format-EntraDuration {
    param([double]$Seconds)
    $ts = [timespan]::FromSeconds([math]::Max(0, $Seconds))
    if ($ts.TotalHours -ge 1) { return ('{0} h {1} min' -f [int][math]::Floor($ts.TotalHours), $ts.Minutes) }
    if ($ts.TotalMinutes -ge 1) { return ('{0} min {1} s' -f $ts.Minutes, $ts.Seconds) }
    return ('{0} s' -f [int][math]::Round($ts.TotalSeconds))
}

# Run duration from RunInfo.DurationSeconds, else Started/Finished, else Started -> now
# (the reports are written before the run is formally finished).
function Get-EntraRunDurationText {
    param([object]$RunInfo)
    $d = Get-EntraRunValue $RunInfo 'DurationSeconds'
    if ($null -ne $d -and '' -ne [string]$d) { try { return (Format-EntraDuration ([double]$d)) } catch { Write-Verbose "Unreadable DurationSeconds: $d" } }
    $start = Get-EntraRunValue $RunInfo 'StartedUtc'
    if (-not $start) { return '' }
    try {
        $s = if ($start -is [datetime]) { $start } else { [datetime]::Parse([string]$start, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) }
        if ($s.Kind -eq [System.DateTimeKind]::Local) { $s = $s.ToUniversalTime() }
        $end = Get-EntraRunValue $RunInfo 'FinishedUtc'
        if ($end) {
            $e = if ($end -is [datetime]) { $end } else { [datetime]::Parse([string]$end, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) }
            if ($e.Kind -eq [System.DateTimeKind]::Local) { $e = $e.ToUniversalTime() }
            return (Format-EntraDuration ($e - $s).TotalSeconds)
        }
        return ((Format-EntraDuration ([datetime]::UtcNow - $s).TotalSeconds) + ' (until the reports were written)')
    } catch { return '' }
}

# License SKU detail for the Posture Summary: a table of $script:LicenseSkus objects
# (whatever properties license detection recorded), else the SKU names in RunInfo.
function ConvertTo-EntraLicenseSkuHtml {
    param([object]$RunInfo)
    $skus = @($script:LicenseSkus | Where-Object { $null -ne $_ })
    if ($skus.Count -gt 0 -and -not ($skus[0] -is [string])) {
        $cols = New-Object System.Collections.Generic.List[string]
        foreach ($s in $skus) { foreach ($p in $s.PSObject.Properties) { if (-not $cols.Contains($p.Name)) { $cols.Add($p.Name) | Out-Null } } }
        $head = ($cols | ForEach-Object { "<th style='text-align:left'>$(HtmlEncode $_)</th>" }) -join ''
        $body = foreach ($s in $skus) {
            '<tr>' + (($cols | ForEach-Object { $p = $s.PSObject.Properties[$_]; "<td>$(HtmlEncode $(if ($p) { ConvertTo-EntraEvidenceCell $p.Value } else { '' }))</td>" }) -join '') + '</tr>'
        }
        return "<h3>Subscribed licenses ($($skus.Count))</h3><table>$("<thead><tr>$head</tr></thead>")<tbody>$($body -join '')</tbody></table>"
    }
    $names = @()
    if ($skus.Count -gt 0) { $names = @($skus | ForEach-Object { [string]$_ }) }
    else {
        $lic = Get-EntraRunValue $RunInfo 'Licenses'
        $ls = if ($lic) { Get-EntraRunValue $lic 'Skus' } else { $null }
        if ($ls) { $names = @($ls | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
    }
    if ($names.Count -gt 0) { return "<h3>Subscribed licenses ($($names.Count))</h3><p>" + (($names | ForEach-Object { "<span class='chip mono'>$(HtmlEncode $_)</span>" }) -join '') + '</p>' }
    return ''
}

# Run details panel (Posture Summary): who ran what, when, with which permissions and
# settings - so a run can be reproduced and two runs compared. Falls back to script state
# for the fields RunInfo does not carry; says so when details were not recorded.
function ConvertTo-EntraRunDetailsHtml {
    param([object]$RunInfo, [string]$TenantName, [object]$Coverage)
    $chips = { param($list) $l = @($list | Where-Object { $_ } | ForEach-Object { [string]$_ }); if ($l.Count -eq 0) { "<span class='muted'>None</span>" } else { ($l | ForEach-Object { "<span class='chip mono'>$(HtmlEncode $_)</span>" }) -join '' } }
    $kv = New-Object System.Collections.Generic.List[string]
    $add = { param([string]$k, [string]$vHtml) if ($vHtml) { $kv.Add("<tr><th>$(HtmlEncode $k)</th><td>$vHtml</td></tr>") | Out-Null } }
    $val = { param($n) Get-EntraRunValue $RunInfo $n }
    $ver = & $val 'ToolVersion'; if (-not $ver) { $ver = $script:Version }
    & $add 'Tool version' (HtmlEncode $ver)
    $tn = & $val 'TenantName'; if (-not $tn) { $tn = $TenantName }
    & $add 'Tenant' (HtmlEncode $tn)
    $tid = & $val 'TenantId'; if ($tid) { & $add 'Tenant id' "<span class='mono'>$(HtmlEncode $tid)</span>" }
    $mode = & $val 'AuthMode'; if (-not $mode) { $mode = $script:AuthType }
    $modeText = switch ([string]$mode) { 'AppOnly' { 'App-only (certificate, unattended)' } 'Delegated' { 'Delegated (an administrator signed in)' } default { [string]$mode } }
    & $add 'Sign-in mode' (HtmlEncode $modeText)
    $acct = & $val 'Account'; if ($acct) { & $add 'Account / app' "<span class='mono'>$(HtmlEncode $acct)</span>" }
    $st = & $val 'StartedUtc'; if ($st) { & $add 'Started' (HtmlEncode (Format-EntraRunTime $st)) }
    $fi = & $val 'FinishedUtc'; if ($fi) { & $add 'Finished' (HtmlEncode (Format-EntraRunTime $fi)) }
    $dur = Get-EntraRunDurationText $RunInfo; if ($dur) { & $add 'Duration' (HtmlEncode $dur) }
    if ($Coverage) {
        $selIds = @($Coverage.Rows | Where-Object { $_.Selected } | ForEach-Object { $_.CheckId })
        & $add 'Checks selected' ("<b>$($selIds.Count)</b> of $($Coverage.Total)<br>" + (& $chips $selIds))
    }
    $exc = & $val 'ExcludedChecks'
    if ($null -ne $exc) { & $add 'Checks excluded' (& $chips $exc) }
    $settings = & $val 'Settings'
    if ($settings -is [System.Collections.IDictionary] -and $settings.Count -gt 0) {
        $srows = foreach ($k in $settings.Keys) { "<span class='chip'>$(HtmlEncode ([string]$k)) = <span class='mono'>$(HtmlEncode (ConvertTo-EntraEvidenceCell $settings[$k]))</span></span>" }
        & $add 'Settings used' ($srows -join '')
    } elseif ($settings) {
        $srows = foreach ($p in $settings.PSObject.Properties) { "<span class='chip'>$(HtmlEncode $p.Name) = <span class='mono'>$(HtmlEncode (ConvertTo-EntraEvidenceCell $p.Value))</span></span>" }
        & $add 'Settings used' ($srows -join '')
    }
    $scopes = & $val 'GrantedScopes'
    if ($null -ne $scopes) {
        $sl = @($scopes | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        & $add 'Permissions granted' ("<b>$($sl.Count)</b><br>" + (& $chips $sl))
    }
    $lic = & $val 'Licenses'
    $licText = "P1=$($script:HasP1), P2=$($script:HasP2), Workload Identities Premium=$($script:WorkloadIdP)" + $(if (-not $script:LicenseKnown) { ' (detection failed)' } else { '' })
    if ($lic) {
        $lp = { param($n) Get-EntraRunValue $lic $n }
        $licText = "P1=$(& $lp 'P1'), P2=$(& $lp 'P2'), Workload Identities Premium=$(& $lp 'WorkloadIdPremium')" + $(if ($false -eq (& $lp 'Known')) { ' (detection failed)' } else { '' })
    }
    & $add 'Licenses' (HtmlEncode $licText)
    $ps = & $val 'PowerShellVersion'; if (-not $ps) { $ps = [string]$PSVersionTable.PSVersion }
    & $add 'PowerShell' (HtmlEncode $ps)
    $gv = & $val 'GraphModuleVersion'; if ($gv) { & $add 'Microsoft Graph SDK' (HtmlEncode $gv) }
    $log = & $val 'LogFile'
    if ($log) {
        $lh = '../' + (([string]$log) -replace '\\', '/')
        & $add 'Run log' "<a href='$(HtmlAttrEncode (Resolve-SourceHref $lh))'>$(HtmlEncode $log)</a>"
    }
    $partial = if ($null -eq $RunInfo -or -not (& $val 'StartedUtc')) { "<p style='margin-top:8px'><small>Some run details (start time, account, permissions) were not recorded for this report.</small></p>" } else { '' }
    "<table class='kv'><tbody>$($kv -join '')</tbody></table>$partial"
}

# Datasets for the Raw Data index / Posture Summary / Findings.json, each with the
# findings that cite it (UsedBy, matched on SourceFile) and the producing check. A
# dataset whose check could not be recorded inherits it from the findings that cite it.
# A BaseName written twice keeps only its last entry (the files were overwritten).
function Get-EntraDatasetIndex {
    param([object[]]$Items)
    if ($null -eq $Items) { $Items = Get-EntraFindingList }
    $byName = [ordered]@{}
    foreach ($d in $script:RawDatasets) {
        if ($null -eq $d) { continue }
        $prop = { param($n) if ($d.PSObject.Properties[$n]) { $d.$n } else { $null } }
        $html = & $prop 'HtmlHref'; $csv = & $prop 'CsvHref'; $txt = & $prop 'TxtHref'
        $src = & $prop 'SourceHref'; if (-not $src) { $src = if ($html) { $html } else { $csv } }
        $cid = [string](& $prop 'CheckId')
        $ct = [string](& $prop 'CheckTitle')
        if ($byName.Contains([string]$d.BaseName)) { $byName.Remove([string]$d.BaseName) }
        $byName[[string]$d.BaseName] = [pscustomobject]@{
            BaseName = [string]$d.BaseName; Title = [string]$d.Title; Rows = [int]$d.Rows
            CheckId = $cid; CheckTitle = $ct
            Notes = @(& $prop 'Notes' | Where-Object { $_ })
            HtmlHref = $html; CsvHref = $csv; TxtHref = $txt; SourceHref = $src
            Errors = @(& $prop 'Errors' | Where-Object { $_ })
            UsedBy = (New-Object System.Collections.Generic.List[object])
        }
    }
    $byHref = @{}
    foreach ($e in $byName.Values) { foreach ($h in @($e.HtmlHref, $e.CsvHref, $e.SourceHref)) { if ($h) { $byHref[[string]$h] = $e } } }
    foreach ($f in $Items) {
        $s = [string]$f.SourceFile
        if ($s -and $byHref.ContainsKey($s)) { $byHref[$s].UsedBy.Add($f) | Out-Null }
    }
    foreach ($e in $byName.Values) {
        if (-not $e.CheckId -and $e.UsedBy.Count -gt 0) {
            $e.CheckId = [string](@($e.UsedBy | Group-Object { [string]$_.CheckId } | Sort-Object Count -Descending)[0].Name)
        }
        if ($e.CheckId -and -not $e.CheckTitle -and $script:Registry -and $script:Registry.Contains($e.CheckId)) { $e.CheckTitle = [string]$script:Registry[$e.CheckId].Title }
    }
    foreach ($e in $byName.Values) { $e }
}

# Fills the <!--EA-USEDBY--> marker of every dataset page with the findings that cite
# it. A page that cannot be updated keeps working (it only lacks the list); the failure
# is warned about rather than hidden.
function Write-EntraDatasetUsage {
    param([object[]]$Datasets)
    if (-not $script:RawDir) { return }
    foreach ($e in $Datasets) {
        if (-not $e.HtmlHref) { continue }
        $file = Join-Path $script:RawDir ($e.BaseName + '.html')
        try {
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
            $html = Get-Content -LiteralPath $file -Raw -Encoding UTF8 -ErrorAction Stop
            if ($html.IndexOf('<!--EA-USEDBY-->') -lt 0) { continue }
            $n = $e.UsedBy.Count
            $block = if ($n -gt 0) {
                $li = foreach ($f in @($e.UsedBy | Select-Object -First 50)) {
                    $sev = Normalize-Severity $f.Severity
                    $gap = if (Test-EntraCoverageGap $f) { " <span class='badge sev-Information'>Not assessed</span>" } else { '' }
                    "<li><span class='badge sev-$sev'>$sev</span><a href='../../HTML Reports/EntraAudit-Results.html#$(HtmlAttrEncode (New-FindingAnchor $f))'>$(HtmlEncode $f.Title)</a>$gap</li>"
                }
                $more = if ($n -gt 50) { "<li>... and $($n - 50) more in the <a href='../../HTML Reports/EntraAudit-Results.html'>audit results</a>.</li>" } else { '' }
                # Long lists start collapsed so the table stays near the top of the page.
                "<details class='raw-used'$(if ($n -le 8) { ' open' })><summary>Findings that use this dataset ($n)</summary><ul>$($li -join '')$more</ul></details>"
            } else {
                "<div class='raw-used muted'>No finding refers to this dataset: it is background evidence recorded by the check.</div>"
            }
            Set-Content -LiteralPath $file -Value $html.Replace('<!--EA-USEDBY-->', $block) -Encoding UTF8 -NoNewline -ErrorAction Stop
        } catch {
            Write-Warn2 "Could not add the 'used by findings' list to '$($e.BaseName).html': $($_.Exception.Message)"
        }
    }
}

# Machine-readable exports (automation / trend comparison) with a stable finding id.
#   Findings.csv  - flat table, one row per finding (spreadsheet-safe values).
#   Findings.json - one object: SchemaVersion, GeneratedUtc, RunInfo, Score, CheckStatus
#                   (EVERY registry check, including 'NotRun' ones, so "not run" or
#                   "skipped" can never be mistaken for "clean" when two runs are
#                   compared), Datasets and Findings.
# FindingId uses the effective Rule (RuleId, else the digit-stripped title slug); IssueKey
# is the (check|rule|severity) key the risk score and the reports group by.
# Each file is written on its own with -ErrorAction Stop, so one failure is reported and
# does not stop the other.
function Export-EntraAuditData {
    param([string]$RunRoot, [string]$TenantId, [pscustomobject]$Score, [object[]]$Items, [object]$RunInfo = $script:RunInfo)
    if ($null -eq $Items) { $Items = Get-EntraFindingList }
    if ($null -eq $Score) { $Score = Get-EntraRiskScore $Items }
    $rows = foreach ($f in $Items) {
        [pscustomobject][ordered]@{
            FindingId         = (New-FindingKey -TenantId $TenantId -Finding $f)
            Severity          = $f.Severity
            Category          = $f.Category
            CheckId           = $f.CheckId
            RuleId            = $f.RuleId
            Rule              = (Get-FindingRule $f)
            IssueKey          = (Get-EntraIssueKey $f).Key
            ObjectType        = $f.ObjectType
            ObjectId          = $f.ObjectId
            Title             = $f.Title
            AffectedPrincipal = $f.AffectedPrincipal
            Evidence          = $f.Evidence
            WhyItMatters      = $f.WhyItMatters
            RecommendedAction = $f.RecommendedAction
            DocumentationUrl  = $f.DocumentationUrl
            SourceFile        = $f.SourceFile
            CoverageGap       = [bool](Test-EntraCoverageGap $f)
        }
    }
    $rows = @($rows)
    try {
        # utf8BOM so Excel decodes non-ASCII display names / UPNs correctly.
        ConvertTo-SafeCsvRows $rows | Export-Csv -LiteralPath (Join-Path $RunRoot 'Findings.csv') -NoTypeInformation -Encoding utf8BOM -ErrorAction Stop
    } catch { Write-Warn2 "Could not write Findings.csv: $($_.Exception.Message)" }

    try {
        $cov = if ($Score.Coverage) { $Score.Coverage } else { Get-EntraRunCoverage -RunInfo $RunInfo }
        $datasets = @(Get-EntraDatasetIndex -Items $Items)
        $idByAnchor = @{}
        for ($i = 0; $i -lt $rows.Count; $i++) { $idByAnchor[(New-FindingAnchor $Items[$i])] = $rows[$i].FindingId }
        $toRunRel = { param($h) if ($h) { ([string]$h) -replace '^\.\./', '' } else { $null } }
        $dsJson = foreach ($d in $datasets) {
            [ordered]@{
                BaseName = $d.BaseName; Title = $d.Title; CheckId = $(if ($d.CheckId) { $d.CheckId } else { $null }); Rows = $d.Rows
                Notes = @($d.Notes); Errors = @($d.Errors)
                Files = [ordered]@{ Html = (& $toRunRel $d.HtmlHref); Csv = (& $toRunRel $d.CsvHref); Txt = (& $toRunRel $d.TxtHref) }
                UsedByFindingIds = @($d.UsedBy | ForEach-Object { $idByAnchor[(New-FindingAnchor $_)] } | Where-Object { $_ })
            }
        }
        $checks = foreach ($r in $cov.Rows) {
            [ordered]@{
                CheckId = $r.CheckId; Title = $r.Title; Selected = $r.Selected
                Status = $(if ($r.Group -eq 'notrun') { 'NotRun' } else { $r.Status }); Result = $r.Label; Reason = $r.Reason
                ErrorMessage = $r.ErrorMessage; MissingScopes = @($r.MissingScopes)
                Count = $r.Count; InfoCount = $r.InfoCount; CoverageCount = $r.CoverageCount; Partial = $r.Partial
                DurationSeconds = $r.DurationSeconds
                Datasets = @($datasets | Where-Object { $_.CheckId -eq $r.CheckId } | ForEach-Object { $_.BaseName })
            }
        }
        $findingsJson = for ($i = 0; $i -lt $rows.Count; $i++) {
            $o = [ordered]@{}
            foreach ($p in $rows[$i].PSObject.Properties) { $o[$p.Name] = $p.Value }
            $o['ReportLink'] = 'HTML Reports/EntraAudit-Results.html#' + (New-FindingAnchor $Items[$i])
            $o
        }
        $doc = [ordered]@{
            SchemaVersion = 2
            GeneratedUtc  = [datetime]::UtcNow.ToString('o')
            RunInfo       = $RunInfo
            Score         = [ordered]@{
                Score = $Score.Score; Band = $Score.Band; ScoreBand = $Score.ScoreBand
                ConfirmedScore = $Score.ConfirmedScore; NotAssessedPoints = $Score.NotAssessedPoints
                CoverageComplete = $Score.CoverageComplete
                Counts = [ordered]@{ Critical = $Score.Critical; High = $Score.High; Medium = $Score.Medium; Low = $Score.Low; Information = $Score.Information }
                ConfirmedCounts = $Score.ConfirmedCounts; NotAssessedCounts = $Score.NotAssessedCounts
                Coverage = [ordered]@{ Total = $cov.Total; Selected = $cov.Selected; Evaluated = $cov.Evaluated; FullyEvaluated = $cov.FullyEvaluated; Clean = $cov.Clean; WithFindings = $cov.WithFindings; Incomplete = $cov.Incomplete; Skipped = $cov.Skipped; Errored = $cov.Errored; NotRun = $cov.NotRun }
                Drivers = @($Score.Drivers | ForEach-Object { [ordered]@{ IssueKey = $_.Key; Severity = $_.Severity; CheckId = $_.CheckId; Rule = $_.Rule; Title = $_.Title; Count = $_.Count; Points = $_.Points; Share = $_.Share; CoverageGap = $_.CoverageGap } })
            }
            CheckStatus   = @($checks)
            Datasets      = @($dsJson)
            Findings      = @($findingsJson)
        }
        ConvertTo-Json -InputObject $doc -Depth 8 | Set-Content -LiteralPath (Join-Path $RunRoot 'Findings.json') -Encoding UTF8 -ErrorAction Stop
    } catch { Write-Warn2 "Could not write Findings.json: $($_.Exception.Message)" }
}

# Posture page script: theme toggle plus the check-results filter.
function Get-EntraRiskJs2 {
@'
<script>
(function(){
  function q(s){return document.querySelector(s);}
  function currentTheme(){var s=null;try{s=localStorage.getItem('entraaudit-theme');}catch(e){}if(s==='light'||s==='dark')return s;if(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)return 'dark';return 'light';}
  function applyTheme(t){document.documentElement.setAttribute('data-theme',t);var b=q('#themeToggle');if(b){b.innerText=(t==='dark')?'Light mode':'Dark mode';}try{localStorage.setItem('entraaudit-theme',t);}catch(e){}}
  applyTheme(currentTheme());
  var tb=q('#themeToggle');if(tb){tb.addEventListener('click',function(){var n=(document.documentElement.getAttribute('data-theme')==='dark')?'light':'dark';applyTheme(n);});}
  var cf=q('#checkFilter');
  function apply(){if(!cf)return;var v=cf.value;var shown=0;Array.prototype.slice.call(document.querySelectorAll('#checkTable tbody tr')).forEach(function(r){var g=(r.getAttribute('data-group')||'').split(' ');var ok=v==='all'||(v==='attention'?(g.indexOf('findings')>=0||g.indexOf('gaps')>=0):g.indexOf(v)>=0);if(!ok&&location.hash==='#'+r.id)ok=true;r.style.display=ok?'':'none';if(ok)shown++;});var c=q('#checkCount');if(c)c.textContent=shown;}
  if(cf)cf.addEventListener('change',apply);
  apply();
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

    # Run context for the reports and exports (the $script:RunInfo contract). It is filled
    # in as the run progresses; report writers tolerate any field that is still $null.
    $runStarted = [datetime]::UtcNow
    $script:RunInfo = [ordered]@{
        ToolVersion        = $script:Version
        StartedUtc         = $runStarted
        FinishedUtc        = $null
        DurationSeconds    = $null
        AuthMode           = $null
        Account            = $null
        TenantId           = $null
        TenantName         = $null
        GrantedScopes      = [string[]]@()
        SelectedChecks     = [string[]]@()
        ExcludedChecks     = [string[]]@()
        Settings           = [ordered]@{
            InactiveDays           = $InactiveDays
            ExpiringCredentialDays = $ExpiringCredentialDays
            RecentChangeDays       = $RecentChangeDays
            StaleAppDays           = $StaleAppDays
            BreakGlassUpnsCount    = @(Normalize-StringList -Values $BreakGlassUpns).Count   # count only - names stay out of the report
            DelegatedClientId      = $(if ($DelegatedClientId) { $DelegatedClientId } else { $null })
            UseDeviceCode          = [bool]$UseDeviceCode
            OfflineModulesPath     = [bool]$ModulesPath
        }
        PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
        GraphModuleVersion = $null
        Licenses           = [ordered]@{ P1 = $false; P2 = $false; WorkloadIdPremium = $false; Known = $false; Skus = [string[]]@(); Notes = [string[]]@() }
        LogFile            = $null
    }

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
    $graphAuthModule = Get-Module -Name Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
    if ($graphAuthModule) { $script:RunInfo.GraphModuleVersion = $graphAuthModule.Version.ToString() }

    # Decide which checks to run. -select/-exclude accept both registry ids
    # (privileged-roles) and switch-style aliases (privroles, the form the GUI emits),
    # comma- or semicolon-separated. An unknown -select id stops the run (exit code 1): a
    # typo in a scheduled task must not quietly run nothing, or less than intended.
    $exc = @()
    if ($select -and $select.Count) {
        $sel = @(Resolve-CheckIds -Values $select -ParameterName '-select' -FailOnUnknown)
        $toRun = @($script:Registry.Keys | Where-Object { $sel -contains $_ })
        if ($exclude) { Write-Warn2 "-exclude is ignored because -select is used (-select already names exactly the checks to run)." }
    } elseif ($all -or -not $anySelected) {
        $exc = if ($exclude) { @(Resolve-CheckIds -Values $exclude -ParameterName '-exclude') } else { @() }
        $toRun = @($script:Registry.Keys | Where-Object { $exc -notcontains $_ })
        if ($exc.Count -gt 0) { Write-Info ("Excluded from this run: {0}" -f ($exc -join ', ')) }
    } else {
        $toRun = @($script:Registry.Keys | Where-Object { $individual[$_] })
        if ($exclude) { Write-Warn2 "-exclude is ignored because individual check switches are used (-exclude only applies to a run of all checks)." }
    }
    if ($toRun.Count -eq 0) {
        # A run that does nothing must not look successful: the entry point turns this into exit code 1.
        throw 'No checks selected - nothing to run. Compare the -select / -exclude values with the check ids in README.md.'
    }
    $script:RunInfo.SelectedChecks = [string[]]@($toRun)
    $script:RunInfo.ExcludedChecks = [string[]]@($exc)

    # Connect (read-only)
    $ctx = Connect-EntraAuditGraph
    $script:RunInfo.AuthMode = $script:AuthType
    $script:RunInfo.TenantId = [string]$ctx.TenantId
    $script:RunInfo.Account  = if ($script:AuthType -eq 'AppOnly') {
        if ($ctx.ClientId) { [string]$ctx.ClientId } else { [string]$ClientId }
    } else { [string]$ctx.Account }
    $granted = if ($script:AuthType -eq 'AppOnly') { $script:AppOnlyGrantedPermissions } else { $ctx.Scopes }
    $script:RunInfo.GrantedScopes = [string[]]@($granted | Where-Object { $_ } | Sort-Object -Unique)

    # Say up front which selected checks this sign-in cannot run (each is also recorded as
    # Skipped-NoScope with the missing permission names for the reports).
    $preSkip = @(foreach ($id in $toRun) {
        $m = @(Get-EAMissingScope -Required @($script:Registry[$id].Scopes))
        if ($m.Count -gt 0) { '{0} (needs {1})' -f $id, ($m -join ', ') }
    })
    if ($preSkip.Count -gt 0) {
        Write-Warn2 ("{0} of {1} selected check(s) will be skipped because the sign-in lacks a permission: {2}" -f $preSkip.Count, $toRun.Count, ($preSkip -join '; '))
    }

    # Tenant name. A failed read is not fatal (the tenant id names the run folder instead),
    # but it is recorded and printed, never swallowed.
    try {
        $script:Tenant = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
    } catch {
        $script:TenantReadError = $_.Exception.Message
        Write-Warn2 "Could not read the organization details ($($_.Exception.Message)) - the tenant id is used as the tenant name."
    }

    # License detection from enabled SERVICE PLANS (not just SKU part number) - many
    # tenants get Entra P1/P2 bundled inside other SKUs (e.g. EMS, M365 E3/E5).
    # Only subscriptions that can serve licenses count: a lapsed subscription (Suspended,
    # Deleted, LockedOut, or no active units) still lists its plans, and counting it would
    # run license-gated checks whose 403s then look like missing permissions. 'Warning'
    # (grace period) still serves, so it counts - its units move from Enabled to Warning.
    # A FAILED read must not masquerade as 'no license': track it so gated checks are
    # reported as 'license unknown' instead of a false 'Skipped-NoLicense'.
    $licenseLabels = @{ P1 = 'Entra ID P1'; P2 = 'Entra ID P2'; WorkloadIdPremium = 'Workload ID Premium' }
    $skuRows = New-Object System.Collections.Generic.List[object]
    $licNotes = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($sku in @(Get-MgSubscribedSku -All -ErrorAction Stop)) {
            $enabledPlans = @($sku.ServicePlans | Where-Object { $_.ProvisioningStatus -eq 'Success' } | ForEach-Object { $_.ServicePlanName })
            $grants = @()
            if ($sku.SkuPartNumber -eq 'AAD_PREMIUM_P2' -or $enabledPlans -contains 'AAD_PREMIUM_P2') { $grants += 'P2' }
            if ($sku.SkuPartNumber -eq 'AAD_PREMIUM'    -or $enabledPlans -contains 'AAD_PREMIUM')    { $grants += 'P1' }
            # Workload ID SKUs are 'Workload_Identities_*'; their service plans are AAD_WRKLDID_P1/P2.
            if ($sku.SkuPartNumber -match '(?i)^Workload_Identities' -or @($enabledPlans | Where-Object { $_ -match '(?i)^AAD_WRKLDID_P[12]$' }).Count -gt 0) { $grants += 'WorkloadIdPremium' }

            $capability = [string]$sku.CapabilityStatus
            $units = $sku.PrepaidUnits
            $enabledUnits = if ($units -and $null -ne $units.Enabled) { [int]$units.Enabled } else { $null }
            $warningUnits = if ($units -and $null -ne $units.Warning) { [int]$units.Warning } else { 0 }
            $activeUnits  = if ($null -ne $enabledUnits) { $enabledUnits + $warningUnits } else { $null }
            # A missing status or unit count (older SDK shapes) keeps the previous behaviour: counted.
            $usable = ((-not $capability) -or ($capability -in @('Enabled','Warning'))) -and (($null -eq $activeUnits) -or ($activeUnits -gt 0))
            $provides = ($grants | ForEach-Object { $licenseLabels[$_] }) -join ' + '
            $skuRows.Add([pscustomobject]@{
                SkuPartNumber = [string]$sku.SkuPartNumber; CapabilityStatus = $capability
                ActiveUnits = $activeUnits; ConsumedUnits = $sku.ConsumedUnits
                Provides = $provides; CountedAsLicensed = $usable
            })
            if ($grants.Count -eq 0) { continue }
            if (-not $usable) {
                $licNotes.Add(("{0} ({1}) is in the tenant but not usable - subscription status '{2}', {3} active license(s) - so it was not counted." -f
                    $sku.SkuPartNumber, $provides, $(if ($capability) { $capability } else { 'unknown' }), $(if ($null -ne $activeUnits) { $activeUnits } else { 'unknown' })))
                continue
            }
            if ($capability -eq 'Warning') {
                $licNotes.Add(("{0} ({1}) has expired and is in its grace period (status 'Warning') - counted, but these features stop when the grace period ends." -f $sku.SkuPartNumber, $provides))
            }
            if ($grants -contains 'P2') { $script:HasP2 = $true }
            if ($grants -contains 'P1') { $script:HasP1 = $true }
            if ($grants -contains 'WorkloadIdPremium') { $script:WorkloadIdP = $true }
        }
        if ($script:HasP2) { $script:HasP1 = $true }
    } catch {
        $script:LicenseKnown = $false
        Write-Warn2 "License (SKU) detection failed: $($_.Exception.Message) - license-gated checks will be reported as 'license unknown', not 'no license'."
    }
    # .ToArray(): @() over a New-Object generic list throws 'Argument types do not match' in pwsh 7.4.
    $script:LicenseSkus = $skuRows.ToArray()
    $script:LicenseNotes = $licNotes.ToArray()
    foreach ($note in $script:LicenseNotes) { Write-Warn2 "License: $note" }

    $tenantName = if ($script:Tenant -and $script:Tenant.DisplayName) { [string]$script:Tenant.DisplayName } else { [string]$ctx.TenantId }
    $script:RunInfo.TenantName = $tenantName
    $script:RunInfo.Licenses = [ordered]@{
        P1 = [bool]$script:HasP1; P2 = [bool]$script:HasP2; WorkloadIdPremium = [bool]$script:WorkloadIdP
        Known = [bool]$script:LicenseKnown
        Skus  = [string[]]@($skuRows | ForEach-Object {
            '{0} ({1}, {2}{3})' -f $_.SkuPartNumber,
                $(if ($_.CapabilityStatus) { $_.CapabilityStatus } else { 'status unknown' }),
                $(if ($null -ne $_.ActiveUnits) { "$($_.ActiveUnits) active" } else { 'units unknown' }),
                $(if ($_.CountedAsLicensed) { '' } else { ', not counted' })
        })
        Notes = [string[]]@($script:LicenseNotes)
    }
    Write-Good ("Tenant: {0} | Licensing P1={1} P2={2}" -f $tenantName, $script:HasP1, $script:HasP2)

    # Output folders (mirrors the AD audit layout). Seconds in the name plus a -2, -3 ...
    # suffix keep two runs started close together from writing into one folder: the run
    # folder is created WITHOUT -Force, so an existing folder is never reused.
    $safeTenant = ((($tenantName -replace '[^\w\.\- ]','_')).Trim()) -replace '\s+','_'
    if ([string]::IsNullOrWhiteSpace($safeTenant)) { $safeTenant = 'tenant' }
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    $root = if ($OutputRoot) { $OutputRoot } else { $PSScriptRoot }
    $baseRunRoot = Join-Path $root ("{0}-EntraAudit-{1}" -f $safeTenant, $ts)
    $script:RunRoot = $null
    for ($attempt = 1; $attempt -le 50 -and -not $script:RunRoot; $attempt++) {
        $candidate = if ($attempt -eq 1) { $baseRunRoot } else { '{0}-{1}' -f $baseRunRoot, $attempt }
        try {
            New-Item -ItemType Directory -Path $candidate -ErrorAction Stop | Out-Null
            $script:RunRoot = $candidate
        } catch [System.IO.IOException] {
            if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { throw }   # a real I/O failure, not "already exists"
        }
    }
    if (-not $script:RunRoot) { throw "Could not create a new run folder: $baseRunRoot and 49 numbered variants already exist." }
    $script:HtmlDir = Join-Path $script:RunRoot 'HTML Reports'
    $script:RawDir  = Join-Path $script:RunRoot 'Raw Data' 'Source'   # segment-wise: '\' is a literal filename char on non-Windows pwsh
    # Fail fast: if the output folders cannot be created, every later write fails too -
    # do not run the whole audit only to print 'Audit complete' over a missing report.
    New-Item -ItemType Directory -Force -Path $script:HtmlDir -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Force -Path $script:RawDir  -ErrorAction Stop | Out-Null
    Write-Info "Run folder: $($script:RunRoot)"
    $script:RunInfo.LogFile = Open-EARunLog -Folder $script:RunRoot

    # Run the selected checks
    Write-Host ""
    Write-Info ("Running {0} check(s)..." -f $toRun.Count)
    foreach ($id in $toRun) {
        $c = $script:Registry[$id]
        Invoke-AuditCheck -CheckId $id -Title $c.Title -Scopes $c.Scopes -NeedP1:([bool]$c.P1) -NeedP2:([bool]$c.P2) -Action ([scriptblock]::Create($c.Func))
    }
    $runFinished = [datetime]::UtcNow
    $script:RunInfo.FinishedUtc = $runFinished
    $script:RunInfo.DurationSeconds = [math]::Round(($runFinished - $runStarted).TotalSeconds, 1)

    # Build reports
    Write-Host ""
    Write-Info "Generating reports..."
    # Get-EntraRiskScore normalizes and counts every severity in one pass - reuse its
    # counts so the report cards and the score can never disagree. It also reads
    # $script:CheckStatus, so its Band never says 'Clean' while a selected check was
    # skipped, errored or incomplete.
    $findingItems = $script:Findings.ToArray()
    $score = Get-EntraRiskScore $findingItems
    $counts = @{ Critical=$score.Critical; High=$score.High; Medium=$score.Medium; Low=$score.Low; Information=$score.Information }
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'

    $stats = Get-EntraReportStatistic
    # Coverage in the Results subtitle: checks that were skipped by scope/license are not
    # counted as performed. Plain ASCII so it reads the same whether or not it is encoded.
    $cov = if ($score.Coverage) { $score.Coverage } else { Get-EntraRunCoverage }
    $covParts = @()
    if ($cov.Incomplete -gt 0) { $covParts += "$($cov.Incomplete) incomplete" }
    if ($cov.Skipped -gt 0)    { $covParts += "$($cov.Skipped) skipped" }
    if ($cov.Errored -gt 0)    { $covParts += "$($cov.Errored) with errors" }
    $covText = ("{0} of {1} selected check(s) gave a full result{2}" -f $cov.FullyEvaluated, $cov.Selected, $(if ($covParts.Count) { ' (' + ($covParts -join ', ') + ')' } else { '' }))
    $subtitle = ("Read-only Microsoft Graph and optional Azure Resource Manager audit - {0} | overall risk: {1} (score {2}, higher = worse)" -f $covText, $score.Band, $score.Score)

    $resultsPath = Join-Path $script:HtmlDir 'EntraAudit-Results.html'
    $riskPath    = Join-Path $script:HtmlDir 'Risk-Report.html'
    $posturePath = Join-Path $script:HtmlDir 'Posture-Summary.html'

    # Every output is written on its own: one page that fails (an I/O error, or a
    # rendering bug hit by unusual tenant data) must not take the other pages or the
    # machine-readable export down with it. A failure is still loud - it is printed,
    # listed in $reportFailures and makes the run exit with code 1 ($script:AuditFailed).
    $reportFailures = New-Object System.Collections.Generic.List[string]
    $writeOutput = {
        param([string]$Name, [scriptblock]$Writer)
        try { & $Writer }
        catch {
            $reportFailures.Add($Name) | Out-Null
            Write-Err2 "Could not write $($Name): $($_.Exception.Message)"
            $script:AuditFailed = $true
        }
    }

    # Machine-readable exports first (automation / trend comparison) with a stable finding
    # id: Findings.csv (flat) and Findings.json ({ RunInfo, Score, CheckStatus, Datasets,
    # Findings }). They depend on no HTML page, so they are written before any of them.
    $tenantId = [string]$ctx.TenantId
    & $writeOutput 'Findings.csv / Findings.json' { Export-EntraAuditData -RunRoot $script:RunRoot -TenantId $tenantId -Score $score -Items $findingItems }

    & $writeOutput 'EntraAudit-Results.html' { Write-EntraResultsReport -Path $resultsPath -Items $findingItems -Counts $counts -TenantName $tenantName -GeneratedOn $now -Subtitle $subtitle }
    & $writeOutput 'Risk-Report.html'        { Write-EntraRiskReport    -Path $riskPath    -Items $findingItems -Counts $counts -TenantName $tenantName -GeneratedOn $now -Score $score -Stats $stats }
    & $writeOutput 'Posture-Summary.html'    { Write-PostureSummaryReport -Path $posturePath -TenantName $tenantName -GeneratedOn $now -Stats $stats -Items $findingItems }
    & $writeOutput 'Raw-Data.html'           { Write-RawDataIndexReport -Path (Join-Path $script:HtmlDir 'Raw-Data.html') -TenantName $tenantName -GeneratedOn $now -Items $findingItems }
    if ($reportFailures.Count -gt 0) {
        Write-Err2 ("{0} output file(s) could not be written: {1}. The other reports are complete." -f $reportFailures.Count, ($reportFailures -join ', '))
    }

    # Summary
    Write-Host ""
    Write-Good "Audit complete."
    Write-Host ("  Overall risk : {0} (score {1}, higher = worse)" -f $score.Band, $score.Score) -ForegroundColor White
    $statusList = @($script:CheckStatus.Values)
    $skippedN = @($statusList | Where-Object { [string]$_.Status -like 'Skipped*' }).Count
    $erroredN = @($statusList | Where-Object { [string]$_.Status -eq 'Error' }).Count
    $incompleteN = @($statusList | Where-Object { [string]$_.Status -like '*Incomplete*' }).Count
    $summaryLines = @(
        ("  Findings     : Critical={0} High={1} Medium={2} Low={3} Info={4}" -f $counts.Critical,$counts.High,$counts.Medium,$counts.Low,$counts.Information)
        ("  Checks       : {0} selected | {1} completed | {2} skipped | {3} stopped with an error | {4} with unreadable data" -f
            $toRun.Count, ($toRun.Count - $skippedN - $erroredN), $skippedN, $erroredN, $incompleteN)
        ("  Run folder   : {0}" -f $script:RunRoot)
        ("  Reports      : {0}" -f $script:HtmlDir)
        ("  Raw evidence : {0}" -f $script:RawDir)
    )
    if ($script:RunInfo.LogFile) { $summaryLines += ("  Run log      : {0}" -f (Join-Path $script:RunRoot $script:RunInfo.LogFile)) }
    foreach ($line in $summaryLines) { Add-EARunLog 'INFO' $line.Trim() }
    Write-Host ($summaryLines -join [Environment]::NewLine)
    if (($skippedN + $erroredN) -gt 0) {
        Write-Warn2 ("{0} check(s) did not run completely, so the findings are a partial picture. Posture-Summary.html lists each check and the reason." -f ($skippedN + $erroredN))
    }
    Write-Warn2 "Reports contain sensitive identity/security data (users, admins, apps, sign-in & risk signals). Store the output in a restricted folder and avoid sharing the raw CSV/JSON broadly."

    # Open the results page unless -NoLaunch was given or the session is non-interactive
    # (a scheduled task or service), where it would start a browser under the service
    # account or fail on a server. Deliberately NOT gated on the sign-in mode: the GUI runs
    # app-only audits for an operator at the keyboard, and unattended scripts pass -NoLaunch.
    $noOpenReason = if ($NoLaunch) { $null }
        elseif (-not [Environment]::UserInteractive) { 'non-interactive session' }
        else { '' }
    if ($null -eq $noOpenReason) {
        # -NoLaunch: the operator asked for no browser; nothing to explain.
    } elseif ($noOpenReason) {
        Write-Info "The report was not opened automatically ($noOpenReason). Open: $resultsPath"
    } else {
        try { Invoke-Item -LiteralPath $resultsPath -ErrorAction Stop }
        catch { Write-Warn2 "Could not open the report automatically ($($_.Exception.Message)). Open: $resultsPath" }
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
    if ($script:LogPath) { Write-Err2 "The run log has everything printed up to the failure: $($script:LogPath)" }
    $script:AuditFailed = $true
} finally {
    # Only tear down a session this script created - never a pre-existing one the
    # operator connected themselves before running the audit.
    try {
        if ($script:GraphConnectedByScript -and (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
            if (Get-MgContext) { Disconnect-MgGraph -ErrorAction Stop | Out-Null; Write-Info "Disconnected from Microsoft Graph." }
        }
    } catch { Write-Warn2 "Could not disconnect from Microsoft Graph: $($_.Exception.Message)" }
    # Last: stop the transcript (or write the buffered messages) so the log is complete.
    Close-EARunLog
}
if ($script:AuditFailed) { exit 1 }




