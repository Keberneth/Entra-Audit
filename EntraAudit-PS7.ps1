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
                        Raw-Data.html, Action-Register.html
      Raw Data\Source\  one or more datasets per check, each as .html + .csv + .txt
      Findings.json / Findings.csv   all findings with stable ids (automation / trend)
      EntraAudit-Run.log             everything the run printed (warnings, errors, skips)
      Action-Register.csv / Follow-Up.json   actions, comparison and documented exceptions

  Exit codes: 1 for startup, authentication or output failure; 2 for collection errors,
  missing scopes/permissions or unknown licensing. -FailOnIncomplete also returns 2 for
  partial coverage and known licensing exclusions. Otherwise 0, even when security
  findings exist. Reports explain every skipped or incomplete check.

.PARAMETER PreviousRunPath
  Previous Findings.json for the same tenant, ruleset and assessment settings.
.PARAMETER ExceptionsPath
  Local JSON records of accepted risks, with exact rule/object, owner, reason and expiry.
  Findings remain visible and scored. See README.md for the schema.
.PARAMETER FailOnIncomplete
  Return exit code 2 for any incomplete or skipped selected check.

.PARAMETER DisabledAccountDays
  Days (1-3650, default 180) after which a disabled account that is still in the
  directory is reported as a clean-up candidate by the accounts check (disabled-account
  hygiene rule). The value used is recorded in Findings.json (RunInfo.Settings).

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

# -DisabledAccountDays is read by the accounts check through script scope, which the
# analyzer cannot see (the other tuning parameters show the same false positive).
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DisabledAccountDays', Justification = 'Read by the check functions through script scope.')]
[CmdletBinding()]
param(
    # ---- Run modes ----
    [switch]$all,
    [string[]]$exclude,
    [string[]]$select,
    [switch]$installdeps,

    # ---- Individual checks (mirrors the AD audit switch style) ----
    [switch]$tenantinfo,        # Tenant / organization overview
    [switch]$privroles,         # FLAGSHIP: permanent vs eligible vs time-bound roles - works without P2, PIM eligibility detail needs P2
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
    # Days after which a disabled account still in the directory is reported as a clean-up
    # candidate by the accounts check (disabled-account hygiene rule). Default 180.
    [ValidateRange(1, 3650)][int]$DisabledAccountDays = 180,
    [string]$ModulesPath,       # offline: folder containing Save-Module output
    [switch]$NoLaunch,          # do not open the report when finished
    [switch]$FailOnIncomplete, # exit 2 for any skipped/incomplete selected check, including licensing gaps
    [string]$PreviousRunPath,  # previous Findings.json (same tenant, ruleset and assessment settings)
    [string]$ExceptionsPath    # documented risk acceptances; findings remain visible and scored
)

$ErrorActionPreference = 'Continue'
$script:Version = 'EntraAudit-PS7 v2.2.0'
$script:RulesetVersion = '2.2.0'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7 (pwsh.exe). Current version: $($PSVersionTable.PSVersion)"
    exit 1
}
# A pasted application id with stray spaces must not fail the GUID check at sign-in.
if ($DelegatedClientId) { $DelegatedClientId = $DelegatedClientId.Trim() }

# Shared definitions and check registration are loaded by the guarded entry point below.
function Invoke-EntraAudit {
    Write-Host ""
    Write-Host "  $($script:Version) - read-only Microsoft Entra ID security audit" -ForegroundColor White
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor DarkGray

    # Run context for the reports and exports (the $script:RunInfo contract). It is filled
    # in as the run progresses; report writers tolerate any field that is still $null.
    $runStarted = [datetime]::UtcNow
    $script:RunInfo = [ordered]@{
        ToolVersion        = $script:Version
        RunId              = [guid]::NewGuid().ToString()
        RulesetVersion     = $script:RulesetVersion
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
            DisabledAccountDays    = $DisabledAccountDays
            BreakGlassUpnsCount    = @(Normalize-StringList -Values $BreakGlassUpns).Count   # settings use count/hash; names can appear in evidence
            BreakGlassUpnsHash     = Get-EAStringSetHash (Normalize-StringList -Values $BreakGlassUpns)
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
    $individual = [ordered]@{}
    foreach ($id in $script:Registry.Keys) {
        $individual[$id] = [bool](Get-Variable -Name $script:Registry[$id].Switch -ValueOnly -ErrorAction Stop)
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
    # counts so the report cards and the score can never disagree. It also carries the
    # check coverage (Get-EntraRunCoverage) and a Band that never says 'Clean' while a
    # selected check was skipped, errored or incomplete. Every page and the export get
    # this ONE score object, so they all show the same band, score and coverage.
    $findingItems = $script:Findings.ToArray()
    $score = Get-EntraRiskScore $findingItems
    $script:CollectionExitCode = Get-EntraAuditExitCode -CheckStatus $script:CheckStatus -FailOnIncomplete:$FailOnIncomplete
    $script:RunInfo['CollectionExitCode'] = $script:CollectionExitCode
    Initialize-EntraFollowUp -Items $findingItems -RunInfo $script:RunInfo -Score $score -PreviousRunPath $PreviousRunPath -ExceptionsPath $ExceptionsPath | Out-Null
    # Acceptance changes the work queue, never the severity or risk points.
    $score = Get-EntraRiskScore $findingItems
    $counts = @{ Critical=$score.Critical; High=$score.High; Medium=$score.Medium; Low=$score.Low; Information=$score.Information }
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'

    $stats = Get-EntraReportStatistic

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

    & $writeOutput 'EntraAudit-Results.html' { Write-EntraResultsReport -Path $resultsPath -Items $findingItems -Counts $counts -TenantName $tenantName -GeneratedOn $now -TenantId $tenantId -Score $score }
    & $writeOutput 'Risk-Report.html'        { Write-EntraRiskReport    -Path $riskPath    -Items $findingItems -Counts $counts -TenantName $tenantName -GeneratedOn $now -Score $score -Stats $stats }
    & $writeOutput 'Posture-Summary.html'    { Write-PostureSummaryReport -Path $posturePath -TenantName $tenantName -GeneratedOn $now -Stats $stats -Items $findingItems -Score $score }
    & $writeOutput 'Raw-Data.html'           { Write-RawDataIndexReport -Path (Join-Path $script:HtmlDir 'Raw-Data.html') -TenantName $tenantName -GeneratedOn $now -Items $findingItems }
    & $writeOutput 'Action register / comparison' { Write-EntraFollowUpReport -RunRoot $script:RunRoot -Items $findingItems -TenantId $tenantId }
    if ($reportFailures.Count -gt 0) {
        Write-Err2 ("{0} output file(s) could not be written: {1}. The other reports are complete." -f $reportFailures.Count, ($reportFailures -join ', '))
    }

    # Summary
    Write-Host ""
    # Output files the Build reports step could not write ($reportFailures, names as listed
    # there). A run with a missing output must not end on "Audit complete".
    $failedOutputs = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $reportFailures) { foreach ($f in $reportFailures) { if ($f) { $failedOutputs.Add([string]$f) } } }
    if ($failedOutputs.Count -gt 0) {
        Write-Err2 ("Audit finished, but {0} output file(s) could not be written: {1}. See the errors above." -f $failedOutputs.Count, ($failedOutputs -join ', '))
    } elseif ($script:CollectionExitCode -ne 0) {
        Write-Warn2 'Reports generated, but collection was incomplete (exit code 2). See the posture summary for the affected checks.'
    } else {
        Write-Good "Audit complete."
    }
    $riskLine = "  Confirmed risk index: {0} | Assessment-gap points: {1} | Highest confirmed severity: {2}" -f $score.ConfirmedScore, $score.NotAssessedPoints, $score.HighestConfirmedSeverity
    Add-EARunLog 'INFO' $riskLine.Trim()
    Write-Host $riskLine -ForegroundColor White
    # Check coverage from the same function the reports use, so the console and the
    # pages always agree (every selected check lands in exactly one of these groups).
    $runCov = if ($score -and $score.Coverage) { $score.Coverage } else { Get-EntraRunCoverage }
    $findingsFailed = @($failedOutputs | Where-Object { $_ -like 'Findings*' }).Count -gt 0
    $cc = if ($score.ConfirmedCounts) { $score.ConfirmedCounts } else { $counts }
    $summaryLines = @(
        # Confirmed counts plus the Not assessed total - the same numbers as the report tiles.
        ("  Findings     : Critical={0} High={1} Medium={2} Low={3} Info={4} | Not assessed={5}" -f $cc.Critical,$cc.High,$cc.Medium,$cc.Low,$cc.Information,[int]$score.NotAssessedFindings)
        ("  Checks       : {0} of {1} selected check(s) gave a full result | {2} could not read all of their data | {3} skipped | {4} stopped with an error" -f
            $runCov.FullyEvaluated, $runCov.Selected, $runCov.Incomplete, $runCov.Skipped, $runCov.Errored)
        ("  Run folder   : {0}" -f $script:RunRoot)
        ("  Reports      : {0}" -f $script:HtmlDir)
        ("  Findings data: {0}{1}" -f (Join-Path $script:RunRoot 'Findings.json'),
            $(if ($findingsFailed) { ' (not written completely - see the errors above)' } else { ' and Findings.csv (for automation and trend comparison)' }))
        ("  Raw evidence : {0}" -f $script:RawDir)
    )
    if ($script:RunInfo.LogFile) { $summaryLines += ("  Run log      : {0}" -f (Join-Path $script:RunRoot $script:RunInfo.LogFile)) }
    foreach ($line in $summaryLines) { Add-EARunLog 'INFO' $line.Trim() }
    Write-Host ($summaryLines -join [Environment]::NewLine)
    $notRunN = [int]$runCov.Skipped + [int]$runCov.Errored
    if ($notRunN -gt 0) {
        Write-Warn2 ("{0} check(s) did not run completely, so the findings are a partial picture. Posture-Summary.html lists each check and the reason." -f $notRunN)
    }
    if ([int]$runCov.Incomplete -gt 0) {
        Write-Warn2 ("{0} check(s) could not read all of their data. What could not be checked is marked 'Not assessed' in the reports - it is not a clean result." -f $runCov.Incomplete)
    }
    Write-Warn2 "Reports contain sensitive identity/security data (users, admins, apps, sign-in & risk signals). Store the output in a restricted folder and avoid sharing the raw CSV/JSON broadly."

    # Open the results page unless -NoLaunch was given or the session is non-interactive
    # (a scheduled task or service), where it would start a browser under the service
    # account or fail on a server. Deliberately NOT gated on the sign-in mode: the GUI runs
    # app-only audits for an operator at the keyboard, and unattended scripts pass -NoLaunch.
    # A results page that could not be written is never opened (it may be missing or stale).
    $resultsWritten = ($failedOutputs -notcontains 'EntraAudit-Results.html') -and (Test-Path -LiteralPath $resultsPath -PathType Leaf)
    if ($NoLaunch) {
        # -NoLaunch: the operator asked for no browser; nothing to explain.
    } elseif (-not $resultsWritten) {
        Write-Warn2 "The results page could not be written, so it was not opened. The other reports are in: $($script:HtmlDir)"
    } elseif (-not [Environment]::UserInteractive) {
        Write-Info "The report was not opened automatically (non-interactive session). Open: $resultsPath"
    } else {
        try { Invoke-Item -LiteralPath $resultsPath -ErrorAction Stop }
        catch { Write-Warn2 "Could not open the report automatically ($($_.Exception.Message)). Open: $resultsPath" }
    }
}

# Definition-only bootstrap, then execute the selected audit once.
$script:AuditFailed = $false
try {
    . (Join-Path $PSScriptRoot 'Library/EntraAudit.Loader.ps1')
    Invoke-EntraAudit
} catch {
    if (Get-Command Write-Err2 -ErrorAction SilentlyContinue) {
        Write-Err2 "Audit failed: $($_.Exception.Message)"
        Write-Err2 $_.ScriptStackTrace
    } else { Write-Error "Audit failed: $($_.Exception.Message)" }
    $script:AuditFailed = $true
} finally {
    try {
        if ($script:GraphConnectedByScript -and (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
            if (Get-MgContext) { Disconnect-MgGraph -ErrorAction Stop | Out-Null }
        }
    } catch { Write-Warning "Could not disconnect from Microsoft Graph: $($_.Exception.Message)" }
    if (Get-Command Close-EARunLog -ErrorAction SilentlyContinue) { Close-EARunLog }
}
if ($script:AuditFailed) { exit 1 }
if ($script:CollectionExitCode) { exit $script:CollectionExitCode }
