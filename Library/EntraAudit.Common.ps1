<#
EntraAudit shared definitions. Dot-source from the runner so script-scoped state is shared.
Do not execute check files with &: that creates a different script scope.
#>

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

$script:GlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'

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

$script:DangerousAppPermissions = @(
    'RoleManagement.ReadWrite.Directory','AppRoleAssignment.ReadWrite.All',
    'Application.ReadWrite.All','Directory.ReadWrite.All','full_access_as_app',
    'Mail.ReadWrite','Mail.Read','Mail.Send','Files.ReadWrite.All','Sites.FullControl.All',
    'User.ReadWrite.All','Group.ReadWrite.All','GroupMember.ReadWrite.All',
    'PrivilegedAccess.ReadWrite.AzureAD','RoleManagementPolicy.ReadWrite.Directory'
)

$script:Findings    = [System.Collections.Generic.List[object]]::new()

$script:CheckStatus = [ordered]@{}

$script:CurrentCheckId = $null

$script:AuthType    = 'Delegated'

$script:GraphConnectedByScript = $false

$script:HasP1       = $false

$script:HasP2       = $false

$script:LicenseKnown = $true

$script:WorkloadIdP = $false

$script:Tenant      = $null

$script:UsersCache  = $null

$script:UsersCacheHasSignIn = $false

$script:SignInFetchError = $null

$script:UsersCacheHasManager = $false

$script:ManagerExpansionFailed = $false

$script:ManagerExpansionError = $null

$script:UserById    = @{}

$script:RegCache    = $null

$script:AppsCache   = $null

$script:SpsCache    = $null

$script:SpSignInActivity = $null

$script:OAuthGrantsCache = $null

$script:MfaCapableById = @{}

$script:RoleDefById = @{}

$script:RolePrivilegedById = @{}

$script:RolePrivilegedMetadataKnown = $false

$script:AppOnlyGrantedPermissions = @()

$script:RawDatasets = [System.Collections.Generic.List[object]]::new()

$script:PrivAssignments = $null

$script:PrivAssignmentsFailed = $false

$script:PrivAssignmentsError = $null

$script:PrivActiveFetchError = $null

$script:PrivClassicFetchError = $null

$script:PrivActiveSource = $null

$script:PrivEligibilityAssignmentsFailed = $false

$script:PrivEligibilityFetchError = $null

$script:PrivUserLookupError = $null

$script:PrivilegedUserMap = $null

$script:PrivilegedUserMapIncomplete = $false

$script:CaPoliciesCache = $null

$script:AuthenticationStrengthById = @{}
$script:AuthenticationStrengthReadErrors = @{}

$script:GroupMembersCache = @{}

$script:GroupOwnersCache  = @{}

$script:TenantReadError = $null

$script:RolePrivilegedMetadataError = $null

$script:LicenseSkus  = @()

$script:LicenseNotes = @()

$script:RunInfo = [ordered]@{ ToolVersion = $script:Version }

$script:RunLog = New-Object System.Collections.Generic.List[string]

$script:RunLogWritten = 0

$script:EAPageSizeRejected = @{}

$script:LogPath = $null

$script:TranscriptStarted = $false

function Add-EARunLog {
    param([string]$Level, [string]$Message)
    if ($null -ne $script:RunLog) { $script:RunLog.Add(('{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message)) }
}

function Write-Info  { param([string]$m) Add-EARunLog 'INFO' $m; Write-Host "[*] $m" -ForegroundColor Cyan }

function Write-Good  { param([string]$m) Add-EARunLog 'OK' $m;   Write-Host "[+] $m" -ForegroundColor Green }

function Write-Warn2 { param([string]$m) Add-EARunLog 'WARN' $m; Write-Host "[!] $m" -ForegroundColor Yellow }

function Write-Err2  { param([string]$m) Add-EARunLog 'ERROR' $m; Write-Host "[x] $m" -ForegroundColor Red }

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

function Normalize-StringList {
    param([string[]]$Values)
    @($Values | ForEach-Object { $_ -split '[;,]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
}

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

function Get-FindingRule {
    param([object]$Finding)
    if ($Finding.RuleId) { return [string]$Finding.RuleId }
    (([string]$Finding.Title -replace '\d+','') -replace '[^A-Za-z]+','-').Trim('-').ToLowerInvariant()
}

function New-FindingKey {
    param([string]$TenantId, [object]$Finding)
    $checkId = [string]$Finding.CheckId
    $rule = Get-FindingRule $Finding
    $objType = if ($Finding.ObjectType) { [string]$Finding.ObjectType } else { '' }
    $objId = if ($Finding.ObjectId) { $Finding.ObjectId } elseif ($Finding.AffectedPrincipal) { $Finding.AffectedPrincipal } else { 'tenant' }
    $path = if ($Finding.PathHash) { [string]$Finding.PathHash } else { '' }
    (@($TenantId, $checkId, $rule, $objType, ([string]$objId).ToLowerInvariant(), $path) -join '|')
}

function Test-CaGrantHasNonMfaAlternative {
    param($Grant, [string[]]$MfaBuiltIns = @('mfa'))
    if (-not $Grant) { return $false }
    if ([string](Get-EAField $Grant 'Operator') -notmatch '^(?i)OR$') { return $false }
    $builtIns = @((Get-EAField $Grant 'BuiltInControls') | Where-Object { $_ })
    if (@($builtIns | Where-Object { [string]$_ -notin $MfaBuiltIns }).Count -gt 0) { return $true }
    if (@((Get-EAField $Grant 'TermsOfUse') | Where-Object { $_ }).Count -gt 0) { return $true }
    if (@((Get-EAField $Grant 'CustomAuthenticationFactors') | Where-Object { $_ }).Count -gt 0) { return $true }
    return $false
}

function Get-EACaAuthenticationStrength {
    param($Policy)
    $strength = Get-EAField $Policy.GrantControls 'AuthenticationStrength'
    $id = [string](Get-EAField $strength 'Id')
    if ($id -and $script:AuthenticationStrengthById -and $script:AuthenticationStrengthById.ContainsKey($id)) {
        return $script:AuthenticationStrengthById[$id]
    }
    return $strength
}

function Test-CaPolicyStrengthKnown {
    param($Policy)
    $strength = Get-EACaAuthenticationStrength $Policy
    $id = [string](Get-EAField $strength 'Id')
    if (-not $id) { return $true }
    if ($id -in @('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004')) { return $true }
    return ([string](Get-EAField $strength 'RequirementsSatisfied') -in @('none','mfa') -and
        @((Get-EAField $strength 'AllowedCombinations') | Where-Object { $_ }).Count -gt 0)
}

function Test-CaPolicyRequiresMfaOrStrength {
    param($Policy)
    $grant = $Policy.GrantControls
    if (-not $grant) { return $false }
    $builtIns = @($grant.BuiltInControls | Where-Object { $_ })
    $hasMfa = ($builtIns -contains 'mfa')
    $strength = Get-EACaAuthenticationStrength $Policy
    $strengthId = [string](Get-EAField $strength 'Id')
    # Custom strengths may allow password-only or other single-factor methods.
    # An ID alone does not prove MFA. Unknown definitions are separately reported.
    $hasStrength = ([string](Get-EAField $strength 'RequirementsSatisfied') -eq 'mfa') -or
        $strengthId -in @('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004')
    if (-not ($hasMfa -or $hasStrength)) { return $false }

    # With OR, MFA/auth strength is not mandatory when another grant (a compliant device,
    # Terms of Use, a custom control ...) can satisfy the policy. Count only policies where
    # every OR alternative is itself an MFA control.
    if (Test-CaGrantHasNonMfaAlternative -Grant $grant) { return $false }
    return $true
}

function Test-CaPolicyRequiresPhishingResistantStrength {
    param($Policy)
    $grant = $Policy.GrantControls
    $strength = if ($grant) { Get-EACaAuthenticationStrength $Policy } else { $null }
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

    # An OR policy containing built-in MFA (or any other built-in grant), Terms of Use or a
    # custom control still permits a weaker alternative to the phishing-resistant strength.
    if (Test-CaGrantHasNonMfaAlternative -Grant $grant -MfaBuiltIns @()) { return $false }
    return $true
}

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

function Test-CaPolicyTargetsAllApps {
    param($Policy)
    return (Test-CaPolicyTargetsAllResources $Policy)
}

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

$script:WriteScopePattern = '(?i)(ReadWrite|\.Write\b|\.Send\b|\.Create\b|\.Delete|\.Update\b|\.Invite\b|\.Manage|PrivilegedOperations|ManageAsApp|AccessAsUser|FullControl|full_access|Impersonation|\.EnableDisableAccount\b|\.RevokeSessions\b|\.Command\b|\.Export\b|\.Selected$|\.Restore\b|\.Assign|\.Migrate|\.Submit|\.Execute|\.Invoke|\.Remove|\.Reset|\.Approve)'

function Test-EAReadOnlyScope {
    param([string]$Scope)
    $s = ([string]$Scope).Trim()
    if (-not $s) { return $false }
    if ($s -in @('openid','profile','email','offline_access')) { return $true }
    if ($s -match $script:WriteScopePattern) { return $false }
    $readSegments = @($s -split '\.' | Where-Object { $_ -match '^(?i)(Read|ReadBasic|ReadFor(User|Team|Chat))$' })
    return ($readSegments.Count -gt 0)
}

function Get-EntraFindingPopulation {
    param([Parameter(Mandatory)][object]$Finding)
    # Population is supplied by the collector, never inferred from evidence rows:
    # one object can have several role paths, settings or historical events.
    $ids = @((Get-EAField $Finding 'AffectedObjectIds') | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { ([string]$_).Trim() } | Sort-Object -Unique)
    $type = [string](Get-EAField $Finding 'AffectedObjectType')
    $count = Get-EAField $Finding 'AffectedCount'
    $assessed = Get-EAField $Finding 'AssessedCount'
    $unknown = Get-EAField $Finding 'UnknownCount'
    $label = [string](Get-EAField $Finding 'PopulationLabel')
    if (-not $type) { $type = [string](Get-EAField $Finding 'ObjectType') }
    if (-not $ids.Count -and $null -eq $count -and $type -and $type -ne 'tenant' -and
        -not @((Get-EAField $Finding 'ResultRows') | Where-Object { $null -ne $_ }).Count) {
        $objectId = [string](Get-EAField $Finding 'ObjectId')
        if ($objectId.Trim()) { $ids = @($objectId.Trim()) }
    }
    if ($ids.Count) { $count = [Math]::Max($ids.Count, $(if ($null -ne $count) { [int]$count } else { 0 })) }
    $basis = if ($ids.Count -and $ids.Count -eq $count) { 'ObjectIds' } elseif ($null -ne $count -and [int]$count -gt 0) { 'AffectedCount' } else { 'FindingRecord' }
    [pscustomobject]@{
        Ids = [string[]]$ids; ObjectType = $type; AffectedCount = $count
        AssessedCount = $assessed; UnknownCount = $unknown; Label = $label
        IdsComplete = [bool]($ids.Count -gt 0 -and $ids.Count -eq $count)
        ScoringCount = $(if ($basis -eq 'FindingRecord') { 1 } else { [int]$count })
        ScoringBasis = $basis
    }
}

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
        [string]$DocumentationUrl,
        # Explicit assessed population, independent of stable finding identity and display rows.
        [string[]]$AffectedObjectIds, [string]$AffectedObjectType,
        [Nullable[int]]$AffectedCount, [Nullable[int]]$AssessedCount, [Nullable[int]]$UnknownCount,
        [string]$PopulationLabel,
        [ValidateSet('Configuration','HistoricalEvent','ManualTest','Collection')][string]$VerificationType,
        [string]$VerificationSteps
    )
    $Severity = Normalize-Severity $Severity
    $populationIds = @($AffectedObjectIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
    foreach ($value in @($AffectedCount,$AssessedCount,$UnknownCount)) { if ($null -ne $value -and $value -lt 0) { throw 'Population counts cannot be negative.' } }
    if ($null -ne $AffectedCount -and $AffectedCount -lt $populationIds.Count) { throw 'AffectedCount cannot be smaller than the distinct affected-object list.' }
    if ($null -eq $AffectedCount -and $populationIds.Count) { $AffectedCount = $populationIds.Count }
    if ($null -ne $AssessedCount -and $null -ne $AffectedCount -and $AssessedCount -lt $AffectedCount) { throw 'AssessedCount cannot be smaller than AffectedCount.' }
    if (-not $VerificationType) { $VerificationType = if ($CoverageGap) { 'Collection' } else { 'Configuration' } }
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
        AffectedObjectIds = [string[]]$populationIds
        AffectedObjectType = $AffectedObjectType
        AffectedCount     = $AffectedCount
        AssessedCount     = $AssessedCount
        UnknownCount      = $UnknownCount
        PopulationLabel   = $PopulationLabel
        VerificationType  = $VerificationType
        VerificationSteps = $VerificationSteps
    }) | Out-Null
}

function Test-EntraCoverageGap {
    param([Parameter(Mandatory)][object]$Finding)

    if ($Finding.PSObject.Properties['CoverageGap']) { return [bool]$Finding.CoverageGap }
    $rule = [string]$Finding.RuleId
    if ($rule -match '(?i)(^|[-_])(coverage|unknown|incomplete|unreadable|not-assessed|not-available)($|[-_])') { return $true }
    $text = ('{0} {1} {2}' -f $Finding.Title, $Finding.Evidence, $Finding.WhyItMatters)
    return ($text -match '(?i)(coverage\s+(gap|is\s+unknown)|unknown\s+coverage|\b(is|are)\s+unknown\b|could\s+not\s+be\s+(fully\s+)?(read|retrieved|fetched|evaluated|assessed|verified)|cannot\s+be\s+(fully\s+)?(evaluated|assessed|verified)|not\s+assessed|not\s+a\s+clean\s+result|coverage\s+is\s+incomplete|result\s+is\s+unknown|status\s+is\s+unknown|unknown[,/]?\s+not\s+(clean|confirmed))')
}

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
    if ($null -eq $Rows) { return }
    # Leading characters that make a spreadsheet read a cell as a formula (the same set as
    # the pattern in ConvertTo-SafeCsvValue).
    $lead = [char[]]@('=', '+', '-', '@', "`t", "`r", "`n")
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $props = $row.PSObject.Properties
        if ($row -is [System.Management.Automation.PSCustomObject]) {
            $plain = $true
            foreach ($p in $props) {
                $v = $p.Value
                if ($v -is [string]) { if ($v.Length -gt 0 -and $v[0] -in $lead) { $plain = $false; break } }
                elseif ($null -eq $v) {
                    # "No value" left by an empty $(...) (AutomationNull) renders as "" when
                    # passed through; the old path wrote an empty field, so copy the row.
                    if (@($v).Count -eq 0) { $plain = $false; break }
                }
                elseif ($v -is [System.Collections.IEnumerable]) { $plain = $false; break }
            }
            if ($plain) { $row; continue }
        }
        $out = [ordered]@{}
        foreach ($p in $props) {
            $v = $p.Value
            if ($null -eq $v) { $out[$p.Name] = $null; continue }
            if ($v -isnot [string] -and $v -is [System.Collections.IEnumerable]) {
                # PowerShell's own rule for what a function output unrolls (not strings or
                # dictionaries).
                $enumerable = [System.Management.Automation.LanguagePrimitives]::GetEnumerable($v)
                if ($null -ne $enumerable) {
                    $items = [System.Collections.Generic.List[object]]::new()
                    foreach ($item in $enumerable) { $items.Add($item) }
                    if ($items.Count -eq 0) { $v = '' }   # the old path wrote "" here, not an empty field
                    elseif ($items.Count -eq 1) { $v = $items[0] }
                    else { $v = $items.ToArray() }
                }
            }
            if ($v -is [string] -and $v.Length -gt 0 -and $v[0] -in $lead) { $v = "'" + $v }
            $out[$p.Name] = $v
        }
        [pscustomobject]$out
    }
}

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

function ConvertTo-EntraEvidenceCell {
    param($Value)
    if ($null -eq $Value) { return '' }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $s = if ($Value -is [string]) { $Value }
         elseif ($Value -is [datetime]) { $Value.ToString('yyyy-MM-dd HH:mm:ss', $inv) }
         elseif ($Value -is [datetimeoffset]) { $Value.ToString('yyyy-MM-dd HH:mm:ss zzz', $inv) }
         elseif ($Value -is [System.Collections.IDictionary]) { (@(foreach ($k in $Value.Keys) { '{0}={1}' -f $k, $Value[$k] }) -join '; ') }
         elseif ($Value -is [System.Collections.IEnumerable]) { (@(foreach ($i in $Value) { if ($null -eq $i) { '' } else { [string]$i } }) -join ', ') }
         elseif ($Value -is [System.Management.Automation.PSCustomObject]) { (@(foreach ($p in $Value.PSObject.Properties) { '{0}={1}' -f $p.Name, $p.Value }) -join '; ') }
         else { [string]$Value }
    if ($s.IndexOfAny([char[]]"`r`n`t") -ge 0) { $s = ($s -replace "\r\n|\r|\n", ' / ') -replace "\t", ' ' }
    return $s
}

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
        ErrorMessage    = $(if ($ErrorMessage) { [string]$ErrorMessage } else { $null })   # raw exception text (runtime failures only: Error / Skipped-NoPermission / Skipped-NoLicense)
        MissingScopes   = [string[]]@($MissingScopes | Where-Object { $_ })   # Skipped-NoScope only
        Partial         = [bool]$Partial   # stopped part-way after recording findings
        DurationSeconds = [math]::Round($DurationSeconds, 1)
    }
}

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

    # Published for the evidence writer (Get-EntraEvidenceCheckId), so every dataset is
    # attributed to its check without a call-stack search; cleared in the finally below.
    $script:CurrentCheckId = $CheckId
    try {
        & $Action
        $n = Get-EACheckFindingCount -Since $before
        $status = if ($n.Risk -gt 0 -and $n.Coverage -gt 0) { "RiskFindings($($n.Risk))+Incomplete($($n.Coverage))" } `
            elseif ($n.Risk -gt 0) { "RiskFindings($($n.Risk))" } `
            elseif ($n.Coverage -gt 0) { "Incomplete($($n.Coverage))" } `
            elseif ($n.Info -gt 0) { "InfoOnly($($n.Info))" } `
            else { 'Pass' }
        # "finding" = one recorded finding; the report keeps "issue" for a group of findings
        # with the same rule and severity (Get-EntraIssueKey), so this count is never called that.
        $issues = if ($n.Risk -eq 1) { '1 finding needs' } else { "$($n.Risk) findings need" }
        $gaps = if ($n.Coverage -eq 1) { '1 data source or object could not be read' } else { "$($n.Coverage) data sources or objects could not be read" }
        $notes = if ($n.Info -eq 1) { '1 informational note' } else { "$($n.Info) informational notes" }
        $reason = if ($n.Risk -gt 0 -and $n.Coverage -gt 0) { "$issues attention; $gaps, so there may be more." } `
            elseif ($n.Risk -gt 0) { "$issues attention." } `
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
        $licenseText = (('{0} {1}' -f $message, $details) -match '(?i)premium|licen[cs]')
        $licenseHint = if ($licenseText) { ' (the message mentions licensing - the tenant may lack the required license)' } else { '' }
        # Microsoft Graph also answers 401/403 when the TENANT is not licensed for a feature
        # (e.g. Identity Protection after an Entra ID P2 subscription lapsed). That is a
        # licence gap, not a missing permission, so it is reported as Skipped-NoLicense.
        $licenseDenied = ($denied -and (('{0} {1}' -f $message, $details) -match '(?i)licen[cs]'))
        $shortMessage = ($message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
        if (-not $shortMessage) { $shortMessage = $err.Exception.GetType().Name }
        if ($shortMessage.Length -gt 240) { $shortMessage = $shortMessage.Substring(0, 240) + '...' }

        # Findings recorded before the failure stay in the report (they are real); they are
        # counted here so the posture page and the results page agree.
        $prior = Get-EACheckFindingCount -Since $before
        $partial = ($prior.Total -gt 0)
        $priorText = if ($prior.Total -eq 1) { '1 finding' } else { "$($prior.Total) findings" }
        if ($licenseDenied -and -not $partial) {
            $status = 'Skipped-NoLicense'
            $reason = "Microsoft Graph reports the tenant is not licensed for this: $shortMessage"
            $fTitle = "Check could not run (licence missing): $Title"
            $fWhy = 'Microsoft refused the data because the tenant lacks the licence this feature needs, so nothing in this area was checked. This is a gap in the audit, not a clean result.'
            $fAction = "Confirm the tenant has an active licence for this feature (Microsoft 365 admin center > Billing > Your products), then run this check again with -select $CheckId."
        } elseif ($denied -and -not $partial) {
            $status = 'Skipped-NoPermission'
            $reason = "Access denied by Microsoft Graph: the signed-in account or app lacks a permission or admin role this check needs$licenseHint."
            $fTitle = "Check could not run (access denied): $Title"
            $fWhy = 'Nothing in this area was checked, so problems here cannot show up in this report. This is a gap in the audit, not a clean result.'
            $fAction = "Give the audit account or app the missing read permission or admin role (see PREREQUISITE.md), then run this check again with -select $CheckId."
        } elseif ($partial) {
            # 'Skipped' would claim the check never ran; it did, part-way.
            $status = 'Error'
            $cause = if ($licenseDenied) { "Microsoft Graph reports the tenant is not licensed for this ($shortMessage)" }
                     elseif ($denied) { "access was denied by Microsoft Graph$licenseHint" } else { "an error occurred: $shortMessage" }
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
        elseif ($licenseDenied) { Write-Warn2 "  $Title -> $status - $reason" }
        else { Write-Warn2 "  $Title -> $status - $reason Error: $shortMessage" }
    } finally {
        $script:CurrentCheckId = $null
    }
}

function Format-EACount {
    param([int]$Count, [string]$One, [string]$Many)
    if ($Count -eq 1) { return ('1 ' + $One) }
    return ('{0} {1}' -f $Count, $Many)
}

function Test-EARoleActivationEvent {
    param([string]$ActivityDisplayName)
    return ([string]$ActivityDisplayName -match '(?i)PIM (de)?activat')
}

$script:AppCount = '-'

function Get-EAStringSetHash {
    param([string[]]$Values)
    $canonical = (@($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Sort-Object -Unique) -join "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical)) } finally { $sha.Dispose() }
    return ([BitConverter]::ToString($hash) -replace '-','').ToLowerInvariant()
}

function Get-EntraAuditExitCode {
    param([System.Collections.IDictionary]$CheckStatus = $script:CheckStatus, [switch]$FailOnIncomplete, [switch]$OutputFailed)
    if ($OutputFailed) { return 1 }
    foreach ($check in $CheckStatus.Values) {
        $status = [string]$check.Status
        # An unavailable license is expected on some tenants. Unexpected failed reads,
        # missing authorization and unknown licensing are collection failures.
        if ($status -in @('Error','Skipped-NoPermission','Skipped-NoScope','Skipped-LicenseUnknown')) { return 2 }
        if ($FailOnIncomplete -and ($status -match 'Incomplete|^Skipped-' -or [bool]$check.Partial)) { return 2 }
    }
    return 0
}
