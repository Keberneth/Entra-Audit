<#
App / Service Principal Hygiene. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-Apps {
    $apps = Get-EAApplications
    $sps  = @(Get-EAServicePrincipals)
    # (The Applications tile reads $script:AppsCache directly, so no separate count is kept.)
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
            -Title ("App permissions could not be read on {0}, so risky apps may be missing" -f (Format-EACount -Count $spPermErrors.Count -One 'API' -Many 'APIs')) `
            -Evidence ("The list of apps holding permissions could not be read for {0} of {1}: {2}. Typical causes: throttling, a missing permission or a transient Graph error; the exact error per API is in the collection-errors file." -f $spPermErrors.Count, (Format-EACount -Count $resourceSps.Count -One 'resource API' -Many 'resource APIs'), (($spPermErrors.ResourceApi | Select-Object -First 10) -join ', ')) `
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
            -Title ((Format-EACount -Count $spNames.Count -One 'app holds' -Many 'apps hold') + ' top-risk permissions (tenant takeover, all mail or all files)') `
            -Evidence ("Apps (first 10 of {0}): {1}. Permissions found (number of grants): {2}. Also listed per grant by -enterpriseapps, which may rate some permissions differently." -f $spNames.Count, (($spNames | Select-Object -First 10) -join ', '), ($permSummary -join ', ')) `
            -WhyItMatters 'These application permissions work without any user signing in, so anyone who steals one secret or certificate of the app can, for example, make themselves Global Administrator or read every mailbox. They are among the most common routes to a full tenant compromise.' `
            -RecommendedAction 'Remove every one of these permissions that is not strictly needed (Entra admin center > Enterprise applications > app > Permissions); replace the rest with narrower, resource-scoped permissions, and switch these apps to certificate credentials with a named owner.' `
            -SourceFile $permSrc -ResultRows $tier0 -RuleId 'apps-tier0-app-permissions' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/graph/permissions-reference' `
            -AffectedObjectIds @($tier0 | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($tier0 | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated permission or ownership issue'
    }
    if ($writePerms.Count -gt 0) {
        $spNames = @($writePerms.ServicePrincipal | Select-Object -Unique)
        $permSummary = @($writePerms | Group-Object Permission | Sort-Object Count -Descending | Select-Object -First 8 |
            ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })
        Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Applications' `
            -Title ((Format-EACount -Count $spNames.Count -One 'app' -Many 'apps') + ' can change data or settings tenant-wide without a user signing in') `
            -Evidence ("Apps (first 10 of {0}): {1}. Write permissions found (number of grants): {2}. Also listed per grant by -enterpriseapps, which may rate some permissions differently." -f $spNames.Count, (($spNames | Select-Object -First 10) -join ', '), ($permSummary -join ', ')) `
            -WhyItMatters 'Application permissions with write access (for example ReadWrite, FullControl or Mail.Send) let the app change data or send mail for the whole organisation. If its secret leaks, an attacker can alter data, send mail as anyone or quietly keep access.' `
            -RecommendedAction 'Confirm each write permission is really needed; switch to read-only or resource-scoped permissions where possible, and make sure these apps use certificates and have a named owner.' `
            -SourceFile $permSrc -ResultRows $writePerms -RuleId 'apps-write-app-permissions' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/graph/permissions-reference' `
            -AffectedObjectIds @($writePerms | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($writePerms | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated permission or ownership issue'
    }
    if ($resourceSps.Count -eq 0) {
        # Every tenant has at least the Microsoft Graph service principal, which defines
        # application permissions. Finding none means the app-role data was not returned -
        # "no dangerous permissions" would then be an unverified (not a clean) result.
        Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Applications' `
            -Title 'App permissions could not be checked: no API with application permissions was found' `
            -Evidence ("{0} read, but none returned app roles that can be granted to an application (not even Microsoft Graph), so no application permission could be evaluated." -f (Format-EACount -Count $sps.Count -One 'service principal was' -Many 'service principals were')) `
            -WhyItMatters 'Apps with dangerous permissions could not be seen, so they are not reported. The absence of a finding here does not mean the tenant is clean.' `
            -RecommendedAction 'Confirm the audit account can read service principals including their app roles (Application.Read.All), then re-run the apps check.' `
            -SourceFile $permSrc -RuleId 'apps-permission-apis-not-found' -ObjectType 'tenant' -CoverageGap
    } elseif ($permRows.Count -eq 0 -and $spPermErrors.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'apps' -Category 'Applications' `
            -Title 'No app holds write-level or top-risk application permissions' `
            -Evidence ("{0}; no service principal holds a tier-0 or write-capable application permission." -f $(if ($resourceSps.Count -eq 1) { 'The 1 resource API that can grant application permissions was read' } else { 'All {0} resource APIs that can grant application permissions were read' -f $resourceSps.Count })) `
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
    $spCacheHasPublisher = $null   # decided on first use (see the publisher lookup below)
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
            $appVp = Get-EAField $app 'VerifiedPublisher'
            $publisherName = [string](Get-EAField $appVp 'DisplayName')
            $verifiedPub = [bool]($publisherName -or [string](Get-EAField $appVp 'VerifiedPublisherId'))
        } elseif ($publisherType -eq 'Other organisation') {
            $multiTenant = $true
            # The shared service-principal list selects verifiedPublisher, so the cached value
            # answers without a Graph call. An EMPTY value only means "unverified" when the
            # list really carried the property: the Graph SDK can hand back an empty object for
            # a property that was never selected. That is proven once per run by any cached
            # service principal with a verified publisher; otherwise (or when the value is
            # missing) the publisher is read per service principal (this small set of
            # third-party high-permission apps only). A failed read leaves VerifiedPublisher
            # UNKNOWN (blank), never "unverified".
            if ($null -eq $spCacheHasPublisher) {
                $spCacheHasPublisher = (@($sps | Where-Object {
                    $v = Get-EAField $_ 'VerifiedPublisher'
                    $v -and ([string](Get-EAField $v 'DisplayName') -or [string](Get-EAField $v 'VerifiedPublisherId'))
                } | Select-Object -First 1).Count -gt 0)
            }
            $vpObj = Get-EAField $sp 'VerifiedPublisher'
            $publisherKnown = ($null -ne $vpObj) -and ($spCacheHasPublisher -or [string](Get-EAField $vpObj 'DisplayName') -or [string](Get-EAField $vpObj 'VerifiedPublisherId'))
            if (-not $publisherKnown) {
                try {
                    $spFull = Get-MgServicePrincipal -ServicePrincipalId $spId -Property 'id,verifiedPublisher' -ErrorAction Stop
                    $vpObj = Get-EAField $spFull 'VerifiedPublisher'
                    $publisherKnown = $true
                } catch {
                    $publisherReadErrors += [pscustomobject]@{ ServicePrincipal=$sp.DisplayName; SpId=$spId; OwnerTenant=$ownerTenant; Error=$_.Exception.Message }
                }
            }
            $publisherName = [string](Get-EAField $vpObj 'DisplayName')
            $publisherId = [string](Get-EAField $vpObj 'VerifiedPublisherId')
            $verifiedPub = if ($publisherKnown) { [bool]($publisherName -or $publisherId) } else { $null }
        }

        $allOwnerCount = $ownerInfo.Count
        $hardenRows += [pscustomobject]@{
            ServicePrincipal=$sp.DisplayName; AppId=$sp.AppId; SpId=$spId
            ServicePrincipalType=$spType; Publisher=$publisherType; OwnerTenant=$ownerTenant
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
                'The Enterprise Application Governance check (-enterpriseapps) separately reports every enabled app without an owner; this dataset covers only high-permission apps.',
                'Managed identities (Publisher=ManagedIdentity) and Microsoft first-party apps (Publisher=Microsoft) are listed but not rated for ownership: they have no app registration in this tenant and their credentials are managed by the platform. Govern a managed identity through the Azure resource that owns it.'
            )
        # Ownership rules apply only to apps that are owned the usual way - the same rule as
        # the enterpriseapps check (service principal type Application, Legacy or empty, not a
        # Microsoft first-party app). A managed identity has no owner by design, and its owners
        # could not add a secret to it anyway.
        $ownable = @($hardenRows | Where-Object { [string]$_.ServicePrincipalType -in @('Application','Legacy','') -and $_.Publisher -ne 'Microsoft' })
        $noOwner = @($ownable | Where-Object { $_.OwnerReadState -eq 'Known' -and $_.OwnerCount -eq 0 })
        $guestOwned = @($ownable | Where-Object { $_.GuestOwner })
        $mtUnverified = @($hardenRows | Where-Object { $_.MultiTenant -and $_.VerifiedPublisher -eq $false })
        $nonAdminOwned = @($ownable | Where-Object { $_.NonAdminOwner -and -not $_.GuestOwner })
        $privUnknownRows = @($ownable | Where-Object { $_.OwnerAdminStatusUnknown -and -not $_.NonAdminOwner -and -not $_.GuestOwner })
        if ($noOwner.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'apps' -Category 'Applications' `
                -Title ((Format-EACount -Count $noOwner.Count -One 'high-permission app has' -Many 'high-permission apps have') + ' no owner') `
                -Evidence ("Apps with no enterprise-app or app-registration owner (first 10 of {0}): {1}. -enterpriseapps separately lists every enabled app without an owner; this finding covers only apps with high permissions." -f $noOwner.Count, (($noOwner.ServicePrincipal | Select-Object -First 10) -join ', ')) `
                -WhyItMatters 'Nobody is accountable for these powerful apps: no one reviews their permissions or renews their secrets, so misuse or a leaked secret can go unnoticed.' `
                -RecommendedAction 'Assign a named administrator as owner of each app (Entra admin center > Enterprise applications > app > Owners), or remove apps that are no longer needed.' `
                -SourceFile $hsrc -ResultRows $noOwner -RuleId 'apps-high-permission-app-no-owner' -ObjectType 'tenant' `
                -AffectedObjectIds @($noOwner | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($noOwner | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated permission or ownership issue'
        }
        if ($guestOwned.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'apps' -Category 'Applications' `
                -Title ((Format-EACount -Count $guestOwned.Count -One 'high-permission app is' -Many 'high-permission apps are') + ' owned by a guest (external) user') `
                -Evidence ("Guest-owned high-permission apps (first 10 of {0}): {1}." -f $guestOwned.Count, (($guestOwned | Select-Object -First 10 | ForEach-Object { '{0} (owners: {1})' -f $_.ServicePrincipal, $_.Owners }) -join '; ')) `
                -WhyItMatters 'Any owner can add a new secret to the app and then use all of its permissions. When that owner is a guest from another organisation, someone outside your control has a path to take over the tenant.' `
                -RecommendedAction 'Remove guest owners from these apps now (Entra admin center > Enterprise applications or App registrations > app > Owners), then check the app for secrets or certificates you do not recognise.' `
                -SourceFile $hsrc -ResultRows $guestOwned -RuleId 'apps-high-permission-app-guest-owner' -ObjectType 'tenant' `
                -AffectedObjectIds @($guestOwned | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($guestOwned | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated permission or ownership issue'
        }
        if ($mtUnverified.Count -gt 0) {
            $thirdParty = @($mtUnverified | Where-Object { $_.Publisher -eq 'Other organisation' }).Count
            Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Applications' `
                -Title ((Format-EACount -Count $mtUnverified.Count -One 'high-permission third-party or multi-tenant app has' -Many 'high-permission third-party or multi-tenant apps have') + ' no verified publisher') `
                -Evidence ("Apps (first 10 of {0}): {1}. Registered in another organisation: {2}; multi-tenant registrations of this tenant: {3}." -f $mtUnverified.Count, (($mtUnverified.ServicePrincipal | Select-Object -First 10) -join ', '), $thirdParty, ($mtUnverified.Count - $thirdParty)) `
                -WhyItMatters 'A verified publisher means Microsoft has confirmed who built the app. Powerful apps from unconfirmed publishers are a common way attackers trick organisations into granting access (consent phishing) or reach many customers at once (supply-chain attack).' `
                -RecommendedAction 'Confirm who publishes each app and that it still needs these permissions; remove the ones you cannot vouch for, and allow user consent only for apps from verified publishers (Entra admin center > Enterprise applications > Consent and permissions).' `
                -SourceFile $hsrc -ResultRows $mtUnverified -RuleId 'apps-high-permission-app-unverified-publisher' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview' `
                -AffectedObjectIds @($mtUnverified | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($mtUnverified | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated permission or ownership issue'
        }
        if ($nonAdminOwned.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Applications' `
                -Title ((Format-EACount -Count $nonAdminOwned.Count -One 'high-permission app is' -Many 'high-permission apps are') + ' owned by a regular or disabled user') `
                -Evidence ("Apps (first 10 of {0}): {1}. An owner counts as an admin when it holds a privileged directory role, active or eligible, directly or through a group." -f $nonAdminOwned.Count, (($nonAdminOwned | Select-Object -First 10 | ForEach-Object { '{0} (owners: {1})' -f $_.ServicePrincipal, $_.Owners }) -join '; ')) `
                -WhyItMatters 'Any owner can add a new secret to the app and then act with its permissions, so an ordinary user who owns it can quietly gain admin-level access. A disabled owner account that is re-enabled or taken over gives the same path.' `
                -RecommendedAction 'Limit owners of high-permission apps to named administrators; remove regular and disabled user owners (Entra admin center > Enterprise applications or App registrations > app > Owners).' `
                -SourceFile $hsrc -ResultRows $nonAdminOwned -RuleId 'apps-high-permission-app-nonadmin-owner' -ObjectType 'tenant' `
                -AffectedObjectIds @($nonAdminOwned | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($nonAdminOwned | ForEach-Object { $_.SpId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated permission or ownership issue'
        }
        if ($ownerReadErrors.Count -gt 0) {
            $oerrSrc = Write-Evidence -BaseName 'app_owner_collection_errors' -Rows $ownerReadErrors -Title 'High-Permission App Owner Read Errors'
            $oerrApps = @($ownerReadErrors | Group-Object SpId | ForEach-Object { $_.Group[0].ServicePrincipal })
            Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Applications' `
                -Title ("Owners of {0} could not be read, so ownership checks are incomplete" -f (Format-EACount -Count $oerrApps.Count -One 'high-permission app' -Many 'high-permission apps')) `
                -Evidence ("Owner lists could not be read for (first 10 of {0}): {1}. First error: {2}. Typical causes: throttling, a missing permission or a transient Graph error." -f $oerrApps.Count, (($oerrApps | Select-Object -First 10) -join ', '), [string]$ownerReadErrors[0].Error) `
                -WhyItMatters 'Without the owner list the audit cannot tell whether these apps have no owner, a guest owner or a regular-user owner, each of which can let someone misuse the app. No finding for them is not a clean result.' `
                -RecommendedAction 'Re-run the apps check when Graph is not throttling, or review the owners of these apps manually (Entra admin center > Enterprise applications > app > Owners).' `
                -SourceFile $oerrSrc -ResultRows $ownerReadErrors -RuleId 'apps-high-permission-app-owners-unreadable' -ObjectType 'tenant' -CoverageGap
        }
        if ($publisherReadErrors.Count -gt 0) {
            Add-EntraFinding -Severity 'Low' -CheckId 'apps' -Category 'Applications' `
                -Title ("Publisher of {0} could not be checked" -f (Format-EACount -Count $publisherReadErrors.Count -One 'third-party high-permission app' -Many 'third-party high-permission apps')) `
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
            -Title ((Format-EACount -Count $ownerRows.Count -One 'app registration with a secret or certificate has' -Many 'app registrations with a secret or certificate have') + ' no owner') `
            -Evidence ("{0} of {1} a secret or certificate {2} no owner. First 10: {3}." -f $ownerRows.Count, (Format-EACount -Count $credApps.Count -One 'app registration that holds' -Many 'app registrations that hold'), $(if ($ownerRows.Count -eq 1) { 'has' } else { 'have' }), (($ownerRows.App | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Nobody is responsible for renewing these credentials or reviewing what the app can do, so a forgotten secret can stay valid and be misused without anyone noticing.' `
            -RecommendedAction 'Assign a named owner to each app registration (Entra admin center > App registrations > app > Owners), or delete apps that are no longer used.' `
            -SourceFile $ownerSrc -ResultRows $ownerRows -RuleId 'apps-credentialed-app-no-owner' -ObjectType 'tenant' `
            -AffectedObjectIds @($ownerRows | ForEach-Object { $_.AppObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'application' -AffectedCount @($ownerRows | ForEach-Object { $_.AppObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'credentialed app registrations with no owner'
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
        $groupRoles = @{}; $rolesKnown = $true; $rolesError = $null; $rolesThrew = $false
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
            } catch { $rolesKnown = $false; $rolesThrew = $true; $rolesError = $_.Exception.Message }
        }

        $grows = @(); $groupOwnerErrors = @()
        foreach ($g in $raGroups) {
            $gOwnersKnown = $true; $gOwners = @()
            # Shared per-run owner cache (accesspaths reads the same groups); it throws on a
            # failed read, which stays a coverage gap below, never "no owners".
            try { $gOwners = @(Get-EAGroupOwner -GroupId ([string]$g.Id)) }
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
        # Will the accesspaths check rate the owners of groups that hold an admin role? Then
        # they are only pointed to here (one owner per fact, no double score). That needs all
        # three: accesspaths is selected in this run, the sign-in has its permissions (else it
        # is Skipped-NoScope and nothing would rate them), and the ACTIVE role assignments
        # were read (accesspaths rates owners from those; a failed eligibility read alone does
        # not stop it - groups whose roles are then unknown stay 'Unknown' and are rated here).
        # Otherwise (e.g. a standalone -apps run, or the run selection is unknown) they are
        # rated here, so the finding is never lost.
        $accessPathsInRun = $false
        try {
            $apScopesOk = (@(Get-EAMissingScope -Required @($script:Registry['accesspaths'].Scopes)).Count -eq 0)
            $accessPathsInRun = (@($script:RunInfo.SelectedChecks) -contains 'accesspaths') -and $apScopesOk
        } catch { $accessPathsInRun = $false }
        $activeRolesKnown = -not ($script:PrivAssignmentsFailed -or $rolesThrew)
        $deferToAccessPaths = $accessPathsInRun -and $activeRolesKnown

        $gsrc = Write-Evidence -BaseName 'role_assignable_groups' -Rows $grows -Title 'Role-Assignable Groups' `
            -Notes @(
                ("Role-assignable groups: {0}; owner list unreadable: {1}; privileged-role data: {2}." -f $raGroups.Count, $groupOwnerErrors.Count, $(if ($rolesKnown) { 'complete' } else { "incomplete ($rolesError)" })),
                ('HoldsAdminRole=Yes: the group holds a privileged directory role (active or eligible). {0}' -f $(if ($deferToAccessPaths) { 'Owners of these groups are rated per owner by the Effective Access / Attack Paths check (-accesspaths) in this run.' } else { 'Owners of these groups are rated here (the Effective Access / Attack Paths check (-accesspaths) was not part of this run, lacks its permissions, or the active role assignments could not be read).' })),
                'HoldsAdminRole=Unknown: the role data could not be read, so the group is treated as if it grants an admin role.',
                'OwnersNotAdmin: owners that are guests, disabled, regular (non-admin) users or non-user objects such as apps. OwnersAdminStatusUnknown: owners whose admin status could not be read.'
            )

        $withRole = @($grows | Where-Object { $_.HoldsAdminRole -eq 'Yes' -and $_.OwnerCount -gt 0 })
        $rateHere = @($grows | Where-Object { $_.OwnerCount -gt 0 -and ($_.HoldsAdminRole -eq 'Unknown' -or ($_.HoldsAdminRole -eq 'Yes' -and -not $deferToAccessPaths)) })
        $noRoleUnsafe = @($grows | Where-Object { $_.HoldsAdminRole -eq 'No' -and $_.UnsafeOwnerCount -gt 0 })
        if ($rateHere.Count -gt 0) {
            $heldCount = @($rateHere | Where-Object { $_.HoldsAdminRole -eq 'Yes' }).Count
            $unknownCount = $rateHere.Count - $heldCount
            $unknownNote = if ($unknownCount -gt 0) { (" For {0} the admin roles could not be read ({1}), so {2}." -f (Format-EACount -Count $unknownCount -One 'group' -Many 'groups'), $rolesError, $(if ($unknownCount -eq 1) { 'it is treated as if it grants one' } else { 'they are treated as if they grant one' })) } else { '' }
            Add-EntraFinding -Severity 'High' -CheckId 'apps' -Category 'Privileged Access' `
                -Title ((Format-EACount -Count $rateHere.Count -One 'role-assignable group has' -Many 'role-assignable groups have') + ' owners who can add members and gain admin roles') `
                -Evidence ("Groups (first 10 of {0}): {1}. Groups that hold a privileged role: {2}.{3} For a per-owner rating run -accesspaths." -f $rateHere.Count, (($rateHere | Select-Object -First 10 | ForEach-Object { '{0} [{1}] (owners: {2})' -f $_.Group, $(if ($_.AdminRoles) { $_.AdminRoles } else { 'roles unknown' }), $_.Owners }) -join '; '), $heldCount, $unknownNote) `
                -WhyItMatters 'An owner of a role-assignable group can add any account, including their own, to the group, and every member receives the admin roles given to the group. It is a quiet way to become an administrator.' `
                -RecommendedAction 'Remove owners who are not trusted administrators (Entra admin center > Groups > group > Owners), and manage membership through Privileged Identity Management (PIM) for Groups with approval.' `
                -SourceFile $gsrc -ResultRows $rateHere -RuleId 'apps-role-assignable-group-owner' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept' `
                -AffectedObjectIds @($rateHere | ForEach-Object { $_.GroupId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'group' -AffectedCount @($rateHere | ForEach-Object { $_.GroupId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'role-assignable groups with an ownership issue'
        }
        if ($noRoleUnsafe.Count -gt 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'apps' -Category 'Privileged Access' `
                -Title ((Format-EACount -Count $noRoleUnsafe.Count -One 'role-assignable group has' -Many 'role-assignable groups have') + ' owners who are not admins and can add members') `
                -Evidence ("Groups that hold no privileged directory role today (first 10 of {0}): {1}." -f $noRoleUnsafe.Count, (($noRoleUnsafe | Select-Object -First 10 | ForEach-Object { '{0} (owners: {1})' -f $_.Group, $_.OwnersNotAdmin }) -join '; ')) `
                -WhyItMatters 'These groups are built to carry admin roles, and their owners can add anyone as a member. If an admin role is later given to the group, or the group already grants access to Azure resources or apps, these owners decide who gets that access.' `
                -RecommendedAction 'Remove regular, guest and disabled owners from role-assignable groups (Entra admin center > Groups > group > Owners), and delete role-assignable groups that are not needed.' `
                -SourceFile $gsrc -ResultRows $noRoleUnsafe -RuleId 'apps-role-assignable-group-nonadmin-owner' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept' `
                -AffectedObjectIds @($noRoleUnsafe | ForEach-Object { $_.GroupId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'group' -AffectedCount @($noRoleUnsafe | ForEach-Object { $_.GroupId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'role-assignable groups with an ownership issue'
        }
        if ($deferToAccessPaths -and $withRole.Count -gt 0) {
            Add-EntraFinding -Severity 'Information' -CheckId 'apps' -Category 'Privileged Access' `
                -Title ("Owners of {0} are rated by the Effective Access check" -f (Format-EACount -Count $withRole.Count -One 'group that holds admin roles' -Many 'groups that hold admin roles')) `
                -Evidence ("Role-assignable groups that hold a privileged role and have owners (first 10 of {0}): {1}." -f $withRole.Count, (($withRole | Select-Object -First 10 | ForEach-Object { '{0} [{1}] (owners: {2})' -f $_.Group, $_.AdminRoles, $_.Owners }) -join '; ')) `
                -WhyItMatters 'An owner of a group that holds an admin role can add themselves and receive that role. The Effective Access / Attack Paths check (-accesspaths) rates each such owner in this run, so the risk is not counted twice.' `
                -RecommendedAction 'Act on the ownership findings of the Effective Access / Attack Paths check (-accesspaths).' `
                -SourceFile $gsrc -ResultRows $withRole -RuleId 'apps-role-assignable-group-owner-see-accesspaths' -ObjectType 'tenant'
        }
        $groupPrivUnknownRows = @($grows | Where-Object { $_.HoldsAdminRole -eq 'No' -and $_.OwnersAdminStatusUnknown -and $_.UnsafeOwnerCount -eq 0 })
        if ($groupOwnerErrors.Count -gt 0) {
            Add-EntraFinding -Severity 'Low' -CheckId 'apps' -Category 'Privileged Access' `
                -Title ("Owners of {0} could not be read" -f (Format-EACount -Count $groupOwnerErrors.Count -One 'role-assignable group' -Many 'role-assignable groups')) `
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
            -Title ("Could not confirm whether the owners of {0} are administrators" -f (Format-EACount -Count $statusUnknownRows.Count -One 'app or group' -Many 'apps or groups')) `
            -Evidence ("Affected (first 10 of {0}): {1}. Reason: {2}." -f $statusUnknownRows.Count, (($statusUnknownRows | Select-Object -First 10 | ForEach-Object { '{0} [{1}]' -f $_.Object, $_.ObjectKind }) -join ', '), ($whyUnknown -join '; ')) `
            -WhyItMatters 'A regular user who owns a high-permission app or a role-assignable group can use it to gain admin access. For these owners the audit could not tell, so a missing finding here is not a clean result.' `
            -RecommendedAction 'Confirm the audit account can read directory roles, Privileged Identity Management (PIM) eligibility and group members (RoleManagement.Read.Directory, Group.Read.All, User.Read.All), then re-run the apps check.' `
            -SourceFile $(if ($hsrc) { $hsrc } else { $gsrc }) -ResultRows $statusUnknownRows -RuleId 'apps-owner-admin-status-unknown' -ObjectType 'tenant' -CoverageGap
    }
}
