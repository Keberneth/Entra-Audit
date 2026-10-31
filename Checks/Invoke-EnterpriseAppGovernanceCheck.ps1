<#
Enterprise Application Governance. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-EnterpriseAppGovernance {
    $checkId = 'enterpriseapps'
    $category = 'Applications'
    $now = (Get-Date).ToUniversalTime()
    $staleDays = if (Get-Variable -Name StaleAppDays -Scope Script -ErrorAction SilentlyContinue) { [int]$script:StaleAppDays } `
        elseif (Get-Variable -Name StaleAppDays -ErrorAction SilentlyContinue) { [int]$StaleAppDays } else { 90 }
    $cutoff = $now.AddDays(-$staleDays)
    $tenantId = $null
    try { $tenantId = [string](Get-MgContext).TenantId } catch {}
    if (-not $tenantId -and $script:Tenant) { $tenantId = [string]$script:Tenant.Id }
    $microsoftOwnerTenants = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
        '72f988bf-86f1-41af-91ab-2d7cd011db47'
    )
    $appPortalPath = 'Entra admin center > Enterprise applications > app'

    $inventoryKnown = $true
    $ownersExpanded = $true
    $servicePrincipals = @()
    $inventoryUri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,appOwnerOrganizationId,createdDateTime,passwordCredentials,keyCredentials,appRoles&$expand=owners($select=id,displayName,userPrincipalName,userType)&$top=100'
    try {
        $servicePrincipals = @(Get-EAReadOnlyGraphCollection -Uri $inventoryUri)
    } catch {
        $ownersExpanded = $false
        try {
            $fallbackUri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,appOwnerOrganizationId,createdDateTime,passwordCredentials,keyCredentials,appRoles&$top=100'
            $servicePrincipals = @(Get-EAReadOnlyGraphCollection -Uri $fallbackUri)
        } catch {
            $inventoryKnown = $false
            $inventoryError = $_.Exception.Message
        }
    }

    if (-not $inventoryKnown) {
        $inventoryGap = @([pscustomobject]@{ Dataset='Enterprise applications'; State='Unknown'; Error=$inventoryError })
        $gapSource = Write-Evidence -BaseName 'enterprise_app_inventory_gaps' -Rows $inventoryGap -Title 'Enterprise Application Inventory Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Enterprise apps could not be read, so app ownership and access were not checked' `
            -Evidence ("The list of service principals (enterprise apps) could not be read: {0}. Owners, assignments, permissions and activity of every enterprise app are unknown." -f $inventoryError) `
            -WhyItMatters 'Apps without an owner, with broad access or no longer in use cannot show up in this report. This is a gap in the audit, not a clean result.' `
            -RecommendedAction 'Make sure the audit account can read applications (Application.Read.All), fix the error shown, and run the enterpriseapps check again.' `
            -SourceFile $gapSource -ResultRows $inventoryGap -RuleId 'enterprise-app-inventory-unknown' -ObjectType 'tenant' -CoverageGap
        return
    }

    $candidates = @($servicePrincipals | Where-Object {
        $type = [string](Get-EAApplicationCheckValue $_ 'servicePrincipalType')
        $ownerTenant = [string](Get-EAApplicationCheckValue $_ 'appOwnerOrganizationId')
        # Managed identities and emerging workload-principal types can hold app roles too;
        # include them for permission blast-radius review. Social identity-provider objects
        # are not enterprise workload clients.
        ($type -ne 'SocialIdp') -and
        ($ownerTenant -notin $microsoftOwnerTenants)
    })

    $activity = Get-EAServicePrincipalSignInActivityState
    $resourceById = @{}
    $roleValueByResource = @{}
    foreach ($resourceSp in $servicePrincipals) {
        $resourceId = [string](Get-EAApplicationCheckValue $resourceSp 'id')
        if ($resourceId) { $resourceById[$resourceId] = $resourceSp }
    }
    $delegatedGrantsKnown = $true
    $delegatedGrants = @()
    try {
        # Reuse the run-wide grant cache of the main script (shared with consentgrants)
        # when it exists; it throws on a failed read, which lands in the catch below.
        # Otherwise read the list here. This list API documents $filter but not $top;
        # follow its nextLink rather than sending an unsupported page-size option.
        if (Get-Command -Name 'Get-EAOAuth2Grants' -CommandType Function -ErrorAction Ignore) {
            $delegatedGrants = @(Get-EAOAuth2Grants)
        } else {
            $delegatedGrants = @(Get-EAReadOnlyGraphCollection -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants')
        }
    } catch {
        $delegatedGrantsKnown = $false
        $delegatedGrantError = $_.Exception.Message
    }
    $governanceRows = New-Object System.Collections.Generic.List[object]
    $assignmentRows = New-Object System.Collections.Generic.List[object]
    $permissionRows = New-Object System.Collections.Generic.List[object]
    $ownerErrors = New-Object System.Collections.Generic.List[object]
    $assignmentErrors = New-Object System.Collections.Generic.List[object]
    $permissionErrors = New-Object System.Collections.Generic.List[object]
    # Each per-app read type stops on its own after an access-denied error or a run of
    # throttled reads (Get-EAApplicationCheckStopReason). Every app that is then not read
    # is counted and reported as a coverage gap, never as "nothing found".
    $ownerStopReason = $null; $assignmentStopReason = $null; $permissionStopReason = $null
    $ownerThrottleRun = 0; $assignmentThrottleRun = 0; $permissionThrottleRun = 0
    $ownerNotRead = 0; $assignmentNotRead = 0; $permissionNotRead = 0
    $managedIdentityAssignmentSkips = 0

    foreach ($sp in $candidates) {
        $spId = [string](Get-EAApplicationCheckValue $sp 'id')
        $appId = [string](Get-EAApplicationCheckValue $sp 'appId')
        $name = [string](Get-EAApplicationCheckValue $sp 'displayName')
        $servicePrincipalType = [string](Get-EAApplicationCheckValue $sp 'servicePrincipalType')
        $ownerTenant = [string](Get-EAApplicationCheckValue $sp 'appOwnerOrganizationId')
        # Graph sets appOwnerOrganizationId only on service principals that have an app
        # registration. Managed identities and agent identities (ServiceIdentity) have none,
        # so the owner-tenant rules (third party, not used) do not apply to them, and a
        # Legacy service principal can only be used in the tenant that created it. Only an
        # Application principal without the value is an unknown owner tenant.
        $ownerClass = if ($servicePrincipalType -in @('ManagedIdentity','ServiceIdentity')) { 'NotApplicable (no app registration)' } `
            elseif ($servicePrincipalType -eq 'Legacy' -and -not $ownerTenant) { 'TenantOwned' } `
            elseif ($ownerTenant -and $tenantId -and $ownerTenant -eq $tenantId) { 'TenantOwned' } `
            elseif (-not $tenantId) { 'OwnerTenantUnknown' } `
            elseif ($ownerTenant) { 'ThirdParty' } else { 'OwnerTenantUnknown' }

        $ownersKnown = $ownersExpanded
        # @(if ...) keeps a one-owner list an array; assigning the if statement directly
        # unrolls it to the owner object, whose Count is its number of fields.
        $owners = @(if ($ownersExpanded) { (Get-EAApplicationCheckValue $sp 'owners') | Where-Object { $_ } })
        if (-not $ownersExpanded) {
            if ($ownerStopReason) {
                $ownerNotRead++
            } else {
                try {
                    $ownerUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + [uri]::EscapeDataString($spId) + '/owners?$select=id,displayName,userPrincipalName,userType'
                    $owners = @(Get-EAReadOnlyGraphCollection -Uri $ownerUri -MaximumPages 50)
                    $ownersKnown = $true
                    $ownerThrottleRun = 0
                } catch {
                    $ownerErrors.Add([pscustomobject]@{ EnterpriseApplication=$name; ObjectId=$spId; StatusCode=(Get-EAApplicationCheckHttpStatus $_); Error=$_.Exception.Message }) | Out-Null
                    $ownerStopReason = Get-EAApplicationCheckStopReason -ErrorRecord $_ -ThrottleRun ([ref]$ownerThrottleRun)
                }
            }
        }

        # User and group assignments (appRoleAssignedTo). A managed identity is an Azure
        # resource's own identity, not an app that people sign in to, so it has no user or
        # group assignments to review; skipping that read saves one Graph request per
        # managed identity. Its row says NotApplicable, not Known.
        $userAssignments = 0
        $groupAssignments = 0
        $otherAssignments = 0
        $assignmentsKnown = $false
        $assignmentReadState = 'Unknown'
        if ($servicePrincipalType -eq 'ManagedIdentity') {
            $assignmentReadState = 'NotApplicable (managed identity)'
            $managedIdentityAssignmentSkips++
        } elseif ($assignmentStopReason) {
            $assignmentNotRead++
        } else {
            try {
                $assignmentUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + [uri]::EscapeDataString($spId) + '/appRoleAssignedTo?$select=id,principalId,principalDisplayName,principalType,appRoleId,createdDateTime'
                $assignments = @(Get-EAReadOnlyGraphCollection -Uri $assignmentUri -MaximumPages 100)
                $assignmentsKnown = $true
                $assignmentReadState = 'Known'
                $assignmentThrottleRun = 0
                foreach ($assignment in $assignments) {
                    $principalType = [string](Get-EAApplicationCheckValue $assignment 'principalType')
                    if ($principalType -eq 'User') { $userAssignments++ }
                    elseif ($principalType -eq 'Group') { $groupAssignments++ }
                    else { $otherAssignments++ }
                    $assignmentRows.Add([pscustomobject]@{
                        EnterpriseApplication=$name; ServicePrincipalId=$spId; AppId=$appId; ServicePrincipalType=$servicePrincipalType
                        PrincipalType=$principalType
                        PrincipalName=[string](Get-EAApplicationCheckValue $assignment 'principalDisplayName')
                        PrincipalId=[string](Get-EAApplicationCheckValue $assignment 'principalId')
                        AppRoleId=[string](Get-EAApplicationCheckValue $assignment 'appRoleId')
                        AssignedDateTime=ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $assignment 'createdDateTime')
                    }) | Out-Null
                }
            } catch {
                $assignmentErrors.Add([pscustomobject]@{ EnterpriseApplication=$name; ObjectId=$spId; StatusCode=(Get-EAApplicationCheckHttpStatus $_); Error=$_.Exception.Message }) | Out-Null
                $assignmentStopReason = Get-EAApplicationCheckStopReason -ErrorRecord $_ -ThrottleRun ([ref]$assignmentThrottleRun)
            }
        }

        # appRoleAssignments are permissions HELD by this client service principal
        # (managed identities included: they are often granted Graph permissions).
        # Resolve every appRoleId against the actual resource service principal so the
        # report carries names rather than GUIDs and can classify new/custom permissions.
        if ($permissionStopReason) {
            $permissionNotRead++
        } else {
            try {
                $permissionUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + [uri]::EscapeDataString($spId) + '/appRoleAssignments?$select=id,resourceId,resourceDisplayName,appRoleId,createdDateTime'
                foreach ($grant in @(Get-EAReadOnlyGraphCollection -Uri $permissionUri -MaximumPages 100)) {
                    $resourceId = [string](Get-EAApplicationCheckValue $grant 'resourceId')
                    $appRoleId = [string](Get-EAApplicationCheckValue $grant 'appRoleId')
                    $resource = if ($resourceById.ContainsKey($resourceId)) { $resourceById[$resourceId] } else { $null }
                    $permissionValue = $null
                    if ($resource) {
                        # Index each resource's appRoles once (Microsoft Graph alone defines
                        # hundreds) instead of scanning them for every grant.
                        if (-not $roleValueByResource.ContainsKey($resourceId)) {
                            $roleMap = @{}
                            foreach ($role in @(Get-EAApplicationCheckElement $resource 'appRoles')) {
                                $roleId = [string](Get-EAApplicationCheckValue $role 'id')
                                if ($roleId) { $roleMap[$roleId] = [string](Get-EAApplicationCheckValue $role 'value') }
                            }
                            $roleValueByResource[$resourceId] = $roleMap
                        }
                        $roleMap = $roleValueByResource[$resourceId]
                        if ($roleMap.ContainsKey($appRoleId)) { $permissionValue = $roleMap[$appRoleId] }
                    }
                    $resourceName = [string](@(
                        Get-EAApplicationCheckValue $grant 'resourceDisplayName'
                        Get-EAApplicationCheckValue $resource 'displayName'
                        $resourceId
                    ) | Where-Object { $_ } | Select-Object -First 1)
                    $risk = Get-EAApplicationPermissionRisk -PermissionValue $permissionValue -ResourceName $resourceName
                    if (-not $permissionValue -and $appRoleId -eq '00000000-0000-0000-0000-000000000000') {
                        # Graph's documented default app role: the principal is assigned to
                        # the resource app without any specific app role or permission.
                        $permissionValue = '(default access)'
                        $risk = [pscustomobject]@{ Risk='Other'; Reason='Default access to the resource app (no specific app role or permission).' }
                    } elseif ($risk.Risk -eq 'Unknown') {
                        $risk.Reason = if (-not $resource) { 'The resource service principal is not in the readable inventory, so the granted appRoleId could not be resolved.' } `
                            else { 'The granted appRoleId is not defined in the resource service principal appRoles, so it could not be resolved to a permission value.' }
                    }
                    $permissionRows.Add([pscustomobject]@{
                        EnterpriseApplication=$name; ServicePrincipalId=$spId; AppId=$appId; ServicePrincipalType=$servicePrincipalType
                        GrantType='Application'; ConsentType='Application'; PrincipalId=''
                        Permission=$permissionValue; AppRoleId=$appRoleId; Resource=$resourceName; ResourceId=$resourceId
                        Risk=$risk.Risk; RiskReason=$risk.Reason
                        GrantedDateTime=ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $grant 'createdDateTime')
                        ReportedUnder=''
                    }) | Out-Null
                }
                $permissionThrottleRun = 0
            } catch {
                $permissionErrors.Add([pscustomobject]@{ EnterpriseApplication=$name; ObjectId=$spId; StatusCode=(Get-EAApplicationCheckHttpStatus $_); Error=$_.Exception.Message }) | Out-Null
                $permissionStopReason = Get-EAApplicationCheckStopReason -ErrorRecord $_ -ThrottleRun ([ref]$permissionThrottleRun)
            }
        }

        $created = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $sp 'createdDateTime')
        $lastSignIn = $null
        $activityState = 'Unknown-ReportUnavailable'
        if ($activity.Known) {
            if ($activity.ByAppId.ContainsKey($appId) -and $activity.ByAppId[$appId]) {
                $lastSignIn = $activity.ByAppId[$appId]
                $activityState = if ($lastSignIn -lt $cutoff) { 'KnownStale' } else { 'Recent' }
            } else {
                $activityState = 'NoRecordedActivity-UnknownUse'
            }
        }

        $enabledValue = Get-EAApplicationCheckValue $sp 'accountEnabled'
        $enabledState = ConvertTo-EAApplicationCheckBoolean $enabledValue
        $assignmentRequiredValue = Get-EAApplicationCheckValue $sp 'appRoleAssignmentRequired'
        $assignmentRequiredKnown = ($null -ne $assignmentRequiredValue)
        $hasCredentials = (@(Get-EAApplicationCheckElement $sp 'passwordCredentials').Count + @(Get-EAApplicationCheckElement $sp 'keyCredentials').Count) -gt 0
        $governanceRows.Add([pscustomobject]@{
            EnterpriseApplication=$name; ObjectId=$spId; AppId=$appId; ServicePrincipalType=$servicePrincipalType; OwnerClass=$ownerClass
            EnabledState=if ($null -eq $enabledState) { 'Unknown' } else { 'Known' }
            Enabled=$enabledState
            OwnerReadState=if ($ownersKnown) { 'Known' } else { 'Unknown' }
            OwnerCount=if ($ownersKnown) { @($owners).Count } else { $null }
            Owners=if ($ownersKnown) { (@($owners | ForEach-Object {
                [string](@(Get-EAApplicationCheckValue $_ 'userPrincipalName'; Get-EAApplicationCheckValue $_ 'displayName'; Get-EAApplicationCheckValue $_ 'id') | Where-Object { $_ } | Select-Object -First 1)
            }) -join ', ') } else { '' }
            AssignmentRequirementState=if ($assignmentRequiredKnown) { 'Known' } else { 'Unknown' }
            AppRoleAssignmentRequired=if ($assignmentRequiredKnown) { [bool]$assignmentRequiredValue } else { $null }
            AssignmentReadState=$assignmentReadState
            UserAssignments=if ($assignmentsKnown) { $userAssignments } else { $null }
            GroupAssignments=if ($assignmentsKnown) { $groupAssignments } else { $null }
            OtherAssignments=if ($assignmentsKnown) { $otherAssignments } else { $null }
            CreatedDateTime=$created; LastSignInDateTime=$lastSignIn; ActivityState=$activityState
            HasCredentials=$hasCredentials
        }) | Out-Null
    }

    # Delegated grants carry their actual scope names as a space-delimited string.
    # Inventory them once tenant-wide, then associate them with the reviewed client SPs.
    if ($delegatedGrantsKnown) {
        $candidateById = @{}
        foreach ($row in $governanceRows) { if ($row.ObjectId) { $candidateById[$row.ObjectId] = $row } }
        foreach ($grant in $delegatedGrants) {
            $clientId = [string](Get-EAApplicationCheckValue $grant 'clientId')
            if (-not $candidateById.ContainsKey($clientId)) { continue }
            $client = $candidateById[$clientId]
            $resourceId = [string](Get-EAApplicationCheckValue $grant 'resourceId')
            $resource = if ($resourceById.ContainsKey($resourceId)) { $resourceById[$resourceId] } else { $null }
            $resourceName = [string](@(Get-EAApplicationCheckValue $resource 'displayName'; $resourceId) | Where-Object { $_ } | Select-Object -First 1)
            $scopes = @(([string](Get-EAApplicationCheckValue $grant 'scope') -split '\s+') | Where-Object { $_ })
            $consentType = [string](Get-EAApplicationCheckValue $grant 'consentType')
            foreach ($scope in $scopes) {
                $risk = Get-EAApplicationPermissionRisk -PermissionValue $scope -ResourceName $resourceName -GrantType Delegated -ConsentType $consentType
                $permissionRows.Add([pscustomobject]@{
                    EnterpriseApplication=$client.EnterpriseApplication; ServicePrincipalId=$clientId; AppId=$client.AppId; ServicePrincipalType=$client.ServicePrincipalType
                    GrantType='Delegated'; ConsentType=$consentType
                    PrincipalId=[string](Get-EAApplicationCheckValue $grant 'principalId')
                    Permission=$scope; AppRoleId=''; Resource=$resourceName; ResourceId=$resourceId
                    Risk=$risk.Risk; RiskReason=$risk.Reason
                    GrantedDateTime=$null
                    ReportedUnder=''
                }) | Out-Null
            }
        }
    }

    # The apps check (application permissions, over-privileged apps without an owner) and
    # the consentgrants check (delegated grants) run earlier and inspect the same grants.
    # A grant or missing owner they already reported at the same or a higher severity is
    # kept in the evidence (ReportedUnder column) but not scored a second time here.
    $appsIndex = Get-EAReportedElsewhereIndex -CheckId 'apps' -KeySelector {
        param($row)
        $spId = [string](Get-EAApplicationCheckValue $row 'SpId')
        $permission = [string](Get-EAApplicationCheckValue $row 'Permission')
        if ($spId -and $permission) { "permission|$spId|$permission" }
        $ownerCount = Get-EAApplicationCheckValue $row 'OwnerCount'
        $ownerAppId = [string](Get-EAApplicationCheckValue $row 'AppId')
        if ($null -ne $ownerCount -and [string]$ownerCount -eq '0' -and $ownerAppId) { "owner|$ownerAppId" }
    }
    # Only the scopes consentgrants itself rated high-impact (its HighImpactScopes column)
    # count as reported there: it reports every grant that holds one of them, for every
    # user, so a per-user grant of such a scope to the same app is always in its list. The
    # other scopes of the same grant string (for example Calendars.Read next to Mail.Read)
    # were never reported by it, and other users' grants of those scopes must still be
    # rated here. Clients are keyed by service-principal object id (ClientId).
    $consentIndex = Get-EAReportedElsewhereIndex -CheckId 'consentgrants' -KeySelector {
        param($row)
        $client = [string](Get-EAApplicationCheckValue $row 'ClientId')
        if (-not $client) { $client = [string](Get-EAApplicationCheckValue $row 'Client') }
        $resource = [string](Get-EAApplicationCheckValue $row 'Resource')
        $grantConsentType = [string](Get-EAApplicationCheckValue $row 'ConsentType')
        foreach ($grantScope in @([string](Get-EAApplicationCheckValue $row 'HighImpactScopes') -split '\s+' | Where-Object { $_ })) {
            if ($client) { "grant|$client|$resource|$grantConsentType|$grantScope" }
        }
    }
    $ownSeverityRank = @{ Tier0=4; WriteHigh=3; HighImpactRead=3; UserDelegatedSensitive=2 }
    # Older consentgrants rows without ClientId name clients by display name; a name shared
    # by two apps is ambiguous, so such apps are matched only by object id.
    $clientNameCount = @{}
    foreach ($governanceRow in $governanceRows) {
        $clientName = [string]$governanceRow.EnterpriseApplication
        if ($clientName) { $clientNameCount[$clientName] = 1 + [int]$clientNameCount[$clientName] }
    }
    foreach ($permissionRow in $permissionRows) {
        $neededRank = $ownSeverityRank[[string]$permissionRow.Risk]
        if (-not $neededRank) { continue }
        if ($permissionRow.GrantType -eq 'Application') {
            $key = ("permission|{0}|{1}" -f $permissionRow.ServicePrincipalId, $permissionRow.Permission).ToLowerInvariant()
            if ($appsIndex.ContainsKey($key) -and $appsIndex[$key] -ge $neededRank) { $permissionRow.ReportedUnder = 'apps' }
            continue
        }
        $clientKeys = @($permissionRow.ServicePrincipalId)
        if ($clientNameCount[[string]$permissionRow.EnterpriseApplication] -eq 1) { $clientKeys += $permissionRow.EnterpriseApplication }
        foreach ($clientKey in $clientKeys) {
            foreach ($resourceKey in @($permissionRow.Resource, $permissionRow.ResourceId)) {
                $key = ("grant|{0}|{1}|{2}|{3}" -f $clientKey, $resourceKey, $permissionRow.ConsentType, $permissionRow.Permission).ToLowerInvariant()
                if ($consentIndex.ContainsKey($key) -and $consentIndex[$key] -ge $neededRank) { $permissionRow.ReportedUnder = 'consentgrants' }
            }
        }
    }

    $rows = @($governanceRows.ToArray())

    # Apps registered in this tenant (by Graph, the CLI or Terraform) usually have their
    # owner on the app registration and none on the enterprise app. The registration owner
    # is the one who renews credentials and removes the app, and the apps check counts
    # registration owners too, so both lists count here. Third-party apps have no app
    # registration in this tenant; managed identities have none at all. A failed read of
    # the registrations is a coverage gap for the apps it matters to, never "no owner".
    $ownerRuleTypes = @('Application','Legacy','')
    $registrationOwnersKnown = $true
    $registrationOwnersError = $null
    $registrationOwnersByAppId = @{}
    if (@($rows | Where-Object { $_.OwnerClass -ne 'ThirdParty' -and $_.ServicePrincipalType -in $ownerRuleTypes }).Count -gt 0) {
        try {
            # Reuse the run-wide application cache of the main script (owners expanded)
            # when it exists; otherwise read the registrations here.
            $registrations = @(if (Get-Command -Name 'Get-EAApplications' -CommandType Function -ErrorAction Ignore) { Get-EAApplications } `
                else { Get-EAReadOnlyGraphCollection -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId&$expand=owners($select=id)&$top=100' })
            foreach ($registration in $registrations) {
                $registrationAppId = [string](Get-EAApplicationCheckValue $registration 'appId')
                if ($registrationAppId) {
                    $registrationOwnersByAppId[$registrationAppId.ToLowerInvariant()] = @((Get-EAApplicationCheckValue $registration 'owners') | Where-Object { $_ }).Count
                }
            }
        } catch {
            $registrationOwnersKnown = $false
            $registrationOwnersError = $_.Exception.Message
        }
    }
    $registrationOwnerGapCount = 0
    foreach ($row in $rows) {
        $registrationApplies = ($row.OwnerClass -ne 'ThirdParty' -and $row.ServicePrincipalType -in $ownerRuleTypes)
        $registrationOwnerCount = $null
        if ($registrationApplies -and $registrationOwnersKnown) {
            $registrationKey = ([string]$row.AppId).ToLowerInvariant()
            # Not in the list: no app registration in this tenant, so no registration owner.
            $registrationOwnerCount = if ($registrationKey -and $registrationOwnersByAppId.ContainsKey($registrationKey)) { [int]$registrationOwnersByAppId[$registrationKey] } else { 0 }
        }
        $effectiveOwnerCount = if ($null -eq $row.OwnerCount) { $null } `
            elseif (-not $registrationApplies) { $row.OwnerCount } `
            elseif ($null -eq $registrationOwnerCount) { $null } `
            else { $row.OwnerCount + $registrationOwnerCount }
        $row | Add-Member -NotePropertyName RegistrationOwnerCount -NotePropertyValue $registrationOwnerCount -Force
        $row | Add-Member -NotePropertyName EffectiveOwnerCount -NotePropertyValue $effectiveOwnerCount -Force
        if ($registrationApplies -and -not $registrationOwnersKnown -and $row.Enabled -and $row.OwnerReadState -eq 'Known' -and $row.OwnerCount -eq 0) {
            $registrationOwnerGapCount++
        }
    }

    $source = Write-Evidence -BaseName 'enterprise_app_governance' -Rows $rows -Title 'Enterprise Application Governance' `
        -Notes @(
            ("Excluded Microsoft first-party owner tenants and SocialIdp objects; reviewed {0}." -f (Format-EAApplicationCheckCount -Count $rows.Count -One 'tenant-owned, third-party, managed, or owner-tenant-unknown workload service principal' -Many 'tenant-owned, third-party, managed, or owner-tenant-unknown workload service principals')),
            ("AssignmentReadState = NotApplicable (managed identity): {0}" -f (Format-EAApplicationCheckCount -Count $managedIdentityAssignmentSkips -One 'managed identity is an Azure resource identity, not an app that people sign in to, so its user and group assignments were not read. Its granted permissions were read.' -Many 'managed identities are Azure resource identities, not apps that people sign in to, so their user and group assignments were not read. Their granted permissions were read.')),
            'OwnerClass = NotApplicable (no app registration): managed identities and agent identities have no app registration and therefore no owner tenant, so the third-party and unused-app rules do not apply to them. A Legacy service principal can only be used in the tenant that created it, so it counts as tenant-owned.',
            'EffectiveOwnerCount = enterprise-app owners (OwnerCount) plus, for apps registered in this tenant, the owners of the app registration (RegistrationOwnerCount), the same way the apps check counts owners. RegistrationOwnerCount is empty for third-party apps and managed identities, and EffectiveOwnerCount is empty when an owner list could not be read.',
            'NoRecordedActivity-UnknownUse is deliberately not treated as proof that an app is unused.'
        )
    $assignmentSource = Write-Evidence -BaseName 'enterprise_app_assignments' -Rows @($assignmentRows.ToArray()) -Title 'Enterprise Application User and Group Assignments'
    $permissionSource = Write-Evidence -BaseName 'enterprise_app_granted_permissions' -Rows @($permissionRows.ToArray()) `
        -Title 'Enterprise Application Granted Application and Delegated Permissions' `
        -Notes @(
            'Application permission names are resolved from each resource service principal app-role definition; delegated grants use their actual scope strings. Unresolved app-role IDs remain an explicit coverage gap.',
            'Application permissions on the apps check''s top-risk list (tenant takeover, all mail, all files) are rated Tier0 here as well, so both checks rate them the same.',
            'ReportedUnder = apps or consentgrants: the same grant was already reported by that check at the same or a higher severity; it is listed here but not counted again.'
        )

    $coverageRows = @()
    if (-not $ownersExpanded) { $coverageRows += @($ownerErrors.ToArray()) }
    if ($ownerNotRead -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=('Remaining ' + (Format-EAApplicationCheckCount -Count $ownerNotRead -One 'enterprise application' -Many 'enterprise applications')); ObjectId=''; StatusCode=''; Error=("Owners not read: owner reads stopped because {0}." -f $ownerStopReason) } }
    if ($registrationOwnerGapCount -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=(Format-EAApplicationCheckCount -Count $registrationOwnerGapCount -One 'enabled enterprise application without an enterprise-app owner' -Many 'enabled enterprise applications without an enterprise-app owner'); ObjectId=''; StatusCode=''; Error=("App-registration owners not read, so it is unknown whether these apps have an owner on their app registration: {0}" -f $registrationOwnersError) } }
    $coverageRows += @($assignmentErrors.ToArray())
    if ($assignmentNotRead -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=('Remaining ' + (Format-EAApplicationCheckCount -Count $assignmentNotRead -One 'enterprise application' -Many 'enterprise applications')); ObjectId=''; StatusCode=''; Error=("User and group assignments not read: assignment reads stopped because {0}." -f $assignmentStopReason) } }
    $coverageRows += @($permissionErrors.ToArray())
    if ($permissionNotRead -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=('Remaining ' + (Format-EAApplicationCheckCount -Count $permissionNotRead -One 'enterprise application' -Many 'enterprise applications')); ObjectId=''; StatusCode=''; Error=("Granted permissions not read: permission reads stopped because {0}." -f $permissionStopReason) } }
    if (-not $delegatedGrantsKnown) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='All reviewed enterprise applications'; ObjectId=''; StatusCode=''; Error=("Delegated OAuth grant inventory unavailable: {0}" -f $delegatedGrantError) } }
    $unresolvedPermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'Unknown' })
    if ($unresolvedPermissions.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=(Format-EAApplicationCheckCount -Count $unresolvedPermissions.Count -One 'grant' -Many 'grants'); ObjectId=''; StatusCode=''; Error='Granted appRoleId could not be resolved to a permission value.' } }
    if (-not $activity.Known) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='All non-Microsoft enterprise applications'; ObjectId=''; StatusCode=''; Error=("Service-principal sign-in activity unavailable: {0}" -f $activity.Error) } }
    if (-not $tenantId) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='All reviewed enterprise applications'; ObjectId=''; StatusCode=''; Error='The Graph tenant id was unavailable, so tenant-owned versus third-party classification is unknown.' } }
    # Only an app-registration-backed principal is expected to carry appOwnerOrganizationId
    # (managed identities, agent identities and Legacy principals never do). Without the
    # tenant id every row is unknown, and the row above already says why.
    $unknownOwnerTenant = @(if ($tenantId) {
        $rows | Where-Object { $_.OwnerClass -eq 'OwnerTenantUnknown' -and $_.ServicePrincipalType -notin @('ManagedIdentity','ServiceIdentity','Legacy') }
    })
    if ($unknownOwnerTenant.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=(Format-EAApplicationCheckCount -Count $unknownOwnerTenant.Count -One 'application' -Many 'applications'); ObjectId=''; StatusCode=''; Error='appOwnerOrganizationId was not returned, so tenant-owned versus third-party lifecycle rules could not be applied.' } }
    $unknownEnabled = @($rows | Where-Object { $_.EnabledState -eq 'Unknown' })
    if ($unknownEnabled.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=(Format-EAApplicationCheckCount -Count $unknownEnabled.Count -One 'application' -Many 'applications'); ObjectId=''; StatusCode=''; Error='accountEnabled was not returned or was not a recognized boolean value.' } }
    $unknownRequirement = @($rows | Where-Object { $_.AssignmentRequirementState -eq 'Unknown' })
    if ($unknownRequirement.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=(Format-EAApplicationCheckCount -Count $unknownRequirement.Count -One 'application' -Many 'applications'); ObjectId=''; StatusCode=''; Error='appRoleAssignmentRequired was not returned.' } }
    if ($coverageRows.Count -gt 0) {
        $gapKinds = @()
        if ($ownerErrors.Count -gt 0 -or $ownerNotRead -gt 0 -or $registrationOwnerGapCount -gt 0) { $gapKinds += 'owners' }
        if ($assignmentErrors.Count -gt 0 -or $assignmentNotRead -gt 0) { $gapKinds += 'user and group assignments' }
        if ($permissionErrors.Count -gt 0 -or $permissionNotRead -gt 0 -or -not $delegatedGrantsKnown -or $unresolvedPermissions.Count -gt 0) { $gapKinds += 'granted permissions' }
        if (-not $activity.Known) { $gapKinds += 'sign-in activity' }
        if (-not $tenantId -or $unknownOwnerTenant.Count -gt 0 -or $unknownEnabled.Count -gt 0 -or $unknownRequirement.Count -gt 0) { $gapKinds += 'app properties' }
        $stopText = @(
            if ($ownerStopReason) { "owner reads stopped because $ownerStopReason" }
            if ($assignmentStopReason) { "assignment reads stopped because $assignmentStopReason" }
            if ($permissionStopReason) { "permission reads stopped because $permissionStopReason" }
        ) -join '; '
        $coverageSource = Write-Evidence -BaseName 'enterprise_app_governance_gaps' -Rows $coverageRows -Title 'Enterprise Application Governance Coverage Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Some enterprise app details could not be read, so app findings may be incomplete' `
            -Evidence ("{0} recorded in: {1}.{2} Apps with a gap are not counted as clean." -f (Format-EAApplicationCheckCount -Count $coverageRows.Count -One 'gap' -Many 'gaps'), ($gapKinds -join ', '), $(if ($stopText) { " Reads were cut short: $stopText." } else { '' })) `
            -WhyItMatters 'Apps whose owners, assignments, permissions or sign-in activity could not be read were not fully checked, so some ownerless, over-permissioned or unused apps may be missing from this report.' `
            -RecommendedAction 'Check the gaps file for the exact errors. Usually: give the audit account Application.Read.All, Directory.Read.All and AuditLog.Read.All, confirm an Entra ID P1 license for sign-in activity, wait for throttling to clear, then run the enterpriseapps check again.' `
            -SourceFile $coverageSource -ResultRows $coverageRows -RuleId 'enterprise-app-governance-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }

    # EffectiveOwnerCount is empty (never 0) when an owner list could not be read, so such
    # apps are a coverage gap above, not "no owner".
    $ownerlessAll = @($rows | Where-Object {
        $_.Enabled -and $_.ServicePrincipalType -in $ownerRuleTypes -and $_.OwnerReadState -eq 'Known' -and $_.EffectiveOwnerCount -eq 0
    })
    # The apps check reports high-permission apps without an owner as Critical.
    $ownerlessReportedElsewhere = @($ownerlessAll | Where-Object { $_.AppId -and $appsIndex.ContainsKey(("owner|{0}" -f $_.AppId).ToLowerInvariant()) })
    $ownerless = @($ownerlessAll | Where-Object { $_ -notin $ownerlessReportedElsewhere })
    if ($ownerless.Count -gt 0) {
        # "Reported by the apps check instead" is only true when that check ran to the end in
        # this run (it runs before this one); otherwise high-permission apps without an owner
        # are listed here and nowhere else.
        $appsStatus = $null
        $checkStatusVariable = Get-Variable -Name CheckStatus -Scope Script -ErrorAction SilentlyContinue
        if ($checkStatusVariable -and $checkStatusVariable.Value -is [System.Collections.IDictionary] -and $checkStatusVariable.Value.Contains('apps')) {
            $appsStatus = [string](Get-EAApplicationCheckValue $checkStatusVariable.Value['apps'] 'Status')
        }
        $appsCheckCompleted = ($appsStatus -and $appsStatus -notlike 'Skipped*' -and $appsStatus -ne 'Error')
        $ownerlessNotes = @()
        if ($ownerlessReportedElsewhere.Count -gt 0) {
            $ownerlessNotes += (Format-EAApplicationCheckCount -Count $ownerlessReportedElsewhere.Count `
                -One 'other app without an owner also holds high-risk permissions and is' `
                -Many 'other apps without an owner also hold high-risk permissions and are') +
                " reported by the apps check (-apps) as Critical instead (listed in this check's 'already reported by another check' note)."
        } elseif ($appsCheckCompleted) {
            $ownerlessNotes += 'Apps that also hold high-risk permissions are reported by the apps check (-apps) as Critical instead.'
        }
        if (-not $appsCheckCompleted) {
            $ownerlessNotes += 'Run the apps check (-apps) to see which of these also hold high-risk permissions (reported there as Critical).'
        }
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $ownerless.Count -One 'enabled enterprise app has no owner' -Many 'enabled enterprise apps have no owner') `
            -Evidence ("Enabled apps with no owner: {0}. Neither the enterprise app nor, for apps registered in this tenant, the app registration has an owner. {1}" -f (Format-EAApplicationCheckList @($ownerless.EnterpriseApplication)), ($ownerlessNotes -join ' ')) `
            -WhyItMatters 'Without a named owner, nobody is responsible for reviewing who can use the app, renewing or removing its credentials, or deleting it when it is no longer needed.' `
            -RecommendedAction 'Assign at least one owner to each app and record what the app is for, or remove apps that are no longer used. For an app registered in this tenant, add the owner in Entra admin center > App registrations > app > Owners; for other apps, in Enterprise applications > app > Owners.' `
            -SourceFile $source -ResultRows $ownerless -RuleId 'enterprise-app-ownerless' -ObjectType 'servicePrincipal' `
            -AffectedObjectIds @($ownerless | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($ownerless | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated governance issue'
    }

    $unrestricted = @($rows | Where-Object {
        $_.Enabled -and $_.ServicePrincipalType -in @('Application','Legacy','') -and $_.OwnerClass -eq 'ThirdParty' -and
        $_.AssignmentRequirementState -eq 'Known' -and -not $_.AppRoleAssignmentRequired
    })
    if ($unrestricted.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $unrestricted.Count -One 'third-party app' -Many 'third-party apps') + ' can be used by every user because assignment is not required') `
            -Evidence ("'Assignment required' is off (appRoleAssignmentRequired = false) for: {0}." -f (Format-EAApplicationCheckList @($unrestricted.EnterpriseApplication))) `
            -WhyItMatters 'When assignment is not required, every user in the tenant can sign in to the app, not only the people who need it.' `
            -RecommendedAction ("For apps that only some people should use, turn on 'Assignment required?' ({0} > Properties) and assign the right users or groups. Apps that are not used for user sign-in can be left as they are." -f $appPortalPath) `
            -SourceFile $source -ResultRows $unrestricted -RuleId 'enterprise-app-assignment-not-required' -ObjectType 'servicePrincipal' `
            -AffectedObjectIds @($unrestricted | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($unrestricted | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated governance issue'
    }

    $groupAssigned = @($rows | Where-Object { $_.Enabled -and $_.AssignmentReadState -eq 'Known' -and $_.GroupAssignments -gt 0 })
    if ($groupAssigned.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $groupAssigned.Count -One 'enterprise app gives access through group membership' -Many 'enterprise apps give access through group membership') `
            -Evidence ("{0} on: {1}." -f (Format-EAApplicationCheckCount -Count (($groupAssigned | Measure-Object GroupAssignments -Sum).Sum) -One 'group assignment' -Many 'group assignments'), (Format-EAApplicationCheckList @($groupAssigned.EnterpriseApplication))) `
            -WhyItMatters 'Group assignment is a normal way to manage access. Direct user members of an assigned group receive access; nested group membership does not grant access to the app.' `
            -RecommendedAction ("Keep assigned groups owned and their direct user membership reviewed ({0} > Users and groups). Group assignment alone requires no remediation; address any separate group-governance findings." -f $appPortalPath) `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal' `
            -SourceFile $assignmentSource -ResultRows @($assignmentRows.ToArray() | Where-Object { $_.PrincipalType -eq 'Group' }) -RuleId 'enterprise-app-group-assignment' -ObjectType 'servicePrincipal'
    }

    $tier0Permissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'Tier0' -and -not $_.ReportedUnder })
    $writePermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'WriteHigh' -and -not $_.ReportedUnder })
    $highReadPermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'HighImpactRead' -and -not $_.ReportedUnder })
    $userDelegatedPermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'UserDelegatedSensitive' -and -not $_.ReportedUnder })
    $permissionSummary = {
        param([object[]]$PermissionList)
        Format-EAApplicationCheckList @($PermissionList | Group-Object Permission | Sort-Object Count -Descending | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count })
    }
    if ($tier0Permissions.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $tier0Permissions.Count -One 'app permission allows' -Many 'app permissions allow') + ' tenant takeover or full access to all mail or files') `
            -Evidence ("Apps: {0}. Permissions (number of grants): {1}." -f (Format-EAApplicationCheckList @($tier0Permissions.EnterpriseApplication)), (& $permissionSummary $tier0Permissions)) `
            -WhyItMatters 'These permissions let an app take over the tenant (for example by making itself a Global Administrator) or read all mail or files. Anyone who steals the app''s secret, or controls a user who has signed in to the app, can do the same.' `
            -RecommendedAction ("Remove every one of these permissions that is not strictly needed ({0} > Permissions); replace the rest with narrower permissions, and make sure each app has a named owner and uses certificate credentials." -f $appPortalPath) `
            -SourceFile $permissionSource -ResultRows $tier0Permissions -RuleId 'enterprise-app-tier0-permission' -ObjectType 'servicePrincipal' `
            -AffectedObjectIds @($tier0Permissions | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($tier0Permissions | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated permission tier'
    }
    if ($writePermissions.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $writePermissions.Count -One 'app permission lets an app' -Many 'app permissions let apps') + ' change data, send mail or manage settings') `
            -Evidence ("Apps: {0}. Permissions (number of grants): {1}." -f (Format-EAApplicationCheckList @($writePermissions.EnterpriseApplication)), (& $permissionSummary $writePermissions)) `
            -WhyItMatters 'If the app or its secret is misused, it can change data, send mail or change settings in everything the permission covers.' `
            -RecommendedAction ("Remove write permissions the app does not need and replace broad ones with the narrowest permission that works ({0} > Permissions)." -f $appPortalPath) `
            -SourceFile $permissionSource -ResultRows $writePermissions -RuleId 'enterprise-app-write-permission' -ObjectType 'servicePrincipal' `
            -AffectedObjectIds @($writePermissions | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($writePermissions | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated permission tier'
    }
    if ($highReadPermissions.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $highReadPermissions.Count -One 'app permission lets an app' -Many 'app permissions let apps') + ' read sensitive data across the tenant') `
            -Evidence ("Read access to tenant-wide mail, files, chats, directory, audit or security data on {0}: {1}. Permissions (number of grants): {2}." -f (Format-EAApplicationCheckCount -Count (@($highReadPermissions.EnterpriseApplication | Select-Object -Unique).Count) -One 'app' -Many 'apps'),
                (Format-EAApplicationCheckList @($highReadPermissions.EnterpriseApplication)), (& $permissionSummary $highReadPermissions)) `
            -WhyItMatters 'Read-only access to all mail, files, chats or directory and security data is enough for large-scale data theft if the app or its secret is misused.' `
            -RecommendedAction ("Confirm each permission is really needed and remove the rest ({0} > Permissions); where the API supports it, limit access to specific mailboxes or sites." -f $appPortalPath) `
            -SourceFile $permissionSource -ResultRows $highReadPermissions -RuleId 'enterprise-app-high-impact-read' -ObjectType 'servicePrincipal' `
            -AffectedObjectIds @($highReadPermissions | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($highReadPermissions | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated permission tier'
    }
    if ($userDelegatedPermissions.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $userDelegatedPermissions.Count -One 'app permission granted by a single user gives' -Many 'app permissions granted by single users give') + ' access to their mail, files or data') `
            -Evidence ("{0} (usually because that user accepted a consent prompt): {1}. Each app can act only as that user, not for the whole tenant." -f (Format-EAApplicationCheckCount -Count (@($userDelegatedPermissions.EnterpriseApplication | Select-Object -Unique).Count) -One 'app holds these permissions for one specific user' -Many 'apps hold these permissions for one specific user each'),
                (Format-EAApplicationCheckList @($userDelegatedPermissions.EnterpriseApplication))) `
            -WhyItMatters 'Attackers trick users into accepting a malicious app (consent phishing). The app then keeps access to that user''s mail, files, or data until the permission is removed.' `
            -RecommendedAction ("Check each app in the evidence list ({0} > Permissions > User consent). Remove permissions for apps you do not recognise or no longer need, and limit user consent to verified publishers and low-risk permissions." -f $appPortalPath) `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions' `
            -SourceFile $permissionSource -ResultRows $userDelegatedPermissions -RuleId 'enterprise-app-user-delegated-sensitive' -ObjectType 'servicePrincipal' `
            -AffectedObjectIds @($userDelegatedPermissions | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($userDelegatedPermissions | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated permission tier'
    }

    if ($activity.Known) {
        $knownStale = @($rows | Where-Object { $_.Enabled -and $_.OwnerClass -eq 'ThirdParty' -and $_.ActivityState -eq 'KnownStale' })
        $noRecorded = @($rows | Where-Object {
            $_.Enabled -and $_.OwnerClass -eq 'ThirdParty' -and $_.ActivityState -eq 'NoRecordedActivity-UnknownUse' -and
            ((-not $_.CreatedDateTime) -or $_.CreatedDateTime -lt $cutoff)
        })
        if ($knownStale.Count -gt 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title ((Format-EAApplicationCheckCount -Count $knownStale.Count -One 'third-party app is still enabled but has' -Many 'third-party apps are still enabled but have') + (' not been used for over {0} days' -f $staleDays)) `
                -Evidence ("Last recorded sign-in is older than {0} days for: {1}." -f $staleDays, (Format-EAApplicationCheckList @($knownStale.EnterpriseApplication))) `
                -WhyItMatters 'An app that nobody uses still keeps its access to your data and any credentials it has. Forgotten apps are easy targets because nobody would notice if they were misused.' `
                -RecommendedAction ("Confirm with the app owner that the app is no longer needed, disable it first ({0} > Properties > 'Enabled for users to sign in?' = No), then delete it after a waiting period." -f $appPortalPath) `
                -SourceFile $source -ResultRows $knownStale -RuleId 'enterprise-app-known-stale' -ObjectType 'servicePrincipal' `
                -AffectedObjectIds @($knownStale | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($knownStale | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with the stated governance issue'
        }
        if ($noRecorded.Count -gt 0) {
            Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
                -Title (Format-EAApplicationCheckCount -Count $noRecorded.Count -One 'older third-party app has no recorded sign-in, so its use is unknown' -Many 'older third-party apps have no recorded sign-in, so their use is unknown') `
                -Evidence ("The sign-in activity report was readable but had no usable timestamp for: {0}. Their use is unknown, not proven absent." -f (Format-EAApplicationCheckList @($noRecorded.EnterpriseApplication))) `
                -WhyItMatters 'These apps may never have been used or may be forgotten, but the activity report cannot prove that, so check before removing them.' `
                -RecommendedAction 'Ask the app owner whether the app is still used. If not, disable it first and delete it after a waiting period.' `
                -SourceFile $source -ResultRows $noRecorded -RuleId 'enterprise-app-no-recorded-activity' -ObjectType 'servicePrincipal' -CoverageGap
        }
    }

    $reportedElsewhere = @(
        foreach ($permissionRow in @($permissionRows.ToArray() | Where-Object { $_.ReportedUnder })) {
            [pscustomobject]@{
                EnterpriseApplication=$permissionRow.EnterpriseApplication; AppId=$permissionRow.AppId
                Item=("{0} permission {1} on {2}" -f $permissionRow.GrantType, $permissionRow.Permission, $permissionRow.Resource)
                ReportedUnder=$permissionRow.ReportedUnder
            }
        }
        foreach ($ownerlessRow in $ownerlessReportedElsewhere) {
            [pscustomobject]@{ EnterpriseApplication=$ownerlessRow.EnterpriseApplication; AppId=$ownerlessRow.AppId; Item='No owner'; ReportedUnder='apps' }
        }
    )
    if ($reportedElsewhere.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $reportedElsewhere.Count -One 'enterprise app issue is' -Many 'enterprise app issues are') + ' already reported by another check') `
            -Evidence ("These permissions or missing owners were already reported by the {0} at the same or a higher severity. They are listed here for completeness but not counted twice." -f $(
                $otherChecks = @($reportedElsewhere.ReportedUnder | Select-Object -Unique)
                if ($otherChecks.Count -eq 1) { "$($otherChecks[0]) check" } else { "{0} checks" -f ($otherChecks -join ' and ') })) `
            -WhyItMatters 'Counting the same app permission or missing owner in two checks would show one problem twice and inflate the risk score.' `
            -RecommendedAction 'Fix these items using the findings of the check named in the ReportedUnder column; nothing extra is needed here.' `
            -SourceFile $permissionSource -ResultRows $reportedElsewhere -RuleId 'enterprise-app-reported-elsewhere' -ObjectType 'tenant'
    }

    $riskFindings = @($script:Findings | Where-Object { $_.CheckId -eq $checkId -and $_.Severity -ne 'Information' })
    if ($riskFindings.Count -eq 0 -and $reportedElsewhere.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'No problems found with enterprise app ownership, access or activity' `
            -Evidence ("{0}, {1}, and {2} were inventoried." -f (Format-EAApplicationCheckCount -Count $rows.Count -One 'non-Microsoft enterprise application' -Many 'non-Microsoft enterprise applications'), (Format-EAApplicationCheckCount -Count $assignmentRows.Count -One 'direct access assignment' -Many 'direct access assignments'), (Format-EAApplicationCheckCount -Count $permissionRows.Count -One 'granted application/delegated permission entry' -Many 'granted application/delegated permission entries')) `
            -WhyItMatters 'Apps with a named owner, limited access and regular clean-up give attackers fewer forgotten ways into your data.' `
            -RecommendedAction 'Keep asking app owners to confirm their apps regularly, review access, and remove apps that are no longer used.' `
            -SourceFile $source -ResultRows $rows -RuleId 'enterpriseapps-reviewed' -ObjectType 'tenant'
    }
}
