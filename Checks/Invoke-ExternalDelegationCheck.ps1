<#
External Delegation & Partner Trust. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-ExternalDelegation {
    [CmdletBinding()]
    param()

    $checkId = 'externaldelegation'
    $doc = 'https://learn.microsoft.com/graph/api/tenantrelationship-list-delegatedadminrelationships?view=graph-rest-1.0'
    $sponsorDoc = 'https://learn.microsoft.com/graph/api/user-list-sponsors?view=graph-rest-1.0'
    $guestDoc = 'https://learn.microsoft.com/graph/api/user-list?view=graph-rest-1.0'
    $gdapGuideDoc = 'https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction'
    $sponsorGuideDoc = 'https://learn.microsoft.com/en-us/entra/external-id/b2b-sponsors'
    $guestReviewDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/manage-guest-access-with-access-reviews'
    $customerPartnerDoc = 'https://learn.microsoft.com/en-us/microsoft-365/commerce/manage-partners'
    # Customer side: where this tenant sees and removes partners that manage it.
    $partnerPath = 'Microsoft 365 admin center > Settings > Partner relationships'
    # Partner side: where this tenant, as a partner, manages its access to customers.
    $partnerCenterPath = 'Partner Center > Customers > [customer] > Admin relationships'

    # ------------------------- GDAP relationships -------------------------
    # Direction matters. GET /tenantRelationships/delegatedAdminRelationships is the
    # PARTNER-side API: it lists the relationships this tenant holds, as a Microsoft
    # partner, with its customers, and the roles it can use in THEIR tenants. It returns
    # nothing about partners that hold admin roles in this tenant, and Microsoft Graph has
    # no read-only customer-side API for that. So every row below is outbound access
    # (customer = the other tenant), and a separate note always tells the reader that
    # inbound partner access must be checked by hand; an empty list never means "no
    # partner has admin access to this tenant".
    $relationshipResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships?$top=300'
    $relationships = @(if ($relationshipResult.Success) { @($relationshipResult.Rows) } else { @() })

    # Role definitions come from the main script's shared cache, and are only loaded
    # when there is at least one relationship to classify. If the read fails,
    # Get-EARoleInfo still recognises the static tier-0/privileged template ids and
    # reports everything else as Unknown (with a coverage finding), never Standard.
    $roleDefinitionsKnown = $true
    $roleDefinitionError = $null
    if ($relationships.Count -gt 0) {
        try { Get-EARoleDefMap | Out-Null }
        catch { $roleDefinitionsKnown = $false; $roleDefinitionError = [string]$_.Exception.Message }
    }

    $relationshipRows = New-Object System.Collections.Generic.List[object]
    foreach ($relationship in $relationships) {
        $access = Get-EAGovProperty $relationship 'accessDetails'
        $roles = @(Get-EAGovProperty $access 'unifiedRoles')
        if ($roles.Count -eq 0) { $roles = @($null) }
        foreach ($roleRef in $roles) {
            $roleId = [string](Get-EAGovProperty $roleRef 'roleDefinitionId')
            $roleClass = Get-EAGovDirectoryRoleRisk -RoleDefinitionId $roleId
            $relationshipRows.Add([pscustomobject]@{
                RelationshipId      = Get-EAGovProperty $relationship 'id'
                DisplayName         = Get-EAGovProperty $relationship 'displayName'
                Status              = Get-EAGovProperty $relationship 'status'
                CustomerTenantId    = Get-EAGovProperty (Get-EAGovProperty $relationship 'customer') 'tenantId'
                CustomerDisplayName = Get-EAGovProperty (Get-EAGovProperty $relationship 'customer') 'displayName'
                CreatedDateTime     = Get-EAGovProperty $relationship 'createdDateTime'
                ActivatedDateTime   = Get-EAGovProperty $relationship 'activatedDateTime'
                LastModifiedDateTime = Get-EAGovProperty $relationship 'lastModifiedDateTime'
                EndDateTime         = Get-EAGovProperty $relationship 'endDateTime'
                Duration            = Get-EAGovProperty $relationship 'duration'
                DurationDays        = ConvertFrom-EAGovDurationDays (Get-EAGovProperty $relationship 'duration')
                AutoExtendDuration  = Get-EAGovProperty $relationship 'autoExtendDuration'
                RoleDefinitionId    = $roleId
                RoleDisplayName     = $roleClass.Name
                RoleRisk            = $roleClass.Risk
            }) | Out-Null
        }
    }
    $relationshipSrc = Write-Evidence -BaseName 'external_delegated_admin_relationships' -Rows $relationshipRows.ToArray() `
        -Title 'Granular Delegated Admin Privileges (GDAP) Relationships and Approved Roles'

    # Relationship accessDetails describes the roles approved for the
    # relationship. Effective partner access is represented by active
    # accessAssignments that bind those roles to a partner security group.
    $accessAssignmentRows = New-Object System.Collections.Generic.List[object]
    $accessAssignmentErrors = New-Object System.Collections.Generic.List[object]
    $activeRelationshipsWithoutAssignments = New-Object System.Collections.Generic.List[object]
    foreach ($relationship in @($relationships | Where-Object { [string](Get-EAGovProperty $_ 'status') -ieq 'active' })) {
        $relationshipId = [string](Get-EAGovProperty $relationship 'id')
        $customer = Get-EAGovProperty $relationship 'customer'
        $customerTenantId = Get-EAGovProperty $customer 'tenantId'
        $customerDisplayName = Get-EAGovProperty $customer 'displayName'
        if (-not $relationshipId) {
            $accessAssignmentErrors.Add([pscustomobject]@{ RelationshipId=$null; Relationship=(Get-EAGovProperty $relationship 'displayName'); Reason='active relationship has no id' }) | Out-Null
            continue
        }
        $assignmentResult = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships/{0}/accessAssignments?`$top=300" -f [uri]::EscapeDataString($relationshipId))
        if (-not $assignmentResult.Success -or $assignmentResult.Truncated) {
            $reason = if ($assignmentResult.Success) { 'pagination limit reached' } else { [string]$assignmentResult.Error.Exception.Message }
            $accessAssignmentErrors.Add([pscustomobject]@{ RelationshipId=$relationshipId; Relationship=(Get-EAGovProperty $relationship 'displayName'); Reason=$reason }) | Out-Null
            continue
        }
        $activeAssignments = @($assignmentResult.Rows | Where-Object { [string](Get-EAGovProperty $_ 'status') -ieq 'active' })
        if ($activeAssignments.Count -eq 0) {
            $activeRelationshipsWithoutAssignments.Add([pscustomobject]@{
                RelationshipId=$relationshipId; Relationship=(Get-EAGovProperty $relationship 'displayName')
                CustomerTenantId=$customerTenantId; CustomerDisplayName=$customerDisplayName
                EndDateTime=Get-EAGovProperty $relationship 'endDateTime'; ApprovedRoleCount=@(Get-EAGovProperty (Get-EAGovProperty $relationship 'accessDetails') 'unifiedRoles').Count
            }) | Out-Null
            continue
        }
        foreach ($assignment in $activeAssignments) {
            $container = Get-EAGovProperty $assignment 'accessContainer'
            $assignmentRoles = @(Get-EAGovProperty (Get-EAGovProperty $assignment 'accessDetails') 'unifiedRoles')
            if ($assignmentRoles.Count -eq 0) {
                $accessAssignmentErrors.Add([pscustomobject]@{
                    RelationshipId=$relationshipId; Relationship=(Get-EAGovProperty $relationship 'displayName')
                    AssignmentId=Get-EAGovProperty $assignment 'id'; Reason='active access assignment has no readable unifiedRoles'
                }) | Out-Null
                continue
            }
            foreach ($roleRef in $assignmentRoles) {
                $roleId = [string](Get-EAGovProperty $roleRef 'roleDefinitionId')
                $roleClass = Get-EAGovDirectoryRoleRisk -RoleDefinitionId $roleId
                $accessAssignmentRows.Add([pscustomobject]@{
                    RelationshipId=$relationshipId
                    DisplayName=Get-EAGovProperty $relationship 'displayName'
                    CustomerTenantId=$customerTenantId
                    CustomerDisplayName=$customerDisplayName
                    Status=Get-EAGovProperty $relationship 'status'
                    EndDateTime=Get-EAGovProperty $relationship 'endDateTime'
                    Duration=Get-EAGovProperty $relationship 'duration'
                    DurationDays=ConvertFrom-EAGovDurationDays (Get-EAGovProperty $relationship 'duration')
                    AutoExtendDuration=Get-EAGovProperty $relationship 'autoExtendDuration'
                    AssignmentId=Get-EAGovProperty $assignment 'id'
                    AssignmentStatus=Get-EAGovProperty $assignment 'status'
                    AccessContainerId=Get-EAGovProperty $container 'accessContainerId'
                    AccessContainerType=Get-EAGovProperty $container 'accessContainerType'
                    RoleDefinitionId=$roleId
                    RoleDisplayName=$roleClass.Name
                    RoleRisk=$roleClass.Risk
                }) | Out-Null
            }
        }
    }
    $assignmentSrc = Write-Evidence -BaseName 'external_delegated_admin_access_assignments' -Rows $accessAssignmentRows.ToArray() `
        -Title 'Effective Active GDAP Access Assignments'

    if (-not $relationshipResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP delegated admin relationships' `
            -Reason ([string]$relationshipResult.Error.Exception.Message) -RequiredScope 'DelegatedAdminRelationship.Read.All' `
            -DocumentationUrl $doc -SourceFile $relationshipSrc -Subject 'the list of customer tenants this tenant manages as a partner (GDAP)' `
            -Impact 'This list only has data when this tenant is a Microsoft partner; admin roles this tenant holds in customer tenants were not checked. It never shows partners that hold admin roles in this tenant (see the note on partner access).' `
            -RecommendedAction 'If this tenant is a Microsoft partner (for example a Cloud Solution Provider), give the audit account DelegatedAdminRelationship.Read.All and run the audit again; if it is not a partner, this list does not apply and nothing needs to be done'
    } elseif ($relationshipResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP delegated admin relationship pagination' `
            -Reason "pagination exceeded $($relationshipResult.Pages) pages." -RequiredScope 'DelegatedAdminRelationship.Read.All' `
            -DocumentationUrl $doc -SourceFile $relationshipSrc -Partial -Subject 'the list of customer tenants this tenant manages as a partner (GDAP)' `
            -Impact 'Customer tenants beyond the part that was read are missing from this report.'
    }
    if (-not $roleDefinitionsKnown) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP role definitions and effective role risk' `
            -Reason $roleDefinitionError -RequiredScope 'RoleManagement.Read.Directory' -DocumentationUrl $doc -SourceFile $relationshipSrc `
            -Subject 'the admin role definitions used to rate roles in customer tenants' `
            -Impact 'Roles in customer tenants other than the well-known top admin roles are shown as of unknown risk, so some privileged roles this tenant holds in customer tenants may be missing from this report.'
    }
    if ($accessAssignmentErrors.Count -gt 0) {
        $assignmentErrorSrc = Write-Evidence -BaseName 'external_delegated_admin_access_assignment_errors' -Rows $accessAssignmentErrors.ToArray() -Title 'GDAP Access Assignment Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Effective GDAP access assignments' `
            -Reason ((Format-EACount $accessAssignmentErrors.Count 'active relationship or assignment read was' 'active relationship or assignment reads were') + ' incomplete.') `
            -RequiredScope 'DelegatedAdminRelationship.Read.All' -DocumentationUrl $doc -SourceFile $assignmentErrorSrc `
            -Subject 'the list of staff groups that hold the approved customer roles' `
            -Impact "Admin roles this tenant's staff can use in customer tenants today may be missing from this report."
    }
    if ($activeRelationshipsWithoutAssignments.Count -gt 0) {
        $noAssignmentSrc = Write-Evidence -BaseName 'external_delegated_admin_relationships_without_assignments' -Rows $activeRelationshipsWithoutAssignments.ToArray() -Title 'Active GDAP Relationships Without Active Access Assignments'
        $unusedCustomers = @($activeRelationshipsWithoutAssignments | ForEach-Object { Get-EAGovGdapCustomerLabel $_ } | Select-Object -Unique)
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'External Access' `
            -Title ((Format-EACount $activeRelationshipsWithoutAssignments.Count 'admin relationship with a customer tenant is' 'admin relationships with customer tenants are') + ' approved but not in use') `
            -Evidence ("This tenant, as a Microsoft partner, has active Granular Delegated Admin Privileges (GDAP) relationships with approved roles, but no staff security group is assigned to use them (accessAssignments returned no active binding). Customers: {0}." -f ($unusedCustomers -join ', ')) `
            -WhyItMatters "Nobody in this tenant uses these approved admin roles in the customers' tenants today, but staff can be given them at any time without asking the customer again." `
            -RecommendedAction ("End the relationships that are no longer needed in {0}" -f $partnerCenterPath) `
            -DocumentationUrl $gdapGuideDoc -SourceFile $noAssignmentSrc -ResultRows $activeRelationshipsWithoutAssignments.ToArray() -RuleId 'gdap-active-without-access-assignment'
    }

    $activeRows = @($accessAssignmentRows.ToArray())
    foreach ($group in @($activeRows | Group-Object RelationshipId)) {
        $relationship = @($group.Group)
        $customerLabel = Get-EAGovGdapCustomerLabel $relationship[0]
        $critical = @($relationship | Where-Object { $_.RoleRisk -eq 'Critical' })
        $high = @($relationship | Where-Object { $_.RoleRisk -eq 'High' })
        $unknown = @($relationship | Where-Object { $_.RoleRisk -eq 'Unknown' -and $_.RoleDefinitionId })
        $severity = if ($critical.Count -gt 0) { 'Critical' } elseif ($high.Count -gt 0) { 'High' } else { $null }
        if ($severity) {
            $roleNames = @($relationship | Where-Object { $_.RoleRisk -in @('Critical','High') } | ForEach-Object {
                $_.RoleDisplayName ?? $_.RoleDefinitionId
            } | Select-Object -Unique)
            Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'External Access' `
                -Title ("This tenant (as a partner) holds admin roles in customer tenant: {0}" -f $customerLabel) `
                -Evidence ("Customer tenant: {0} (tenant id {1}); relationship: {2}. Privileged roles in active GDAP access assignments: {3}; end={4}; autoExtend={5}." -f $customerLabel,$relationship[0].CustomerTenantId,$relationship[0].DisplayName,($roleNames -join ', '),$relationship[0].EndDateTime,$relationship[0].AutoExtendDuration) `
                -WhyItMatters "Members of this tenant's partner staff groups can use these admin roles in the customer's tenant (Granular Delegated Admin Privileges, GDAP). Anyone who takes over one of those groups or staff accounts gets the same admin access to the customer, and top roles such as Global Administrator allow a full takeover of the customer tenant." `
                -RecommendedAction ("In {0}, keep only the roles the customer's contract needs and end relationships you no longer use; keep the staff groups that hold these roles small and protected with phishing-resistant MFA" -f $partnerCenterPath) `
                -DocumentationUrl $gdapGuideDoc -SourceFile $assignmentSrc -ResultRows $relationship `
                -AffectedPrincipal $customerLabel -RuleId 'gdap-privileged-role' `
                -ObjectType 'delegatedAdminRelationship' -ObjectId ([string]$relationship[0].RelationshipId) `
                -AffectedObjectIds @(([string]$relationship[0].RelationshipId)) -AffectedObjectType 'delegatedAdminRelationship' -AffectedCount 1
        }
        if ($unknown.Count -gt 0) {
            # One rule for every relationship (the relationship is the object, not part of
            # the rule id), so renaming a relationship never changes the finding id and all
            # relationships with unresolved roles group under one "could not be read" card.
            # One-time id change, part of the finding-id migration: the rule used to be
            # coverage-gdap-role-risk-for-relationship-<relationship name> with no object.
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP role risk for relationship' `
                -Reason ("{0} in relationship {1} could not be resolved." -f (Format-EACount $unknown.Count 'role definition' 'role definitions'),$relationship[0].DisplayName) `
                -RequiredScope 'RoleManagement.Read.Directory' -DocumentationUrl $doc -SourceFile $assignmentSrc `
                -Subject ("the roles this tenant holds in customer tenant {0}" -f $customerLabel) `
                -Impact 'Whether this tenant holds admin roles in this customer tenant was not fully checked.' `
                -ObjectType 'delegatedAdminRelationship' -ObjectId ([string]$relationship[0].RelationshipId) -AffectedPrincipal $customerLabel
        }
    }

    $now = [datetimeoffset]::UtcNow
    $expiredActive = @($activeRows | Where-Object {
        $end = ConvertTo-EAGovDateTime $_.EndDateTime
        $end -and $end -lt $now
    })
    if ($expiredActive.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'External Access' `
            -Title (Format-EACount $expiredActive.Count 'admin role grant in a customer tenant is still active after its end date' 'admin role grants in customer tenants are still active after their end date') `
            -Evidence ("This tenant, as a Microsoft partner, has GDAP relationships whose status is active while EndDateTime is earlier than the audit time. Each row is one role in a relationship. Customers: {0}." -f (@($expiredActive | ForEach-Object { Get-EAGovGdapCustomerLabel $_ } | Select-Object -Unique) -join ', ')) `
            -WhyItMatters "This tenant may still have admin access in the customers' tenants that should already have ended, and nobody is tracking it." `
            -RecommendedAction ("Check these relationships in {0} and end any access that should have expired" -f $partnerCenterPath) `
            -DocumentationUrl $gdapGuideDoc -SourceFile $relationshipSrc -ResultRows $expiredActive -RuleId 'gdap-active-past-end' `
            -AffectedObjectIds @($expiredActive | ForEach-Object { $_.RelationshipId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'delegatedAdminRelationship' -AffectedCount @($expiredActive | ForEach-Object { $_.RelationshipId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'delegated administration relationships with the stated condition'
    }

    # Graph caps duration at P2Y (730 days), so "longer than two years" can never
    # occur; flag relationships set to the two-year maximum or with no readable end.
    $longLived = @($activeRows | Where-Object { $null -eq $_.EndDateTime -or ($null -ne $_.DurationDays -and $_.DurationDays -ge 730) })
    if ($longLived.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'External Access' `
            -Title (Format-EACount $longLived.Count 'admin role grant in a customer tenant lasts two years or has no readable end date' 'admin role grants in customer tenants last two years or have no readable end date') `
            -Evidence ("{0} no readable EndDateTime. Each row is one role in a relationship. Customers: {1}." -f (Format-EACount @($longLived | Select-Object -ExpandProperty RelationshipId -Unique).Count 'GDAP relationship this tenant holds as a Microsoft partner uses the maximum two-year duration or has' 'GDAP relationships this tenant holds as a Microsoft partner use the maximum two-year duration or have'),(@($longLived | ForEach-Object { Get-EAGovGdapCustomerLabel $_ } | Select-Object -Unique) -join ', ')) `
            -WhyItMatters 'The longer admin access to a customer lasts, the more likely it is to outlive the contract or the staff who needed it.' `
            -RecommendedAction ("Use shorter relationships with each customer in {0}, and re-approve the roles regularly against the current contract" -f $partnerCenterPath) `
            -DocumentationUrl $gdapGuideDoc -SourceFile $relationshipSrc -ResultRows $longLived -RuleId 'gdap-long-lived' `
            -AffectedObjectIds @($longLived | ForEach-Object { $_.RelationshipId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'delegatedAdminRelationship' -AffectedCount @($longLived | ForEach-Object { $_.RelationshipId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'delegated administration relationships with the stated condition'
    }

    # autoExtendDuration (P0D/PT0S = off, P180D = on) is what makes a partner
    # relationship effectively permanent: it renews itself every 180 days unless
    # someone terminates it. Report once per relationship.
    foreach ($group in @($activeRows | Where-Object {
        $days = ConvertFrom-EAGovDurationDays $_.AutoExtendDuration
        $null -ne $days -and $days -gt 0
    } | Group-Object RelationshipId)) {
        $relationship = @($group.Group)
        $customerLabel = Get-EAGovGdapCustomerLabel $relationship[0]
        $privilegedRoles = @($relationship | Where-Object { $_.RoleRisk -in @('Critical','High') })
        # A role whose definition could not be resolved may be privileged: keep the High
        # severity and say so, rather than reporting "none" for data that was never read.
        $unknownRoles = @($relationship | Where-Object { $_.RoleRisk -eq 'Unknown' -and $_.RoleDefinitionId })
        $severity = if ($privilegedRoles.Count -gt 0 -or $unknownRoles.Count -gt 0) { 'High' } else { 'Medium' }
        $roleNames = @($privilegedRoles | ForEach-Object { $_.RoleDisplayName ?? $_.RoleDefinitionId } | Select-Object -Unique)
        $roleText = @(
            if ($roleNames.Count -gt 0) { $roleNames -join ', ' }
            if ($unknownRoles.Count -gt 0) {
                "{0} of unknown risk (role definitions could not be resolved)" -f (Format-EACount @($unknownRoles.RoleDefinitionId | Select-Object -Unique).Count 'role' 'roles')
            }
        )
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'External Access' `
            -Title ("Admin access to a customer tenant renews itself automatically: {0}" -f $customerLabel) `
            -Evidence ("Customer tenant: {0}; relationship: {1}. GDAP autoExtendDuration={2}; current end={3}; privileged roles: {4}." -f $customerLabel,$relationship[0].DisplayName,$relationship[0].AutoExtendDuration,$relationship[0].EndDateTime,$(if ($roleText.Count -gt 0) { $roleText -join '; plus ' } else { 'none' })) `
            -WhyItMatters "This tenant's admin access to the customer has no real end date: the relationship extends itself by six months every time it reaches its end, so nobody has to re-approve it." `
            -RecommendedAction ("Turn off auto extend for this relationship in {0}, or replace it with a relationship that has a fixed end date; re-approve customer access on a regular schedule" -f $partnerCenterPath) `
            -DocumentationUrl $gdapGuideDoc -SourceFile $assignmentSrc -ResultRows $relationship `
            -AffectedPrincipal $customerLabel -RuleId 'gdap-auto-extend' `
            -ObjectType 'delegatedAdminRelationship' -ObjectId ([string]$relationship[0].RelationshipId) `
            -AffectedObjectIds @(([string]$relationship[0].RelationshipId)) -AffectedObjectType 'delegatedAdminRelationship' -AffectedCount 1
    }

    # Partners that hold admin roles in THIS tenant cannot be listed through Microsoft
    # Graph from the customer side, so this note is always added. It is an Information
    # note, not a coverage gap: no permission can fix it, and a permanent gap would mark
    # every run as incomplete. Its text states plainly that this part was not checked.
    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'External Access' `
        -Title 'Partners with admin access to this tenant must be checked by hand' `
        -Evidence 'Microsoft Graph has no read-only API that lists, from the customer side, the partners (GDAP or older DAP) that hold admin roles in this tenant. The GDAP list this check reads only shows the relationships this tenant holds as a partner with its own customers. Partner access to this tenant was therefore not checked; this is not a clean result.' `
        -WhyItMatters 'A partner with admin roles in your tenant can make changes from outside your organization, and a breach at the partner can reach your tenant. The audit cannot see these partners.' `
        -RecommendedAction ("Review every partner in {0}: remove admin roles a partner does not need (Remove roles), and ask partners you no longer work with to end the relationship" -f $partnerPath) `
        -DocumentationUrl $customerPartnerDoc -SourceFile $relationshipSrc -RuleId 'gdap-inbound-not-readable'

    # ------------------------- Accepted guest lifecycle -------------------------
    $inactiveThreshold = 90
    $thresholdVariable = Get-Variable -Name InactiveDays -Scope Script -ErrorAction SilentlyContinue
    if ($thresholdVariable -and [int]$thresholdVariable.Value -gt 0) { $inactiveThreshold = [int]$thresholdVariable.Value }
    # Keep the base guest/sponsor read separate from signInActivity. A missing P1
    # license or AuditLog.Read.All must not prevent sponsor governance from running.
    #
    # Sponsors come with the guest list through $expand: one request per page of guests
    # instead of one request per guest. Directory $expand returns at most 20 related
    # objects and no nextLink, so a guest whose expanded sponsor list is missing or exactly
    # at that cap is read again on its own. If the service refuses the expanded query, the
    # plain guest list is read and every accepted guest's sponsors are read one by one:
    # slower, but no guest is ever skipped, and every guest whose sponsors could not be
    # read is listed in the sponsor coverage gap.
    #
    # Page safety limits are sized so every guest read covers about 500,000 guests: the
    # plain list is served at up to 999 rows per page (500 pages), a directory list with
    # $expand may be served at only 100 rows per page (5000 pages), and a list that selects
    # signInActivity at up to 500 rows per page (1000 pages). A smaller limit on the
    # expanded or activity read would mark large guest lists as partial and skip rules the
    # plain read could still run.
    $sponsorExpandCap = 20
    $guestSelect = 'id,userPrincipalName,displayName,accountEnabled,userType,externalUserState,externalUserStateChangeDateTime,createdDateTime'
    $guestBaseUri = "https://graph.microsoft.com/v1.0/users?`$filter=userType%20eq%20'Guest'&`$select=$guestSelect&`$top=999"
    $guestActivityUri = "https://graph.microsoft.com/v1.0/users?`$filter=userType%20eq%20'Guest'&`$select=id,signInActivity&`$top=999"
    $sponsorsExpanded = $false
    $sponsorExpandErrors = New-Object System.Collections.Generic.List[string]
    $guestResult = $null
    foreach ($expandShape in @('sponsors($select=id,displayName,userPrincipalName)', 'sponsors')) {
        $attempt = Invoke-EAGovGraphCollection -Uri ($guestBaseUri + '&$expand=' + $expandShape) -MaxPages 5000
        if ($attempt.Success) { $guestResult = $attempt; $sponsorsExpanded = $true; break }
        $sponsorExpandErrors.Add(('$expand={0}: {1}' -f $expandShape, [string]$attempt.Error.Exception.Message)) | Out-Null
        # Only a rejected query (HTTP 400) is worth retrying in another shape; access
        # denied, throttling or a service error would fail the same way again.
        $queryRejected = $attempt.StatusCode -eq 400 -or ($null -eq $attempt.StatusCode -and (Test-EAPageSizeRejection $attempt.Error))
        if (-not $queryRejected) { break }
    }
    if (-not $sponsorsExpanded) { $guestResult = Invoke-EAGovGraphCollection -Uri $guestBaseUri }
    $guestActivityResult = Invoke-EAGovGraphCollection -Uri $guestActivityUri -MaxPages 1000
    $activityByGuestId = @{}
    $guestActivityComplete = $guestActivityResult.Success -and -not $guestActivityResult.Truncated
    if ($guestActivityComplete) {
        foreach ($activityGuest in @($guestActivityResult.Rows)) {
            $activityGuestId = [string](Get-EAGovProperty $activityGuest 'id')
            if ($activityGuestId) {
                $activityByGuestId[$activityGuestId] = [pscustomobject]@{
                    Present = Test-EAGovPropertyPresent $activityGuest 'signInActivity'
                    Value   = Get-EAGovProperty $activityGuest 'signInActivity'
                }
            }
        }
    }
    $guestRows = New-Object System.Collections.Generic.List[object]
    $sponsorErrors = New-Object System.Collections.Generic.List[object]
    $acceptedGuests = @(if ($guestResult.Success) {
        @($guestResult.Rows | Where-Object { [string](Get-EAGovProperty $_ 'externalUserState') -ieq 'Accepted' })
    } else { @() })

    # Decide up front which guests need their own sponsor read, so the console can show
    # how many there are and report progress on long runs.
    $needsOwnSponsorRead = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($guest in $acceptedGuests) {
        $guestId = [string](Get-EAGovProperty $guest 'id')
        if (-not $guestId) { continue }
        $expandedPresent = $sponsorsExpanded -and (Test-EAGovPropertyPresent $guest 'sponsors')
        $expandedCount = if ($expandedPresent) { @(Get-EAGovProperty $guest 'sponsors' | Where-Object { $null -ne $_ }).Count } else { 0 }
        if (-not $expandedPresent -or $expandedCount -ge $sponsorExpandCap) { [void]$needsOwnSponsorRead.Add($guestId) }
    }
    if ($needsOwnSponsorRead.Count -gt 0) {
        $whyOwnRead = if (-not $sponsorsExpanded) {
            'the guest list could not include sponsors'
        } else {
            "their sponsors were missing from the guest list or may have been cut off at $sponsorExpandCap"
        }
        Write-Info ("  Reading sponsors one guest at a time for {0} of {1}, because {2}." -f $needsOwnSponsorRead.Count,(Format-EACount $acceptedGuests.Count 'accepted guest' 'accepted guests'),$whyOwnRead)
    }

    $ownReads = 0
    $ownReadSucceeded = 0
    $ownReadDenied = 0
    $ownReadStopReason = $null
    $expandedSponsorGuests = 0
    foreach ($guest in $acceptedGuests) {
        $guestId = [string](Get-EAGovProperty $guest 'id')
        $sponsorsKnown = $false
        $sponsors = @()
        $sponsorSource = $null
        if (-not $guestId) {
            $sponsorErrors.Add([pscustomobject]@{ GuestId=$null; UserPrincipalName=(Get-EAGovProperty $guest 'userPrincipalName'); Reason='the guest record has no id, so its sponsors could not be read' }) | Out-Null
        } elseif (-not $needsOwnSponsorRead.Contains($guestId)) {
            $sponsorsKnown = $true
            $sponsors = @(Get-EAGovProperty $guest 'sponsors' | Where-Object { $null -ne $_ })
            $sponsorSource = 'GuestList'
            $expandedSponsorGuests++
        } elseif ($ownReadStopReason) {
            $sponsorErrors.Add([pscustomobject]@{ GuestId=$guestId; UserPrincipalName=(Get-EAGovProperty $guest 'userPrincipalName'); Reason=$ownReadStopReason }) | Out-Null
        } else {
            $ownReads++
            $sponsorResult = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/users/{0}/sponsors?`$select=id,displayName,userPrincipalName" -f [uri]::EscapeDataString($guestId))
            if ($sponsorResult.Success -and -not $sponsorResult.Truncated) {
                $sponsorsKnown = $true
                $sponsors = @($sponsorResult.Rows)
                $sponsorSource = 'PerGuest'
                $ownReadSucceeded++
            } else {
                $reason = if ($sponsorResult.Success) { 'pagination limit reached' } else { [string]$sponsorResult.Error.Exception.Message }
                $sponsorErrors.Add([pscustomobject]@{ GuestId=$guestId; UserPrincipalName=(Get-EAGovProperty $guest 'userPrincipalName'); Reason=$reason }) | Out-Null
                if (-not $sponsorResult.Success -and ($sponsorResult.StatusCode -in @(401, 403) -or (Test-EAAccessDenied $sponsorResult.Error))) { $ownReadDenied++ }
                # When the first reads are all refused, the rest would be refused too:
                # stop sending thousands of doomed requests, but still list every guest.
                if ($ownReadSucceeded -eq 0 -and $ownReadDenied -ge 5) {
                    $ownReadStopReason = "not attempted: the first $ownReadDenied per-guest sponsor reads were refused (access denied)"
                    Write-Warn2 ("  Guest sponsor reads are being refused (access denied); the remaining {0} reported as not checked." -f (Format-EACount ($needsOwnSponsorRead.Count - $ownReads) 'guest is' 'guests are'))
                }
            }
            if ($ownReads % 100 -eq 0) {
                Write-Info ("  Guest sponsors read one by one: {0} of {1}." -f $ownReads,$needsOwnSponsorRead.Count)
            }
        }

        $activityEnvelope = if ($activityByGuestId.ContainsKey($guestId)) { $activityByGuestId[$guestId] } else { $null }
        $activityKnown = $guestActivityComplete -and $activityEnvelope -and $activityEnvelope.Present
        $signIn = if ($activityKnown) { $activityEnvelope.Value } else { $null }
        $lastSuccessful = ConvertTo-EAGovDateTime (Get-EAGovProperty $signIn 'lastSuccessfulSignInDateTime')
        $lastSignIn = ConvertTo-EAGovDateTime (Get-EAGovProperty $signIn 'lastSignInDateTime')
        # A failed sign-in attempt can update lastSignInDateTime. It must not
        # make a dormant guest look active (for example during password spray).
        $lastActivity = $lastSuccessful
        $accepted = ConvertTo-EAGovDateTime (Get-EAGovProperty $guest 'externalUserStateChangeDateTime')
        if (-not $accepted) { $accepted = ConvertTo-EAGovDateTime (Get-EAGovProperty $guest 'createdDateTime') }

        $guestRows.Add([pscustomobject]@{
            Id                         = $guestId
            UserPrincipalName          = Get-EAGovProperty $guest 'userPrincipalName'
            DisplayName                = Get-EAGovProperty $guest 'displayName'
            AccountEnabled             = Get-EAGovProperty $guest 'accountEnabled'
            ExternalUserState          = Get-EAGovProperty $guest 'externalUserState'
            AcceptedDateTime           = $accepted
            LastSuccessfulSignInDateTime = $lastSuccessful
            LastSignInDateTime         = $lastSignIn
            LastActivityDateTime       = $lastActivity
            ActivityKnown              = $activityKnown
            SponsorsKnown              = $sponsorsKnown
            SponsorCount               = if ($sponsorsKnown) { $sponsors.Count } else { $null }
            SponsorSource              = $sponsorSource
            Sponsors                   = (($sponsors | ForEach-Object {
                (Get-EAGovProperty $_ 'userPrincipalName') ?? (Get-EAGovProperty $_ 'displayName') ?? (Get-EAGovProperty $_ 'id')
            }) -join '; ')
        }) | Out-Null
    }
    if ($ownReads -ge 100 -and $ownReads % 100 -ne 0) {
        Write-Info ("  Guest sponsors read one by one: {0} of {1}." -f $ownReads,$needsOwnSponsorRead.Count)
    }

    $sponsorReadNote = if (-not $guestResult.Success) {
        'Sponsors: not read, because the guest list itself could not be read.'
    } elseif ($sponsorsExpanded) {
        "Sponsors: read with the guest list for {0} (SponsorSource=GuestList) and one guest at a time for {1} (SponsorSource=PerGuest; expanded list missing or at the {2}-item limit)." -f (Format-EACount $expandedSponsorGuests 'guest' 'guests'),(Format-EACount $ownReadSucceeded 'guest' 'guests'),$sponsorExpandCap
    } else {
        "Sponsors: the guest list could not include sponsors ({0}), so they were read one guest at a time (SponsorSource=PerGuest) for {1}." -f ($sponsorExpandErrors -join ' | '),(Format-EACount $ownReadSucceeded 'guest' 'guests')
    }
    $guestSrc = Write-Evidence -BaseName 'accepted_guest_lifecycle' -Rows $guestRows.ToArray() `
        -Title 'Accepted Guest Activity and Sponsor Governance' `
        -Notes @(
            ("Inactive threshold: {0} days. Only LastSuccessfulSignInDateTime establishes activity; failed attempts in LastSignInDateTime do not reset the inactivity clock." -f $inactiveThreshold),
            $sponsorReadNote,
            'SponsorsKnown=False means the sponsors of that guest could not be read (see guest_sponsor_collection_errors); it never means the guest has no sponsor.'
        )

    if (-not $guestResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest inventory and sponsor population' `
            -Reason ([string]$guestResult.Error.Exception.Message) -RequiredScope 'User.Read.All' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc -Subject 'the list of guest users' `
            -Impact 'Guests without a sponsor and guests who no longer sign in were not checked.'
    } elseif ($guestResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest pagination' `
            -Reason "pagination exceeded $($guestResult.Pages) pages." -RequiredScope 'User.Read.All' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc -Partial -Subject 'the list of guest users' `
            -Impact 'Guests beyond the part that was read were not checked for a sponsor or for recent sign-ins.'
    }
    if (-not $guestActivityResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest sign-in activity' `
            -Reason ([string]$guestActivityResult.Error.Exception.Message) -RequiredScope 'AuditLog.Read.All plus Entra ID P1 or P2' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc -Subject 'the sign-in activity of guest users' `
            -Impact 'Guests who no longer sign in were not identified.'
    } elseif ($guestActivityResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest sign-in activity pagination' `
            -Reason "pagination exceeded $($guestActivityResult.Pages) pages." -RequiredScope 'AuditLog.Read.All plus Entra ID P1 or P2' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc -Partial -Subject 'the sign-in activity of guest users' `
            -Impact 'Guests who no longer sign in were not identified.'
    }
    if ($sponsorErrors.Count -gt 0) {
        $sponsorErrSrc = Write-Evidence -BaseName 'guest_sponsor_collection_errors' -Rows $sponsorErrors.ToArray() -Title 'Guest Sponsor Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest sponsors' `
            -Reason ("sponsor enumeration failed or truncated for {0}." -f (Format-EACount $sponsorErrors.Count 'accepted guest' 'accepted guests')) `
            -RequiredScope 'User.Read.All (a delegated sign-in also needs a role such as Directory Readers or Guest Inviter)' `
            -DocumentationUrl $sponsorDoc -SourceFile $sponsorErrSrc -Subject 'the sponsors of some guest users' `
            -Impact 'Guests without a sponsor may be missing from this report.' `
            -RecommendedAction 'Give the audit account User.Read.All and, when it signs in as a user, a role that can read sponsors (Directory Readers, Guest Inviter, Directory Writers or User Administrator), then run the audit again; if the evidence shows a different error, such as throttling, simply run it again'
    }

    $missingSponsors = @($guestRows | Where-Object { $_.SponsorsKnown -and $_.SponsorCount -eq 0 })
    if ($missingSponsors.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'External Access' `
            -Title (Format-EACount $missingSponsors.Count 'guest has no sponsor' 'guests have no sponsor') `
            -Evidence 'Accepted guests: sponsor enumeration succeeded and returned zero sponsors for these guests.' `
            -WhyItMatters 'A sponsor is the person or group inside your organization who answers for a guest. Without one, nobody checks whether the guest still needs access when the project or contract ends.' `
            -RecommendedAction 'Add a sponsor to each listed guest (Entra admin center > Entra ID > Users > [guest] > Properties > Job information > Sponsors), and make sponsors the reviewers in guest access reviews' `
            -DocumentationUrl $sponsorGuideDoc -SourceFile $guestSrc -ResultRows $missingSponsors -RuleId 'accepted-guests-no-sponsor' `
            -AffectedObjectIds @($missingSponsors | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $missingSponsors.Count -PopulationLabel 'accepted guests with readable sponsors' -AssessedCount (@($guestRows | Where-Object SponsorsKnown).Count) -UnknownCount (@($guestRows | Where-Object { -not $_.SponsorsKnown }).Count)
    }

    if ($guestResult.Success -and -not $guestResult.Truncated -and $guestActivityComplete) {
        $cutoff = [datetimeoffset]::UtcNow.AddDays(-$inactiveThreshold)
        $inactiveGuests = @($guestRows | Where-Object {
            if ($_.AccountEnabled -ne $true -or -not $_.ActivityKnown) { return $false }
            $last = ConvertTo-EAGovDateTime $_.LastActivityDateTime
            if ($last) { return $last -lt $cutoff }
            $accepted = ConvertTo-EAGovDateTime $_.AcceptedDateTime
            return ($accepted -and $accepted -lt $cutoff)
        })
        if ($inactiveGuests.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'External Access' `
                -Title ("{0} not signed in for more than {1} days" -f (Format-EACount $inactiveGuests.Count 'guest has' 'guests have'),$inactiveThreshold) `
                -Evidence 'Guests are accepted and enabled, and their last successful sign-in is older than the threshold; never-successfully-signed-in guests are flagged only after the accepted/created date exceeds the threshold. Failed attempts do not count as activity.' `
                -WhyItMatters "Guest accounts nobody uses still have access to your groups, apps and files. If the guest's own account is taken over, an attacker can use that access without anyone noticing." `
                -RecommendedAction 'Ask each sponsor whether the guest still needs access, then block sign-in for or delete guests that do not; an access review of inactive guests can do this regularly' `
                -DocumentationUrl $guestReviewDoc -SourceFile $guestSrc -ResultRows $inactiveGuests -RuleId 'accepted-guests-inactive' `
                -AffectedObjectIds @($inactiveGuests | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $inactiveGuests.Count -PopulationLabel 'accepted enabled guests with activity assessed'
        }
    }

    # Counts come from the read results: a list that could not be read says so instead of
    # showing 0, and a partial list shows "N+".
    $customerCountText = if (-not $relationshipResult.Success) { 'customer tenants managed as partner not read' }
        elseif ($relationshipResult.Truncated) { '{0}+ customer tenants managed as partner' -f $relationships.Count }
        else { '{0} managed as partner' -f (Format-EACount $relationships.Count 'customer tenant' 'customer tenants') }
    $guestCountText = if (-not $guestResult.Success) { 'guests not read' }
        elseif ($guestResult.Truncated) { '{0}+ accepted guests' -f $guestRows.Count }
        else { Format-EACount $guestRows.Count 'accepted guest' 'accepted guests' }
    $relationshipEvidence = if ($relationshipResult.Success) { [string]$relationships.Count + $(if ($relationshipResult.Truncated) { ' (partial list)' } else { '' }) } else { 'not read' }
    $guestEvidence = if ($guestResult.Success) { [string]$guestRows.Count + $(if ($guestResult.Truncated) { ' (partial list)' } else { '' }) } else { 'not read' }
    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'External Access' `
        -Title ("External access recorded ({0}, {1})" -f $guestCountText,$customerCountText) `
        -Evidence ("Accepted guests={0}; sponsor read errors={1}; customer tenants this tenant manages as a Microsoft partner through GDAP={2}; active GDAP role rows={3}. Partners that hold admin roles in this tenant are not in these numbers: Microsoft Graph cannot list them (see 'Partners with admin access to this tenant must be checked by hand')." -f `
            $guestEvidence,$sponsorErrors.Count,$relationshipEvidence,$activeRows.Count) `
        -WhyItMatters 'Guest accounts and partner admin relationships are the two main ways outsiders get into a tenant. Each needs an owner, an end date and a regular review.' `
        -RecommendedAction ("Compare guest access with current sponsors and contracts, check partner access to this tenant in {0}, and review both on a regular schedule" -f $partnerPath) `
        -DocumentationUrl $gdapGuideDoc -SourceFile $relationshipSrc -ResultRows $relationshipRows.ToArray() -RuleId 'external-delegation-inventory'
}
