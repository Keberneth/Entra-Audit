<#
Group Governance. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-GroupGovernance {
    [CmdletBinding()]
    param()

    $checkId = 'groupgovernance'
    $doc = 'https://learn.microsoft.com/entra/identity/users/groups-lifecycle'
    $reportDoc = 'https://learn.microsoft.com/graph/api/reportroot-getoffice365groupsactivitydetail?view=graph-rest-beta'
    $groupSettingsGuideDoc = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-settings-cmdlets'
    $namingDoc = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-naming-policy'
    $roleGroupDoc = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept'
    $dynamicDoc = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership'
    $groupsPath = 'Entra admin center > Entra ID > Groups'
    $groupUri = 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName,description,groupTypes,mailEnabled,securityEnabled,visibility,isAssignableToRole,membershipRule,membershipRuleProcessingState,createdDateTime,renewedDateTime,expirationDateTime,onPremisesSyncEnabled,resourceProvisioningOptions&$expand=owners($select=id,displayName,userPrincipalName)&$top=999'
    $result = Invoke-EAGovGraphCollection -Uri $groupUri
    if (-not $result.Success) { throw $result.Error }

    $activityById = @{}
    $activityCoverage = $false
    $activityResult = Invoke-EAGovGraphCollection -Uri "https://graph.microsoft.com/beta/reports/getOffice365GroupsActivityDetail(period='D180')?`$format=application/json&`$top=200"
    if ($activityResult.Success -and -not $activityResult.Truncated) {
        $activityCoverage = $true
        foreach ($activity in @($activityResult.Rows)) {
            $groupId = [string](Get-EAGovProperty $activity 'groupId')
            if ($groupId) { $activityById[$groupId] = $activity }
        }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    $ownerReadErrors = New-Object System.Collections.Generic.List[object]
    foreach ($group in @($result.Rows)) {
        $id = [string](Get-EAGovProperty $group 'id')
        $ownersKnown = Test-EAGovPropertyPresent $group 'owners'
        $owners = @(if ($ownersKnown) { @(Get-EAGovProperty $group 'owners') } else { @() })

        # An omitted expanded navigation is unknown, not ownerless. Retry through the
        # documented sponsors/owners-style navigation using another GET.
        if (-not $ownersKnown -and $id) {
            $ownerResult = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/owners?`$select=id,displayName,userPrincipalName" -f [uri]::EscapeDataString($id))
            if ($ownerResult.Success -and -not $ownerResult.Truncated) {
                $ownersKnown = $true
                $owners = @($ownerResult.Rows)
            } else {
                $reason = if ($ownerResult.Success) { 'pagination limit reached' } else { [string]$ownerResult.Error.Exception.Message }
                $ownerReadErrors.Add([pscustomobject]@{ GroupId=$id; DisplayName=(Get-EAGovProperty $group 'displayName'); Reason=$reason }) | Out-Null
            }
        }

        $types = @(Get-EAGovProperty $group 'groupTypes')
        $isM365 = $types -contains 'Unified'
        $isDynamic = $types -contains 'DynamicMembership'
        $activity = if ($activityById.ContainsKey($id)) { $activityById[$id] } else { $null }
        $activityKnownForGroup = $null -ne $activity
        $lastActivity = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'lastActivityDate' } else { $null }

        $rows.Add([pscustomobject]@{
            Id                    = $id
            DisplayName           = Get-EAGovProperty $group 'displayName'
            Description           = Get-EAGovProperty $group 'description'
            GroupKind             = if ($isM365) { 'Microsoft365' } elseif ((Get-EAGovProperty $group 'securityEnabled') -eq $true) { 'Security' } else { 'Other' }
            MailEnabled           = Get-EAGovProperty $group 'mailEnabled'
            SecurityEnabled       = Get-EAGovProperty $group 'securityEnabled'
            Visibility            = Get-EAGovProperty $group 'visibility'
            IsAssignableToRole    = Get-EAGovProperty $group 'isAssignableToRole'
            IsDynamic             = $isDynamic
            MembershipRule        = Get-EAGovProperty $group 'membershipRule'
            MembershipRuleState   = Get-EAGovProperty $group 'membershipRuleProcessingState'
            OnPremisesSyncEnabled = Get-EAGovProperty $group 'onPremisesSyncEnabled'
            CreatedDateTime       = Get-EAGovProperty $group 'createdDateTime'
            RenewedDateTime       = Get-EAGovProperty $group 'renewedDateTime'
            ExpirationDateTime    = Get-EAGovProperty $group 'expirationDateTime'
            OwnersKnown           = $ownersKnown
            OwnerCount            = if ($ownersKnown) { $owners.Count } else { $null }
            Owners                = (($owners | ForEach-Object {
                (Get-EAGovProperty $_ 'userPrincipalName') ?? (Get-EAGovProperty $_ 'displayName') ?? (Get-EAGovProperty $_ 'id')
            }) -join '; ')
            ActivityEvidenceKnown = $activityKnownForGroup
            LastActivityDate      = $lastActivity
            ExternalMemberCount   = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'externalMemberCount' } else { $null }
            ReportRefreshDate     = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'reportRefreshDate' } else { $null }
            # D180 activity counters. lastActivityDate only covers mail, SharePoint and
            # Yammer, so a Team used only for channel chat and meetings needs the Teams
            # counters to show as active.
            IsDeleted                   = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'isDeleted' } else { $null }
            TeamsChannelMessagesCount   = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'teamsChannelMessagesCount' } else { $null }
            TeamsMeetingsOrganizedCount = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'teamsMeetingsOrganizedCount' } else { $null }
            ExchangeReceivedEmailCount  = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'exchangeReceivedEmailCount' } else { $null }
            SharePointActiveFileCount   = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'sharePointActiveFileCount' } else { $null }
            YammerPostedMessageCount    = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'yammerPostedMessageCount' } else { $null }
            YammerReadMessageCount      = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'yammerReadMessageCount' } else { $null }
            YammerLikedMessageCount     = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'yammerLikedMessageCount' } else { $null }
        }) | Out-Null
    }

    # A successful report call with zero rows isn't useful coverage when the
    # directory contains Microsoft 365 groups. Treat it as unknown rather than
    # silently making every group ineligible for inactivity evaluation.
    $m365GroupCount = @($rows | Where-Object { $_.GroupKind -eq 'Microsoft365' }).Count
    $activityReturnedNoRows = $activityCoverage -and $m365GroupCount -gt 0 -and @($activityResult.Rows).Count -eq 0
    if ($activityReturnedNoRows) { $activityCoverage = $false }

    $src = Write-Evidence -BaseName 'group_governance' -Rows $rows.ToArray() -Title 'Group Ownership, Lifecycle, Visibility, and Activity Governance' `
        -Notes @('A group is considered inactive only when the Microsoft 365 D180 activity report contains a row for it, the group was created before the 180-day window, every Teams, mail, SharePoint and Yammer counter in that row is zero, and LastActivityDate is empty or older than the window. Absence from that report, or an unknown creation date, is unknown, not stale.')

    if ($result.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Group inventory pagination' `
            -Reason "pagination exceeded $($result.Pages) pages." -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $doc -SourceFile $src -Partial -Subject 'the list of groups' `
            -Impact 'Problems with groups beyond the part that was read are missing from this report.'
    }
    if ($ownerReadErrors.Count -gt 0) {
        $ownerErrSrc = Write-Evidence -BaseName 'group_owner_collection_errors' -Rows $ownerReadErrors.ToArray() -Title 'Group Owner Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Group owners' `
            -Reason ("owner data was incomplete for {0}." -f (Format-EACount $ownerReadErrors.Count 'group' 'groups')) -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $doc -SourceFile $ownerErrSrc -Subject 'the owners of some groups' `
            -Impact 'Groups without an owner may be missing from this report.'
    }
    if (-not $activityCoverage) {
        $reason = if ($activityReturnedNoRows) {
            "the API returned zero report rows while {0}" -f (Format-EACount $m365GroupCount 'Microsoft 365 group exists' 'Microsoft 365 groups exist')
        } elseif ($activityResult.Success) { 'pagination limit reached' } else { [string]$activityResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Microsoft 365 group activity (D180)' `
            -Reason $reason -RequiredScope 'Reports.Read.All' -DocumentationUrl $reportDoc -SourceFile $src `
            -Subject 'the Microsoft 365 group activity report' `
            -Impact 'Microsoft 365 groups that nobody uses any more were not identified.'
    }

    # Tenant-level group settings and the Microsoft 365 group expiration policy
    # are separate resources; an object inventory alone cannot assess them.
    $groupSettingsDoc = 'https://learn.microsoft.com/graph/group-directory-settings'
    $unifiedTemplateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'
    $settingsResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/groupSettings?$top=999'
    $settingsTemplateResult = Invoke-EAGovGraphObject -Uri ("https://graph.microsoft.com/v1.0/groupSettingTemplates/{0}" -f $unifiedTemplateId)
    $unifiedSetting = $null
    if ($settingsResult.Success -and -not $settingsResult.Truncated) {
        $candidate = @($settingsResult.Rows | Where-Object {
            [string](Get-EAGovProperty $_ 'templateId') -ieq $unifiedTemplateId -or
            [string](Get-EAGovProperty $_ 'displayName') -ieq 'Group.Unified'
        } | Select-Object -First 1)
        if ($candidate.Count -gt 0) { $unifiedSetting = $candidate[0] }
    }
    $unifiedMap = if ($settingsResult.Success -and -not $settingsResult.Truncated -and $settingsTemplateResult.Success) {
        Merge-EAGovSettingMap -Template $settingsTemplateResult.Value -Setting $unifiedSetting
    } elseif ($unifiedSetting) { ConvertTo-EAGovSettingMap $unifiedSetting } else { @{} }
    $groupSettingRows = @([pscustomobject]@{
        EffectiveValuesKnown       = ($unifiedMap.Count -gt 0)
        UsesExplicitTenantSetting  = ($null -ne $unifiedSetting)
        EnableGroupCreation        = ConvertTo-EAGovBoolean $unifiedMap['EnableGroupCreation']
        GroupCreationAllowedGroupId = $unifiedMap['GroupCreationAllowedGroupId']
        AllowGuestsToBeGroupOwner  = ConvertTo-EAGovBoolean $unifiedMap['AllowGuestsToBeGroupOwner']
        AllowGuestsToAccessGroups  = ConvertTo-EAGovBoolean $unifiedMap['AllowGuestsToAccessGroups']
        AllowToAddGuests           = ConvertTo-EAGovBoolean $unifiedMap['AllowToAddGuests']
        PrefixSuffixNamingRequirement = $unifiedMap['PrefixSuffixNamingRequirement']
        CustomBlockedWordsConfigured = (-not [string]::IsNullOrWhiteSpace([string]$unifiedMap['CustomBlockedWordsList']))
        UsageGuidelinesConfigured  = (-not [string]::IsNullOrWhiteSpace([string]$unifiedMap['UsageGuidelinesUrl']))
        GuestUsageGuidelinesConfigured = (-not [string]::IsNullOrWhiteSpace([string]$unifiedMap['GuestUsageGuidelinesUrl']))
    })
    $groupSettingsSrc = Write-Evidence -BaseName 'group_governance_tenant_settings' -Rows $groupSettingRows -Title 'Tenant Group Governance Settings'
    if (-not $settingsResult.Success -or $settingsResult.Truncated -or (-not $settingsTemplateResult.Success -and -not $unifiedSetting)) {
        $reason = if (-not $settingsResult.Success) { [string]$settingsResult.Error.Exception.Message } `
            elseif ($settingsResult.Truncated) { 'groupSettings pagination limit reached' } `
            else { [string]$settingsTemplateResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Tenant Group.Unified settings' `
            -Reason $reason -RequiredScope 'Directory.Read.All' -DocumentationUrl $groupSettingsDoc -SourceFile $groupSettingsSrc `
            -Subject 'the tenant-wide Microsoft 365 group settings' `
            -Impact 'Who may create groups, whether guests may own groups and the naming policy were not checked.'
    } elseif ($unifiedMap.Count -gt 0) {
        if ((ConvertTo-EAGovBoolean $unifiedMap['AllowGuestsToBeGroupOwner']) -eq $true) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Group Governance' `
                -Title 'Guests are allowed to own Microsoft 365 groups' `
                -Evidence 'The effective Group.Unified setting AllowGuestsToBeGroupOwner=true.' `
                -WhyItMatters "A guest who owns a group can add members and control the group's files, mailbox and Teams content, even after the business relationship with them ends." `
                -RecommendedAction 'Set AllowGuestsToBeGroupOwner to false in the Group.Unified directory setting (only available through Microsoft Graph PowerShell) unless a documented need requires it, then review groups that already have guest owners' `
                -DocumentationUrl $groupSettingsGuideDoc -SourceFile $groupSettingsSrc -RuleId 'group-settings-guest-owners-allowed'
        }
        if ((ConvertTo-EAGovBoolean $unifiedMap['EnableGroupCreation']) -eq $true) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
                -Title 'Every user can create Microsoft 365 groups' `
                -Evidence 'The effective Group.Unified setting EnableGroupCreation=true; no restriction group is applied by this setting.' `
                -WhyItMatters 'Unrestricted creation leads to many groups and Teams with unclear owners, guests and data, which makes access hard to keep under control.' `
                -RecommendedAction 'Decide whether everyone should create groups. If yes, back it with expiration, naming and owner rules; if not, limit creation to an approved group (Group.Unified settings EnableGroupCreation=false and GroupCreationAllowedGroupId)' `
                -DocumentationUrl $groupSettingsGuideDoc -SourceFile $groupSettingsSrc -RuleId 'group-settings-creation-unrestricted'
        }
        if ([string]::IsNullOrWhiteSpace([string]$unifiedMap['PrefixSuffixNamingRequirement']) -and
            [string]::IsNullOrWhiteSpace([string]$unifiedMap['CustomBlockedWordsList'])) {
            Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Group Governance' `
                -Title 'No naming policy for Microsoft 365 groups' `
                -Evidence 'Both PrefixSuffixNamingRequirement and CustomBlockedWordsList are empty in the effective Group.Unified settings.' `
                -WhyItMatters 'A naming standard makes it easier to see what a group is for and who owns it. It helps cleanup but is not a security control on its own.' `
                -RecommendedAction ("If it helps your cleanup process, set a prefix/suffix or blocked words in {0} > Naming policy" -f $groupsPath) `
                -DocumentationUrl $namingDoc -SourceFile $groupSettingsSrc -RuleId 'group-settings-naming-policy-absent'
        }
    }

    $lifecycleDoc = 'https://learn.microsoft.com/graph/api/resources/grouplifecyclepolicy?view=graph-rest-1.0'
    $lifecycleResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/groupLifecyclePolicies?$top=100'
    $lifecycleRows = @(if ($lifecycleResult.Success) {
        @($lifecycleResult.Rows | ForEach-Object { [pscustomobject]@{
            Id=Get-EAGovProperty $_ 'id'; ManagedGroupTypes=Get-EAGovProperty $_ 'managedGroupTypes'
            GroupLifetimeInDays=Get-EAGovProperty $_ 'groupLifetimeInDays'
            AlternateNotificationEmailsConfigured=(-not [string]::IsNullOrWhiteSpace([string](Get-EAGovProperty $_ 'alternateNotificationEmails')))
        } })
    } else { @() })
    $lifecycleSrc = Write-Evidence -BaseName 'group_governance_lifecycle_policy' -Rows $lifecycleRows -Title 'Microsoft 365 Group Expiration Policy'
    if (-not $lifecycleResult.Success -or $lifecycleResult.Truncated) {
        $reason = if ($lifecycleResult.Success) { 'groupLifecyclePolicies pagination limit reached' } else { [string]$lifecycleResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Microsoft 365 group expiration policy' `
            -Reason $reason -RequiredScope 'Directory.Read.All' -DocumentationUrl $lifecycleDoc -SourceFile $lifecycleSrc `
            -Subject 'the Microsoft 365 group expiration policy' `
            -Impact 'Whether unused Microsoft 365 groups expire was not checked.'
    } elseif ($m365GroupCount -gt 0 -and ($lifecycleRows.Count -eq 0 -or @($lifecycleRows | Where-Object { [string]$_.ManagedGroupTypes -notmatch '^None$' }).Count -eq 0)) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
            -Title 'Microsoft 365 groups never expire' `
            -Evidence ("Microsoft 365 groups={0}; lifecycle policy records={1}; none apply to All or Selected groups." -f $m365GroupCount,$lifecycleRows.Count) `
            -WhyItMatters 'Without expiration, groups and the access they give stay forever after the project ends, unless someone cleans them up by hand.' `
            -RecommendedAction ("Turn on group expiration in {0} > Expiration (for example 365 days, with owners renewing by email), or document the cleanup process you use instead" -f $groupsPath) `
            -DocumentationUrl $doc -SourceFile $lifecycleSrc -RuleId 'm365-group-expiration-policy-absent'
    }

    $roleOwnerless = @($rows | Where-Object { $_.OwnersKnown -and $_.OwnerCount -eq 0 -and $_.IsAssignableToRole -eq $true })
    if ($roleOwnerless.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Group Governance' `
            -Title ((Format-EACount $roleOwnerless.Count 'group that can hold admin roles has' 'groups that can hold admin roles have') + ' no owner') `
            -Evidence 'Owner enumeration succeeded and returned zero owners for these role-assignable groups (isAssignableToRole=true).' `
            -WhyItMatters 'These groups can give admin rights. With no owner, nobody is accountable for who is in them, so unneeded admin access is not noticed or removed.' `
            -RecommendedAction 'Name an accountable owner for each listed group (two for resilience), manage that ownership through Privileged Identity Management (PIM) for Groups, and set up a recurring access review of the members' `
            -DocumentationUrl $roleGroupDoc -SourceFile $src -ResultRows $roleOwnerless -RuleId 'role-group-ownerless' `
            -AffectedObjectIds @($roleOwnerless | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'group' -AffectedCount @($roleOwnerless | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'groups with the stated governance condition'
    }

    $cloudOwnerless = @($rows | Where-Object {
        $_.OwnersKnown -and $_.OwnerCount -eq 0 -and $_.IsAssignableToRole -ne $true -and
        $_.OnPremisesSyncEnabled -ne $true -and $_.GroupKind -in @('Security','Microsoft365')
    })
    if ($cloudOwnerless.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Group Governance' `
            -Title (Format-EACount $cloudOwnerless.Count 'cloud group has no owner' 'cloud groups have no owner') `
            -Evidence 'Security or Microsoft 365 groups created in the cloud: owner enumeration succeeded and returned zero owners. Groups synced from on-premises are reported separately.' `
            -WhyItMatters 'Nobody is responsible for approving members, checking guest access or deleting the group when it is no longer needed.' `
            -RecommendedAction ("Add an owner to each listed group in {0} > All groups > [group] > Owners, or delete groups that are no longer used" -f $groupsPath) `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $cloudOwnerless -RuleId 'cloud-group-ownerless' `
            -AffectedObjectIds @($cloudOwnerless | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'group' -AffectedCount @($cloudOwnerless | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'groups with the stated governance condition'
    }

    $syncedOwnerless = @($rows | Where-Object { $_.OwnersKnown -and $_.OwnerCount -eq 0 -and $_.OnPremisesSyncEnabled -eq $true })
    if ($syncedOwnerless.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
            -Title ((Format-EACount $syncedOwnerless.Count 'group synced from on-premises has' 'groups synced from on-premises have') + ' no owner in the cloud') `
            -Evidence 'These groups are synchronized from on-premises, so ownership may be managed in the source directory; the cloud owner field is empty.' `
            -WhyItMatters 'Owners may be managed in on-premises Active Directory, but reviewers still need a named business owner to confirm who should be in each group.' `
            -RecommendedAction 'Confirm who owns these groups in on-premises Active Directory and record the owner where access reviewers can see it' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $syncedOwnerless -RuleId 'synced-group-ownerless' `
            -AffectedObjectIds @($syncedOwnerless | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'group' -AffectedCount @($syncedOwnerless | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'groups with the stated governance condition'
    }

    $publicM365 = @($rows | Where-Object { $_.GroupKind -eq 'Microsoft365' -and [string]$_.Visibility -ieq 'Public' })
    if ($publicM365.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
            -Title ((Format-EACount $publicM365.Count 'Microsoft 365 group is' 'Microsoft 365 groups are') + ' public: anyone in the organization can join') `
            -Evidence 'Visibility=Public allows users in the organization to discover and join these groups without owner approval.' `
            -WhyItMatters "Anyone in the organization can join a public group without approval and then read its files, mail and Teams content. That is fine for open topics but not for sensitive work." `
            -RecommendedAction 'Check that each listed group is meant to be open, and make groups with sensitive content private (Microsoft 365 admin center > Teams & groups > Active teams & groups)' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $publicM365 -RuleId 'public-m365-groups' `
            -AffectedObjectIds @($publicM365 | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'group' -AffectedCount @($publicM365 | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'groups with the stated governance condition'
    }

    $pausedDynamic = @($rows | Where-Object { $_.IsDynamic -and [string]$_.MembershipRuleState -notmatch '^(On|Processing)$' })
    if ($pausedDynamic.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Group Governance' `
            -Title (Format-EACount $pausedDynamic.Count 'dynamic group has stopped updating its members' 'dynamic groups have stopped updating their members') `
            -Evidence 'The group is DynamicMembership, but membershipRuleProcessingState is not On/Processing.' `
            -WhyItMatters 'Dynamic groups add and remove members automatically based on a rule. While processing is paused, people who left or changed jobs keep the access the group gives, and new people do not get it.' `
            -RecommendedAction 'Check the membership rule of each listed group, turn processing back on, and review the current members before relying on the group for access' `
            -DocumentationUrl $dynamicDoc -SourceFile $src -ResultRows $pausedDynamic -RuleId 'dynamic-group-processing-off' `
            -AffectedObjectIds @($pausedDynamic | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'group' -AffectedCount @($pausedDynamic | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'groups with the stated governance condition'
    }

    $invalidPrivilegedDynamic = @($rows | Where-Object { $_.IsAssignableToRole -eq $true -and $_.IsDynamic })
    if ($invalidPrivilegedDynamic.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Group Governance' `
            -Title ((Format-EACount $invalidPrivilegedDynamic.Count 'group that can hold admin roles uses' 'groups that can hold admin roles use') + ' automatic (dynamic) membership') `
            -Evidence 'Graph returned both isAssignableToRole=true and DynamicMembership. This unsupported/high-risk combination requires validation.' `
            -WhyItMatters 'Anyone whose user details match the rule would get admin rights automatically, without approval. Microsoft does not normally allow this combination, so it needs checking.' `
            -RecommendedAction ("Check the listed groups in {0}, switch them to assigned membership, and manage admin access through Privileged Identity Management (PIM) for Groups" -f $groupsPath) `
            -DocumentationUrl $roleGroupDoc -SourceFile $src -ResultRows $invalidPrivilegedDynamic -RuleId 'role-group-dynamic' `
            -AffectedObjectIds @($invalidPrivilegedDynamic | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'group' -AffectedCount @($invalidPrivilegedDynamic | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'groups with the stated governance condition'
    }

    if ($activityCoverage) {
        # The D180 window ends at the report's refresh date (the report lags by about two
        # days), so measure the window from there; fall back to now when it is unreadable.
        # A group counts as inactive only when every signal agrees: it existed for the
        # whole window, no activity counter is above zero, and lastActivityDate (mail,
        # SharePoint and Yammer only) is empty or older than the window.
        $activityCounters = @('TeamsChannelMessagesCount','TeamsMeetingsOrganizedCount','ExchangeReceivedEmailCount',
            'SharePointActiveFileCount','YammerPostedMessageCount','YammerReadMessageCount','YammerLikedMessageCount')
        $inactive = @($rows | Where-Object {
            if (-not $_.ActivityEvidenceKnown -or $_.IsDeleted -eq $true) { return $false }
            $windowEnd = ConvertTo-EAGovDateTime $_.ReportRefreshDate
            if (-not $windowEnd) { $windowEnd = [datetimeoffset]::UtcNow }
            $cutoff = $windowEnd.AddDays(-180)
            $created = ConvertTo-EAGovDateTime $_.CreatedDateTime
            if (-not $created -or $created -ge $cutoff) { return $false }
            foreach ($counter in $activityCounters) {
                $value = 0.0
                if ([double]::TryParse([string]$_.$counter, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$value) -and $value -gt 0) { return $false }
            }
            $last = ConvertTo-EAGovDateTime $_.LastActivityDate
            return (-not $last -or $last -lt $cutoff)
        })
        if ($inactive.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
                -Title ((Format-EACount $inactive.Count 'Microsoft 365 group has' 'Microsoft 365 groups have') + ' had no activity for 180 days') `
                -Evidence 'Microsoft 365 groups activity report (D180): only groups with an explicit report row were evaluated; missing report rows were treated as unknown. Groups created within the 180-day window (or with an unknown creation date), deleted groups, and groups with any Teams channel message, Teams meeting, received mail, active SharePoint file or Yammer activity counted in the report were excluded.' `
                -WhyItMatters 'Unused groups keep their members, guests, files and app access long after the work ended.' `
                -RecommendedAction 'Ask the owners whether each group is still needed, then archive or delete unused ones through your normal process (group expiration can do this automatically)' `
                -DocumentationUrl $doc -SourceFile $src -ResultRows $inactive -RuleId 'm365-groups-inactive-180d' `
                -AffectedObjectIds @($inactive | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'group' -AffectedCount @($inactive | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'groups with the stated governance condition'
        }
    }

    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Group Governance' `
        -Title ("Group owners, visibility and activity recorded ({0})" -f (Format-EACount $rows.Count 'group' 'groups')) `
        -Evidence ("Groups={0}; role-assignable={1}; dynamic={2}; public M365={3}; activity coverage={4}." -f `
            $rows.Count,@($rows | Where-Object {$_.IsAssignableToRole -eq $true}).Count,
            @($rows | Where-Object {$_.IsDynamic}).Count,$publicM365.Count,$activityCoverage) `
        -WhyItMatters 'The list shows which groups have owners, who can join them and which are no longer used.' `
        -RecommendedAction 'Compare the list with your group standards for naming, owners, expiration and access reviews' `
        -DocumentationUrl $doc -SourceFile $src -ResultRows $rows.ToArray() -RuleId 'group-governance-inventory'
}
