<#
Recently Created Users / Groups. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

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
            EventId          = [string]$_.Id
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
            $evidence = ("Since {0}: {1} ({2} not successful) by {3}: {4}. Roles most affected: {5}. Not counted: {6} and {7} the PIM service made to carry out PIM activations or assignments that are already listed (each PIM assignment is counted once, through its own PIM event). Run the changemonitoring check for a classified timeline of all security-sensitive changes." -f `
                $sinceDay, (Format-EACount -Count $changes.Count -One 'role grant, removal, eligibility or role-setting event' -Many 'role grant, removal, eligibility or role-setting events'), $failed, (Format-EACount -Count $initiators.Count -One 'initiator' -Many 'initiators'), $topInitiators, $(if ($roles) { $roles } else { 'not recorded' }), (Format-EACount -Count $activations.Count -One 'PIM activation/deactivation event' -Many 'PIM activation/deactivation events'), (Format-EACount -Count $pimWrites.Count -One 'directory write' -Many 'directory writes'))
            if ($retentionShort) { $evidence += (' Audit log retention is {0}, so older changes in the {1}-day window are not visible.' -f $retentionText, $RecentChangeDays) }
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title ("{0} in the last {1} days" -f (Format-EACount -Count $changes.Count -One 'admin role grant, removal or setting change' -Many 'admin role grants, removals or setting changes'), $RecentChangeDays) `
                -Evidence $evidence `
                -WhyItMatters 'A new administrator role grant is often the first sign of a rogue administrator or a compromised provisioning account. Each grant, removal or change to Privileged Identity Management (PIM) role settings should match an approved change.' `
                -RecommendedAction ("Check each listed change against an approved change or access request and investigate any change made by an unexpected person or app. The full list is in the evidence file and in {0}." -f $auditPortal) `
                -SourceFile $rcsrc -ResultRows @($changes | Select-Object -First 50) `
                -RuleId 'recentchanges-role-changes' -ObjectType 'tenant' `
                -AffectedObjectIds @($changes.EventId) -AffectedObjectType 'auditEvent' -AffectedCount $changes.Count -PopulationLabel 'role-change events in the retained lookback window' `
                -VerificationType HistoricalEvent -VerificationSteps 'Match each event to an approved access/change request. Investigate unexplained events and verify current role assignments after any remediation. Record the review outcome; historical audit events remain until retention expiry and need not disappear on rerun.' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs'
        }
        if ($activations.Count -gt 0) {
            $activators = @($activations | Group-Object Initiator | Sort-Object Count -Descending)
            Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
                -Title ("{0} in the last {1} days" -f (Format-EACount -Count $activations.Count -One 'PIM role activation or deactivation event' -Many 'PIM role activation or deactivation events'), $RecentChangeDays) `
                -Evidence ("{0} by {1}; most active: {2}. Activating an eligible role is the intended way to use Privileged Identity Management (PIM); these are listed for visibility and do not count as role changes." -f `
                    (Format-EACount -Count $activations.Count -One 'event' -Many 'events'), (Format-EACount -Count $activators.Count -One 'initiator' -Many 'initiators'), ((@($activators | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })) -join ', ')) `
                -WhyItMatters 'Just-in-time activation of eligible roles in Privileged Identity Management (PIM) is the desired way to work with admin rights. Unfamiliar people activating roles, or unusual volumes or times, are still worth a look.' `
                -RecommendedAction 'Spot-check activations by unfamiliar users or at unusual times (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles > Resource audit).' `
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
    $userText = ('New users: {0} ({1}, {2} disabled).' -f $newUsers.Count, (Format-EACount -Count $guestCount -One 'guest' -Many 'guests'), @($newUsers | Where-Object { $_.AccountEnabled -eq $false }).Count)
    if ($groupsKnown) {
        $roleAssignable = @($newGroups | Where-Object { $_.IsAssignableToRole }).Count
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title ("{0} and {1} created in the last {2} days" -f (Format-EACount -Count $newUsers.Count -One 'user' -Many 'users'), (Format-EACount -Count $newGroups.Count -One 'group' -Many 'groups'), $RecentChangeDays) `
            -Evidence ("{0} New groups: {1} ({2} role-assignable). Created on or after {3}." -f $userText, $newGroups.Count, $roleAssignable, $sinceDay) `
            -WhyItMatters 'New accounts and groups should match approved onboarding; unexpected ones can point to rogue provisioning. A new role-assignable group can be used to hand out admin roles.' `
            -RecommendedAction 'Spot-check the new accounts and groups against HR / onboarding records, and make sure every new role-assignable group has a known owner and purpose.' `
            -SourceFile $src -ResultRows $rows -RuleId 'recentchanges-new-users-groups' -ObjectType 'tenant'
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title ("{0} created in the last {1} days; new groups could not be read" -f (Format-EACount -Count $newUsers.Count -One 'user' -Many 'users'), $RecentChangeDays) `
            -Evidence ("{0} New groups: unknown - the group read failed: {1}. Created on or after {2}." -f $userText, $groupsError, $sinceDay) `
            -WhyItMatters 'New accounts and groups should match approved onboarding; unexpected ones can point to rogue provisioning. Because the group list could not be read, new groups (including role-assignable ones) were not reviewed.' `
            -RecommendedAction 'Grant Group.Read.All (or Directory.Read.All) and re-run the recentchanges check; meanwhile spot-check the new accounts against HR / onboarding records.' `
            -SourceFile $src -ResultRows $rows -RuleId 'recentchanges-new-groups-unreadable' -ObjectType 'tenant' -CoverageGap
    }
}
