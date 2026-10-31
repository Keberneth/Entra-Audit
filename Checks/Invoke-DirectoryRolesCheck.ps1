<#
Privileged Assignment Volume. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

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
    # A row with MemberType 'Group' is a user who holds the role only as a member of a
    # role-assignable group. The group has its own row and is counted once (its members are
    # expanded for Global Administrator below), so these rows are not counted again as
    # separate standing or eligible principals. A JIT activation is always the user's own
    # (a group cannot activate), so it is kept even when it came through a group.
    $standing  = @($active | Where-Object { [string]$_.ActivationModel -ne 'TimeBound-Active-JIT' -and [string]$_.MemberType -ne 'Group' })
    $activated = @($active | Where-Object { [string]$_.ActivationModel -eq 'TimeBound-Active-JIT' })
    $eligibleRows = @($eligibleRows | Where-Object { [string]$_.MemberType -ne 'Group' })
    $notes = @(
        'Counts are distinct principals per role. Standing = permanent or time-bound active assignments; ActivatedJitNow = PIM activations in effect at audit time (not counted); Eligible = PIM-eligible (not counted).'
        'A role held through a role-assignable group counts the group once per role; members who get the role only through the group are not counted again.'
    )
    if ($script:PrivEligibilityAssignmentsFailed) {
        # The raw read error is published by Get-EAPrivAssignments when available.
        $eligErr = [string]$script:PrivEligibilityFetchError
        $notes += ('The PIM-eligible assignments could not be read{0}; the Eligible column is incomplete.' -f $(if ($eligErr) { " ($eligErr)" } else { '' }))
    }

    if ($active.Count -eq 0) {
        # Every tenant has at least one active Global Administrator, so zero active rows
        # means the read failed or returned nothing - the volume is UNKNOWN, not low.
        $activeErr = [string]$script:PrivAssignmentsError
        if (-not $activeErr) { $activeErr = [string]$script:PrivActiveFetchError }
        $src = Write-Evidence -BaseName 'directory_role_counts' -Rows @() -Title 'Privileged Role Assignment Volume' `
            -Notes ($notes + ('No active role assignments were returned - the admin count could not be determined.{0}' -f $(if ($activeErr) { " Read error: $activeErr" } else { '' })))
        Add-EntraFinding -Severity 'Information' -CheckId 'directory-roles' -Category 'Privileged Access' -RuleId 'directory-roles-volume-unknown' -CoverageGap `
            -Title 'Number of admins could not be counted - role assignments could not be read' `
            -Evidence ("No active role assignments were returned{0}. Microsoft Entra always has at least one active Global Administrator, so the Global Administrator and admin-role counts are unknown, not zero." -f $(if ($activeErr) { " (the role-assignment read failed: $activeErr)" } elseif ($script:PrivAssignmentsFailed) { ' (the role-assignment read failed)' } else { '' })) `
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
            # Shared, run-wide member cache (throws on a failed read; only successes are cached):
            # the privileged-user map and the break-glass / access-path checks expand the same
            # Global Administrator groups.
            foreach ($m in @(Get-EAGroupTransitiveMember -GroupId $gid)) {
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
    if ($gaGroups.Count -gt 0) { $notes += ('Global Administrator is assigned to {0}: {1}. {2} counted as Global Administrators.' -f (Format-EACount -Count $gaGroups.Count -One 'group' -Many 'groups'), (@($gaGroups.Values) -join ', '), $(if ($gaGroups.Count -eq 1) { 'Its members are' } else { 'Their members are' })) }
    foreach ($ge in $gaGroupErrors) { $notes += ('Could not read the members of Global Administrator group {0}; the group is counted once, so the Global Administrator count is a minimum.' -f $ge) }
    $src = Write-Evidence -BaseName 'directory_role_counts' -Rows $rows -Title 'Privileged Role Assignment Volume' -Notes $notes

    $totalPriv = 0
    foreach ($t in $byRole.Keys) { if ($byRole[$t].Privileged) { $totalPriv += $byRole[$t].Standing.Count } }
    $totalActivated = 0
    foreach ($t in $byRole.Keys) { if ($byRole[$t].Privileged) { $totalActivated += $byRole[$t].Activated.Count } }

    $gaEvidence = ("Always-on Global Administrators: {0}{1} - {2}, {3} through {4}, {5}{6}. Not counted: {7} currently activated just-in-time through PIM and {8} PIM-eligible." -f `
        $gaCount, $(if ($gaCountIsMinimum) { ' (at least)' } else { '' }),
        (Format-EACount -Count $gaDirectUsers -One 'directly assigned user' -Many 'directly assigned users'),
        (Format-EACount -Count ($gaUserIds.Count - $gaDirectUsers) -One 'more user' -Many 'more users'),
        (Format-EACount -Count $gaGroups.Count -One 'group' -Many 'groups'),
        (Format-EACount -Count $gaOther.Count -One 'app or other principal' -Many 'apps or other principals'),
        $(if ($gaCountIsMinimum) { ('; members of {0} could not be read' -f (Format-EACount -Count $gaGroupErrors.Count -One 'group' -Many 'groups')) } else { '' }), $gaActivatedNow, $gaEligible)
    $raised = $false
    if ($gaCount -ge 5) {
        $raised = $true
        Add-EntraFinding -Severity 'High' -CheckId 'directory-roles' -Category 'Privileged Access' -RuleId 'directory-roles-global-admin-count' `
            -Title ("{0} always-on Global Administrators - Microsoft recommends fewer than 5" -f $gaCount) `
            -Evidence $gaEvidence `
            -WhyItMatters 'A Global Administrator can change everything in the tenant, so every extra one is another account whose stolen password gives an attacker full control.' `
            -RecommendedAction 'Remove Global Administrator from everyone who does not strictly need it: give day-to-day admins a narrower role, and make the remaining Global Administrators PIM-eligible (just-in-time) except the two emergency-access accounts (Entra admin center > Entra ID > Roles & admins).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices' `
            -SourceFile $src -ResultRows $rows `
            -AffectedObjectIds @(@($gaUserIds) + @($gaOther.Keys) | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType directoryObject -AffectedCount ($gaUserIds.Count + $gaOther.Count) -PopulationLabel 'resolved always-on Global Administrator principals; unreadable group members excluded'
    } elseif ($gaCount -eq 4) {
        $raised = $true
        Add-EntraFinding -Severity 'Medium' -CheckId 'directory-roles' -Category 'Privileged Access' -RuleId 'directory-roles-global-admin-count' `
            -Title '4 always-on Global Administrators - at the upper limit of Microsoft guidance (fewer than 5)' `
            -Evidence $gaEvidence `
            -WhyItMatters 'A Global Administrator can change everything in the tenant. The tenant is at the highest count Microsoft recommends, so one more admin would go over it.' `
            -RecommendedAction 'Check whether every Global Administrator still needs the role; prefer narrower admin roles and PIM-eligible (just-in-time) assignments (Entra admin center > Entra ID > Roles & admins).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices' `
            -SourceFile $src -ResultRows $rows `
            -AffectedObjectIds @(@($gaUserIds) + @($gaOther.Keys) | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType directoryObject -AffectedCount ($gaUserIds.Count + $gaOther.Count) -PopulationLabel 'resolved always-on Global Administrator principals; unreadable group members excluded'
    }
    if ($totalPriv -ge 10) {
        $raised = $true
        Add-EntraFinding -Severity 'High' -CheckId 'directory-roles' -Category 'Privileged Access' -RuleId 'directory-roles-privileged-assignment-count' `
            -Title ("{0} always-on privileged role assignments - Microsoft recommends fewer than 10" -f $totalPriv) `
            -Evidence ("Always-on assignments across privileged roles: {0} (each principal counted once per role; a group counts once). Not counted: {1} currently activated just-in-time through PIM." -f $totalPriv, $totalActivated) `
            -WhyItMatters 'Every always-on privileged role assignment is an account that can do tenant-wide damage the moment its password or session is stolen.' `
            -RecommendedAction 'Remove privileged roles that are no longer needed and make the rest PIM-eligible (just-in-time) (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices' `
            -SourceFile $src -ResultRows $rows `
            -AffectedObjectIds @($standing | Where-Object IsPrivileged | ForEach-Object { $_.PrincipalId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'directoryObject' -AffectedCount @($standing | Where-Object IsPrivileged | ForEach-Object { $_.PrincipalId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'principals with standing privileged role assignments'
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
