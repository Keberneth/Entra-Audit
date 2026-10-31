<#
Guest / External Governance. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

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
                -SourceFile $src -AffectedPrincipal $g.UserPrincipalName -ObjectType 'user' -ObjectId $g.Id -ResultRows $g.RoleRows `
                -AffectedObjectIds @($g.Id) -AffectedObjectType 'user' -AffectedCount 1
        } else {
            Add-EntraFinding -Severity 'High' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-admin-role-eligible' `
                -Title ("Guest account can switch on an admin role: {0}" -f $g.UserPrincipalName) `
                -Evidence ("Guest {0} (object id {1}, enabled: {2}) is eligible for or has activated: {3}." -f $g.UserPrincipalName, $g.Id, $g.Enabled, $g.RoleText) `
                -WhyItMatters 'A guest account is controlled by another organization: you do not manage its password, multifactor authentication (MFA) or when it is removed. It can switch the admin role on whenever it needs it.' `
                -RecommendedAction 'Remove the admin role from the guest. If an external person must administer the tenant, give them a member account that your own policies control (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles).' `
                -SourceFile $src -AffectedPrincipal $g.UserPrincipalName -ObjectType 'user' -ObjectId $g.Id -ResultRows $g.RoleRows `
                -AffectedObjectIds @($g.Id) -AffectedObjectType 'user' -AffectedCount 1
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
        [pscustomobject]@{ Id = $_.Id; UserPrincipalName = $_.UserPrincipalName; PendingSince = $since; ExternalUserStateChangeDateTime = $_.ExternalUserStateChangeDateTime; CreatedDateTime = $_.CreatedDateTime }
    })
    $pending90 = @($pending | Where-Object { $_.PendingSince -and $_.PendingSince -lt $now0.AddDays(-90) })
    $pending30 = @($pending | Where-Object { $_.PendingSince -and $_.PendingSince -lt $now0.AddDays(-30) -and $_.PendingSince -ge $now0.AddDays(-90) })
    if ($pending90.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-invite-pending-over-90-days' `
            -Title ((Format-EACount -Count $pending90.Count -One 'guest invitation has' -Many 'guest invitations have') + ' not been accepted for over 90 days') `
            -Evidence ("Guests in PendingAcceptance state for over 90 days: {0}. First {1}: {2}" -f $pending90.Count, [Math]::Min(10, $pending90.Count), (($pending90 | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Invitations that were never accepted are leftover external accounts. They clutter the directory and can hide abandoned or mistaken invitations that someone could still redeem.' `
            -RecommendedAction 'Delete guest accounts whose invitation has not been accepted for over 90 days (Entra admin center > Entra ID > Users, filter on invitation state).' `
            -SourceFile $src -ResultRows @($pending90 | Select-Object UserPrincipalName,PendingSince) `
            -AffectedObjectIds @($pending90 | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $pending90.Count -PopulationLabel 'pending guest invitations with known age' -AssessedCount (@($pending | Where-Object PendingSince).Count) -UnknownCount (@($pending | Where-Object { -not $_.PendingSince }).Count)
    }
    if ($pending30.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-invite-pending-30-90-days' `
            -Title ((Format-EACount -Count $pending30.Count -One 'guest invitation has' -Many 'guest invitations have') + ' not been accepted for 30-90 days') `
            -Evidence ("Guests in PendingAcceptance state for 30-90 days: {0}." -f $pending30.Count) `
            -WhyItMatters 'Invitations that stay unaccepted this long are usually abandoned and should be cleaned up before they become forgotten accounts.' `
            -RecommendedAction 'Follow up with the inviter, or delete invitations that are no longer needed.' `
            -SourceFile $src -ResultRows @($pending30 | Select-Object UserPrincipalName,PendingSince) `
            -AffectedObjectIds @($pending30 | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $pending30.Count -PopulationLabel 'pending guest invitations with known age' -AssessedCount (@($pending | Where-Object PendingSince).Count) -UnknownCount (@($pending | Where-Object { -not $_.PendingSince }).Count)
    }
    Add-EntraFinding -Severity 'Information' -CheckId 'guests' -Category 'External Access' -RuleId 'guests-population' `
        -Title ((Format-EACount -Count $guestUsers.Count -One 'guest (external) account' -Many 'guest (external) accounts') + ' in the tenant') `
        -Evidence ("Guest accounts: {0} ({1} enabled); invitations not yet accepted: {2}." -f $guestUsers.Count, @($guestUsers | Where-Object { $_.AccountEnabled }).Count, $pending.Count) `
        -WhyItMatters 'Shows how much the tenant is shared with outside people - background for the other guest findings.' `
        -RecommendedAction 'No action needed - background information.' -SourceFile $src
}
