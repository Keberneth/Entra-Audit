<#
Effective Access / Attack Paths. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-AccessPaths {
    $apDoc = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept'
    $caDoc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access'
    # A thrown read (for example the role-definition read it depends on) is treated like a
    # failed active-assignment read: role paths are unknown, the CA analysis still runs.
    $allAssignments = @(); $privAssignError = $null
    try { $allAssignments = @(Get-EAPrivAssignments) } catch { $privAssignError = $_.Exception.Message }
    # Get-EAPrivAssignments returns whatever it managed to read: when BOTH active-assignment
    # reads failed it still returns the ELIGIBLE rows, so a non-empty list is not proof that
    # the data is complete. Without the active (standing) assignments, "Active path"
    # duplicates cannot be detected and the "owner already holds this role" suppression is
    # empty, so every such owner would be reported as an escalation path and a quiet run
    # would end in a false "nothing found" baseline. Skip the role-path analysis in that
    # case; the Conditional Access exclusion-owner analysis below does not depend on it.
    $activeKnown   = -not ($script:PrivAssignmentsFailed -or $privAssignError)
    $eligibleKnown = -not $script:PrivEligibilityAssignmentsFailed
    $assignments   = if ($activeKnown) { $allAssignments } else { @() }
    # PrivAssignmentsError names BOTH failed active reads (PIM schedule instances and the
    # classic roleAssignments fallback), so it comes before the PIM-only error text - the
    # same order as the breakglass check.
    $activeWhy = if ($privAssignError) { $privAssignError }
                 elseif ($script:PrivAssignmentsError) { [string]$script:PrivAssignmentsError }
                 elseif ($script:PrivActiveFetchError) { [string]$script:PrivActiveFetchError }
                 else { $null }
    # The user list only enriches labels and the "owner is disabled" test; remember a failure
    # so a disabled owner is shown as unknown instead of silently as enabled.
    $usersKnown = $true; $usersError = $null
    try { Get-EAUsers | Out-Null } catch { $usersKnown = $false; $usersError = $_.Exception.Message }

    # Direct (user) privileged assignments, tracking activation state (Active wins).
    # A user row with MemberType 'Group' is the same assignment inherited through a group
    # (the group's own row is expanded below), so it is not a second, direct path; it still
    # counts as "already holds this role" for the owner suppression further down.
    $directKey = @{}   # "userId|roleTemplateId|scope" -> 'Active' | 'Eligible'
    $inheritedActiveKey = New-Object System.Collections.Generic.HashSet[string]
    foreach ($a in $assignments) {
        if ($a.IsPrivileged -and $a.PrincipalType -eq 'user' -and $a.PrincipalId) {
            $k = '{0}|{1}|{2}' -f $a.PrincipalId, $a.RoleTemplateId, $a.ScopeKey
            if ([string]$a.MemberType -eq 'Group') {
                if ($a.State -eq 'Active') { [void]$inheritedActiveKey.Add($k) }
                continue
            }
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
        # Shared per-run member cache (the privileged-user map expands the same groups).
        try { $members = @(Get-EAGroupTransitiveMember -GroupId ([string]$g.PrincipalId)) } catch {
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
    if (-not $activeKnown) { $apNotes += ('Role-path analysis skipped: active admin role assignments could not be read ({0} read).{1}' -f (Format-EACount -Count $allAssignments.Count -One 'eligible assignment was' -Many 'eligible assignments were'), $(if ($activeWhy) { " Error: $activeWhy" } else { '' })) }
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
            -Title ((Format-EACount -Count $dupActive.Count -One 'case' -Many 'cases') + ' of a user holding the same admin role through several active paths') `
            -Evidence ("Same admin role reached through more than one standing path (several active groups, or an active direct assignment plus a group), shown as user -> role: {0}" -f (_PairText $dupActive { "$($_.User) -> $($_.Role)" })) `
            -WhyItMatters 'When someone gets the same admin role in more than one way, removing one assignment does not remove the access. Hidden duplicate paths make it easy to leave admin rights behind when a person changes job or leaves.' `
            -RecommendedAction 'Keep one reviewed path per user and role: remove the extra group memberships or direct assignments (Entra admin center > Roles and administrators) and prefer a single eligible assignment in Privileged Identity Management (PIM).' `
            -SourceFile $src -ResultRows $dupActive -RuleId 'accesspaths-duplicate-active-paths' -ObjectType 'tenant' -DocumentationUrl $apDoc `
            -AffectedObjectIds @($dupActive | ForEach-Object { $_.UserId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount @($dupActive | ForEach-Object { $_.UserId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'users with duplicate privileged access paths'
    }
    if ($dupElig.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ((Format-EACount -Count $dupElig.Count -One 'case' -Many 'cases') + ' of a user being eligible for the same admin role through several paths') `
            -Evidence ("Same admin role reachable through more than one eligible path (several eligible groups, or an eligible direct assignment plus a group), shown as user -> role: {0}" -f (_PairText $dupElig { "$($_.User) -> $($_.Role)" })) `
            -WhyItMatters 'Several eligible paths to the same admin role make access reviews and removal harder, even though the role still has to be activated in Privileged Identity Management (PIM) before use.' `
            -RecommendedAction 'Keep one reviewed eligible path per user and role and remove the extra group memberships or assignments.' `
            -SourceFile $src -ResultRows $dupElig -RuleId 'accesspaths-duplicate-eligible-paths' -ObjectType 'tenant' -DocumentationUrl $apDoc `
            -AffectedObjectIds @($dupElig | ForEach-Object { $_.UserId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount @($dupElig | ForEach-Object { $_.UserId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'users with duplicate privileged access paths'
    }

    # Effective holders of each EXACT role (direct + group-reachable), keyed "userId|roleTemplateId".
    # Suppress an owner-escalation path ONLY when the owner already holds the SAME role the
    # group grants as ACTIVE standing access. Two refinements:
    #  - "privileged via some OTHER role" must NOT suppress (Exchange Admin owning a GA group).
    #  - holding the same role only as ELIGIBLE must NOT suppress: owning a group with the role
    #    ACTIVE lets the owner self-add and bypass the PIM activation workflow.
    $sameRoleActiveKey = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in $directKey.Keys) { if ($directKey[$k] -eq 'Active') { [void]$sameRoleActiveKey.Add($k) } }
    foreach ($k in $inheritedActiveKey) { [void]$sameRoleActiveKey.Add($k) }
    foreach ($key in $pathByUserRole.Keys) { if (@($pathByUserRole[$key] | Where-Object { $_.State -eq 'Active' }).Count -gt 0) { [void]$sameRoleActiveKey.Add($key) } }

    # Ownership-based escalation: owners of groups assigned a privileged role.
    # $groupAssign holds one row per (group, role, STATE) - dedup on (group, role) so
    # owners are neither double-counted nor fetched twice, and treat a failed owner
    # read as a coverage gap rather than "no owners".
    $ownEscRows = @()
    # Owners skipped below as "already holds this role" although their account status was
    # unknown (user list unreadable): a disabled one would have been a Critical path.
    $unknownStatusSuppressed = @()
    $seenGroupRole = New-Object System.Collections.Generic.HashSet[string]
    foreach ($g in $groupAssign) {
        if (-not $seenGroupRole.Add(('{0}|{1}|{2}' -f $g.PrincipalId, $g.RoleTemplateId, $g.ScopeKey))) { continue }
        $grantsGAorPRA = ([bool]$g.IsTier0 -or $g.RoleTemplateId -eq $script:GlobalAdminTemplateId -or ($script:PrivilegedRoleTemplates[$g.RoleTemplateId] -match 'Privileged Role Administrator|Privileged Authentication'))
        $owners = @(); try { $owners = @(Get-EAGroupOwner -GroupId ([string]$g.PrincipalId)) } catch { $ownerGaps += ($g.PrincipalName ?? $g.PrincipalId) }
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
                if ($hasSameRole -and -not $isGuest -and -not $disabled) {
                    if (-not $disabledKnown) { $unknownStatusSuppressed += ('{0} -> {1}' -f $label, $g.RoleName) }
                    continue
                }
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
                -Title ((Format-EACount -Count $critEsc.Count -One 'critical path' -Many 'critical paths') + ' where a group owner can add themselves to gain admin rights') `
                -Evidence ("Critical because the group grants a top-tier role (such as Global Administrator or Privileged Role Administrator) or the owner is a guest or disabled account. Owner -> role the group grants: {0}.{1}" -f (_PairText $critEsc { "$($_.Owner) -> $($_.GrantsRole)$(if ($_.OwnerGuest -eq $true) { ' [guest owner]' })$(if ($_.OwnerDisabled -eq $true) { ' [disabled owner]' })" }), $statusNote) `
                -WhyItMatters 'The owner of a group that holds an admin role can add themselves (or anyone) to the group and get that role. For top-tier roles, or when the owner is a guest or a disabled account, this is a direct route to taking over the tenant. Holding a different admin role does not make it safe.' `
                -RecommendedAction 'Remove guest, disabled and non-admin owners from groups that hold admin roles (Entra admin center > Groups > the group > Owners). For groups that grant top-tier roles, keep ownership with a few trusted admins and manage membership with PIM for Groups and approval.' `
                -SourceFile $osrc -ResultRows $critEsc -RuleId 'accesspaths-owner-escalation-critical' -ObjectType 'tenant' -DocumentationUrl $apDoc `
                -AffectedObjectIds @($critEsc | ForEach-Object { $_.OwnerId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'directoryObject' -AffectedCount @($critEsc | ForEach-Object { $_.OwnerId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'group owners with the stated access path'
        }
        if ($highEsc.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'accesspaths' -Category 'Privileged Access' `
                -Title ((Format-EACount -Count $highEsc.Count -One 'path' -Many 'paths') + ' where a group owner can add themselves to gain an admin role') `
                -Evidence ("Owners who do not already hold (as active) the admin role the group grants. Owner -> role the group grants: {0}.{1}" -f (_PairText $highEsc { "$($_.Owner) -> $($_.GrantsRole)" }), $statusNote) `
                -WhyItMatters 'The owner of a group that holds an admin role can add themselves to the group and get a role they do not have today. This goes around the normal, reviewed way of handing out admin roles.' `
                -RecommendedAction 'Remove non-admin owners from groups that hold admin roles (Entra admin center > Groups > the group > Owners) and manage membership with PIM for Groups and approval.' `
                -SourceFile $osrc -ResultRows $highEsc -RuleId 'accesspaths-owner-escalation' -ObjectType 'tenant' -DocumentationUrl $apDoc `
                -AffectedObjectIds @($highEsc | ForEach-Object { $_.OwnerId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'directoryObject' -AffectedCount @($highEsc | ForEach-Object { $_.OwnerId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'group owners with the stated access path'
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
        $owners = @(); try { $owners = @(Get-EAGroupOwner -GroupId ([string]$gid)) } catch { $ownerGaps += $gname }
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
                -Title ((Format-EACount -Count $mfaExcl.Count -One 'owner' -Many 'owners') + ' of MFA-exclusion groups can add themselves and skip MFA') `
                -Evidence ("Owners of groups excluded from an enabled Conditional Access policy that requires MFA, shown as owner -> excluded group: {0}" -f (_PairText $mfaExcl { "$($_.Owner) -> $($_.ExcludedGroup)" })) `
                -WhyItMatters 'Conditional Access (CA) exclusion groups are left out of a policy. The owner of a group excluded from an MFA policy can add their own account to it and no longer be asked for multifactor authentication (MFA) - no admin role needed.' `
                -RecommendedAction 'Remove non-admin and guest owners from Conditional Access exclusion groups (Entra admin center > Groups > the group > Owners), keep their membership minimal (ideally only the break-glass accounts), and manage membership with PIM for Groups.' `
                -SourceFile $csrc -ResultRows $mfaExcl -RuleId 'accesspaths-ca-mfa-exclusion-owner' -ObjectType 'tenant' -DocumentationUrl $caDoc `
                -AffectedObjectIds @($mfaExcl | ForEach-Object { $_.OwnerId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'directoryObject' -AffectedCount @($mfaExcl | ForEach-Object { $_.OwnerId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'group owners with the stated access path'
        }
        if ($otherExcl.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'accesspaths' -Category 'Privileged Access' `
                -Title ((Format-EACount -Count $otherExcl.Count -One 'owner' -Many 'owners') + ' of Conditional Access exclusion groups can exempt themselves from policies') `
                -Evidence ("Owners of groups excluded from enabled Conditional Access policies that do not require MFA (for example block, device or location rules), shown as owner -> excluded group: {0}" -f (_PairText $otherExcl { "$($_.Owner) -> $($_.ExcludedGroup)" })) `
                -WhyItMatters 'The owner of a group that is excluded from a Conditional Access (CA) policy can add their own account to the group and escape that policy, such as a block or a device or location rule.' `
                -RecommendedAction 'Limit who owns Conditional Access exclusion groups to a few trusted admins and review the groups'' members regularly.' `
                -SourceFile $csrc -ResultRows $otherExcl -RuleId 'accesspaths-ca-exclusion-owner' -ObjectType 'tenant' -DocumentationUrl $caDoc `
                -AffectedObjectIds @($otherExcl | ForEach-Object { $_.OwnerId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'directoryObject' -AffectedCount @($otherExcl | ForEach-Object { $_.OwnerId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'group owners with the stated access path'
        }
    }

    # Coverage gaps - every one of them keeps the "nothing found" baseline from appearing.
    if (-not $activeKnown) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'Admin access paths could not be checked: active role assignments could not be read' `
            -Evidence ("{0} Duplicate-path and group-owner escalation analysis needs the active assignments too, so it was skipped. Status is unknown, not clean. (Conditional Access exclusion-group owners were still checked.){1}" -f $(if ($privAssignError) { 'The admin role assignment list could not be read at all.' } else { ('Both reads of active (standing) admin role assignments failed; {0} read.' -f (Format-EACount -Count $allAssignments.Count -One 'eligible assignment was' -Many 'eligible assignments were')) }), $(if ($activeWhy) { (' Error: {0}' -f $activeWhy) } else { '' })) `
            -WhyItMatters 'This check finds hidden ways to become an admin, such as the same role through several groups or a group owner who can add themselves. Without the list of active admin role assignments those paths cannot be seen.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory (read-only) to the audit identity, or re-run if the error was temporary, then re-run the accesspaths check.' `
            -SourceFile $src -RuleId 'accesspaths-role-paths-not-assessed' -ObjectType 'tenant' -DocumentationUrl $apDoc -CoverageGap
    } elseif (-not $eligibleKnown) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'Eligible (PIM) admin role assignments could not be read, so access paths are incomplete' `
            -Evidence ("{0} Duplicate paths and group-owner escalation through eligible assignments (including groups that are eligible for a role) are unknown; only active assignments were analysed.{1}" -f $(if ($script:LicenseKnown) { 'The tenant has Entra ID P2, but the eligible role assignments could not be read.' } else { 'The licence check failed, so the tenant may have Entra ID P2, and the eligible role assignments could not be read.' }), $(if ($script:PrivEligibilityFetchError) { (' Error: {0}' -f $script:PrivEligibilityFetchError) } else { '' })) `
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
            -Title ("Members of {0} could not be read" -f (Format-EACount -Count $hiddenGaps.Count -One 'admin-role group' -Many 'admin-role groups')) `
            -Evidence ("Membership could not be read (hidden membership or missing permission) for: {0}" -f (_PairText $hiddenGaps { $_ })) `
            -WhyItMatters 'Without the member list the audit cannot see who gets admin rights through these groups, so duplicate or hidden admin paths may be missed. This is a gap in the audit, not a clean result.' `
            -RecommendedAction 'Grant the audit identity Member.Read.Hidden (read-only) and re-run, or review the members of these groups manually.' `
            -SourceFile $src -RuleId 'accesspaths-group-members-unreadable' -ObjectType 'tenant' -DocumentationUrl $apDoc -CoverageGap
    }
    # A gap only when an owner of an admin-role group was actually looked at without its
    # account status; otherwise the user list only labels users (shown by id instead).
    $unknownOwnerRated = @($ownEscRows | Where-Object { $_.OwnerDisabled -eq 'unknown' }).Count
    $ownerStatusGap = (-not $usersKnown -and ($unknownStatusSuppressed.Count + $unknownOwnerRated) -gt 0)
    if ($ownerStatusGap) {
        $suppressedText = if ($unknownStatusSuppressed.Count -gt 0) { (' {0} not rated for this reason: {1}.' -f (Format-EACount -Count $unknownStatusSuppressed.Count -One 'owner who already holds the same role was' -Many 'owners who already hold the same role were'), (_PairText $unknownStatusSuppressed { $_ })) } else { '' }
        $ratedText = if ($unknownOwnerRated -gt 0) { (' ' + (Format-EACount -Count $unknownOwnerRated -One 'owner in the other findings of this check was rated without knowing whether the account is disabled, so it may be rated too low.' -Many 'owners in the other findings of this check were rated without knowing whether their account is disabled, so some may be rated too low.')) } else { '' }
        Add-EntraFinding -Severity 'Low' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'Account status of admin-group owners could not be read' `
            -Evidence ("The user list could not be read ({0}), so it is unknown whether any owner of a group that holds an admin role is a disabled account.{1}{2}" -f $usersError, $suppressedText, $ratedText) `
            -WhyItMatters 'A disabled account that owns a group holding an admin role is rated Critical: once the account is enabled again or taken over, it can add anyone to the group and so hand out the admin role. Without the user list such owners cannot be identified. This is a gap in the audit, not a clean result.' `
            -RecommendedAction 'Grant User.Read.All (read-only) to the audit identity, or re-run if the error was temporary, then re-run the accesspaths check.' `
            -SourceFile $src -RuleId 'accesspaths-owner-status-unknown' -ObjectType 'tenant' -DocumentationUrl $apDoc -CoverageGap
    }
    $ownerGaps = @($ownerGaps | Select-Object -Unique)
    if ($ownerGaps.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title ("Owners of {0} could not be read" -f (Format-EACount -Count $ownerGaps.Count -One 'group' -Many 'groups')) `
            -Evidence ("Owner lists could not be read for these admin-role or Conditional Access exclusion groups: {0}" -f (_PairText $ownerGaps { $_ })) `
            -WhyItMatters 'Group owners can add members. If the owners cannot be read, the audit cannot tell whether someone could add themselves to gain admin rights or to skip Conditional Access.' `
            -RecommendedAction 'Make sure the audit identity has Group.Read.All (read-only) and re-run, or review the owners of these groups manually.' `
            -SourceFile $src -RuleId 'accesspaths-group-owners-unreadable' -ObjectType 'tenant' -DocumentationUrl $apDoc -CoverageGap
    }

    if ($activeKnown -and $eligibleKnown -and $caKnown -and -not $ownerStatusGap -and
        $dupRows.Count -eq 0 -and $ownEscRows.Count -eq 0 -and $caOwnRows.Count -eq 0 -and $hiddenGaps.Count -eq 0 -and $ownerGaps.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'accesspaths' -Category 'Privileged Access' `
            -Title 'No duplicate admin role paths or risky group owners found' `
            -Evidence ("{0} analysed: each admin role is reached through a single path, and no group that holds an admin role or is excluded from Conditional Access has an owner who could add themselves." -f (Format-EACount -Count $assignments.Count -One 'admin role assignment' -Many 'admin role assignments')) `
            -WhyItMatters 'One reviewed path per admin role makes removing access reliable and leaves no hidden standing admin rights.' `
            -RecommendedAction 'Keep single-path admin assignments and keep group ownership limited to trusted admins.' `
            -SourceFile $src -RuleId 'accesspaths-baseline' -ObjectType 'tenant' -DocumentationUrl $apDoc
    }
}
