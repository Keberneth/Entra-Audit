<#
Privileged Roles - Permanent vs Eligible. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-PrivRoles {
    Get-EARoleDefMap | Out-Null
    # The user and MFA-registration caches only ANNOTATE assignments (UPN, guest, synced,
    # MFA-capable). A failed read is remembered and reported instead of being swallowed:
    # without the user cache a synced or guest admin can look like a cloud-only member.
    $userError = $null; $regError = $null
    try { Get-EAUsers | Out-Null } catch { $userError = $_.Exception.Message }
    try { Get-EARegistrationDetails | Out-Null } catch { $regError = $_.Exception.Message }

    $assignments = New-Object System.Collections.Generic.List[object]   # one row per (principal, role, state)

    # Resolve a directory-role template id -> our privileged classification
    function _RoleInfo([string]$roleDefId) {
        return (Get-EARoleInfo -RoleDefinitionId $roleDefId)
    }

    function _Principal($p) {
        # Graph frequently omits @odata.type on the default (user) type when a Principal
        # is $expand-ed, and the UPN lives in AdditionalProperties (not as a first-class
        # member). Resolve UPN from the user cache as a fallback, and infer the type from
        # the UPN / known-user cache / group or app markers so the break-glass and
        # guest/synced gates work.
        $id   = if ($p) { $p.Id } else { $null }
        $upn  = (Get-Ap $p 'userPrincipalName')
        $name = (Get-Ap $p 'displayName')
        if (-not $name -and $p -and $p.PSObject.Properties['DisplayName']) { $name = $p.DisplayName }
        if (-not $upn -and $id -and $script:UserById.ContainsKey($id)) { $upn = $script:UserById[$id].UserPrincipalName }

        $odt = Get-Ap $p '@odata.type'
        $type = if ($odt) { ($odt -replace '#microsoft.graph.','') }
                elseif ($upn) { 'user' }
                elseif ($id -and $script:UserById.ContainsKey($id)) { 'user' }
                elseif ((Get-Ap $p 'groupTypes') -or $null -ne (Get-Ap $p 'securityEnabled')) { 'group' }
                elseif (Get-Ap $p 'appId') { 'servicePrincipal' }
                else { '' }

        $synced = $false
        if ($id -and $script:UserById.ContainsKey($id)) { $synced = [bool]$script:UserById[$id].OnPremisesSyncEnabled }
        $mfa = $null
        if ($id -and $script:MfaCapableById.ContainsKey($id)) { $mfa = [bool]$script:MfaCapableById[$id] }
        # External identity: the '#EXT#' UPN marker OR userType Guest (the same rule as the
        # guests check). A renamed UPN can lose the marker, so either signal is enough.
        $isGuest = ([string]$upn -like '*#EXT#*') -or ([string](Get-Ap $p 'userType') -eq 'Guest')
        if (-not $isGuest -and $id -and $script:UserById.ContainsKey($id)) { $isGuest = ([string]$script:UserById[$id].UserType -eq 'Guest') }
        return [pscustomobject]@{ Id=$id; Type=$type; Upn=$upn; Name=$name; Synced=$synced; MfaCapable=$mfa; IsGuest=[bool]$isGuest }
    }

    # MemberType is how Graph says the principal holds the role: Direct, Group (a user who
    # gets it as a member of a role-assignable group - the group has its own row) or
    # Inherited. Graph can leave it empty; that is a real assignment, so it becomes Direct.
    function _Row {
        param($Principal, $RoleInfo, [string]$State, $EndDateTime, $MemberType, $AssignmentType, $DirectoryScopeId, $AppScopeId)
        return [pscustomobject]@{
            PrincipalId=$Principal.Id; Principal=($Principal.Upn ?? $Principal.Name); PrincipalType=$Principal.Type; IsGuest=$Principal.IsGuest
            Role=$RoleInfo.Name; RoleTemplateId=$RoleInfo.TemplateId; RoleDefinitionId=$RoleInfo.RoleDefinitionId; IsPrivileged=$RoleInfo.IsPrivileged; IsGA=$RoleInfo.IsGA; IsTier0=$RoleInfo.IsTier0
            State=$State; EndDateTime=$EndDateTime; MemberType=$(if ($MemberType) { [string]$MemberType } else { 'Direct' }); AssignmentType=$AssignmentType
            DirectoryScopeId=$DirectoryScopeId; AppScopeId=$AppScopeId; RoleClassification=$RoleInfo.ClassificationSource; Synced=$Principal.Synced; MfaCapable=$Principal.MfaCapable
        }
    }

    $pimAvailable = $true; $pimActiveCount = 0; $pimError = $null

    # --- Model A: ACTIVE assignment schedule instances (PIM-aware) ---
    try {
        foreach ($i in @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)) {
            # Order matters: an Activated (JIT) instance is time-bound even on the rare
            # occasion its EndDateTime is null; only a non-activated null-end is permanent.
            $state = if ($i.AssignmentType -eq 'Activated') { 'TimeBound-Active(JIT)' }
                     elseif ($null -eq $i.EndDateTime) { 'Permanent' }
                     else { 'TimeBound-Assigned' }
            $assignments.Add((_Row -Principal (_Principal $i.Principal) -RoleInfo (_RoleInfo $i.RoleDefinitionId) -State $state `
                -EndDateTime $i.EndDateTime -MemberType $i.MemberType -AssignmentType $i.AssignmentType `
                -DirectoryScopeId $i.DirectoryScopeId -AppScopeId $i.AppScopeId))
            $pimActiveCount++
        }
    } catch {
        $pimAvailable = $false; $pimError = $_.Exception.Message
        Write-Warn2 "  PIM active-schedule endpoint unavailable ($pimError) - falling back to classic role assignments."
    }

    # --- Model B: ELIGIBLE schedule instances (PIM) ---
    $eligibleCount = 0; $eligibilityKnown = $true; $eligibilityError = $null
    try {
        foreach ($i in @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)) {
            $eligibleCount++
            $assignments.Add((_Row -Principal (_Principal $i.Principal) -RoleInfo (_RoleInfo $i.RoleDefinitionId) -State 'Eligible' `
                -EndDateTime $i.EndDateTime -MemberType $i.MemberType -AssignmentType 'Eligible' `
                -DirectoryScopeId $i.DirectoryScopeId -AppScopeId $i.AppScopeId))
        }
    } catch {
        $eligibilityKnown = $false; $eligibilityError = $_.Exception.Message
        Write-Warn2 "  PIM eligibility endpoint unavailable ($eligibilityError) - requires Entra ID P2."
    }

    # --- Fallback: classic roleAssignments when PIM is unavailable OR returned no ACTIVE rows.
    # Keyed on the ACTIVE count, not on all rows: eligible rows must not suppress the
    # fallback, otherwise an empty active read would look like "no standing admins". ---
    $fetchErr = $null
    $activeSource = if ($pimAvailable -and $pimActiveCount -gt 0) { 'PIM role-assignment schedule instances' } else { 'none (every read failed or returned nothing)' }
    if (-not $pimAvailable -or $pimActiveCount -eq 0) {
        try {
            foreach ($a in @(Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop)) {
                $assignments.Add((_Row -Principal (_Principal $a.Principal) -RoleInfo (_RoleInfo $a.RoleDefinitionId) -State 'Permanent' `
                    -EndDateTime $null -MemberType 'Direct' -AssignmentType 'Assigned' `
                    -DirectoryScopeId $a.DirectoryScopeId -AppScopeId $a.AppScopeId))
            }
            $activeSource = 'classic role assignments (roleManagement/directory/roleAssignments)'
        } catch {
            $fetchErr = $_
            # last resort: classic directoryRoles + members (errors recorded, not hidden -
            # a failed fetch must surface as Error/Skipped/coverage gap, never as a clean 'Pass')
            try {
                foreach ($dr in @(Get-MgDirectoryRole -All -ErrorAction Stop)) {
                    $ri = _RoleInfo $dr.RoleTemplateId
                    foreach ($m in @(Get-MgDirectoryRoleMember -DirectoryRoleId $dr.Id -All -ErrorAction Stop)) {
                        $assignments.Add((_Row -Principal (_Principal $m) -RoleInfo $ri -State 'Permanent' `
                            -EndDateTime $null -MemberType 'Direct' -AssignmentType 'Assigned' -DirectoryScopeId '/' -AppScopeId $null))
                    }
                }
                $fetchErr = $null
                $activeSource = 'activated directory roles and their members (directoryRoles)'
            } catch { if (-not $fetchErr) { $fetchErr = $_ } }
        }
    }

    # De-duplicate by principal, role and BOTH assignment scopes. App-scoped/custom-role
    # grants must not collapse into a tenant- or Administrative-Unit-scoped grant. A row
    # inherited through a group (MemberType 'Group') is kept apart from the user's own
    # assignment, so a user who holds a role both ways still gets the finding for the
    # own (direct) assignment.
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $rows = @(foreach ($a in $assignments) {
        $k = '{0}|{1}|{2}|{3}|{4}|{5}' -f $a.PrincipalId,$a.RoleTemplateId,$a.DirectoryScopeId,$a.AppScopeId,$a.State,([string]$a.MemberType -eq 'Group')
        if ($seen.Add($k)) { $a }
    })

    # Every real tenant has at least one active role assignment (Entra does not let the last
    # active Global Administrator be removed). An EMPTY result is therefore UNKNOWN, not "no
    # admins" - throw so Invoke-AuditCheck classifies the check Error/Skipped-NoPermission
    # instead of drawing conclusions (e.g. "no break-glass admin") from no data.
    if ($rows.Count -eq 0) {
        if ($fetchErr) { throw $fetchErr }
        $why = @(); if ($pimError) { $why += "PIM: $pimError" }; if ($eligibilityError) { $why += "eligibility: $eligibilityError" }
        throw ("Privileged role assignments could not be retrieved from any endpoint (PIM, classic roleAssignments, directoryRoles){0} - result is UNKNOWN, not clean." -f $(if ($why) { ' [' + ($why -join '; ') + ']' } else { '' }))
    }
    # Zero ACTIVE rows (eligible only) or a failed active read: the standing-access picture
    # is unknown, so no "no permanent admin / no break-glass" conclusion may be drawn.
    $activeRows  = @($rows | Where-Object { $_.State -ne 'Eligible' })
    $activeKnown = ($activeRows.Count -gt 0 -and -not $fetchErr)

    $notes = @(
        ("Active assignments read from: {0}" -f $activeSource)
        ("PIM endpoints available: {0}" -f $pimAvailable)
        ("Eligible (PIM) assignments: {0}" -f $(if ($eligibilityKnown) { $eligibleCount } else { "could not be read ($eligibilityError)" }))
    )
    if ($pimError) { $notes += ("PIM active-assignment read failed: {0}" -f $pimError) }
    if ($fetchErr) { $notes += ("Classic role-assignment read failed: {0}" -f $fetchErr.Exception.Message) }
    if ($userError) { $notes += ("The user directory could not be read ({0}); guest and on-premises-synced status may be missing." -f $userError) }
    if ($regError)  { $notes += ("The MFA registration report could not be read ({0}); MfaCapable is empty (unknown)." -f $regError) }
    $inheritedCount = @($rows | Where-Object { [string]$_.MemberType -eq 'Group' }).Count
    if ($inheritedCount -gt 0) {
        $notes += ("{0} MemberType = Group: a user who holds the role only as a member of a role-assignable group. {1} listed here for completeness but {2} not reported as the user's own assignment - the group's row (and its finding) covers {3}, and the fix is made on the group." -f (Format-EACount -Count $inheritedCount -One 'row has' -Many 'rows have'), $(if ($inheritedCount -eq 1) { 'It is' } else { 'They are' }), $(if ($inheritedCount -eq 1) { 'is' } else { 'are' }), $(if ($inheritedCount -eq 1) { 'it' } else { 'them' }))
    }
    $src = Write-Evidence -BaseName 'privileged_roles' -Rows $rows `
        -Title 'Privileged Role Assignments - Permanent vs Eligible vs Time-Bound' -Notes $notes

    if (-not $activeKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-active-unknown' -CoverageGap `
            -Title 'Permanent admin role assignments could not be read - result unknown' `
            -Evidence ("Active role assignments found: {0} (source: {1}).{2} Microsoft Entra always keeps at least one active Global Administrator assignment, so this is a failed or incomplete read, not proof that there are no permanent admins." -f $activeRows.Count, $activeSource, $(if ($fetchErr) { ' Error: ' + $fetchErr.Exception.Message + '.' } else { '' })) `
            -WhyItMatters 'Who holds admin rights all the time is the main question of this check. A failed read must not look like "no permanent admins".' `
            -RecommendedAction 'Check that the audit account or app has RoleManagement.Read.Directory, look for throttling errors in the console output, and run the check again.' `
            -SourceFile $src
    }
    if ($userError) {
        Add-EntraFinding -Severity 'Information' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-account-details-unknown' -CoverageGap `
            -Title 'Admin account details could not be read - guest and on-premises status unknown' `
            -Evidence ("The user directory read failed: {0}. Guest accounts are then only recognised by the #EXT# marker in their sign-in name, and accounts synced from on-premises Active Directory cannot be recognised, so a guest admin may be rated High instead of Critical and a synced account named in -BreakGlassUpns is treated as cloud-only." -f $userError) `
            -WhyItMatters 'These details decide how risky an admin account is - for example a guest admin is always Critical. Without them the result can look better than it is.' `
            -RecommendedAction 'Grant User.Read.All to the audit account or app and run the check again.' `
            -SourceFile $src
    }

    $bg = Normalize-StringList -Values $BreakGlassUpns
    # A user row with MemberType 'Group' is the group's assignment seen from one member: it
    # cannot be removed from the user, and the group's own row already raises the finding.
    # Only that value is left out - an empty or 'Inherited' MemberType is a real assignment.
    $permanentPriv = @($rows | Where-Object { $_.IsPrivileged -and $_.State -eq 'Permanent' -and [string]$_.MemberType -ne 'Group' })
    $permanentGA   = @($permanentPriv | Where-Object { $_.IsGA })

    # Index rows by principal once - re-scanning all rows per permanent assignment is
    # O(n*m) with hundreds of standing assignments (the systemic case this check exists for).
    # ::new() rather than New-Object: New-Object returns the list PSObject-wrapped, and
    # @() over a wrapped List throws "Argument types do not match" on some pwsh 7.4 builds.
    $rowsByPrincipal = @{}
    foreach ($r in $rows) {
        $pid0 = [string]$r.PrincipalId
        if (-not $rowsByPrincipal.ContainsKey($pid0)) { $rowsByPrincipal[$pid0] = [System.Collections.Generic.List[object]]::new() }
        $rowsByPrincipal[$pid0].Add($r) | Out-Null
    }

    function _ScopeText($a) {
        $t = if ([string]::IsNullOrEmpty([string]$a.DirectoryScopeId) -or [string]$a.DirectoryScopeId -eq '/') { 'whole tenant' } else { 'directory scope ' + [string]$a.DirectoryScopeId }
        if ($a.AppScopeId -and [string]$a.AppScopeId -ne '/') { $t += ('; app scope {0}' -f $a.AppScopeId) }
        return $t
    }

    # Per-assignment findings for permanent privileged roles. Stable ids: the RuleId carries
    # the role TEMPLATE id (one issue per role, so the risk score and the report keep one
    # bucket per role, as the title prefix did before) and PathHash carries both scopes (the
    # same role at two scopes is two findings, matching the de-duplication key above).
    foreach ($a in $permanentPriv) {
        $roleKey  = ([string]$a.RoleTemplateId).ToLowerInvariant()
        $scopeKey = '{0};{1}' -f $a.DirectoryScopeId, $a.AppScopeId
        $who = if ($a.Principal) { [string]$a.Principal } else { 'unknown principal ' + [string]$a.PrincipalId }

        $isBreakGlass = ($a.Principal -and ($a.Principal.ToLowerInvariant() -in $bg) -and -not $a.Synced -and $a.PrincipalType -eq 'user')
        if ($isBreakGlass -and $a.IsGA) { continue }   # permanent GA on a break-glass account is the expected posture
        if ($isBreakGlass -and -not $a.IsGA) {
            # A break-glass account should be permanent ONLY for Global Administrator. Any
            # extra standing privileged role widens its blast radius beyond emergency recovery
            # and is still worth reporting (just not at the full standing-privilege severity).
            Add-EntraFinding -Severity 'Medium' -CheckId 'privileged-roles' -Category 'Privileged Access' `
                -RuleId 'privileged-roles-breakglass-extra-role' -PathHash ('{0};{1}' -f $roleKey, $scopeKey) `
                -Title ("Break-glass account has an extra permanent admin role: {0} ({1})" -f $who, $a.Role) `
                -Evidence ("Designated break-glass account {0} (object id {1}) permanently holds {2} ({3}). A break-glass account should hold only Global Administrator." -f $who, $a.PrincipalId, $a.Role, (_ScopeText $a)) `
                -WhyItMatters 'Emergency-access (break-glass) accounts are kept outside the normal sign-in rules, so they should be as simple as possible. Every extra permanent role gives an attacker more to misuse and makes the account harder to monitor.' `
                -RecommendedAction 'Remove the extra role from the break-glass account unless a documented recovery procedure needs it (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles).' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
                -SourceFile $src -AffectedPrincipal $a.Principal -ObjectType $a.PrincipalType -ObjectId $a.PrincipalId `
                -ResultRows @($rowsByPrincipal[[string]$a.PrincipalId]) `
                -AffectedObjectIds @($a.PrincipalId) -AffectedObjectType $a.PrincipalType -AffectedCount 1
            continue
        }

        # Severity follows the role TIER, not the principal type: tier-0 roles are
        # Critical, every other privileged role caps at High. The risk factors are
        # recorded as reasons on the finding instead of escalating its severity - a
        # guest (external) holder is the one exception, because a foreign-tenant
        # credential with standing admin rights is a takeover path regardless of role.
        $isTier0 = [bool]$a.IsTier0
        $sev = if ($isTier0) { 'Critical' } else { 'High' }
        $reasons = @()
        if ($a.MfaCapable -eq $false) { $reasons += 'cannot use multifactor authentication (not MFA-capable)' }
        elseif ($regError -and $a.PrincipalType -eq 'user') { $reasons += 'MFA status unknown (registration report unreadable)' }
        if ($a.Synced) { $reasons += 'synced from on-premises Active Directory' }
        if ($a.PrincipalType -eq 'group') { $reasons += 'assigned to a group - every member gets the role' }
        elseif ($a.PrincipalType -eq 'servicePrincipal') { $reasons += 'assigned to an app (service principal)' }
        if ($a.IsGuest) { $sev = 'Critical'; $reasons += 'guest/external account' }

        $factors = if ($reasons.Count) { ' Risk factors: ' + ($reasons -join '; ') + '.' } else { '' }
        $action = 'Make this role PIM-eligible (just-in-time) and remove the permanent assignment (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles). Only the two cloud-only emergency-access (break-glass) Global Administrators should stay permanent.'
        # The explanation follows the holder type: an app has no password, session or MFA and
        # cannot be made PIM-eligible, and a group passes the role to every member.
        $why = 'The admin role is switched on all the time, so anyone who steals this account''s password or session gets the admin rights at once. With Privileged Identity Management (PIM) the role is only switched on when needed, for a short time and after multifactor authentication (MFA) or approval.'
        if ($a.PrincipalType -eq 'servicePrincipal') {
            $action = 'Check whether this app really needs a directory admin role; replace it with the narrowest role or Microsoft Graph permission it needs, or remove it.'
            $why = 'This app holds the admin role all the time and uses it without anyone signing in. Anyone who steals one of its secrets or certificates gets the admin rights at once, and an app cannot use multifactor authentication (MFA) or switch a role on only when needed.'
        } elseif ($a.PrincipalType -eq 'group') {
            $why = 'Every member of this group holds the admin role all the time, so a stolen password or session of any member gives the admin rights at once. With Privileged Identity Management (PIM) the role or the group membership is only switched on when needed, for a short time and after multifactor authentication (MFA) or approval.'
        }
        # Include the directory object id so two findings for similarly-named but DISTINCT
        # accounts (e.g. niclas@contoso.se vs niclas@contoso.onmicrosoft.com) are clearly
        # separate objects, not a double-count - and so each gets a stable per-object id.
        Add-EntraFinding -Severity $sev -CheckId 'privileged-roles' -Category 'Privileged Access' `
            -RuleId ('privileged-roles-permanent-{0}' -f $roleKey) -PathHash $scopeKey `
            -Title ("Permanent {0} role (not just-in-time): {1}" -f $a.Role, $who) `
            -Evidence ("{0} (object id {1}, type {2}) holds {3} as a permanent active assignment with no end date ({4}).{5}" -f $who, $a.PrincipalId, $(if ($a.PrincipalType) { $a.PrincipalType } else { 'unknown' }), $a.Role, (_ScopeText $a), $factors) `
            -WhyItMatters $why `
            -RecommendedAction $action `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure' `
            -SourceFile $src -AffectedPrincipal $a.Principal -ObjectType $a.PrincipalType -ObjectId $a.PrincipalId `
            -ResultRows @($rowsByPrincipal[[string]$a.PrincipalId]) `
            -AffectedObjectIds @($a.PrincipalId) -AffectedObjectType $a.PrincipalType -AffectedCount 1
    }

    # Redundant: principal is BOTH eligible AND permanently active for the same role. The
    # permanent side must be the principal's own assignment: a permanent role inherited
    # through a group is fixed on the group (see its own finding), not on this user.
    $byPrincipalRole = $rows | Group-Object PrincipalId, RoleTemplateId, DirectoryScopeId, AppScopeId
    foreach ($g in $byPrincipalRole) {
        $ownPermanent = @($g.Group | Where-Object { $_.State -eq 'Permanent' -and [string]$_.MemberType -ne 'Group' })
        $states = @($g.Group.State)
        if (($ownPermanent.Count -gt 0) -and ($states -contains 'Eligible')) {
            $a = $g.Group | Select-Object -First 1
            $who = if ($a.Principal) { [string]$a.Principal } else { 'unknown principal ' + [string]$a.PrincipalId }
            Add-EntraFinding -Severity 'High' -CheckId 'privileged-roles' -Category 'Privileged Access' `
                -RuleId ('privileged-roles-redundant-{0}' -f ([string]$a.RoleTemplateId).ToLowerInvariant()) -PathHash ('{0};{1}' -f $a.DirectoryScopeId, $a.AppScopeId) `
                -Title ("Permanent {0} role makes the PIM-eligible one pointless: {1}" -f $a.Role, $who) `
                -Evidence ("{0} (object id {1}) is PIM-eligible for {2} and also holds it permanently ({3}), so the role never has to be activated." -f $who, $a.PrincipalId, $a.Role, (_ScopeText $a)) `
                -WhyItMatters 'The account is set up to switch the role on just-in-time through Privileged Identity Management (PIM), but the extra permanent assignment keeps the role on all the time. PIM then only looks like it protects the role.' `
                -RecommendedAction 'Remove the permanent (active) assignment and keep the eligible one (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles > Assignments).' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure' `
                -SourceFile $src -AffectedPrincipal $a.Principal -ObjectType $a.PrincipalType -ObjectId $a.PrincipalId -ResultRows $g.Group `
                -AffectedObjectIds @($a.PrincipalId) -AffectedObjectType $a.PrincipalType -AffectedCount 1
        }
    }

    # Break-glass posture - only on a KNOWN active picture (see $activeKnown above).
    if ($permanentGA.Count -eq 0 -and $pimAvailable -and $activeKnown) {
        $gaEligible  = @($rows | Where-Object { $_.IsGA -and $_.State -eq 'Eligible' }).Count
        $gaTimeBound = @($rows | Where-Object { $_.IsGA -and $_.State -in @('TimeBound-Assigned','TimeBound-Active(JIT)') }).Count
        Add-EntraFinding -Severity 'High' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-no-permanent-breakglass' `
            -Title 'No permanent emergency-access (break-glass) Global Administrator found' `
            -Evidence ("No Global Administrator holds the role permanently. Global Administrator assignments found: {0} PIM-eligible, {1} time-bound or activated just-in-time." -f $gaEligible, $gaTimeBound) `
            -WhyItMatters 'Emergency-access (break-glass) accounts are the way back in when normal admin sign-in fails. If every Global Administrator must first activate the role through Privileged Identity Management (PIM), a problem with PIM, multifactor authentication (MFA) or federation can lock all admins out of the tenant.' `
            -RecommendedAction 'Create two cloud-only emergency-access accounts with a permanent Global Administrator assignment, protect them with phishing-resistant MFA (for example FIDO2 security keys), keep them out of Conditional Access policies that could lock them out, and alert on every sign-in.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
            -SourceFile $src
    }

    # PIM not in use / over-reliance on standing access. A failed eligibility read on a
    # P2 tenant - or on a tenant whose licence state is UNKNOWN - is a coverage gap, not
    # evidence that nobody uses PIM.
    $eligibilityGapMatters = (-not $eligibilityKnown) -and ($script:HasP2 -or -not $script:LicenseKnown)
    if ($eligibleCount -eq 0 -and $permanentPriv.Count -gt 0 -and -not $eligibilityGapMatters) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-pim-not-used' `
            -Title 'Just-in-time admin access (PIM) is not used - admin roles are permanent' `
            -Evidence ("{0} and 0 PIM-eligible assignments. Entra ID P2 detected: {1}." -f (Format-EACount -Count $permanentPriv.Count -One 'permanent admin role assignment' -Many 'permanent admin role assignments'), $script:HasP2) `
            -WhyItMatters 'Without Privileged Identity Management (PIM) every admin right is switched on all the time, so any stolen admin password can be used at once. PIM lets admins switch a role on only when needed, for a limited time and after multifactor authentication (MFA) or approval.' `
            -RecommendedAction 'License Microsoft Entra ID P2 (or Entra ID Governance) for admins, then make admin roles PIM-eligible instead of permanent (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure' `
            -SourceFile $src
    }
    if ($eligibilityGapMatters) {
        Add-EntraFinding -Severity 'Information' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-eligible-unknown' -CoverageGap `
            -Title 'PIM-eligible admin roles could not be read - list of admins is incomplete' `
            -Evidence ("Reading roleEligibilityScheduleInstances failed ({0}); Entra ID P2 detected: {1}. Eligible administrators are unknown, not zero." -f $eligibilityError, $(if ($script:LicenseKnown) { $script:HasP2 } else { 'unknown (licence read failed)' })) `
            -WhyItMatters 'People who can switch an admin role on just-in-time are still admins and need the same multifactor authentication (MFA), lifecycle and risk checks. They are missing from this result.' `
            -RecommendedAction 'Confirm RoleManagement.Read.Directory is consented (it covers the PIM schedule-instance reads), the audit account holds Global Reader, and the tenant is licensed for Microsoft Entra ID P2; then run the check again.' `
            -SourceFile $src
    }

    # Information: eligible assignments (the good posture) listed for visibility
    $eligible = @($rows | Where-Object { $_.State -eq 'Eligible' -and $_.IsPrivileged })
    if ($eligible.Count -gt 0) {
        $byRoleText = ($eligible | Group-Object Role | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) -join '; '
        Add-EntraFinding -Severity 'Information' -CheckId 'privileged-roles' -Category 'Privileged Access' -RuleId 'privileged-roles-eligible-summary' `
            -Title ((Format-EACount -Count $eligible.Count -One 'admin role assignment is' -Many 'admin role assignments are') + ' PIM-eligible (just-in-time) - good practice') `
            -Evidence ("Eligible assignments by role: {0}. These admins must switch the role on when they need it; this is the recommended setup, not a problem." -f $byRoleText) `
            -WhyItMatters 'Eligible (just-in-time) access means admin rights are only switched on for short periods, which limits how long a stolen account can misuse them.' `
            -RecommendedAction 'No action needed. Keep moving the remaining permanent admin roles to eligible.' `
            -SourceFile $src -ResultRows $eligible
    }
}
