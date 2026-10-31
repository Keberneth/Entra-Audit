<#
Emergency-Access (Break-Glass) Health. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-BreakGlass {
    # signInActivity is OPTIONAL enrichment here: when the users+signInActivity read fails
    # (throttling/timeout on a large directory, or an app-only token without the AuditLog
    # permission) Get-EAUsers -IncludeSignInActivity throws. Degrade to the plain user list so
    # every other emergency-access control is still validated, and report the sign-in test as
    # unknown. (Get-EAUsers remembers the failure, so the retry below reads the base set once.)
    # A failure of the BASE user read is not a sign-in problem - rethrow it so the check is
    # recorded as Error/Skipped instead of retrying the same read.
    $signinFetchError = $null
    try { $users = Get-EAUsers -IncludeSignInActivity }
    catch {
        if (-not $script:SignInFetchError) { throw }
        $signinFetchError = [string]$script:SignInFetchError.Message
        $users = Get-EAUsers
    }
    $byUpn = @{}; foreach ($u in $users) { if ($u.UserPrincipalName) { $byUpn[$u.UserPrincipalName.ToLowerInvariant()] = $u } }
    $bgDoc = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access'

    # PERMANENT Global Administrators, and every user's privileged role-template ids (active AND
    # eligible) - eligible roles must feed the CA-applicability check because an eligible-only
    # role does not appear in transitiveMemberOf. A break-glass account must hold GA as a
    # PERMANENT standing assignment (not a time-bound / JIT-activated one), so $gaIds is keyed
    # on ActivationModel -eq 'Permanent', not merely "currently active".
    $gaIds = @{}
    $privRolesByUser = @{}
    $gaExpandFailed = $false; $gaExpandFailedGroups = @()
    # A failed role-assignment read (including the role-definition read it depends on) makes
    # Global Administrator status UNKNOWN; every other emergency-access control is still checked.
    $privAssignments = @(); $privAssignError = $null
    try { $privAssignments = @(Get-EAPrivAssignments) } catch { $privAssignError = $_.Exception.Message }
    foreach ($a in $privAssignments) {
        if ($a.IsGA -and $a.ActivationModel -eq 'Permanent' -and $a.PrincipalId) {
            $gaIds[$a.PrincipalId] = $true
            # GA held via a role-assignable GROUP is still permanent standing GA for
            # every member - expand so a break-glass account whose GA comes through a
            # group is not falsely reported as "not a permanent Global Administrator".
            # A FAILED expansion makes GA-via-group status UNKNOWN, not "not GA".
            # (Shared per-run member cache: the privileged-user map expands the same groups.)
            if ($a.PrincipalType -eq 'group') {
                try { foreach ($m in @(Get-EAGroupTransitiveMember -GroupId ([string]$a.PrincipalId))) { if ($m.Id) { $gaIds[$m.Id] = $true } } }
                catch { $gaExpandFailed = $true; $gaExpandFailedGroups += ($a.PrincipalName ?? $a.PrincipalId) }
            }
        }
        if ($a.PrincipalId -and $a.PrincipalType -eq 'user' -and $a.RoleTemplateId) {
            if (-not $privRolesByUser.ContainsKey($a.PrincipalId)) { $privRolesByUser[$a.PrincipalId] = New-Object System.Collections.Generic.HashSet[string] }
            [void]$privRolesByUser[$a.PrincipalId].Add($a.RoleTemplateId)
        }
    }
    # Merge group-expanded and eligible assignments so role-targeted CA applicability for
    # a designated account is not understated. A failed/incomplete merge is tracked: a
    # role-targeted CA policy could then apply without showing in the CA columns.
    $privRolesKnown = $true; $privRolesError = $null
    try {
        $effectivePrivUsers = Get-EAPrivilegedUserMap
        foreach ($uid in $effectivePrivUsers.Keys) {
            if (-not $privRolesByUser.ContainsKey($uid)) { $privRolesByUser[$uid] = New-Object System.Collections.Generic.HashSet[string] }
            # Plain foreach (no @()): the map values are List objects created with New-Object.
            foreach ($pa in $effectivePrivUsers[$uid]) { if ($pa.RoleTemplateId) { [void]$privRolesByUser[$uid].Add([string]$pa.RoleTemplateId) } }
        }
        if ($script:PrivilegedUserMapIncomplete) { $privRolesKnown = $false }
    } catch { $privRolesKnown = $false; $privRolesError = $_.Exception.Message }
    # When the assignment fetch itself failed, GA status is UNKNOWN - report that
    # instead of a false "not a permanent Global Administrator" Critical.
    $gaKnown = -not ($script:PrivAssignmentsFailed -or $privAssignError)
    $gaUnknownWhy = if ($privAssignError) { $privAssignError }
                    elseif ($script:PrivAssignmentsError) { [string]$script:PrivAssignmentsError }
                    elseif ($script:PrivActiveFetchError) { [string]$script:PrivActiveFetchError }
                    else { $null }

    # Conditional Access lockout evaluation context. A failed policy read means the CA
    # exposure is UNKNOWN - it must not silently evaluate as "no policies apply".
    $caKnown = $true; $caError = $null
    $enabledCa = @(); try { $enabledCa = @(Get-EACaPolicies | Where-Object { $_.State -eq 'enabled' }) } catch { $caKnown = $false; $caError = $_.Exception.Message }
    if (@($enabledCa | Where-Object { -not (Test-CaPolicyStrengthKnown $_) }).Count -gt 0) {
        $caKnown = $false
        $caError = 'One or more custom authentication strength definitions could not be assessed; MFA lockout coverage is unknown.'
    }
    # Sign-in data is known only when the cached user set really carries signInActivity (P1 +
    # AuditLog.Read.All AND a successful read) - otherwise the test status is unknown, never
    # "no successful sign-in in 90 days".
    $signinKnown = [bool]$script:UsersCacheHasSignIn

    # (CA applicability uses the shared Get-EAUserScopeIds / Test-CaPolicyAppliesToUser helpers.)
    $bg = Normalize-StringList -Values $BreakGlassUpns

    if ($bg.Count -eq 0) {
        # Nothing to validate - but still write the evidence file so the finding has a source
        # and the raw-data index shows the check ran.
        $src0 = Write-Evidence -BaseName 'break_glass' -Rows @() -Title 'Emergency-Access (Break-Glass) Account Health' `
            -Notes @('No accounts were passed with -BreakGlassUpns, so no emergency-access account could be validated.')
        # This is a visibility gap (the audit was not told which accounts to test), not proof
        # that the tenant lacks emergency-access accounts - hence CoverageGap at High.
        Add-EntraFinding -Severity 'High' -CheckId 'breakglass' -Category 'Privileged Access' `
            -Title 'Emergency-access (break-glass) accounts were not checked because none were named' `
            -Evidence 'The audit was run without -BreakGlassUpns, so it does not know which accounts are the emergency-access accounts. Example: -BreakGlassUpns "bg1@tenant.onmicrosoft.com;bg2@tenant.onmicrosoft.com".' `
            -WhyItMatters 'Microsoft recommends two cloud-only emergency-access Global Administrator accounts so you can still get in if MFA, federation or Privileged Identity Management (PIM) breaks. Without their names the audit cannot confirm they exist and work.' `
            -RecommendedAction 'Create two cloud-only break-glass Global Administrator accounts on the .onmicrosoft.com domain (if you do not have them), then re-run the audit with -BreakGlassUpns naming both.' `
            -SourceFile $src0 -RuleId 'breakglass-none-designated' -ObjectType 'tenant' -DocumentationUrl $bgDoc -CoverageGap
        return
    }
    # Per-account findings are QUEUED and only emitted after Write-Evidence, so every
    # one of them links to the break_glass evidence file (which can only be written
    # once the loop has built the rows).
    $pending = New-Object System.Collections.Generic.List[object]
    if ($bg.Count -lt 2) {
        $pending.Add(@{ Severity='Critical'; RuleId='breakglass-fewer-than-two'; ObjectType='tenant'
            Title='Fewer than two emergency-access (break-glass) accounts were named'
            Evidence=("Only {0} account was passed in -BreakGlassUpns: {1}." -f $bg.Count, ($bg -join ', '))
            WhyItMatters='With a single emergency-access account there is no backup: if that one account is lost, locked or broken, nobody may be able to get back into the tenant during an outage.'
            RecommendedAction='Keep at least two cloud-only emergency-access Global Administrator accounts, and name both with -BreakGlassUpns.' }) | Out-Null
    }

    $rows = @()
    foreach ($upn in $bg) {
        $u = $byUpn[$upn.ToLowerInvariant()]
        if (-not $u) {
            $pending.Add(@{ Severity='High'; AffectedPrincipal=$upn; RuleId='breakglass-account-not-found'; ObjectType='user'; ObjectId=$upn
                Title=("Named break-glass account was not found in the directory: {0}" -f $upn)
                Evidence=("The UPN {0} passed to -BreakGlassUpns does not match any user in the tenant." -f $upn)
                WhyItMatters='If the emergency-access account you rely on does not exist (or its name is wrong), you have no tested way back in during a lockout.'
                RecommendedAction='Check the spelling of the UPN passed to -BreakGlassUpns. If the account is really missing, create it: cloud-only, on the .onmicrosoft.com domain, with permanent Global Administrator.' }) | Out-Null
            continue
        }
        $enabled   = [bool]$u.AccountEnabled
        $isGA      = [bool]($u.Id -and $gaIds.ContainsKey($u.Id))
        $cloudOnly = -not [bool]$u.OnPremisesSyncEnabled
        $onmsft    = ($u.UserPrincipalName -like '*.onmicrosoft.com')
        $licenseCount = @($u.AssignedLicenses | Where-Object { $_ }).Count
        $licensed  = ($licenseCount -gt 0)
        $lastSucc  = $null
        if ($signinKnown -and $u.SignInActivity -and $u.SignInActivity.LastSuccessfulSignInDateTime) { $lastSucc = [datetime]$u.SignInActivity.LastSuccessfulSignInDateTime }
        $objKeys = @{ AffectedPrincipal=$u.UserPrincipalName; ObjectType='user'; ObjectId=$(if ($u.Id) { [string]$u.Id } else { $u.UserPrincipalName }) }

        # Which enabled blocking / MFA-requiring CA policies apply, and at what APP scope?
        # A policy that only targets a single workload app is far less of a lockout risk than
        # one covering all cloud apps (which includes the admin portals / Graph / Azure mgmt).
        $scope = Get-EAUserScopeIds $u.Id
        # An unreadable membership hides exclusion groups: evaluating CA with an empty group
        # set would report a correctly excluded account as locked out. Report unknown instead.
        $scopeKnown = [bool]$scope.Known
        $caRowKnown = ($caKnown -and $scopeKnown)
        # Copy the cached role set before adding eligible roles - mutating the shared cache
        # entry would pollute it for any later consumer of this user's scope.
        $bgRoles = [System.Collections.Generic.HashSet[string]]::new($scope.Roles)
        if ($u.Id -and $privRolesByUser.ContainsKey($u.Id)) { foreach ($rt in $privRolesByUser[$u.Id]) { [void]$bgRoles.Add($rt) } }
        $blockAll = @(); $blockScoped = @(); $mfaAll = @(); $mfaScoped = @(); $legacyOnlyPolicies = @()
        foreach ($p in $(if ($scopeKnown) { $enabledCa } else { @() })) {
            if (-not (Test-CaPolicyAppliesToUser -Policy $p -UserId $u.Id -GroupIds $scope.Groups -RoleTemplateIds $bgRoles)) { continue }
            $allApps = Test-CaPolicyTargetsAllApps $p
            $isBlock = (@($p.GrantControls.BuiltInControls) -contains 'block')
            if (-not $isBlock -and -not (Test-CaPolicyRequiresMfaOrStrength $p)) { continue }
            # Only a policy that applies to every sign-in to all apps can lock the account out
            # of the admin portals. A policy limited to legacy clients (Exchange ActiveSync /
            # other) cannot affect browser or modern sign-in at all, and one limited by
            # location, platform, device, risk or client type applies only in some situations.
            $clients = @($p.Conditions.ClientAppTypes | Where-Object { $_ })
            $legacyOnly = ($clients.Count -gt 0 -and $clients -notcontains 'all' -and $clients -notcontains 'browser' -and $clients -notcontains 'mobileAppsAndDesktopClients')
            if ($legacyOnly) { $legacyOnlyPolicies += $p.DisplayName; continue }
            # The admin portals are reached in a browser, so a policy that covers browsers
            # (or every client) and has no other condition is the lockout case.
            $coversBrowser = ($clients.Count -eq 0 -or $clients -contains 'all' -or $clients -contains 'browser')
            $narrowOther = Test-CaPolicyHasNarrowingConditions $p -Ignore @('ClientApps')
            $limits = @()
            if (-not $allApps) { $limits += 'specific apps only' }
            if (-not $coversBrowser) { $limits += 'desktop and mobile apps only, not the browser' }
            if ($narrowOther) { $limits += 'only in some situations: location, platform, device, risk or client app' }
            $conditionText = if ($limits.Count -gt 0) { ' ({0})' -f ($limits -join '; ') } else { '' }
            $everySignIn = ($allApps -and $coversBrowser -and -not $narrowOther)
            if ($isBlock) {
                if ($everySignIn) { $blockAll += $p.DisplayName } else { $blockScoped += ('{0}{1}' -f $p.DisplayName, $conditionText) }
            } else {
                if ($everySignIn) { $mfaAll += $p.DisplayName } else { $mfaScoped += ('{0}{1}' -f $p.DisplayName, $conditionText) }
            }
        }

        $rows += [pscustomobject]@{
            Account=$u.UserPrincipalName; Enabled=$enabled
            GlobalAdmin=$(if (-not $gaKnown) { 'unknown' } elseif ($isGA) { $isGA } elseif ($gaExpandFailed) { 'unknown' } else { $isGA })
            CloudOnly=$cloudOnly; OnMicrosoftDomain=$onmsft
            Licensed=$licensed; LicenseCount=$licenseCount
            LastSuccessfulSignIn=$(if ($signinKnown) { $lastSucc } else { 'unknown' })
            BlockAllApps=$(if ($caRowKnown) { $blockAll -join '; ' } else { 'unknown' }); BlockScoped=$(if ($caRowKnown) { $blockScoped -join '; ' } else { 'unknown' })
            MfaAllApps=$(if ($caRowKnown) { $mfaAll -join '; ' } else { 'unknown' }); MfaScoped=$(if ($caRowKnown) { $mfaScoped -join '; ' } else { 'unknown' })
            LegacyClientsOnly=$(if ($caRowKnown) { $legacyOnlyPolicies -join '; ' } else { 'unknown' })
            UserId=$u.Id
        }
        if ($caKnown -and -not $scopeKnown) {
            $pending.Add(@{ Severity='Medium'; CoverageGap=$true; RuleId='breakglass-ca-membership-unknown'
                Title=("Conditional Access lockout risk is unknown for break-glass account: {0}" -f $u.UserPrincipalName)
                Evidence='The account''s group and role memberships could not be read, so exclusion groups are invisible. The Conditional Access columns in the evidence file show "unknown", not clean.'
                WhyItMatters='Conditional Access (CA) policies that block sign-in or demand MFA can lock an emergency-access account out during an outage. Without its memberships the audit cannot tell whether the account is excluded.'
                RecommendedAction='Make sure the audit identity can read group memberships (GroupMember.Read.All or Directory.Read.All), or retry if the error was temporary, then re-run the breakglass check.' } + $objKeys) | Out-Null
        }

        if (-not $enabled) {
            $pending.Add(@{ Severity='Critical'; RuleId='breakglass-account-disabled'
                Title=("Break-glass account is disabled: {0}" -f $u.UserPrincipalName)
                Evidence='accountEnabled = false on the emergency-access account.'
                WhyItMatters='A disabled emergency-access account cannot be used to get back into the tenant, so the safety net fails exactly when it is needed.'
                RecommendedAction='Enable the account (Entra admin center > Users), then test that it can sign in.' } + $objKeys) | Out-Null
        }
        if ($blockAll.Count -gt 0) {
            $pending.Add(@{ Severity='Critical'; RuleId='breakglass-ca-block-all-apps'
                Title=("Break-glass account is blocked by a Conditional Access policy for all apps: {0}" -f $u.UserPrincipalName)
                Evidence=("In scope of (and not excluded from) {0} to every sign-in to all cloud apps, with no location, platform, device, risk or client-app condition: {1}" -f $(if ($blockAll.Count -eq 1) { 'a blocking policy that applies' } else { 'blocking policies that apply' }), ($blockAll -join '; '))
                WhyItMatters='A Conditional Access (CA) policy that blocks all cloud apps also blocks the admin portals, so the emergency-access account would be locked out during the very incident it exists for.'
                RecommendedAction='Exclude the break-glass accounts (directly, or through a dedicated exclusion group) from every blocking policy in Entra admin center > Entra ID > Conditional Access.' } + $objKeys) | Out-Null
        }
        if ($blockScoped.Count -gt 0) {
            $pending.Add(@{ Severity='Medium'; RuleId='breakglass-ca-block-scoped'
                Title=("Break-glass account is blocked from some apps or in some situations by Conditional Access: {0}" -f $u.UserPrincipalName)
                Evidence=("In scope of {0} limited to specific apps or to some situations (the condition is named in brackets): {1}" -f $(if ($blockScoped.Count -eq 1) { 'a blocking policy' } else { 'blocking policies' }), ($blockScoped -join '; '))
                WhyItMatters='A Conditional Access (CA) block that covers only some apps, or applies only in some situations (for example outside named locations or on some platforms), does not always stop the account. It can still lock the account out if the emergency happens in exactly that situation, for example when the account has to be used from another place.'
                RecommendedAction='Check whether the break-glass account could need these apps or situations during recovery (for example signing in from another country); exclude it from the policy if so.' } + $objKeys) | Out-Null
        }
        if ($mfaAll.Count -gt 0) {
            $pending.Add(@{ Severity='High'; RuleId='breakglass-ca-mfa-all-apps'
                Title=("Break-glass account must pass MFA for all apps under Conditional Access: {0}" -f $u.UserPrincipalName)
                Evidence=("In scope of (and not excluded from) {0} to every sign-in to all cloud apps: {1}" -f $(if ($mfaAll.Count -eq 1) { 'an MFA / authentication-strength policy that applies' } else { 'MFA / authentication-strength policies that apply' }), ($mfaAll -join '; '))
                WhyItMatters='If the emergency-access account has to pass multifactor authentication (MFA) for every app and cannot do so during an outage (for example the MFA device is lost or the method is unavailable), it is locked out when it is needed most.'
                RecommendedAction='Either exclude the break-glass accounts from MFA-requiring Conditional Access policies, or register a resilient phishing-resistant method (such as a FIDO2 security key) on each of them; monitor and alert on their sign-ins.' } + $objKeys) | Out-Null
        }
        if ($mfaScoped.Count -gt 0) {
            $pending.Add(@{ Severity='Low'; RuleId='breakglass-ca-mfa-scoped'
                Title=("Break-glass account must pass MFA for some apps or in some situations under Conditional Access: {0}" -f $u.UserPrincipalName)
                Evidence=("In scope of {0} limited to specific apps or to some situations (the condition is named in brackets): {1}" -f $(if ($mfaScoped.Count -eq 1) { 'an MFA / authentication-strength policy' } else { 'MFA / authentication-strength policies' }), ($mfaScoped -join '; '))
                WhyItMatters='An MFA requirement on a few specific apps, or only in some situations, is a small lockout risk compared with one that covers every sign-in to all apps.'
                RecommendedAction='Confirm the break-glass account does not need those apps during recovery, or exclude it from the policy.' } + $objKeys) | Out-Null
        }

        if ($gaKnown -and -not $isGA) {
            if ($gaExpandFailed) {
                # A GA-granting group could not be expanded - the account may hold GA
                # through it, so "not a GA" cannot be concluded (a false Critical).
                $pending.Add(@{ Severity='Medium'; CoverageGap=$true; RuleId='breakglass-ga-group-expansion-unknown'
                    Title=("Global Administrator status is unknown for break-glass account: {0}" -f $u.UserPrincipalName)
                    Evidence=("Members of {0} could not be read ({1}), so whether this account holds permanent Global Administrator through a group is unknown." -f $(if (@($gaExpandFailedGroups | Select-Object -Unique).Count -eq 1) { 'a Global-Administrator-granting group' } else { 'Global-Administrator-granting groups' }), ((@($gaExpandFailedGroups | Select-Object -Unique | Select-Object -First 5)) -join ', '))
                    WhyItMatters='An emergency-access account must hold permanent Global Administrator. The members of a group that grants that role could not be read, so this could neither be confirmed nor ruled out.'
                    RecommendedAction='Grant the audit identity Group.Read.All and Member.Read.Hidden (read-only) and re-run, or check the account''s role assignments manually in Entra admin center > Roles and administrators.' } + $objKeys) | Out-Null
            } else {
                $pending.Add(@{ Severity='Critical'; RuleId='breakglass-not-permanent-ga'
                    Title=("Break-glass account is not a permanent Global Administrator: {0}" -f $u.UserPrincipalName)
                    Evidence='The account does not hold Global Administrator as a PERMANENT (standing) assignment - directly or through a role-assignable group. An eligible, time-bound or just-in-time activated Global Administrator assignment does not count.'
                    WhyItMatters='An emergency-access account must already be Global Administrator so it can fix the tenant when all other admin access fails. Rights that first have to be activated in Privileged Identity Management (PIM) may not work during an outage.'
                    RecommendedAction='Give the account a permanent (active, no end date) Global Administrator assignment in Entra admin center > Roles and administrators.' } + $objKeys) | Out-Null
            }
        }
        if (-not $cloudOnly) {
            $pending.Add(@{ Severity='Critical'; RuleId='breakglass-not-cloud-only'
                Title=("Break-glass account is synced from on-premises AD, not cloud-only: {0}" -f $u.UserPrincipalName)
                Evidence='onPremisesSyncEnabled = true on the emergency-access account.'
                WhyItMatters='A synced account depends on on-premises Active Directory (AD) and directory sync or federation - exactly the systems that may be down during an emergency.'
                RecommendedAction='Create a new cloud-only break-glass account (not synced from AD) and retire this one.' } + $objKeys) | Out-Null
        }
        if (-not $onmsft) {
            $upnDomain = if ($u.UserPrincipalName -match '@(.+)$') { $matches[1] } else { 'unknown' }
            $pending.Add(@{ Severity='High'; RuleId='breakglass-not-onmicrosoft'
                Title=("Break-glass account does not use the .onmicrosoft.com domain: {0}" -f $u.UserPrincipalName)
                Evidence=("UPN domain: {0}. Emergency-access accounts should use the tenant's built-in .onmicrosoft.com domain." -f $upnDomain)
                WhyItMatters='A custom or federated domain can stop working (for example when federation breaks); the built-in .onmicrosoft.com domain always works.'
                RecommendedAction='Change the account''s sign-in name (UPN) to the tenant''s .onmicrosoft.com domain.' } + $objKeys) | Out-Null
        }
        if (-not $signinKnown) {
            $signinWhy = if ($signinFetchError) { ("the users + signInActivity read failed: {0}" -f $signinFetchError) }
                         elseif (-not $script:HasP1) { 'signInActivity needs Entra ID P1 or higher, which was not detected' }
                         else { 'signInActivity needs AuditLog.Read.All, which was not granted' }
            $signinFix = if ($signinFetchError) { 'Re-run the audit (the failure may be temporary throttling); if it keeps failing, confirm AuditLog.Read.All is granted to the audit identity.' }
                         else { 'Grant AuditLog.Read.All and make sure the tenant has Entra ID P1 or higher, then re-run the breakglass check.' }
            $pending.Add(@{ Severity='Medium'; CoverageGap=$true; RuleId='breakglass-signin-unknown'
                Title=("Last test sign-in is unknown for break-glass account: {0}" -f $u.UserPrincipalName)
                Evidence=("No sign-in data is available because {0}. The test status is unknown, not ""never tested""." -f $signinWhy)
                WhyItMatters='Emergency-access accounts should be test-signed-in regularly. Without sign-in data the audit cannot tell when this account last worked, so it is reported as unknown rather than as a failure.'
                RecommendedAction=$signinFix } + $objKeys) | Out-Null
        }
        elseif ($null -eq $lastSucc -or $lastSucc -lt (Get-Date).ToUniversalTime().AddDays(-90)) {
            $pending.Add(@{ Severity='Medium'; RuleId='breakglass-not-tested-90d'; VerificationType='ManualTest'
                VerificationSteps='Complete an approved emergency-access sign-in test, confirm access works and the monitoring alert is received, then record the tester, date and result. A recent sign-in alone does not prove the alert or emergency procedure worked.'
                Title=("Break-glass account has not signed in successfully for 90+ days: {0}" -f $u.UserPrincipalName)
                Evidence=("Last successful sign-in: {0}" -f ($lastSucc ?? 'none on record'))
                WhyItMatters='Emergency-access accounts must be tested regularly (Microsoft recommends at least every 90 days) so you know the password, sign-in method and alerting still work before a real emergency.'
                RecommendedAction='Run a documented break-glass test: sign in with the account, confirm the sign-in alert fires, and record the date and who did it.' } + $objKeys) | Out-Null
        }
        if ($licensed) {
            $pending.Add(@{ Severity='Low'; RuleId='breakglass-licensed'
                Title=("Break-glass account has licences assigned like a normal user: {0}" -f $u.UserPrincipalName)
                Evidence=("{0} assigned to the emergency-access account." -f (Format-EACount -Count $licenseCount -One 'licence' -Many 'licences'))
                WhyItMatters='Licences switch on a mailbox and other services the emergency account does not need, which adds ways to attack or misuse it.'
                RecommendedAction='Remove every licence the break-glass account does not need for sign-in and logging.' } + $objKeys) | Out-Null
        }
    }
    $bgNotes = @()
    if (-not $signinKnown) { $bgNotes += ('LastSuccessfulSignIn = unknown: sign-in activity was not available for this run.' + $(if ($signinFetchError) { " ($signinFetchError)" } else { '' })) }
    if (-not $caKnown) { $bgNotes += ("Conditional Access columns = unknown: policies could not be read ({0})." -f $caError) }
    if (-not $gaKnown) { $bgNotes += ('GlobalAdmin = unknown: the admin role assignment list could not be read.' + $(if ($gaUnknownWhy) { " ($gaUnknownWhy)" } else { '' })) }
    $src = Write-Evidence -BaseName 'break_glass' -Rows $rows -Title 'Emergency-Access (Break-Glass) Account Health' -Notes $bgNotes

    # Coverage gaps discovered before/during the loop are reported once, tenant-level.
    if ($rows.Count -gt 0 -and -not $caKnown) {
        $pending.Add(@{ Severity='Medium'; CoverageGap=$true; RuleId='breakglass-ca-unknown'; ObjectType='tenant'
            Title='Conditional Access lockout risk is unknown for the break-glass accounts'
            Evidence=("Conditional Access policies could not be read ({0}), so the Conditional Access columns in the evidence file are ""unknown"", not clean." -f ($caError ?? 'no detail'))
            WhyItMatters='Conditional Access (CA) policies that block sign-in or require MFA can lock emergency-access accounts out. Without the policies the audit cannot check this.'
            RecommendedAction='Grant Policy.Read.All (or retry if the error was temporary) and re-run the breakglass check.' }) | Out-Null
    }
    if ($rows.Count -gt 0 -and -not $gaKnown) {
        $pending.Add(@{ Severity='Medium'; CoverageGap=$true; RuleId='breakglass-ga-assignments-unknown'; ObjectType='tenant'
            Title='Global Administrator status is unknown for the break-glass accounts'
            Evidence=('The list of admin role assignments could not be read, so the audit cannot tell whether the named accounts hold permanent Global Administrator.' + $(if ($gaUnknownWhy) { (' Error: {0}' -f $gaUnknownWhy) } else { '' }))
            WhyItMatters='Permanent Global Administrator is what makes an emergency-access account useful; without the role assignment data this cannot be confirmed.'
            RecommendedAction='Grant RoleManagement.Read.Directory (or retry if the error was temporary) and re-run the breakglass check.' }) | Out-Null
    }
    # Role-targeted CA policies can apply to a break-glass account through eligible or
    # group-based roles; when those could not be fully read, such a policy may be missing
    # from the CA columns above.
    $roleTargetedCa = @($enabledCa | Where-Object { @($_.Conditions.Users.IncludeRoles | Where-Object { $_ -and $_ -ne 'None' }).Count -gt 0 })
    if ($rows.Count -gt 0 -and $caKnown -and -not $privRolesKnown -and $roleTargetedCa.Count -gt 0) {
        $roleWhy = if ($privRolesError) { (" ({0})" -f $privRolesError) } else { '' }
        $pending.Add(@{ Severity='Low'; CoverageGap=$true; RuleId='breakglass-ca-role-scope-unknown'; ObjectType='tenant'
            Title='Role-targeted Conditional Access for the break-glass accounts could not be fully checked'
            Evidence=("Eligible or group-based admin role assignments could not be fully read{0}, and {1} directory roles: {2}. A policy that applies through such a role may be missing from the CA columns." -f $roleWhy, (Format-EACount -Count $roleTargetedCa.Count -One 'enabled Conditional Access policy targets' -Many 'enabled Conditional Access policies target'), ((@($roleTargetedCa | Select-Object -First 5 | ForEach-Object { $_.DisplayName })) -join '; '))
            WhyItMatters='A Conditional Access (CA) policy aimed at admin roles also applies to a break-glass account that holds those roles, so incomplete role data can hide a lockout risk.'
            RecommendedAction='Restore read access to role eligibility and group membership (RoleManagement.Read.Directory, Group.Read.All; Entra ID P2 for eligibility) and re-run the breakglass check.' }) | Out-Null
    }
    foreach ($p in $pending) { Add-EntraFinding -CheckId 'breakglass' -Category 'Privileged Access' -SourceFile $src -DocumentationUrl $bgDoc @p }

    if ($script:Findings.Where({$_.CheckId -eq 'breakglass'}).Count -eq 0 -and $rows.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'breakglass' -Category 'Privileged Access' `
            -Title 'Emergency-access (break-glass) accounts pass every check' `
            -Evidence ("{0} checked: enabled, cloud-only, on .onmicrosoft.com, permanent Global Administrator, not locked out by Conditional Access, no licences, and signed in within the last 90 days." -f (Format-EACount -Count $rows.Count -One 'account' -Many 'accounts')) `
            -WhyItMatters 'Working emergency-access accounts let you get back into the tenant if normal admin sign-in breaks.' `
            -RecommendedAction 'Keep testing the accounts at least every 90 days and alert on every sign-in.' `
            -SourceFile $src -ResultRows $rows -RuleId 'breakglass-baseline' -ObjectType 'tenant' -DocumentationUrl $bgDoc
    }
}
