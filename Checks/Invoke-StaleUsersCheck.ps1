<#
Stale / Inactive Users. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-StaleUsers {
    $privDays = [Math]::Min($InactiveDays, 45)   # admins held to <= 45 days
    $noSignInData = {
        param([string]$Reason)
        $s = Write-Evidence -BaseName 'stale_users' -Rows @() -Title ("Stale / Inactive Users (> {0} days)" -f $InactiveDays) -Notes @($Reason)
        Add-EntraFinding -Severity 'Information' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-signin-data-unavailable' -CoverageGap `
            -Title 'Inactive accounts could not be checked - sign-in dates are not available' `
            -Evidence $Reason `
            -WhyItMatters 'Without last-sign-in dates the audit cannot find unused or forgotten accounts, so this is a gap in the audit, not a clean result.' `
            -RecommendedAction 'Grant AuditLog.Read.All to the audit account or app (the tenant also needs Microsoft Entra ID P1 or P2) and run the check again.' -SourceFile $s
    }
    if (-not (Test-MgScope @('AuditLog.Read.All') -Quiet)) {
        & $noSignInData 'Last-sign-in data (signInActivity) needs the AuditLog.Read.All permission and a Microsoft Entra ID P1 licence; the permission is missing.'
        return
    }
    $users = Get-EAUsers -IncludeSignInActivity
    # Without signInActivity every account would look "never signed in" - a false flood.
    # Get-EAUsers only returns sign-in data when the P1 + AuditLog gate is met.
    if (-not $script:UsersCacheHasSignIn) {
        & $noSignInData ('The user list was read without signInActivity (Entra ID P1 detected: {0}; licence state known: {1}), so last-sign-in dates are not available.' -f $script:HasP1, $script:LicenseKnown)
        return
    }

    # Privileged principals get a tighter inactivity bar (escalated severity).
    # Shared assignment cache (one Graph download per run instead of a private re-fetch).
    # A THROW from the helper (e.g. the role-definition read 403s before the helper's own
    # failure tracking runs) must count as an incomplete classification, not as "no admins".
    $privIds = @{}; $privXrefError = $null
    try { foreach ($id in @((Get-EAPrivilegedUserMap).Keys)) { $privIds[[string]$id] = $true } } catch { $privXrefError = $_.Exception.Message }
    $privCoverageIncomplete = ([bool]$privXrefError -or $script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)

    $now0      = (Get-Date).ToUniversalTime()
    $cut       = $now0.AddDays(-$InactiveDays)
    $cut180    = $now0.AddDays(-180)
    $created30 = $now0.AddDays(-30)
    $privCut   = $now0.AddDays(-$privDays)

    # lastSignInDateTime / lastNonInteractiveSignInDateTime include FAILED attempts (e.g. a
    # password spray), so only lastSuccessfulSignInDateTime proves the account is used.
    # Microsoft records that date only from 1 December 2023 and did not fill in older ones:
    #  - no successful date + an attempt ON/AFTER the cut-over = no successful sign-in since
    #    then (FailedAttemptsOnly). The last use is taken as the cut-over date, or - for an
    #    account created later - as never (judged by its creation date, like NeverSeen);
    #  - no successful date + an attempt BEFORE the cut-over may have been a successful
    #    sign-in, so that date is the possible last use (PreTrackingActivity).
    # If NO account has a successful date while some have attempts, the field was not
    # returned at all: the attempt date is used (AttemptOnly) and that is reported as a gap
    # instead of flagging every account as unused.
    $succCutover = [datetime]::new(2023, 12, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $members = @($users | Where-Object { $_.UserType -ne 'Guest' })
    $withSuccess = 0; $withAttempt = 0
    foreach ($u in $members) {
        $sa = $u.SignInActivity
        if (-not $sa) { continue }
        if ($sa.LastSuccessfulSignInDateTime) { $withSuccess++ }
        elseif ($sa.LastSignInDateTime -or $sa.LastNonInteractiveSignInDateTime) { $withAttempt++ }
    }
    $successTracked = ($withSuccess -gt 0 -or $withAttempt -eq 0)

    # Collected as a single foreach expression: array += per user is O(n^2) at 50k users.
    $rows = @(foreach ($u in $members) {
        $sa = $u.SignInActivity
        $eff = $null; $conf = 'NeverSeen'; $lastAttempt = $null
        if ($sa) {
            if ($sa.LastSuccessfulSignInDateTime) {
                $eff = [datetime]$sa.LastSuccessfulSignInDateTime; $conf = 'SuccessfulSignIn'
            } elseif ($sa.LastSignInDateTime -or $sa.LastNonInteractiveSignInDateTime) {
                $lastAttempt = @($sa.LastSignInDateTime, $sa.LastNonInteractiveSignInDateTime) | Where-Object { $_ } | ForEach-Object { [datetime]$_ } | Sort-Object -Descending | Select-Object -First 1
                if (-not $successTracked) {
                    $eff = $lastAttempt; $conf = 'AttemptOnly'
                } elseif ($lastAttempt -ge $succCutover) {
                    $conf = 'FailedAttemptsOnly'
                    $eff = if ($u.CreatedDateTime -and [datetime]$u.CreatedDateTime -gt $succCutover) { $null } else { $succCutover }
                } else {
                    $eff = $lastAttempt; $conf = 'PreTrackingActivity'
                }
            }
        }
        [pscustomobject]@{
            Id                      = $u.Id
            UserPrincipalName       = $u.UserPrincipalName
            Enabled                 = $u.AccountEnabled
            Privileged              = [bool]($u.Id -and $privIds.ContainsKey([string]$u.Id))
            Created                 = $u.CreatedDateTime
            LastSuccessfulOrAttempt = $eff
            Confidence              = $conf
            LastAttempt             = $lastAttempt
        }
    })
    $notes = @(
        'LastSuccessfulOrAttempt is the last successful sign-in (lastSuccessfulSignInDateTime). Microsoft records successful sign-ins separately only from 1 December 2023 and did not fill in older dates. The last-sign-in fields also count FAILED attempts, so they are used only as described below.'
        'Confidence: SuccessfulSignIn = a successful sign-in on that date. FailedAttemptsOnly = sign-in attempts since 1 December 2023 (LastAttempt shows the latest) but no successful sign-in since then; LastSuccessfulOrAttempt is set to 2023-12-01, or left empty for accounts created later, which are then treated as never signed in. PreTrackingActivity = the last recorded sign-in is from before 1 December 2023, so it may have been successful and is used as the last use. NeverSeen = no sign-in on record.'
    )
    if (-not $successTracked) { $notes += ('No account has a successful-sign-in date, although {0} have sign-in attempts, so that field was not returned. Confidence AttemptOnly = the last sign-in attempt (possibly failed) is used as the last use.' -f $withAttempt) }
    if ($privXrefError) { $notes += ("Admin accounts could not be identified: {0}. Privileged is false for everyone." -f $privXrefError) }
    $src = Write-Evidence -BaseName 'stale_users' -Rows $rows -Title ("Stale / Inactive Users (> {0} days)" -f $InactiveDays) -Notes $notes

    if (-not $successTracked) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-successful-signin-date-unavailable' -CoverageGap `
            -Title 'Successful sign-in dates were not returned, so failed sign-in attempts may hide unused accounts' `
            -Evidence ("None of the {0} accounts with sign-in activity has a last successful sign-in date (lastSuccessfulSignInDateTime), so the last sign-in attempt was used instead. That attempt may have failed, so an unused account that someone is trying to break into can look active, and accounts with only failed attempts could not be told apart." -f $withAttempt) `
            -WhyItMatters 'Unused accounts that attackers are guessing passwords for are the ones this check most needs to find. Without the successful sign-in date some of them may be missing from the results.' `
            -RecommendedAction 'Update the Microsoft Graph PowerShell modules (Update-Module Microsoft.Graph) and run the check again.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/graph/api/resources/signinactivity' -SourceFile $src
    }

    if ($privCoverageIncomplete) {
        $what = if ($privXrefError) { ('The admin list could not be built at all ({0}), so every account was judged with the normal {1}-day rule instead of the {2}-day admin rule.' -f $privXrefError, $InactiveDays, $privDays) }
                else { ('Active or eligible role assignments, or the members of a group that holds an admin role, could not be fully read, so some admins were judged with the normal {0}-day rule instead of the {1}-day admin rule.' -f $InactiveDays, $privDays) }
        Add-EntraFinding -Severity 'Information' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-admin-classification-incomplete' -CoverageGap `
            -Title 'Unused admin accounts could not be fully identified' `
            -Evidence $what `
            -WhyItMatters 'Unused admin accounts are rated High and held to a stricter limit. Admins the audit could not recognise may be missing from that finding.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory and GroupMember.Read.All (or Directory.Read.All) to the audit account or app and run the check again.' `
            -SourceFile $src
    }

    # Never-seen admins only count once the account is older than the 30-day grace window,
    # matching the non-privileged rule - a GA created yesterday is not a dormant admin.
    # A row without a last-use date (NeverSeen, or FailedAttemptsOnly for an account created
    # after 1 December 2023) has never signed in successfully: it is judged by its creation date.
    $privStale  = @($rows | Where-Object { $_.Privileged -and $_.Enabled -and ((($null -eq $_.LastSuccessfulOrAttempt) -and $_.Created -and $_.Created -lt $created30) -or ($null -ne $_.LastSuccessfulOrAttempt -and $_.LastSuccessfulOrAttempt -lt $privCut)) })
    $never      = @($rows | Where-Object { -not $_.Privileged -and $null -eq $_.LastSuccessfulOrAttempt -and $_.Enabled -and $_.Created -and $_.Created -lt $created30 })
    $stale      = @($rows | Where-Object { -not $_.Privileged -and $null -ne $_.LastSuccessfulOrAttempt -and $_.Enabled -and $_.LastSuccessfulOrAttempt -lt $cut })
    $stale180   = @($stale | Where-Object { $_.LastSuccessfulOrAttempt -lt $cut180 })
    # Only failed attempts since 1 December 2023, however recent: recent failed-only attempts
    # are exactly the password-guessing signal. (Admins are in the High finding above.)
    $attemptOnly= @($rows | Where-Object { -not $_.Privileged -and $_.Confidence -eq 'FailedAttemptsOnly' -and $_.Enabled })
    $attemptRecent = @($attemptOnly | Where-Object { $_.LastAttempt -and $_.LastAttempt -ge $created30 }).Count

    if ($privStale.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-inactive-admins' `
            -Title ((Format-EACount -Count $privStale.Count -One 'admin account has' -Many 'admin accounts have') + (' not signed in for over {0} days (or never)' -f $privDays)) `
            -Evidence ("Enabled admin accounts with no successful sign-in in the last {0} days, or never (accounts older than 30 days): {1}. First {2}: {3}" -f $privDays, $privStale.Count, [Math]::Min(10, $privStale.Count), (($privStale | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'An admin account that nobody uses still has its admin rights. Nobody notices if someone else signs in with it, which makes it an ideal target for attackers.' `
            -RecommendedAction 'Confirm whether each admin role is still needed; remove it or make it PIM-eligible (just-in-time), or disable the account. Investigate any admin account that has never signed in successfully.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
            -SourceFile $src -ResultRows @($privStale | Select-Object UserPrincipalName,LastSuccessfulOrAttempt,Confidence,LastAttempt) `
            -AffectedObjectIds @($privStale | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $privStale.Count -PopulationLabel 'enabled member accounts with recorded activity or creation dates'
    }
    if ($stale.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-inactive-accounts' `
            -Title ((Format-EACount -Count $stale.Count -One 'enabled account has' -Many 'enabled accounts have') + (' not signed in for over {0} days' -f $InactiveDays)) `
            -Evidence ("{0} no successful sign-in for over {1} days ({2} of them for over 180 days)." -f (Format-EACount -Count $stale.Count -One 'enabled non-admin account has' -Many 'enabled non-admin accounts have'), $InactiveDays, $stale180.Count) `
            -WhyItMatters 'Unused but enabled accounts are easy targets for password-guessing attacks, and a break-in is unlikely to be noticed because nobody uses the account.' `
            -RecommendedAction 'Confirm with the owners, disable accounts that are no longer needed, and delete them after your retention period.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
            -SourceFile $src -ResultRows @($stale | Select-Object UserPrincipalName,LastSuccessfulOrAttempt,Confidence,LastAttempt | Sort-Object LastSuccessfulOrAttempt) `
            -AffectedObjectIds @($stale | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $stale.Count -PopulationLabel 'enabled member accounts with recorded activity or creation dates'
    }
    if ($never.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-never-signed-in' `
            -Title ((Format-EACount -Count $never.Count -One 'enabled account has' -Many 'enabled accounts have') + ' never signed in successfully') `
            -Evidence ("{0} no successful sign-in on record{1}." -f (Format-EACount -Count $never.Count -One 'enabled non-admin account older than 30 days has' -Many 'enabled non-admin accounts older than 30 days have'), $(if (@($never | Where-Object { $_.Confidence -eq 'FailedAttemptsOnly' }).Count -gt 0) { (' ({0} only failed sign-in attempts)' -f (Format-EACount -Count @($never | Where-Object { $_.Confidence -eq 'FailedAttemptsOnly' }).Count -One 'of them shows' -Many 'of them show')) } else { '' })) `
            -WhyItMatters 'Accounts that were never used are often provisioning mistakes or forgotten accounts, and can be taken over and used as a hidden way in.' `
            -RecommendedAction 'Check whether each account is still needed; disable and remove the ones that are not.' `
            -SourceFile $src -ResultRows @($never | Select-Object UserPrincipalName,Created,Confidence,LastAttempt) `
            -AffectedObjectIds @($never | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $never.Count -PopulationLabel 'enabled member accounts with recorded activity or creation dates'
    }
    if ($attemptOnly.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'staleusers' -Category 'Identity Hygiene' -RuleId 'staleusers-attempts-only' `
            -Title (Format-EACount -Count $attemptOnly.Count -One 'unused account shows only failed sign-in attempts' -Many 'unused accounts show only failed sign-in attempts') `
            -Evidence ("{0} sign-in attempts since 1 December 2023 (when Microsoft began recording successful sign-ins separately) but no successful sign-in since then - possible password-guessing on otherwise unused accounts. The latest attempt was in the last 30 days for {1} of them." -f (Format-EACount -Count $attemptOnly.Count -One 'enabled non-admin account has' -Many 'enabled non-admin accounts have'), $attemptRecent) `
            -WhyItMatters 'Failed attempts can make an unused account look active, and they may mean someone is trying to guess its password.' `
            -RecommendedAction 'Treat these accounts as unused (disable them if not needed) and review their sign-in logs for attack attempts (Entra admin center > Monitoring & health > Sign-in logs).' `
            -SourceFile $src -ResultRows @($attemptOnly | Sort-Object LastAttempt -Descending | Select-Object UserPrincipalName,LastAttempt,Created,Confidence) `
            -AffectedObjectIds @($attemptOnly | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $attemptOnly.Count -PopulationLabel 'enabled member accounts with recorded activity or creation dates'
    }
}
