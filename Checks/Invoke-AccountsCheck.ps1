<#
Account Hygiene. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-Accounts {
    $users = @(Get-EAUsers)
    # MFA capability decides whether the non-expiring-password finding is High. A failed
    # registration read must not quietly downgrade it to Medium (see the coverage finding).
    $regError = $null
    try { Get-EARegistrationDetails | Out-Null } catch { $regError = $_.Exception.Message }

    # Licensed = at least one real assignedLicenses entry (@($null).Count is 1, so filter first).
    $disabledLicensed = @($users | Where-Object { -not $_.AccountEnabled -and @($_.AssignedLicenses | Where-Object { $_ }).Count -gt 0 })
    # Entra Connect sets DisablePasswordExpiration on every synced user by default (expiry is
    # governed by on-prem AD), so only enabled cloud-only accounts count toward the finding.
    $neverExpireAll   = @($users | Where-Object { $_.PasswordPolicies -and $_.PasswordPolicies -match 'DisablePasswordExpiration' })
    $neverExpire      = @($neverExpireAll | Where-Object { $_.AccountEnabled -and -not $_.OnPremisesSyncEnabled })
    $neverExpireSkipped = $neverExpireAll.Count - $neverExpire.Count
    $weakPwPolicy     = @($users | Where-Object { $_.PasswordPolicies -and $_.PasswordPolicies -match 'DisableStrongPassword' })
    $rows = $users | Select-Object UserPrincipalName, DisplayName, AccountEnabled, UserType,
        @{n='Licensed';e={ @($_.AssignedLicenses | Where-Object { $_ }).Count -gt 0 }},
        @{n='PasswordPolicies';e={ $_.PasswordPolicies }},
        @{n='Synced';e={ [bool]$_.OnPremisesSyncEnabled }}, CreatedDateTime

    # --- Disabled accounts left in the directory (hygiene) ---
    # A disabled account with no successful sign-in for more than -DisabledAccountDays days
    # (or none on record and created that long ago) is a forgotten account. How long it has
    # been unused comes from signInActivity, which Get-EAUsers includes only when
    # AuditLog.Read.All and Microsoft Entra ID P1/P2 are available. This check is not
    # P1-gated, so without that data the age is UNKNOWN: the disabled accounts are still
    # counted and listed, and a coverage gap is raised instead of a guess.
    $disabledDays = 180
    if ($null -ne $DisabledAccountDays -and ($DisabledAccountDays -as [int]) -gt 0) { $disabledDays = [int]$DisabledAccountDays }
    $disabledCut = (Get-Date).ToUniversalTime().AddDays(-$disabledDays)
    $signInKnown = [bool]$script:UsersCacheHasSignIn
    $signInWhy = $null; $signInAction = $null
    if (-not $signInKnown) {
        # The reason and the first recommended step come from the same branch, so the action
        # always fixes the actual cause (granting a permission does not help a tenant without
        # P1/P2, or a read that failed although the permission is there).
        $manualReview = 'review the disabled accounts by hand (Entra admin center > Entra ID > Users > All users, add the filter Account enabled = No) and delete the ones no longer needed'
        $fetchErr = $script:SignInFetchError
        if ($fetchErr) {
            $signInWhy = 'reading sign-in activity failed: ' + $(if ($fetchErr -is [System.Exception]) { $fetchErr.Message } else { [string]$fetchErr })
            $signInAction = 'Fix the failed read of sign-in activity and run the check again: make sure the audit account or app has AuditLog.Read.All (an app needs it as an application permission with admin consent), and if Microsoft Graph was throttling requests, wait and retry. Until then, ' + $manualReview + '.'
        } elseif (-not (Test-MgScope @('AuditLog.Read.All') -Quiet)) {
            $signInWhy = 'the AuditLog.Read.All permission is missing'
            $signInAction = 'Grant AuditLog.Read.All to the audit account or app and run the check again' +
                $(if (-not $script:HasP1) { ' (sign-in dates also need Microsoft Entra ID P1 or P2 in the tenant)' } else { '' }) + '. Until then, ' + $manualReview + '.'
        } elseif (-not $script:HasP1) {
            if ($script:LicenseKnown) {
                $signInWhy = 'no Microsoft Entra ID P1 or P2 licence was found (sign-in dates need one)'
                $signInAction = 'Review the disabled accounts by hand (Entra admin center > Entra ID > Users > All users, add the filter Account enabled = No) and delete the ones no longer needed. The audit cannot tell how long they have been unused: last-sign-in dates need a Microsoft Entra ID P1 or P2 licence, which this tenant does not have.'
            } else {
                $signInWhy = 'the licence check failed, so it is unknown whether the tenant has the Microsoft Entra ID P1 licence that sign-in dates need'
                $signInAction = 'Fix the failed licence check and run the check again: make sure the audit account can read subscriptions (Organization.Read.All), and if Microsoft Graph was throttling requests, wait and retry. Until then, ' + $manualReview + '.'
            }
        } else {
            $signInWhy = 'the user list was read without sign-in activity'
            $signInAction = 'Run the accounts check again so the user list is read with sign-in activity. Until then, ' + $manualReview + '.'
        }
    }
    $disabledRows = @(foreach ($u in $users) {
        if ($u.AccountEnabled -ne $false) { continue }   # only accounts known to be disabled
        $created = if ($u.CreatedDateTime) { [datetime]$u.CreatedDateTime } else { $null }
        $lastOk = $null
        if ($signInKnown) {
            $sa = Get-EAField $u 'SignInActivity'
            $okRaw = if ($sa) { Get-EAField $sa 'LastSuccessfulSignInDateTime' } else { $null }
            if ($okRaw) { $lastOk = [datetime]$okRaw }
        }
        # Failed attempts do not count as use (a disabled account cannot sign in successfully).
        # No successful sign-in on record: judged by the creation date; a missing creation date
        # counts as old, because the account is then not recent either.
        $unused = if (-not $signInKnown) { 'Unknown' }
                  elseif ($lastOk) { $(if ($lastOk -lt $disabledCut) { 'Yes' } else { 'No' }) }
                  elseif (-not $created -or $created -lt $disabledCut) { 'Yes' }
                  else { 'No' }
        [pscustomobject]@{
            Id                   = $u.Id
            UserPrincipalName    = $u.UserPrincipalName
            DisplayName          = $u.DisplayName
            UserType             = $(if ($u.UserType) { [string]$u.UserType } else { '' })
            Created              = $created
            LastSuccessfulSignIn = $lastOk
            Licensed             = (@($u.AssignedLicenses | Where-Object { $_ }).Count -gt 0)
            Synced               = [bool]$u.OnPremisesSyncEnabled
            UnusedOverLimit      = $unused
        }
    })
    $disabledStale = @($disabledRows | Where-Object { $_.UnusedOverLimit -eq 'Yes' } | Sort-Object @{ e = { if ($_.LastSuccessfulSignIn) { $_.LastSuccessfulSignIn } elseif ($_.Created) { $_.Created } else { [datetime]::MinValue } } })
    # Without sign-in dates: accounts that COULD be over the limit (created before the cut-off,
    # or with no creation date on record). Newer disabled accounts cannot be.
    $disabledAgeUnknown = @($disabledRows | Where-Object { $_.UnusedOverLimit -eq 'Unknown' -and (-not $_.Created -or $_.Created -lt $disabledCut) })
    $disabledGuests = @($disabledRows | Where-Object { $_.UserType -eq 'Guest' }).Count
    $disabledSummary = ('Disabled accounts: {0} (members: {1}, guests: {2}).' -f $disabledRows.Count, ($disabledRows.Count - $disabledGuests), $disabledGuests)
    $disabledNotes = @(
        $disabledSummary
        ('UnusedOverLimit = Yes: no successful sign-in for over {0} days, or no successful sign-in on record and created over {0} days ago (or with no creation date on record). Failed sign-in attempts do not count as use.' -f $disabledDays)
    )
    if ($signInKnown) { $disabledNotes += ('Disabled accounts unused for over {0} days: {1}.' -f $disabledDays, $disabledStale.Count) }
    else { $disabledNotes += ('Last-sign-in dates are not available ({0}), so UnusedOverLimit is Unknown. {1} created over {2} days ago or {3} no creation date on record.' -f $signInWhy, (Format-EACount -Count $disabledAgeUnknown.Count -One 'of the disabled accounts was' -Many 'of the disabled accounts were'), $disabledDays, $(if ($disabledAgeUnknown.Count -eq 1) { 'has' } else { 'have' })) }
    $disabledSrc = Write-Evidence -BaseName 'disabled_accounts' -Rows $disabledRows -Title ('Disabled Accounts (unused limit: {0} days)' -f $disabledDays) -Notes $disabledNotes

    $notes = @()
    if ($regError) { $notes += ("The MFA registration report could not be read ({0}); MFA capability of accounts with non-expiring passwords is unknown." -f $regError) }
    $notes += $disabledSummary
    $src = Write-Evidence -BaseName 'accounts' -Rows $rows -Title 'Account Hygiene' -Notes $notes

    # Manager: when the shared user cache already expanded manager (UsersCacheHasManager),
    # evaluate it in memory; otherwise resolve it in one expanded, paged GET rather than one
    # request per user. The separate read keeps a tenant/API that rejects the expansion from
    # losing every user-based check - it only loses this sub-check (reported, not hidden).
    $managerKnown = $true; $managerError = $null; $managerRows = @()
    try {
        $managerUsers = if ($script:UsersCacheHasManager) { $users } else {
            @(Get-MgUser -All -Property 'id,userPrincipalName,displayName,accountEnabled,userType' -ExpandProperty 'manager($select=id)' -ErrorAction Stop)
        }
        $managerRows = @(foreach ($mu in $managerUsers) {
            if (-not $mu.AccountEnabled -or $mu.UserType -eq 'Guest') { continue }
            $manager = Get-EAField $mu 'Manager'; if ($null -eq $manager) { $manager = Get-Ap $mu 'manager' }
            # The manager arrives as an expanded directory object (Id) or, from the shared user
            # cache, possibly as the id string itself - accept both shapes.
            $managerId = if ($manager -is [string]) { $manager } elseif ($manager) { Get-EAField $manager 'Id' } else { $null }
            [pscustomobject]@{ Id=$mu.Id; UserPrincipalName=$mu.UserPrincipalName; DisplayName=$mu.DisplayName; Enabled=[bool]$mu.AccountEnabled; HasManager=[bool]$managerId }
        })
    } catch { $managerKnown = $false; $managerError = $_.Exception.Message }
    $noManager = @($managerRows | Where-Object { -not $_.HasManager })
    $managerSrc = $null
    if ($managerRows.Count -gt 0) { $managerSrc = Write-Evidence -BaseName 'account_managers' -Rows $managerRows -Title 'Enabled Member Manager Coverage' }

    if ($disabledLicensed.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-disabled-with-licenses' `
            -Title ((Format-EACount -Count $disabledLicensed.Count -One 'disabled account still has' -Many 'disabled accounts still have') + ' licences assigned') `
            -Evidence ("{0} with assignedLicenses. First {1}: {2}" -f (Format-EACount -Count $disabledLicensed.Count -One 'disabled account' -Many 'disabled accounts'), [Math]::Min(10, $disabledLicensed.Count), (($disabledLicensed | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Licences on disabled accounts cost money, and if such an account is switched back on it immediately gets its mail, files and apps back. Licences may also come from group membership.' `
            -RecommendedAction 'Remove the licences from disabled accounts as part of the leaver process (Microsoft 365 admin center > Users > Active users, or remove the account from the licensing group when the licence comes from a group).' `
            -SourceFile $src -ResultRows @($disabledLicensed | Select-Object UserPrincipalName,DisplayName,AccountEnabled) `
            -AffectedObjectIds @($disabledLicensed | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $disabledLicensed.Count -PopulationLabel 'disabled user accounts' -AssessedCount ($disabledRows.Count)
    }
    if ($signInKnown -and $disabledStale.Count -gt 0) {
        $staleGuests = @($disabledStale | Where-Object { $_.UserType -eq 'Guest' }).Count
        $staleNever = @($disabledStale | Where-Object { -not $_.LastSuccessfulSignIn })
        $staleNoCreated = @($staleNever | Where-Object { -not $_.Created }).Count
        Add-EntraFinding -Severity 'Low' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-disabled-not-removed' `
            -Title ((Format-EACount -Count $disabledStale.Count -One 'disabled account has' -Many 'disabled accounts have') + (' not been used for over {0} days' -f $disabledDays)) `
            -Evidence ("{0} of {1} disabled accounts {11} no successful sign-in for over {4} days, or {12} none on record and {13} created over {4} days ago. Members: {2}; guests: {3}; still licensed: {5}; synced from on-premises Active Directory: {6}; no successful sign-in on record: {7}{8}. First {9}: {10}" -f `
                $disabledStale.Count, $disabledRows.Count, ($disabledStale.Count - $staleGuests), $staleGuests, $disabledDays,
                @($disabledStale | Where-Object { $_.Licensed }).Count, @($disabledStale | Where-Object { $_.Synced }).Count, $staleNever.Count,
                $(if ($staleNoCreated -gt 0) { " ({0} of them also {1} no creation date on record)" -f $staleNoCreated, $(if ($staleNoCreated -eq 1) { 'has' } else { 'have' }) } else { '' }),
                [Math]::Min(10, $disabledStale.Count), (($disabledStale | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', '),
                $(if ($disabledStale.Count -eq 1) { 'has had' } else { 'have had' }), $(if ($disabledStale.Count -eq 1) { 'has' } else { 'have' }), $(if ($disabledStale.Count -eq 1) { 'was' } else { 'were' })) `
            -WhyItMatters 'Disabled accounts that stay in the directory are easily forgotten. An administrator can switch one back on by mistake, or an attacker with admin rights can quietly re-enable one, with its old group memberships and access, and use it as a hidden way in.' `
            -RecommendedAction 'Delete these accounts once your retention period has passed (Entra admin center > Entra ID > Users > All users, add the filter Account enabled = No). Delete accounts that are synced from on-premises Active Directory in Active Directory instead. Keep shared, room and equipment mailboxes: they are disabled accounts by design.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
            -SourceFile $disabledSrc -ResultRows @($disabledStale | Select-Object UserPrincipalName,UserType,Created,LastSuccessfulSignIn,Licensed,Synced) `
            -AffectedObjectIds @($disabledStale | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $disabledStale.Count -PopulationLabel 'disabled user accounts with activity assessed' -AssessedCount ($disabledRows.Count)
    } elseif (-not $signInKnown -and $disabledAgeUnknown.Count -gt 0) {
        $unkGuests = @($disabledRows | Where-Object { $_.UserType -eq 'Guest' }).Count
        Add-EntraFinding -Severity 'Information' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-disabled-age-unknown' -CoverageGap `
            -Title 'Could not check how long disabled accounts have been unused - sign-in dates not available' `
            -Evidence ("Disabled accounts found: {0} (members: {1}, guests: {2}). {3} created over {4} days ago (or {6} no creation date on record), so {7} may have been unused for longer than that. Last-sign-in dates are not available: {5}. How long they have been unused is unknown, not confirmed recent." -f `
                $disabledRows.Count, ($disabledRows.Count - $unkGuests), $unkGuests, (Format-EACount -Count $disabledAgeUnknown.Count -One 'of them was' -Many 'of them were'), $disabledDays, $signInWhy,
                $(if ($disabledAgeUnknown.Count -eq 1) { 'has' } else { 'have' }), $(if ($disabledAgeUnknown.Count -eq 1) { 'it' } else { 'they' })) `
            -WhyItMatters 'Without last-sign-in dates the audit cannot tell which disabled accounts are long forgotten and should be deleted. This is a gap in the audit, not a clean result.' `
            -RecommendedAction $signInAction `
            -SourceFile $disabledSrc -ResultRows @($disabledAgeUnknown | Select-Object UserPrincipalName,UserType,Created,Licensed,Synced) `
            -UnknownCount $disabledAgeUnknown.Count -PopulationLabel 'disabled accounts whose inactivity cannot be assessed' -VerificationType Collection
    }
    if ($neverExpire.Count -gt 0) {
        $noMfaNeverExpire = @($neverExpire | Where-Object { $_.Id -and $script:MfaCapableById.ContainsKey($_.Id) -and -not $script:MfaCapableById[$_.Id] })
        $sev = if ($noMfaNeverExpire.Count -gt 0) { 'High' } else { 'Medium' }
        $mfaText = if ($regError) { 'MFA capability could not be checked (registration report unreadable), so these accounts could not be rated High' }
                   else { ('{0} of them cannot use multifactor authentication (not MFA-capable)' -f $noMfaNeverExpire.Count) }
        Add-EntraFinding -Severity $sev -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-password-never-expires' `
            -Title (Format-EACount -Count $neverExpire.Count -One 'enabled cloud account has a password that never expires' -Many 'enabled cloud accounts have passwords that never expire') `
            -Evidence ("PasswordPolicies=DisablePasswordExpiration on {0}; {1}. {2} not counted (synced accounts follow the on-premises AD password policy). First {3}: {4}" -f (Format-EACount -Count $neverExpire.Count -One 'enabled cloud-only account' -Many 'enabled cloud-only accounts'), $mfaText, (Format-EACount -Count $neverExpireSkipped -One 'synced or disabled account with the same flag is' -Many 'synced or disabled accounts with the same flag are'), [Math]::Min(10, $neverExpire.Count), (($neverExpire | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'These accounts are exempt from the tenant password policy, usually because they are service or shared accounts. A password that never changes stays valid for years if it leaks, and without multifactor authentication (MFA) that password alone is enough to sign in.' `
            -RecommendedAction 'Make sure each of these accounts is protected by MFA (for service accounts, move to managed identities or certificate sign-in instead of passwords), then remove the per-account never-expire exception.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy' `
            -SourceFile $src -ResultRows @($neverExpire | Select-Object UserPrincipalName,DisplayName,PasswordPolicies) `
            -AffectedObjectIds @($neverExpire | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $neverExpire.Count -PopulationLabel 'enabled cloud-only user accounts' -AssessedCount (@($users | Where-Object { $_.AccountEnabled -and -not $_.OnPremisesSyncEnabled }).Count)
        if ($regError) {
            Add-EntraFinding -Severity 'Information' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-password-never-expires-mfa-unknown' -CoverageGap `
                -Title 'MFA status of accounts with never-expiring passwords could not be checked' `
                -Evidence ("The MFA registration report could not be read: {0}. {1} rated Medium; {2}." -f $regError, (Format-EACount -Count $neverExpire.Count -One 'account with a non-expiring password was' -Many 'accounts with non-expiring passwords were'), $(if ($neverExpire.Count -eq 1) { 'if it has no MFA the finding would be High' } else { 'any of them without MFA would make the finding High' })) `
                -WhyItMatters 'A never-expiring password without multifactor authentication (MFA) is the higher-risk case. Because MFA could not be checked, the rating may be too low.' `
                -RecommendedAction 'Grant AuditLog.Read.All to the audit account or app and run the check again.' `
                -SourceFile $src
        }
    }
    if ($weakPwPolicy.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-strong-password-disabled' `
            -Title ((Format-EACount -Count $weakPwPolicy.Count -One 'account is' -Many 'accounts are') + ' allowed to use weak passwords') `
            -Evidence ("PasswordPolicies=DisableStrongPassword on {0} ({1} enabled). First {2}: {3}" -f (Format-EACount -Count $weakPwPolicy.Count -One 'account' -Many 'accounts'), @($weakPwPolicy | Where-Object { $_.AccountEnabled }).Count, [Math]::Min(10, $weakPwPolicy.Count), (($weakPwPolicy | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'These accounts skip the password complexity rules, so short or simple passwords that are easy to guess are accepted.' `
            -RecommendedAction 'Turn the password rules back on for these accounts. There is no admin-center switch for this: in Microsoft Graph PowerShell run Update-MgUser -UserId <user> -PasswordPolicies "None" (use "DisablePasswordExpiration" instead if that exception must stay), then have each user set a new password that meets the rules. Microsoft Entra Password Protection (banned-password list) adds further protection.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy' `
            -SourceFile $src -ResultRows @($weakPwPolicy | Select-Object UserPrincipalName,PasswordPolicies) `
            -AffectedObjectIds @($weakPwPolicy | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $weakPwPolicy.Count -PopulationLabel 'user accounts' -AssessedCount ($users.Count)
    }
    if (-not $managerKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-manager-unknown' -CoverageGap `
            -Title 'Could not check which accounts have a manager' `
            -Evidence ("Reading users with their manager failed: {0}. Accounts without a manager are unknown, not confirmed absent." -f $managerError) `
            -WhyItMatters 'The manager field is used by access reviews and joiner/mover/leaver processes to decide who approves or removes access.' `
            -RecommendedAction 'Verify User.Read.All for the audit account or app and run the check again, or review manager assignments manually.' -SourceFile $src
    } elseif ($noManager.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-no-manager' `
            -Title ((Format-EACount -Count $noManager.Count -One 'enabled member account has' -Many 'enabled member accounts have') + ' no manager set') `
            -Evidence ("Enabled non-guest users without a manager: {0} of {1}. First {2}: {3}" -f $noManager.Count, $managerRows.Count, [Math]::Min(10, $noManager.Count), (($noManager | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Without a manager, nobody is clearly responsible for approving or removing the account''s access, so access reviews and leaver processes can miss it.' `
            -RecommendedAction 'Set a manager on workforce accounts (usually from the HR system) and document the accepted exceptions such as top executives and service accounts.' `
            -SourceFile $managerSrc -ResultRows $noManager `
            -AffectedObjectIds @($noManager | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $noManager.Count -PopulationLabel 'enabled member accounts' -AssessedCount ($managerRows.Count)
    }
    # Synced vs cloud-only baseline
    $synced = @($users | Where-Object { $_.OnPremisesSyncEnabled }).Count
    Add-EntraFinding -Severity 'Information' -CheckId 'accounts' -Category 'Identity Hygiene' -RuleId 'accounts-population-overview' `
        -Title 'Account population overview' `
        -Evidence ("Total users: {0}; enabled: {1}; disabled: {2}; synced from on-premises: {3}; cloud-only: {4}; guests: {5}" -f `
            $users.Count, @($users | Where-Object { $_.AccountEnabled }).Count, $disabledRows.Count, $synced, ($users.Count - $synced), @($users | Where-Object { $_.UserType -eq 'Guest' }).Count) `
        -WhyItMatters 'How many accounts the tenant has and how many come from on-premises Active Directory - background for the rest of the report.' `
        -RecommendedAction 'No action needed - background information.' -SourceFile $src
}
