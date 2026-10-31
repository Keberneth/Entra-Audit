<#
MFA Capability & Method Strength. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-Mfa {
    $reg = @(Get-EARegistrationDetails)
    # Privileged principals (shared assignment cache - one Graph download per run). A THROW
    # from the helper (e.g. the role-definition read 403s before the helper's own failure
    # tracking runs) must count as an incomplete classification, not as "no admins".
    $privIds = @{}; $privXrefError = $null
    try { foreach ($id in @((Get-EAPrivilegedUserMap).Keys)) { $privIds[[string]$id] = $true } } catch { $privXrefError = $_.Exception.Message }
    $privCoverageIncomplete = ([bool]$privXrefError -or $script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)

    # Disabled accounts are excluded from the risk findings (a disabled account that is not
    # MFA-capable is not a live risk). A failed user read keeps every account "enabled" -
    # the finding can then only be too broad, never falsely clean - and is noted.
    $userById = @{}; $userError = $null
    try { foreach ($u in @(Get-EAUsers)) { if ($u.Id) { $userById[[string]$u.Id] = $u } } } catch { $userError = $_.Exception.Message }

    # Method-strength categories from the registration report's methodsRegistered.
    # Phishing-resistant: FIDO2 / Windows Hello / passkeys / certificate-based.
    # Strong (not phishing-resistant): Authenticator app / OTP.
    # Weak: SMS / voice / email (anything not matching strong or phishing-resistant).
    # Match the real methodsRegistered enum values. TAP is a bootstrap/recovery credential,
    # not steady-state MFA, so it is deliberately NOT counted as "strong" - a TAP-only admin
    # should still surface in the weak/no-strong bucket.
    $phishRx  = '(?i)(fido2|windowsHello|passKey|x509Certificate)'
    $strongRx = '(?i)(microsoftAuthenticator|oneTimePasscode)'

    # Collected as a single foreach expression: array += per user is O(n^2) at 50k rows.
    $rows = @(foreach ($r in $reg) {
        $methods = @($r.MethodsRegistered)
        $methodsKnown = ($null -ne $r.MethodsRegistered) -and (-not [bool]$r.IsMfaCapable -or @($methods | Where-Object { $_ }).Count -gt 0)
        $hasPhish  = (@($methods | Where-Object { $_ -match $phishRx }).Count -gt 0)
        $hasStrong = (@($methods | Where-Object { $_ -match $strongRx }).Count -gt 0)
        $isPriv = ([bool]$r.IsAdmin -or ($r.Id -and $privIds.ContainsKey([string]$r.Id)))
        $u = if ($r.Id -and $userById.ContainsKey([string]$r.Id)) { $userById[[string]$r.Id] } else { $null }
        $enabled = if ($u) { [bool]$u.AccountEnabled } else { $true }
        # Guests normally satisfy MFA in their HOME tenant and show as not MFA-capable here;
        # userType comes from the report itself, then the user cache, then the #EXT# marker.
        $userType = [string](Get-EAField $r 'UserType')
        if (-not $userType -and $u) { $userType = [string]$u.UserType }
        $isGuest = ($userType -eq 'guest') -or ([string]$r.UserPrincipalName -like '*#EXT#*')
        [pscustomobject]@{
            AccountId=$(if ($r.Id) { [string]$r.Id } else { [string]$r.UserPrincipalName })
            UserPrincipalName=$r.UserPrincipalName; UserType=$(if ($isGuest) { 'Guest' } elseif ($userType) { 'Member' } else { '' })
            Privileged=$isPriv; Enabled=$enabled
            MfaRegistered=[bool]$r.IsMfaRegistered; MfaCapable=[bool]$r.IsMfaCapable
            MfaCapabilityKnown=($null -ne (Get-EAField $r 'IsMfaCapable'))
            StrongMethod=$hasStrong; PhishingResistant=$hasPhish; Methods=($methods -join ','); MethodsKnown=$methodsKnown
        }
    })
    $notes = @('MfaCapable = has registered a strong method that the tenant policy allows. Guests are listed but not counted in the member totals.')
    if ($userError) { $notes += ("The user directory could not be read ({0}); every account is treated as enabled." -f $userError) }
    if ($privXrefError) { $notes += ("Admin accounts could not be identified from role assignments ({0}); only the report's own isAdmin flag was used." -f $privXrefError) }
    $src = Write-Evidence -BaseName 'mfa_registration' -Rows $rows -Title 'MFA Posture - Registered / Capable / Strong / Phishing-Resistant' -Notes $notes

    if ($userError) {
        Add-EntraFinding -Severity 'Information' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-account-status-unknown' -CoverageGap `
            -Title 'Account enabled status could not be verified for MFA findings' -Evidence $userError `
            -WhyItMatters 'The findings include potentially disabled accounts, and the enabled-account denominator is not confirmed.' `
            -RecommendedAction 'Restore read access to users and rerun MFA assessment to verify which affected accounts are enabled.' -SourceFile $src
    }
    $capabilityUnknown = @($rows | Where-Object { $_.Enabled -and -not $_.MfaCapabilityKnown })
    if ($capabilityUnknown.Count) {
        Add-EntraFinding -Severity 'Information' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-registration-capability-unknown' -CoverageGap `
            -Title 'Some registration records omit MFA capability' -Evidence ("{0} accounts returned no capability value; they were not classified as lacking MFA." -f $capabilityUnknown.Count) `
            -WhyItMatters 'Missing capability data cannot prove that a method is registered or absent.' `
            -RecommendedAction 'Check the registration report and its permissions, then rerun after the data refreshes.' -SourceFile $src `
            -AffectedObjectIds @($capabilityUnknown.AccountId) -AffectedObjectType 'user' -UnknownCount $capabilityUnknown.Count -PopulationLabel 'registration records with unknown MFA capability'
    }
    $methodsUnknown = @($rows | Where-Object { $_.Enabled -and -not $_.MethodsKnown })
    if ($methodsUnknown.Count) {
        Add-EntraFinding -Severity 'Information' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-registration-methods-unknown' -CoverageGap `
            -Title 'Method strength could not be assessed for some registration records' -Evidence ("{0} accounts omitted readable method data or reported MFA capability without a method list." -f $methodsUnknown.Count) `
            -WhyItMatters 'Missing method details cannot prove weak authentication or absence of phishing-resistant registration.' `
            -RecommendedAction 'Inspect the authentication-methods registration report and recheck after its data refreshes.' -SourceFile $src `
            -AffectedObjectIds @($methodsUnknown.AccountId) -AffectedObjectType 'user' -UnknownCount $methodsUnknown.Count -PopulationLabel 'registration records with unknown method strength'
    }

    if ($privCoverageIncomplete) {
        $what = if ($privXrefError) { ('The admin list could not be built ({0}); only accounts the MFA report itself marks as admin were treated as admins.' -f $privXrefError) }
                else { 'Active or eligible role assignments, or the members of a group that holds an admin role, could not be fully read; some admins may be missing from the admin MFA findings.' }
        Add-EntraFinding -Severity 'Information' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-admin-classification-incomplete' -CoverageGap `
            -Title 'MFA of all admin accounts could not be checked - admin list incomplete' `
            -Evidence $what `
            -WhyItMatters 'Admins who can switch a role on just-in-time, or who get it through a group, need the same strong multifactor authentication (MFA) as permanent admins. Missing admins may hide a Critical finding.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory and GroupMember.Read.All (or Directory.Read.All) to the audit account or app and run the check again.' `
            -SourceFile $src
    }

    $priv         = @($rows | Where-Object { $_.Privileged -and $_.Enabled })
    $privAssessed = @($priv | Where-Object MfaCapabilityKnown)
    $privUnknown = if ($privCoverageIncomplete -or $userError) { $null } else { $priv.Count - $privAssessed.Count }
    $privNoMfa    = @($privAssessed | Where-Object { -not $_.MfaCapable })
    $privMethodsAssessed = @($priv | Where-Object MethodsKnown)
    $privMethodsUnknown = if ($privCoverageIncomplete -or $userError) { $null } else { $priv.Count - $privMethodsAssessed.Count }
    $privWeakOnly = @($privMethodsAssessed | Where-Object { $_.MfaCapable -and -not $_.StrongMethod -and -not $_.PhishingResistant })
    $privNoPhish  = @($privMethodsAssessed | Where-Object { $_.MfaCapable -and $_.StrongMethod -and -not $_.PhishingResistant })
    $memberRows   = @($rows | Where-Object { -not $_.Privileged -and $_.Enabled -and $_.UserType -ne 'Guest' })
    $memberAssessed = @($memberRows | Where-Object MfaCapabilityKnown)
    $memberUnknown = if ($privCoverageIncomplete -or $userError) { $null } else { $memberRows.Count - $memberAssessed.Count }
    $memberNoMfa  = @($memberAssessed | Where-Object { -not $_.MfaCapable })
    $enabledMembers = @($rows | Where-Object { $_.Enabled -and $_.UserType -ne 'Guest' })
    $enabledGuests  = @($rows | Where-Object { $_.Enabled -and $_.UserType -eq 'Guest' -and -not $_.Privileged })

    if ($privNoMfa.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-admins-without-mfa' `
            -Title ((Format-EACount -Count $privNoMfa.Count -One 'admin account has' -Many 'admin accounts have') + ' no allowed MFA method recorded') `
            -Evidence ("Enabled admin accounts that are not MFA-capable (isMfaCapable = false): {0}. First {1}: {2}" -f $privNoMfa.Count, [Math]::Min(10, $privNoMfa.Count), (($privNoMfa | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'The registration report shows no registered MFA method allowed by policy for these admins. This is a registration-readiness gap, not proof of password-only sign-ins: Conditional Access may block access or require registration. Verify effective enforcement and, for external administrators, authentication in their home tenant.' `
            -RecommendedAction 'Register a phishing-resistant method (FIDO2 security key, Windows Hello for Business or passkey) for each admin, then require it for admins with a Conditional Access authentication strength (Entra admin center > Entra ID > Conditional Access).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa' `
            -SourceFile $src -ResultRows @($privNoMfa | Select-Object AccountId,UserPrincipalName,MfaCapable,Methods) `
            -AffectedObjectIds @($privNoMfa.AccountId) -AffectedObjectType 'user' -AssessedCount $privAssessed.Count `
            -UnknownCount $privUnknown -PopulationLabel 'admin accounts in the registration report treated as enabled' `
            -VerificationSteps 'For each listed account, verify an allowed registered method, effective Conditional Access coverage and a fresh sign-in. For external admins verify home-tenant MFA and inbound trust. Confirm the registration report has refreshed; a missing finding alone does not prove enforcement.'
    }
    if ($privWeakOnly.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-admins-weak-methods-only' `
            -Title ((Format-EACount -Count $privWeakOnly.Count -One 'admin account only has' -Many 'admin accounts only have') + ' weak MFA methods (text message, phone call or email)') `
            -Evidence ("Admins whose registered methods include no authenticator app, one-time-passcode or phishing-resistant method: {0}. First {1}: {2}" -f $privWeakOnly.Count, [Math]::Min(10, $privWeakOnly.Count), (($privWeakOnly | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'Codes sent by text message, phone call or email can be phished or stolen by taking over the phone number (SIM swap). For an admin that means a full account takeover.' `
            -RecommendedAction 'Register FIDO2 security keys, Windows Hello for Business or passkeys for these admins and stop allowing text message and phone call as their sign-in factor.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths' `
            -SourceFile $src -ResultRows @($privWeakOnly | Select-Object AccountId,UserPrincipalName,Methods) `
            -AffectedObjectIds @($privWeakOnly.AccountId) -AffectedObjectType 'user' -AssessedCount $privMethodsAssessed.Count `
            -UnknownCount $privMethodsUnknown -PopulationLabel 'admin accounts with readable method details treated as enabled' `
            -VerificationSteps 'Verify each affected admin has a phishing-resistant method and that effective policy requires it. Test a new sign-in and confirm the registration report has refreshed.'
    }
    if ($privNoPhish.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-admins-not-phishing-resistant' `
            -Title ((Format-EACount -Count $privNoPhish.Count -One 'admin account has' -Many 'admin accounts have') + ' MFA but no phishing-resistant method') `
            -Evidence ("Admins with an authenticator app or one-time passcode but no FIDO2, Windows Hello, passkey or certificate method: {0}. First {1}: {2}" -f $privNoPhish.Count, [Math]::Min(10, $privNoPhish.Count), (($privNoPhish | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', ')) `
            -WhyItMatters 'App notifications and one-time codes are much better than a password alone, but a fake sign-in page can still relay them, and repeated push prompts can wear a user down. Admin accounts should use methods that cannot be phished.' `
            -RecommendedAction 'Give all admins FIDO2 security keys, passkeys or Windows Hello for Business and require a phishing-resistant authentication strength for them in Conditional Access.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa' `
            -SourceFile $src -ResultRows @($privNoPhish | Select-Object AccountId,UserPrincipalName,Methods) `
            -AffectedObjectIds @($privNoPhish.AccountId) -AffectedObjectType 'user' -AssessedCount $privMethodsAssessed.Count `
            -UnknownCount $privMethodsUnknown -PopulationLabel 'admin accounts with readable method details treated as enabled' `
            -VerificationSteps 'Verify registration and enforcement of phishing-resistant authentication for each affected admin, and test a fresh sign-in after the registration report refreshes.'
    }
    if ($memberNoMfa.Count -gt 0) {
        $denom = [Math]::Max(1, $memberAssessed.Count)
        $sev = if (($memberNoMfa.Count / [double]$denom) -gt 0.25) { 'Medium' } else { 'Low' }
        Add-EntraFinding -Severity $sev -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-members-without-mfa' `
            -Title ((Format-EACount -Count $memberNoMfa.Count -One 'non-admin account has' -Many 'non-admin accounts have') + ' no allowed MFA method recorded') `
            -Evidence ("{0} of {1} enabled non-admin member accounts {2} not MFA-capable ({3}%). {4} not counted - guests normally use MFA from their own organization." -f $memberNoMfa.Count, $denom, $(if ($memberNoMfa.Count -eq 1) { 'is' } else { 'are' }), [math]::Round(100 * $memberNoMfa.Count / [double]$denom, 1), (Format-EACount -Count $enabledGuests.Count -One 'enabled guest account is' -Many 'enabled guest accounts are')) `
            -WhyItMatters 'The registration report shows no allowed registered MFA method. These users may be unable to satisfy MFA requirements. Password-only exposure depends on effective sign-in policy; this registration check does not prove how they actually sign in.' `
            -RecommendedAction 'Get every enabled user registered for MFA (registration campaign or Conditional Access registration policy) and require MFA for all users with Conditional Access.' `
            -SourceFile $src -ResultRows @($memberNoMfa | Select-Object AccountId,UserPrincipalName,MfaRegistered,Methods) `
            -AffectedObjectIds @($memberNoMfa.AccountId) -AffectedObjectType 'user' -AssessedCount $memberAssessed.Count `
            -UnknownCount $memberUnknown -PopulationLabel 'non-admin member accounts in the registration report treated as enabled' `
            -VerificationSteps 'Confirm the listed users have an allowed registered method, that effective policy requires MFA, and that a new sign-in works. Recheck after the registration report refreshes.'
    }
    $methodMembers = @($enabledMembers | Where-Object MethodsKnown)
    $phishCount = @($methodMembers | Where-Object { $_.PhishingResistant }).Count
    $prAdopt = if ($methodMembers.Count) { [math]::Round((100 * $phishCount / $methodMembers.Count), 1) } else { $null }
    Add-EntraFinding -Severity 'Information' -CheckId 'mfa' -Category 'Authentication' -RuleId 'mfa-phishing-resistant-adoption' `
        -Title $(if ($null -ne $prAdopt) { "Phishing-resistant registration: $prAdopt% of assessed member accounts" } else { 'Phishing-resistant registration: no readable member-method population' }) `
        -Evidence ("{0} of {1} member accounts treated as enabled with readable method data have a phishing-resistant method registered. {2} additional member records have unknown method details; {3} guests are excluded. Enabled status and admin classification limitations are reported separately." -f $phishCount,$methodMembers.Count,($enabledMembers.Count-$methodMembers.Count),$enabledGuests.Count) `
        -WhyItMatters 'This measures registration readiness, not enforcement or actual sign-in protection. Check effective authentication policy and sign-in evidence as well.' `
        -RecommendedAction 'Roll out phishing-resistant methods to all admins first, then to everyone else.' -SourceFile $src
}
