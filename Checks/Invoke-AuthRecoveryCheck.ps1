<#
Authentication Recovery Readiness. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-AuthRecovery {
    [CmdletBinding()]
    param()

    $checkId = 'authrecovery'
    $doc = 'https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0'
    $policyDoc = 'https://learn.microsoft.com/graph/api/authenticationmethodspolicy-get?view=graph-rest-1.0'
    $ssprDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr'
    $passwordlessDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-plan-prerequisites-phishing-resistant-passwordless-authentication'
    $systemPreferredDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-system-preferred-authentication'
    $migrationDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-methods-manage'
    $campaignDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-registration-campaign'
    $methodsPath = 'Entra admin center > Entra ID > Authentication methods'

    # authrecovery is registered as self-gating (Scopes=@()), so a missing
    # AuditLog.Read.All must not abort the independent policy, password-protection and
    # hybrid sub-controls below. Record the failure as a coverage gap instead.
    $registrationKnown = $true
    $registrationError = $null
    try {
        $registration = @(Get-EARegistrationDetails)
    } catch {
        $registration = @()
        $registrationKnown = $false
        $registrationError = [string]$_.Exception.Message
    }
    $rows = @(foreach ($record in $registration) {
        [pscustomobject]@{
            Id                 = Get-EAGovProperty $record 'id'
            UserPrincipalName  = Get-EAGovProperty $record 'userPrincipalName'
            UserDisplayName    = Get-EAGovProperty $record 'userDisplayName'
            UserType           = Get-EAGovProperty $record 'userType'
            IsAdmin            = Get-EAGovProperty $record 'isAdmin'
            IsSsprEnabled      = Get-EAGovProperty $record 'isSsprEnabled'
            IsSsprRegistered   = Get-EAGovProperty $record 'isSsprRegistered'
            IsSsprCapable      = Get-EAGovProperty $record 'isSsprCapable'
            IsMfaRegistered    = Get-EAGovProperty $record 'isMfaRegistered'
            IsMfaCapable       = Get-EAGovProperty $record 'isMfaCapable'
            IsPasswordlessCapable = Get-EAGovProperty $record 'isPasswordlessCapable'
            IsSystemPreferredAuthenticationMethodEnabled = Get-EAGovProperty $record 'isSystemPreferredAuthenticationMethodEnabled'
            SystemPreferredAuthenticationMethods = (@(Get-EAGovProperty $record 'systemPreferredAuthenticationMethods') -join '; ')
            MethodsRegistered  = (@(Get-EAGovProperty $record 'methodsRegistered') -join '; ')
            LastUpdatedDateTime = Get-EAGovProperty $record 'lastUpdatedDateTime'
        }
    })
    $src = Write-Evidence -BaseName 'authentication_recovery_registration' -Rows @($rows) `
        -Title 'Authentication Recovery, Passwordless, and System-Preferred Registration'

    if (-not $registrationKnown) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method user registration details' `
            -Reason ("the registration report read failed ({0}); SSPR, passwordless and system-preferred registration rules were not evaluated." -f $registrationError) `
            -RequiredScope 'AuditLog.Read.All' -DocumentationUrl $doc -SourceFile $src `
            -Subject "the report of users' registered sign-in methods" `
            -Impact 'Whether users can reset their own password or sign in without a password was not checked.'
    } elseif ($rows.Count -eq 0) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method user registration details' `
            -Reason 'the API returned no rows; disabled users are not represented by this API and tenant-wide recovery posture cannot be inferred.' `
            -RequiredScope 'AuditLog.Read.All' -DocumentationUrl $doc -SourceFile $src `
            -Subject "the report of users' registered sign-in methods" `
            -Impact 'Whether users can reset their own password or sign in without a password was not checked.' `
            -RecommendedAction ("Check the user registration details in {0} > Activity; if they are empty too, confirm the audit account has AuditLog.Read.All and a reader role, then run the audit again" -f $methodsPath)
    }
    # Registration-derived rules run only on a successful, non-empty read. The policy,
    # password-protection and hybrid sections below are independent and always run.
    $registrationAvailable = $registrationKnown -and $rows.Count -gt 0

    $members = @($rows | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.UserType) -or [string]$_.UserType -ieq 'member' })
    $admins = @($members | Where-Object { $_.IsAdmin -eq $true })
    $ssprEnabled = @($members | Where-Object { $_.IsSsprEnabled -eq $true })
    $ssprNotCapable = @($ssprEnabled | Where-Object { $_.IsSsprCapable -ne $true })
    $passwordless = @($members | Where-Object { $_.IsPasswordlessCapable -eq $true })
    $passwordlessAdmins = @($admins | Where-Object { $_.IsPasswordlessCapable -eq $true })
    $adminsWithoutPasswordless = @($admins | Where-Object { $_.IsPasswordlessCapable -ne $true })

    if ($registrationAvailable) {
        if ($ssprEnabled.Count -eq 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
                -Title 'Self-service password reset is not turned on for any user' `
                -Evidence ("The registration report contains {0}, with IsSsprEnabled=true for zero." -f (Format-EACount $members.Count 'member user' 'member users')) `
                -WhyItMatters 'Without self-service password reset (SSPR), every forgotten password goes through the helpdesk, where an attacker can pose as a user on the phone to get a password reset.' `
                -RecommendedAction 'Turn on self-service password reset for all users (a pilot group first if needed) in Entra admin center > Entra ID > Password reset > Properties, and require two methods to reset' `
                -DocumentationUrl $ssprDoc -SourceFile $src -RuleId 'sspr-no-enabled-members'
        } elseif ($ssprNotCapable.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
                -Title ((Format-EACount $ssprNotCapable.Count 'user allowed to reset their own password has' 'users allowed to reset their own password have') + ' not set up a way to do it') `
                -Evidence 'IsSsprEnabled=true but IsSsprCapable is not true: these users are enabled by policy but have not registered enough allowed recovery methods.' `
                -WhyItMatters 'These users cannot reset their own password, so they depend on helpdesk resets (which attackers try to abuse) and can be locked out when it matters most.' `
                -RecommendedAction "Ask these users to register reset methods at https://aka.ms/mysecurityinfo, and turn on 'Require users to register when signing in' in Entra admin center > Entra ID > Password reset > Registration" `
                -DocumentationUrl $ssprDoc -SourceFile $src -ResultRows $ssprNotCapable -RuleId 'sspr-enabled-not-capable' `
                -AffectedObjectIds @($ssprNotCapable | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $ssprNotCapable.Count -PopulationLabel 'SSPR-enabled member registration records' -AssessedCount ($ssprEnabled.Count)
        }

        if ($adminsWithoutPasswordless.Count -gt 0) {
            Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Authentication' `
                -Title ((Format-EACount $adminsWithoutPasswordless.Count 'admin account has' 'admin accounts have') + ' no passwordless sign-in method, such as a passkey, set up') `
                -Evidence ("Administrators with IsPasswordlessCapable=true: {0}/{1}; every remaining administrator is listed. Passwordless capability is not by itself proof that Conditional Access requires phishing-resistant authentication. Related: the 'MFA Capability & Method Strength' check (mfa) scores admins without a phishing-resistant method separately (rule mfa-admins-not-phishing-resistant); registering a passkey or Windows Hello for Business fixes both." -f $passwordlessAdmins.Count,$admins.Count) `
                -WhyItMatters 'Admins who still sign in with a password can have it stolen by a fake sign-in page or guessed, and a helpdesk password reset can be abused to take over the account.' `
                -RecommendedAction 'Register a passkey (FIDO2 security key or passkey in Microsoft Authenticator) or Windows Hello for Business for every admin, then require phishing-resistant sign-in for admins with a Conditional Access authentication strength (Entra admin center > Entra ID > Conditional Access)' `
                -DocumentationUrl $passwordlessDoc -SourceFile $src -ResultRows $adminsWithoutPasswordless -RuleId 'passwordless-admins-not-capable' `
                -AffectedObjectIds @($adminsWithoutPasswordless | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $adminsWithoutPasswordless.Count -PopulationLabel 'administrator registration records' -AssessedCount ($admins.Count)
        }

        if ($members.Count -gt 0) {
            $passwordlessPercent = [math]::Round(($passwordless.Count * 100.0) / $members.Count, 1)
            if ($passwordlessPercent -lt 25) {
                Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Authentication' `
                    -Title ("Only {0}% of users can sign in without a password" -f $passwordlessPercent) `
                    -Evidence ("{0}/{1} member users are reported as passwordless capable. The 25% threshold is an adoption-prioritization threshold, not a compliance requirement." -f $passwordless.Count,$members.Count) `
                    -WhyItMatters 'Passwords are the main target of phishing and password-guessing attacks. The fewer users who can sign in without one, the more accounts stay exposed.' `
                    -RecommendedAction 'Roll out passwordless sign-in (passkeys, Windows Hello for Business or Microsoft Authenticator), starting with admins and other high-risk users, and track the share in each audit' `
                    -DocumentationUrl $passwordlessDoc -SourceFile $src -RuleId 'passwordless-low-adoption'
            }
        }

        $systemPreferredKnown = @($members | Where-Object { $null -ne $_.IsSystemPreferredAuthenticationMethodEnabled })
        if ($systemPreferredKnown.Count -eq 0) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'System-preferred authentication status' `
                -Reason 'the property was absent/null on every registration record.' -RequiredScope 'AuditLog.Read.All' `
                -DocumentationUrl $doc -SourceFile $src -Subject 'the system-preferred authentication status of users' `
                -Impact 'Whether users are steered to their strongest sign-in method was not checked.' `
                -RecommendedAction ("Check the System-preferred authentication setting in {0} > Settings" -f $methodsPath)
        } else {
            $memberSystemPreferredOff = @($members | Where-Object { $_.IsSystemPreferredAuthenticationMethodEnabled -eq $false })
            if ($memberSystemPreferredOff.Count -gt 0) {
                $adminSystemPreferredOff = @($memberSystemPreferredOff | Where-Object { $_.IsAdmin -eq $true })
                $severity = if ($adminSystemPreferredOff.Count -gt 0) { 'Medium' } else { 'Low' }
                Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Authentication' `
                    -Title ("System-preferred authentication is off for {0}" -f (Format-EACount $memberSystemPreferredOff.Count 'user' 'users')) `
                    -Evidence ("IsSystemPreferredAuthenticationMethodEnabled=false; {0}. The report exposes effective per-user state, not a user choice." -f (Format-EACount $adminSystemPreferredOff.Count 'affected record is an administrator' 'affected records are administrators')) `
                    -WhyItMatters 'System-preferred authentication makes Microsoft ask each user for the strongest method they registered. When it is off, users can choose a weaker method, such as a text message, even when a stronger one is available.' `
                    -RecommendedAction ("Turn on System-preferred authentication for all users in {0} > Settings, and exclude only groups with a documented reason" -f $methodsPath) `
                    -DocumentationUrl $systemPreferredDoc -SourceFile $src -ResultRows $memberSystemPreferredOff -RuleId 'system-preferred-member-disabled' `
                    -AffectedObjectIds @($memberSystemPreferredOff | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $memberSystemPreferredOff.Count -PopulationLabel 'member registration records with known system-preferred state' -AssessedCount ($systemPreferredKnown.Count) -UnknownCount ($members.Count - $systemPreferredKnown.Count)
            }
        }
    }

    $policyResult = Invoke-EAGovGraphObject -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    if (-not $policyResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method migration and registration campaign policy' `
            -Reason ([string]$policyResult.Error.Exception.Message) -RequiredScope 'Policy.Read.All' `
            -DocumentationUrl $policyDoc -SourceFile $src -Subject 'the authentication methods policy' `
            -Impact 'The migration status and the registration campaign were not checked here.'
    } else {
        $policy = $policyResult.Value
        $enforcement = Get-EAGovProperty $policy 'registrationEnforcement'
        $campaign = Get-EAGovProperty $enforcement 'authenticationMethodsRegistrationCampaign'
        $policyRows = @([pscustomobject]@{
            PolicyMigrationState = Get-EAGovProperty $policy 'policyMigrationState'
            PolicyVersion        = Get-EAGovProperty $policy 'policyVersion'
            LastModifiedDateTime = Get-EAGovProperty $policy 'lastModifiedDateTime'
            CampaignState        = Get-EAGovProperty $campaign 'state'
            CampaignSnoozeDays   = Get-EAGovProperty $campaign 'snoozeDurationInDays'
            CampaignIncludeTargets = (ConvertTo-EAGovCompactJson (Get-EAGovProperty $campaign 'includeTargets'))
            CampaignExcludeTargets = (ConvertTo-EAGovCompactJson (Get-EAGovProperty $campaign 'excludeTargets'))
        })
        $policySrc = Write-Evidence -BaseName 'authentication_recovery_policy' -Rows $policyRows `
            -Title 'Authentication Methods Migration and Registration Campaign'

        $migration = [string](Get-EAGovProperty $policy 'policyMigrationState')
        if ($migration -and $migration -notmatch '^migrationComplete$') {
            $severity = if ($migration -match '^preMigration$') { 'Medium' } else { 'Low' }
            Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Authentication' `
                -Title ("Old MFA and password-reset method settings still apply (migration state: {0})" -f $migration) `
                -Evidence ("policyMigrationState={0} (finished = migrationComplete), so legacy MFA/SSPR policy settings may still affect which methods work. Related: the 'Authentication Methods Policy' check (authmethodpolicy) reports the same setting as rule authmethodpolicy-migration-incomplete; one fix resolves both." -f $migration) `
                -WhyItMatters 'Until the move to the single authentication methods policy is finished, the old multifactor authentication (MFA) and self-service password reset (SSPR) settings can still allow methods that the new policy has turned off.' `
                -RecommendedAction ("Move the old MFA and SSPR method settings into the authentication methods policy, then set {0} > Policies > Manage migration to Migration Complete" -f $methodsPath) `
                -DocumentationUrl $migrationDoc -SourceFile $policySrc -RuleId 'auth-method-policy-migration-not-complete'
        } elseif ([string]::IsNullOrWhiteSpace($migration)) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method migration state' `
                -Reason 'policyMigrationState was absent from the response.' -RequiredScope 'Policy.Read.All' `
                -DocumentationUrl $policyDoc -SourceFile $policySrc -Subject 'the authentication methods migration status' `
                -Impact 'Whether old MFA and password-reset method settings still apply was not checked.' `
                -RecommendedAction ("Check {0} > Policies > Manage migration in the admin center" -f $methodsPath)
        }

        # The main authmethodpolicy check already reports a disabled campaign on its own.
        # This rule only adds the population that is not yet passwordless, so it needs
        # registration data; without it the registration coverage finding above applies.
        # 'default' is the Microsoft managed state, which is an active campaign (the main
        # check treats it as on too), so only disabled or unreadable states count here.
        # An empty or unexpected state is not proof that the campaign is off: it is a
        # coverage gap under its own rule (coverage-registration-campaign-state), adds no
        # risk points, and never shares a trend identity with the known-off finding.
        # One-time id change, part of the finding-id migration: the unknown state used to
        # be reported under registration-campaign-disabled.
        $campaignState = [string](Get-EAGovProperty $campaign 'state')
        if ($campaignState -notmatch '^(enabled|default)$' -and $registrationAvailable -and $members.Count -gt $passwordless.Count) {
            $notPasswordless = $members.Count - $passwordless.Count
            if ($campaignState -match '^disabled$') {
                Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Authentication' `
                    -Title ("Users are not prompted to set up stronger sign-in methods ({0})" -f (Format-EACount $notPasswordless 'is not passwordless yet' 'are not passwordless yet')) `
                    -Evidence ("Campaign state={0}; {1} not passwordless capable. Related: the 'Authentication Methods Policy' check (authmethodpolicy) scores the campaign being off (rule authmethodpolicy-registration-campaign-off); this finding adds how many users it affects." -f $campaignState,(Format-EACount $notPasswordless 'member user is' 'member users are')) `
                    -WhyItMatters 'The registration campaign asks users to set up Microsoft Authenticator or a passkey when they sign in. Without it, many users never move away from weaker methods such as text messages.' `
                    -RecommendedAction ("Set the registration campaign to Microsoft managed or Enabled for all users in {0} > Registration campaign" -f $methodsPath) `
                    -DocumentationUrl $campaignDoc -SourceFile $policySrc -RuleId 'registration-campaign-disabled'
            } else {
                $stateText = if ([string]::IsNullOrWhiteSpace($campaignState)) { 'empty' } else { $campaignState }
                Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Registration campaign state' `
                    -Reason ("registrationEnforcement.authenticationMethodsRegistrationCampaign.state was '{0}' (missing or unexpected), so the campaign state is unknown, not proven off. Related: the 'Authentication Methods Policy' check (authmethodpolicy) reports the same unreadable setting (rule authmethodpolicy-registration-campaign-unknown)." -f $stateText) `
                    -RequiredScope 'Policy.Read.All' -DocumentationUrl $campaignDoc -SourceFile $policySrc `
                    -Subject 'the registration campaign state' `
                    -Impact ("Whether {0} prompted to set up stronger sign-in methods was not checked" -f (Format-EACount $notPasswordless 'member user who is not passwordless yet is' 'member users who are not passwordless yet are')) `
                    -RecommendedAction ("Check the registration campaign in {0} > Registration campaign and set it to Microsoft managed or Enabled for all users if it is off" -f $methodsPath)
            }
        }
    }

    # Password-protection settings are stored as tenant group settings.  Merge
    # explicit values over the template defaults because Graph returns no setting
    # object when the tenant still uses every default.
    $passwordProtectionDoc = 'https://learn.microsoft.com/graph/group-directory-settings'
    $customBannedDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-configure-custom-password-protection'
    $smartLockoutDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout'
    $onPremProtectionDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises-operations'
    $writebackDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr-writeback'
    $passwordTemplateId = '5cf42378-d67d-4f36-ba46-e8b86229381d'
    $settingResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/groupSettings?$top=999'
    $templateResult = Invoke-EAGovGraphObject -Uri ("https://graph.microsoft.com/v1.0/groupSettingTemplates/{0}" -f $passwordTemplateId)
    $passwordSetting = $null
    if ($settingResult.Success -and -not $settingResult.Truncated) {
        $passwordSetting = @($settingResult.Rows | Where-Object {
            [string](Get-EAGovProperty $_ 'templateId') -ieq $passwordTemplateId -or
            [string](Get-EAGovProperty $_ 'displayName') -ieq 'Password Rule Settings'
        } | Select-Object -First 1)
        if ($passwordSetting.Count -gt 0) { $passwordSetting = $passwordSetting[0] } else { $passwordSetting = $null }
    }

    $passwordMap = if ($settingResult.Success -and -not $settingResult.Truncated -and $templateResult.Success) {
        Merge-EAGovSettingMap -Template $templateResult.Value -Setting $passwordSetting
    } elseif ($passwordSetting) {
        ConvertTo-EAGovSettingMap -Setting $passwordSetting
    } else { @{} }

    $bannedWords = @(if ($passwordMap.ContainsKey('BannedPasswordList')) {
        @(([string]$passwordMap['BannedPasswordList'] -split "`t") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    } else { @() })
    $passwordRows = @([pscustomobject]@{
        EffectiveValuesKnown                = ($passwordMap.Count -gt 0)
        UsesExplicitTenantSetting           = ($null -ne $passwordSetting)
        EnableCustomBannedPasswordCheck     = ConvertTo-EAGovBoolean $passwordMap['EnableBannedPasswordCheck']
        CustomBannedPasswordCount           = $bannedWords.Count
        EnableOnPremisesPasswordProtection  = ConvertTo-EAGovBoolean $passwordMap['EnableBannedPasswordCheckOnPremises']
        OnPremisesPasswordProtectionMode    = $passwordMap['BannedPasswordCheckOnPremisesMode']
        LockoutThreshold                    = $passwordMap['LockoutThreshold']
        LockoutDurationInSeconds            = $passwordMap['LockoutDurationInSeconds']
    })
    $passwordSrc = Write-Evidence -BaseName 'authentication_password_protection' -Rows $passwordRows `
        -Title 'Password Protection and Smart Lockout Settings' `
        -Notes @('The custom banned-password words themselves are deliberately not exported; only the count is retained.')

    if (-not $settingResult.Success -or $settingResult.Truncated -or (-not $templateResult.Success -and -not $passwordSetting)) {
        $reasons = New-Object System.Collections.Generic.List[string]
        if (-not $settingResult.Success) { $reasons.Add([string]$settingResult.Error.Exception.Message) | Out-Null }
        elseif ($settingResult.Truncated) { $reasons.Add('groupSettings pagination limit reached') | Out-Null }
        if (-not $templateResult.Success -and -not $passwordSetting) { $reasons.Add([string]$templateResult.Error.Exception.Message) | Out-Null }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Password protection and smart-lockout settings' `
            -Reason ($reasons -join '; ') -RequiredScope 'Directory.Read.All' `
            -DocumentationUrl $passwordProtectionDoc -SourceFile $passwordSrc `
            -Subject 'the password protection and account lockout settings' `
            -Impact 'The banned-password list, the lockout limit and on-premises password protection were not checked.'
    } elseif ($passwordMap.Count -gt 0) {
        $customEnabled = ConvertTo-EAGovBoolean $passwordMap['EnableBannedPasswordCheck']
        if ($bannedWords.Count -gt 0 -and $customEnabled -ne $true) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
                -Title 'Custom banned-password list is set up but not enforced' `
                -Evidence ("Custom banned-password entries={0}; EnableBannedPasswordCheck={1}." -f $bannedWords.Count,$customEnabled) `
                -WhyItMatters 'Users can still choose passwords built from your company, product or place names, which attackers try first when guessing passwords.' `
                -RecommendedAction ("Set 'Enforce custom list' to Yes in {0} > Password protection, and check that the list is still up to date" -f $methodsPath) `
                -DocumentationUrl $customBannedDoc -SourceFile $passwordSrc -RuleId 'custom-banned-password-check-disabled'
        }
        $lockoutThreshold = 0
        if ([int]::TryParse([string]$passwordMap['LockoutThreshold'], [ref]$lockoutThreshold) -and $lockoutThreshold -gt 10) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Authentication' `
                -Title ("Account lockout allows {0} wrong passwords before it starts (Microsoft default: 10)" -f $lockoutThreshold) `
                -Evidence ("The effective smart lockout LockoutThreshold is {0}, above the Microsoft default of 10 failed attempts; this is a review threshold, not a universal compliance boundary." -f $lockoutThreshold) `
                -WhyItMatters 'A higher limit gives attackers more password guesses per account before smart lockout temporarily blocks further attempts.' `
                -RecommendedAction ("Set 'Lockout threshold' back to 10 or lower in {0} > Password protection, unless you have a documented reason for the higher value" -f $methodsPath) `
                -DocumentationUrl $smartLockoutDoc -SourceFile $passwordSrc -RuleId 'smart-lockout-threshold-high'
        }
    }

    # Graph exposes the directory-sync feature flag for password writeback, but
    # Microsoft documents that this particular property isn't in use. Capture it
    # without treating true as proof of operational writeback health.
    $syncDoc = 'https://learn.microsoft.com/graph/api/resources/onpremisesdirectorysynchronizationfeature?view=graph-rest-1.0'
    $organizationResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,onPremisesSyncEnabled'
    $hybrid = $organizationResult.Success -and @($organizationResult.Rows | Where-Object { (Get-EAGovProperty $_ 'onPremisesSyncEnabled') -eq $true }).Count -gt 0
    if ($hybrid) {
        $syncResult = Get-EAGovOnPremisesSyncObject
        $syncAccess = Get-EAGovOnPremSyncAccess
        if (-not $syncResult.Success -or $null -eq $syncResult.Object) {
            $syncReason = if ($syncResult.Success) { 'Graph returned no on-premises synchronization object.' } else { [string]$syncResult.Error.Exception.Message }
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Hybrid SSPR password-writeback configuration' `
                -Reason ($syncReason + $syncAccess.Note) -RequiredScope $syncAccess.Scope `
                -DocumentationUrl $syncDoc -SourceFile $src -Subject 'the password writeback setting for accounts synced from on-premises' `
                -Impact 'Whether password resets reach on-premises Active Directory was not checked.' `
                -RecommendedAction 'Test a self-service password reset with a synced test account and check the writeback settings in Entra admin center > Entra ID > Password reset > On-premises integration; to let the audit read the sync settings, run it signed in as a Global Administrator with OnPremDirectorySynchronization.Read.All (app-only sign-in is not supported for this setting)'
        } else {
            $features = Get-EAGovProperty $syncResult.Object 'features'
            $writebackPresent = Test-EAGovPropertyPresent $features 'passwordWritebackEnabled'
            $writebackValue = Get-EAGovProperty $features 'passwordWritebackEnabled'
            Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Authentication' `
                -Title 'Password writeback to on-premises Active Directory must be tested by hand' `
                -Evidence ("Graph passwordWritebackEnabled present={0}; value={1}. Microsoft documents that this property isn't in use, so the audit does not interpret it as proof that resets are writing back." -f $writebackPresent,$writebackValue) `
                -WhyItMatters 'The audit cannot see whether password resets made in the cloud reach on-premises Active Directory (AD). If writeback is broken, synced users cannot reset their own password even though the report shows them as able to.' `
                -RecommendedAction 'Test a self-service password reset with a synced test account in each domain, and check the writeback settings and errors in Entra admin center > Entra ID > Password reset > On-premises integration' `
                -DocumentationUrl $writebackDoc -SourceFile $src -RuleId 'hybrid-password-writeback-manual-validation' -CoverageGap
        }

        if ($passwordMap.Count -gt 0) {
            $onPremProtection = ConvertTo-EAGovBoolean $passwordMap['EnableBannedPasswordCheckOnPremises']
            $onPremMode = [string]$passwordMap['BannedPasswordCheckOnPremisesMode']
            if ($onPremProtection -ne $true -or $onPremMode -notmatch '^(Enforce|Enforced)$') {
                # Same rule id either way (the exposure is identical), but tell the reader
                # whether this is an explicit choice or the untouched Microsoft default.
                $onPremSource = if ($null -ne $passwordSetting) {
                    'explicit tenant Password Rule Settings object'
                } else {
                    'Microsoft template defaults - the tenant has never saved Password protection settings, so domain controller agents are probably not deployed'
                }
                Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
                    -Title 'Banned-password check is not enforced in on-premises Active Directory' `
                    -Evidence ("EnableBannedPasswordCheckOnPremises={0}; mode={1}; source={2}." -f $onPremProtection,$onPremMode,$onPremSource) `
                    -WhyItMatters 'Users can still set weak, commonly guessed passwords in on-premises Active Directory (AD), and synced accounts then use the same weak password to sign in to Microsoft 365.' `
                    -RecommendedAction ("Install the Microsoft Entra Password Protection proxy and domain controller agents, review the audit-mode results, then set 'Mode' to Enforced in {0} > Password protection (Microsoft Entra ID P1 or P2 is required for synced users)" -f $methodsPath) `
                    -DocumentationUrl $onPremProtectionDoc -SourceFile $passwordSrc -RuleId 'onprem-password-protection-not-enforced'
            }
        }
    } elseif (-not $organizationResult.Success -or $organizationResult.Truncated) {
        $reason = if ($organizationResult.Success) { 'organization pagination limit reached' } else { [string]$organizationResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Hybrid status for password recovery controls' `
            -Reason $reason -RequiredScope 'Organization.Read.All' -DocumentationUrl $syncDoc -SourceFile $src `
            -Subject "the tenant's on-premises sync status" `
            -Impact 'Password writeback and on-premises password protection were not checked.'
    }

    if (-not $registrationAvailable) { return }
    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Authentication' `
        -Title 'Password reset and passwordless readiness recorded' `
        -Evidence ("Members={0}; SSPR enabled/registered/capable={1}/{2}/{3}; passwordless capable={4}; admins={5}." -f `
            $members.Count,$ssprEnabled.Count,@($members | Where-Object {$_.IsSsprRegistered -eq $true}).Count,
            @($members | Where-Object {$_.IsSsprCapable -eq $true}).Count,$passwordless.Count,$admins.Count) `
        -WhyItMatters 'Registration data shows whether users can actually reset their password and sign in without one, not just whether a policy exists.' `
        -RecommendedAction 'Compare these numbers between audits and help users who are not ready before you enforce stronger sign-in rules' `
        -DocumentationUrl $doc -SourceFile $src -ResultRows @($rows) -RuleId 'auth-recovery-baseline'
}
