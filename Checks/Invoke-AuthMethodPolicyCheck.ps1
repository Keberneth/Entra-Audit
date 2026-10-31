<#
Authentication Methods Policy. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-AuthMethodPolicy {
    $pol = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
    $configs = @($pol.AuthenticationMethodConfigurations | Where-Object { $_ })
    # authenticationMethodConfigurations is auto-expanded on this GET. An empty list means the
    # per-method settings were not returned - every method would then look "not present"
    # (SMS/voice off, TAP off), which is a false clean. Track it and skip method conclusions.
    $configsKnown = ($configs.Count -gt 0)
    $ampDocMethods = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-methods-manage'
    $ampPath = 'Entra admin center > Entra ID > Authentication methods > Policies'

    $privMap = @{}; $privPopulationKnown = $true; $privError = $null
    try { $privMap = Get-EAPrivilegedUserMap; if ($script:PrivilegedUserMapIncomplete) { $privPopulationKnown = $false } } catch { $privPopulationKnown = $false; $privError = $_.Exception.Message }
    $privScopes = @{}

    function _TargetIds($obj, [string]$propertyName) {
        $rawValue = Get-EAField $obj $propertyName
        if ($null -eq $rawValue) { $rawValue = Get-EAField $obj ($propertyName.Substring(0,1).ToLowerInvariant() + $propertyName.Substring(1)) }
        $raw = @($rawValue)
        $ids = @()
        foreach ($t in @($raw)) {
            if ($null -eq $t) { continue }
            $id = Get-EAField $t 'Id'; if ($null -eq $id) { $id = Get-EAField $t 'id' }
            if ($id) { $ids += [string]$id }
        }
        return @($ids | Select-Object -Unique)
    }

    # Resolve a method's state AND its include-target scope. A method is only "tenant-wide"
    # if it targets all_users; targeting a specific group (e.g. a migration pilot) is far
    # lower risk. Handle both typed (.IncludeTargets) and AdditionalProperties shapes.
    function _Method([string]$id) {
        $cfg = $configs | Where-Object { $_.Id -eq $id } | Select-Object -First 1
        if (-not $cfg) { return [pscustomobject]@{ Present=$false; State='not-present'; TenantWide=$false; IncludeIds=@(); ExcludeIds=@(); Targets=''; Exclusions=''; Cfg=$null } }
        $incIds = @(_TargetIds $cfg 'IncludeTargets')
        $excIds = @(_TargetIds $cfg 'ExcludeTargets')
        return [pscustomobject]@{
            Present=$true; State=[string]$cfg.State
            TenantWide=(($incIds -contains 'all_users') -and $excIds.Count -eq 0)
            IncludeIds=$incIds; ExcludeIds=$excIds; Targets=($incIds -join ','); Exclusions=($excIds -join ','); Cfg=$cfg
        }
    }

    function _CoversPrivilegedUser($m, [string]$uid) {
        if (-not $m.Present -or $m.State -ne 'enabled') { return $false }
        if (-not $privScopes.ContainsKey($uid)) { $privScopes[$uid] = Get-EAUserScopeIds $uid }
        $scope = $privScopes[$uid]
        $includeByGroup = @($m.IncludeIds | Where-Object { $_ -notin @('all_users',$uid) })
        $excludeByGroup = @($m.ExcludeIds | Where-Object { $_ -notin @('all_users',$uid) })
        if (-not $scope.Known -and ($includeByGroup.Count -gt 0 -or $excludeByGroup.Count -gt 0)) { return $null }
        $included = ($m.IncludeIds -contains 'all_users') -or ($m.IncludeIds -contains $uid)
        if (-not $included) { foreach ($gid in $includeByGroup) { if ($scope.Groups.Contains($gid)) { $included = $true; break } } }
        if (-not $included) { return $false }
        if ($m.ExcludeIds -contains 'all_users' -or $m.ExcludeIds -contains $uid) { return $false }
        foreach ($gid in $excludeByGroup) { if ($scope.Groups.Contains($gid)) { return $false } }
        return $true
    }

    # Unknown = the admin's group memberships could not be read while the setting targets
    # groups. Such an admin is neither covered nor missing: the gap findings below only use
    # the confirmed-missing admins, and the unknown ones are reported as a coverage gap.
    function _PrivCoverage($methods) {
        $covered = 0; $unknown = 0; $missing = @(); $unknownIds = @()
        foreach ($uid in $privMap.Keys) {
            $yes = $false; $unk = $false
            foreach ($m in @($methods)) {
                $r = _CoversPrivilegedUser $m $uid
                if ($r -eq $true) { $yes = $true; break }
                if ($null -eq $r) { $unk = $true }
            }
            if ($yes) { $covered++ } elseif ($unk) { $unknown++; $unknownIds += $uid } else { $missing += $uid }
        }
        return [pscustomobject]@{ Covered=$covered; Unknown=$unknown; UnknownIds=$unknownIds; Missing=$missing; Total=$privMap.Count }
    }

    # Empty include/exclude lists read as 'none' in the Evidence text.
    function _T([string]$Value) { if ($Value) { return $Value }; return 'none' }

    # Admins a control does not reach, by UPN where known, for the Evidence text.
    function _MissingText($coverage, [int]$Max = 8) { return (_AdminNames @($coverage.Missing) $Max) }
    function _AdminNames($ids, [int]$Max = 8) {
        $names = @(@($ids) | Where-Object { $_ } | ForEach-Object { if ($script:UserById.ContainsKey($_)) { $script:UserById[$_].UserPrincipalName } else { $_ } })
        if ($names.Count -eq 0) { return 'none confirmed' }
        $text = (@($names | Select-Object -First $Max)) -join ', '
        if ($names.Count -gt $Max) { $text += (' (+{0} more)' -f ($names.Count - $Max)) }
        return $text
    }
    # Settings whose admin coverage could not be confirmed (memberships unreadable); they
    # feed the authmethodpolicy-privileged-targeting-unknown coverage gap at the end.
    $coverageUnknown = [System.Collections.Generic.List[string]]::new()
    $coverageUnknownIds = [System.Collections.Generic.HashSet[string]]::new()
    function _NoteUnknown([string]$Setting, $coverage) {
        if ($coverage.Unknown -le 0) { return }
        $coverageUnknown.Add(('{0}: {1} of {2}' -f $Setting, $coverage.Unknown, (Format-EACount -Count $coverage.Total -One 'admin' -Many 'admins'))) | Out-Null
        foreach ($id in @($coverage.UnknownIds)) { if ($id) { [void]$coverageUnknownIds.Add([string]$id) } }
    }

    $methodIds = @('Sms','Voice','Fido2','WindowsHelloForBusiness','MicrosoftAuthenticator','TemporaryAccessPass','Email','SoftwareOath','X509Certificate')
    $rows = @()
    foreach ($mid in $methodIds) {
        $m = _Method $mid; $cov = _PrivCoverage -methods @($m)
        $details = ''
        if ($mid -eq 'TemporaryAccessPass' -and $m.Cfg) {
            $details = 'oneTime={0}; min={1}; default={2}; max={3} minutes' -f
                ((Get-EAField $m.Cfg 'IsUsableOnce') ?? (Get-EAField $m.Cfg 'isUsableOnce')),
                ((Get-EAField $m.Cfg 'MinimumLifetimeInMinutes') ?? (Get-EAField $m.Cfg 'minimumLifetimeInMinutes')),
                ((Get-EAField $m.Cfg 'DefaultLifetimeInMinutes') ?? (Get-EAField $m.Cfg 'defaultLifetimeInMinutes')),
                ((Get-EAField $m.Cfg 'MaximumLifetimeInMinutes') ?? (Get-EAField $m.Cfg 'maximumLifetimeInMinutes'))
        }
        if ($mid -eq 'WindowsHelloForBusiness' -and -not $m.Present) { $details = 'Not part of this policy - Windows Hello for Business is normally configured through Intune / Windows policy.' }
        $rows += [pscustomobject]@{ MethodId=$mid; State=$m.State; TenantWide=$m.TenantWide; IncludeTargets=$m.Targets; ExcludeTargets=$m.Exclusions; PrivilegedCoverage=("{0}/{1} (+{2} unknown)" -f $cov.Covered,$cov.Total,$cov.Unknown); Details=$details }
    }

    $sms = _Method 'Sms'; $voice = _Method 'Voice'; $fido2 = _Method 'Fido2'; $whfb = _Method 'WindowsHelloForBusiness'; $tap = _Method 'TemporaryAccessPass'
    $x509 = _Method 'X509Certificate'   # certificate-based auth is also phishing-resistant
    $phishCoverage = _PrivCoverage -methods @($fido2,$whfb,$x509)

    $migrationState = Get-EAField $pol 'PolicyMigrationState'; if ($null -eq $migrationState) { $migrationState = Get-EAField $pol 'policyMigrationState' }
    $registrationEnforcement = Get-EAField $pol 'RegistrationEnforcement'; if ($null -eq $registrationEnforcement) { $registrationEnforcement = Get-EAField $pol 'registrationEnforcement' }
    $campaign = Get-EAField $registrationEnforcement 'AuthenticationMethodsRegistrationCampaign'
    if ($null -eq $campaign) { $campaign = Get-EAField $registrationEnforcement 'authenticationMethodsRegistrationCampaign' }
    $campaignState = if ($campaign) { [string](Get-EAField $campaign 'State') } else { 'not-present' }
    if (-not $campaignState -and $campaign) { $campaignState = [string](Get-EAField $campaign 'state') }
    $campaignInc = if ($campaign) { @(_TargetIds $campaign 'IncludeTargets') } else { @() }
    $campaignExc = if ($campaign) { @(_TargetIds $campaign 'ExcludeTargets') } else { @() }
    # 'default' is "Microsoft managed" in the portal, and Microsoft documents the managed value
    # of both the registration campaign and system-preferred authentication as ENABLED
    # (learn.microsoft.com/entra/identity/authentication/concept-authentication-default-enablement).
    # Evaluate coverage for it exactly like 'enabled' instead of reporting it as switched off.
    $campaignOn = ($campaignState -in @('enabled','default'))
    $campaignScope = [pscustomobject]@{
        Present=[bool]$campaign; State=$(if ($campaignOn) { 'enabled' } else { $campaignState }); IncludeIds=$campaignInc; ExcludeIds=$campaignExc
        TenantWide=(($campaignInc -contains 'all_users') -and $campaignExc.Count -eq 0)
        Targets=($campaignInc -join ','); Exclusions=($campaignExc -join ','); Cfg=$campaign
    }
    # systemCredentialPreferences is a TOP-LEVEL policy property, not an
    # authenticationMethodConfiguration entry. It exists only on the BETA
    # authenticationMethodsPolicy: the v1.0 policy read above never returns it (kept as a
    # forward-compatible first try), so it is read with a GET to the beta endpoint
    # (Policy.Read.All, like the policy itself). A failed beta read leaves the setting
    # unknown and is reported as a coverage gap below, never as "off".
    $systemPreferredRaw = Get-EAField $pol 'SystemCredentialPreferences'
    $systemPreferredSource = 'v1.0 authenticationMethodsPolicy'
    $systemReadError = $null
    if ($null -eq $systemPreferredRaw) {
        $systemPreferredSource = 'beta authenticationMethodsPolicy'
        # $select keeps the answer small. If Graph refuses the query option on this singleton
        # (HTTP 400), the same GET is sent once more without it; any other error (no
        # permission, throttling, service error) is final.
        foreach ($betaUri in @(
                'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy?$select=systemCredentialPreferences',
                'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy')) {
            try {
                $betaPol = Invoke-MgGraphRequest -Method GET -Uri $betaUri -ErrorAction Stop
                $systemPreferredRaw = Get-EAField $betaPol 'systemCredentialPreferences'
                $systemReadError = $null
                break
            } catch {
                $systemReadError = $_.Exception.Message
                if ((Get-EAHttpStatus $_) -ne 400) { break }
            }
        }
    }
    $systemInc = if ($systemPreferredRaw) { @(_TargetIds $systemPreferredRaw 'IncludeTargets') } else { @() }
    $systemExc = if ($systemPreferredRaw) { @(_TargetIds $systemPreferredRaw 'ExcludeTargets') } else { @() }
    $systemState = if ($systemPreferredRaw) { Get-EAField $systemPreferredRaw 'State' } else { $null }
    if ($null -eq $systemState -and $systemPreferredRaw) { $systemState = Get-EAField $systemPreferredRaw 'state' }
    $systemStateText = if ($systemPreferredRaw) { [string]$systemState } elseif ($systemReadError) { 'unknown (read failed)' } else { 'not-present' }
    $systemOn = ($systemStateText -in @('enabled','default'))
    $systemPreferred = [pscustomobject]@{
        Present=[bool]$systemPreferredRaw; State=$(if ($systemOn) { 'enabled' } else { $systemStateText })
        IncludeIds=$systemInc; ExcludeIds=$systemExc; TenantWide=(($systemInc -contains 'all_users') -and $systemExc.Count -eq 0)
        Targets=($systemInc -join ','); Exclusions=($systemExc -join ','); Cfg=$systemPreferredRaw
    }
    $campaignCoverage = _PrivCoverage -methods @($campaignScope)
    $systemPreferredCoverage = _PrivCoverage -methods @($systemPreferred)
    $rows += [pscustomobject]@{ MethodId='PolicyMigrationState'; State=[string]$migrationState; TenantWide=$null; IncludeTargets=''; ExcludeTargets=''; PrivilegedCoverage=''; Details='' }
    $rows += [pscustomobject]@{ MethodId='RegistrationCampaign'; State=$campaignState; TenantWide=$campaignScope.TenantWide; IncludeTargets=$campaignScope.Targets; ExcludeTargets=$campaignScope.Exclusions; PrivilegedCoverage=("{0}/{1} (+{2} unknown)" -f $campaignCoverage.Covered,$campaignCoverage.Total,$campaignCoverage.Unknown); Details=$(if ($campaignState -eq 'default') { 'Microsoft managed (currently enabled by Microsoft)' } else { '' }) }
    $rows += [pscustomobject]@{ MethodId='SystemCredentialPreferences'; State=$systemStateText; TenantWide=$systemPreferred.TenantWide; IncludeTargets=$systemPreferred.Targets; ExcludeTargets=$systemPreferred.Exclusions; PrivilegedCoverage=("{0}/{1} (+{2} unknown)" -f $systemPreferredCoverage.Covered,$systemPreferredCoverage.Total,$systemPreferredCoverage.Unknown); Details=$(if ($systemReadError) { 'Could not be read: ' + $systemReadError } elseif ($systemStateText -eq 'default') { 'Microsoft managed (currently enabled by Microsoft); read from the ' + $systemPreferredSource } else { 'Read from the ' + $systemPreferredSource }) }
    $ampNotes = @()
    if ($systemReadError) { $ampNotes += ('System-preferred authentication (systemCredentialPreferences) could not be read from the beta authenticationMethodsPolicy ({0}); its state is unknown, not off.' -f $systemReadError) }
    elseif ($systemPreferredSource -like 'beta*') { $ampNotes += 'System-preferred authentication (systemCredentialPreferences) is read from the beta authenticationMethodsPolicy: the v1.0 policy does not include it.' }
    if (-not $configsKnown) { $ampNotes += 'authenticationMethodConfigurations was empty: per-method states are unknown, not "not present".' }
    if (-not $privPopulationKnown) { $ampNotes += 'Privileged coverage numbers are incomplete: some admin role assignments or group memberships could not be read.' }
    if (@($privScopes.Values | Where-Object { -not $_.Known }).Count -gt 0) { $ampNotes += 'Some admins'' group memberships could not be read: where a setting targets groups they are counted as "unknown" in PrivilegedCoverage, not as covered or missing.' }
    $src = Write-Evidence -BaseName 'auth_method_policy' -Rows $rows -Title 'Authentication Methods Policy (state, include/exclude targets, privileged coverage)' -Notes $ampNotes

    if ($null -eq $migrationState -or [string]$migrationState -eq '') {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Authentication methods policy migration status could not be read' `
            -Evidence 'policyMigrationState was not returned by Microsoft Graph, so whether the legacy MFA/SSPR method settings still apply is unknown.' `
            -WhyItMatters 'Until the migration to the authentication methods policy is finished, the old multifactor authentication (MFA) and self-service password reset (SSPR) settings can still allow methods this policy has turned off. Without the status this cannot be confirmed.' `
            -RecommendedAction ("Check {0} > Manage migration in the portal, and re-run with Policy.Read.All." -f $ampPath) `
            -SourceFile $src -RuleId 'authmethodpolicy-migration-state-unknown' -ObjectType 'tenant' -DocumentationUrl $ampDocMethods -CoverageGap
    } elseif ([string]$migrationState -ne 'migrationComplete') {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Legacy MFA and password-reset method settings still apply (migration not finished)' `
            -Evidence ("policyMigrationState = {0} (finished = migrationComplete)." -f $migrationState) `
            -WhyItMatters 'Until the migration is finished, the old multifactor authentication (MFA) and self-service password reset (SSPR) settings can still allow methods (such as SMS) that this policy has turned off, so this policy alone does not show what people can really use.' `
            -RecommendedAction ("Review the legacy MFA and SSPR method settings, move them into the authentication methods policy, then set the migration to complete in {0} > Manage migration." -f $ampPath) `
            -SourceFile $src -RuleId 'authmethodpolicy-migration-incomplete' -ObjectType 'tenant' -DocumentationUrl $ampDocMethods
    }

    $campaignDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-registration-campaign'
    if (-not $campaign -or -not $campaignState -or $campaignState -notin @('enabled','default','disabled')) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Registration campaign setting could not be read' `
            -Evidence ("registrationEnforcement.authenticationMethodsRegistrationCampaign state: {0}. The setting was missing or had an unexpected value, so it is unknown, not off." -f $(if ($campaignState) { $campaignState } else { 'empty' })) `
            -WhyItMatters 'The registration campaign prompts people to set up a stronger sign-in method; without the setting the audit cannot tell whether it runs.' `
            -RecommendedAction 'Check Entra admin center > Entra ID > Authentication methods > Registration campaign manually, or update the Microsoft.Graph modules and re-run.' `
            -SourceFile $src -RuleId 'authmethodpolicy-registration-campaign-unknown' -ObjectType 'tenant' -DocumentationUrl $campaignDoc -CoverageGap
    } elseif (-not $campaignOn) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Campaign that prompts users to set up stronger sign-in methods is turned off' `
            -Evidence ("Registration campaign state: {0}." -f $campaignState) `
            -WhyItMatters 'The registration campaign asks people to set up a stronger method (such as Microsoft Authenticator or a passkey) when they sign in, which speeds up the move away from SMS and voice calls.' `
            -RecommendedAction 'Set the registration campaign to Microsoft managed or Enabled for all users in Entra admin center > Entra ID > Authentication methods > Registration campaign.' `
            -SourceFile $src -RuleId 'authmethodpolicy-registration-campaign-off' -ObjectType 'tenant' -DocumentationUrl $campaignDoc
    } elseif ($privMap.Count -gt 0 -and @($campaignCoverage.Missing).Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Registration campaign does not reach every admin' `
            -Evidence ("State {0}; admins covered: {1}/{2}; unknown: {3}; not covered: {4}. include={5}; exclude={6}." -f $campaignState,$campaignCoverage.Covered,$campaignCoverage.Total,$campaignCoverage.Unknown,(_MissingText $campaignCoverage),(_T $campaignScope.Targets),(_T $campaignScope.Exclusions)) `
            -WhyItMatters 'Admins left out of the campaign are never prompted to set up a stronger method and may keep relying on methods that can be phished.' `
            -RecommendedAction 'Include all active and eligible admins in the registration campaign and remove admin exclusions.' `
            -SourceFile $src -RuleId 'authmethodpolicy-registration-campaign-gaps' -ObjectType 'tenant' -DocumentationUrl $campaignDoc
    }
    if ($campaignOn) { _NoteUnknown 'registration campaign' $campaignCoverage }

    $systemDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-system-preferred-authentication'
    if (-not $systemPreferred.Present -or -not $systemStateText -or $systemStateText -notin @('enabled','default','disabled')) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'System-preferred authentication setting could not be read' `
            -Evidence $(if ($systemReadError) {
                    "Reading the setting (systemCredentialPreferences) from the beta authenticationMethodsPolicy failed: $systemReadError. Its state is unknown, not off."
                } elseif (-not $systemPreferred.Present) {
                    ("The {0} returned no systemCredentialPreferences value, so the state is unknown, not off." -f $systemPreferredSource)
                } else {
                    ("The {0} returned an unexpected systemCredentialPreferences state '{1}', so the state is unknown, not off." -f $systemPreferredSource, $(if ($systemStateText) { $systemStateText } else { 'empty' }))
                }) `
            -WhyItMatters 'System-preferred authentication makes Entra ask for the strongest method a person has registered; without the setting the audit cannot tell whether that is on.' `
            -RecommendedAction 'Check the setting by hand in Entra admin center > Entra ID > Authentication methods > Settings. To have the audit read it, make sure the audit account or app has Policy.Read.All and can reach the Microsoft Graph beta endpoint, then run the check again.' `
            -SourceFile $src -RuleId 'authmethodpolicy-system-preferred-unknown' -ObjectType 'tenant' -DocumentationUrl $systemDoc -CoverageGap
    } elseif (-not $systemOn) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'System-preferred authentication is turned off, so users can pick weaker methods' `
            -Evidence ("systemCredentialPreferences state: {0}." -f $systemStateText) `
            -WhyItMatters 'System-preferred authentication makes Entra ask for the strongest method a person has registered. When it is off, people can keep choosing a weaker method such as SMS even when they have a stronger one.' `
            -RecommendedAction 'Set System-preferred authentication to Microsoft managed or Enabled for all users in Entra admin center > Entra ID > Authentication methods > Settings.' `
            -SourceFile $src -RuleId 'authmethodpolicy-system-preferred-off' -ObjectType 'tenant' -DocumentationUrl $systemDoc
    } elseif ($privMap.Count -gt 0 -and @($systemPreferredCoverage.Missing).Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'System-preferred authentication does not cover every admin' `
            -Evidence ("State {0}; admins covered: {1}/{2}; unknown: {3}; not covered: {4}. exclusions: {5}." -f $systemStateText,$systemPreferredCoverage.Covered,$systemPreferredCoverage.Total,$systemPreferredCoverage.Unknown,(_MissingText $systemPreferredCoverage),(_T $systemPreferred.Exclusions)) `
            -WhyItMatters 'Admins outside system-preferred authentication can keep choosing a weaker method that can be phished, even when they have a stronger one registered.' `
            -RecommendedAction 'Target system-preferred authentication at all users (or at least every active and eligible admin) and remove admin exclusions.' `
            -SourceFile $src -RuleId 'authmethodpolicy-system-preferred-gaps' -ObjectType 'tenant' -DocumentationUrl $systemDoc
    }
    if ($systemOn) { _NoteUnknown 'system-preferred authentication' $systemPreferredCoverage }

    if (-not $configsKnown) {
        # Without the per-method settings SMS/voice/TAP would all read as "not present" -
        # report the gap and skip every method-level conclusion instead of a false clean.
        Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Sign-in method settings (SMS, voice, passkeys, Temporary Access Pass) could not be read' `
            -Evidence 'The authentication methods policy was read but its authenticationMethodConfigurations list was empty, so the state of each sign-in method is unknown.' `
            -WhyItMatters 'Without the per-method settings the audit cannot tell whether weak methods such as SMS are on, or whether phishing-resistant methods are available to admins.' `
            -RecommendedAction ("Check the methods in {0} manually, confirm Policy.Read.All is granted, and re-run the authmethodpolicy check." -f $ampPath) `
            -SourceFile $src -RuleId 'authmethodpolicy-method-settings-unknown' -ObjectType 'tenant' -DocumentationUrl $ampDocMethods -CoverageGap
    } else {
        $phoneDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-phone-options'
        foreach ($weak in @(@{ n='SMS'; id='Sms'; m=$sms }, @{ n='Voice'; id='Voice'; m=$voice })) {
            if ($weak.m.State -ne 'enabled') { continue }
            $weakCoverage = _PrivCoverage -methods @($weak.m)
            if ($weak.m.TenantWide -or $weakCoverage.Covered -gt 0) {
                Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title ("Weak phone-based sign-in method is on for everyone or for admins: {0}" -f $weak.n) `
                    -Evidence ("{0}: all users without exclusions={1}; admins covered={2}/{3} (+{4} unknown); include={5}; exclude={6}." -f $weak.n,$weak.m.TenantWide,$weakCoverage.Covered,$weakCoverage.Total,$weakCoverage.Unknown,(_T $weak.m.Targets),(_T $weak.m.Exclusions)) `
                    -WhyItMatters 'SMS and voice-call codes can be phished or stolen by taking over the phone number (SIM swapping). Leaving them on for everyone, or for any admin, keeps an easy way into high-value accounts.' `
                    -RecommendedAction ("Turn off {0} in {1}, or at least exclude every admin now and limit it to a small, time-limited group." -f $weak.n, $ampPath) `
                    -SourceFile $src -RuleId 'authmethodpolicy-phishable-method-broad' -ObjectType 'policy' -ObjectId $weak.id -DocumentationUrl $phoneDoc
            } else {
                # Admins whose memberships could not be read may be in the group, which would
                # make this High; the coverage gap at the end names them.
                _NoteUnknown $weak.n $weakCoverage
                Add-EntraFinding -Severity 'Low' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title ("Weak phone-based sign-in method is on for a limited group: {0}" -f $weak.n) `
                    -Evidence ("{0} include targets: {1}; exclude targets: {2}; admins covered: {3}/{4} (+{5} unknown)." -f $weak.n,(_T $weak.m.Targets),(_T $weak.m.Exclusions),$weakCoverage.Covered,$weakCoverage.Total,$weakCoverage.Unknown) `
                    -WhyItMatters 'SMS or voice for a small group (for example during a migration) is much lower risk than for everyone, but it is still a weak method that can be phished.' `
                    -RecommendedAction 'Confirm the group is intentional and time-limited, and turn the method off when the migration ends.' `
                    -SourceFile $src -RuleId 'authmethodpolicy-phishable-method-scoped' -ObjectType 'policy' -ObjectId $weak.id -DocumentationUrl $phoneDoc
            }
        }

        $passkeyDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passkeys-fido2'
        $phishEnabled = (($fido2.Present -and $fido2.State -eq 'enabled') -or ($whfb.Present -and $whfb.State -eq 'enabled') -or ($x509.Present -and $x509.State -eq 'enabled'))
        if (-not $phishEnabled) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title 'No phishing-resistant sign-in method (passkey/FIDO2 or certificate) is turned on' `
                -Evidence ("Passkey (FIDO2) state: {0}; certificate-based authentication state: {1}; Windows Hello for Business in this policy: {2} (normally configured through Intune / Windows policy instead)." -f $fido2.State, $x509.State, $whfb.State) `
                -WhyItMatters 'Phishing-resistant methods such as passkeys (FIDO2) and certificate-based authentication stop fake sign-in pages and stolen codes from working. If none is turned on, admins cannot register one.' `
                -RecommendedAction ("Turn on Passkey (FIDO2) - and optionally certificate-based authentication - in {0}, then require it for admins with a Conditional Access authentication strength." -f $ampPath) `
                -SourceFile $src -RuleId 'authmethodpolicy-no-phishing-resistant-method' -ObjectType 'tenant' -DocumentationUrl $passkeyDoc
        } elseif ($privMap.Count -gt 0 -and @($phishCoverage.Missing).Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title 'Phishing-resistant sign-in methods are not available to every admin' `
                -Evidence ("Admins covered by passkey (FIDO2) / Windows Hello / certificate-based: {0}/{1}; unknown: {2}; not covered: {3}. FIDO2 include/exclude={4}/{5}; WHfB={6}/{7}; CBA={8}/{9}." -f $phishCoverage.Covered,$phishCoverage.Total,$phishCoverage.Unknown,(_MissingText $phishCoverage),(_T $fido2.Targets),(_T $fido2.Exclusions),(_T $whfb.Targets),(_T $whfb.Exclusions),(_T $x509.Targets),(_T $x509.Exclusions)) `
                -WhyItMatters 'A method that is on somewhere in the tenant does not help admins who are excluded from it or outside its target groups; they are left with methods that can be phished.' `
                -RecommendedAction 'Make at least one phishing-resistant method (passkey/FIDO2 or certificate) available to every active and eligible admin and remove admin exclusions.' `
                -SourceFile $src -RuleId 'authmethodpolicy-phishing-resistant-gaps' -ObjectType 'tenant' -DocumentationUrl $passkeyDoc
        } elseif (-not ($fido2.TenantWide -or $whfb.TenantWide -or $x509.TenantWide)) {
            # When some admins could not be checked, "covers admins" is not confirmed: state
            # only what is known. The coverage gap below names the admins that were not checked.
            $phishTitle = if ($phishCoverage.Unknown -gt 0) { 'Phishing-resistant sign-in methods are not available to all users' }
                          else { 'Phishing-resistant sign-in methods cover admins but not all users' }
            Add-EntraFinding -Severity 'Low' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                -Title $phishTitle `
                -Evidence ("FIDO2 targets/exclusions: {0}/{1}; WHfB: {2}/{3}; certificate-based: {4}/{5}." -f (_T $fido2.Targets),(_T $fido2.Exclusions),(_T $whfb.Targets),(_T $whfb.Exclusions),(_T $x509.Targets),(_T $x509.Exclusions)) `
                -WhyItMatters 'Admins come first, but making passkeys available to everyone lowers the phishing risk for the whole organisation.' `
                -RecommendedAction ("Widen the passkey (FIDO2) or certificate-based authentication target to all users in {0}." -f $ampPath) `
                -SourceFile $src -RuleId 'authmethodpolicy-phishing-resistant-not-tenant-wide' -ObjectType 'tenant' -DocumentationUrl $passkeyDoc
        }
        if ($phishEnabled) { _NoteUnknown 'phishing-resistant methods (passkey/FIDO2, Windows Hello, certificate)' $phishCoverage }

        if ($tap.Present -and $tap.State -eq 'enabled') {
            $tapDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass'
            $cfg = $tap.Cfg
            $oneTime = $null; $minLife = $null; $defaultLife = $null; $maxLife = $null; $tapReadError = $null
            try {
                if ($cfg.PSObject.Properties['IsUsableOnce']) { $oneTime = [bool]$cfg.IsUsableOnce } elseif ($cfg.AdditionalProperties -and $cfg.AdditionalProperties.ContainsKey('isUsableOnce')) { $oneTime = [bool]$cfg.AdditionalProperties['isUsableOnce'] }
                $maxLife = Get-Ap $cfg 'maximumLifetimeInMinutes'; if ($null -eq $maxLife -and $cfg.PSObject.Properties['MaximumLifetimeInMinutes']) { $maxLife = $cfg.MaximumLifetimeInMinutes }
                $minLife = Get-Ap $cfg 'minimumLifetimeInMinutes'; if ($null -eq $minLife -and $cfg.PSObject.Properties['MinimumLifetimeInMinutes']) { $minLife = $cfg.MinimumLifetimeInMinutes }
                $defaultLife = Get-Ap $cfg 'defaultLifetimeInMinutes'; if ($null -eq $defaultLife -and $cfg.PSObject.Properties['DefaultLifetimeInMinutes']) { $defaultLife = $cfg.DefaultLifetimeInMinutes }
            } catch { $tapReadError = $_.Exception.Message }   # values stay null -> reported as unknown below
            if ($oneTime -eq $false -and $tap.TenantWide) {
                Add-EntraFinding -Severity 'High' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title 'Temporary Access Pass can be reused and is available to all users' `
                    -Evidence ("TAP isUsableOnce=false, targeted at all users; maximum lifetime {0} minutes." -f ($maxLife ?? 'default')) `
                    -WhyItMatters 'A Temporary Access Pass (TAP) is a time-limited passcode that can sign someone in and set up new sign-in methods. If it can be reused and anyone can be given one, an intercepted pass works like a password for its whole lifetime.' `
                    -RecommendedAction ("In {0} > Temporary Access Pass, turn on one-time use, shorten the lifetime and limit it to a controlled onboarding/helpdesk group." -f $ampPath) `
                    -SourceFile $src -RuleId 'authmethodpolicy-tap-reusable-broad' -ObjectType 'tenant' -DocumentationUrl $tapDoc
            } elseif ($oneTime -eq $false) {
                Add-EntraFinding -Severity 'Medium' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title 'Temporary Access Pass can be reused (not one-time)' `
                    -Evidence ("TAP isUsableOnce=false; targets: {0}." -f (_T $tap.Targets)) `
                    -WhyItMatters 'A reusable Temporary Access Pass (TAP) can be replayed for its whole lifetime if it is intercepted, unlike a one-time pass.' `
                    -RecommendedAction ("In {0} > Temporary Access Pass, turn on one-time use and keep the lifetime short." -f $ampPath) `
                    -SourceFile $src -RuleId 'authmethodpolicy-tap-reusable' -ObjectType 'tenant' -DocumentationUrl $tapDoc
            }
            if ($null -eq $oneTime -or $null -eq $defaultLife -or $null -eq $maxLife) {
                $tapWhy = if ($tapReadError) { (" Read error: {0}." -f $tapReadError) } else { '' }
                Add-EntraFinding -Severity 'Information' -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title 'Temporary Access Pass reuse and lifetime settings could not be fully read' `
                    -Evidence ("isUsableOnce={0}; minimum={1}; default={2}; maximum={3} minutes. Missing values are unknown, not safe defaults.{4}" -f ($oneTime ?? 'unknown'),($minLife ?? 'unknown'),($defaultLife ?? 'unknown'),($maxLife ?? 'unknown'),$tapWhy) `
                    -WhyItMatters 'A Temporary Access Pass (TAP) can set up new sign-in methods; whether it is one-time and how long it lives decide how long an intercepted pass could be misused.' `
                    -RecommendedAction ("Check {0} > Temporary Access Pass and set one-time use with a short default and maximum lifetime." -f $ampPath) `
                    -SourceFile $src -RuleId 'authmethodpolicy-tap-settings-unknown' -ObjectType 'tenant' -DocumentationUrl $tapDoc -CoverageGap
            }
            if (($defaultLife -as [int]) -gt 60 -or ($maxLife -as [int]) -gt 480) {
                $sev = if (($defaultLife -as [int]) -gt 480 -or ($maxLife -as [int]) -gt 1440) { 'High' } else { 'Medium' }
                Add-EntraFinding -Severity $sev -CheckId 'authmethodpolicy' -Category 'Authentication' `
                    -Title 'Temporary Access Pass can stay valid longer than recommended' `
                    -Evidence ("TAP minimum={0}, default={1}, maximum={2} minutes; hardened baseline is default <=60 and maximum <=480 minutes." -f ($minLife ?? 'unknown'),($defaultLife ?? 'unknown'),($maxLife ?? 'unknown')) `
                    -WhyItMatters 'A long-lived Temporary Access Pass (TAP) behaves like a temporary password: if it is copied, logged or overheard, it can be misused for longer.' `
                    -RecommendedAction ("In {0} > Temporary Access Pass, set the default lifetime to 60 minutes or less and the maximum to 8 hours or less." -f $ampPath) `
                    -SourceFile $src -RuleId 'authmethodpolicy-tap-lifetime-long' -ObjectType 'tenant' -DocumentationUrl $tapDoc
            }
        }
    }

    # One coverage gap for everything the admin-coverage rules could not confirm: an
    # incomplete admin list, or admins whose group memberships could not be read while a
    # setting targets groups. Those admins are counted neither as covered nor as missing,
    # so a throttled membership read never turns into a confirmed "does not cover every
    # admin" finding - and never into a clean result either.
    if (-not $privPopulationKnown -or $coverageUnknown.Count -gt 0) {
        $gapParts = @()
        if (-not $privPopulationKnown) {
            $gapParts += ("Some admin role assignments or group memberships could not be read{0}, so the list of admins is incomplete." -f $(if ($privError) { (" ({0})" -f $privError) } else { '' }))
        }
        if ($coverageUnknown.Count -gt 0) {
            $gapParts += ("The group memberships of {0} could not be read ({1}). These settings target groups, so whether they reach those admins is unknown: {2}. Those admins are counted neither as covered nor as missing." -f (Format-EACount -Count $coverageUnknownIds.Count -One 'admin' -Many 'admins'), (_AdminNames ($coverageUnknownIds | ForEach-Object { $_ })), ($coverageUnknown -join '; '))
        }
        # Unreadable memberships can hide a High "does not cover every admin" finding, so
        # that case carries weight (as capolicies-admin-membership-unknown does); an
        # incomplete admin list on its own stays informational.
        $gapSev = if ($coverageUnknown.Count -gt 0) { 'Medium' } else { 'Information' }
        Add-EntraFinding -Severity $gapSev -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Could not fully check which admins the sign-in method settings reach' `
            -Evidence (($gapParts -join ' ') + ' The admin coverage numbers are incomplete, not confirmed clean.') `
            -WhyItMatters 'A method can look enabled for everyone while an unreadable group leaves an admin outside it. Admins who could not be checked may be left with sign-in methods that can be phished.' `
            -RecommendedAction 'Restore read access to roles and group memberships (RoleManagement.Read.Directory, Group.Read.All or GroupMember.Read.All), or re-run if the error was temporary, then re-run the authmethodpolicy check.' `
            -SourceFile $src -RuleId 'authmethodpolicy-privileged-targeting-unknown' -ObjectType 'tenant' -CoverageGap
    }

    if ($script:Findings.Where({$_.CheckId -eq 'authmethodpolicy'}).Count -eq 0) {
        $f2scope = if ($fido2.TenantWide) { 'all' } else { 'scoped' }
        $whscope = if ($whfb.TenantWide) { 'all' } else { 'scoped' }
        $cbscope = if ($x509.TenantWide) { 'all' } else { 'scoped' }
        Add-EntraFinding -Severity 'Information' -CheckId 'authmethodpolicy' -Category 'Authentication' `
            -Title 'Authentication methods policy reviewed - no weak settings found' `
            -Evidence ("FIDO2={0}/{1}, WHfB={2}/{3}, CBA={4}/{5}; SMS={6}, Voice={7}; registration campaign={8}; system-preferred={9}." -f $fido2.State,$f2scope,$whfb.State,$whscope,$x509.State,$cbscope,$sms.State,$voice.State,$campaignState,$systemStateText) `
            -WhyItMatters 'This policy decides which sign-in methods people can register and use, and for whom.' `
            -RecommendedAction 'Keep phishing-resistant methods available to everyone and keep SMS/voice to a minimum.' `
            -SourceFile $src -ResultRows $rows -RuleId 'authmethodpolicy-baseline' -ObjectType 'tenant' -DocumentationUrl $ampDocMethods
    }
}
