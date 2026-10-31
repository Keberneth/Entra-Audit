<#
Conditional Access Posture. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-CAPolicies {
    $pols = @(Get-EACaPolicies)
    $named = @(); $namedKnown = $true; $namedError = $null
    try { $named = @(Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop) }
    catch { $namedKnown = $false; $namedError = $_.Exception.Message }

    # Security Defaults decide how serious a missing admin-MFA policy is: when ON, administrators
    # are still asked for MFA; when OFF, nothing else in Entra forces it. A failed read stays
    # 'Unknown' - never 'Off' (would inflate severity) and never 'On' (would hide risk).
    $sdState = 'Unknown'; $sdError = $null
    try {
        $sdText = [string](Get-EAField (Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop) 'IsEnabled')
        if ($sdText -eq 'True') { $sdState = 'On' } elseif ($sdText -eq 'False') { $sdState = 'Off' } else { $sdError = 'the IsEnabled value was not returned' }
    } catch { $sdError = $_.Exception.Message }
    $sdSentence = switch ($sdState) {
        'On'    { 'Security Defaults is on, so administrators are still asked for MFA through Security Defaults.' }
        'Off'   { 'Security Defaults is off, so nothing else in Entra forces administrators to use MFA (per-user MFA settings were not checked).' }
        default { ("Security Defaults could not be read ({0}), so it is unknown whether it provides MFA for administrators." -f $sdError) }
    }

    # Emergency-access (break-glass) accounts are the ONLY direct user exclusions a tenant-wide
    # baseline may have. Resolve them explicitly: a failed lookup must not silently turn every
    # break-glass exclusion into a baseline gap, nor be mistaken for "no such user".
    $bg = Normalize-StringList -Values $BreakGlassUpns
    $usersKnown = $true; $usersError = $null
    try { Get-EAUsers | Out-Null } catch { $usersKnown = $false; $usersError = $_.Exception.Message }
    $allowedBgIds = @(); $bgUpnById = @{}; $bgNotFound = @(); $bgLookupFailed = @(); $bgLookupError = $usersError
    if ($bg.Count -gt 0) {
        $idByUpn = @{}
        if ($usersKnown) {
            foreach ($u in @($script:UsersCache)) { if ($u.Id -and $u.UserPrincipalName) { $idByUpn[([string]$u.UserPrincipalName).ToLowerInvariant()] = [string]$u.Id } }
        }
        foreach ($b in $bg) {
            if ($idByUpn.ContainsKey($b)) { $allowedBgIds += $idByUpn[$b]; $bgUpnById[$idByUpn[$b]] = $b; continue }
            if ($usersKnown) { $bgNotFound += $b; continue }
            # The directory list could not be read - look the designated account up on its own (GET).
            try {
                $one = Get-MgUser -UserId $b -Property 'id,userPrincipalName' -ErrorAction Stop
                if ($one -and $one.Id) { $allowedBgIds += [string]$one.Id; $bgUpnById[[string]$one.Id] = $b } else { $bgNotFound += $b }
            } catch {
                $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch { $code = $null }
                if ($code -eq 404 -or "$_" -match 'Request_ResourceNotFound') { $bgNotFound += $b } else { $bgLookupFailed += $b; $bgLookupError = $_.Exception.Message }
            }
        }
    } else {
        Write-Warn2 '  -BreakGlassUpns not supplied: users excluded by name from baseline CA policies cannot be recognised as emergency-access accounts.'
    }
    # True when a directly excluded user COULD be an emergency account the audit was not told about.
    $bgUnconfirmed = ($bg.Count -eq 0) -or ($bgLookupFailed.Count -gt 0)
    $bgWhyUnknown = if ($bg.Count -eq 0) { 'No emergency-access accounts were supplied with -BreakGlassUpns' }
                    else { ("The -BreakGlassUpns {0} {1} could not be looked up ({2})" -f $(if ($bgLookupFailed.Count -eq 1) { 'account' } else { 'accounts' }), ($bgLookupFailed -join ', '), $bgLookupError) }
    $bgNote = if ($bg.Count -eq 0) { ' No emergency-access accounts were supplied with -BreakGlassUpns, so emergency accounts are not told apart from other users here.' }
              elseif ($bgLookupFailed.Count -gt 0) { (" The -BreakGlassUpns {0} {1} could not be looked up ({2}), so {3} not told apart from other users here." -f $(if ($bgLookupFailed.Count -eq 1) { 'account' } else { 'accounts' }), ($bgLookupFailed -join ', '), $bgLookupError, $(if ($bgLookupFailed.Count -eq 1) { 'it is' } else { 'they are' })) }
              elseif ($bgNotFound.Count -gt 0) { (" These -BreakGlassUpns did not match any user: {0}." -f ($bgNotFound -join ', ')) }
              else { '' }

    $rows = $pols | Select-Object DisplayName, State,
        @{n='IncludeUsers';e={ ($_.Conditions.Users.IncludeUsers -join ',') }},
        @{n='ExcludeUsers';e={ ($_.Conditions.Users.ExcludeUsers -join ',') }},
        @{n='IncludeGroups';e={ ($_.Conditions.Users.IncludeGroups -join ',') }},
        @{n='ExcludeGroups';e={ ($_.Conditions.Users.ExcludeGroups -join ',') }},
        @{n='IncludeRoles';e={ ($_.Conditions.Users.IncludeRoles -join ',') }},
        @{n='ExcludeRoles';e={ ($_.Conditions.Users.ExcludeRoles -join ',') }},
        @{n='IncludeResources';e={ ($_.Conditions.Applications.IncludeApplications -join ',') }},
        @{n='ExcludeResources';e={ ($_.Conditions.Applications.ExcludeApplications -join ',') }},
        @{n='Controls';e={ ($_.GrantControls.BuiltInControls -join ',') }},
        @{n='GrantOperator';e={ $_.GrantControls.Operator }},
        @{n='AuthenticationStrength';e={ $_.GrantControls.AuthenticationStrength.Id }},
        @{n='ClientApps';e={ ($_.Conditions.ClientAppTypes -join ',') }},
        @{n='UserRisk';e={ ($_.Conditions.UserRiskLevels -join ',') }},
        @{n='SignInRisk';e={ ($_.Conditions.SignInRiskLevels -join ',') }},
        @{n='IncludeLocations';e={ (@(Get-EAField (Get-EAField $_.Conditions 'Locations') 'IncludeLocations') -join ',') }},
        @{n='ExcludeLocations';e={ (@(Get-EAField (Get-EAField $_.Conditions 'Locations') 'ExcludeLocations') -join ',') }},
        Id
    $caNotes = @(
        ('Security Defaults: {0}' -f $(if ($sdState -eq 'Unknown') { "unknown (read failed: $sdError)" } else { $sdState })),
        ('Emergency-access accounts supplied with -BreakGlassUpns: {0} (resolved: {1})' -f $bg.Count, $allowedBgIds.Count)
    )
    $src = Write-Evidence -BaseName 'conditional_access' -Rows $rows -Title 'Conditional Access Policies' -Notes $caNotes
    # Always write the named-location evidence: an empty file must be distinguishable from a failed read.
    $nrows = @($named | Select-Object Id, DisplayName,
        @{n='Trusted';e={ (Get-EAField $_ 'IsTrusted') }},
        @{n='Type';e={ (Get-EAField $_ '@odata.type') }},
        @{n='IpRanges';e={ (@(@(Get-EAField $_ 'IpRanges') | ForEach-Object { Get-EAField $_ 'cidrAddress' } | Where-Object { $_ }) -join ', ') }})
    $nNotes = if ($namedKnown) { @() } else { @("READ FAILED: named locations could not be read ($namedError). This list is unknown, not empty.") }
    Write-Evidence -BaseName 'named_locations' -Rows $nrows -Title 'Named Locations' -Notes $nNotes | Out-Null
    if (-not $namedKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Named locations could not be read, so location-based rules were not fully checked' `
            -Evidence ("Reading named locations failed: {0}. Locations excluded from policies could not be matched to trusted networks." -f $namedError) `
            -WhyItMatters 'Without the list of named locations the audit cannot tell whether a location excluded from a policy is a trusted company network or a loophole.' `
            -RecommendedAction 'Check that the audit account has Policy.Read.All (and a role that can read Conditional Access), then re-run the capolicies check.' `
            -SourceFile $src -RuleId 'capolicies-named-location-coverage-unknown' -ObjectType 'tenant' -CoverageGap `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network'
    }

    $enabled = @($pols | Where-Object { $_.State -eq 'enabled' })
    $unknownStrengthPolicies = @($enabled | Where-Object { -not (Test-CaPolicyStrengthKnown $_) })
    if ($unknownStrengthPolicies.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' -CoverageGap `
            -Title 'Some authentication strength definitions could not be assessed' `
            -Evidence ("Custom strengths are missing their MFA requirements or allowed methods in: {0}. A strength ID alone does not prove MFA." -f ($unknownStrengthPolicies.DisplayName -join ', ')) `
            -WhyItMatters 'A custom strength can allow a password alone. Missing definitions must not be treated as MFA or as a confirmed policy gap.' `
            -RecommendedAction 'Check Policy.Read.All and Security Reader access, inspect the listed authentication strengths, and re-run the audit.' `
            -SourceFile $src -RuleId 'capolicies-authentication-strength-unknown' -ObjectType 'tenant' `
            -ResultRows @($unknownStrengthPolicies | Select-Object Id,DisplayName)
    }

    function _GrantBlocks($p) { return (@($p.GrantControls.BuiltInControls) -contains 'block') }
    # True when the grant is OR and offers a choice outside $controls: another built-in control, an
    # authentication strength, terms of use or a custom control. Any of these lets a user satisfy
    # the policy WITHOUT the controls being tested, so they are not mandatory.
    function _GrantHasOtherOrChoice($p, [string[]]$controls) {
        $g = $p.GrantControls
        if ([string](Get-EAField $g 'Operator') -notmatch '^(?i)OR$') { return $false }
        if (@(@(Get-EAField $g 'BuiltInControls') | Where-Object { $_ -and [string]$_ -notin $controls }).Count -gt 0) { return $true }
        if (Get-EAField (Get-EAField $g 'AuthenticationStrength') 'Id') { return $true }
        if (@(@(Get-EAField $g 'TermsOfUse') | Where-Object { $_ }).Count -gt 0) { return $true }
        return (@(@(Get-EAField $g 'CustomAuthenticationFactors') | Where-Object { $_ }).Count -gt 0)
    }
    function _GrantRequiresBuiltIn($p, [string]$control) {
        $built = @($p.GrantControls.BuiltInControls | Where-Object { $_ })
        if ($built -notcontains $control) { return $false }
        return -not (_GrantHasOtherOrChoice $p @($control))
    }
    # A trusted device is mandatory when the grant requires a compliant device and/or a hybrid-joined
    # device with no weaker OR alternative. Microsoft's own template "Require compliant or hybrid
    # joined device" (compliantDevice OR domainJoinedDevice) therefore qualifies; "... or MFA",
    # "... or an authentication strength" and "... or terms of use / a custom control" do not.
    function _GrantRequiresDeviceTrust($p) {
        $built = @($p.GrantControls.BuiltInControls | Where-Object { $_ })
        $deviceControls = @('compliantDevice','domainJoinedDevice')
        if (@($built | Where-Object { $_ -in $deviceControls }).Count -eq 0) { return $false }
        return -not (_GrantHasOtherOrChoice $p $deviceControls)
    }
    function _HasMfaGrant($p) {
        $strength = Get-EAField $p.GrantControls 'AuthenticationStrength'
        return ((@($p.GrantControls.BuiltInControls) -contains 'mfa') -or [bool](Get-EAField $strength 'Id'))
    }
    function _UniversalResourcePolicy($p, [string[]]$ignore = @()) {
        return ((Test-CaPolicyTargetsAllResources $p) -and -not (Test-CaPolicyHasNarrowingConditions $p $ignore))
    }
    function _UserLabel([string]$id) {
        if ($script:UserById -and $script:UserById.ContainsKey($id) -and $script:UserById[$id].UserPrincipalName) { return [string]$script:UserById[$id].UserPrincipalName }
        if ($bgUpnById.ContainsKey($id)) { return [string]$bgUpnById[$id] }
        return $id
    }
    function _ListText([object[]]$items, [int]$max = 10) {
        $all = @($items | Where-Object { $_ })
        $shown = @($all | Select-Object -First $max)
        $text = $shown -join ', '
        if ($all.Count -gt $shown.Count) { $text += (' (+{0} more)' -f ($all.Count - $shown.Count)) }
        return $text
    }

    # Evaluate one tenant-wide baseline. $Match tests everything except WHO the policy covers
    # (grant, resources, narrowing conditions). A match that covers all users (direct exclusions
    # only for the designated break-glass accounts) satisfies the baseline. A match that fails
    # ONLY because of users excluded by name is kept as a candidate, so the report can name those
    # users - or say the baseline could not be confirmed when no break-glass list was supplied.
    function _EvaluateBaseline([scriptblock]$Match) {
        $ok = @(); $candidates = @()
        foreach ($p in $enabled) {
            if (-not (& $Match $p)) { continue }
            if (Test-CaPolicyTargetsAllUsers $p $allowedBgIds) { $ok += $p; continue }
            $direct = @($p.Conditions.Users.ExcludeUsers | Where-Object { $_ -and $_ -ne 'None' } | ForEach-Object { [string]$_ })
            # Only real object ids qualify ('GuestsOrExternalUsers' is a broad exclusion, not a person).
            if ($direct.Count -eq 0 -or @($direct | Where-Object { $_ -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' }).Count -gt 0) { continue }
            if (Test-CaPolicyTargetsAllUsers $p $direct) {
                $candidates += [pscustomobject]@{ Policy = $p; Excluded = @($direct | Where-Object { $_ -notin $allowedBgIds }) }
            }
        }
        return [pscustomobject]@{ Satisfied = @($ok); Candidates = @($candidates | Sort-Object { @($_.Excluded).Count }) }
    }
    # Candidates small enough to plausibly be only emergency accounts (Microsoft guidance: two).
    function _SmallCandidates($eval) { return @($eval.Candidates | Where-Object { @($_.Excluded).Count -le 5 }) }

    # Report a missing baseline. With no (or unresolvable) -BreakGlassUpns and a policy that fails
    # only because a few users are excluded by name, the honest result is "cannot confirm"
    # (coverage gap), not a confirmed gap. With -BreakGlassUpns supplied the original finding and
    # severity stand, now naming the excluded users.
    function _ReportBaseline($eval, [hashtable]$spec) {
        if (@($eval.Satisfied).Count -gt 0) { return }
        # Keep independent baselines (legacy protocols/devices/flows) assessable while
        # avoiding a false absence claim for controls whose strength definition failed.
        if ($unknownStrengthPolicies.Count -gt 0 -and $spec.RuleId -in @('capolicies-no-mfa-baseline','capolicies-no-signin-risk-policy','capolicies-no-user-risk-policy')) { return }
        $cands = @($eval.Candidates)
        $candRows = @(foreach ($c in $cands) { foreach ($x in @($c.Excluded)) {
            [pscustomobject]@{ Policy = [string]$c.Policy.DisplayName; PolicyId = [string]$c.Policy.Id; ExcludedUser = (_UserLabel $x); ExcludedUserId = $x }
        } })
        $candText = (@($cands | Select-Object -First 3 | ForEach-Object {
            "'{0}' excludes {1} by name: {2}" -f $_.Policy.DisplayName, (Format-EACount -Count @($_.Excluded).Count -One 'user' -Many 'users'), (_ListText @($_.Excluded | ForEach-Object { _UserLabel $_ }))
        }) -join '; ')
        $small = @(_SmallCandidates $eval)
        if ($bgUnconfirmed -and $small.Count -gt 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title ("{0} policy excludes users not confirmed as emergency accounts" -f $spec.Label) `
                -Evidence ("{0}. The policy meets every other requirement of this baseline. {1}, so the audit cannot tell whether these users are your emergency (break-glass) accounts or a real gap. Result: not confirmed (neither passed nor failed)." -f $candText, $bgWhyUnknown) `
                -WhyItMatters ("If an excluded user is not an emergency-access (break-glass) account, that person {0}. Microsoft recommends excluding only the emergency accounts." -f $spec.Exposure) `
                -RecommendedAction 'Re-run the audit with -BreakGlassUpns listing your emergency accounts. If an excluded user is not an emergency account, remove the exclusion in Entra admin center > Entra ID > Conditional Access.' `
                -SourceFile $src -ResultRows $candRows -RuleId ('{0}-unconfirmed-exclusions' -f ($spec.RuleId -replace '^capolicies-no-','capolicies-')) -ObjectType 'tenant' -CoverageGap `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access'
            return
        }
        $ev = $spec.Evidence
        if ($cands.Count -gt 0) { $ev += (" Policies that would qualify except for users excluded by name: {0}." -f $candText) }
        $ev += $bgNote
        $splat = @{
            Severity = $spec.Severity; CheckId = 'capolicies'; Category = 'Tenant Posture'
            Title = $spec.Title; Evidence = $ev; WhyItMatters = $spec.Why; RecommendedAction = $spec.Action
            SourceFile = $src; RuleId = $spec.RuleId; ObjectType = 'tenant'; DocumentationUrl = $spec.Doc
        }
        if ($candRows.Count -gt 0) { $splat.ResultRows = $candRows }
        Add-EntraFinding @splat
    }

    if ($pols.Count -eq 0) {
        # With Security Defaults also OFF nothing requires MFA for anyone, administrators included -
        # at least as bad as the Critical "some administrators have no MFA policy" case below, so
        # the severity matches it. With Security Defaults ON (or unknown) the finding stays High.
        $sevNoPolicies = if ($sdState -eq 'Off') { 'Critical' } else { 'High' }
        $sdNoPolicies = switch ($sdState) {
            'On'    { 'Security Defaults is on, which gives basic protection (MFA registration and prompts, legacy sign-ins blocked) but no per-user, per-app or device control.' }
            'Off'   { 'Security Defaults is also off, so nothing requires MFA for anyone, including administrators (per-user MFA settings were not checked).' }
            default { ("Security Defaults could not be read ({0}), so it is unknown whether basic MFA is enforced." -f $sdError) }
        }
        Add-EntraFinding -Severity $sevNoPolicies -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No Conditional Access policies exist' `
            -Evidence ("The Conditional Access policy list was read successfully and is empty (0 policies). {0}" -f $sdNoPolicies) `
            -WhyItMatters 'Conditional Access (CA) is where Entra enforces sign-in rules such as multifactor authentication (MFA), blocking old sign-in protocols and requiring trusted devices. With no policies, none of these rules are applied.' `
            -RecommendedAction 'Create baseline policies in Entra admin center > Entra ID > Conditional Access: MFA for administrators and all users, block legacy authentication, require compliant or hybrid-joined devices. Without an Entra ID P1 licence, turn on Security Defaults instead.' `
            -SourceFile $src -RuleId 'capolicies-no-policies' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access'
        return
    }

    # --- Tenant-wide baselines (all users, all resources) ---
    $mfaAllEval = _EvaluateBaseline { param($p) (Test-CaPolicyRequiresMfaOrStrength $p) -and (_UniversalResourcePolicy -p $p -ignore @('ModernClients')) }
    _ReportBaseline $mfaAllEval @{
        Label = 'All-users MFA'; RuleId = 'capolicies-no-mfa-baseline'; Severity = 'High'
        Title = 'No Conditional Access policy requires MFA for all users and all apps'
        Evidence = 'No enabled policy requires MFA or an authentication strength (as a mandatory control, not one of several OR choices) for all users and all resources without app exclusions, group/role/guest exclusions or extra platform, location, risk or device conditions. Users excluded by name are accepted only for the -BreakGlassUpns accounts.'
        Why = 'Without multifactor authentication (MFA) for everyone, one stolen or guessed password is enough to take over an account. Tenant-wide MFA is the most effective single sign-in control.'
        Action = 'Create and enable a policy in Entra admin center > Entra ID > Conditional Access: all users, all resources, grant "Require multifactor authentication" (or an authentication strength); exclude only the emergency-access accounts.'
        Exposure = 'can sign in with just a password'
        Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength'
    }
    $legacyEval = _EvaluateBaseline { param($p)
        (_GrantBlocks $p) -and
        (@($p.Conditions.ClientAppTypes) -contains 'exchangeActiveSync') -and
        (@($p.Conditions.ClientAppTypes) -contains 'other') -and
        (_UniversalResourcePolicy -p $p -ignore @('ClientApps'))
    }
    _ReportBaseline $legacyEval @{
        Label = 'Legacy-authentication block'; RuleId = 'capolicies-no-legacy-auth-block'; Severity = 'High'
        Title = 'Legacy authentication is not blocked for all users and apps'
        Evidence = 'No enabled block policy covers both legacy client types (exchangeActiveSync and other clients) for all users and all resources without exclusions or extra platform, location or device conditions.'
        Why = 'Legacy authentication (old mail protocols such as POP and IMAP, and older Office clients) cannot do multifactor authentication (MFA), so attackers use it to try stolen or sprayed passwords while skipping MFA.'
        Action = 'Create and enable a Conditional Access policy that blocks the client apps "Exchange ActiveSync clients" and "Other clients" for all users and all resources, excluding only the emergency-access accounts.'
        Exposure = 'can still use old sign-in protocols that skip MFA'
        Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication'
    }

    # Risk policies need Entra ID P2 and workload-identity CA needs Workload ID Premium. When the
    # licence read failed these baselines were not evaluated - say so instead of staying silent.
    if (-not $script:LicenseKnown -and (-not $script:HasP2 -or -not $script:WorkloadIdP)) {
        $skippedParts = @()
        if (-not $script:HasP2) { $skippedParts += 'sign-in-risk and user-risk policies (need Entra ID P2)' }
        if (-not $script:WorkloadIdP) { $skippedParts += 'workload-identity policies (need Workload ID Premium)' }
        Add-EntraFinding -Severity 'Information' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Risk-based and workload-identity policies were not checked (licences could not be read)' `
            -Evidence ("The licence (subscribed SKU) read failed at the start of the audit, so these baselines were not evaluated: {0}. Their result is unknown, not clean." -f ($skippedParts -join '; ')) `
            -WhyItMatters 'These policies react automatically to signs of account or app compromise. The audit cannot say whether they are needed or present without knowing which licences the tenant has.' `
            -RecommendedAction 'Make sure the audit account can read subscriptions (Organization.Read.All) and re-run the capolicies check.' `
            -SourceFile $src -RuleId 'capolicies-risk-baselines-license-unknown' -ObjectType 'tenant' -CoverageGap
    }
    if ($script:HasP2) {
        $signInRiskEval = _EvaluateBaseline { param($p)
            $riskLevels = @((Get-EAField $p.Conditions 'SignInRiskLevels'))
            (Test-CaPolicyRequiresMfaOrStrength $p) -and
            ($riskLevels -contains 'high') -and ($riskLevels -contains 'medium') -and
            (_UniversalResourcePolicy -p $p -ignore @('SignInRisk'))
        }
        _ReportBaseline $signInRiskEval @{
            Label = 'Sign-in-risk'; RuleId = 'capolicies-no-signin-risk-policy'; Severity = 'High'
            Title = 'No policy requires MFA when a sign-in looks risky (medium or high sign-in risk)'
            Evidence = 'Entra ID P2 is licensed, but no enabled policy for all users and all resources requires MFA or an authentication strength at both medium and high sign-in risk (SignInRiskLevels) without exclusions or other narrowing conditions.'
            Why = 'Microsoft Entra ID Protection flags sign-ins that look like an attacker (for example a sign-in from an anonymous IP address or an unfamiliar location). Requiring multifactor authentication (MFA) for those sign-ins stops most password-only takeovers automatically.'
            Action = 'Create and enable a sign-in-risk policy in Conditional Access: all users, all resources, sign-in risk medium and high, grant "Require multifactor authentication".'
            Exposure = 'is not asked for MFA when a sign-in looks risky'
            Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-sign-in'
        }

        # Two setups count, both with every control required (AND, not OR) and MFA or an
        # authentication strength: Microsoft's current template, "Require risk remediation"
        # (riskRemediation), and the older "Require password change" (passwordChange).
        # riskRemediation is a newer enum value: when Graph could not be asked to name it (see
        # Get-EACaPolicies) it arrives as 'unknownFutureValue'. Such a policy is reported as
        # "not confirmed" below - never counted as a pass, and never as a missing policy.
        function _UserRiskMatch($p, [string[]]$remediation) {
            $g = $p.GrantControls
            $built = @((Get-EAField $g 'BuiltInControls') | Where-Object { $_ } | ForEach-Object { [string]$_ })
            return (([string](Get-EAField $g 'Operator') -notmatch '^(?i)OR$') -and
                (Test-CaPolicyRequiresMfaOrStrength $p) -and
                (@($built | Where-Object { $_ -in $remediation }).Count -gt 0) -and
                (@((Get-EAField $p.Conditions 'UserRiskLevels')) -contains 'high') -and
                (_UniversalResourcePolicy -p $p -ignore @('UserRisk')))
        }
        $userRiskEval = _EvaluateBaseline { param($p) _UserRiskMatch $p @('riskRemediation','passwordChange') }
        $userRiskUnnamed = @()
        if (@($userRiskEval.Satisfied).Count -eq 0) {
            $userRiskUnknownEval = _EvaluateBaseline { param($p) _UserRiskMatch $p @('unknownFutureValue') }
            $userRiskUnnamed = @(@($userRiskUnknownEval.Satisfied) + @($userRiskUnknownEval.Candidates | ForEach-Object { $_.Policy }))
        }
        if ($userRiskUnnamed.Count -gt 0) {
            $unnamedRows = @(foreach ($p in $userRiskUnnamed) {
                [pscustomobject]@{ Policy = [string]$p.DisplayName; PolicyId = [string]$p.Id
                    GrantControls = (@($p.GrantControls.BuiltInControls | Where-Object { $_ }) -join ', ')
                    GrantOperator = [string]$p.GrantControls.Operator }
            })
            Add-EntraFinding -Severity 'Information' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'User-risk policy found, but its grant control could not be confirmed' `
                -Evidence ("{0} target high user risk for all users and all resources and require MFA or an authentication strength, but Microsoft Graph returned the other grant control as 'unknownFutureValue' instead of its name. It is most likely ""Require risk remediation"" (Microsoft's current template), but the audit could not confirm it. Result: not confirmed (neither passed nor failed)." -f $(if ($userRiskUnnamed.Count -eq 1) { "Policy '" + $userRiskUnnamed[0].DisplayName + "' appears to" } else { 'Policies ' + (_ListText @($userRiskUnnamed | ForEach-Object { "'" + $_.DisplayName + "'" }) 5) + ' appear to' })) `
                -WhyItMatters 'High user risk means Microsoft believes the account is probably compromised. If the policy does not really make the user secure the account, the attacker can keep using it.' `
                -RecommendedAction 'Open the policy in Entra admin center > Entra ID > Conditional Access and check that the grant is "Require risk remediation" (or "Require multifactor authentication" AND "Require password change"). Updating the Microsoft Graph PowerShell modules lets the audit read the control by name.' `
                -SourceFile $src -ResultRows $unnamedRows -RuleId 'capolicies-user-risk-policy-unconfirmed' -ObjectType 'tenant' -CoverageGap `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-user'
        } else {
            _ReportBaseline $userRiskEval @{
                Label = 'User-risk'; RuleId = 'capolicies-no-user-risk-policy'; Severity = 'High'
                Title = 'No policy makes users at high risk of compromise secure their account'
                Evidence = 'Entra ID P2 is licensed, but no enabled policy for all users and all resources, at high user risk (UserRiskLevels), requires either "Require risk remediation" with an authentication strength (Microsoft''s current template) or both "Require multifactor authentication" and "Require password change" (AND, not OR).'
                Why = 'High user risk means Microsoft believes the account is probably compromised (for example its password appeared in a leak). Making the user prove who they are and secure the account (a new password, or for passwordless users ending all their sessions) removes the attacker without waiting for the help desk.'
                Action = 'Create and enable a user-risk policy in Conditional Access from Microsoft''s template: all users, all resources, user risk high, grant "Require authentication strength" (multifactor authentication) and "Require risk remediation". The older setup, "Require multifactor authentication" AND "Require password change", also counts.'
                Exposure = 'is not made to secure an account that is probably compromised'
                Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-user'
            }
        }
    }

    $deviceCodeEval = _EvaluateBaseline { param($p)
        $flows = Get-EAField $p.Conditions 'AuthenticationFlows'
        # TransferMethods is ONE flags string: a policy blocking both flows returns
        # 'deviceCodeFlow,authenticationTransfer', so split it before comparing.
        $tm = @((Get-EAField $flows 'TransferMethods') | ForEach-Object { [string]$_ -split '\s*,\s*' } | Where-Object { $_ })
        (_GrantBlocks $p) -and
        ($tm -contains 'deviceCodeFlow') -and
        (_UniversalResourcePolicy -p $p -ignore @('AuthenticationFlows'))
    }
    _ReportBaseline $deviceCodeEval @{
        Label = 'Device-code block'; RuleId = 'capolicies-no-device-code-block'; Severity = 'Medium'
        Title = 'Device code sign-in is not blocked for all users and apps'
        Evidence = 'No enabled block policy for all users and all resources targets the device code flow (AuthenticationFlows.TransferMethods = deviceCodeFlow) without other narrowing conditions.'
        Why = 'In device-code phishing the attacker sends the victim a genuine Microsoft sign-in code; when the victim enters it, the attacker''s device is signed in as the victim, with MFA already completed.'
        Action = 'Block the device code flow for all users and all resources in Conditional Access (Conditions > Authentication flows), then allow narrow exceptions only for documented devices that need it, such as meeting-room devices.'
        Exposure = 'can still be phished through device-code sign-in'
        Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows'
    }

    $deviceTrustEval = _EvaluateBaseline { param($p) (_GrantRequiresDeviceTrust $p) -and (_UniversalResourcePolicy -p $p) }
    _ReportBaseline $deviceTrustEval @{
        Label = 'Compliant or hybrid-joined device'; RuleId = 'capolicies-no-device-compliance-baseline'; Severity = 'Medium'
        Title = 'No policy requires a compliant or hybrid-joined device for all users and apps'
        Evidence = 'No enabled policy for all users and all resources makes a trusted device mandatory - "Require device to be marked as compliant" (compliantDevice) and/or "Require Microsoft Entra hybrid joined device" (domainJoinedDevice) - without another OR choice (such as MFA), application exclusions or narrowing conditions.'
        Why = 'Without a device requirement, a valid password and MFA are enough to sign in from any personal or attacker-controlled computer, where tokens and downloaded data can be stolen.'
        Action = 'Require compliant or hybrid-joined devices for all users and all resources in Conditional Access, and document narrow exceptions for unmanaged (BYOD) scenarios, for example browser-only access with app restrictions.'
        Exposure = 'can sign in from unmanaged devices'
        Doc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance'
    }

    if ($script:WorkloadIdP) {
        function _TargetsAllTenantServicePrincipals($p) {
            $ca = Get-EAField $p.Conditions 'ClientApplications'
            $incSp = @((Get-EAField $ca 'IncludeServicePrincipals') | Where-Object { $_ })
            $excSp = @((Get-EAField $ca 'ExcludeServicePrincipals') | Where-Object { $_ })
            $spFilter = Get-EAField $ca 'ServicePrincipalFilter'
            return (($incSp -contains 'ServicePrincipalsInMyTenant' -or $incSp -contains 'All') -and
                $excSp.Count -eq 0 -and
                -not ($spFilter -and ((Get-EAField $spFilter 'Mode') -or (Get-EAField $spFilter 'Rule'))))
        }

        # Prove the exclusions used by the location baseline are actually trusted. An arbitrary
        # excluded named location is a bypass, not a trusted-network design. When the named-location
        # list could not be read, a policy that is otherwise right is "unverified", not missing.
        $trustedNamedLocationIds = @($named | Where-Object { (Get-EAField $_ 'IsTrusted') -eq $true } | ForEach-Object { [string]$_.Id })
        $workloadLocationPolicies = @(); $workloadLocationUnverified = @()
        foreach ($p in $enabled) {
            $locations = Get-EAField $p.Conditions 'Locations'
            $includeLocations = @((Get-EAField $locations 'IncludeLocations') | Where-Object { $_ })
            $excludeLocations = @((Get-EAField $locations 'ExcludeLocations') | Where-Object { $_ })
            if (-not ((_GrantBlocks $p) -and (Test-CaPolicyTargetsAllResources $p) -and
                (_TargetsAllTenantServicePrincipals $p) -and
                ($includeLocations -contains 'All') -and $excludeLocations.Count -gt 0 -and
                -not (Test-CaPolicyHasNarrowingConditions $p @('ClientApplications','Locations')))) { continue }
            if (-not $namedKnown) { $workloadLocationUnverified += $p; continue }
            if ($trustedNamedLocationIds.Count -eq 0) { continue }
            $untrustedExclusions = @($excludeLocations | Where-Object { $_ -ne 'AllTrusted' -and [string]$_ -notin $trustedNamedLocationIds })
            if ($untrustedExclusions.Count -eq 0) { $workloadLocationPolicies += $p }
        }

        $workloadRiskPolicies = @($enabled | Where-Object {
            $riskLevels = @((Get-EAField $_.Conditions 'ServicePrincipalRiskLevels') | Where-Object { $_ })
            (_GrantBlocks $_) -and (Test-CaPolicyTargetsAllResources $_) -and
            (_TargetsAllTenantServicePrincipals $_) -and ($riskLevels -contains 'high') -and
            -not (Test-CaPolicyHasNarrowingConditions $_ @('ClientApplications','ServicePrincipalRisk'))
        })

        if ($workloadLocationPolicies.Count -eq 0 -and $workloadLocationUnverified.Count -gt 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'Workload-identity location policy could not be verified (named locations unreadable)' `
                -Evidence ("{0} {1} {2} service principals outside excluded locations, but the named-location list could not be read ({3}), so it is unknown whether the excluded locations are really trusted." -f $(if (@($workloadLocationUnverified).Count -eq 1) { 'Policy' } else { 'Policies' }), (_ListText @($workloadLocationUnverified | ForEach-Object { "'" + $_.DisplayName + "'" }) 5), $(if (@($workloadLocationUnverified).Count -eq 1) { 'blocks' } else { 'block' }), $namedError) `
                -WhyItMatters 'If an excluded location is not a trusted company network, stolen app credentials can still be used from there.' `
                -RecommendedAction 'Make sure the audit account can read named locations (Policy.Read.All) and re-run the capolicies check.' `
                -SourceFile $src -RuleId 'capolicies-workload-location-unverified' -ObjectType 'tenant' -CoverageGap `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity'
        } elseif ($workloadLocationPolicies.Count -eq 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'Workload identities (apps) are not restricted to trusted locations' `
                -Evidence ("Workload ID Premium is licensed, but no enabled policy blocks all of this tenant's service principals, for all resources, from every location except trusted ones (AllTrusted or named locations marked trusted) without other narrowing conditions. Trusted named locations found: {0}." -f $trustedNamedLocationIds.Count) `
                -WhyItMatters 'Apps and service accounts (service principals) cannot use multifactor authentication (MFA). If their secret or certificate is stolen, the attacker can use it from anywhere unless access is limited to your own networks.' `
                -RecommendedAction 'Create a Conditional Access policy for workload identities: all service principals in your tenant, all resources, block access from all locations except your trusted named locations.' `
                -SourceFile $src -RuleId 'capolicies-no-workload-location-policy' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity'
        }
        if ($workloadRiskPolicies.Count -eq 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                -Title 'Risky workload identities (apps) are not blocked automatically' `
                -Evidence 'Workload ID Premium is licensed, but no enabled policy blocks all of this tenant''s service principals, for all resources, at high service-principal risk (ServicePrincipalRiskLevels) without exclusions or other narrowing conditions.' `
                -WhyItMatters 'High service-principal risk means Microsoft has seen signs that an app''s credentials are compromised. Blocking at that point stops the attacker from getting new access tokens.' `
                -RecommendedAction 'Create a Conditional Access policy for workload identities: all service principals in your tenant, all resources, service principal risk high (and medium where practical), grant Block.' `
                -SourceFile $src -RuleId 'capolicies-no-workload-risk-policy' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity'
        }
    }

    # Policies that look like MFA enforcement but are switched off or report-only give a false
    # sense of security. "Looks like MFA" = the grant would require MFA / an authentication
    # strength, or the name says MFA (block policies named "... no MFA" are not MFA policies).
    # Severity depends on whether MFA is actually enforced tenant-wide: without an effective
    # all-users MFA baseline this may be the policy that was meant to provide it (High); with one
    # it is clean-up (Low).
    $mfaBaselinePresent = (@($mfaAllEval.Satisfied).Count -gt 0) -or ($bgUnconfirmed -and @(_SmallCandidates $mfaAllEval).Count -gt 0)
    $inactiveMfa = @($pols | Where-Object {
        $_.State -ne 'enabled' -and (
            (_HasMfaGrant $_) -or
            ([string]$_.DisplayName -match '(?i)mfa|multi.?factor' -and -not (_GrantBlocks $_)))
    })
    foreach ($p in $inactiveMfa) {
        $stateText = if ([string]$p.State -eq 'enabledForReportingButNotEnforced') { 'report-only (Entra only logs what the policy would have done; nobody is asked for MFA)' }
                     elseif ([string]$p.State -eq 'disabled') { 'switched off' } else { [string]$p.State }
        $context = if (@($mfaAllEval.Satisfied).Count -gt 0) {
            ("An enforced all-users MFA policy exists ({0}), so this is clean-up rather than a gap." -f (_ListText @($mfaAllEval.Satisfied | ForEach-Object { "'" + $_.DisplayName + "'" }) 3))
        } elseif ($mfaBaselinePresent) {
            ("An enforced all-users MFA policy exists ({0}; its user exclusions are not yet confirmed as emergency accounts), so this is most likely clean-up rather than a gap." -f (_ListText @(_SmallCandidates $mfaAllEval | ForEach-Object { "'" + $_.Policy.DisplayName + "'" }) 3))
        } else { 'No enforced policy requires MFA for all users and all apps, so this may be the policy that was meant to provide it.' }
        $grantParts = @($p.GrantControls.BuiltInControls | Where-Object { $_ })
        if (Get-EAField (Get-EAField $p.GrantControls 'AuthenticationStrength') 'Id') { $grantParts += 'authentication strength' }
        Add-EntraFinding -Severity $(if ($mfaBaselinePresent) { 'Low' } else { 'High' }) -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("MFA policy is not enforced: {0}" -f $p.DisplayName) `
            -Evidence ("Policy '{0}' is {1} (State = {2}). Grant controls: {3}. {4}" -f $p.DisplayName, $stateText, $p.State, $(if ($grantParts.Count) { $grantParts -join ', ' } else { 'none' }), $context) `
            -WhyItMatters 'A policy that looks like it enforces multifactor authentication (MFA) but is switched off or only in report-only mode protects nobody, while suggesting the protection exists.' `
            -RecommendedAction 'Turn the policy on after checking its report-only results (Entra admin center > Entra ID > Conditional Access), or delete it if it is no longer needed.' `
            -SourceFile $src -RuleId 'capolicies-mfa-policy-not-enforced' -ObjectType 'policy' -ObjectId ([string]$p.Id) -AffectedPrincipal ([string]$p.DisplayName) `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only'
    }

    # Trusted named locations that are broad/public
    foreach ($n in $named) {
        $isTrusted = (Get-EAField $n 'IsTrusted')
        $ranges = @((Get-EAField $n 'IpRanges') | Where-Object { $_ })
        if ($isTrusted -and $ranges.Count -gt 0) {
            # ipRanges elements arrive as raw dictionaries, typed objects or AdditionalProperties -
            # Get-EAField reads all three shapes.
            $broad = @($ranges | ForEach-Object { [string](Get-EAField $_ 'cidrAddress') } | Where-Object { $_ -match '/(?:[0-9]|1[0-6])$' })
            if ($broad.Count -gt 0) {
                # The object is the NAMED LOCATION (not a policy): ObjectType/ObjectId/AffectedPrincipal
                # identify it, so the finding stays one stable id per location across runs.
                $locName = [string](Get-EAField $n 'DisplayName')
                $locRows = @(foreach ($cidr in $broad) { [pscustomobject]@{ NamedLocation = $locName; NamedLocationId = [string]$n.Id; BroadRange = $cidr } })
                Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
                    -Title ("Trusted named location covers a very large IP range: {0}" -f $locName) `
                    -Evidence ("Named location '{0}' (id {1}) is marked trusted and includes {2}: {3}. A /16 or wider IPv4 range covers at least 65,536 addresses." -f $locName, $n.Id, $(if ($broad.Count -eq 1) { 'this very large range' } else { ('{0} very large ranges' -f $broad.Count) }), (_ListText $broad 10)) `
                    -WhyItMatters 'Trusted locations are often used to skip multifactor authentication (MFA) or other checks. A very wide trusted range gives the same exemption to anyone signing in from that address space, which may include shared or public networks.' `
                    -RecommendedAction 'Narrow the trusted location to your own public (egress) IP addresses in Entra admin center > Entra ID > Conditional Access > Named locations, and do not use trusted locations to skip MFA.' `
                    -SourceFile $src -ResultRows $locRows -RuleId 'capolicies-trusted-location-too-broad' -ObjectType 'namedLocation' -ObjectId ([string]$n.Id) -AffectedPrincipal $locName `
                    -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network' `
                    -AffectedObjectIds @(([string]$n.Id)) -AffectedObjectType 'namedLocation' -AffectedCount 1
            }
        }
    }

    # EFFECTIVE admin coverage uses the full active+eligible population, including users
    # reached through role-assignable groups. A policy counts only if it covers all resources,
    # has no app exclusions/narrowing conditions and makes its grant mandatory under OR.
    $mfaPolicies = @($enabled | Where-Object {
        (Test-CaPolicyRequiresMfaOrStrength $_) -and (Test-CaPolicyTargetsAllResources $_) -and
        -not (Test-CaPolicyHasNarrowingConditions $_ @('ModernClients'))
    })
    $phishPolicies = @($enabled | Where-Object {
        (Test-CaPolicyRequiresPhishingResistantStrength $_) -and (Test-CaPolicyTargetsAllResources $_) -and
        -not (Test-CaPolicyHasNarrowingConditions $_ @('ModernClients'))
    })
    # Enabled MFA-style policies that were NOT counted, with the plain reason - so the reader can
    # see why an existing "MFA for admins" policy does not satisfy the coverage test.
    $notCountedText = (@($enabled | Where-Object { (_HasMfaGrant $_) -and $mfaPolicies -notcontains $_ } | Select-Object -First 5 | ForEach-Object {
        $reasons = @()
        if (-not (Test-CaPolicyRequiresMfaOrStrength $_)) { $reasons += 'the grants do not prove mandatory MFA (single-factor strength, unknown definition or non-MFA OR choice)' }
        if (-not (Test-CaPolicyTargetsAllResources $_)) { $reasons += 'does not cover all apps' }
        if (Test-CaPolicyHasNarrowingConditions $_ @('ModernClients')) { $reasons += 'only applies under extra platform, location, risk, device or client-app conditions' }
        "'{0}' ({1})" -f $_.DisplayName, ($reasons -join '; ')
    }) -join '; ')
    $notCountedSentence = if ($notCountedText) { " Enabled MFA policies not counted: $notCountedText." } else { '' }

    $privUserIds = @{}; $privMapError = $null
    try { $privUserIds = Get-EAPrivilegedUserMap } catch { $script:PrivilegedUserMapIncomplete = $true; $privMapError = $_.Exception.Message }
    if ($null -eq $privUserIds) { $privUserIds = @{} }
    $privGapReasons = @()
    if ($privMapError) { $privGapReasons += ("the administrator list could not be built ({0})" -f $privMapError) }
    if ($script:PrivAssignmentsFailed) { $privGapReasons += 'active role assignments could not be read' }
    if ($script:PrivEligibilityAssignmentsFailed) { $privGapReasons += 'eligible (PIM) role assignments could not be read' }
    if ($privGapReasons.Count -eq 0 -and $script:PrivilegedUserMapIncomplete) { $privGapReasons += 'at least one role-assignable group could not be expanded' }
    if (($script:PrivAssignmentsFailed -or $script:PrivilegedUserMapIncomplete) -and $privUserIds.Count -eq 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Could not check whether administrators are covered by MFA policies' `
            -Evidence ("Per-administrator Conditional Access coverage was not assessed because {0}. Coverage is unknown, not confirmed." -f ($privGapReasons -join '; ')) `
            -WhyItMatters 'Without the list of administrators the audit cannot tell whether every privileged account must use multifactor authentication (MFA). A missing result here must not be read as a pass.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory plus group-membership read permissions (or retry after a transient failure) and re-run the capolicies check.' `
            -SourceFile $src -RuleId 'capolicies-admin-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }
    elseif ($script:PrivilegedUserMapIncomplete) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Some administrators could not be checked for MFA policy coverage' `
            -Evidence ("The administrator list is incomplete because {0}. The {1} evaluated; any others are unknown." -f ($privGapReasons -join '; '), (Format-EACount -Count $privUserIds.Count -One 'administrator account that could be read was' -Many 'administrator accounts that could be read were')) `
            -WhyItMatters 'Administrators the audit cannot see may be outside every multifactor authentication (MFA) or phishing-resistant policy.' `
            -RecommendedAction 'Grant RoleManagement.Read.Directory, Group.Read.All and Member.Read.Hidden as appropriate (or retry after a transient failure) and re-run the capolicies check.' `
            -SourceFile $src -RuleId 'capolicies-admin-coverage-incomplete' -ObjectType 'tenant' -CoverageGap
    }
    # True when $p would apply to the user if the user were not in its ExcludeUsers list, i.e. the
    # by-name exclusion is the only thing keeping this policy away from the user.
    function _AppliesIfNotExcludedByName($p, [string]$uid, $groups, $roles) {
        $cu = $p.Conditions.Users
        if (@($cu.ExcludeUsers) -notcontains $uid) { return $false }
        $shadow = [pscustomobject]@{ Conditions = [pscustomobject]@{ Users = [pscustomobject]@{
            IncludeUsers = $cu.IncludeUsers; ExcludeUsers = @($cu.ExcludeUsers | Where-Object { $_ -ne $uid })
            IncludeGroups = $cu.IncludeGroups; ExcludeGroups = $cu.ExcludeGroups
            IncludeRoles = $cu.IncludeRoles; ExcludeRoles = $cu.ExcludeRoles } } }
        return (Test-CaPolicyAppliesToUser -Policy $shadow -UserId $uid -GroupIds $groups -RoleTemplateIds $roles)
    }
    $uncovered = @(); $uncoveredPhish = @(); $unknownScope = @(); $evaluated = 0; $coveredCount = 0; $nameOnlyPolicies = @{}
    # Unknown strength metadata prevents a reliable negative administrator-coverage
    # conclusion. The explicit coverage finding above explains the omitted assessment.
    $adminIdsToAssess = if ($unknownStrengthPolicies.Count -gt 0) { @() } else { @($privUserIds.Keys) }
    foreach ($uid in $adminIdsToAssess) {
        $upn = if ($script:UserById -and $script:UserById.ContainsKey($uid)) { $script:UserById[$uid].UserPrincipalName } else { $uid }
        if (([string]$uid -in $allowedBgIds) -or ($upn -and ([string]$upn).ToLowerInvariant() -in $bg)) { continue }   # break-glass expected to be excluded
        $evaluated++   # count only non-break-glass admins, so the all-uncovered test below is correct
        $scope = Get-EAUserScopeIds $uid
        $adminRoles = [System.Collections.Generic.HashSet[string]]::new($scope.Roles)
        # foreach over the value itself, not @(): the map values are Lists created with
        # New-Object, and @() over such a list throws 'Argument types do not match' on some
        # pwsh 7.4 builds (the same pattern as the guests check).
        foreach ($a in $privUserIds[$uid]) { if ($a -and $a.RoleTemplateId) { [void]$adminRoles.Add([string]$a.RoleTemplateId) } }

        $covered = $false; $phishCovered = $false; $mfaMembershipUnknown = $false; $phishMembershipUnknown = $false
        foreach ($p in $mfaPolicies) {
            $cu = $p.Conditions.Users
            if (-not $scope.Known -and (@($cu.IncludeGroups | Where-Object { $_ }).Count -gt 0 -or @($cu.ExcludeGroups | Where-Object { $_ }).Count -gt 0)) { $mfaMembershipUnknown = $true; continue }
            if (Test-CaPolicyAppliesToUser $p $uid $scope.Groups $adminRoles) { $covered = $true; break }
        }
        foreach ($p in $phishPolicies) {
            $cu = $p.Conditions.Users
            if (-not $scope.Known -and (@($cu.IncludeGroups | Where-Object { $_ }).Count -gt 0 -or @($cu.ExcludeGroups | Where-Object { $_ }).Count -gt 0)) { $phishMembershipUnknown = $true; continue }
            if (Test-CaPolicyAppliesToUser $p $uid $scope.Groups $adminRoles) { $phishCovered = $true; break }
        }
        $unknownFor = @()
        if ($mfaMembershipUnknown -and -not $covered) { $unknownFor += 'MFA' }
        if ($phishMembershipUnknown -and -not $phishCovered) { $unknownFor += 'phishing-resistant MFA' }
        if ($unknownFor.Count -gt 0) { $unknownScope += [pscustomobject]@{ Account=$upn; UserId=[string]$uid; Reason=("group membership could not be resolved for {0}" -f ($unknownFor -join ' and ')) } }
        if ($covered) { $coveredCount++ }
        if (-not $covered -and -not $mfaMembershipUnknown) {
            $uncovered += [pscustomobject]@{ Account = $upn; UserId = [string]$uid }
            # Only relevant when emergency accounts are not confirmed: which all-apps MFA policies
            # would cover this administrator if it were not excluded by name?
            if ($bgUnconfirmed) {
                $byName = @($mfaPolicies | Where-Object { _AppliesIfNotExcludedByName -p $_ -uid ([string]$uid) -groups $scope.Groups -roles $adminRoles } | ForEach-Object { "'" + $_.DisplayName + "'" })
                if ($byName.Count -gt 0) { $nameOnlyPolicies[[string]$uid] = $byName }
            }
        }
        if (-not $phishCovered -and -not $phishMembershipUnknown) { $uncoveredPhish += [pscustomobject]@{ Account = $upn; UserId = [string]$uid } }
    }
    # Microsoft's guidance is to exclude the emergency-access (break-glass) accounts - usually Global
    # Administrators - by name from Conditional Access. Without a confirmed -BreakGlassUpns list, an
    # administrator whose ONLY reason for being outside MFA is such a by-name exclusion from an
    # otherwise applicable all-apps MFA policy may be one of them. As for the all-users baselines,
    # a few such accounts are reported as "not confirmed" (a High coverage gap, one step below the
    # Critical they would be if confirmed as ordinary admins - an admin excluded by name is also a
    # known attacker persistence trick) instead of a confirmed Critical. Guards: at most 5 accounts
    # (the same limit as the baselines), and at least one administrator must be covered by MFA - if
    # none is, this is not an emergency-account pattern and every uncovered admin stays Critical.
    $possibleBg = @()
    if ($bgUnconfirmed -and $coveredCount -gt 0 -and $nameOnlyPolicies.Count -gt 0 -and $nameOnlyPolicies.Count -le 5) {
        $possibleBg = @($uncovered | Where-Object { $nameOnlyPolicies.ContainsKey([string]$_.UserId) } | ForEach-Object {
            [pscustomobject]@{ Account = $_.Account; UserId = $_.UserId; ExcludedByNameFrom = ($nameOnlyPolicies[[string]$_.UserId] -join ', ') }
        })
        $uncovered = @($uncovered | Where-Object { -not $nameOnlyPolicies.ContainsKey([string]$_.UserId) })
    }
    $possibleBgIds = @($possibleBg | ForEach-Object { [string]$_.UserId })
    $phishUncoveredAll = $uncoveredPhish.Count
    $possibleBgNoPhish = @($uncoveredPhish | Where-Object { [string]$_.UserId -in $possibleBgIds })
    $uncoveredPhish = @($uncoveredPhish | Where-Object { [string]$_.UserId -notin $possibleBgIds })
    $possibleBgSentence = if ($possibleBg.Count -gt 0) {
        (" Not counted here: {0} ({1}); {2} reported separately as not confirmed." -f (Format-EACount -Count $possibleBg.Count -One 'administrator account excluded by name that may be an emergency account' -Many 'administrator accounts excluded by name that may be emergency accounts'), (_ListText @($possibleBg.Account) 5), $(if ($possibleBg.Count -eq 1) { 'it is' } else { 'they are' }))
    } else { '' }
    if ($unknownScope.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ('MFA policy coverage is unknown for {0} (group memberships unreadable)' -f (Format-EACount -Count $unknownScope.Count -One 'administrator' -Many 'administrators')) `
            -Evidence ("Coverage could not be determined for: {0}. Their group memberships could not be read, and the relevant policies include or exclude groups." -f (_ListText @($unknownScope.Account))) `
            -WhyItMatters 'Policies that include or exclude groups cannot be evaluated without membership data, so these administrators may or may not be required to use multifactor authentication (MFA).' `
            -RecommendedAction 'Restore read access to group memberships (GroupMember.Read.All / Group.Read.All) and re-run the capolicies check.' `
            -SourceFile $src -ResultRows $unknownScope -RuleId 'capolicies-admin-membership-unknown' -ObjectType 'tenant' -CoverageGap
    }
    $adminBgNote = if ($bg.Count -eq 0) { ' No emergency-access accounts were supplied with -BreakGlassUpns, so emergency accounts that hold admin roles (and should be excluded) cannot be told apart from other administrators here; re-run with -BreakGlassUpns to leave them out.' } else { $bgNote }
    # Severity is monotonic in the number of uncovered administrators: some OR all administrators
    # left out of every existing MFA policy is Critical (one rule id, so the trend follows the same
    # issue as it is fixed). Only when NO usable MFA policy exists at all does Security Defaults
    # matter: if it is confirmed OFF nothing forces admin MFA (Critical, same as above); if it is
    # ON (admins still get MFA from it) or unknown, the systemic finding stays High.
    if ($evaluated -gt 0 -and $mfaPolicies.Count -eq 0) {
        Add-EntraFinding -Severity $(if ($sdState -eq 'Off') { 'Critical' } else { 'High' }) -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No Conditional Access policy requires MFA for administrators across all apps' `
            -Evidence ("{0} checked (active and eligible, including through groups). No enabled policy that requires MFA or an authentication strength for all apps, without extra conditions, applies to {1}. {2}{3}{4}" -f (Format-EACount -Count $evaluated -One 'administrator account was' -Many 'administrator accounts were'), $(if ($evaluated -eq 1) { 'it' } else { 'any of them' }), $sdSentence, $notCountedSentence, $adminBgNote) `
            -WhyItMatters 'Administrators are the most valuable accounts to attackers. Without multifactor authentication (MFA), a stolen or guessed password is enough to take over the account and, with it, the tenant.' `
            -RecommendedAction 'Create and enable a Conditional Access policy that requires MFA (preferably phishing-resistant) for all administrator roles and all apps, excluding only the emergency-access accounts: Entra admin center > Entra ID > Conditional Access.' `
            -SourceFile $src -RuleId 'ENTRA-CA-ADMIN-MFA-NONE' -ObjectType 'Tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
    }
    elseif ($uncovered.Count -gt 0) {
        $uncoveredTitle = if ($uncovered.Count -eq $evaluated -and $evaluated -eq 1) { 'The only administrator account is outside every MFA policy' }
                          elseif ($uncovered.Count -eq $evaluated) { "All {0} administrator accounts are outside every MFA policy" -f $evaluated }
                          else { "{0} of {1} administrator accounts {2} not covered by any MFA policy" -f $uncovered.Count, $evaluated, $(if ($uncovered.Count -eq 1) { 'is' } else { 'are' }) }
        Add-EntraFinding -Severity 'Critical' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title $uncoveredTitle `
            -Evidence ("Administrators to whom no enabled all-apps MFA policy applies (excluded, or never included): {0}. All-apps MFA policies found: {1}.{2}{3}{4}" -f (_ListText @($uncovered.Account)), $mfaPolicies.Count, $notCountedSentence, $possibleBgSentence, $adminBgNote) `
            -WhyItMatters 'Conditional Access (CA) does not require multifactor authentication (MFA) for these administrator accounts, because every MFA policy either excludes them or does not include them. A stolen password for any of them could lead to tenant takeover.' `
            -RecommendedAction 'Remove these accounts from MFA policy exclusions, or add them to an MFA policy, in Entra admin center > Entra ID > Conditional Access. Only the emergency-access accounts should be excluded.' `
            -SourceFile $src -ResultRows $uncovered -RuleId 'ENTRA-CA-ADMIN-MFA-NOT-EFFECTIVE' -ObjectType 'Tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa' `
            -AffectedObjectIds @($uncovered | ForEach-Object { $_.UserId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount @($uncovered | ForEach-Object { $_.UserId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'identified administrators missing effective MFA policy coverage'
    }
    if ($possibleBg.Count -gt 0) {
        $pbTitle = if ($possibleBg.Count -eq 1) { '1 administrator is excluded from MFA by name and not confirmed as an emergency account' }
                   else { "{0} administrators are excluded from MFA by name and not confirmed as emergency accounts" -f $possibleBg.Count }
        $pbPhish = if ($possibleBgNoPhish.Count -gt 0) { $(if ($possibleBg.Count -eq 1) { ' It is also left out of the phishing-resistant MFA result.' } else { ' They are also left out of the phishing-resistant MFA result.' }) } else { '' }
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title $pbTitle `
            -Evidence ("Administrators outside every all-apps MFA policy only because a policy excludes them by name: {0}. {1}, so the audit cannot tell whether they are your emergency (break-glass) accounts or administrators who can sign in without MFA. Result: not confirmed (neither passed nor failed). {2} covered by an MFA policy.{3}" -f (_ListText @($possibleBg | ForEach-Object { "{0} (excluded in {1})" -f $_.Account, $_.ExcludedByNameFrom }) 5), $bgWhyUnknown, (Format-EACount -Count $coveredCount -One 'other administrator account is' -Many 'other administrator accounts are'), $pbPhish) `
            -WhyItMatters 'If one of these accounts is not an emergency-access (break-glass) account, it is an administrator who can sign in with just a password. Excluding an administrator by name is also a known way for attackers to keep access.' `
            -RecommendedAction 'Re-run the audit with -BreakGlassUpns listing your emergency accounts. If an account is not an emergency account, remove its exclusion in Entra admin center > Entra ID > Conditional Access.' `
            -SourceFile $src -ResultRows $possibleBg -RuleId 'capolicies-admin-mfa-unconfirmed-exclusions' -ObjectType 'tenant' -CoverageGap `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access'
    }

    if ($evaluated -gt 0 -and ($phishPolicies.Count -eq 0 -or $phishUncoveredAll -eq $evaluated)) {
        $pbNone = if ($possibleBgNoPhish.Count -gt 0) { (" {0} (not confirmed)." -f (Format-EACount -Count $possibleBgNoPhish.Count -One 'of them is excluded from MFA by name and may be an emergency account' -Many 'of them are excluded from MFA by name and may be emergency accounts')) } else { '' }
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'No administrator is required to use phishing-resistant MFA' `
            -Evidence ("{0} covered by an enabled all-apps policy that requires a phishing-resistant authentication strength (FIDO2 security key, Windows Hello for Business or certificate-based MFA). Such policies found: {1}.{2}{3}" -f $(if ($evaluated -eq 1) { 'The 1 administrator account checked is not' } else { 'None of the {0} administrator accounts checked is' -f $evaluated }), $phishPolicies.Count, $pbNone, $adminBgNote) `
            -WhyItMatters 'Ordinary MFA (app notifications, codes, text messages) can be defeated by fake sign-in pages that relay the session, or by users approving repeated prompts. Phishing-resistant methods stop this for the accounts that matter most.' `
            -RecommendedAction 'Create a Conditional Access policy for all administrator roles and all apps that requires the built-in "Phishing-resistant MFA" authentication strength, excluding only the emergency-access accounts.' `
            -SourceFile $src -RuleId 'ENTRA-CA-ADMIN-PHISH-RESISTANT-NONE' -ObjectType 'Tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
    } elseif ($uncoveredPhish.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title ("{0} of {1} administrator accounts {2} not required to use phishing-resistant MFA" -f $uncoveredPhish.Count, $evaluated, $(if ($uncoveredPhish.Count -eq 1) { 'is' } else { 'are' })) `
            -Evidence ("Administrators without an applicable all-apps phishing-resistant authentication-strength policy: {0}.{1}{2}" -f (_ListText @($uncoveredPhish.Account)), $(if ($possibleBgNoPhish.Count -gt 0) { (" Not counted here: {0} ({1}), reported separately as not confirmed." -f (Format-EACount -Count $possibleBgNoPhish.Count -One 'administrator account excluded from MFA by name that may be an emergency account' -Many 'administrator accounts excluded from MFA by name that may be emergency accounts'), (_ListText @($possibleBgNoPhish.Account) 5)) } else { '' }), $adminBgNote) `
            -WhyItMatters 'A single administrator left on phishable MFA (codes, app notifications, text messages) can become the easiest path to taking over the tenant.' `
            -RecommendedAction 'Remove the scope gaps or exclusions and require the "Phishing-resistant MFA" authentication strength for these administrators in Entra admin center > Entra ID > Conditional Access.' `
            -SourceFile $src -ResultRows $uncoveredPhish -RuleId 'ENTRA-CA-ADMIN-PHISH-RESISTANT-PARTIAL' -ObjectType 'Tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa' `
            -AffectedObjectIds @($uncoveredPhish | ForEach-Object { $_.UserId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount @($uncoveredPhish | ForEach-Object { $_.UserId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'identified administrators missing phishing-resistant policy coverage'
    }

    if ($script:Findings.Where({$_.CheckId -eq 'capolicies'}).Count -eq 0) {
        $checkedList = @('MFA for all users','legacy-authentication block','device-code block','compliant or hybrid-joined device','MFA and phishing-resistant MFA for administrators')
        if ($script:HasP2) { $checkedList += 'sign-in-risk and user-risk policies' }
        if ($script:WorkloadIdP) { $checkedList += 'workload-identity location and risk policies' }
        Add-EntraFinding -Severity 'Information' -CheckId 'capolicies' -Category 'Tenant Posture' `
            -Title 'Conditional Access baseline policies are in place' `
            -Evidence ("{0}. Baselines checked and found effective: {1}." -f (Format-EACount -Count $enabled.Count -One 'enabled policy' -Many 'enabled policies'), ($checkedList -join ', ')) `
            -WhyItMatters 'A complete Conditional Access (CA) baseline enforces MFA, blocks old sign-in protocols and limits risky sign-ins for everyone.' `
            -RecommendedAction 'Keep the baseline and review policy exclusions regularly; extend coverage (for example risk-based policies with Entra ID P2) as licences allow.' `
            -SourceFile $src -ResultRows $rows -RuleId 'capolicies-baselines-in-place' -ObjectType 'tenant'
    }
}
