<#
PIM Role-Management Policy Quality. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-PimPolicies {
    Get-EARoleDefMap | Out-Null
    # scopeType for Entra directory-role policies is 'DirectoryRole' on most tenants but
    # 'Directory' on some - try the documented value first, fall back to the other.
    function _FetchPim([string]$scopeType) {
        $u = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq '$scopeType'&`$expand=policy(`$expand=rules)"
        $acc = @(); $g = 0
        while ($u -and $g -lt 50) {
            $u = Assert-EAGraphReadUri $u
            $r = Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop
            if ($r['value']) { $acc += @($r['value']) }
            $u = $r['@odata.nextLink']; $g++
        }
        if ($u) { throw 'Microsoft Graph PIM-policy pagination exceeded the 50-page safety limit.' }
        return $acc
    }
    $scopeUsed = 'DirectoryRole'
    $assignments = @()
    $firstScopeError = $null
    try { $assignments = @(_FetchPim 'DirectoryRole') } catch { $firstScopeError = $_ }
    if ($assignments.Count -eq 0) {
        $scopeUsed = 'Directory'
        try { $assignments = @(_FetchPim 'Directory') } catch { if ($firstScopeError) { throw $firstScopeError }; throw }
    }

    # Every reason a PIM rule could come back UNKNOWN is recorded here and repeated in the
    # evidence of the "could not be fully read" finding, so the reader sees WHY.
    $unknownCauses = @()
    $scopeNote = if ($firstScopeError) { ("The scopeType 'DirectoryRole' query failed ({0}); the 'Directory' fallback was used." -f $firstScopeError.Exception.Message) } else { $null }

    # Authentication context is a valid MFA substitute only when the referenced context is
    # available AND an enabled CA policy actually protects that context with mandatory MFA /
    # authentication strength. Merely seeing isEnabled=true on the PIM rule is insufficient.
    $authContextDefinitions = @{}; $authContextDefinitionsKnown = $true
    try {
        $u = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences'; $guard = 0
        while ($u -and $guard -lt 20) {
            $u = Assert-EAGraphReadUri $u
            $resp = Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop
            foreach ($d in @($resp['value'])) { if ($d['id']) { $authContextDefinitions[[string]$d['id']] = $d } }
            $u = $resp['@odata.nextLink']; $guard++
        }
        if ($u) { throw 'Microsoft Graph authentication-context pagination exceeded the 20-page safety limit.' }
    } catch {
        $authContextDefinitionsKnown = $false
        $unknownCauses += ("authentication contexts could not be read ({0})" -f $_.Exception.Message)
    }
    $caKnown = $true; $enabledCa = @()
    try { $enabledCa = @(Get-EACaPolicies | Where-Object { $_.State -eq 'enabled' }) } catch {
        $caKnown = $false
        $unknownCauses += ("Conditional Access policies could not be read ({0})" -f $_.Exception.Message)
    }
    # Break-glass ids are only used to accept an otherwise all-users CA policy that excludes
    # the designated emergency accounts. If they cannot be resolved such a policy evaluates
    # as 'Unknown-ScopedUserCoverage' (never as valid) - record why.
    $pimBgIds = @(); $pimBg = Normalize-StringList -Values $BreakGlassUpns
    if ($pimBg.Count -gt 0) {
        try { foreach ($u0 in @(Get-EAUsers)) { if ($u0.Id -and $u0.UserPrincipalName -and $u0.UserPrincipalName.ToLowerInvariant() -in $pimBg) { $pimBgIds += [string]$u0.Id } } }
        catch { $unknownCauses += ("break-glass accounts could not be resolved ({0}), so CA policies excluding them count as scoped" -f $_.Exception.Message) }
    }

    function _ValidateAuthContext([string]$claimValue) {
        if (-not $claimValue) { return 'Invalid-NoClaimValue' }
        if (-not $authContextDefinitionsKnown -or -not $caKnown) { return 'Unknown' }
        if (-not $authContextDefinitions.ContainsKey($claimValue) -or -not [bool]$authContextDefinitions[$claimValue]['isAvailable']) { return 'Invalid-Unavailable' }
        $matchingScopedPolicy = $false; $unknownStrength = $false
        foreach ($p in $enabledCa) {
            $refs = @((Get-EAField $p.Conditions.Applications 'IncludeAuthenticationContextClassReferences') | Where-Object { $_ })
            if ($refs -contains $claimValue -and -not (Test-CaPolicyStrengthKnown $p)) { $unknownStrength = $true; continue }
            if ($refs -contains $claimValue -and
                (Test-CaPolicyRequiresMfaOrStrength $p) -and
                -not (Test-CaPolicyHasNarrowingConditions $p @('ModernClients'))) {
                if (Test-CaPolicyTargetsAllUsers -Policy $p -AllowedExcludedUserIds $pimBgIds) { return 'Valid' }
                $matchingScopedPolicy = $true
            }
        }
        if ($unknownStrength) { return 'Unknown-AuthenticationStrength' }
        if ($matchingScopedPolicy) { return 'Unknown-ScopedUserCoverage' }
        return 'Invalid-NoProtectingCAPolicy'
    }

    $rows = @()
    $noMfaCrit = @(); $noMfaHigh = @(); $noJust = @(); $noApproval = @(); $longDur = @(); $permActiveRoles = @(); $permEligRoles = @()
    $unknownRules = @(); $badAuthContexts = @()

    foreach ($pa in $assignments) {
        $rdId = [string]$pa['roleDefinitionId']
        $ri = Get-EARoleInfo -RoleDefinitionId $rdId
        if (-not $ri.IsPrivileged) { continue }
        $roleName = $ri.Name
        $isGAorPRA = ($ri.IsTier0 -or $roleName -match 'Privileged Role Administrator|Privileged Authentication')

        $rules = @()
        if ($pa['policy'] -and $pa['policy']['rules']) { $rules = @($pa['policy']['rules']) }
        $mfa = $null; $just = $null; $appr = $null; $maxH = $null; $permA = $null; $permE = $null
        $authCtxEnabled = $null; $authCtxClaim = $null
        foreach ($r in $rules) {
            $rid = [string]$r['id']
            switch -Regex ($rid) {
                'Enablement_EndUser_Assignment' {
                    if ($r.ContainsKey('enabledRules') -and $null -ne $r['enabledRules']) {
                        $en = @($r['enabledRules']); $mfa = ($en -contains 'MultiFactorAuthentication'); $just = ($en -contains 'Justification')
                    }
                }
                # Requiring a Conditional Access AUTHENTICATION CONTEXT on activation is
                # mutually exclusive with the MultiFactorAuthentication enablement value
                # (the portal removes MFA from the enablement rule when auth context is
                # selected) and is typically the STRONGER control - it must not be
                # reported as "can be activated without MFA".
                'AuthenticationContext_EndUser_Assignment' {
                    if ($r.ContainsKey('isEnabled')) { $authCtxEnabled = [bool]$r['isEnabled'] }
                    $authCtxClaim = [string]$r['claimValue']
                }
                'Approval_EndUser_Assignment'   { if ($r['setting']) { $appr = [bool]$r['setting']['isApprovalRequired'] } }
                'Expiration_EndUser_Assignment' {
                    # ISO-8601 durations also come in day form (P1D) and mixed form
                    # (P1DT2H / PT8H30M) - XmlConvert parses them all; the regex stays
                    # as a fallback only.
                    $d = [string]$r['maximumDuration']
                    if ($d) {
                        try { $maxH = [math]::Round(([System.Xml.XmlConvert]::ToTimeSpan($d)).TotalHours, 1) }
                        catch {
                            if ($d -match 'PT(\d+)H') { $maxH = [int]$matches[1] } elseif ($d -match 'PT(\d+)M') { $maxH = [math]::Round(([int]$matches[1]/60),1) }
                        }
                    }
                }
                'Expiration_Admin_Assignment'   { if ($r.ContainsKey('isExpirationRequired')) { $permA = (-not [bool]$r['isExpirationRequired']) } }
                'Expiration_Admin_Eligibility'  { if ($r.ContainsKey('isExpirationRequired')) { $permE = (-not [bool]$r['isExpirationRequired']) } }
            }
        }
        $authCtxStatus = if ($authCtxEnabled -eq $true) { _ValidateAuthContext $authCtxClaim } elseif ($authCtxEnabled -eq $false) { 'Disabled' } else { 'NotConfigured' }
        $authCtxValid = ($authCtxStatus -eq 'Valid')
        $rows += [pscustomobject]@{
            Role=$roleName; RoleDefinitionId=$ri.RoleDefinitionId; RoleTemplateId=$ri.TemplateId
            MfaOnActivation=$mfa; AuthContextEnabled=$authCtxEnabled; AuthContextClaim=$authCtxClaim; AuthContextValidation=$authCtxStatus
            JustificationRequired=$just; ApprovalRequired=$appr; MaxActivationHours=$maxH
            PermanentActiveAllowed=$permA; PermanentEligibleAllowed=$permE
        }

        if ($authCtxEnabled -eq $true -and $authCtxStatus -ne 'Valid' -and $authCtxStatus -notlike 'Unknown*') { $badAuthContexts += ("{0} ({1}: {2})" -f $roleName, ($authCtxClaim ?? 'no claim'), $authCtxStatus) }
        if ($mfa -eq $false -and -not $authCtxValid -and $authCtxStatus -notlike 'Unknown*') { if ($isGAorPRA) { $noMfaCrit += $roleName } else { $noMfaHigh += $roleName } }
        if ($isGAorPRA -and $just -eq $false) { $noJust += $roleName }
        if ($isGAorPRA -and $appr -eq $false) { $noApproval += $roleName }
        if ($maxH -and $maxH -gt 8) { $longDur += ("{0} ({1}h)" -f $roleName, $maxH) }
        if ($permA -eq $true) { $permActiveRoles += $roleName }
        if ($permE -eq $true) { $permEligRoles += $roleName }
        $unknown = @()
        if ($null -eq $mfa -and -not $authCtxValid) { $unknown += 'MFA/auth-context requirement' }
        if ($authCtxStatus -like 'Unknown*') { $unknown += 'authentication-context availability/CA enforcement' }
        if ($isGAorPRA -and $null -eq $just) { $unknown += 'justification' }
        if ($isGAorPRA -and $null -eq $appr) { $unknown += 'approval' }
        if ($null -eq $maxH) { $unknown += 'maximum activation duration' }
        if ($null -eq $permA) { $unknown += 'active-assignment expiration' }
        if ($null -eq $permE) { $unknown += 'eligible-assignment expiration' }
        if ($unknown.Count -gt 0) { $unknownRules += ("{0}: {1}" -f $roleName, ($unknown -join ', ')) }
    }
    $pimNotes = @("Policy scopeType used: $scopeUsed")
    if ($scopeNote) { $pimNotes += $scopeNote }
    if ($unknownCauses.Count -gt 0) { $pimNotes += ('Unknown inputs: ' + ($unknownCauses -join '; ')) }
    $src = Write-Evidence -BaseName 'pim_policies' -Rows $rows -Title 'PIM Role-Management Policy Rules (privileged roles)' -Notes $pimNotes
    $pimDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
    $pimPath = 'Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles > Roles > (role) > Role settings'
    # Short "a, b, c (+N more)" list for Evidence; the full list is always in the evidence file.
    function _ListText([string[]]$Items, [int]$Max = 12) {
        $all = @($Items | Where-Object { $_ })
        $text = (@($all | Select-Object -First $Max)) -join '; '
        if ($all.Count -gt $Max) { $text += (' (+{0} more - see the evidence file)' -f ($all.Count - $Max)) }
        return $text
    }

    if ($rows.Count -eq 0) {
        $whyEmpty = if ($firstScopeError) { (' The scopeType DirectoryRole query failed: {0}.' -f $firstScopeError.Exception.Message) } else { '' }
        Add-EntraFinding -Severity 'Information' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title 'PIM activation settings for admin roles could not be checked' `
            -Evidence ("No PIM role settings (role-management policies) were returned for any privileged role (scopeType tried: DirectoryRole, Directory).{0} Needs Microsoft Entra ID P2 and RoleManagementPolicy.Read.Directory. Status is unknown, not clean." -f $whyEmpty) `
            -WhyItMatters 'Privileged Identity Management (PIM) settings decide whether an admin needs MFA, approval and a time limit before admin rights switch on. Without reading them the audit cannot tell whether those safeguards exist.' `
            -RecommendedAction 'Confirm the tenant has Entra ID P2, grant RoleManagementPolicy.Read.Directory (read-only) to the audit identity, then re-run the pimpolicies check.' `
            -SourceFile $src -RuleId 'pimpolicies-not-assessed' -ObjectType 'tenant' -DocumentationUrl $pimDoc -CoverageGap
        return
    }
    if ($badAuthContexts.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ((Format-EACount -Count $badAuthContexts.Count -One 'admin role uses' -Many 'admin roles use') + ' a PIM authentication context that does not actually enforce MFA') `
            -Evidence ("Roles whose PIM activation relies on an authentication context that is unavailable or not bound to an enabled, all-users Conditional Access policy requiring MFA: {0}" -f (_ListText $badAuthContexts)) `
            -WhyItMatters 'PIM can require a Conditional Access (CA) authentication context instead of MFA. That only protects the role if the context exists and an enabled CA policy demands MFA for it; otherwise the role can be activated without the extra check you intended.' `
            -RecommendedAction 'In Entra admin center > Entra ID > Conditional Access > Authentication contexts, make the context available and bind it to an enabled all-users CA policy that requires MFA (ideally phishing-resistant). Otherwise turn on "On activation, require multifactor authentication" for the role in PIM.' `
            -SourceFile $src -RuleId 'pimpolicies-auth-context-not-enforced' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($unknownRules.Count -gt 0) {
        $causeText = if ($unknownCauses.Count -gt 0) { (' Why: {0}.' -f ($unknownCauses -join '; ')) } else { '' }
        Add-EntraFinding -Severity 'Medium' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ("PIM settings for {0} could not be fully read" -f (Format-EACount -Count $unknownRules.Count -One 'admin role' -Many 'admin roles')) `
            -Evidence ("Settings that are missing or unreadable (treated as unknown, not as safe): {0}.{1}" -f (_ListText $unknownRules), $causeText) `
            -WhyItMatters 'When a PIM setting is missing from the Microsoft Graph response, the audit cannot tell whether that safeguard (MFA, approval, time limit) is on. It is reported as unknown so an incomplete read never looks like a pass.' `
            -RecommendedAction ("Open {0} for each listed role and confirm MFA, approval, justification, activation time and expiration are set explicitly; then re-run the pimpolicies check." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-rules-unreadable' -ObjectType 'tenant' -DocumentationUrl $pimDoc -CoverageGap
    }
    if ($noMfaCrit.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ((Format-EACount -Count $noMfaCrit.Count -One 'top-level admin role' -Many 'top-level admin roles') + ' can be activated in PIM without MFA') `
            -Evidence ("Top-tier roles whose activation requires neither MFA nor a working authentication context: {0}" -f (_ListText $noMfaCrit)) `
            -WhyItMatters 'Roles such as Global Administrator and Privileged Role Administrator control the whole tenant. If Privileged Identity Management (PIM) lets them be activated without multifactor authentication (MFA), a stolen password alone is enough to take over the tenant.' `
            -RecommendedAction ("In {0}, edit each listed role and turn on ""On activation, require multifactor authentication"" (better: a Conditional Access authentication context that requires phishing-resistant MFA)." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-top-tier-activation-no-mfa' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($noMfaHigh.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ((Format-EACount -Count $noMfaHigh.Count -One 'admin role' -Many 'admin roles') + ' can be activated in PIM without MFA') `
            -Evidence ("Privileged roles whose activation requires neither MFA nor a working authentication context: {0}" -f (_ListText $noMfaHigh)) `
            -WhyItMatters 'If Privileged Identity Management (PIM) lets an admin role be activated without multifactor authentication (MFA), anyone who steals an eligible admin''s password can switch on admin rights.' `
            -RecommendedAction ("In {0}, turn on ""On activation, require multifactor authentication"" for every listed role." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-activation-no-mfa' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($noApproval.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ((Format-EACount -Count $noApproval.Count -One 'top-level admin role' -Many 'top-level admin roles') + ' can be activated without anyone approving it') `
            -Evidence ("Top-tier roles without activation approval: {0}" -f (_ListText $noApproval)) `
            -WhyItMatters 'Without an approval step in Privileged Identity Management (PIM), one compromised eligible account can make itself Global Administrator (or similar) before anyone notices.' `
            -RecommendedAction ("In {0}, turn on ""Require approval to activate"" for the listed roles and name at least two approvers." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-top-tier-no-approval' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($noJust.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ((Format-EACount -Count $noJust.Count -One 'top-level admin role' -Many 'top-level admin roles') + ' can be activated without giving a reason') `
            -Evidence ("Top-tier roles that do not require a justification on activation: {0}" -f (_ListText $noJust)) `
            -WhyItMatters 'Asking for a reason (justification) when admin rights are switched on leaves an audit trail. Without it, investigating misuse of admin rights is much harder.' `
            -RecommendedAction ("In {0}, turn on ""Require justification on activation"" for the listed roles." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-top-tier-no-justification' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($longDur.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ((Format-EACount -Count $longDur.Count -One 'admin role' -Many 'admin roles') + ' can stay activated for more than 8 hours') `
            -Evidence ("Roles with a maximum activation time above 8 hours: {0}" -f (_ListText $longDur)) `
            -WhyItMatters 'The longer an activated admin role stays on, the longer a stolen session or token can be used with admin rights.' `
            -RecommendedAction ("In {0}, set ""Activation maximum duration"" to 8 hours or less for the listed roles." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-long-activation' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($permActiveRoles.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ((Format-EACount -Count $permActiveRoles.Count -One 'admin role allows' -Many 'admin roles allow') + ' permanent, always-on assignments') `
            -Evidence ("Roles whose PIM settings allow permanent active assignment (Expiration_Admin_Assignment.isExpirationRequired = false): {0}" -f (_ListText $permActiveRoles)) `
            -WhyItMatters 'Allowing permanent active assignments lets admins keep standing admin rights, which defeats the just-in-time protection of Privileged Identity Management (PIM).' `
            -RecommendedAction ("In {0}, on the Assignment tab, turn off ""Allow permanent active assignment"" for the listed roles and use eligible (just-in-time) assignments instead." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-permanent-active-allowed' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($permEligRoles.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title ((Format-EACount -Count $permEligRoles.Count -One 'admin role allows' -Many 'admin roles allow') + ' eligible assignments that never expire') `
            -Evidence ("Roles whose PIM settings allow permanent eligible assignment (Expiration_Admin_Eligibility.isExpirationRequired = false): {0}" -f (_ListText $permEligRoles)) `
            -WhyItMatters 'Eligibility that never expires builds up over time, so people keep the ability to become admin long after they need it.' `
            -RecommendedAction ("In {0}, on the Assignment tab, turn off ""Allow permanent eligible assignment"" and review eligible admins regularly with access reviews." -f $pimPath) `
            -SourceFile $src -RuleId 'pimpolicies-permanent-eligible-allowed' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
    if ($script:Findings.Where({$_.CheckId -eq 'pimpolicies'}).Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'pimpolicies' -Category 'Privileged Access' `
            -Title 'PIM activation settings for admin roles are strong' `
            -Evidence ("{0} reviewed: MFA (or an enforced authentication context) on activation, approval and justification for top-tier roles, activation of 8 hours or less, and expiring assignments are all in place." -f (Format-EACount -Count $rows.Count -One 'privileged role setting' -Many 'privileged role settings')) `
            -WhyItMatters 'Strong Privileged Identity Management (PIM) settings make just-in-time admin access safe to use.' `
            -RecommendedAction 'Keep these settings and re-check them after any PIM change.' `
            -SourceFile $src -ResultRows $rows -RuleId 'pimpolicies-baseline' -ObjectType 'tenant' -DocumentationUrl $pimDoc
    }
}
