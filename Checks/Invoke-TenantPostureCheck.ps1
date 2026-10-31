<#
Security Defaults & Consent Settings. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-TenantPosture {
    # Track read success per source: a swallowed read must not evaluate as "setting is
    # fine" (false clean) or as "zero CA policies" (false High).
    $sd = $null;    $sdError = $null;    try { $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop } catch { $sdError = $_.Exception.Message }
    $authz = $null; $authzError = $null; try { $authz = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop | Select-Object -First 1 } catch { $authzError = $_.Exception.Message }
    $caCount = 0;   $caTotal = 0; $caError = $null
    try { $caAll = @(Get-EACaPolicies); $caTotal = $caAll.Count; $caCount = @($caAll | Where-Object { $_.State -eq 'enabled' }).Count } catch { $caError = $_.Exception.Message }
    if (-not $sd -and -not $sdError) { $sdError = 'the read returned no object' }
    if (-not $authz -and -not $authzError) { $authzError = 'the read returned no object' }
    $sdKnown = -not $sdError; $authzKnown = -not $authzError; $caKnown = -not $caError

    $rows = @()
    if ($sd)    { $rows += [pscustomobject]@{ Setting='Security Defaults enabled'; Value=$sd.IsEnabled } }
    if ($caKnown) { $rows += [pscustomobject]@{ Setting='Enabled Conditional Access policies'; Value=$caCount } }
    if ($authz) {
        $rows += [pscustomobject]@{ Setting='Users may create app registrations'; Value=$authz.DefaultUserRolePermissions.AllowedToCreateApps }
        $rows += [pscustomobject]@{ Setting='Users may create security groups';   Value=$authz.DefaultUserRolePermissions.AllowedToCreateSecurityGroups }
        $rows += [pscustomobject]@{ Setting='Users may create tenants';           Value=$authz.DefaultUserRolePermissions.AllowedToCreateTenants }
        $rows += [pscustomobject]@{ Setting='Users may read other users';         Value=$authz.DefaultUserRolePermissions.AllowedToReadOtherUsers }
        $rows += [pscustomobject]@{ Setting='Email-verified users may join';      Value=$authz.AllowEmailVerifiedUsersToJoinOrganization }
        $rows += [pscustomobject]@{ Setting='AllowInvitesFrom';                   Value=$authz.AllowInvitesFrom }
        $rows += [pscustomobject]@{ Setting='User consent allowed for risky apps';Value=$authz.AllowUserConsentForRiskyApps }
        $rows += [pscustomobject]@{ Setting='PermissionGrantPoliciesAssigned';    Value=($authz.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned -join ',') }
    }
    $notes = @()
    if ($sdError)    { $notes += ("Security Defaults could not be read: {0}" -f $sdError) }
    if ($authzError) { $notes += ("Authorization policy could not be read: {0}" -f $authzError) }
    if ($caError)    { $notes += ("Conditional Access policies could not be read: {0}" -f $caError) }
    $src = Write-Evidence -BaseName 'tenant_posture' -Rows $rows -Title 'Security Defaults, Authorization & Consent Settings' -Notes $notes

    # "Nothing enforces MFA" is the same fact the Conditional Access check rates (capolicies-no-
    # policies, Critical with Security Defaults off; or capolicies-no-mfa-baseline, High, when
    # policies exist but none is on). When -capolicies is part of this run it runs after this
    # check on the same cached, successfully read policy list and always raises one of those,
    # so this check records an Information pointer instead of scoring the gap a second time.
    # Run on its own (or with the run selection unknown, e.g. offline), or when -capolicies
    # already ran in this run and was skipped or stopped with an error, it keeps the High.
    $caCheckStatus = if ($script:CheckStatus -and $script:CheckStatus.Contains('capolicies')) { [string]$script:CheckStatus['capolicies'].Status } else { '' }
    $caCheckInRun = (@(Get-EAField $script:RunInfo 'SelectedChecks') -contains 'capolicies') -and ($caCheckStatus -notmatch '^(Skipped|Error)')
    if ($sd -and -not $sd.IsEnabled -and $caKnown -and $caCount -eq 0 -and $caCheckInRun) {
        Add-EntraFinding -Severity 'Information' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-no-mfa-baseline-see-capolicies' `
            -Title 'Security defaults are off and no Conditional Access policy is on - see Conditional Access' `
            -Evidence ("Security Defaults isEnabled = false and {0}. The Conditional Access Posture check (-capolicies) in this run rates this gap, so it is not counted twice in the risk score." -f $(if ($caTotal -eq 0) { 'no Conditional Access policies exist' } elseif ($caTotal -eq 1) { 'the only Conditional Access policy is not in the enabled state (it is off or report-only)' } else { 'none of the {0} Conditional Access policies is in the enabled state (they are off or report-only)' -f $caTotal })) `
            -WhyItMatters 'Nothing in the tenant enforces multifactor authentication (MFA), so a password alone is enough to sign in. The risk is scored once, by the Conditional Access check.' `
            -RecommendedAction 'Act on the Conditional Access Posture findings: create Conditional Access policies that require MFA, or turn on security defaults as a stop-gap (Entra admin center > Entra ID > Overview > Properties > Manage security defaults).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults' -SourceFile $src
    } elseif ($sd -and -not $sd.IsEnabled -and $caKnown -and $caCount -eq 0) {
        Add-EntraFinding -Severity 'High' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-no-mfa-baseline' `
            -Title 'Security defaults are off and no Conditional Access policy is turned on' `
            -Evidence 'Security Defaults isEnabled = false and 0 Conditional Access policies are in the enabled state.' `
            -WhyItMatters 'Neither security defaults nor Conditional Access (CA) is enforcing multifactor authentication (MFA), so accounts can be signed in to with a password alone - the most common way accounts are taken over.' `
            -RecommendedAction 'Create Conditional Access policies that require MFA (preferred when the tenant has Entra ID P1), or turn on security defaults as a stop-gap (Entra admin center > Entra ID > Overview > Properties > Manage security defaults).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults' -SourceFile $src
    } elseif ($sd -and -not $sd.IsEnabled -and -not $caKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-mfa-baseline-unknown' -CoverageGap `
            -Title 'Could not tell whether MFA is enforced - Conditional Access policies could not be read' `
            -Evidence ("Security Defaults isEnabled = false and the Conditional Access policy read failed: {0}. Whether any baseline MFA enforcement exists is unknown." -f $caError) `
            -WhyItMatters 'With security defaults off, Conditional Access (CA) is the only thing that can enforce multifactor authentication (MFA). Because the policies could not be read, this was not checked.' `
            -RecommendedAction 'Grant Policy.Read.All to the audit account or app and run the check again.' -SourceFile $src
    } elseif ($sd -and $sd.IsEnabled -and $caKnown -and $caCount -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-security-defaults-with-ca' `
            -Title 'Security defaults are on while Conditional Access policies also exist' `
            -Evidence ("Security Defaults isEnabled = true and {0} enabled." -f (Format-EACount -Count $caCount -One 'Conditional Access policy is' -Many 'Conditional Access policies are')) `
            -WhyItMatters 'Security defaults and Conditional Access (CA) are not meant to be used together. Running both suggests the move to CA was never finished, so the fine-grained CA controls may not work as intended.' `
            -RecommendedAction 'Finish the move to Conditional Access: make sure CA policies cover MFA and block legacy authentication, then turn security defaults off.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults' -SourceFile $src
    }
    if ($authz) {
        if ($authz.DefaultUserRolePermissions.AllowedToCreateApps) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-users-can-register-apps' `
                -Title 'Any user can register applications' `
                -Evidence 'defaultUserRolePermissions.allowedToCreateApps = true.' `
                -WhyItMatters 'Every user can create app registrations that nobody reviews. Such apps can be used for phishing that asks for consent to data, or grow into unmanaged "shadow IT".' `
                -RecommendedAction 'Set "Users can register applications" to No (Entra admin center > Entra ID > Users > User settings) and route app registration through a request and approval process.' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions' -SourceFile $src
        }
        if ($authz.AllowEmailVerifiedUsersToJoinOrganization) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-email-verified-self-join' `
                -Title 'People can join the tenant themselves by verifying an email address' `
                -Evidence 'allowEmailVerifiedUsersToJoinOrganization = true.' `
                -WhyItMatters 'Anyone with an email address on one of your domains can create an account in the tenant without being invited or approved.' `
                -RecommendedAction 'Turn off email-verified self-service sign-up unless you rely on it. There is no admin-center switch for this setting: in Microsoft Graph PowerShell run Update-MgPolicyAuthorizationPolicy -BodyParameter @{ allowEmailVerifiedUsersToJoinOrganization = $false }.' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/users/directory-self-service-signup' -SourceFile $src
        }
        $pg = @($authz.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)
        if ($pg -match 'legacy') {
            Add-EntraFinding -Severity 'High' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-user-consent-legacy' `
                -Title 'Users can give any application access to their data' `
                -Evidence ("permissionGrantPoliciesAssigned = {0} (the legacy, unrestricted user-consent policy)." -f ($pg -join ',')) `
                -WhyItMatters 'With unrestricted user consent, a phishing app only needs one click from a user to get lasting access to that user''s mail and files - no password needed.' `
                -RecommendedAction 'Allow user consent only for apps from verified publishers asking for low-risk permissions (or not at all), and turn on the admin consent request workflow (Entra admin center > Entra ID > Enterprise apps > Consent and permissions).' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent' -SourceFile $src
        }
    }
    # A failed Conditional Access read is a gap here too - with Security Defaults on (or
    # unknown) the "Security Defaults and CA both in use" rule could not be evaluated. With
    # Security Defaults off it is already reported by tenantposture-mfa-baseline-unknown.
    $caCovered = [bool]($sd -and -not $sd.IsEnabled)
    if (-not $sdKnown -or -not $authzKnown -or (-not $caKnown -and -not $caCovered)) {
        $failed = @()
        if (-not $sdKnown) { $failed += ('Security Defaults setting ({0})' -f $sdError) }
        if (-not $authzKnown) { $failed += ('authorization policy - app registration, self-service sign-up and user consent ({0})' -f $authzError) }
        if (-not $caKnown -and -not $caCovered) { $failed += ('Conditional Access policies ({0})' -f $caError) }
        Add-EntraFinding -Severity 'Information' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-settings-unreadable' -CoverageGap `
            -Title 'Some tenant security settings could not be read' `
            -Evidence ("Could not read: {0}. These settings are unknown, not confirmed safe." -f ($failed -join '; ')) `
            -WhyItMatters 'The unread settings decide basic protections such as MFA enforcement and who may register or consent to apps. They were not checked.' `
            -RecommendedAction 'Grant Policy.Read.All to the audit account or app and run the check again.' -SourceFile $src
    } elseif ($script:Findings.Where({$_.CheckId -eq 'tenantposture'}).Count -eq 0) {
        # State only what was read: an enabled CA policy does not by itself prove MFA is
        # required (it may only block a country) - that is the capolicies check's job.
        $baseline = if ($sd.IsEnabled) { 'Security defaults are turned on.' }
                    elseif ($caCount -eq 1) { '1 Conditional Access policy is turned on (whether it requires MFA is checked separately by the Conditional Access Posture check).' }
                    else { '{0} Conditional Access policies are turned on (whether they require MFA is checked separately by the Conditional Access Posture check).' -f $caCount }
        Add-EntraFinding -Severity 'Information' -CheckId 'tenantposture' -Category 'Tenant Posture' -RuleId 'tenantposture-defaults-restrictive' `
            -Title 'Tenant default permissions and consent settings are restrictive' `
            -Evidence ('App registration by users, email-verified self-join and unrestricted user consent are all turned off. {0}' -f $baseline) `
            -WhyItMatters 'Restrictive defaults reduce the risk of consent phishing and unmanaged apps.' `
            -RecommendedAction 'No action needed. Review these settings periodically.' -SourceFile $src
    }
}
