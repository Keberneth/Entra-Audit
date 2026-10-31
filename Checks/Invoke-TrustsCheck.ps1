<#
Cross-Tenant Access & B2B Trust. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-Trusts {
    $checkId = 'trusts'; $category = 'External Access'
    $crossTenantDoc = 'https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-settings-b2b-collaboration'
    $portalPath = 'Entra admin center > External Identities > Cross-tenant access settings'

    # Both reads are tracked explicitly: a failed read must never surface as "0 partners"
    # or as "reviewed, nothing flagged".
    $def = $null; $defError = $null
    try { $def = Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction Stop } catch { $defError = $_.Exception.Message }
    $partners = @(); $partnersKnown = $true; $partnersError = $null
    try { $partners = @(Get-MgPolicyCrossTenantAccessPolicyPartner -All -ErrorAction Stop) } catch { $partnersKnown = $false; $partnersError = $_.Exception.Message }
    $partnerText = if ($partnersKnown) { Format-EACount -Count $partners.Count -One 'partner-specific configuration exists; it overrides the default only for that named organization.' -Many 'partner-specific configurations exist; they override the default only for those named organizations.' }
                   else { 'Partner-specific configurations could not be read, so how many organizations have their own settings is unknown.' }

    # Display-only enrichment: resolve partner tenant names (GET findTenantInformationByTenantId,
    # CrossTenantInformation.ReadBasic.All). A failed lookup only means the tenant id is shown.
    $partnerNames = @{}; $nameLookupFailed = $false
    foreach ($p in @($partners | Select-Object -First 50)) {
        $ptid = [string]$p.TenantId
        if ($nameLookupFailed -or $ptid -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { continue }
        try {
            $info = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='{0}')" -f $ptid) -ErrorAction Stop
            $pname = [string](Get-EAField $info 'displayName')
            if ($pname) { $partnerNames[$ptid] = $pname }
        } catch { $nameLookupFailed = $true }
    }

    # Read a nested setting; $null means "not set": on the DEFAULT policy that is shown as
    # '(not returned)', on a PARTNER entry it means the partner inherits the default.
    function _RawSetting {
        param($Container, [string[]]$Path)
        $v = $Container
        foreach ($segment in $Path) { if ($null -eq $v) { return $null }; $v = Get-EAField $v $segment }
        return $v
    }
    function _Setting {
        param($Container, [string[]]$Path, [string]$NullText)
        $v = _RawSetting -Container $Container -Path $Path
        if ($null -eq $v) { return $NullText }
        return $v
    }
    $settingMap = @(
        @{ Label='B2B collaboration inbound (users/groups)';      Path=@('B2bCollaborationInbound','UsersAndGroups','AccessType') }
        @{ Label='B2B collaboration inbound (applications)';      Path=@('B2bCollaborationInbound','Applications','AccessType') }
        @{ Label='B2B collaboration outbound (users/groups)';     Path=@('B2bCollaborationOutbound','UsersAndGroups','AccessType') }
        @{ Label='B2B direct connect inbound (users/groups)';     Path=@('B2bDirectConnectInbound','UsersAndGroups','AccessType') }
        @{ Label='B2B direct connect inbound (applications)';     Path=@('B2bDirectConnectInbound','Applications','AccessType') }
        @{ Label='B2B direct connect outbound (users/groups)';    Path=@('B2bDirectConnectOutbound','UsersAndGroups','AccessType') }
        @{ Label='Inbound trust: MFA accepted';                   Path=@('InboundTrust','IsMfaAccepted') }
        @{ Label='Inbound trust: compliant device accepted';      Path=@('InboundTrust','IsCompliantDeviceAccepted') }
        @{ Label='Inbound trust: hybrid-joined device accepted';  Path=@('InboundTrust','IsHybridAzureADJoinedDeviceAccepted') }
        @{ Label='Automatic inbound user consent (redemption)';   Path=@('AutomaticUserConsentSettings','InboundAllowed') }
    )

    $rows = New-Object System.Collections.Generic.List[object]
    if ($def) {
        $rows.Add([pscustomobject]@{ Scope='Default (all other organizations)'; Setting='Microsoft default settings unchanged (isServiceDefault)'; Value=(_Setting -Container $def -Path @('IsServiceDefault') -NullText '(not returned)') }) | Out-Null
        foreach ($s in $settingMap) {
            $rows.Add([pscustomobject]@{ Scope='Default (all other organizations)'; Setting=$s.Label; Value=(_Setting -Container $def -Path $s.Path -NullText '(not returned)') }) | Out-Null
        }
    }
    foreach ($p in $partners) {
        $ptid = [string]$p.TenantId
        $scope = if ($partnerNames.ContainsKey($ptid)) { 'Partner {0} ({1})' -f $partnerNames[$ptid], $ptid } else { 'Partner ' + $ptid }
        $rows.Add([pscustomobject]@{ Scope=$scope; Setting='Service provider (e.g. CSP / GDAP partner)'; Value=(_Setting -Container $p -Path @('IsServiceProvider') -NullText '(not returned)') }) | Out-Null
        foreach ($s in $settingMap) {
            $rows.Add([pscustomobject]@{ Scope=$scope; Setting=$s.Label; Value=(_Setting -Container $p -Path $s.Path -NullText '(inherits default)') }) | Out-Null
        }
    }
    $notes = @(
        'Default = the settings that apply to every outside organization that has no partner entry of its own.',
        '(inherits default) = the partner entry does not override that setting.'
    )
    if ($defError) { $notes += ('The default cross-tenant access policy could not be read: {0}' -f $defError) }
    if (-not $partnersKnown) { $notes += ('Partner-specific configurations could not be read: {0}' -f $partnersError) }
    if ($nameLookupFailed) { $notes += 'Partner organization names could not be resolved (CrossTenantInformation.ReadBasic.All); tenant ids are shown instead.' }
    if (@($partners).Count -gt 50) { $notes += 'Organization names were resolved for the first 50 partners only.' }
    $src = Write-Evidence -BaseName 'cross_tenant_access' -Rows $rows.ToArray() -Title 'Cross-Tenant Access & B2B Trust' -Notes $notes

    # A failed/empty DEFAULT-policy read means the trust posture was NOT evaluated -
    # never fall through to 'reviewed, nothing flagged', even when partner configs
    # were readable.
    if (-not $def) {
        $why = if ($defError) { "Reading it failed: $defError" } else { 'Microsoft Graph returned no data for it.' }
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Cross-tenant access settings could not be read, so outside trust was not checked' `
            -Evidence ("The default cross-tenant access policy is unknown. {0} {1} External-trust posture was not evaluated - this is not a clean result." -f $why, $partnerText) `
            -WhyItMatters 'These settings decide which outside organizations can reach your tenant and whose multi-factor authentication (MFA) and device checks you accept. Without them the audit cannot say whether outside access is locked down.' `
            -RecommendedAction 'Grant Policy.Read.All (and Global Reader or Security Reader for a delegated run), then re-run the trusts check.' `
            -SourceFile $src -RuleId 'trusts-policy-not-assessed' -ObjectType 'tenant' -CoverageGap -DocumentationUrl $crossTenantDoc
        return
    }

    # A trust setting the default policy did not return is UNKNOWN, not "off". Only when the
    # policy reports isServiceDefault = true is an absent value known to be the Microsoft
    # default (MFA/device trust off, automatic redemption off, direct connect blocked).
    $isServiceDefault = ((Get-EAField $def 'IsServiceDefault') -eq $true)
    $trustMfa     = _RawSetting -Container $def -Path @('InboundTrust','IsMfaAccepted')
    $trustCompRaw = _RawSetting -Container $def -Path @('InboundTrust','IsCompliantDeviceAccepted')
    $trustHybRaw  = _RawSetting -Container $def -Path @('InboundTrust','IsHybridAzureADJoinedDeviceAccepted')
    $autoInbound  = _RawSetting -Container $def -Path @('AutomaticUserConsentSettings','InboundAllowed')
    $dcUsersRaw   = _RawSetting -Container $def -Path @('B2bDirectConnectInbound','UsersAndGroups','AccessType')
    $unknownSettings = New-Object System.Collections.Generic.List[string]
    if (-not $isServiceDefault) {
        if ($null -eq $trustMfa)     { $unknownSettings.Add('MFA trust (InboundTrust.IsMfaAccepted)') | Out-Null }
        if ($null -eq $trustCompRaw) { $unknownSettings.Add('compliant-device trust (InboundTrust.IsCompliantDeviceAccepted)') | Out-Null }
        if ($null -eq $trustHybRaw)  { $unknownSettings.Add('hybrid-joined device trust (InboundTrust.IsHybridAzureADJoinedDeviceAccepted)') | Out-Null }
        if ($null -eq $autoInbound)  { $unknownSettings.Add('automatic redemption (AutomaticUserConsentSettings.InboundAllowed)') | Out-Null }
        if (-not [string]$dcUsersRaw) { $unknownSettings.Add('B2B direct connect inbound (B2bDirectConnectInbound.UsersAndGroups.AccessType)') | Out-Null }
    }
    $shown = { param($v) if ($null -eq $v) { 'not returned' } else { [string]$v } }

    $flagged = 0
    # Partner configs override the default only for the NAMED tenants - the default
    # policy still applies to every other tenant, so partner entries must not suppress
    # these findings.
    if ($trustMfa) {
        $flagged++
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'MFA completed in any outside organization is trusted by default' `
            -Evidence ("Default cross-tenant access policy (applies to every outside organization without its own entry): InboundTrust.IsMfaAccepted = true. {0}" -f $partnerText) `
            -WhyItMatters "Guests from any organization can satisfy your multi-factor authentication (MFA) rules with MFA done in their home tenant, whose MFA standards you cannot see or control. A weakly protected outside tenant then becomes a way around your Conditional Access (CA) policies." `
            -RecommendedAction ("Turn off MFA trust in the default settings and enable it only for named partner organizations you have vetted ({0} > Default settings > Inbound access > Trust settings)." -f $portalPath) `
            -SourceFile $src -RuleId 'trusts-default-mfa-trust' -ObjectType 'tenant' -DocumentationUrl $crossTenantDoc
    }
    $trustCompliant = [bool]$trustCompRaw
    $trustHybrid = [bool]$trustHybRaw
    if ($trustCompliant -or $trustHybrid) {
        $flagged++
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Device checks done by any outside organization are trusted by default' `
            -Evidence ("Default cross-tenant access policy: InboundTrust.IsCompliantDeviceAccepted = {0}; InboundTrust.IsHybridAzureADJoinedDeviceAccepted = {1}. {2}" -f (& $shown $trustCompRaw), (& $shown $trustHybRaw), $partnerText) `
            -WhyItMatters "Conditional Access (CA) rules that require a compliant or company-joined device are satisfied for a guest whenever any outside organization says the guest's device is fine, although you cannot see how that organization manages its devices." `
            -RecommendedAction ("Turn off compliant-device and hybrid-joined-device trust in the default settings and enable them only for named partner organizations you have vetted ({0} > Default settings > Inbound access > Trust settings)." -f $portalPath) `
            -SourceFile $src -RuleId 'trusts-default-device-trust' -ObjectType 'tenant' -DocumentationUrl $crossTenantDoc
    }
    $dcUsers = [string]$dcUsersRaw
    if ($dcUsers -eq 'allowed') {
        $flagged++
        $dcApps = [string](_Setting -Container $def -Path @('B2bDirectConnectInbound','Applications','AccessType') -NullText '(not returned)')
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Users from any outside organization can use B2B direct connect (Teams shared channels)' `
            -Evidence ("Default cross-tenant access policy: B2bDirectConnectInbound.UsersAndGroups.AccessType = allowed; Applications.AccessType = {0}. The Microsoft default is blocked. {1}" -f $dcApps, $partnerText) `
            -WhyItMatters 'Business-to-business (B2B) direct connect lets outside users reach shared resources (today: Teams shared channels) without a guest account in your directory, so they do not appear in guest lists or access reviews. Allowing it for every organization instead of named partners widens who can reach that data.' `
            -RecommendedAction ("Set B2B direct connect inbound back to blocked in the default settings and allow it only for named partner organizations ({0} > Default settings > Inbound access)." -f $portalPath) `
            -SourceFile $src -RuleId 'trusts-default-direct-connect-inbound' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/external-id/b2b-direct-connect-overview'
    }
    if ($autoInbound) {
        $flagged++
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Invited users from any outside organization can skip the consent prompt' `
            -Evidence ("Default cross-tenant access policy: AutomaticUserConsentSettings.InboundAllowed = true (automatic redemption). The Microsoft default is false. {0}" -f $partnerText) `
            -WhyItMatters 'Normally an invited outside user must accept a consent prompt before first access. With automatic redemption allowed for all organizations, users from any outside organization that also turns it on for its side get access without that prompt, so nobody confirms the access when it starts.' `
            -RecommendedAction ("Turn off automatic redemption in the default settings and enable it only for named partner organizations that need it ({0})." -f $portalPath) `
            -SourceFile $src -RuleId 'trusts-default-auto-redemption' -ObjectType 'tenant' -DocumentationUrl $crossTenantDoc
    }
    if ($unknownSettings.Count -gt 0) {
        # Settings the default policy did not return were not assessed: report them as a
        # coverage gap and never let the baseline below describe them as "off".
        $returnedText = if ($flagged -eq 0) { 'None of the settings that were returned trusts outside organizations broadly.' }
                        else { 'The settings that were returned are covered by the other trusts findings.' }
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title (Format-EACount -Count $unknownSettings.Count -One 'cross-tenant trust setting was not returned, so it could not be checked' -Many 'cross-tenant trust settings were not returned, so they could not be checked') `
            -Evidence ("The default cross-tenant access policy was read (isServiceDefault = {0}), but Microsoft Graph returned no value for: {1}. These settings are unknown, not off - this is not a clean result. {2} {3}" -f `
                (& $shown (Get-EAField $def 'IsServiceDefault')), ($unknownSettings -join '; '), $returnedText, $partnerText) `
            -WhyItMatters 'These settings decide whether multi-factor authentication (MFA) and device checks done by any outside organization count as your own, and whether outside users can skip the consent prompt. The audit cannot confirm that they are off.' `
            -RecommendedAction ("Check these settings by hand ({0} > Default settings > Inbound access), then re-run the trusts check; update the Microsoft Graph PowerShell modules if values keep missing." -f $portalPath) `
            -SourceFile $src -RuleId 'trusts-default-settings-unknown' -ObjectType 'tenant' -CoverageGap -DocumentationUrl $crossTenantDoc
    } elseif ($flagged -eq 0) {
        # No unknowns here: an absent value only occurs with isServiceDefault = true, where it
        # is the Microsoft default.
        $defaultText = if ($isServiceDefault) { ' (Microsoft default settings, never changed)' } else { '' }
        $dcText = if ($dcUsers) { $dcUsers } else { 'blocked (Microsoft default)' }
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'No broad trust of outside organizations found in cross-tenant access settings' `
            -Evidence ("Default policy{0}: MFA trust off, compliant/hybrid-joined device trust off, B2B direct connect inbound {1}, automatic redemption off. {2}" -f $defaultText, $dcText, $partnerText) `
            -WhyItMatters 'Keeping trust limited to named partner organizations stops outside tenants from satisfying your own security rules.' `
            -RecommendedAction 'Keep trust settings and direct connect limited to named partner organizations and review the partner list periodically.' `
            -SourceFile $src -RuleId 'trusts-baseline' -ObjectType 'tenant' -DocumentationUrl $crossTenantDoc
    }
}
