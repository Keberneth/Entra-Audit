<#
OAuth2 Consent Grants. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-ConsentGrants {
    # Per-user grants are one row per (user, app), so large tenants hold 100k+ grants. They
    # are read ONCE per run through the shared cache (Get-EAOAuth2Grants, also used by the
    # enterpriseapps library), which throws on failure. A failed read is recorded and
    # reported as a coverage gap below - never as "no risky grants" - and the admin consent
    # workflow setting, which does not depend on the grants, is still checked.
    $grants = @(); $grantsKnown = $true; $grantsError = $null
    try { $grants = @(Get-EAOAuth2Grants) } catch { $grantsKnown = $false; $grantsError = $_.Exception.Message }
    # Rule ids: every finding carries an explicit -RuleId (one-time migration from the old
    # title-slug ids) so rewording a title never changes its trend id again.

    # Resolve SP display names from the shared cache when a check already populated it;
    # otherwise ONE paged list call (id,displayName) replaces the previous per-id lookups
    # (two Graph calls per grant on tenants with thousands of grants). A failed name read
    # only costs readability (ids are shown instead) - the grants are still evaluated.
    $spById = @{}; $nameReadError = $null
    # (Skipped when the grants could not be read - there is nothing to label.)
    if ($grantsKnown -and $null -ne $script:SpsCache) {
        foreach ($sp in $script:SpsCache) { if ($sp.Id) { $spById[$sp.Id] = $sp } }
    } elseif ($grantsKnown) {
        try { foreach ($sp in @(Get-MgServicePrincipal -All -Property 'id,displayName' -PageSize 999 -ErrorAction Stop)) { if ($sp.Id) { $spById[$sp.Id] = $sp } } }
        catch { $nameReadError = $_.Exception.Message }
    }
    # offline_access alone is routine (it only lengthens token lifetime) and User.ReadWrite
    # (self-profile) is not high-impact - flagging them alone made nearly every ordinary
    # admin-consented app a High finding. Only data/directory-write scopes count as high.
    $highScopes = 'Mail\.|Files\.ReadWrite|Directory\.ReadWrite|User\.ReadWrite\.All|full_access|Sites\.ReadWrite|Sites\.FullControl'
    $rows = @(foreach ($g in $grants) {
        $client = if ($g.ClientId -and $spById.ContainsKey($g.ClientId)) { $spById[$g.ClientId] } else { $null }
        $resource = if ($g.ResourceId -and $spById.ContainsKey($g.ResourceId)) { $spById[$g.ResourceId] } else { $null }
        $scopeList = @(([string]$g.Scope -split '\s+') | Where-Object { $_ })
        $user = $null
        if ($g.PrincipalId) {
            $user = if ($script:UserById.ContainsKey([string]$g.PrincipalId)) { $script:UserById[[string]$g.PrincipalId].UserPrincipalName } else { [string]$g.PrincipalId }
        }
        [pscustomobject]@{
            Client=($client.DisplayName ?? $g.ClientId); ClientId=$g.ClientId; ConsentType=$g.ConsentType
            User=$user
            Resource=($resource.DisplayName ?? $g.ResourceId); Scope=$g.Scope
            HighImpactScopes=(@($scopeList | Where-Object { $_ -match $highScopes }) -join ' ')
            High=([string]$g.Scope -match $highScopes)
        }
    })
    $notes = @(
        ("Delegated permission grants: {0} (tenant-wide / AllPrincipals: {1}; single user / Principal: {2})." -f $rows.Count, @($rows | Where-Object { $_.ConsentType -eq 'AllPrincipals' }).Count, @($rows | Where-Object { $_.ConsentType -ne 'AllPrincipals' }).Count),
        'High = the grant includes a high-impact scope: any Mail.*, Files.ReadWrite*, Sites.ReadWrite* / Sites.FullControl*, Directory.ReadWrite*, User.ReadWrite.All or full_access*.',
        'User = the user who consented (per-user grants only); shown as an object id when the user list was not loaded in this run.',
        'The Enterprise Application Governance check (-enterpriseapps) also rates delegated grants, with its own permission risk tiers.'
    )
    if ($nameReadError) { $notes += ('App names could not be read, so ids are shown instead: {0}' -f $nameReadError) }
    if (-not $grantsKnown) { $notes = @(('The delegated permission grants could not be read, so this list is empty because the data is missing, not because there are no grants: {0}' -f $grantsError)) }
    $src = Write-Evidence -BaseName 'oauth_consent_grants' -Rows $rows -Title 'OAuth2 Delegated Consent Grants' -Notes $notes

    if (-not $grantsKnown) {
        Add-EntraFinding -Severity 'Medium' -CheckId 'consentgrants' -Category 'Applications' `
            -Title 'App consent grants could not be read, so risky app approvals were not checked' `
            -Evidence ("Reading the delegated permission grants (oauth2PermissionGrants) failed: {0}. Which apps users or admins have approved to read mail, files or directory data is unknown - this is not a clean result." -f $grantsError) `
            -WhyItMatters 'Approved apps keep their access to mail, files or directory data until someone removes the approval. A malicious app approved through consent phishing would stay hidden while this list cannot be read.' `
            -RecommendedAction 'Make sure the audit account can read the directory (Directory.Read.All), wait for any throttling to clear and re-run the consentgrants check. Until then, review approvals in Entra admin center > Enterprise applications > app > Permissions.' `
            -SourceFile $src -RuleId 'consentgrants-grants-unreadable' -ObjectType 'tenant' -CoverageGap `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions'
    }

    $tenantWideHigh = @($rows | Where-Object { $_.ConsentType -eq 'AllPrincipals' -and $_.High })
    if ($tenantWideHigh.Count -gt 0) {
        $twApps = @($tenantWideHigh.Client | Select-Object -Unique)
        Add-EntraFinding -Severity 'High' -CheckId 'consentgrants' -Category 'Applications' `
            -Title ((Format-EACount -Count $twApps.Count -One 'app was' -Many 'apps were') + ' approved to access mail, files or directory data for all users') `
            -Evidence ("{0} to {1} {2} a high-impact scope. Apps (first 10): {3}. Scopes: {4}. -enterpriseapps also rates these grants." -f (Format-EACount -Count $tenantWideHigh.Count -One 'tenant-wide (AllPrincipals) grant' -Many 'tenant-wide (AllPrincipals) grants'), (Format-EACount -Count $twApps.Count -One 'app' -Many 'apps'), $(if ($tenantWideHigh.Count -eq 1) { 'includes' } else { 'include' }), (($twApps | Select-Object -First 10) -join ', '), ((@($tenantWideHigh.HighImpactScopes -split ' ') | Where-Object { $_ } | Select-Object -Unique -First 12) -join ', ')) `
            -WhyItMatters 'An admin approved these apps to act as any signed-in user on mail, files or directory data. If one of them is malicious or compromised it can read or change that data for everyone, and the approval stays in place, even after password resets, until someone removes it.' `
            -RecommendedAction 'Review each app (Entra admin center > Enterprise applications > app > Permissions); revoke the grants of apps you do not recognise or no longer need, and allow user consent only for verified publishers and low-risk permissions.' `
            -SourceFile $src -ResultRows $tenantWideHigh -RuleId 'consentgrants-tenant-wide-high-impact' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions' `
            -AffectedObjectIds @($tenantWideHigh | ForEach-Object { $_.ClientId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($tenantWideHigh | ForEach-Object { $_.ClientId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with high-impact tenant-wide consent'
    }
    $userHigh = @($rows | Where-Object { $_.ConsentType -ne 'AllPrincipals' -and $_.High })
    if ($userHigh.Count -gt 0) {
        $uhApps = @($userHigh.Client | Select-Object -Unique)
        $uhUsers = @($userHigh.User | Where-Object { $_ } | Select-Object -Unique)
        Add-EntraFinding -Severity 'Medium' -CheckId 'consentgrants' -Category 'Applications' `
            -Title ((Format-EACount -Count $uhApps.Count -One 'app was' -Many 'apps were') + ' approved by individual users to access their mail, files or directory data') `
            -Evidence ("{0} by {1} to {2} {3} a high-impact scope. Apps (first 10): {4}. -enterpriseapps also rates these grants." -f (Format-EACount -Count $userHigh.Count -One 'per-user grant' -Many 'per-user grants'), (Format-EACount -Count $uhUsers.Count -One 'user' -Many 'users'), (Format-EACount -Count $uhApps.Count -One 'app' -Many 'apps'), $(if ($userHigh.Count -eq 1) { 'includes' } else { 'include' }), (($uhApps | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'In consent phishing, an attacker tricks a user into approving a malicious app, which can then read that user''s mail or files without ever needing the password.' `
            -RecommendedAction 'Revoke grants to apps you do not recognise (Entra admin center > Enterprise applications > app > Permissions > User consent), and allow users to consent only to apps from verified publishers with low-risk permissions (Enterprise applications > Consent and permissions).' `
            -SourceFile $src -ResultRows $userHigh -RuleId 'consentgrants-user-consent-high-impact' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent' `
            -AffectedObjectIds @($userHigh | ForEach-Object { $_.ClientId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($userHigh | ForEach-Object { $_.ClientId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'enterprise applications with high-impact user consent'
    }
    # Admin consent request workflow - if disabled while user consent is permissive,
    # users have no safe path to request apps and may be tempted into risky self-consent.
    # A failed read is a coverage gap, not "the workflow is enabled".
    $acr = $null; $acrError = $null
    try { $acr = Get-MgPolicyAdminConsentRequestPolicy -ErrorAction Stop } catch { $acrError = $_.Exception.Message }
    if (-not $acrError -and $null -eq $acr) { $acrError = 'the policy read returned no data' }
    if ($acrError) {
        Add-EntraFinding -Severity 'Information' -CheckId 'consentgrants' -Category 'Applications' `
            -Title 'Could not check whether users can request admin approval for apps' `
            -Evidence ("The admin consent request policy (adminConsentRequestPolicy) could not be read: {0}" -f $acrError) `
            -WhyItMatters 'If the admin consent workflow is off, users have no safe way to ask for an app, which pushes organisations to leave user consent open. The audit could not tell, so no finding here is not a clean result.' `
            -RecommendedAction 'Grant the audit account Policy.Read.All and re-run the consentgrants check, or check the setting in Entra admin center > Enterprise applications > Consent and permissions > Admin consent settings.' `
            -SourceFile $src -RuleId 'consentgrants-admin-consent-workflow-unreadable' -ObjectType 'tenant' -CoverageGap
    } elseif (-not $acr.IsEnabled) {
        Add-EntraFinding -Severity 'Low' -CheckId 'consentgrants' -Category 'Applications' `
            -Title 'Users cannot ask an admin to approve an app (admin consent workflow is off)' `
            -Evidence 'adminConsentRequestPolicy.isEnabled = false.' `
            -WhyItMatters 'Without a request process, users who need an app either get stuck or push for user consent to stay open - the setting that consent phishing abuses.' `
            -RecommendedAction 'Turn on the admin consent workflow and name reviewers (Entra admin center > Enterprise applications > Consent and permissions > Admin consent settings), so user consent can stay restricted.' `
            -SourceFile $src -RuleId 'consentgrants-admin-consent-workflow-disabled' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow'
    }

    if ($grantsKnown -and $tenantWideHigh.Count -eq 0 -and $userHigh.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'consentgrants' -Category 'Applications' `
            -Title 'No app has been approved for high-impact access to mail, files or directory data' `
            -Evidence ("{0} reviewed; none includes a high-impact scope (mail, files, SharePoint sites, directory write or all-user write)." -f (Format-EACount -Count $rows.Count -One 'delegated permission grant' -Many 'delegated permission grants')) `
            -WhyItMatters 'Limiting which apps users and admins can approve prevents consent phishing, where a malicious app is approved and then reads mail or files.' `
            -RecommendedAction 'Keep user consent restricted and review app grants periodically.' `
            -SourceFile $src -RuleId 'consentgrants-no-high-impact-grants' -ObjectType 'tenant'
    }
}
