<#
Stale / Unused Applications. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-StaleApps {
    $cut = (Get-Date).ToUniversalTime().AddDays(-$StaleAppDays)
    $now = (Get-Date).ToUniversalTime()
    $cutText = $cut.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $staleDoc = 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/recommendation-remove-unused-apps'
    $appRegPath = 'Entra admin center > Entra ID > App registrations > All applications'
    # BOTH Microsoft first-party owner tenants - built-in SPs are owned by either.
    $msftTenants = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a'   # Microsoft services
        '72f988bf-86f1-41af-91ab-2d7cd011db47'   # Microsoft corporate
    )

    # Service principals are the check's main inventory: a failed read stops the check
    # (Error / Skipped-NoPermission, with a coverage finding), never "no unused apps".
    $sps = @(Get-EAServicePrincipals)
    # Every tenant holds Microsoft first-party service principals (Microsoft Graph at least),
    # so an EMPTY list means the data was not returned - not that there are no apps.
    $spsUsable = ($sps.Count -gt 0)
    # The shared application cache carries createdDateTime + credentials + owners for the
    # apps registered in THIS tenant. A failed read is tracked: without it, secrets and
    # certificates held on app registrations are unknown (not "none").
    $appCreated = @{}; $appKinds = @{}
    $appsKnown = $true; $appsError = $null
    $appsAll = @(); try { $appsAll = @(Get-EAApplications) } catch { $appsKnown = $false; $appsError = $_.Exception.Message }

    # Service-principal sign-in activity: the shared, cached read of the beta
    # servicePrincipalSignInActivities report (Get-EAServicePrincipalSignInActivity). It
    # covers delegated and app-only sign-ins, with the app as client and as resource (API),
    # and its lastSignInDateTime values are persisted "last seen" timestamps, so they reach
    # back beyond the 30-day raw sign-in log. The helper does not throw; an unexpected failure
    # is still recorded as unknown, never as "unused".
    $activity = $null
    try { $activity = Get-EAServicePrincipalSignInActivity }
    catch { $activity = [pscustomobject]@{ Known = $false; ByAppId = @{}; Error = $_.Exception.Message } }
    $coverageOk = [bool](Get-EAField $activity 'Known')
    $activityError = [string](Get-EAField $activity 'Error')
    if (-not $coverageOk -and -not $activityError) { $activityError = 'no data was returned' }
    $lastByAppId = @{}
    # The helper already converts every report timestamp to UTC and counts the ones it could
    # not parse (UnreadableDates); those feed the evidence note, plus any local cast failure.
    $badDates = [int](Get-EAField $activity 'UnreadableDates')
    $byAppId = Get-EAField $activity 'ByAppId'
    if ($coverageOk -and $byAppId -is [System.Collections.IDictionary]) {
        foreach ($k in @($byAppId.Keys)) {
            $v = $byAppId[$k]
            # Listed without a timestamp = no recorded activity (same as absent from the report).
            if ($null -eq $v -or -not [string]$k) { continue }
            # An unparsable timestamp is counted (and noted in the evidence) instead of being
            # dropped silently; the app then falls back to its creation date.
            try {
                $d = if ($v -is [datetimeoffset]) { $v.UtcDateTime } else { [datetime]$v }
                if ($d.Kind -eq [System.DateTimeKind]::Local) { $d = $d.ToUniversalTime() }
                $lastByAppId[[string]$k] = $d
            } catch { $badDates++ }
        }
    }

    # What counts as a LIVE credential - something that lets a caller sign in AS the app:
    # unexpired client secrets, certificates and symmetric keys. Not counted:
    #  - SAML token-signing certificates. Entra adds them to the service principal of every
    #    SAML-federated app (a Sign key, its Verify half and a password protecting the private
    #    key, all sharing one customKeyIdentifier). Entra uses them to SIGN tokens for the app;
    #    nobody can use them to authenticate as the app.
    #  - Encryption keys and expired credentials (Entra rejects expired secrets/certificates).
    function _KeyIdText($value) {
        if ($null -eq $value) { return $null }
        if ($value -is [byte[]]) { if ($value.Length -eq 0) { return $null }; return [Convert]::ToBase64String($value) }
        $t = [string]$value
        if ($t) { return $t }
        return $null
    }
    function _CredentialKinds($obj) {
        $keys = @(@($obj.KeyCredentials) | Where-Object { $_ })
        $pwds = @(@($obj.PasswordCredentials) | Where-Object { $_ })
        $signIds = New-Object System.Collections.Generic.HashSet[string]
        foreach ($k in $keys) { if ([string]$k.Usage -eq 'Sign') { $kid = _KeyIdText $k.CustomKeyIdentifier; if ($kid) { [void]$signIds.Add($kid) } } }
        $out = @()
        foreach ($k in $keys) {
            $kid = _KeyIdText $k.CustomKeyIdentifier
            $usage = [string]$k.Usage
            $kind = if ($usage -eq 'Sign' -or ($kid -and $signIds.Contains($kid))) { 'SamlSigningCert' }
                    elseif ($usage -eq 'Verify' -and [string]$k.Type -eq 'Symmetric') { 'SymmetricKey' }
                    elseif ($usage -eq 'Verify') { 'Certificate' }
                    else { 'Key/' + $(if ($usage) { $usage } else { 'unknown' }) }
            $end = if ($k.EndDateTime) { ([datetime]$k.EndDateTime).ToUniversalTime() } else { $null }
            $expired = [bool]($end -and $end -lt $now)
            $out += [pscustomobject]@{ Kind=$kind; Expired=$expired; Live=(($kind -in @('Certificate','SymmetricKey')) -and -not $expired); End=$end }
        }
        foreach ($pc in $pwds) {
            $kid = _KeyIdText $pc.CustomKeyIdentifier
            $kind = if ($kid -and $signIds.Contains($kid)) { 'SamlSigningKeyPassword' } else { 'Secret' }
            $end = if ($pc.EndDateTime) { ([datetime]$pc.EndDateTime).ToUniversalTime() } else { $null }
            $expired = [bool]($end -and $end -lt $now)
            $out += [pscustomobject]@{ Kind=$kind; Expired=$expired; Live=(($kind -eq 'Secret') -and -not $expired); End=$end }
        }
        return $out
    }
    # "Secret, Certificate (expired), SamlSigningCert x2" for the evidence columns.
    function _KindsText($kinds) {
        # Drop nulls: an empty array passed through parameter binding arrives as $null, and
        # @($null) has Count 1, which would print '' instead of 'none'.
        $all = @($kinds | Where-Object { $_ })
        if ($all.Count -eq 0) { return 'none' }
        return ((@($all | Group-Object { if ($_.Expired) { '{0} (expired)' -f $_.Kind } else { $_.Kind } } | ForEach-Object {
            if ($_.Count -gt 1) { '{0} x{1}' -f $_.Name, $_.Count } else { $_.Name }
        })) -join ', ')
    }
    # "a, b, c (+N more)" for Evidence text; the full list is in the evidence file.
    function _AppList($items, [int]$Max = 10, [string]$Property = 'Application') {
        $all = @($items)
        $text = (@($all | Select-Object -First $Max | ForEach-Object { [string]$_.$Property })) -join ', '
        if ($all.Count -gt $Max) { $text += (' (+{0} more - see the evidence file)' -f ($all.Count - $Max)) }
        return $text
    }

    foreach ($a in $appsAll) {
        if ($a.AppId) {
            $appCreated[$a.AppId] = $a.CreatedDateTime
            $appKinds[$a.AppId] = @(_CredentialKinds $a)
        }
    }

    # =======================================================================
    # Part 1 - service principals (enterprise apps) with no recent sign-in
    # =======================================================================
    $rows = @(); $unknownRows = @()
    $reviewed = 0
    if ($coverageOk -and $spsUsable) {
        foreach ($sp in $sps) {
            # Real applications only (skip managed identities etc.) and skip Microsoft first-party
            # service principals - those are built-in and are not the customer's to remove.
            if ($sp.ServicePrincipalType -and $sp.ServicePrincipalType -notin @('Application','Legacy')) { continue }
            if ($sp.AppOwnerOrganizationId -and (([string]$sp.AppOwnerOrganizationId) -in $msftTenants)) { continue }
            $reviewed++
            $appId = [string]$sp.AppId
            $last = if ($lastByAppId.ContainsKey($appId)) { $lastByAppId[$appId] } else { $null }
            # Prefer the local application object's creation time, but fall back to the service
            # principal's when the app has none: Graph returns a NULL createdDateTime for old
            # registrations - exactly the oldest, most likely unused apps. Multi-tenant/third-party
            # service principals have no local application object at all. Only when neither
            # timestamp exists is the age UNKNOWN.
            $created = $appCreated[$appId]; $createdFrom = 'application'
            if (-not $created) { $created = $sp.CreatedDateTime; $createdFrom = 'servicePrincipal' }
            if (-not $created) { $created = $null; $createdFrom = $null }

            $spKinds = @(_CredentialKinds $sp)
            # @(if ...) - an if-statement that outputs an empty array yields AutomationNull, not @().
            $localKinds = @(if ($appKinds.ContainsKey($appId)) { $appKinds[$appId] })
            $liveCred = (@($spKinds | Where-Object { $_.Live }).Count + @($localKinds | Where-Object { $_.Live }).Count) -gt 0
            # With the application list unreadable, a registration's own secrets are unknown: the
            # app is only known to be credential-free if the service principal shows a live one.
            $credKnown = ($liveCred -or $appsKnown)
            $credText = 'ServicePrincipal: {0}; AppRegistration: {1}' -f (_KindsText $spKinds), $(if ($appKinds.ContainsKey($appId)) { _KindsText $localKinds } elseif ($appsKnown) { 'no local app registration' } else { 'unknown (could not be read)' })

            $stale = $false; $reason = ''
            if ($null -ne $last) {
                if ($last -lt $cut) { $stale = $true; $reason = ("Last sign-in {0}" -f $last.ToString('yyyy-MM-dd')) }
            } elseif ($created -and ([datetime]$created) -lt $cut) {
                # No sign-in on record AND the app is older than the window (avoids flagging brand-new apps).
                $stale = $true; $reason = ("No sign-in on record (created {0}, {1} timestamp)" -f ([datetime]$created).ToString('yyyy-MM-dd'), $createdFrom)
            }
            if ($stale) {
                $rows += [pscustomobject]@{
                    Application=$sp.DisplayName; AppId=$appId; ServicePrincipalId=$sp.Id; LastSignIn=$last; Created=$created; CreatedFrom=$createdFrom; Reason=$reason
                    HasCredentials=$(if ($credKnown) { $liveCred } else { 'unknown' }); CredentialKinds=$credText; Enabled=$sp.AccountEnabled
                }
            } elseif ($null -eq $last -and $null -eq $created) {
                $unknownRows += [pscustomobject]@{ Application=$sp.DisplayName; AppId=$appId; ServicePrincipalId=$sp.Id; LastSignIn=$null; Created=$null; Reason='No sign-in record and no creation timestamp'; HasCredentials=$(if ($credKnown) { $liveCred } else { 'unknown' }); CredentialKinds=$credText; Enabled=$sp.AccountEnabled; OwnerTenant=$sp.AppOwnerOrganizationId }
            }
        }
    }
    if (-not $spsUsable) {
        $saNotes = @('No service principals were returned, so unused applications could not be identified - this list is empty because the data is missing.')
    } elseif (-not $coverageOk) {
        $saNotes = @(("App sign-in activity could not be read, so unused applications could not be identified - this list is empty because the data is missing, not because every app is in use: {0}" -f $activityError))
    } else {
        $saNotes = @(
            ("Reviewed {0}." -f (Format-EACount -Count $reviewed -One 'non-Microsoft application service principal' -Many 'non-Microsoft application service principals')),
            "Unknown-age/no-sign-in service principals: $($unknownRows.Count)",
            'LastSignIn = the newest sign-in of any kind (delegated or app-only, with the app as client or as API) in the servicePrincipalSignInActivities report.',
            'HasCredentials counts only unexpired client secrets, certificates and symmetric keys. SAML token-signing certificates (and the password Entra stores with them), encryption keys and expired credentials are listed in CredentialKinds but are not counted.'
        )
        if (-not $appsKnown) { $saNotes += ("App registrations could not be read ({0}): their secrets/certificates and creation dates are unknown (HasCredentials = unknown where the service principal has no live credential)." -f $appsError) }
        if ($badDates -gt 0) { $saNotes += (Format-EACount -Count $badDates -One 'sign-in timestamp in the activity report could not be parsed and was ignored.' -Many 'sign-in timestamps in the activity report could not be parsed and were ignored.') }
    }
    $src = Write-Evidence -BaseName 'stale_applications' -Rows $rows -Title ("Stale / Unused Applications (no sign-in > {0} days)" -f $StaleAppDays) -Notes $saNotes
    $unknownSrc = $null
    if ($unknownRows.Count -gt 0) { $unknownSrc = Write-Evidence -BaseName 'stale_applications_unknown' -Rows $unknownRows -Title 'Applications with Unknown Usage/Age' -Notes $saNotes }

    if (-not $spsUsable) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
            -Title 'Unused applications could not be checked because no service principals were returned' `
            -Evidence 'Microsoft Graph returned an empty service-principal (enterprise app) list, although every tenant holds at least the Microsoft built-in ones. Unused applications and app registrations without an enterprise app were therefore not checked - this is not a clean result.' `
            -WhyItMatters 'Without the list of enterprise apps the audit cannot tell which applications are no longer used and could be removed.' `
            -RecommendedAction 'Make sure the audit identity can read applications (Application.Read.All, read-only), then re-run the staleapps check.' `
            -SourceFile $src -RuleId 'staleapps-service-principals-unreadable' -ObjectType 'tenant' -DocumentationUrl $staleDoc -CoverageGap
    } elseif (-not $coverageOk) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
            -Title 'Unused applications could not be identified because app sign-in activity could not be read' `
            -Evidence ("The beta servicePrincipalSignInActivities report could not be read ({0}). It needs AuditLog.Read.All and Entra ID P1 or higher. This is a gap in the audit, not proof that all apps are in use. App registrations without an enterprise app are checked separately and do not need this report." -f $activityError) `
            -WhyItMatters 'Without app sign-in activity the audit cannot tell which applications are no longer used and could be removed.' `
            -RecommendedAction 'Grant AuditLog.Read.All (read-only) to the audit identity, confirm the tenant has Entra ID P1 or higher, then re-run the staleapps check.' `
            -SourceFile $src -RuleId 'staleapps-signin-activity-unknown' -ObjectType 'tenant' -DocumentationUrl $staleDoc -CoverageGap
    } else {
        $staleCred = @($rows | Where-Object { $_.HasCredentials -is [bool] -and $_.HasCredentials })
        $staleNoCred = @($rows | Where-Object { -not ($_.HasCredentials -is [bool] -and $_.HasCredentials) })
        $staleCredUnknown = @($rows | Where-Object { $_.HasCredentials -isnot [bool] })
        $cols = @('Application','LastSignIn','Created','Reason','CredentialKinds','Enabled')
        if ($staleCred.Count -gt 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId 'staleapps' -Category 'Applications' `
                -Title ("{0} valid secrets or certificates (no sign-in for {1}+ days)" -f (Format-EACount -Count $staleCred.Count -One 'unused application still has' -Many 'unused applications still have'), $StaleAppDays) `
                -Evidence ("Applications with no sign-in in the last {0} days that still hold an unexpired client secret, certificate or key: {1}" -f $StaleAppDays, (_AppList $staleCred)) `
                -WhyItMatters 'An application nobody has used for months that still has a valid secret or certificate is a forgotten way into your tenant: if that secret leaks, an attacker can sign in as the app and nobody is likely to notice.' `
                -RecommendedAction 'Ask each app''s owner whether it is still needed and delete unused apps (Entra admin center > Entra ID > App registrations or Enterprise applications). If an app must stay, remove its unused secrets and certificates and record an owner.' `
                -SourceFile $src -ResultRows @($staleCred | Select-Object $cols) -RuleId 'staleapps-unused-with-credentials' -ObjectType 'tenant' -DocumentationUrl $staleDoc `
                -AffectedObjectIds @($staleCred | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($staleCred | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'stale service principals with valid credentials'
        }
        if ($staleNoCred.Count -gt 0) {
            Add-EntraFinding -Severity 'Low' -CheckId 'staleapps' -Category 'Applications' `
                -Title ("{0} not been used for {1}+ days" -f (Format-EACount -Count $staleNoCred.Count -One 'application has' -Many 'applications have'), $StaleAppDays) `
                -Evidence ("Cleanup candidates with no sign-in in the last {0} days and no valid secret or certificate (SAML token-signing certificates and expired credentials are not counted){1}: {2}" -f $StaleAppDays, $(if ($staleCredUnknown.Count -gt 0) { ('; for {0} of them the app registration could not be read, see the separate finding' -f $staleCredUnknown.Count) } else { '' }), (_AppList $staleNoCred)) `
                -WhyItMatters 'Unused applications keep their permissions and consent grants, clutter the directory and make reviews harder. Removing what is no longer needed reduces risk and noise.' `
                -RecommendedAction 'Review each unused application with its owner and delete the ones that are no longer needed (Entra admin center > Entra ID > Enterprise applications).' `
                -SourceFile $src -ResultRows @($staleNoCred | Select-Object $cols) -RuleId 'staleapps-unused' -ObjectType 'tenant' -DocumentationUrl $staleDoc `
                -AffectedObjectIds @($staleNoCred | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount @($staleNoCred | ForEach-Object { $_.ServicePrincipalId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'stale service principals without confirmed valid credentials'
        }
        if ($staleCredUnknown.Count -gt 0) {
            Add-EntraFinding -Severity 'Low' -CheckId 'staleapps' -Category 'Applications' `
                -Title ("Could not check whether {0} secrets" -f (Format-EACount -Count $staleCredUnknown.Count -One 'unused application still has' -Many 'unused applications still have')) `
                -Evidence ("App registrations could not be read ({0}), so secrets or certificates stored on these apps' registrations are unknown. They are listed with the unused apps above, but some may belong in the higher-risk ""still have valid secrets"" group: {1}" -f $appsError, (_AppList $staleCredUnknown)) `
                -WhyItMatters 'An unused app that still has a valid secret is a bigger risk than one without. When the registrations cannot be read, the audit cannot tell which case applies.' `
                -RecommendedAction 'Make sure the audit identity has Application.Read.All (read-only) and re-run the staleapps check, or check these apps'' Certificates & secrets pages manually.' `
                -SourceFile $src -ResultRows @($staleCredUnknown | Select-Object $cols) -RuleId 'staleapps-app-credentials-unknown' -ObjectType 'tenant' -DocumentationUrl $staleDoc -CoverageGap
        }
        if ($unknownRows.Count -gt 0) {
            Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
                -Title ((Format-EACount -Count $unknownRows.Count -One 'application has' -Many 'applications have') + ' no sign-in record and no known creation date') `
                -Evidence ("These third-party or legacy service principals have no entry in the sign-in activity report and no readable creation date on the application or service principal, so their usage is unknown: {0}." -f (_AppList $unknownRows)) `
                -WhyItMatters 'No sign-in record does not prove an app is in use or unused when its age is also unknown; treating these apps as clean would hide unreviewed application access.' `
                -RecommendedAction 'Review these enterprise applications manually, find an owner and purpose for each, and delete those no longer needed.' `
                -SourceFile $unknownSrc -ResultRows $unknownRows -RuleId 'staleapps-unknown-age' -ObjectType 'tenant' -DocumentationUrl $staleDoc -CoverageGap
        }
    }

    # =======================================================================
    # Part 2 - app registrations with NO service principal in this tenant
    # =======================================================================
    # An app registration is only usable in a tenant through its service principal (the
    # "enterprise app"): without one, nobody can sign in to the app, or with its secrets,
    # here. Part 1 starts from service principals, so these registrations are evaluated
    # separately (no sign-in data is needed). Single-tenant registrations (AzureADMyOrg)
    # cannot be used anywhere else either; multi-tenant and personal-account registrations
    # may be in use in OTHER tenants, whose sign-ins this audit cannot see, so they are only
    # listed for the owner to confirm. Not flagged: registrations created inside the
    # -StaleAppDays window (they may still be being set up) and registrations that hold
    # directory extension attributes (deleting them deletes that data).
    $noSpTitle = 'App Registrations Without an Enterprise App (service principal) in This Tenant'
    $noSpSingle = @(); $noSpMulti = @(); $noSpRows = @()
    $noSpSrc = $null
    if (-not $appsKnown -or -not $spsUsable) {
        $why = if (-not $appsKnown) { ('the app registration list could not be read: {0}' -f $appsError) } else { 'the service-principal (enterprise app) list came back empty' }
        $noSpSrc = Write-Evidence -BaseName 'app_registrations_without_service_principal' -Rows @() -Title $noSpTitle `
            -Notes @(("Not checked, because {0}. This list is empty because the data is missing, not because every app registration has an enterprise app." -f $why))
        # When the service-principal list is empty the finding above already reports the gap.
        if (-not $appsKnown -and $spsUsable) {
            Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
                -Title 'App registrations without an enterprise app could not be checked (app list unreadable)' `
                -Evidence ("The app registration list could not be read ({0}), so app registrations that have no service principal (enterprise app) in this tenant - unused leftovers - are unknown, not zero." -f $appsError) `
                -WhyItMatters 'App registrations without an enterprise app are usually leftovers from tests or retired integrations; while the list cannot be read they cannot be found and cleaned up.' `
                -RecommendedAction 'Make sure the audit identity has Application.Read.All (read-only) and re-run the staleapps check.' `
                -SourceFile $noSpSrc -RuleId 'staleapps-appreg-inventory-unknown' -ObjectType 'tenant' -DocumentationUrl $staleDoc -CoverageGap
        }
    } else {
        $spAppIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($sp in $sps) { if ($sp.AppId) { [void]$spAppIds.Add([string]$sp.AppId) } }
        $audienceText = @{
            'AzureADMyOrg'                       = 'This organization only'
            'AzureADMultipleOrgs'                = 'Any Microsoft Entra organization'
            'AzureADandPersonalMicrosoftAccount' = 'Any organization and personal Microsoft accounts'
            'PersonalMicrosoftAccount'           = 'Personal Microsoft accounts only'
        }
        # Order for the directory-extension check (capped below): first the registrations that
        # Microsoft tools create to hold extension attributes (Entra Connect's "Tenant Schema
        # Extension App", Entra Cloud Sync's "CloudSyncCustomExtensionsApp", the Azure AD B2C
        # "b2c-extensions-app. Do not modify. ..."), so a large tenant never recommends deleting
        # one unchecked; then single-tenant candidates, which get the "delete" recommendation.
        $extHolderPattern = '^(Tenant Schema Extension App|CloudSyncCustomExtensionsApp)$|^b2c-extensions-app\b'
        $candidates = @($appsAll | Where-Object { $_.AppId -and -not $spAppIds.Contains([string]$_.AppId) } |
            Sort-Object @{ Expression = { if ([string]$_.DisplayName -match $extHolderPattern) { 0 } else { 1 } } },
                        @{ Expression = { if ([string]$_.SignInAudience -eq 'AzureADMyOrg') { 0 } else { 1 } } },
                        @{ Expression = { [string]$_.DisplayName } })
        # Directory extension attributes (for example those created by Microsoft Entra Connect
        # on the "Tenant Schema Extension App") are defined ON an app registration, which needs
        # no enterprise app. Deleting such a registration deletes the attribute data, so it is
        # never recommended for deletion. One GET per candidate, at most $extCap calls.
        $extCap = 50; $extCalls = 0; $extErrors = 0; $extSkipped = 0
        function _ExtensionAttributeCount([string]$AppObjectId) {
            $u = ('https://graph.microsoft.com/v1.0/applications/{0}/extensionProperties?$select=id,name' -f $AppObjectId); $n = 0; $guard = 0
            while ($u -and $guard -lt 10) {
                $u = Assert-EAGraphReadUri $u
                $resp = Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop
                $n += @($resp['value'] | Where-Object { $_ }).Count
                $u = $resp['@odata.nextLink']; $guard++
            }
            if ($u) { throw 'Extension-property pagination exceeded the 10-page safety limit.' }
            return $n
        }
        foreach ($a in $candidates) {
            $appId = [string]$a.AppId
            $aud = [string]$a.SignInAudience
            $audClass = if ($aud -eq 'AzureADMyOrg') { 'Single' } elseif ($audienceText.ContainsKey($aud)) { 'Multi' } else { 'Unknown' }
            $created = $null
            if ($a.CreatedDateTime) {
                try {
                    $created = if ($a.CreatedDateTime -is [datetimeoffset]) { $a.CreatedDateTime.UtcDateTime } else { [datetime]$a.CreatedDateTime }
                    if ($created.Kind -eq [System.DateTimeKind]::Local) { $created = $created.ToUniversalTime() }
                } catch { $created = $null }
            }
            $recent = ($null -ne $created -and $created -ge $cut)
            $kinds = @(if ($appKinds.ContainsKey($appId)) { $appKinds[$appId] } else { _CredentialKinds $a })
            $live = @($kinds | Where-Object { $_ -and $_.Live })
            $expiredCount = @($kinds | Where-Object { $_ -and $_.Expired }).Count
            $nextEnd = @($live | Where-Object { $_.End } | Sort-Object End | Select-Object -First 1)
            $nextExpiry = if ($nextEnd.Count -gt 0) { $nextEnd[0].End } elseif ($live.Count -gt 0) { 'never (no end date)' } else { $null }
            # Owners come expanded (ids only) on the cached application list: no extra Graph
            # call. Names are shown when the user list was already loaded in this run.
            $ownerIds = @(@($a.Owners) | Where-Object { $_ } | ForEach-Object { if ($_ -is [string]) { $_ } else { [string]$_.Id } } | Where-Object { $_ })
            $ownerLabels = @($ownerIds | ForEach-Object { if ($script:UserById.ContainsKey($_)) { [string]$script:UserById[$_].UserPrincipalName } else { $_ } })
            $ownerText = (@($ownerLabels | Select-Object -First 5)) -join ', '
            if ($ownerLabels.Count -gt 5) { $ownerText += (' (+{0} more)' -f ($ownerLabels.Count - 5)) }

            $extText = 'not checked (recently created)'; $extCount = $null
            if (-not $recent) {
                if ($extCalls -ge $extCap) { $extText = ('not checked (limit of {0} checks reached)' -f $extCap); $extSkipped++ }
                else {
                    $extCalls++
                    try { $extCount = _ExtensionAttributeCount ([string]$a.Id); $extText = [string]$extCount }
                    catch { $extErrors++; $extText = ('unknown (read failed: {0})' -f $_.Exception.Message) }
                }
            }
            # Extension attributes not confirmed (check limit reached or read failed): never
            # "delete if not needed" - deleting the registration would delete that data.
            $status = if ($recent) { ('Created in the last {0} days - not flagged' -f $StaleAppDays) }
                      elseif ($extCount -gt 0) { 'Holds directory extension attributes - keep' }
                      elseif ($null -eq $extCount) {
                          if ($audClass -eq 'Single') { 'Extension attributes not checked - confirm before deleting' }
                          else { 'May be used in other organizations; extension attributes not checked - ask the owner' }
                      }
                      elseif ($audClass -eq 'Single') { 'Cannot be used in this tenant - delete if not needed' }
                      else { 'May be used in other organizations - ask the owner' }
            $row = [pscustomobject]@{
                DisplayName=$a.DisplayName; AppId=$appId; AppObjectId=$a.Id
                SignInAudience=$(if ($aud) { $aud } else { '(not returned)' })
                Audience=$(if ($audienceText.ContainsKey($aud)) { $audienceText[$aud] } elseif ($aud) { $aud } else { 'Unknown (not returned)' })
                Created=$created
                CredentialCount=$live.Count; ExpiredCredentialCount=$expiredCount; NextCredentialExpiry=$nextExpiry
                CredentialKinds=(_KindsText $kinds)
                OwnerCount=$ownerIds.Count; Owners=$ownerText
                ExtensionAttributes=$extText
                Status=$status
            }
            $noSpRows += $row
            if ($recent -or $extCount -gt 0) { continue }
            if ($audClass -eq 'Single') { $noSpSingle += $row } else { $noSpMulti += $row }
        }
        $keptForExtensions = @($noSpRows | Where-Object { $_.Status -like 'Holds directory extension*' }).Count
        $recentCount = @($noSpRows | Where-Object { $_.Status -like 'Created in the last*' }).Count
        $noSpNotes = @(
            ("App registrations: {0}; service principals (enterprise apps): {1}; app registrations without a service principal: {2} (flagged as not usable here: {3}; to confirm with the owner: {4}; created in the last {5} days: {6}; holding directory extension attributes: {7})." -f $appsAll.Count, $sps.Count, $noSpRows.Count, $noSpSingle.Count, $noSpMulti.Count, $StaleAppDays, $recentCount, $keptForExtensions),
            'Flagged: single-tenant registrations (sign-in audience AzureADMyOrg) created before the window or with no creation date - without an enterprise app they cannot be used for sign-in in this tenant. Multi-tenant and personal-account registrations may be used in other tenants, so they are listed for the owner to confirm.',
            'CredentialCount = unexpired client secrets, certificates and symmetric keys; expired ones are counted in ExpiredCredentialCount.',
            'Owners: read from the application list (at most 20 per app are returned). Names are shown when the user list was already loaded in this run, otherwise object ids.',
            'ExtensionAttributes: number of directory extension attributes defined on the registration. Registrations that hold them are not flagged, because deleting the registration deletes that data.'
        )
        if ($extSkipped -gt 0) { $noSpNotes += ('Directory extension attributes were checked for the first {0} registrations only (the known extension-holder apps of Entra Connect, Entra Cloud Sync and Azure AD B2C first, then single-tenant registrations); {1}, and {2} Status says "extension attributes not checked".' -f $extCap, (Format-EACount -Count $extSkipped -One 'was not checked' -Many 'were not checked'), $(if ($extSkipped -eq 1) { 'its' } else { 'their' })) }
        if ($extErrors -gt 0) { $noSpNotes += ('The directory extension attributes of {0}' -f (Format-EACount -Count $extErrors -One 'registration could not be read; it stays in the list but is marked unknown.' -Many 'registrations could not be read; they stay in the list but are marked unknown.')) }
        $noSpSrc = Write-Evidence -BaseName 'app_registrations_without_service_principal' -Rows $noSpRows -Title $noSpTitle -Notes $noSpNotes

        $noSpCols = @('DisplayName','AppId','Audience','Created','CredentialCount','NextCredentialExpiry','Owners','ExtensionAttributes')
        # Shared wording: credentials held, and registrations whose extension attributes
        # were not confirmed (they must be checked before a deletion).
        function _NoSpCredText($set) {
            $withCred = @($set | Where-Object { $_.CredentialCount -gt 0 })
            if ($withCred.Count -eq 0) { return 'None of them holds a valid secret or certificate.' }
            $credSum = 0; foreach ($r in $withCred) { $credSum += [int]$r.CredentialCount }
            return ('{0} of them still {1} {2}: {3}.' -f $withCred.Count, $(if ($withCred.Count -eq 1) { 'holds' } else { 'hold' }), (Format-EACount -Count $credSum -One 'valid secret or certificate' -Many 'valid secrets or certificates'), (_AppList -items $withCred -Property 'DisplayName'))
        }
        function _NoSpExtText($set) {
            $uncheckedRows = @($set | Where-Object { [string]$_.ExtensionAttributes -notmatch '^\d+$' })
            if ($uncheckedRows.Count -eq 0) { return '' }
            return (' For {0} of them it could not be confirmed that they hold no directory extension attributes (check limit reached or read failed) - check before deleting: {1}.' -f $uncheckedRows.Count, (_AppList -items $uncheckedRows -Property 'DisplayName'))
        }
        if ($noSpSingle.Count -gt 0) {
            $keptText = if ($keptForExtensions -gt 0) { (' {0} directory extension attributes and {1} not included.' -f (Format-EACount -Count $keptForExtensions -One 'other registration without an enterprise app holds' -Many 'other registrations without an enterprise app hold'), $(if ($keptForExtensions -eq 1) { 'is' } else { 'are' })) } else { '' }
            Add-EntraFinding -Severity 'Low' -CheckId 'staleapps' -Category 'Applications' `
                -Title ((Format-EACount -Count $noSpSingle.Count -One 'app registration has' -Many 'app registrations have') + ' no enterprise app in this tenant and cannot be used') `
                -Evidence ("{0} no service principal (enterprise app) in this tenant. Without one, no one can sign in to the app or with its secrets until an enterprise app is created for it. Each was created before {1} or has no creation date. {2}{3}{4} Apps: {5}." -f (Format-EACount -Count $noSpSingle.Count -One 'single-tenant app registration (sign-in audience: this organization only) has' -Many 'single-tenant app registrations (sign-in audience: this organization only) have'), $cutText, (_NoSpCredText $noSpSingle), (_NoSpExtText $noSpSingle), $keptText, (_AppList -items $noSpSingle -Property 'DisplayName')) `
                -WhyItMatters 'An app registration only works through its enterprise app, so these are almost always leftovers from tests or retired integrations. They clutter app reviews, and any secret or certificate on them becomes usable again as soon as someone creates the enterprise app, for example by consenting to the app.' `
                -RecommendedAction ("Confirm with each app's owner that it is no longer needed, then delete it ({0} > app > Delete; deleted registrations can be restored for 30 days). Remove the secrets and certificates of any registration you keep." -f $appRegPath) `
                -SourceFile $noSpSrc -ResultRows @($noSpSingle | Select-Object $noSpCols) -RuleId 'staleapps-appreg-no-service-principal' -ObjectType 'tenant' -DocumentationUrl $staleDoc `
                -AffectedObjectIds @($noSpSingle | ForEach-Object { $_.AppObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'application' -AffectedCount @($noSpSingle | ForEach-Object { $_.AppObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'older single-tenant app registrations without a local service principal'
        }
        if ($noSpMulti.Count -gt 0) {
            $unknownAud = @($noSpMulti | Where-Object { $_.SignInAudience -eq '(not returned)' -or -not $audienceText.ContainsKey([string]$_.SignInAudience) }).Count
            $unknownAudText = if ($unknownAud -gt 0) { (' For {0} of them the sign-in audience was not returned, so {1} treated the same way.' -f $unknownAud, $(if ($unknownAud -eq 1) { 'it is' } else { 'they are' })) } else { '' }
            Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
                -Title ((Format-EACount -Count $noSpMulti.Count -One 'app registration open to outside accounts has' -Many 'app registrations open to outside accounts have') + ' no enterprise app here and may be unused') `
                -Evidence ("{0} no service principal (enterprise app) in this tenant, so nothing here uses the app. Customers or partners may still use it in their own tenants; those sign-ins are not visible to this audit.{1} {2}{3} Apps: {4}." -f (Format-EACount -Count $noSpMulti.Count -One 'app registration that allows sign-in from other organizations or personal Microsoft accounts has' -Many 'app registrations that allow sign-in from other organizations or personal Microsoft accounts have'), $unknownAudText, (_NoSpCredText $noSpMulti), (_NoSpExtText $noSpMulti), (_AppList -items $noSpMulti -Property 'DisplayName')) `
                -WhyItMatters 'Your organization owns these apps even when only other organizations use them. If one is no longer needed, its secrets remain a way to sign in as the app in every tenant that still has it.' `
                -RecommendedAction ("Ask each app's owner whether customers or partners still use it. Delete the ones that are no longer needed ({0}) and remove unused secrets and certificates from the rest." -f $appRegPath) `
                -SourceFile $noSpSrc -ResultRows @($noSpMulti | Select-Object $noSpCols) -RuleId 'staleapps-appreg-multitenant-no-local-sp' -ObjectType 'tenant' -DocumentationUrl $staleDoc `
                -AffectedObjectIds @($noSpMulti | ForEach-Object { $_.AppObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'application' -AffectedCount @($noSpMulti | ForEach-Object { $_.AppObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'older multitenant app registrations without a local service principal'
        }
    }

    if ($coverageOk -and $spsUsable -and $appsKnown -and $rows.Count -eq 0 -and $unknownRows.Count -eq 0 -and $noSpSingle.Count -eq 0 -and $noSpMulti.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'staleapps' -Category 'Applications' `
            -Title ("No unused applications found (no sign-in for {0}+ days)" -f $StaleAppDays) `
            -Evidence ("{0} within the last {1} days or {2} created within that window, and every app registration older than that window has an enterprise app in this tenant (or holds directory extension attributes)." -f $(if ($reviewed -eq 1) { 'The 1 reviewed non-Microsoft application service principal either signed in' } else { 'All {0} reviewed non-Microsoft application service principals either signed in' -f $reviewed }), $StaleAppDays, $(if ($reviewed -eq 1) { 'was' } else { 'were' })) `
            -WhyItMatters 'Keeping only applications that are actually used keeps the attack surface small.' `
            -RecommendedAction 'Keep reviewing application usage periodically.' `
            -SourceFile $src -RuleId 'staleapps-baseline' -ObjectType 'tenant' -DocumentationUrl $staleDoc
    }
}
