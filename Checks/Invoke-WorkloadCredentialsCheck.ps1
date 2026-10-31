<#
Workload Identity Credentials. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-WorkloadCredentials {
    $checkId = 'workloadcredentials'
    $category = 'Applications'
    $now = (Get-Date).ToUniversalTime()
    $warningDays = if (Get-Variable -Name ExpiringCredentialDays -Scope Script -ErrorAction SilentlyContinue) { [int]$script:ExpiringCredentialDays } `
        elseif (Get-Variable -Name ExpiringCredentialDays -ErrorAction SilentlyContinue) { [int]$ExpiringCredentialDays } else { 30 }

    $applications = @()
    $servicePrincipals = @()
    $applicationKnown = $true
    $servicePrincipalKnown = $true
    try { $applications = @(Get-EAApplications) } catch { $applicationKnown = $false; $applicationError = $_.Exception.Message }
    try { $servicePrincipals = @(Get-EAServicePrincipals) } catch { $servicePrincipalKnown = $false; $servicePrincipalError = $_.Exception.Message }

    if ($applicationKnown) { Invoke-EAApplicationAuthenticationReview -Applications $applications -CheckId $checkId }

    $credentialRows = @()
    if ($applicationKnown) { $credentialRows += @(Get-EAWorkloadCredentialRows -Objects $applications -ObjectType Application -Now $now -WarningDays $warningDays) }
    # Microsoft first-party and managed-identity credentials are service-managed rather
    # than tenant-managed workload secrets. Including their backing certificates creates
    # unactionable expiry/long-life findings, so retain only application/legacy enterprise
    # service principals not owned by the two Microsoft first-party home tenants.
    $microsoftOwnerTenants = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
        '72f988bf-86f1-41af-91ab-2d7cd011db47'
    )
    $credentialServicePrincipals = @($servicePrincipals | Where-Object {
        $type = [string](Get-EAApplicationCheckValue $_ 'servicePrincipalType')
        $ownerTenant = [string](Get-EAApplicationCheckValue $_ 'appOwnerOrganizationId')
        ($type -in @('Application','Legacy') -or [string]::IsNullOrWhiteSpace($type)) -and
        ($ownerTenant -notin $microsoftOwnerTenants)
    })
    if ($servicePrincipalKnown) { $credentialRows += @(Get-EAWorkloadCredentialRows -Objects $credentialServicePrincipals -ObjectType ServicePrincipal -Now $now -WarningDays $warningDays) }
    # The appcredentials check runs earlier and reports expired and expiring app
    # registration credentials. The same credential is kept in the evidence here
    # (ReportedUnder column) but not scored a second time.
    $appCredentialIndex = Get-EAReportedElsewhereIndex -CheckId 'appcredentials' -KeySelector {
        param($row)
        $credentialAppId = [string](Get-EAApplicationCheckValue $row 'AppId')
        $credentialName = [string](Get-EAApplicationCheckValue $row 'CredName')
        $credentialKind = ([string](Get-EAApplicationCheckValue $row 'CredType') -split '/')[0]
        if ($credentialAppId -and $credentialName) { "credential|$credentialAppId|$credentialName|$credentialKind" }
    }
    foreach ($credentialRow in @($credentialRows | Where-Object { $_.ObjectType -eq 'Application' -and $_.State -in @('Expired','ExpiringSoon') })) {
        $neededRank = if ($credentialRow.State -eq 'Expired') { 2 } else { 1 }
        $key = ("credential|{0}|{1}|{2}" -f $credentialRow.AppId, $credentialRow.CredentialName, $credentialRow.CredentialType).ToLowerInvariant()
        if ($appCredentialIndex.ContainsKey($key) -and $appCredentialIndex[$key] -ge $neededRank) { $credentialRow.ReportedUnder = 'appcredentials' }
    }
    $credentialSource = Write-Evidence -BaseName 'workload_credentials' -Rows $credentialRows `
        -Title 'Workload Identity Credentials (applications and service principals)' `
        -Notes @(
            'Lifetime limits used: secrets 180 days; certificates 730 days (2 years); SAML token-signing certificates three years (the Microsoft default).',
            'A SAML token-signing certificate on a service principal is listed once: its public key (usage Verify) and the password that protects its private key share its customKeyIdentifier and are part of the same certificate.',
            'Expired credentials are reported as expired only (LongLived = False): Entra no longer accepts them, so their lifetime no longer matters.',
            ("Expiry warning window: {0} days." -f $warningDays),
            'ReportedUnder = appcredentials: an expired or expiring app registration credential that the appcredentials check already reported. It is listed here but not counted again.',
            'Credential values are never returned by these Graph reads; only metadata is exported.',
            ("Excluded {0} whose credentials are not tenant-managed workload secrets." -f (Format-EAApplicationCheckCount -Count ($servicePrincipals.Count - $credentialServicePrincipals.Count) -One 'Microsoft first-party, managed-identity, or other non-application service principal' -Many 'Microsoft first-party, managed-identity, or other non-application service principals'))
        )

    $coverageRows = @()
    if (-not $applicationKnown) { $coverageRows += [pscustomobject]@{ Dataset='Applications'; State='Unknown'; Error=$applicationError } }
    if (-not $servicePrincipalKnown) { $coverageRows += [pscustomobject]@{ Dataset='ServicePrincipals'; State='Unknown'; Error=$servicePrincipalError } }
    if ($coverageRows.Count -gt 0) {
        $coverageSource = Write-Evidence -BaseName 'workload_credential_collection_gaps' -Rows $coverageRows -Title 'Workload Credential Collection Gaps'
        $unreadLists = @($coverageRows | ForEach-Object { if ($_.Dataset -eq 'Applications') { 'app registrations' } else { 'service principals (enterprise apps)' } }) -join ' and '
        $firstError = [string](@($coverageRows.Error | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -First 1) -join '')
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'App credentials could not be fully read, so credential problems may be missing' `
            -Evidence ("Could not read the {0}; their secrets and certificates were not checked.{1}" -f $unreadLists, $(if ($firstError) { " Error: $firstError" } else { '' })) `
            -WhyItMatters 'Expired, never-expiring or long-lived app secrets and certificates in the unread lists cannot show up in this report. This is a gap in the audit, not a clean result.' `
            -RecommendedAction 'Make sure the audit account can read applications and service principals (Application.Read.All), wait for any Microsoft Graph throttling to clear, then run the workloadcredentials check again.' `
            -SourceFile $coverageSource -ResultRows $coverageRows -RuleId 'workload-credential-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }

    $expired = @($credentialRows | Where-Object { $_.State -eq 'Expired' -and -not $_.ReportedUnder })
    $expiring = @($credentialRows | Where-Object { $_.State -eq 'ExpiringSoon' -and -not $_.ReportedUnder })
    $credentialsReportedElsewhere = @($credentialRows | Where-Object { $_.ReportedUnder })
    $noExpiry = @($credentialRows | Where-Object { $_.State -eq 'NoExpiry' })
    $longLived = @($credentialRows | Where-Object { $_.LongLived })
    $overlaps = @(Get-EAWorkloadCredentialOverlapRows -CredentialRows $credentialRows)
    $overlapSource = Write-Evidence -BaseName 'workload_credential_overlap' -Rows $overlaps -Title 'Workload Credential Overlap Review'
    $credentialPortalPath = 'Entra admin center > App registrations > app > Certificates & secrets'

    if ($noExpiry.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $noExpiry.Count -One 'app secret or certificate shows no end date, so it may never expire' -Many 'app secrets or certificates show no end date, so they may never expire') `
            -Evidence ("{0} on {1} {2} returned without an end date (endDateTime empty): {3}." -f (Format-EAApplicationCheckCount -Count $noExpiry.Count -One 'credential' -Many 'credentials'), (Format-EAApplicationCheckCount -Count (@($noExpiry.ObjectId | Select-Object -Unique).Count) -One 'app or service principal' -Many 'apps or service principals'), $(if ($noExpiry.Count -eq 1) { 'was' } else { 'were' }),
                (Format-EAApplicationCheckList @($noExpiry | ForEach-Object { "{0} [{1}]" -f $_.ObjectName, $_.CredentialType }))) `
            -WhyItMatters 'A secret or certificate without an end date can keep working forever, even after the project or the person who created it is gone. If it leaks, an attacker can use it for as long as it exists.' `
            -RecommendedAction ("Replace each one with a credential that has an end date (preferably a certificate valid for 12 months or less), update the system that uses it, then delete the old credential ({0}; credentials added directly to a service principal are removed with Microsoft Graph PowerShell)." -f $credentialPortalPath) `
            -SourceFile $credentialSource -ResultRows $noExpiry -RuleId 'workload-credential-no-expiry' -ObjectType 'workloadIdentity' -CoverageGap
    }
    if ($expired.Count -gt 0) {
        $expiredElsewhereNote = if (@($credentialsReportedElsewhere | Where-Object { $_.State -eq 'Expired' }).Count -gt 0) { ' Expired app registration credentials already reported by the appcredentials check are not repeated here.' } else { '' }
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $expired.Count -One 'app or service principal secret or certificate has expired' -Many 'app or service principal secrets and certificates have expired') `
            -Evidence ("Expired credentials on {0}, oldest first: {1}.{2}" -f (Format-EAApplicationCheckCount -Count (@($expired.ObjectId | Select-Object -Unique).Count) -One 'object' -Many 'objects'),
                (Format-EAApplicationCheckList @($expired | Sort-Object DaysLeft | ForEach-Object { "{0} [{1}] expired {2}" -f $_.ObjectName, $_.CredentialType, (Format-EAApplicationCheckCount -Count ([math]::Abs([int]$_.DaysLeft)) -One 'day ago' -Many 'days ago') })), $expiredElsewhereNote) `
            -WhyItMatters 'An expired secret or certificate usually means an integration has stopped working, or that nobody removed a credential the app no longer uses. Either way, nobody is looking after these apps.' `
            -RecommendedAction ("For each app, check whether the integration is still needed. If it is, create a new credential and update the system that uses it; if not, delete the expired credential or the whole app ({0})." -f $credentialPortalPath) `
            -SourceFile $credentialSource -ResultRows $expired -RuleId 'workload-credential-expired' -ObjectType 'workloadIdentity' `
            -AffectedObjectIds @($expired | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'workloadIdentity' -AffectedCount @($expired | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'applications and service principals with the stated credential issue'
    }
    if ($expiring.Count -gt 0) {
        $expiringElsewhereNote = if (@($credentialsReportedElsewhere | Where-Object { $_.State -eq 'ExpiringSoon' }).Count -gt 0) { ' Expiring app registration credentials already reported by the appcredentials check are not repeated here.' } else { '' }
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $expiring.Count -One 'app or service principal secret or certificate expires' -Many 'app or service principal secrets and certificates expire') + (' within {0} days' -f $warningDays)) `
            -Evidence ("Expiring on {0}, soonest first: {1}.{2}" -f (Format-EAApplicationCheckCount -Count (@($expiring.ObjectId | Select-Object -Unique).Count) -One 'object' -Many 'objects'),
                (Format-EAApplicationCheckList @($expiring | Sort-Object DaysLeft | ForEach-Object { "{0} [{1}] {2}" -f $_.ObjectName, $_.CredentialType, (Format-EAApplicationCheckCount -Count $_.DaysLeft -One 'day left' -Many 'days left') })), $expiringElsewhereNote) `
            -WhyItMatters 'When a secret or certificate runs out without a planned renewal, the integration that uses it stops working without warning.' `
            -RecommendedAction ("Renew each credential before its end date: create the new one, update the system that uses it, test it, then delete the old one ({0})." -f $credentialPortalPath) `
            -SourceFile $credentialSource -ResultRows $expiring -RuleId 'workload-credential-expiring' -ObjectType 'workloadIdentity' `
            -AffectedObjectIds @($expiring | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'workloadIdentity' -AffectedCount @($expiring | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'applications and service principals with the stated credential issue'
    }
    if ($longLived.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $longLived.Count -One 'app secret or certificate stays valid for too long' -Many 'app secrets or certificates stay valid for too long') `
            -Evidence ("Credentials over the lifetime limit (secrets 180 days, certificates 2 years, SAML token-signing certificates 3 years), longest first: {0}." -f
                (Format-EAApplicationCheckList @($longLived | Sort-Object LifetimeDays -Descending | ForEach-Object { "{0} [{1}] valid {2:N0} days" -f $_.ObjectName, $_.CredentialType, $_.LifetimeDays }))) `
            -WhyItMatters 'The longer a secret or certificate stays valid, the longer a stolen copy can be used to sign in as the app. Long lifetimes also usually mean nobody renews them on a schedule.' `
            -RecommendedAction 'Replace these credentials with shorter-lived ones (secrets 180 days or less, certificates 2 years or less) and automate renewal. Where the other system supports it, use workload identity federation so that no secret is stored at all. A tenant-wide app management policy can enforce maximum lifetimes.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation' `
            -SourceFile $credentialSource -ResultRows $longLived -RuleId 'workload-credential-long-lived' -ObjectType 'workloadIdentity' `
            -AffectedObjectIds @($longLived | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'workloadIdentity' -AffectedCount @($longLived | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'applications and service principals with the stated credential issue'
    }
    if ($credentialsReportedElsewhere.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $credentialsReportedElsewhere.Count -One 'expired or expiring app credential is' -Many 'expired or expiring app credentials are') + ' already reported by the appcredentials check') `
            -Evidence 'These app registration credentials are listed here for completeness but not counted twice. Service principal credentials, missing end dates, long lifetimes and overlapping credentials are still reported by this check.' `
            -WhyItMatters 'Counting the same credential in two checks would show one problem twice and inflate the risk score.' `
            -RecommendedAction 'Fix these credentials using the appcredentials findings; nothing extra is needed here.' `
            -SourceFile $credentialSource -ResultRows $credentialsReportedElsewhere -RuleId 'workload-credential-reported-elsewhere' -ObjectType 'tenant'
    }
    if ($overlaps.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $overlaps.Count -One 'app keeps' -Many 'apps keep') + ' several secrets or certificates valid at the same time') `
            -Evidence ("More than two active credentials of the same type, or two that overlap for more than 30 days: {0}." -f
                (Format-EAApplicationCheckList @($overlaps | ForEach-Object { "{0} [{1}]: {2}" -f $_.ObjectName, $_.CredentialType, $_.Reason }))) `
            -WhyItMatters 'A short overlap is normal while a credential is being renewed. Keeping several valid at once gives attackers more credentials to steal and makes it unclear which one is really in use.' `
            -RecommendedAction ("Find out which credential each app actually uses, then delete the ones it replaced ({0})." -f $credentialPortalPath) `
            -SourceFile $overlapSource -ResultRows $overlaps -RuleId 'workload-credential-excessive-overlap' -ObjectType 'workloadIdentity' `
            -AffectedObjectIds @($overlaps | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'workloadIdentity' -AffectedCount @($overlaps | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'applications and service principals with the stated credential issue'
    }

    # Federated identity credentials (trusts) are a relationship of application objects and
    # are not part of the cached application list. One paged list read with the
    # relationship expanded ($expand=federatedIdentityCredentials, documented for the
    # application resource) replaces one GET per application. An application is read on
    # its own only when the combined read failed, did not return its trusts, or may have
    # cut them short (an application holds at most 20 trusts, so 20 expanded items are
    # re-read). The beta endpoint is needed for the flexible-FIC claimsMatchingExpression;
    # it is a GET-only read with the same Application.Read.All permission as v1.0.
    $ficRows = New-Object System.Collections.Generic.List[object]
    $ficErrors = New-Object System.Collections.Generic.List[object]
    $ficNotes = New-Object System.Collections.Generic.List[string]
    $ficNotes.Add('Issuer, subject, and audience are trust-boundary metadata. Secrets/tokens are not returned.') | Out-Null
    $ficStopReason = $null
    $ficNotAttempted = 0
    if ($applicationKnown) {
        $expandedById = $null
        try {
            $expandedById = @{}
            $expandedUri = 'https://graph.microsoft.com/beta/applications?$select=id,appId,displayName&$expand=federatedIdentityCredentials&$top=100'
            foreach ($expandedApplication in @(Get-EAReadOnlyGraphCollection -Uri $expandedUri)) {
                $expandedId = [string](Get-EAApplicationCheckValue $expandedApplication 'id')
                if ($expandedId) { $expandedById[$expandedId] = $expandedApplication }
            }
        } catch {
            $expandedById = $null
            $ficNotes.Add(("The combined read of all applications with their federated credentials failed, so each application was read on its own instead: {0}" -f $_.Exception.Message)) | Out-Null
        }

        $perApplication = New-Object System.Collections.Generic.List[object]
        foreach ($application in $applications) {
            $applicationId = [string](Get-EAApplicationCheckValue $application 'Id')
            if ($null -ne $expandedById -and $applicationId -and $expandedById.ContainsKey($applicationId)) {
                $expandedApplication = $expandedById[$applicationId]
                $expandedTrusts = Get-EAApplicationCheckValue $expandedApplication 'federatedIdentityCredentials'
                $moreTrusts = Get-EAApplicationCheckValue $expandedApplication 'federatedIdentityCredentials@odata.nextLink'
                if ($null -ne $expandedTrusts -and -not $moreTrusts -and @($expandedTrusts).Count -lt 20) {
                    foreach ($fic in @($expandedTrusts)) {
                        if ($null -ne $fic) { $ficRows.Add((ConvertTo-EAFederatedCredentialRow -Application $application -Trust $fic)) | Out-Null }
                    }
                    continue
                }
            }
            $perApplication.Add($application) | Out-Null
        }
        if ($null -ne $expandedById -and $perApplication.Count -gt 0) {
            $ficNotes.Add((Format-EAApplicationCheckCount -Count $perApplication.Count -One 'application was read on its own because the combined read did not return all of its federated credentials.' -Many 'applications were read on their own because the combined read did not return all of their federated credentials.')) | Out-Null
        }

        $ficThrottleRun = 0
        foreach ($application in $perApplication) {
            if ($ficStopReason) { $ficNotAttempted++; continue }
            $applicationId = [string](Get-EAApplicationCheckValue $application 'Id')
            if (-not $applicationId) {
                $ficErrors.Add([pscustomobject]@{
                    Application=[string](Get-EAApplicationCheckValue $application 'DisplayName'); ObjectId=''
                    StatusCode=''; Error='The application was returned without an object id, so its federated credentials could not be read.'
                }) | Out-Null
                continue
            }
            $uri = 'https://graph.microsoft.com/beta/applications/' + [uri]::EscapeDataString($applicationId) + '/federatedIdentityCredentials?$select=id,name,issuer,subject,audiences,description,claimsMatchingExpression'
            try {
                foreach ($fic in @(Get-EAReadOnlyGraphCollection -Uri $uri -MaximumPages 20)) {
                    if ($null -ne $fic) { $ficRows.Add((ConvertTo-EAFederatedCredentialRow -Application $application -Trust $fic)) | Out-Null }
                }
                $ficThrottleRun = 0
            } catch {
                $ficErrors.Add([pscustomobject]@{
                    Application=[string](Get-EAApplicationCheckValue $application 'DisplayName'); ObjectId=$applicationId
                    StatusCode=(Get-EAApplicationCheckHttpStatus $_); Error=$_.Exception.Message
                }) | Out-Null
                # An access-denied error repeats for every application, and sustained
                # throttling only gets worse: stop and record the rest as not checked.
                $ficStopReason = Get-EAApplicationCheckStopReason -ErrorRecord $_ -ThrottleRun ([ref]$ficThrottleRun)
            }
        }
    }
    $ficSource = Write-Evidence -BaseName 'federated_identity_credentials' -Rows @($ficRows.ToArray()) `
        -Title 'Federated Identity Credential Trusts' -Notes @($ficNotes.ToArray())
    if ($ficErrors.Count -gt 0 -or $ficNotAttempted -gt 0 -or -not $applicationKnown) {
        $ficErrorRows = @($ficErrors.ToArray())
        if (-not $applicationKnown) { $ficErrorRows += [pscustomobject]@{ Application='All applications'; ObjectId=''; StatusCode=''; Error='Application collection unavailable' } }
        if ($ficNotAttempted -gt 0) {
            $ficErrorRows += [pscustomobject]@{ Application=('Remaining ' + (Format-EAApplicationCheckCount -Count $ficNotAttempted -One 'application' -Many 'applications')); ObjectId=''; StatusCode=''; Error=("Not checked: federated credential reads stopped because {0}." -f $ficStopReason) }
        }
        $ficErrorSource = Write-Evidence -BaseName 'federated_identity_credential_collection_gaps' -Rows $ficErrorRows -Title 'Federated Identity Credential Collection Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Federated credentials could not be read for all apps, so risky trusts may be missing' `
            -Evidence ("{0} failed and {1} not checked{2}. An empty list of trusts here does not mean there are none." -f (Format-EAApplicationCheckCount -Count $ficErrors.Count -One 'application read' -Many 'application reads'),
                $(if (-not $applicationKnown) { 'all applications were' } else { Format-EAApplicationCheckCount -Count $ficNotAttempted -One 'application was' -Many 'applications were' }), $(if ($ficStopReason) { " (reads stopped because $ficStopReason)" } else { '' })) `
            -WhyItMatters 'A federated credential lets an outside system, such as a GitHub Actions workflow or a Kubernetes cluster, sign in as the app without a secret. Trusts that could not be read were not checked for risky settings.' `
            -RecommendedAction 'Make sure the audit account can read applications (Application.Read.All) and has at least the Global Reader role, wait for any throttling to clear, then run the workloadcredentials check again.' `
            -SourceFile $ficErrorSource -ResultRows $ficErrorRows -RuleId 'federated-credential-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }
    $invalidFic = @($ficRows.ToArray() | Where-Object {
        $_.MissingTrustField -or $_.NonStandardAudience -or $_.ConflictingSubjectAndExpression -or $_.InvalidExpressionLanguageVersion
    })
    if ($invalidFic.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $invalidFic.Count -One 'federated credential trust is incomplete or unusual and needs review' -Many 'federated credential trusts are incomplete or unusual and need review') `
            -Evidence ("Trusts with a problem (app / trust: problem): {0}." -f
                (Format-EAApplicationCheckList @($invalidFic | ForEach-Object { "{0} / {1}: {2}" -f $_.Application, $_.Credential, (Get-EAFederatedCredentialIssue -Row $_) }))) `
            -WhyItMatters 'A federated credential lets an outside system sign in as the app without a secret, so its issuer, subject and audience decide exactly who is trusted. A missing or unusual value can let a workload you did not intend to trust sign in as the app.' `
            -RecommendedAction 'Open each trust (Entra admin center > App registrations > app > Certificates & secrets > Federated credentials): confirm the issuer, set the subject to the exact repository, branch, environment or service account, and use the audience api://AzureADTokenExchange unless a documented design needs another.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation' `
            -SourceFile $ficSource -ResultRows $invalidFic -RuleId 'federated-credential-broad-trust' -ObjectType 'application' `
            -AffectedObjectIds @($invalidFic | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'application' -AffectedCount @($invalidFic | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'app registrations with federated trust requiring review'
    }
    $flexibleFic = @($ficRows.ToArray() | Where-Object { $_.FlexibleWildcardExpression })
    if ($flexibleFic.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $flexibleFic.Count -One 'federated credential trust uses' -Many 'federated credential trusts use') + ' wildcards that may trust more workloads than intended') `
            -Evidence ("Claim expressions with a wildcard (* or ?): {0}. A plain subject value is always an exact match and is not counted here." -f
                (Format-EAApplicationCheckList @($flexibleFic | ForEach-Object { "{0} / {1}: {2}" -f $_.Application, $_.Credential, $_.ClaimsMatchingExpression }))) `
            -WhyItMatters 'A wildcard can match many repositories, branches or workloads. If it is broader than intended, an outside workload you do not control may be able to sign in as the app.' `
            -RecommendedAction 'Review each expression and narrow the wildcard so it only covers your own organization and repositories; add exact branch or environment conditions where possible.' `
            -SourceFile $ficSource -ResultRows $flexibleFic -RuleId 'federated-credential-flexible-wildcard' -ObjectType 'application' `
            -AffectedObjectIds @($flexibleFic | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'application' -AffectedCount @($flexibleFic | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'app registrations with federated trust requiring review'
    }

    # Tenant and custom application-management policies are optional controls, but an
    # unreadable endpoint is explicitly surfaced and cannot produce a posture pass.
    $policyRows = @()
    $policyErrors = @()
    $defaultPolicy = $null
    try {
        $defaultPolicy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy' -ErrorAction Stop
        $policyRows += @(Get-EAAppManagementPolicyRows -Policy $defaultPolicy -PolicyType Default)
    } catch { $policyErrors += [pscustomobject]@{ Dataset='Default policy'; Error=$_.Exception.Message } }

    $customPolicies = @()
    $policyAssignments = @{}
    $policyAssignmentsKnown = $true
    try {
        $customPolicies = @(Get-EAReadOnlyGraphCollection -Uri 'https://graph.microsoft.com/v1.0/policies/appManagementPolicies?$top=999')
        foreach ($policy in $customPolicies) {
            $policyId = [string](Get-EAApplicationCheckValue $policy 'id')
            $assignmentCount = 0
            $assignmentState = 'Known'
            try {
                $assignmentUri = 'https://graph.microsoft.com/v1.0/policies/appManagementPolicies/' + [uri]::EscapeDataString($policyId) + '/appliesTo?$select=id,appId,displayName'
                $assignedObjects = @(Get-EAReadOnlyGraphCollection -Uri $assignmentUri -MaximumPages 50)
                $assignmentCount = $assignedObjects.Count
                $policyAssignments[$policyId] = @($assignedObjects | ForEach-Object { [string](Get-EAApplicationCheckValue $_ 'id') } | Where-Object { $_ })
                if ($policyAssignments[$policyId].Count -ne $assignmentCount) { throw 'A policy assignment was returned without an object id.' }
            } catch {
                $assignmentState = 'Unknown'
                $policyAssignmentsKnown = $false
                $policyErrors += [pscustomobject]@{ Dataset=("Policy appliesTo: {0}" -f $policyId); Error=$_.Exception.Message }
            }
            $policyRows += @(Get-EAAppManagementPolicyRows -Policy $policy -PolicyType Custom -AssignmentCount $assignmentCount -AssignmentState $assignmentState)
        }
    } catch {
        $policyAssignmentsKnown = $false
        $policyErrors += [pscustomobject]@{ Dataset='Custom policies'; Error=$_.Exception.Message }
    }

    $policySource = Write-Evidence -BaseName 'app_management_policies' -Rows $policyRows -Title 'Application Authentication Method Policies'
    $policyDocumentation = 'https://learn.microsoft.com/en-us/graph/api/resources/tenantappmanagementpolicy'
    if ($policyErrors.Count -gt 0) {
        $policyErrorSource = Write-Evidence -BaseName 'app_management_policy_collection_gaps' -Rows $policyErrors -Title 'Application Management Policy Collection Gaps'
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'App credential lifetime policies could not be fully read' `
            -Evidence ("Could not read: {0}. Reading them needs Policy.Read.All and Application.Read.All." -f (Format-EAApplicationCheckList @($policyErrors.Dataset))) `
            -WhyItMatters 'These policies can block long-lived or never-expiring app secrets for the whole tenant. Because they could not be read, the audit cannot tell whether such limits are in place.' `
            -RecommendedAction 'Give the audit account the read-only permissions Policy.Read.All and Application.Read.All and at least the Global Reader role, then run the workloadcredentials check again.' `
            -SourceFile $policyErrorSource -ResultRows $policyErrors -RuleId 'app-management-policy-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }
    if ($defaultPolicy) {
        $defaultEnabledValue = Get-EAApplicationCheckValue $defaultPolicy 'isEnabled'
        $defaultEnabled = ConvertTo-EAApplicationCheckBoolean $defaultEnabledValue
        if ($null -eq $defaultEnabled) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'Could not tell whether the tenant-wide app credential policy is turned on' `
                -Evidence 'defaultAppManagementPolicy was returned, but isEnabled was missing or was not true/false.' `
                -WhyItMatters 'Lifetime limits for app secrets and certificates can only be counted as enforced when the policy is known to be on.' `
                -RecommendedAction 'Run the check again. If isEnabled is still missing, read the policy with Microsoft Graph (GET /policies/defaultAppManagementPolicy) and treat its limits as not enforced until this is confirmed.' `
                -DocumentationUrl $policyDocumentation `
                -SourceFile $policySource -ResultRows @($policyRows | Where-Object { $_.PolicyType -eq 'Default' }) -RuleId 'default-app-management-policy-state-unknown' -ObjectType 'tenant' -CoverageGap
        } elseif (-not $defaultEnabled) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'The tenant-wide app credential policy is turned off' `
                -Evidence 'defaultAppManagementPolicy.isEnabled is false, so no tenant-wide limits on app secrets or certificates are enforced.' `
                -WhyItMatters 'Without this policy, anyone who manages an app can add secrets that never expire or last for years. Limits then depend on every app owner doing the right thing.' `
                -RecommendedAction 'Turn on the default app management policy with maximum lifetimes for secrets and certificates (for example 180 days for secrets), test the effect on existing integrations first, then enforce it for new credentials. It is configured with Microsoft Graph (policies/defaultAppManagementPolicy).' `
                -DocumentationUrl $policyDocumentation `
                -SourceFile $policySource -ResultRows @($policyRows | Where-Object { $_.PolicyType -eq 'Default' }) -RuleId 'default-app-management-policy-disabled' -ObjectType 'tenant'
        } else {
            # The tenant policy has independent applicationRestrictions and
            # servicePrincipalRestrictions. A rule in one object class must never make the
            # other class appear protected. Blocking new secrets or symmetric keys altogether
            # (passwordAddition / symmetricKeyAddition) is stronger than a lifetime limit, so
            # it covers that credential type. customPasswordAddition only blocks secrets the
            # caller chooses and does not.
            $missingDefaultLifetimes = @()
            $laterEnforcement = @()
            foreach ($scopeName in @('Applications','ServicePrincipals')) {
                $scopeRows = @($policyRows | Where-Object {
                    $_.PolicyType -eq 'Default' -and $_.AppliesTo -eq $scopeName -and $_.PolicyEnabled -and
                    $_.RestrictionState -eq 'enabled'
                })
                $hasPassword = @($scopeRows | Where-Object {
                    ($_.RestrictionType -eq 'passwordLifetime' -and $null -ne $_.MaxLifetimeDays) -or $_.RestrictionType -eq 'passwordAddition'
                }).Count -gt 0
                $hasSymmetricKey = @($scopeRows | Where-Object {
                    ($_.RestrictionType -eq 'symmetricKeyLifetime' -and $null -ne $_.MaxLifetimeDays) -or $_.RestrictionType -eq 'symmetricKeyAddition'
                }).Count -gt 0
                # restrictForAppsCreatedAfterDateTime: a rule applies only to apps created
                # after that date, so older apps are not restricted by it.
                foreach ($laterRow in @($scopeRows | Where-Object {
                    $_.RestrictionType -in @('passwordLifetime','passwordAddition','symmetricKeyLifetime','symmetricKeyAddition','asymmetricKeyLifetime') -and
                    $_.EnforcedFrom -is [datetime] -and $_.EnforcedFrom.Year -gt 1900
                })) {
                    $laterEnforcement += "{0} {1} (from {2:yyyy-MM-dd})" -f $(if ($scopeName -eq 'Applications') { 'app registrations:' } else { 'service principals:' }), $laterRow.RestrictionType, $laterRow.EnforcedFrom
                }
                $hasCertificate = @($scopeRows | Where-Object {
                    $_.RestrictionType -eq 'asymmetricKeyLifetime' -and $null -ne $_.MaxLifetimeDays
                }).Count -gt 0
                if (-not $hasPassword -or -not $hasSymmetricKey -or -not $hasCertificate) {
                    $missingDefaultLifetimes += [pscustomobject]@{
                        AppliesTo=$scopeName; PasswordLifetime=$hasPassword; SymmetricKeyLifetime=$hasSymmetricKey; CertificateLifetime=$hasCertificate
                    }
                }
            }
            if ($missingDefaultLifetimes.Count -gt 0) {
                $missingText = @($missingDefaultLifetimes | ForEach-Object {
                    $missingKinds = @()
                    if (-not $_.PasswordLifetime) { $missingKinds += 'secrets' }
                    if (-not $_.SymmetricKeyLifetime) { $missingKinds += 'symmetric keys' }
                    if (-not $_.CertificateLifetime) { $missingKinds += 'certificates' }
                    "{0}: {1}" -f $(if ($_.AppliesTo -eq 'Applications') { 'app registrations' } else { 'service principals' }), ($missingKinds -join ', ')
                }) -join '; '
                Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                    -Title 'The tenant-wide app credential policy does not limit every type of credential' `
                    -Evidence ("No enabled lifetime limit or block for: {0}.{1}" -f $missingText,
                        $(if ($laterEnforcement.Count -gt 0) { " The existing rules apply only to apps created after the date shown, so older apps are not restricted by them: {0}." -f ($laterEnforcement -join '; ') } else { '' })) `
                    -WhyItMatters 'App registrations and service principals have separate limits. Where a limit is missing, new credentials of that type can be created with any lifetime, including many years.' `
                    -RecommendedAction 'Add enabled lifetime limits for secrets (passwordLifetime), symmetric keys (symmetricKeyLifetime) and certificates (asymmetricKeyLifetime) for both app registrations and service principals, or block new secrets and symmetric keys altogether (passwordAddition, symmetricKeyAddition), after testing the effect on existing integrations.' `
                    -DocumentationUrl $policyDocumentation `
                    -SourceFile $policySource -ResultRows $missingDefaultLifetimes -RuleId 'default-app-management-policy-lifetime-gap' -ObjectType 'tenant'
            }
        }
    }

    $unassignedCustomPolicies = @($policyRows | Where-Object {
        $_.PolicyType -eq 'Custom' -and $_.PolicyEnabled -and $_.AssignmentState -eq 'Known' -and $_.AssignmentCount -eq 0
    } | Group-Object PolicyId | ForEach-Object { $_.Group | Select-Object -First 1 })
    if ($unassignedCustomPolicies.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $unassignedCustomPolicies.Count -One 'app credential policy is' -Many 'app credential policies are') + ' turned on but not applied to any app') `
            -Evidence ("Enabled custom app management policies with no assigned apps or service principals: {0}." -f (Format-EAApplicationCheckList @($unassignedCustomPolicies.PolicyName))) `
            -WhyItMatters 'A policy that is not applied to any app enforces nothing. It may be an unfinished rollout that gives a false sense of protection.' `
            -RecommendedAction 'Apply each policy to the apps it was meant for, or delete it if it is no longer needed.' `
            -SourceFile $policySource -ResultRows $unassignedCustomPolicies -RuleId 'custom-app-management-policy-unassigned' -ObjectType 'policy' `
            -AffectedObjectIds @($unassignedCustomPolicies | ForEach-Object { $_.PolicyId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'policy' -AffectedCount @($unassignedCustomPolicies | ForEach-Object { $_.PolicyId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'custom application management policies without assignments'
    }

    $policyTenantId = if ($script:Tenant) { [string](Get-EAApplicationCheckValue $script:Tenant 'id') } else { '' }
    if (-not $policyTenantId) { try { $policyTenantId = [string](Get-MgContext).TenantId } catch {} }
    $effectivePolicyRows = @(Get-EAEffectiveCredentialPolicyRows -Applications $applications -ServicePrincipals $credentialServicePrincipals `
        -DefaultPolicy $defaultPolicy -CustomPolicies $customPolicies -PolicyAssignments $policyAssignments `
        -AssignmentsKnown $policyAssignmentsKnown -TenantId $policyTenantId)
    $effectivePolicySource = Write-Evidence -BaseName 'effective_app_credential_policies' -Rows $effectivePolicyRows `
        -Title 'Effective Credential Policy Coverage by Application' `
        -Notes @('Evaluates creation dates and app-specific overrides before applying default restrictions. A disabled custom restriction overrides the default; omitted custom restrictions inherit it.',
            'Limits govern creation/update of credentials; they do not invalidate existing credentials. Existing credential metadata is assessed separately.',
            'Audit limits: secrets and symmetric keys 180 days, certificates 730 days. Actor exemptions and unreadable applicability are reported as unknown.')
    $unprotectedPolicyRows = @($effectivePolicyRows | Where-Object State -eq 'Unprotected')
    if ($unprotectedPolicyRows.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Some apps are outside effective credential lifetime protection' `
            -Evidence ("{0} app or service-principal object(s) have an uncovered credential type: {1}. Reasons and applicable custom policies are in the evidence." -f @($unprotectedPolicyRows.ObjectId | Select-Object -Unique).Count,(Format-EAApplicationCheckList @($unprotectedPolicyRows.ObjectName))) `
            -WhyItMatters 'An enabled default policy does not protect older apps excluded by its creation-date cutoff, apps with weaker custom overrides, or credential types with excessive lifetime limits.' `
            -RecommendedAction 'Review the effective-policy rows. Apply tested restrictions to the existing apps, remove unnecessary custom exemptions, and use a creation-date cutoff and maximum lifetime that cover the intended population. Review existing credentials separately.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/graph/api/resources/applicationauthenticationmethodpolicy' `
            -SourceFile $effectivePolicySource -ResultRows $unprotectedPolicyRows -RuleId 'app-management-effective-coverage-gap' -ObjectType 'application' `
            -AffectedObjectIds @($unprotectedPolicyRows | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'workloadIdentity' -AffectedCount @($unprotectedPolicyRows | ForEach-Object { $_.ObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'applications and service principals with an unprotected credential type'
    }
    $unknownPolicyRows = @($effectivePolicyRows | Where-Object State -eq 'Unknown')
    if ($unknownPolicyRows.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Effective app credential policy coverage could not be fully established' `
            -Evidence ("{0} object(s) have unknown policy coverage. Missing creation dates, custom assignments, enabled states or actor exemptions are explained in the evidence." -f @($unknownPolicyRows.ObjectId | Select-Object -Unique).Count) `
            -WhyItMatters 'Restrictions cannot be counted as enforced when the applicable policy or exemptions cannot be established.' `
            -RecommendedAction 'Resolve missing policy and application reads. Validate creation dates and any actor exemptions, then re-run; do not treat the affected apps as protected until this is established.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/graph/api/resources/applicationauthenticationmethodpolicy' `
            -SourceFile $effectivePolicySource -ResultRows $unknownPolicyRows -RuleId 'app-management-effective-coverage-unknown' -ObjectType 'application' -CoverageGap
    }

    $riskRows = @($credentialRows | Where-Object { $_.State -in @('Expired','ExpiringSoon','NoExpiry') -or $_.LongLived })
    $coverageComplete = ($applicationKnown -and $servicePrincipalKnown -and $ficErrors.Count -eq 0 -and $ficNotAttempted -eq 0 -and $policyErrors.Count -eq 0 -and
        $unknownPolicyRows.Count -eq 0 -and @($script:Findings | Where-Object { $_.CheckId -eq $checkId -and $_.CoverageGap }).Count -eq 0)
    $riskFindings = @($script:Findings | Where-Object { $_.CheckId -eq $checkId -and $_.Severity -ne 'Information' })
    if ($riskFindings.Count -eq 0 -and $coverageComplete -and $credentialsReportedElsewhere.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'No problems found with app credentials or federated credential trusts' `
            -Evidence ("{0}, {1}, and {2} were reviewed without a flagged condition." -f (Format-EAApplicationCheckCount -Count $credentialRows.Count -One 'credential' -Many 'credentials'), (Format-EAApplicationCheckCount -Count $ficRows.Count -One 'federated trust' -Many 'federated trusts'), (Format-EAApplicationCheckCount -Count $customPolicies.Count -One 'custom app management policy' -Many 'custom app management policies')) `
            -WhyItMatters 'Short-lived credentials, clean renewals and narrowly set federated trusts limit what an attacker can do with a leaked app credential.' `
            -RecommendedAction 'Keep reviewing regularly, and automate credential renewal where federated credentials cannot be used.' `
            -SourceFile $credentialSource -ResultRows $riskRows -RuleId 'workloadcredentials-reviewed' -ObjectType 'tenant'
    }
}
