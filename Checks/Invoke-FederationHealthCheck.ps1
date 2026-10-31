<#
Federation & Hybrid Authentication Health. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-FederationHealth {
    [CmdletBinding()]
    param()

    $checkId = 'federationhealth'
    $doc = 'https://learn.microsoft.com/graph/api/domain-list-federationconfiguration?view=graph-rest-1.0'
    $domainDoc = 'https://learn.microsoft.com/graph/api/domain-list?view=graph-rest-1.0'
    $certGuideDoc = 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-o365-certs'
    $domainGuideDoc = 'https://learn.microsoft.com/en-us/entra/identity/users/domains-manage'
    $domainResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,authenticationType,isVerified,isDefault,isAdminManaged,supportedServices,availabilityStatus'
    if (-not $domainResult.Success) { throw $domainResult.Error }

    $rows = New-Object System.Collections.Generic.List[object]
    $configErrors = New-Object System.Collections.Generic.List[object]
    $federatedDomains = @($domainResult.Rows | Where-Object { [string](Get-EAGovProperty $_ 'authenticationType') -ieq 'Federated' })

    foreach ($domain in @($domainResult.Rows)) {
        $domainId = [string](Get-EAGovProperty $domain 'id')
        $isFederated = [string](Get-EAGovProperty $domain 'authenticationType') -ieq 'Federated'
        if (-not $isFederated) {
            $rows.Add([pscustomobject]@{
                Domain=$domainId; AuthenticationType=(Get-EAGovProperty $domain 'authenticationType'); IsVerified=(Get-EAGovProperty $domain 'isVerified')
                IsDefault=(Get-EAGovProperty $domain 'isDefault'); ConfigRead='NotApplicable'; ConfigCount=0; DisplayName=$null
                IssuerUri=$null; MetadataExchangeUri=$null; PreferredAuthenticationProtocol=$null; SupportsMfa=$null
                FederatedIdpMfaBehavior=$null; SignedAuthenticationRequestRequired=$null; SigningThumbprint=$null
                SigningNotAfter=$null; NextSigningThumbprint=$null; NextSigningNotBefore=$null; NextSigningNotAfter=$null; SigningCertificateUpdateStatus=$null
            }) | Out-Null
            continue
        }

        $configResult = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/domains/{0}/federationConfiguration" -f [uri]::EscapeDataString($domainId))
        if (-not $configResult.Success -or $configResult.Truncated) {
            $configReason = if ($configResult.Success) { 'federationConfiguration pagination limit reached' } else { [string]$configResult.Error.Exception.Message }
            $configErrors.Add([pscustomobject]@{ Domain=$domainId; StatusCode=$configResult.StatusCode; Reason=$configReason }) | Out-Null
            $rows.Add([pscustomobject]@{
                Domain=$domainId; AuthenticationType='Federated'; IsVerified=(Get-EAGovProperty $domain 'isVerified')
                IsDefault=(Get-EAGovProperty $domain 'isDefault'); ConfigRead='Failed'; ConfigCount=0; DisplayName=$null
                IssuerUri=$null; MetadataExchangeUri=$null; PreferredAuthenticationProtocol=$null; SupportsMfa=$null
                FederatedIdpMfaBehavior=$null; SignedAuthenticationRequestRequired=$null; SigningThumbprint=$null
                SigningNotAfter=$null; NextSigningThumbprint=$null; NextSigningNotBefore=$null; NextSigningNotAfter=$null; SigningCertificateUpdateStatus=$null
            }) | Out-Null
            continue
        }

        if ($configResult.Rows.Count -eq 0) {
            $configErrors.Add([pscustomobject]@{ Domain=$domainId; StatusCode=404; Reason='Federated domain returned no federation configuration.' }) | Out-Null
        }
        foreach ($config in @($configResult.Rows)) {
            $signing = ConvertFrom-EAGovSigningCertificate (Get-EAGovProperty $config 'signingCertificate')
            $nextSigning = ConvertFrom-EAGovSigningCertificate (Get-EAGovProperty $config 'nextSigningCertificate')
            $rows.Add([pscustomobject]@{
                Domain=$domainId
                AuthenticationType='Federated'
                IsVerified=Get-EAGovProperty $domain 'isVerified'
                IsDefault=Get-EAGovProperty $domain 'isDefault'
                ConfigRead='Complete'
                ConfigCount=$configResult.Rows.Count
                DisplayName=Get-EAGovProperty $config 'displayName'
                IssuerUri=Get-EAGovProperty $config 'issuerUri'
                MetadataExchangeUri=Get-EAGovProperty $config 'metadataExchangeUri'
                PassiveSignInUri=Get-EAGovProperty $config 'passiveSignInUri'
                ActiveSignInUri=Get-EAGovProperty $config 'activeSignInUri'
                PreferredAuthenticationProtocol=Get-EAGovProperty $config 'preferredAuthenticationProtocol'
                SupportsMfa=Get-EAGovProperty $config 'supportsMfa'
                FederatedIdpMfaBehavior=Get-EAGovProperty $config 'federatedIdpMfaBehavior'
                SignedAuthenticationRequestRequired=Get-EAGovProperty $config 'isSignedAuthenticationRequestRequired'
                PromptLoginBehavior=Get-EAGovProperty $config 'promptLoginBehavior'
                SigningCertificateParsed=$signing.Parsed
                SigningCertificateError=$signing.Error
                SigningThumbprint=$signing.Thumbprint
                SigningNotBefore=$signing.NotBefore
                SigningNotAfter=$signing.NotAfter
                NextSigningCertificateParsed=$nextSigning.Parsed
                NextSigningCertificateError=$nextSigning.Error
                NextSigningThumbprint=$nextSigning.Thumbprint
                NextSigningNotBefore=$nextSigning.NotBefore
                NextSigningNotAfter=$nextSigning.NotAfter
                SigningCertificateUpdateStatus=ConvertTo-EAGovCompactJson (Get-EAGovProperty $config 'signingCertificateUpdateStatus')
            }) | Out-Null
        }
    }

    $src = Write-Evidence -BaseName 'federation_health' -Rows $rows.ToArray() -Title 'Domain Federation and Signing-Certificate Health' `
        -Notes @('Certificate bodies are deliberately not exported; only parse status, thumbprints, and validity dates are retained.')
    if ($domainResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Federation' -DataSource 'Domain inventory pagination' `
            -Reason "pagination exceeded $($domainResult.Pages) pages." -RequiredScope 'Domain.Read.All' `
            -DocumentationUrl $domainDoc -SourceFile $src -Partial -Subject 'the list of domains' `
            -Impact 'Federated domains beyond the part that was read were not checked.'
    }
    if ($configErrors.Count -gt 0) {
        $errorSrc = Write-Evidence -BaseName 'federation_configuration_errors' -Rows $configErrors.ToArray() -Title 'Federation Configuration Collection Gaps'
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Federation' `
            -Title ("Federation settings could not be read for {0}" -f (Format-EACount $configErrors.Count 'federated domain' 'federated domains')) `
            -Evidence 'The domain is marked Federated, but its federation configuration could not be read or was absent. This is unknown coverage, not a healthy result.' `
            -WhyItMatters 'Sign-in for these domains is handed to another system, such as Active Directory Federation Services (AD FS). Without its settings the audit cannot warn you before its signing certificate expires, which would stop users of the domain from signing in.' `
            -RecommendedAction 'Give the audit account Domain-InternalFederation.Read.All and a supported reader role, then run the audit again; fix any federated domain that has no federation settings' `
            -DocumentationUrl $doc -SourceFile $errorSrc -ResultRows $configErrors.ToArray() -RuleId 'federation-config-unknown' -CoverageGap
    }

    $unverifiedFederated = @($rows | Where-Object { $_.AuthenticationType -eq 'Federated' -and $_.IsVerified -ne $true })
    if ($unverifiedFederated.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Federation' `
            -Title (Format-EACount $unverifiedFederated.Count 'federated domain is not verified' 'federated domains are not verified') `
            -Evidence 'AuthenticationType=Federated while IsVerified is not true.' `
            -WhyItMatters 'A federated domain that is not verified points to an unfinished or abandoned setup, and sign-ins for it may not go where you expect.' `
            -RecommendedAction 'Confirm who owns each domain and whether it should still be federated, then verify it or remove it in Entra admin center > Entra ID > Domain names' `
            -DocumentationUrl $domainGuideDoc -SourceFile $src -ResultRows $unverifiedFederated -RuleId 'federated-domain-unverified' `
            -AffectedObjectIds @($unverifiedFederated | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'domain' -AffectedCount @($unverifiedFederated | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'federated domains with the stated configuration issue'
    }

    $now = [datetimeoffset]::UtcNow
    $expired = @($rows | Where-Object { $_.ConfigRead -eq 'Complete' -and $_.SigningNotAfter -and (ConvertTo-EAGovDateTime $_.SigningNotAfter) -lt $now })
    if ($expired.Count -gt 0) {
        Add-EAGovFinding -Severity 'Critical' -CheckId $checkId -Category 'Federation' `
            -Title (Format-EACount $expired.Count 'federation signing certificate has expired' 'federation signing certificates have expired') `
            -Evidence 'The parsed signing-certificate NotAfter timestamp is earlier than the audit time.' `
            -WhyItMatters 'When the certificate that signs sign-ins for a federated domain has expired, users of that domain can be unable to sign in to Microsoft 365 at all. It can also mean nobody is looking after the federation setup.' `
            -RecommendedAction 'Renew the token-signing certificate at the identity provider (for example AD FS) now, update it in Microsoft Entra, and test sign-in' `
            -DocumentationUrl $certGuideDoc -SourceFile $src -ResultRows $expired -RuleId 'federation-signing-cert-expired' `
            -AffectedObjectIds @($expired | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'domain' -AffectedCount @($expired | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'federated domains with the stated configuration issue'
    }
    $expiring30 = @($rows | Where-Object {
        $date = ConvertTo-EAGovDateTime $_.SigningNotAfter
        $date -and $date -ge $now -and $date -le $now.AddDays(30)
    })
    if ($expiring30.Count -gt 0) {
        $noReadyNext = @($expiring30 | Where-Object { -not (Test-EAGovNextSigningCertificateReady -Row $_ -Now $now) })
        $severity = if ($noReadyNext.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Federation' `
            -Title (Format-EACount $expiring30.Count 'federation signing certificate expires within 30 days' 'federation signing certificates expire within 30 days') `
            -Evidence ("{0} a parsed replacement certificate that is valid now and remains valid beyond the current certificate's expiry. Both NotBefore and NotAfter are checked." -f (Format-EACount $noReadyNext.Count 'does not have' 'do not have')) `
            -WhyItMatters 'If the certificate expires before it is replaced, users of the federated domain cannot sign in.' `
            -RecommendedAction 'Replace the certificate now (automatic renewal through federation metadata where possible) and test sign-in before the expiry date' `
            -DocumentationUrl $certGuideDoc -SourceFile $src -ResultRows $expiring30 -RuleId 'federation-signing-cert-expiring-30d' `
            -AffectedObjectIds @($expiring30 | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'domain' -AffectedCount @($expiring30 | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'federated domains with the stated configuration issue'
    }
    $expiring90 = @($rows | Where-Object {
        $date = ConvertTo-EAGovDateTime $_.SigningNotAfter
        $date -and $date -gt $now.AddDays(30) -and $date -le $now.AddDays(90)
    })
    if ($expiring90.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Federation' `
            -Title (Format-EACount $expiring90.Count 'federation signing certificate expires within 90 days' 'federation signing certificates expire within 90 days') `
            -Evidence 'Parsed certificate NotAfter is between 31 and 90 days from the audit time.' `
            -WhyItMatters 'Replacing the certificate needs planning and testing; leaving it late risks a sign-in outage for the domain.' `
            -RecommendedAction 'Schedule the certificate replacement, check that the next certificate and the federation metadata address are ready, and watch that the update goes through' `
            -DocumentationUrl $certGuideDoc -SourceFile $src -ResultRows $expiring90 -RuleId 'federation-signing-cert-expiring-90d' `
            -AffectedObjectIds @($expiring90 | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'domain' -AffectedCount @($expiring90 | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'federated domains with the stated configuration issue'
    }

    $unparsed = @($rows | Where-Object { $_.ConfigRead -eq 'Complete' -and $_.SigningCertificateParsed -ne $true })
    if ($unparsed.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Federation' `
            -Title ("Signing certificate could not be read for {0}" -f (Format-EACount $unparsed.Count 'federated domain setting' 'federated domain settings')) `
            -Evidence 'The signingCertificate property was absent or could not be parsed as a base64 DER X.509 certificate. This is not a healthy result.' `
            -WhyItMatters 'Without a readable certificate the audit cannot warn you before it expires, and an expired certificate stops users of that domain from signing in.' `
            -RecommendedAction 'Check the federation trust and the token-signing certificate at the identity provider and in Microsoft Entra, then run the audit again' `
            -DocumentationUrl $certGuideDoc -SourceFile $src -ResultRows $unparsed -RuleId 'federation-signing-cert-unreadable' -CoverageGap
    }

    $multipleConfigs = @($rows | Where-Object { $_.ConfigCount -gt 1 })
    if ($multipleConfigs.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Federation' `
            -Title 'A federated domain has more than one set of federation settings' `
            -Evidence 'The documented API normally returns one configuration per domain; multiple records require validation.' `
            -WhyItMatters 'Duplicate settings make it unclear which certificate and sign-in address are really used, so problems are easy to miss.' `
            -RecommendedAction 'Check the federation settings of the listed domains with the team that runs the identity provider (or with Microsoft support) before changing anything' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $multipleConfigs -RuleId 'federation-multiple-configs' `
            -AffectedObjectIds @($multipleConfigs | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'domain' -AffectedCount @($multipleConfigs | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'federated domains with the stated configuration issue'
    }

    $manualRolloverRisk = @($rows | Where-Object {
        $_.ConfigRead -eq 'Complete' -and [string]::IsNullOrWhiteSpace([string]$_.MetadataExchangeUri) -and
        $_.SigningNotAfter -and (ConvertTo-EAGovDateTime $_.SigningNotAfter) -le $now.AddDays(90)
    })
    if ($manualRolloverRisk.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Federation' `
            -Title ((Format-EACount $manualRolloverRisk.Count 'expiring federation certificate' 'expiring federation certificates') + ' cannot be renewed automatically') `
            -Evidence 'MetadataExchangeUri is empty and the current signing certificate expires within 90 days.' `
            -WhyItMatters 'Without a federation metadata address, Microsoft Entra cannot pick up the new certificate by itself, so someone must update it by hand before expiry or sign-in stops.' `
            -RecommendedAction 'Set up automatic renewal through federation metadata, or plan a manual certificate update well before the expiry date' `
            -DocumentationUrl $certGuideDoc -SourceFile $src -ResultRows $manualRolloverRisk -RuleId 'federation-no-metadata-near-expiry' `
            -AffectedObjectIds @($manualRolloverRisk | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'domain' -AffectedCount @($manualRolloverRisk | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'federated domains with the stated configuration issue'
    }

    # federatedIdpMfaBehavior supersedes SupportsMfa. Microsoft explicitly
    # documents that SupportsMfa is ignored once the newer property is set, so
    # differing values are not a conflict and must not generate a finding.

    $unsignedSaml = @($rows | Where-Object {
        [string]$_.PreferredAuthenticationProtocol -match '(?i)saml' -and $_.SignedAuthenticationRequestRequired -eq $false
    })
    if ($unsignedSaml.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Federation' `
            -Title ((Format-EACount $unsignedSaml.Count 'SAML federation does not' 'SAML federations do not') + ' require signed sign-in requests') `
            -Evidence 'The preferred protocol is SAML and isSignedAuthenticationRequestRequired=false.' `
            -WhyItMatters 'Signed requests let the identity provider check that a sign-in request really came from Microsoft Entra. For these Security Assertion Markup Language (SAML) federations that check is off; this is a hardening step rather than an urgent gap.' `
            -RecommendedAction 'Check whether your identity provider supports signed requests, require them where it does, and record any exception' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $unsignedSaml -RuleId 'federation-unsigned-saml-requests' `
            -AffectedObjectIds @($unsignedSaml | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'domain' -AffectedCount @($unsignedSaml | ForEach-Object { $_.Domain } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'federated domains with the stated configuration issue'
    }

    # Hybrid synchronization health affects federation recovery and identity
    # continuity even though it is stored outside the domain-federation object.
    $syncDoc = 'https://learn.microsoft.com/graph/api/resources/onpremisesdirectorysynchronization?view=graph-rest-1.0'
    $syncSchedulerDoc = 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler'
    $deleteProtectionDoc = 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-prevent-accidental-deletes'
    $orgResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,onPremisesSyncEnabled,onPremisesLastSyncDateTime'
    if (-not $orgResult.Success -or $orgResult.Truncated) {
        $reason = if ($orgResult.Success) { 'organization pagination limit reached' } else { [string]$orgResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Federation' -DataSource 'Hybrid directory synchronization status' `
            -Reason $reason -RequiredScope 'Organization.Read.All' -DocumentationUrl $syncDoc -SourceFile $src `
            -Subject 'the directory sync status' `
            -Impact 'Whether sync from on-premises Active Directory is running, and its protection against mass deletion, were not checked.'
    } else {
        $hybridOrg = @($orgResult.Rows | Where-Object { (Get-EAGovProperty $_ 'onPremisesSyncEnabled') -eq $true } | Select-Object -First 1)
        if ($hybridOrg.Count -gt 0) {
            $lastSync = ConvertTo-EAGovDateTime (Get-EAGovProperty $hybridOrg[0] 'onPremisesLastSyncDateTime')
            if (-not $lastSync) {
                Add-EAGovCoverageFinding -CheckId $checkId -Category 'Federation' -DataSource 'Last on-premises directory synchronization time' `
                    -Reason "onPremisesSyncEnabled=true but onPremisesLastSyncDateTime is absent or invalid. Related: the 'Directory-Sync / PHS Health' check (tenanthealth) reports the same gap as rule tenanthealth-last-sync-unknown." `
                    -RequiredScope 'Organization.Read.All' -DocumentationUrl $syncDoc -SourceFile $src `
                    -Subject 'the time of the last directory sync' `
                    -Impact 'Whether changes made in on-premises Active Directory, such as disabled leavers, still reach the cloud was not checked.' `
                    -RecommendedAction 'Check the last sync time in Entra admin center > Entra ID > Entra Connect'
            } elseif ($lastSync -lt $now.AddHours(-24)) {
                Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Federation' `
                    -Title 'Directory sync from on-premises Active Directory has been stopped for over 24 hours' `
                    -Evidence ("Last tenant sync={0:u}; age hours={1}. Related: the 'Directory-Sync / PHS Health' check (tenanthealth) flags the same sync age from 3 hours on (rule tenanthealth-sync-stale); this finding marks an outage of more than a day. One fix resolves both." -f $lastSync,[math]::Round(($now - $lastSync).TotalHours,1)) `
                    -WhyItMatters 'While sync is stopped, accounts disabled in on-premises Active Directory (AD) stay active in the cloud, and password and group changes do not arrive, so leavers can keep signing in to Microsoft 365.' `
                    -RecommendedAction 'Check the Microsoft Entra Connect server or Cloud Sync agents, fix the errors they report, and confirm sync runs again (Entra admin center > Entra ID > Entra Connect)' `
                    -DocumentationUrl $syncSchedulerDoc -SourceFile $src -RuleId 'hybrid-directory-sync-stale'
            }

            $syncResult = Get-EAGovOnPremisesSyncObject
            $syncAccess = Get-EAGovOnPremSyncAccess
            $deletionThresholdAction = 'check the deletion threshold on the Microsoft Entra Connect server (Get-ADSyncExportDeletionThreshold) or in the Cloud Sync configuration'
            if (-not $syncResult.Success -or $null -eq $syncResult.Object) {
                $syncReason = if ($syncResult.Success) { 'Graph returned no on-premises synchronization object.' } else { [string]$syncResult.Error.Exception.Message }
                Add-EAGovCoverageFinding -CheckId $checkId -Category 'Federation' -DataSource 'On-premises synchronization safeguards' `
                    -Reason ($syncReason + $syncAccess.Note) -RequiredScope $syncAccess.Scope `
                    -DocumentationUrl $syncDoc -SourceFile $src -Subject 'the directory sync safety settings' `
                    -Impact 'Whether sync is protected against deleting many accounts at once was not checked.' `
                    -RecommendedAction ("Run the audit signed in as a Global Administrator with OnPremDirectorySynchronization.Read.All (app-only sign-in is not supported for this setting), or {0}" -f $deletionThresholdAction)
            } else {
                $syncObject = $syncResult.Object
                $prevention = Get-EAGovProperty (Get-EAGovProperty $syncObject 'configuration') 'accidentalDeletionPrevention'
                $preventionType = [string](Get-EAGovProperty $prevention 'synchronizationPreventionType')
                $threshold = Get-EAGovProperty $prevention 'alertThreshold'
                $syncRows = @([pscustomobject]@{
                    OnPremisesLastSyncDateTime=$lastSync
                    SyncObjectsReturned=$syncResult.Count
                    AccidentalDeletionPrevention=$preventionType
                    AccidentalDeletionAlertThreshold=$threshold
                    Features=ConvertTo-EAGovCompactJson (Get-EAGovProperty $syncObject 'features')
                })
                $syncSrc = Write-Evidence -BaseName 'federation_hybrid_sync_health' -Rows $syncRows -Title 'Hybrid Directory Synchronization Health and Safeguards'
                if ([string]::IsNullOrWhiteSpace($preventionType)) {
                    Add-EAGovCoverageFinding -CheckId $checkId -Category 'Federation' -DataSource 'Accidental deletion prevention state' `
                        -Reason 'the sync settings were read, but configuration.accidentalDeletionPrevention.synchronizationPreventionType was absent.' -RequiredScope $syncAccess.Scope `
                        -DocumentationUrl $syncDoc -SourceFile $syncSrc -Subject 'the accidental-deletion protection setting' `
                        -Impact 'Whether sync is protected against deleting many accounts at once was not checked.' `
                        -RecommendedAction 'Check the deletion threshold on the Microsoft Entra Connect server (Get-ADSyncExportDeletionThreshold) or in the Cloud Sync configuration'
                } elseif ($preventionType -match '^(disabled|unknownFutureValue)$') {
                    Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Federation' `
                        -Title 'Directory sync has no protection against deleting many accounts at once' `
                        -Evidence ("synchronizationPreventionType={0}; alertThreshold={1}." -f $preventionType,$threshold) `
                        -WhyItMatters 'One wrong filter or mistake in on-premises Active Directory (AD) could delete many cloud accounts in a single sync run, cutting people off from email, files and apps.' `
                        -RecommendedAction 'Turn on accidental-deletion prevention with a threshold (the Microsoft Entra Connect default is 500 objects, set with Enable-ADSyncExportDeletionThreshold) and test the alert and unblock process' `
                        -DocumentationUrl $deleteProtectionDoc -SourceFile $syncSrc -RuleId 'hybrid-sync-accidental-delete-protection-disabled'
                }
            }
        }
    }

    if ($federatedDomains.Count -eq 0 -and -not $domainResult.Truncated) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Federation' `
            -Title 'No federated domains: Microsoft Entra handles sign-in for every domain' `
            -Evidence ((Format-EACount @($domainResult.Rows).Count 'domain was' 'domains were') + ' read; all use managed or another non-federated authentication type.') `
            -WhyItMatters 'Risks from an outside identity provider, such as an expired signing certificate, do not apply to this tenant.' `
            -RecommendedAction 'Keep an eye out for domains being switched to federated sign-in, and limit who holds the roles that can do it' `
            -DocumentationUrl $domainDoc -SourceFile $src -ResultRows $rows.ToArray() -RuleId 'federation-none'
    } else {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Federation' `
            -Title ("Federation settings recorded for {0}" -f (Format-EACount $federatedDomains.Count 'federated domain' 'federated domains')) `
            -Evidence ("Federated domains={0}; configuration read failures={1}; certificate metadata is exported without certificate bodies." -f $federatedDomains.Count,$configErrors.Count) `
            -WhyItMatters "Federated sign-in depends on the outside identity provider's certificate, addresses and settings; this record is the baseline for spotting changes." `
            -RecommendedAction 'Watch certificate renewal dates and set up alerts for changes to federation settings' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $rows.ToArray() -RuleId 'federation-inventory'
    }
}
