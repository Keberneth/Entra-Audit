<#
  Additional read-only application, workload identity, and monitoring checks.

  This file intentionally contains function definitions only. It is dot-sourced by
  EntraAudit-PS7.ps1 after the shared helpers have been defined. Every remote request
  in this module uses Microsoft Graph GET; no create, update, delete, consent, or
  remediation operation is performed.
#>

function Get-EAApplicationCheckValue {
    param(
        [object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) { return $null }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in @($Object.Keys)) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return ,$Object[$key]
            }
        }
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return ,$property.Value }

    $additional = $Object.PSObject.Properties['AdditionalProperties']
    if ($additional -and $additional.Value -is [System.Collections.IDictionary]) {
        $bag = $additional.Value
        foreach ($key in @($bag.Keys)) {
            if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return ,$bag[$key]
            }
        }
    }
    return $null
}

function ConvertTo-EAApplicationCheckUtcDate {
    param([object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return ([datetimeoffset]$Value).UtcDateTime } catch { return $null }
}

function ConvertTo-EAApplicationCheckDurationDays {
    param([object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try {
        if ($Value -is [timespan]) { return [math]::Round($Value.TotalDays, 2) }
        return [math]::Round(([System.Xml.XmlConvert]::ToTimeSpan([string]$Value)).TotalDays, 2)
    } catch { return $null }
}

function ConvertTo-EAApplicationCheckBoolean {
    param([object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    $text = ([string]$Value).Trim()
    if ($text -match '^(?i:true|1|enabled)$') { return $true }
    if ($text -match '^(?i:false|0|disabled)$') { return $false }
    return $null
}

function Get-EAApplicationCheckHttpStatus {
    param([object]$ErrorRecord)

    try { return [int]$ErrorRecord.Exception.Response.StatusCode.value__ } catch {}
    try { return [int]$ErrorRecord.Exception.Response.StatusCode } catch {}
    return $null
}

function Get-EAReadOnlyGraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateRange(1, 2000)][int]$MaximumPages = 500
    )

    $rows = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $page = 0
    while ($next) {
        if ([string]$next -notmatch '^https://graph\.microsoft\.com/(v1\.0|beta)/') {
            throw "Refusing non-Microsoft-Graph collection or pagination URI: $next"
        }
        if ($page -ge $MaximumPages) {
            throw "Graph collection exceeded the $MaximumPages-page safety limit; coverage is incomplete."
        }
        # Invariant: GET is the only HTTP method used anywhere in this module.
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        $values = Get-EAApplicationCheckValue -Object $response -Name 'value'
        if ($null -eq $values) {
            # A collection endpoint should return value[]. Treat a structurally unexpected
            # response as unknown instead of quietly converting it to an empty collection.
            throw "Graph collection response for '$next' did not contain a value array."
        }
        foreach ($item in @($values)) { $rows.Add($item) | Out-Null }
        $next = [string](Get-EAApplicationCheckValue -Object $response -Name '@odata.nextLink')
        $page++
    }
    return @($rows.ToArray())
}

function Get-EAWorkloadCredentialRows {
    param(
        [object[]]$Objects,
        [Parameter(Mandatory)][ValidateSet('Application','ServicePrincipal')][string]$ObjectType,
        [Parameter(Mandatory)][datetime]$Now,
        [Parameter(Mandatory)][int]$WarningDays
    )

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($object in @($Objects)) {
        $displayName = [string](Get-EAApplicationCheckValue $object 'DisplayName')
        $objectId = [string](Get-EAApplicationCheckValue $object 'Id')
        $appId = [string](Get-EAApplicationCheckValue $object 'AppId')

        foreach ($spec in @(
            [pscustomobject]@{ Property='PasswordCredentials'; Type='Secret'; LongDays=180 },
            [pscustomobject]@{ Property='KeyCredentials';      Type='Certificate'; LongDays=730 }
        )) {
            foreach ($credential in @(Get-EAApplicationCheckValue $object $spec.Property)) {
                if ($null -eq $credential) { continue }
                $start = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $credential 'StartDateTime')
                $end = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $credential 'EndDateTime')
                $noExpiry = ($null -eq $end)
                $lifetime = if ($start -and $end) { [math]::Round(($end - $start).TotalDays, 1) } else { $null }
                $daysLeft = if ($end) { [math]::Floor(($end - $Now).TotalDays) } else { $null }
                $state = if ($noExpiry) { 'NoExpiry' } elseif ($end -lt $Now) { 'Expired' } elseif ($end -le $Now.AddDays($WarningDays)) { 'ExpiringSoon' } else { 'Valid' }
                $active = ((-not $start) -or $start -le $Now) -and ($noExpiry -or $end -gt $Now)
                $longLived = ($null -ne $lifetime -and $lifetime -gt $spec.LongDays)
                $rows.Add([pscustomobject]@{
                    ObjectType       = $ObjectType
                    ObjectName       = $displayName
                    ObjectId         = $objectId
                    AppId            = $appId
                    CredentialType   = $spec.Type
                    CredentialName   = [string](@(
                        Get-EAApplicationCheckValue $credential 'DisplayName'
                        Get-EAApplicationCheckValue $credential 'KeyId'
                    ) | Where-Object { $_ } | Select-Object -First 1)
                    KeyId            = [string](Get-EAApplicationCheckValue $credential 'KeyId')
                    StartDateTime    = $start
                    EndDateTime      = $end
                    LifetimeDays     = $lifetime
                    DaysLeft         = $daysLeft
                    State            = $state
                    ActiveNow        = [bool]$active
                    LongLived        = [bool]$longLived
                    LongLifeLimitDays= $spec.LongDays
                }) | Out-Null
            }
        }
    }
    return @($rows.ToArray())
}

function Get-EAWorkloadCredentialOverlapRows {
    param(
        [object[]]$CredentialRows,
        [ValidateRange(1, 3650)][int]$AllowedOverlapDays = 30
    )

    $rows = New-Object System.Collections.Generic.List[object]
    $groups = @($CredentialRows | Where-Object { $_.ActiveNow } | Group-Object ObjectType,ObjectId,CredentialType)
    foreach ($group in $groups) {
        $credentials = @($group.Group)
        if ($credentials.Count -lt 2) { continue }

        $maxOverlap = 0.0
        for ($i = 0; $i -lt $credentials.Count; $i++) {
            for ($j = $i + 1; $j -lt $credentials.Count; $j++) {
                $left = $credentials[$i]
                $right = $credentials[$j]
                if (-not $left.StartDateTime -or -not $right.StartDateTime -or -not $left.EndDateTime -or -not $right.EndDateTime) { continue }
                $overlapStart = if ($left.StartDateTime -gt $right.StartDateTime) { $left.StartDateTime } else { $right.StartDateTime }
                $overlapEnd = if ($left.EndDateTime -lt $right.EndDateTime) { $left.EndDateTime } else { $right.EndDateTime }
                if ($overlapEnd -gt $overlapStart) {
                    $days = ($overlapEnd - $overlapStart).TotalDays
                    if ($days -gt $maxOverlap) { $maxOverlap = $days }
                }
            }
        }

        if ($credentials.Count -gt 2 -or $maxOverlap -gt $AllowedOverlapDays) {
            $sample = $credentials[0]
            $reason = @()
            if ($credentials.Count -gt 2) { $reason += ("{0} simultaneously active credentials" -f $credentials.Count) }
            if ($maxOverlap -gt $AllowedOverlapDays) { $reason += ("maximum pair overlap {0:N0} days" -f $maxOverlap) }
            $rows.Add([pscustomobject]@{
                ObjectType       = $sample.ObjectType
                ObjectName       = $sample.ObjectName
                ObjectId         = $sample.ObjectId
                AppId            = $sample.AppId
                CredentialType   = $sample.CredentialType
                ActiveCount      = $credentials.Count
                MaximumOverlapDays = [math]::Round($maxOverlap, 1)
                Reason           = ($reason -join '; ')
            }) | Out-Null
        }
    }
    return @($rows.ToArray())
}

function Get-EAAppManagementPolicyRows {
    param(
        [Parameter(Mandatory)][object]$Policy,
        [Parameter(Mandatory)][string]$PolicyType,
        [int]$AssignmentCount = 0,
        [string]$AssignmentState = 'NotApplicable'
    )

    $rows = New-Object System.Collections.Generic.List[object]
    $policyId = [string](Get-EAApplicationCheckValue $Policy 'id')
    $policyName = [string](Get-EAApplicationCheckValue $Policy 'displayName')
    $enabledValue = Get-EAApplicationCheckValue $Policy 'isEnabled'
    $enabled = ConvertTo-EAApplicationCheckBoolean $enabledValue

    $configs = @()
    if ($PolicyType -eq 'Default') {
        $configs += [pscustomobject]@{ Scope='Applications'; Config=(Get-EAApplicationCheckValue $Policy 'applicationRestrictions') }
        $configs += [pscustomobject]@{ Scope='ServicePrincipals'; Config=(Get-EAApplicationCheckValue $Policy 'servicePrincipalRestrictions') }
    } else {
        $configs += [pscustomobject]@{ Scope='AssignedObjects'; Config=(Get-EAApplicationCheckValue $Policy 'restrictions') }
    }

    foreach ($configEntry in $configs) {
        $config = $configEntry.Config
        $added = 0
        foreach ($kind in @(
            [pscustomobject]@{ Property='passwordCredentials'; CredentialType='PasswordOrSymmetricKey' },
            [pscustomobject]@{ Property='keyCredentials'; CredentialType='Certificate' }
        )) {
            foreach ($restriction in @(Get-EAApplicationCheckValue $config $kind.Property)) {
                if ($null -eq $restriction) { continue }
                $added++
                $maxLifetime = Get-EAApplicationCheckValue $restriction 'maxLifetime'
                $rows.Add([pscustomobject]@{
                    PolicyType        = $PolicyType
                    PolicyName        = $policyName
                    PolicyId          = $policyId
                    PolicyEnabled     = $enabled
                    AppliesTo         = $configEntry.Scope
                    AssignmentCount   = $AssignmentCount
                    AssignmentState   = $AssignmentState
                    CredentialType    = $kind.CredentialType
                    RestrictionType   = [string](Get-EAApplicationCheckValue $restriction 'restrictionType')
                    RestrictionState  = [string](Get-EAApplicationCheckValue $restriction 'state')
                    MaxLifetime       = [string]$maxLifetime
                    MaxLifetimeDays   = ConvertTo-EAApplicationCheckDurationDays $maxLifetime
                    EnforcedFrom      = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $restriction 'restrictForAppsCreatedAfterDateTime')
                }) | Out-Null
            }
        }
        if ($added -eq 0) {
            $rows.Add([pscustomobject]@{
                PolicyType=$PolicyType; PolicyName=$policyName; PolicyId=$policyId; PolicyEnabled=$enabled
                AppliesTo=$configEntry.Scope; AssignmentCount=$AssignmentCount; AssignmentState=$AssignmentState
                CredentialType='None'; RestrictionType='None'; RestrictionState='None'; MaxLifetime=$null
                MaxLifetimeDays=$null; EnforcedFrom=$null
            }) | Out-Null
        }
    }
    return @($rows.ToArray())
}

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
    $credentialSource = Write-Evidence -BaseName 'workload_credentials' -Rows $credentialRows `
        -Title 'Workload Identity Credentials (applications and service principals)' `
        -Notes @(
            'Secret lifetime review threshold: 180 days; certificate lifetime review threshold: 730 days.',
            ("Expiry warning window: {0} days." -f $warningDays),
            'Credential values are never returned by these Graph reads; only metadata is exported.',
            ("Excluded {0} Microsoft first-party, managed-identity, or other non-application service principal(s) whose credentials are not tenant-managed workload secrets." -f ($servicePrincipals.Count - $credentialServicePrincipals.Count))
        )

    $coverageRows = @()
    if (-not $applicationKnown) { $coverageRows += [pscustomobject]@{ Dataset='Applications'; State='Unknown'; Error=$applicationError } }
    if (-not $servicePrincipalKnown) { $coverageRows += [pscustomobject]@{ Dataset='ServicePrincipals'; State='Unknown'; Error=$servicePrincipalError } }
    if ($coverageRows.Count -gt 0) {
        $coverageSource = Write-Evidence -BaseName 'workload_credential_collection_gaps' -Rows $coverageRows -Title 'Workload Credential Collection Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Workload credential inventory is incomplete' `
            -Evidence ("{0} required object collection(s) could not be read; their credential posture is unknown." -f $coverageRows.Count) `
            -WhyItMatters 'A clean credential result is not trustworthy when application or service-principal credentials were not enumerated.' `
            -RecommendedAction 'Confirm Application.Read.All, resolve Graph throttling/connectivity errors, and re-run the workloadcredentials check.' `
            -SourceFile $coverageSource -ResultRows $coverageRows -RuleId 'workload-credential-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }

    $expired = @($credentialRows | Where-Object { $_.State -eq 'Expired' })
    $expiring = @($credentialRows | Where-Object { $_.State -eq 'ExpiringSoon' })
    $noExpiry = @($credentialRows | Where-Object { $_.State -eq 'NoExpiry' })
    $longLived = @($credentialRows | Where-Object { $_.LongLived })
    $overlaps = @(Get-EAWorkloadCredentialOverlapRows -CredentialRows $credentialRows)
    $overlapSource = Write-Evidence -BaseName 'workload_credential_overlap' -Rows $overlaps -Title 'Workload Credential Overlap Review'

    if ($noExpiry.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId $checkId -Category $category `
            -Title ("{0} workload credential(s) have no readable expiry" -f $noExpiry.Count) `
            -Evidence ("No-expiry credential metadata was returned for {0} object(s)." -f @($noExpiry.ObjectId | Select-Object -Unique).Count) `
            -WhyItMatters 'A secret or certificate without an enforced expiry can remain usable indefinitely after its owner, integration, or operational need has gone away.' `
            -RecommendedAction 'Confirm the metadata is valid, replace non-expiring credentials with short-lived certificates or federated identity credentials, and remove the old credential after rotation.' `
            -SourceFile $credentialSource -ResultRows $noExpiry -RuleId 'workload-credential-no-expiry' -ObjectType 'workloadIdentity' -CoverageGap
    }
    if ($expired.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ("{0} workload credential(s) are expired" -f $expired.Count) `
            -Evidence ("Expired credentials affect {0} application/service-principal object(s)." -f @($expired.ObjectId | Select-Object -Unique).Count) `
            -WhyItMatters 'Expired credentials indicate broken integrations or unmanaged credential lifecycle, and leave stale authentication material obscuring what is actually in use.' `
            -RecommendedAction 'Validate each integration, remove obsolete expired credentials, and rotate required credentials through a documented process.' `
            -SourceFile $credentialSource -ResultRows $expired -RuleId 'workload-credential-expired' -ObjectType 'workloadIdentity'
    }
    if ($expiring.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ("{0} workload credential(s) expire within {1} days" -f $expiring.Count, $warningDays) `
            -Evidence ("Upcoming expirations affect {0} application/service-principal object(s)." -f @($expiring.ObjectId | Select-Object -Unique).Count) `
            -WhyItMatters 'An unplanned credential expiry causes integration outages; a controlled overlap is needed for rotation.' `
            -RecommendedAction 'Schedule rotation before expiry, validate the new credential, then promptly remove the old credential.' `
            -SourceFile $credentialSource -ResultRows $expiring -RuleId 'workload-credential-expiring' -ObjectType 'workloadIdentity'
    }
    if ($longLived.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ("{0} workload credential(s) exceed the lifetime review threshold" -f $longLived.Count) `
            -Evidence 'Secrets longer than 180 days or certificates longer than 730 days were found.' `
            -WhyItMatters 'Long-lived credentials widen the period in which copied authentication material remains useful to an attacker and often indicate missing rotation automation.' `
            -RecommendedAction 'Shorten credential validity, automate rotation, and prefer workload identity federation where the external platform supports it.' `
            -SourceFile $credentialSource -ResultRows $longLived -RuleId 'workload-credential-long-lived' -ObjectType 'workloadIdentity'
    }
    if ($overlaps.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ("{0} workload identity credential set(s) have excessive overlap" -f $overlaps.Count) `
            -Evidence 'More than two credentials are simultaneously active, or a pair overlaps for more than 30 days.' `
            -WhyItMatters 'Brief overlap supports safe rotation; prolonged or multi-credential overlap leaves unnecessary authentication paths active and makes credential ownership unclear.' `
            -RecommendedAction 'Identify the credential currently used by each workload and remove superseded credentials after a tested rotation window.' `
            -SourceFile $overlapSource -ResultRows $overlaps -RuleId 'workload-credential-excessive-overlap' -ObjectType 'workloadIdentity'
    }

    # Federated credentials are a relationship of application objects and are not present
    # in the normal application collection. Enumerate each relationship with read-only GET.
    $ficRows = New-Object System.Collections.Generic.List[object]
    $ficErrors = New-Object System.Collections.Generic.List[object]
    if ($applicationKnown) {
        foreach ($application in $applications) {
            $applicationId = [string](Get-EAApplicationCheckValue $application 'Id')
            if (-not $applicationId) { continue }
            # The beta representation is required to expose flexible FIC
            # claimsMatchingExpression. It is still a GET-only relationship read and uses
            # the same least-privileged Application.Read.All permission as v1.0.
            $uri = 'https://graph.microsoft.com/beta/applications/' + [uri]::EscapeDataString($applicationId) + '/federatedIdentityCredentials?$select=id,name,issuer,subject,audiences,description,claimsMatchingExpression'
            try {
                foreach ($fic in @(Get-EAReadOnlyGraphCollection -Uri $uri -MaximumPages 20)) {
                    $audiences = @((Get-EAApplicationCheckValue $fic 'audiences') | Where-Object { $_ })
                    $issuer = [string](Get-EAApplicationCheckValue $fic 'issuer')
                    $subject = [string](Get-EAApplicationCheckValue $fic 'subject')
                    $claimsExpression = Get-EAApplicationCheckValue $fic 'claimsMatchingExpression'
                    $expressionValue = [string](Get-EAApplicationCheckValue $claimsExpression 'value')
                    $expressionLanguageVersion = Get-EAApplicationCheckValue $claimsExpression 'languageVersion'
                    $ficRows.Add([pscustomobject]@{
                        Application = [string](Get-EAApplicationCheckValue $application 'DisplayName')
                        AppId       = [string](Get-EAApplicationCheckValue $application 'AppId')
                        ObjectId    = $applicationId
                        Credential  = [string](Get-EAApplicationCheckValue $fic 'name')
                        Issuer      = $issuer
                        Subject     = $subject
                        ClaimsMatchingExpression = $expressionValue
                        ExpressionLanguageVersion = $expressionLanguageVersion
                        Audiences   = ($audiences -join ', ')
                        MissingTrustField = (-not $issuer -or (-not $subject -and -not $expressionValue) -or $audiences.Count -eq 0)
                        ConflictingSubjectAndExpression = [bool]($subject -and $expressionValue)
                        InvalidExpressionLanguageVersion = [bool]($expressionValue -and [string]$expressionLanguageVersion -ne '1')
                        NonStandardAudience = ($audiences.Count -gt 0 -and @($audiences | Where-Object { $_ -ne 'api://AzureADTokenExchange' }).Count -gt 0)
                        FlexibleWildcardExpression = ($expressionValue -match '[*?]')
                    }) | Out-Null
                }
            } catch {
                $status = Get-EAApplicationCheckHttpStatus $_
                $ficErrors.Add([pscustomobject]@{
                    Application=[string](Get-EAApplicationCheckValue $application 'DisplayName'); ObjectId=$applicationId
                    StatusCode=$status; Error=$_.Exception.Message
                }) | Out-Null
                # A tenant-wide authorization failure will repeat for every object. Stop and
                # record the remaining population as unknown rather than hammering Graph.
                if ($status -in 401,403) { break }
            }
        }
    }
    $ficSource = Write-Evidence -BaseName 'federated_identity_credentials' -Rows @($ficRows.ToArray()) `
        -Title 'Federated Identity Credential Trusts' `
        -Notes @('Issuer, subject, and audience are trust-boundary metadata. Secrets/tokens are not returned.')
    if ($ficErrors.Count -gt 0 -or -not $applicationKnown) {
        $ficErrorRows = @($ficErrors.ToArray())
        if (-not $applicationKnown) { $ficErrorRows += [pscustomobject]@{ Application='All applications'; ObjectId=''; StatusCode=''; Error='Application collection unavailable' } }
        $ficErrorSource = Write-Evidence -BaseName 'federated_identity_credential_collection_gaps' -Rows $ficErrorRows -Title 'Federated Identity Credential Collection Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Federated identity credential coverage is incomplete' `
            -Evidence ("{0} application relationship read(s) failed or could not be attempted; an empty trust inventory is not a clean result." -f $ficErrorRows.Count) `
            -WhyItMatters 'Unreviewed issuer, subject, or audience bindings can allow an external workload to exchange its token for an Entra application token.' `
            -RecommendedAction 'Confirm Application.Read.All and a supported directory role, resolve Graph errors, and re-run the check.' `
            -SourceFile $ficErrorSource -ResultRows $ficErrorRows -RuleId 'federated-credential-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }
    $invalidFic = @($ficRows.ToArray() | Where-Object {
        $_.MissingTrustField -or $_.NonStandardAudience -or $_.ConflictingSubjectAndExpression -or $_.InvalidExpressionLanguageVersion
    })
    if ($invalidFic.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId $checkId -Category $category `
            -Title ("{0} federated identity credential trust(s) require review" -f $invalidFic.Count) `
            -Evidence 'A trust has a missing issuer/subject-or-expression/audience, conflicting subject and expression fields, an unsupported expression language version, or a nonstandard token-exchange audience.' `
            -WhyItMatters 'Federated credentials remove stored secrets but make the external issuer and subject claim the security boundary; an overly broad binding can authorize the wrong workload.' `
            -RecommendedAction 'Verify the external issuer, pin the subject to the exact repository/environment/service account, and use api://AzureADTokenExchange unless a documented sovereign-cloud design requires another audience.' `
            -SourceFile $ficSource -ResultRows $invalidFic -RuleId 'federated-credential-broad-trust' -ObjectType 'application'
    }
    $flexibleFic = @($ficRows.ToArray() | Where-Object { $_.FlexibleWildcardExpression })
    if ($flexibleFic.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ("{0} flexible federated identity trust(s) use wildcard claim matching" -f $flexibleFic.Count) `
            -Evidence 'Flexible FIC expressions using * or ? were found. A literal subject value is always exact and is not treated as a wildcard.' `
            -WhyItMatters 'Flexible matching can safely reduce credential count, but its wildcard boundary must remain pinned to the intended organization, repository, workflow, environment, or service account.' `
            -RecommendedAction 'Review each complete claim expression and its issuer; keep wildcard comparands inside an immutable trusted namespace and add exact workflow/environment claims where supported.' `
            -SourceFile $ficSource -ResultRows $flexibleFic -RuleId 'federated-credential-flexible-wildcard' -ObjectType 'application'
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
    try {
        $customPolicies = @(Get-EAReadOnlyGraphCollection -Uri 'https://graph.microsoft.com/v1.0/policies/appManagementPolicies?$top=999')
        foreach ($policy in $customPolicies) {
            $policyId = [string](Get-EAApplicationCheckValue $policy 'id')
            $assignmentCount = 0
            $assignmentState = 'Known'
            try {
                $assignmentUri = 'https://graph.microsoft.com/v1.0/policies/appManagementPolicies/' + [uri]::EscapeDataString($policyId) + '/appliesTo?$select=id,appId,displayName'
                $assignmentCount = @(Get-EAReadOnlyGraphCollection -Uri $assignmentUri -MaximumPages 50).Count
            } catch {
                $assignmentState = 'Unknown'
                $policyErrors += [pscustomobject]@{ Dataset=("Policy appliesTo: {0}" -f $policyId); Error=$_.Exception.Message }
            }
            $policyRows += @(Get-EAAppManagementPolicyRows -Policy $policy -PolicyType Custom -AssignmentCount $assignmentCount -AssignmentState $assignmentState)
        }
    } catch { $policyErrors += [pscustomobject]@{ Dataset='Custom policies'; Error=$_.Exception.Message } }

    $policySource = Write-Evidence -BaseName 'app_management_policies' -Rows $policyRows -Title 'Application Authentication Method Policies'
    if ($policyErrors.Count -gt 0) {
        $policyErrorSource = Write-Evidence -BaseName 'app_management_policy_collection_gaps' -Rows $policyErrors -Title 'Application Management Policy Collection Gaps'
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Application-management policy posture is incomplete' `
            -Evidence ("{0} policy or assignment dataset(s) could not be read. Policy.Read.All and Application.Read.All are required." -f $policyErrors.Count) `
            -WhyItMatters 'Credential lifetime findings can recur when tenant or app-specific policy enforcement is absent or cannot be verified.' `
            -RecommendedAction 'Grant only the documented read permissions to the audit identity, confirm the operator is at least Global Reader, and re-run.' `
            -SourceFile $policyErrorSource -ResultRows $policyErrors -RuleId 'app-management-policy-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }
    if ($defaultPolicy) {
        $defaultEnabledValue = Get-EAApplicationCheckValue $defaultPolicy 'isEnabled'
        $defaultEnabled = ConvertTo-EAApplicationCheckBoolean $defaultEnabledValue
        if ($null -eq $defaultEnabled) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'Default application-management policy enabled state is unknown' `
                -Evidence 'defaultAppManagementPolicy was returned, but isEnabled was missing or was not a recognized boolean value.' `
                -WhyItMatters 'Lifetime restrictions cannot be considered enforced unless the tenant policy enabled state is known.' `
                -RecommendedAction 'Confirm Policy.Read.All, inspect the raw response, and re-run after resolving Graph response or compatibility issues.' `
                -SourceFile $policySource -ResultRows @($policyRows | Where-Object { $_.PolicyType -eq 'Default' }) -RuleId 'default-app-management-policy-state-unknown' -ObjectType 'tenant' -CoverageGap
        } elseif (-not $defaultEnabled) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'Default application-management policy is disabled' `
                -Evidence 'defaultAppManagementPolicy.isEnabled is false.' `
                -WhyItMatters 'Without a tenant-wide policy, credential lifetime and credential-addition restrictions depend on app-by-app administration and are easy to bypass operationally.' `
                -RecommendedAction 'Design and enable tenant-wide restrictions for application and service-principal secrets, symmetric keys, and certificate lifetimes; validate compatibility before enforcement.' `
                -SourceFile $policySource -ResultRows @($policyRows | Where-Object { $_.PolicyType -eq 'Default' }) -RuleId 'default-app-management-policy-disabled' -ObjectType 'tenant'
        } else {
            # The tenant policy has independent applicationRestrictions and
            # servicePrincipalRestrictions. A rule in one object class must never make the
            # other class appear protected.
            $missingDefaultLifetimes = @()
            foreach ($scopeName in @('Applications','ServicePrincipals')) {
                $scopeRows = @($policyRows | Where-Object {
                    $_.PolicyType -eq 'Default' -and $_.AppliesTo -eq $scopeName -and $_.PolicyEnabled -and
                    $_.RestrictionState -eq 'enabled'
                })
                $hasPassword = @($scopeRows | Where-Object {
                    $_.RestrictionType -eq 'passwordLifetime' -and $null -ne $_.MaxLifetimeDays
                }).Count -gt 0
                $hasSymmetricKey = @($scopeRows | Where-Object {
                    $_.RestrictionType -eq 'symmetricKeyLifetime' -and $null -ne $_.MaxLifetimeDays
                }).Count -gt 0
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
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'Default application-management policy does not enforce every credential lifetime class' `
                -Evidence ("Missing or incomplete lifetime enforcement affects: {0}." -f (($missingDefaultLifetimes.AppliesTo) -join ', ')) `
                -WhyItMatters 'Application objects and service-principal objects have independent default restrictions; enforcement on one object class does not protect the other.' `
                -RecommendedAction 'Add enabled passwordLifetime, symmetricKeyLifetime, and asymmetricKeyLifetime restrictions with reviewed maximum lifetimes and enforcement dates.' `
                -SourceFile $policySource -ResultRows $missingDefaultLifetimes -RuleId 'default-app-management-policy-lifetime-gap' -ObjectType 'tenant'
            }
        }
    }

    $unassignedCustomPolicies = @($policyRows | Where-Object {
        $_.PolicyType -eq 'Custom' -and $_.PolicyEnabled -and $_.AssignmentState -eq 'Known' -and $_.AssignmentCount -eq 0
    } | Group-Object PolicyId | ForEach-Object { $_.Group | Select-Object -First 1 })
    if ($unassignedCustomPolicies.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ("{0} enabled custom application-management policy/policies have no assignments" -f $unassignedCustomPolicies.Count) `
            -Evidence 'The policies are enabled but their appliesTo relationship returned zero applications or service principals.' `
            -WhyItMatters 'An unassigned custom policy does not enforce its credential restrictions and may indicate an abandoned rollout or mistaken assumption of coverage.' `
            -RecommendedAction 'Assign each policy to the intended application/service-principal objects or remove the unused policy after change control.' `
            -SourceFile $policySource -ResultRows $unassignedCustomPolicies -RuleId 'custom-app-management-policy-unassigned' -ObjectType 'policy'
    }

    $riskRows = @($credentialRows | Where-Object { $_.State -in @('Expired','ExpiringSoon','NoExpiry') -or $_.LongLived })
    $coverageComplete = ($applicationKnown -and $servicePrincipalKnown -and $ficErrors.Count -eq 0 -and $policyErrors.Count -eq 0)
    $riskFindings = @($script:Findings | Where-Object { $_.CheckId -eq $checkId -and $_.Severity -ne 'Information' })
    if ($riskFindings.Count -eq 0 -and $coverageComplete) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Workload credential lifecycle and federation trusts reviewed' `
            -Evidence ("{0} credential(s), {1} federated trust(s), and {2} custom app-management policy/policies were reviewed without a flagged condition." -f $credentialRows.Count, $ficRows.Count, $customPolicies.Count) `
            -WhyItMatters 'Short-lived, non-overlapping credentials and narrowly bound federation trusts reduce unattended identity attack surface.' `
            -RecommendedAction 'Continue periodic review and automate credential rotation where federation is not available.' `
            -SourceFile $credentialSource -ResultRows $riskRows
    }
}

function Get-EAServicePrincipalSignInActivityState {
    $activityByAppId = @{}
    try {
        $uri = 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$top=100'
        foreach ($activity in @(Get-EAReadOnlyGraphCollection -Uri $uri)) {
            $appId = [string](Get-EAApplicationCheckValue $activity 'appId')
            if (-not $appId) { continue }
            $dates = @()
            foreach ($propertyName in @(
                'lastSignInActivity',
                'delegatedClientSignInActivity',
                'delegatedResourceSignInActivity',
                'applicationAuthenticationClientSignInActivity',
                'applicationAuthenticationResourceSignInActivity'
            )) {
                $detail = Get-EAApplicationCheckValue $activity $propertyName
                $date = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $detail 'lastSignInDateTime')
                if ($date) { $dates += $date }
            }
            if ($dates.Count -gt 0) {
                $last = $dates | Sort-Object -Descending | Select-Object -First 1
                if (-not $activityByAppId.ContainsKey($appId) -or $last -gt $activityByAppId[$appId]) {
                    $activityByAppId[$appId] = $last
                }
            } elseif (-not $activityByAppId.ContainsKey($appId)) {
                # Presence in the report with no timestamp is distinct from absence from the
                # report, but both remain "no recorded activity", never a proven clean state.
                $activityByAppId[$appId] = $null
            }
        }
        return [pscustomobject]@{ Known=$true; ByAppId=$activityByAppId; Error=$null }
    } catch {
        return [pscustomobject]@{ Known=$false; ByAppId=$activityByAppId; Error=$_.Exception.Message }
    }
}

function Get-EAApplicationPermissionRisk {
    param(
        [string]$PermissionValue,
        [string]$ResourceName
    )

    if ([string]::IsNullOrWhiteSpace($PermissionValue)) {
        return [pscustomobject]@{ Risk='Unknown'; Reason='The granted appRoleId could not be resolved to a permission value.' }
    }

    # Use both exact takeover primitives and semantic patterns. The pattern layer is
    # intentional: newly introduced/custom resource permissions must not evade review
    # merely because they are absent from a frozen list.
    $takeoverPermissions = @(
        'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All',
        'Application.ReadWrite.All', 'Directory.ReadWrite.All',
        'PrivilegedAccess.ReadWrite.AzureAD', 'RoleManagementPolicy.ReadWrite.Directory',
        'full_access_as_app', 'Exchange.ManageAsApp', 'Sites.FullControl.All'
    )
    if ($PermissionValue -in $takeoverPermissions -or $PermissionValue -match '(?i)(RoleManagement|PrivilegedAccess|AppRoleAssignment).*(ReadWrite|Write|Manage)|FullControl|full_access|ManageAsApp') {
        return [pscustomobject]@{ Risk='Tier0'; Reason='Directory takeover, role grant, impersonation, or full-control application permission.' }
    }

    if ($PermissionValue -match '(?i)(ReadWrite|\.Write(?:\.|$)|\.Send(?:\.|$)|Create|Delete|Update|Manage|Invite|AccessAsUser|Impersonat)') {
        return [pscustomobject]@{ Risk='WriteHigh'; Reason='Write, send, management, or impersonation capability.' }
    }

    $highImpactReadExact = @(
        'Directory.Read.All', 'RoleManagement.Read.Directory', 'Application.Read.All',
        'User.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'Device.Read.All',
        'Domain.Read.All', 'Organization.Read.All', 'CrossTenantInformation.ReadBasic.All',
        'AuditLog.Read.All', 'Reports.Read.All', 'IdentityRiskEvent.Read.All',
        'IdentityRiskyUser.Read.All', 'IdentityRiskyServicePrincipal.Read.All',
        'SecurityAlert.Read.All', 'SecurityIncident.Read.All', 'Mail.Read',
        'Calendars.Read', 'Contacts.Read', 'Files.Read.All', 'Sites.Read.All',
        'Chat.Read.All', 'ChatMessage.Read.All',
        'ChannelMessage.Read.All', 'CallRecords.Read.All', 'OnlineMeetingArtifact.Read.All',
        'DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All'
    )
    if ($PermissionValue -in $highImpactReadExact -or
        $PermissionValue -match '(?i)^(Mail|Calendars|Contacts|Files|Sites|Chat|ChatMessage|ChannelMessage|CallRecords|OnlineMeetingArtifact)\.Read(?:\.All)?$' -or
        $PermissionValue -match '(?i)^(Directory|RoleManagement|Application|User|Group|GroupMember|Device|Domain|Organization|CrossTenant|AuditLog|Reports|IdentityRisk|SecurityAlert|SecurityIncident).*\.Read\.All$') {
        return [pscustomobject]@{ Risk='HighImpactRead'; Reason=("Tenant-wide sensitive-data or security/configuration read access on {0}." -f ($ResourceName ?? 'resource API')) }
    }

    return [pscustomobject]@{ Risk='Other'; Reason='Resolved application permission; no high-impact pattern matched.' }
}

function Invoke-Check-EnterpriseAppGovernance {
    $checkId = 'enterpriseapps'
    $category = 'Applications'
    $now = (Get-Date).ToUniversalTime()
    $staleDays = if (Get-Variable -Name StaleAppDays -Scope Script -ErrorAction SilentlyContinue) { [int]$script:StaleAppDays } `
        elseif (Get-Variable -Name StaleAppDays -ErrorAction SilentlyContinue) { [int]$StaleAppDays } else { 90 }
    $cutoff = $now.AddDays(-$staleDays)
    $tenantId = $null
    try { $tenantId = [string](Get-MgContext).TenantId } catch {}
    if (-not $tenantId -and $script:Tenant) { $tenantId = [string]$script:Tenant.Id }
    $microsoftOwnerTenants = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
        '72f988bf-86f1-41af-91ab-2d7cd011db47'
    )

    $inventoryKnown = $true
    $ownersExpanded = $true
    $servicePrincipals = @()
    $inventoryUri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,appOwnerOrganizationId,createdDateTime,passwordCredentials,keyCredentials,appRoles&$expand=owners($select=id,displayName,userPrincipalName,userType)&$top=100'
    try {
        $servicePrincipals = @(Get-EAReadOnlyGraphCollection -Uri $inventoryUri)
    } catch {
        $ownersExpanded = $false
        try {
            $fallbackUri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,appOwnerOrganizationId,createdDateTime,passwordCredentials,keyCredentials,appRoles&$top=100'
            $servicePrincipals = @(Get-EAReadOnlyGraphCollection -Uri $fallbackUri)
        } catch {
            $inventoryKnown = $false
            $inventoryError = $_.Exception.Message
        }
    }

    if (-not $inventoryKnown) {
        $inventoryGap = @([pscustomobject]@{ Dataset='Enterprise applications'; State='Unknown'; Error=$inventoryError })
        $gapSource = Write-Evidence -BaseName 'enterprise_app_inventory_gaps' -Rows $inventoryGap -Title 'Enterprise Application Inventory Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Enterprise application governance could not be assessed' `
            -Evidence 'The service-principal inventory could not be read; ownership, assignment enforcement, access, and activity are unknown.' `
            -WhyItMatters 'An unavailable inventory must not be interpreted as an absence of ownerless, broadly accessible, or stale enterprise applications.' `
            -RecommendedAction 'Confirm Application.Read.All, resolve the Graph error, and re-run this check.' `
            -SourceFile $gapSource -ResultRows $inventoryGap -RuleId 'enterprise-app-inventory-unknown' -ObjectType 'tenant' -CoverageGap
        return
    }

    $candidates = @($servicePrincipals | Where-Object {
        $type = [string](Get-EAApplicationCheckValue $_ 'servicePrincipalType')
        $ownerTenant = [string](Get-EAApplicationCheckValue $_ 'appOwnerOrganizationId')
        # Managed identities and emerging workload-principal types can hold app roles too;
        # include them for permission blast-radius review. Social identity-provider objects
        # are not enterprise workload clients.
        ($type -ne 'SocialIdp') -and
        ($ownerTenant -notin $microsoftOwnerTenants)
    })

    $activity = Get-EAServicePrincipalSignInActivityState
    $resourceById = @{}
    foreach ($resourceSp in $servicePrincipals) {
        $resourceId = [string](Get-EAApplicationCheckValue $resourceSp 'id')
        if ($resourceId) { $resourceById[$resourceId] = $resourceSp }
    }
    $delegatedGrantsKnown = $true
    $delegatedGrants = @()
    try {
        # This list API documents $filter but not $top; follow its nextLink rather than
        # sending an unsupported page-size option.
        $delegatedGrants = @(Get-EAReadOnlyGraphCollection -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants')
    } catch {
        $delegatedGrantsKnown = $false
        $delegatedGrantError = $_.Exception.Message
    }
    $governanceRows = New-Object System.Collections.Generic.List[object]
    $assignmentRows = New-Object System.Collections.Generic.List[object]
    $permissionRows = New-Object System.Collections.Generic.List[object]
    $ownerErrors = New-Object System.Collections.Generic.List[object]
    $assignmentErrors = New-Object System.Collections.Generic.List[object]
    $permissionErrors = New-Object System.Collections.Generic.List[object]
    $stopOwnerReads = $false
    $stopAssignmentReads = $false
    $stopPermissionReads = $false

    foreach ($sp in $candidates) {
        $spId = [string](Get-EAApplicationCheckValue $sp 'id')
        $appId = [string](Get-EAApplicationCheckValue $sp 'appId')
        $name = [string](Get-EAApplicationCheckValue $sp 'displayName')
        $servicePrincipalType = [string](Get-EAApplicationCheckValue $sp 'servicePrincipalType')
        $ownerTenant = [string](Get-EAApplicationCheckValue $sp 'appOwnerOrganizationId')
        $ownerClass = if ($ownerTenant -and $tenantId -and $ownerTenant -eq $tenantId) { 'TenantOwned' } `
            elseif (-not $tenantId) { 'OwnerTenantUnknown' } `
            elseif ($ownerTenant) { 'ThirdParty' } else { 'OwnerTenantUnknown' }

        $ownersKnown = $ownersExpanded
        $owners = if ($ownersExpanded) { @((Get-EAApplicationCheckValue $sp 'owners') | Where-Object { $_ }) } else { @() }
        if (-not $ownersExpanded -and -not $stopOwnerReads) {
            try {
                $ownerUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + [uri]::EscapeDataString($spId) + '/owners?$select=id,displayName,userPrincipalName,userType'
                $owners = @(Get-EAReadOnlyGraphCollection -Uri $ownerUri -MaximumPages 50)
                $ownersKnown = $true
            } catch {
                $status = Get-EAApplicationCheckHttpStatus $_
                $ownerErrors.Add([pscustomobject]@{ EnterpriseApplication=$name; ObjectId=$spId; StatusCode=$status; Error=$_.Exception.Message }) | Out-Null
                if ($status -in 401,403) { $stopOwnerReads = $true }
            }
        }

        $userAssignments = 0
        $groupAssignments = 0
        $otherAssignments = 0
        $assignmentsKnown = $false
        if (-not $stopAssignmentReads) {
            try {
                $assignmentUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + [uri]::EscapeDataString($spId) + '/appRoleAssignedTo?$select=id,principalId,principalDisplayName,principalType,appRoleId,createdDateTime'
                $assignments = @(Get-EAReadOnlyGraphCollection -Uri $assignmentUri -MaximumPages 100)
                $assignmentsKnown = $true
                foreach ($assignment in $assignments) {
                    $principalType = [string](Get-EAApplicationCheckValue $assignment 'principalType')
                    if ($principalType -eq 'User') { $userAssignments++ }
                    elseif ($principalType -eq 'Group') { $groupAssignments++ }
                    else { $otherAssignments++ }
                    $assignmentRows.Add([pscustomobject]@{
                        EnterpriseApplication=$name; ServicePrincipalId=$spId; AppId=$appId; ServicePrincipalType=$servicePrincipalType
                        PrincipalType=$principalType
                        PrincipalName=[string](Get-EAApplicationCheckValue $assignment 'principalDisplayName')
                        PrincipalId=[string](Get-EAApplicationCheckValue $assignment 'principalId')
                        AppRoleId=[string](Get-EAApplicationCheckValue $assignment 'appRoleId')
                        AssignedDateTime=ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $assignment 'createdDateTime')
                    }) | Out-Null
                }
            } catch {
                $status = Get-EAApplicationCheckHttpStatus $_
                $assignmentErrors.Add([pscustomobject]@{ EnterpriseApplication=$name; ObjectId=$spId; StatusCode=$status; Error=$_.Exception.Message }) | Out-Null
                if ($status -in 401,403) { $stopAssignmentReads = $true }
            }
        }

        # appRoleAssignments are permissions HELD by this client service principal.
        # Resolve every appRoleId against the actual resource service principal so the
        # report carries names rather than GUIDs and can classify new/custom permissions.
        if (-not $stopPermissionReads) {
            try {
                $permissionUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + [uri]::EscapeDataString($spId) + '/appRoleAssignments?$select=id,resourceId,resourceDisplayName,appRoleId,createdDateTime'
                foreach ($grant in @(Get-EAReadOnlyGraphCollection -Uri $permissionUri -MaximumPages 100)) {
                    $resourceId = [string](Get-EAApplicationCheckValue $grant 'resourceId')
                    $appRoleId = [string](Get-EAApplicationCheckValue $grant 'appRoleId')
                    $resource = if ($resourceById.ContainsKey($resourceId)) { $resourceById[$resourceId] } else { $null }
                    $permissionValue = $null
                    foreach ($role in @(Get-EAApplicationCheckValue $resource 'appRoles')) {
                        if ([string](Get-EAApplicationCheckValue $role 'id') -eq $appRoleId) {
                            $permissionValue = [string](Get-EAApplicationCheckValue $role 'value')
                            break
                        }
                    }
                    $resourceName = [string](@(
                        Get-EAApplicationCheckValue $grant 'resourceDisplayName'
                        Get-EAApplicationCheckValue $resource 'displayName'
                        $resourceId
                    ) | Where-Object { $_ } | Select-Object -First 1)
                    $risk = Get-EAApplicationPermissionRisk -PermissionValue $permissionValue -ResourceName $resourceName
                    $permissionRows.Add([pscustomobject]@{
                        EnterpriseApplication=$name; ServicePrincipalId=$spId; AppId=$appId; ServicePrincipalType=$servicePrincipalType
                        GrantType='Application'; ConsentType='Application'; PrincipalId=''
                        Permission=$permissionValue; AppRoleId=$appRoleId; Resource=$resourceName; ResourceId=$resourceId
                        Risk=$risk.Risk; RiskReason=$risk.Reason
                        GrantedDateTime=ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $grant 'createdDateTime')
                    }) | Out-Null
                }
            } catch {
                $status = Get-EAApplicationCheckHttpStatus $_
                $permissionErrors.Add([pscustomobject]@{ EnterpriseApplication=$name; ObjectId=$spId; StatusCode=$status; Error=$_.Exception.Message }) | Out-Null
                if ($status -in 401,403) { $stopPermissionReads = $true }
            }
        }

        $created = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $sp 'createdDateTime')
        $lastSignIn = $null
        $activityState = 'Unknown-ReportUnavailable'
        if ($activity.Known) {
            if ($activity.ByAppId.ContainsKey($appId) -and $activity.ByAppId[$appId]) {
                $lastSignIn = $activity.ByAppId[$appId]
                $activityState = if ($lastSignIn -lt $cutoff) { 'KnownStale' } else { 'Recent' }
            } else {
                $activityState = 'NoRecordedActivity-UnknownUse'
            }
        }

        $enabledValue = Get-EAApplicationCheckValue $sp 'accountEnabled'
        $enabledState = ConvertTo-EAApplicationCheckBoolean $enabledValue
        $assignmentRequiredValue = Get-EAApplicationCheckValue $sp 'appRoleAssignmentRequired'
        $assignmentRequiredKnown = ($null -ne $assignmentRequiredValue)
        $hasCredentials = (@(Get-EAApplicationCheckValue $sp 'passwordCredentials').Count + @(Get-EAApplicationCheckValue $sp 'keyCredentials').Count) -gt 0
        $governanceRows.Add([pscustomobject]@{
            EnterpriseApplication=$name; ObjectId=$spId; AppId=$appId; ServicePrincipalType=$servicePrincipalType; OwnerClass=$ownerClass
            EnabledState=if ($null -eq $enabledState) { 'Unknown' } else { 'Known' }
            Enabled=$enabledState
            OwnerReadState=if ($ownersKnown) { 'Known' } else { 'Unknown' }
            OwnerCount=if ($ownersKnown) { $owners.Count } else { $null }
            Owners=if ($ownersKnown) { (@($owners | ForEach-Object {
                [string](@(Get-EAApplicationCheckValue $_ 'userPrincipalName'; Get-EAApplicationCheckValue $_ 'displayName'; Get-EAApplicationCheckValue $_ 'id') | Where-Object { $_ } | Select-Object -First 1)
            }) -join ', ') } else { '' }
            AssignmentRequirementState=if ($assignmentRequiredKnown) { 'Known' } else { 'Unknown' }
            AppRoleAssignmentRequired=if ($assignmentRequiredKnown) { [bool]$assignmentRequiredValue } else { $null }
            AssignmentReadState=if ($assignmentsKnown) { 'Known' } else { 'Unknown' }
            UserAssignments=if ($assignmentsKnown) { $userAssignments } else { $null }
            GroupAssignments=if ($assignmentsKnown) { $groupAssignments } else { $null }
            OtherAssignments=if ($assignmentsKnown) { $otherAssignments } else { $null }
            CreatedDateTime=$created; LastSignInDateTime=$lastSignIn; ActivityState=$activityState
            HasCredentials=$hasCredentials
        }) | Out-Null
    }

    # Delegated grants carry their actual scope names as a space-delimited string.
    # Inventory them once tenant-wide, then associate them with the reviewed client SPs.
    if ($delegatedGrantsKnown) {
        $candidateById = @{}
        foreach ($row in $governanceRows) { if ($row.ObjectId) { $candidateById[$row.ObjectId] = $row } }
        foreach ($grant in $delegatedGrants) {
            $clientId = [string](Get-EAApplicationCheckValue $grant 'clientId')
            if (-not $candidateById.ContainsKey($clientId)) { continue }
            $client = $candidateById[$clientId]
            $resourceId = [string](Get-EAApplicationCheckValue $grant 'resourceId')
            $resource = if ($resourceById.ContainsKey($resourceId)) { $resourceById[$resourceId] } else { $null }
            $resourceName = [string](@(Get-EAApplicationCheckValue $resource 'displayName'; $resourceId) | Where-Object { $_ } | Select-Object -First 1)
            $scopes = @(([string](Get-EAApplicationCheckValue $grant 'scope') -split '\s+') | Where-Object { $_ })
            foreach ($scope in $scopes) {
                $risk = Get-EAApplicationPermissionRisk -PermissionValue $scope -ResourceName $resourceName
                $permissionRows.Add([pscustomobject]@{
                    EnterpriseApplication=$client.EnterpriseApplication; ServicePrincipalId=$clientId; AppId=$client.AppId; ServicePrincipalType=$client.ServicePrincipalType
                    GrantType='Delegated'; ConsentType=[string](Get-EAApplicationCheckValue $grant 'consentType')
                    PrincipalId=[string](Get-EAApplicationCheckValue $grant 'principalId')
                    Permission=$scope; AppRoleId=''; Resource=$resourceName; ResourceId=$resourceId
                    Risk=$risk.Risk; RiskReason=$risk.Reason
                    GrantedDateTime=$null
                }) | Out-Null
            }
        }
    }

    $rows = @($governanceRows.ToArray())
    $source = Write-Evidence -BaseName 'enterprise_app_governance' -Rows $rows -Title 'Enterprise Application Governance' `
        -Notes @(
            ("Excluded Microsoft first-party owner tenants and SocialIdp objects; reviewed {0} tenant-owned, third-party, managed, or owner-tenant-unknown workload service principals." -f $rows.Count),
            'NoRecordedActivity-UnknownUse is deliberately not treated as proof that an app is unused.'
        )
    $assignmentSource = Write-Evidence -BaseName 'enterprise_app_assignments' -Rows @($assignmentRows.ToArray()) -Title 'Enterprise Application User and Group Assignments'
    $permissionSource = Write-Evidence -BaseName 'enterprise_app_granted_permissions' -Rows @($permissionRows.ToArray()) `
        -Title 'Enterprise Application Granted Application and Delegated Permissions' `
        -Notes @('Application permission names are resolved from each resource service principal app-role definition; delegated grants use their actual scope strings. Unresolved app-role IDs remain an explicit coverage gap.')

    $coverageRows = @()
    if (-not $ownersExpanded) { $coverageRows += @($ownerErrors.ToArray()) }
    if ($stopOwnerReads) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='Remaining enterprise applications'; ObjectId=''; StatusCode=''; Error='Owner enumeration stopped after an authorization failure.' } }
    $coverageRows += @($assignmentErrors.ToArray())
    if ($stopAssignmentReads) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='Remaining enterprise applications'; ObjectId=''; StatusCode=''; Error='Assignment enumeration stopped after an authorization failure.' } }
    $coverageRows += @($permissionErrors.ToArray())
    if ($stopPermissionReads) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='Remaining enterprise applications'; ObjectId=''; StatusCode=''; Error='Granted-permission enumeration stopped after an authorization failure.' } }
    if (-not $delegatedGrantsKnown) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='All reviewed enterprise applications'; ObjectId=''; StatusCode=''; Error=("Delegated OAuth grant inventory unavailable: {0}" -f $delegatedGrantError) } }
    $unresolvedPermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'Unknown' })
    if ($unresolvedPermissions.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=("{0} grant(s)" -f $unresolvedPermissions.Count); ObjectId=''; StatusCode=''; Error='Granted appRoleId could not be resolved to a permission value.' } }
    if (-not $activity.Known) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='All non-Microsoft enterprise applications'; ObjectId=''; StatusCode=''; Error=("Service-principal sign-in activity unavailable: {0}" -f $activity.Error) } }
    if (-not $tenantId) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='All reviewed enterprise applications'; ObjectId=''; StatusCode=''; Error='The Graph tenant id was unavailable, so tenant-owned versus third-party classification is unknown.' } }
    $unknownOwnerTenant = @($rows | Where-Object { $_.OwnerClass -eq 'OwnerTenantUnknown' })
    if ($unknownOwnerTenant.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=("{0} application(s)" -f $unknownOwnerTenant.Count); ObjectId=''; StatusCode=''; Error='appOwnerOrganizationId was not returned, so tenant-owned versus third-party lifecycle rules could not be applied.' } }
    $unknownEnabled = @($rows | Where-Object { $_.EnabledState -eq 'Unknown' })
    if ($unknownEnabled.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=("{0} application(s)" -f $unknownEnabled.Count); ObjectId=''; StatusCode=''; Error='accountEnabled was not returned or was not a recognized boolean value.' } }
    $unknownRequirement = @($rows | Where-Object { $_.AssignmentRequirementState -eq 'Unknown' })
    if ($unknownRequirement.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=("{0} application(s)" -f $unknownRequirement.Count); ObjectId=''; StatusCode=''; Error='appRoleAssignmentRequired was not returned.' } }
    if ($coverageRows.Count -gt 0) {
        $coverageSource = Write-Evidence -BaseName 'enterprise_app_governance_gaps' -Rows $coverageRows -Title 'Enterprise Application Governance Coverage Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Enterprise application governance coverage is incomplete' `
            -Evidence ("{0} ownership, assignment, activity, or property coverage gap(s) were recorded; affected apps are not counted as clean." -f $coverageRows.Count) `
            -WhyItMatters 'Missing relationship or activity data can hide ownerless apps, broad assignment paths, and forgotten third-party integrations.' `
            -RecommendedAction 'Confirm Application.Read.All, Directory.Read.All (for tenant-wide delegated OAuth grants), and AuditLog.Read.All; verify the supported Entra role/licensing, resolve throttling, and re-run.' `
            -SourceFile $coverageSource -ResultRows $coverageRows -RuleId 'enterprise-app-governance-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }

    $ownerless = @($rows | Where-Object {
        $_.Enabled -and $_.ServicePrincipalType -in @('Application','Legacy','') -and $_.OwnerReadState -eq 'Known' -and $_.OwnerCount -eq 0
    })
    if ($ownerless.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ("{0} enabled enterprise application(s) have no tenant owner" -f $ownerless.Count) `
            -Evidence ("Ownerless applications: {0}." -f (($ownerless.EnterpriseApplication | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Without an accountable tenant owner, access assignments, credentials, and vendor lifecycle changes are less likely to be reviewed or removed.' `
            -RecommendedAction 'Assign accountable business and technical owners, document the purpose and renewal date, or decommission the integration.' `
            -SourceFile $source -ResultRows $ownerless -RuleId 'enterprise-app-ownerless' -ObjectType 'servicePrincipal'
    }

    $unrestricted = @($rows | Where-Object {
        $_.Enabled -and $_.ServicePrincipalType -in @('Application','Legacy','') -and $_.OwnerClass -eq 'ThirdParty' -and
        $_.AssignmentRequirementState -eq 'Known' -and -not $_.AppRoleAssignmentRequired
    })
    if ($unrestricted.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ("{0} enabled third-party enterprise application(s) do not require assignment" -f $unrestricted.Count) `
            -Evidence 'appRoleAssignmentRequired is false, so assignment inventory alone does not bound who can attempt user sign-in.' `
            -WhyItMatters 'For user-facing third-party applications, disabling assignment enforcement can make the app available beyond the intended user or group population.' `
            -RecommendedAction 'Confirm whether each app supports user sign-in; where access should be limited, require assignment and maintain reviewed user/group assignments.' `
            -SourceFile $source -ResultRows $unrestricted -RuleId 'enterprise-app-assignment-not-required' -ObjectType 'servicePrincipal'
    }

    $groupAssigned = @($rows | Where-Object { $_.Enabled -and $_.AssignmentReadState -eq 'Known' -and $_.GroupAssignments -gt 0 })
    if ($groupAssigned.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ("{0} enterprise application(s) grant access through group assignments" -f $groupAssigned.Count) `
            -Evidence ("{0} direct group assignment(s) were enumerated; transitive membership should be governed and reviewed." -f ($groupAssigned | Measure-Object GroupAssignments -Sum).Sum) `
            -WhyItMatters 'Group-based app access can expand through nested or poorly governed membership and is easy to miss during app-centric reviews.' `
            -RecommendedAction 'Review the assigned groups, their owners and transitive membership, and cover them with recurring access reviews where licensed.' `
            -SourceFile $assignmentSource -ResultRows @($assignmentRows.ToArray() | Where-Object { $_.PrincipalType -eq 'Group' }) -RuleId 'enterprise-app-group-assignment' -ObjectType 'servicePrincipal'
    }

    $tier0Permissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'Tier0' })
    $writePermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'WriteHigh' })
    $highReadPermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'HighImpactRead' })
    if ($tier0Permissions.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId $checkId -Category $category `
            -Title ("{0} enterprise application grant(s) provide takeover or full-control capability" -f $tier0Permissions.Count) `
            -Evidence ("Affected apps: {0}." -f (($tier0Permissions.EnterpriseApplication | Select-Object -Unique | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Application permissions operate without a signed-in user, while delegated permissions act with a signed-in principal. Role-management, app-role grant, directory write, impersonation, and full-control scopes are takeover primitives in either model.' `
            -RecommendedAction 'Validate the business requirement and approval, replace with scoped least privilege, use workload identity controls, and rotate credentials after removing an unnecessary grant.' `
            -SourceFile $permissionSource -ResultRows $tier0Permissions -RuleId 'enterprise-app-tier0-permission' -ObjectType 'servicePrincipal'
    }
    if ($writePermissions.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId $checkId -Category $category `
            -Title ("{0} enterprise application grant(s) provide write, send, or management access" -f $writePermissions.Count) `
            -Evidence ("Affected apps: {0}." -f (($writePermissions.EnterpriseApplication | Select-Object -Unique | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'A compromised workload or illicit delegated grant can modify or send data across the granted resource.' `
            -RecommendedAction 'Remove unused grants and replace broad write permissions with the narrowest API/resource-specific permission available.' `
            -SourceFile $permissionSource -ResultRows $writePermissions -RuleId 'enterprise-app-write-permission' -ObjectType 'servicePrincipal'
    }
    if ($highReadPermissions.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId $checkId -Category $category `
            -Title ("{0} enterprise application grant(s) provide high-impact read access" -f $highReadPermissions.Count) `
            -Evidence ("Tenant-wide mail, files, sites, chats, directory, audit, identity-risk, security, or configuration reads affect {0} app(s)." -f @($highReadPermissions.EnterpriseApplication | Select-Object -Unique).Count) `
            -WhyItMatters 'Read-only does not mean low impact: application or delegated access to tenant-wide mail, files, chats, directory, audit, or security data enables large-scale confidential-data theft.' `
            -RecommendedAction 'Confirm every high-impact read grant is necessary, prefer resource-scoped controls where supported, and cover the app with owner/access/credential reviews.' `
            -SourceFile $permissionSource -ResultRows $highReadPermissions -RuleId 'enterprise-app-high-impact-read' -ObjectType 'servicePrincipal'
    }

    if ($activity.Known) {
        $knownStale = @($rows | Where-Object { $_.Enabled -and $_.OwnerClass -eq 'ThirdParty' -and $_.ActivityState -eq 'KnownStale' })
        $noRecorded = @($rows | Where-Object {
            $_.Enabled -and $_.OwnerClass -eq 'ThirdParty' -and $_.ActivityState -eq 'NoRecordedActivity-UnknownUse' -and
            ((-not $_.CreatedDateTime) -or $_.CreatedDateTime -lt $cutoff)
        })
        if ($knownStale.Count -gt 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title ("{0} enabled third-party enterprise application(s) have stale recorded activity" -f $knownStale.Count) `
                -Evidence ("The last recorded service-principal sign-in is older than {0} days." -f $staleDays) `
                -WhyItMatters 'An enabled third-party integration that is no longer active retains a trust relationship and may retain credentials or access assignments.' `
                -RecommendedAction 'Confirm continued business need with the owner; disable and then remove unused integrations after validating dependencies.' `
                -SourceFile $source -ResultRows $knownStale -RuleId 'enterprise-app-known-stale' -ObjectType 'servicePrincipal'
        }
        if ($noRecorded.Count -gt 0) {
            Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
                -Title ("{0} older third-party enterprise application(s) have no recorded activity" -f $noRecorded.Count) `
                -Evidence 'The activity report was readable but contained no usable timestamp for these apps. Their use is unknown, not proven absent.' `
                -WhyItMatters 'A missing activity record may identify a never-used or forgotten app, but report semantics and retention mean it requires owner validation before removal.' `
                -RecommendedAction 'Validate usage with the application owner and workload logs; disable in a controlled window before deleting an apparently unused app.' `
                -SourceFile $source -ResultRows $noRecorded -RuleId 'enterprise-app-no-recorded-activity' -ObjectType 'servicePrincipal' -CoverageGap
        }
    }

    $riskFindings = @($script:Findings | Where-Object { $_.CheckId -eq $checkId -and $_.Severity -ne 'Information' })
    if ($riskFindings.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Enterprise application ownership, assignment, and activity reviewed' `
            -Evidence ("{0} non-Microsoft enterprise application(s), {1} direct access assignment(s), and {2} granted application/delegated permission entries were inventoried." -f $rows.Count, $assignmentRows.Count, $permissionRows.Count) `
            -WhyItMatters 'Accountable owners and constrained, reviewed assignments reduce persistent third-party access.' `
            -RecommendedAction 'Continue periodic owner attestation, access reviews, and activity-based lifecycle cleanup.' `
            -SourceFile $source -ResultRows $rows
    }
}

function Invoke-EAMonitoringGraphProbe {
    param(
        [Parameter(Mandatory)][string]$Dataset,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$TimestampProperty,
        [Parameter(Mandatory)][string]$RequiredScope,
        [switch]$Core
    )

    try {
        $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        $values = Get-EAApplicationCheckValue $response 'value'
        if ($null -eq $values) { throw 'The Graph response did not contain a value array.' }
        $records = @($values)
        $latest = $null
        if ($records.Count -gt 0) {
            $latest = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $records[0] $TimestampProperty)
        }
        $state = if ($records.Count -eq 0) { 'Readable-NoRecords' } elseif ($latest) { 'Readable' } else { 'Unknown-TimestampMissing' }
        return [pscustomobject]@{
            Dataset=$Dataset; Core=[bool]$Core; State=$state
            RequiredScope=$RequiredScope; LatestRecord=$latest
            AgeDays=if ($latest) { [math]::Round(((Get-Date).ToUniversalTime() - $latest).TotalDays, 1) } else { $null }
            Error=if ($state -eq 'Unknown-TimestampMissing') { "A record was returned without a parseable $TimestampProperty timestamp." } else { '' }
        }
    } catch {
        return [pscustomobject]@{
            Dataset=$Dataset; Core=[bool]$Core; State='Unknown-Unreadable'; RequiredScope=$RequiredScope
            LatestRecord=$null; AgeDays=$null; Error=$_.Exception.Message
        }
    }
}

function Get-EAEmergencyAccessMonitoringRows {
    param([string[]]$UserPrincipalNames)

    $rows = New-Object System.Collections.Generic.List[object]
    if (@($UserPrincipalNames).Count -eq 0) {
        $rows.Add([pscustomobject]@{
            EmergencyAccount='Not supplied to this run'; SignInLogState='Unknown-NoAccountInput'; LatestSignIn=$null
            AlertRuleState='Unknown-CrossPlane'; Detail='Use -BreakGlassUpns so sign-in log visibility can be tested for the designated emergency accounts.'
        }) | Out-Null
        return @($rows.ToArray())
    }

    foreach ($upn in @($UserPrincipalNames)) {
        $escapedUpn = $upn.Replace("'", "''")
        $filter = [uri]::EscapeDataString("userPrincipalName eq '$escapedUpn'")
        $uri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=' + $filter + '&$top=1'
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $values = Get-EAApplicationCheckValue $response 'value'
            if ($null -eq $values) { throw 'The sign-in response did not contain a value array.' }
            $events = @($values)
            $latest = if ($events.Count -gt 0) { ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $events[0] 'createdDateTime') } else { $null }
            $rows.Add([pscustomobject]@{
                EmergencyAccount=$upn; SignInLogState=if ($events.Count -gt 0) { 'Readable-RecordFound' } else { 'Readable-NoRecordInRetention' }
                LatestSignIn=$latest; AlertRuleState='Unknown-CrossPlane'
                Detail='Graph confirms whether sign-in records can be queried; it does not expose Azure Monitor alert-rule routing for this account.'
            }) | Out-Null
        } catch {
            $rows.Add([pscustomobject]@{
                EmergencyAccount=$upn; SignInLogState='Unknown-Unreadable'; LatestSignIn=$null
                AlertRuleState='Unknown-CrossPlane'; Detail=$_.Exception.Message
            }) | Out-Null
        }
    }
    return @($rows.ToArray())
}

function Invoke-EAReadOnlyAzRestCollection {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$DefaultProfile,
        [ValidateRange(1, 5000)][int]$MaximumPages = 500
    )

    $command = Get-Command Invoke-AzRestMethod -ErrorAction Stop
    $environment = Get-EAApplicationCheckValue $DefaultProfile 'Environment'
    $resourceManagerUrl = [string](Get-EAApplicationCheckValue $environment 'ResourceManagerUrl')
    $resourceManagerUri = $null
    if ($resourceManagerUrl) {
        try { $resourceManagerUri = [uri]$resourceManagerUrl } catch {}
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $next = $Path
    $page = 0
    while ($next) {
        if ($page -ge $MaximumPages) {
            throw "Azure Resource Manager collection exceeded the $MaximumPages-page safety limit; coverage is incomplete."
        }

        # Invoke-AzRestMethod accepts -Uri for an absolute ARM nextLink and -Path for
        # resource paths. Every page is explicitly pinned to GET.
        $parameters = @{ Method='GET'; ErrorAction='Stop' }
        if ($next -match '^https?://') {
            $nextUri = $null
            try { $nextUri = [uri]$next } catch { throw "Azure Resource Manager returned an invalid nextLink URI: '$next'." }
            if ($nextUri.Scheme -ne 'https' -or -not $resourceManagerUri -or
                -not [string]::Equals($nextUri.Authority, $resourceManagerUri.Authority, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Azure Resource Manager returned a nextLink outside the current Az environment ResourceManagerUrl host; refusing authenticated follow-up GET."
            }
            if (-not $command.Parameters.ContainsKey('Uri')) {
                throw 'This Invoke-AzRestMethod version cannot safely follow an absolute ARM nextLink because it does not expose -Uri.'
            }
            $parameters.Uri = $nextUri.AbsoluteUri
        } elseif ($next.StartsWith('//')) {
            throw "Azure Resource Manager returned a protocol-relative nextLink; refusing authenticated follow-up GET."
        } else {
            $parameters.Path = $next
        }
        if ($command.Parameters.ContainsKey('DefaultProfile')) { $parameters.DefaultProfile = $DefaultProfile }
        $response = Invoke-AzRestMethod @parameters
        $statusValue = Get-EAApplicationCheckValue $response 'StatusCode'
        if ($null -ne $statusValue) {
            $statusCode = $null
            try { $statusCode = [int]$statusValue } catch {}
            if ($null -ne $statusCode -and ($statusCode -lt 200 -or $statusCode -ge 300)) {
                $failureContent = [string](Get-EAApplicationCheckValue $response 'Content')
                if ($failureContent.Length -gt 1000) { $failureContent = $failureContent.Substring(0,1000) }
                throw "Azure Resource Manager GET returned HTTP $statusCode for '$next'. $failureContent"
            }
        }

        $body = $response
        $content = Get-EAApplicationCheckValue $response 'Content'
        if ($null -ne $content) {
            if ($content -is [string]) {
                if ([string]::IsNullOrWhiteSpace($content)) { return @($rows.ToArray()) }
                $body = $content | ConvertFrom-Json -AsHashtable -Depth 100
            } else {
                $body = $content
            }
        }
        $values = Get-EAApplicationCheckValue $body 'value'
        if ($null -ne $values) {
            foreach ($value in @($values)) { $rows.Add($value) | Out-Null }
            $next = [string](Get-EAApplicationCheckValue $body 'nextLink')
        } elseif ($page -eq 0 -and $null -ne $body) {
            # Keep support for a singleton response, while a paginated list must retain
            # its collection shape on every page.
            $rows.Add($body) | Out-Null
            $next = $null
        } else {
            throw "Azure Resource Manager collection response for '$next' did not contain a value array."
        }
        $page++
    }
    return @($rows.ToArray())
}

function Get-EAAzureMonitoringCoverage {
    param([string[]]$EmergencyAccessUpns)

    $rows = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]
    $exportedCategories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $enabledActionGroups = @{}
    $alertCandidates = New-Object System.Collections.Generic.List[object]
    $result = [ordered]@{
        State='Unknown'; Detail=''; Rows=$rows; Errors=$errors; SubscriptionCount=0
        DiagnosticSettingCount=0; EnabledDiagnosticSettingCount=0
        AlertRuleCount=0; IdentityAlertCandidateCount=0; EmergencyAlertCandidateCount=0
        IdentityAlertWithActionCount=0; EmergencyAlertWithActionCount=0
        ActionGroupCount=0; EnabledActionGroupCount=0
        ExportedLogCategories=@(); CoreDiagnosticCategoriesComplete=$false
    }

    if (-not (Get-Command Get-AzContext -ErrorAction SilentlyContinue) -or
        -not (Get-Command Invoke-AzRestMethod -ErrorAction SilentlyContinue)) {
        $result.State = 'Unknown-NoAzModule'
        $result.Detail = 'Az.Accounts/Get-AzContext or Invoke-AzRestMethod is unavailable; no Azure context was created or module installed.'
        return [pscustomobject]$result
    }

    try { $azContext = Get-AzContext -ErrorAction Stop } catch {
        $result.State = 'Unknown-NoAzContext'; $result.Detail = $_.Exception.Message
        return [pscustomobject]$result
    }
    if (-not $azContext -or -not $azContext.Account) {
        $result.State = 'Unknown-NoAzContext'
        $result.Detail = 'No pre-existing signed-in Azure context is available.'
        return [pscustomobject]$result
    }

    $graphTenantId = $null
    try { $graphTenantId = [string](Get-MgContext).TenantId } catch {}
    $azureTenantId = [string]$azContext.Tenant.Id
    if (-not $graphTenantId -or -not $azureTenantId) {
        $result.State = 'Unknown-TenantUnverified'
        $result.Detail = 'The Graph and Azure tenant identifiers were not both available, so the pre-existing Azure context could not be proven to match. No ARM request was sent.'
        return [pscustomobject]$result
    }
    if ($graphTenantId -and $azureTenantId -and $graphTenantId -ne $azureTenantId) {
        $result.State = 'Unknown-TenantMismatch'
        $result.Detail = "The pre-existing Azure context tenant '$azureTenantId' does not match Graph tenant '$graphTenantId'. The context was not changed."
        return [pscustomobject]$result
    }

    $subscriptions = @()
    if (Get-Command Get-AzSubscription -ErrorAction SilentlyContinue) {
        try {
            $subscriptionCommand = Get-Command Get-AzSubscription -ErrorAction Stop
            $subscriptionParameters = @{ ErrorAction='Stop' }
            if ($graphTenantId -and $subscriptionCommand.Parameters.ContainsKey('TenantId')) { $subscriptionParameters.TenantId = $graphTenantId }
            if ($subscriptionCommand.Parameters.ContainsKey('DefaultProfile')) { $subscriptionParameters.DefaultProfile = $azContext }
            $subscriptions = @(Get-AzSubscription @subscriptionParameters)
        } catch {
            $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope='Subscriptions'; Control='Subscription enumeration'; Error=$_.Exception.Message }) | Out-Null
        }
    } else {
        $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope='Subscriptions'; Control='Subscription enumeration'; Error='Get-AzSubscription is unavailable; only the current context subscription can be sampled and tenant subscription coverage is unknown.' }) | Out-Null
    }
    if ($subscriptions.Count -eq 0 -and $azContext.Subscription -and $azContext.Subscription.Id) {
        if (@($errors | Where-Object { $_.Control -eq 'Subscription enumeration' }).Count -eq 0) {
            $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope='Subscriptions'; Control='Subscription enumeration'; Error='Get-AzSubscription returned no subscriptions; the current context subscription is sampled, but tenant subscription coverage is unknown.' }) | Out-Null
        }
        $subscriptions = @([pscustomobject]@{ Id=[string]$azContext.Subscription.Id; Name=[string]$azContext.Subscription.Name })
    }
    $result.SubscriptionCount = $subscriptions.Count
    if ($subscriptions.Count -eq 0) {
        $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope='Subscriptions'; Control='Azure Monitor alert inventory'; Error='No readable Azure subscription was available, so alert rules and action groups could not be enumerated.' }) | Out-Null
    }

    # Microsoft Entra diagnostic settings are tenant-level ARM resources.
    try {
        $diagnosticPath = '/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01'
        foreach ($setting in @(Invoke-EAReadOnlyAzRestCollection -Path $diagnosticPath -DefaultProfile $azContext)) {
            $properties = Get-EAApplicationCheckValue $setting 'properties'
            $enabledCategories = @()
            foreach ($log in @(Get-EAApplicationCheckValue $properties 'logs')) {
                if ((ConvertTo-EAApplicationCheckBoolean (Get-EAApplicationCheckValue $log 'enabled')) -eq $true) {
                    $categoryName = [string](@(Get-EAApplicationCheckValue $log 'category'; Get-EAApplicationCheckValue $log 'categoryGroup') | Where-Object { $_ } | Select-Object -First 1)
                    if ($categoryName) { $enabledCategories += $categoryName }
                }
            }
            $destinations = @()
            foreach ($destinationProperty in @('workspaceId','storageAccountId','eventHubAuthorizationRuleId','marketplacePartnerId')) {
                if (Get-EAApplicationCheckValue $properties $destinationProperty) { $destinations += $destinationProperty }
            }
            $result.DiagnosticSettingCount++
            if ($enabledCategories.Count -gt 0 -and $destinations.Count -gt 0) {
                $result.EnabledDiagnosticSettingCount++
                foreach ($categoryName in $enabledCategories) { $exportedCategories.Add($categoryName) | Out-Null }
            }
            $rows.Add([pscustomobject]@{
                Plane='Azure Resource Manager'; Scope='Tenant'; Control='Entra diagnostic setting'
                Name=[string](Get-EAApplicationCheckValue $setting 'name')
                Enabled=($enabledCategories.Count -gt 0); State='Known'
                Detail=("Categories={0}; Destinations={1}" -f (($enabledCategories | Select-Object -Unique) -join ','), (($destinations | Select-Object -Unique) -join ','))
                IdentitySignal=$false; EmergencySignal=$false; ActionGroupReferences=''
            }) | Out-Null
        }
    } catch {
        $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope='Tenant'; Control='Entra diagnostic settings'; Error=$_.Exception.Message }) | Out-Null
    }

    $identityPattern = '(?i)(entra|azure.?ad|identity|sign.?in|audit|role|conditional.?access|authentication|credential|consent|federat|cross.?tenant)'
    $emergencyPattern = '(?i)(break.?glass|emergency.?access)'
    foreach ($subscription in $subscriptions) {
        $subscriptionId = [string]$subscription.Id
        $subscriptionName = [string]$subscription.Name
        foreach ($endpoint in @(
            [pscustomobject]@{ Control='Scheduled query rule'; Suffix='providers/Microsoft.Insights/scheduledQueryRules?api-version=2021-08-01' },
            [pscustomobject]@{ Control='Activity log alert'; Suffix='providers/Microsoft.Insights/activityLogAlerts?api-version=2020-10-01' },
            [pscustomobject]@{ Control='Action group'; Suffix='providers/Microsoft.Insights/actionGroups?api-version=2021-09-01' }
        )) {
            $path = '/subscriptions/' + [uri]::EscapeDataString($subscriptionId) + '/' + $endpoint.Suffix
            try {
                foreach ($resource in @(Invoke-EAReadOnlyAzRestCollection -Path $path -DefaultProfile $azContext)) {
                    $properties = Get-EAApplicationCheckValue $resource 'properties'
                    $enabledValue = Get-EAApplicationCheckValue $properties 'enabled'
                    $parsedEnabled = ConvertTo-EAApplicationCheckBoolean $enabledValue
                    $enabled = if ($null -eq $enabledValue) { $true } elseif ($null -eq $parsedEnabled) { $false } else { $parsedEnabled }
                    $serialized = ''
                    try { $serialized = $resource | ConvertTo-Json -Compress -Depth 50 } catch {}
                    $identitySignal = ($serialized -match $identityPattern)
                    $emergencySignal = ($serialized -match $emergencyPattern)
                    foreach ($upn in @($EmergencyAccessUpns | Where-Object { $_ })) {
                        if ($serialized -match [regex]::Escape($upn)) { $emergencySignal = $true; break }
                    }
                    $actionGroupReferences = @()
                    if ($endpoint.Control -ne 'Action group') {
                        $actions = Get-EAApplicationCheckValue $properties 'actions'
                        foreach ($reference in @(Get-EAApplicationCheckValue $actions 'actionGroups')) {
                            $referenceId = if ($reference -is [string]) { [string]$reference } else { [string](Get-EAApplicationCheckValue $reference 'actionGroupId') }
                            if ($referenceId) { $actionGroupReferences += $referenceId.TrimEnd('/') }
                        }
                    }
                    if ($endpoint.Control -eq 'Action group') {
                        $result.ActionGroupCount++
                        $actionGroupId = [string](Get-EAApplicationCheckValue $resource 'id')
                        if ($actionGroupId) { $enabledActionGroups[$actionGroupId.TrimEnd('/').ToLowerInvariant()] = [bool]$enabled }
                        if ($enabled) { $result.EnabledActionGroupCount++ }
                    } else {
                        $result.AlertRuleCount++
                        if ($enabled -and $identitySignal) { $result.IdentityAlertCandidateCount++ }
                        if ($enabled -and $emergencySignal) { $result.EmergencyAlertCandidateCount++ }
                        if ($enabled -and ($identitySignal -or $emergencySignal)) {
                            $alertCandidates.Add([pscustomobject]@{
                                IdentitySignal=$identitySignal; EmergencySignal=$emergencySignal
                                ActionGroupReferences=@($actionGroupReferences | Select-Object -Unique)
                            }) | Out-Null
                        }
                    }
                    $rows.Add([pscustomobject]@{
                        Plane='Azure Resource Manager'; Scope=("{0} ({1})" -f $subscriptionName,$subscriptionId)
                        Control=$endpoint.Control; Name=[string](Get-EAApplicationCheckValue $resource 'name')
                        Enabled=$enabled; State='Known'
                        Detail=if ($endpoint.Control -eq 'Action group') { 'Notification/action destination metadata read.' } else { 'Rule metadata, criteria, and action references read.' }
                        IdentitySignal=$identitySignal; EmergencySignal=$emergencySignal
                        ActionGroupReferences=($actionGroupReferences -join ',')
                    }) | Out-Null
                }
            } catch {
                $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope=("{0} ({1})" -f $subscriptionName,$subscriptionId); Control=$endpoint.Control; Error=$_.Exception.Message }) | Out-Null
            }
        }
    }

    foreach ($candidate in @($alertCandidates.ToArray())) {
        $hasEnabledAction = $false
        foreach ($reference in @($candidate.ActionGroupReferences)) {
            $key = ([string]$reference).TrimEnd('/').ToLowerInvariant()
            if ($enabledActionGroups.ContainsKey($key) -and $enabledActionGroups[$key]) { $hasEnabledAction = $true; break }
        }
        if ($hasEnabledAction -and $candidate.IdentitySignal) { $result.IdentityAlertWithActionCount++ }
        if ($hasEnabledAction -and $candidate.EmergencySignal) { $result.EmergencyAlertWithActionCount++ }
    }
    $result.ExportedLogCategories = @($exportedCategories | Sort-Object)
    $allLogsExported = $exportedCategories.Contains('allLogs')
    $result.CoreDiagnosticCategoriesComplete = [bool]($allLogsExported -or
        ($exportedCategories.Contains('AuditLogs') -and $exportedCategories.Contains('SignInLogs')))

    if ($errors.Count -gt 0) {
        $result.State = 'Partial'
        $result.Detail = "Azure read context matched, but $($errors.Count) ARM dataset(s) could not be read."
    } else {
        $result.State = 'Complete'
        $result.Detail = "Azure read context matched and all requested tenant/subscription datasets were read across $($subscriptions.Count) subscription(s)."
    }
    return [pscustomobject]$result
}

function Invoke-Check-Monitoring {
    $checkId = 'monitoring'
    $category = 'Monitoring'

    $probeRows = @(
        Invoke-EAMonitoringGraphProbe -Dataset 'Directory audit log' `
            -Uri 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=1&$orderby=activityDateTime%20desc&$select=id,activityDateTime,activityDisplayName,category,result' `
            -TimestampProperty 'activityDateTime' -RequiredScope 'AuditLog.Read.All' -Core
        Invoke-EAMonitoringGraphProbe -Dataset 'User sign-in log' `
            -Uri 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1' `
            -TimestampProperty 'createdDateTime' -RequiredScope 'AuditLog.Read.All' -Core
        Invoke-EAMonitoringGraphProbe -Dataset 'Provisioning log' `
            -Uri 'https://graph.microsoft.com/v1.0/auditLogs/provisioning?$top=1&$orderby=activityDateTime%20desc' `
            -TimestampProperty 'activityDateTime' -RequiredScope 'AuditLog.Read.All + Directory.Read.All'
        Invoke-EAMonitoringGraphProbe -Dataset 'Identity Protection risk detections' `
            -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$top=1' `
            -TimestampProperty 'detectedDateTime' -RequiredScope 'IdentityRiskEvent.Read.All'
        Invoke-EAMonitoringGraphProbe -Dataset 'Microsoft security alerts' `
            -Uri 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=1' `
            -TimestampProperty 'createdDateTime' -RequiredScope 'SecurityAlert.Read.All'
    )
    $probeSource = Write-Evidence -BaseName 'monitoring_graph_visibility' -Rows $probeRows -Title 'Graph-Visible Monitoring and Log Availability' `
        -Notes @(
            'Readable-NoRecords proves API access only; it does not prove that export, retention, alert routing, or analyst response is configured.',
            'Security alert visibility requires the read-only SecurityAlert.Read.All permission.'
        )

    $coreUnknown = @($probeRows | Where-Object { $_.Core -and $_.State -like 'Unknown-*' })
    $coreEmpty = @($probeRows | Where-Object { $_.Core -and $_.State -eq 'Readable-NoRecords' })
    $optionalUnknown = @($probeRows | Where-Object { -not $_.Core -and $_.State -like 'Unknown-*' })
    $optionalEmpty = @($probeRows | Where-Object { -not $_.Core -and $_.State -eq 'Readable-NoRecords' })
    $staleCore = @($probeRows | Where-Object { $_.Core -and $_.State -eq 'Readable' -and $null -ne $_.AgeDays -and $_.AgeDays -gt 7 })
    if ($coreUnknown.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Core Entra monitoring logs could not be read' `
            -Evidence ("Unreadable core datasets: {0}." -f (($coreUnknown.Dataset) -join ', ')) `
            -WhyItMatters 'If sign-in or directory audit visibility is unavailable, this audit cannot verify the evidence needed to detect identity compromise and configuration changes.' `
            -RecommendedAction 'Confirm AuditLog.Read.All, the operator role, licensing/retention, and Graph connectivity, then re-run.' `
            -SourceFile $probeSource -ResultRows $coreUnknown -RuleId 'monitoring-core-log-unreadable' -ObjectType 'tenant' -CoverageGap
    }
    if ($coreEmpty.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Core Entra log endpoints returned no records' `
            -Evidence ("Readable but empty core datasets: {0}. This is not treated as proof of configured logging." -f (($coreEmpty.Dataset) -join ', ')) `
            -WhyItMatters 'An empty result may be legitimate for a new/quiet tenant, but can also reflect retention, licensing, or collection gaps.' `
            -RecommendedAction 'Validate recent activity in the Entra portal and confirm the tenant retention/export design.' `
            -SourceFile $probeSource -ResultRows $coreEmpty -RuleId 'monitoring-core-log-empty' -ObjectType 'tenant' -CoverageGap
    }
    if ($optionalUnknown.Count -gt 0 -or $optionalEmpty.Count -gt 0) {
        $optionalGaps = @($optionalUnknown) + @($optionalEmpty)
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Some threat-monitoring datasets were not assessable' `
            -Evidence ("Unreadable, timestamp-unknown, or empty optional/Premium datasets: {0}." -f (($optionalGaps | ForEach-Object { "{0} [{1}] ({2})" -f $_.Dataset,$_.State,$_.RequiredScope }) -join '; ')) `
            -WhyItMatters 'Unavailable provisioning, risk-detection, or security-alert data reduces the audit evidence available for detecting compromised identities and workloads.' `
            -RecommendedAction 'Where licensed and operationally required, grant the documented read-only scope and verify the supporting service is enabled.' `
            -SourceFile $probeSource -ResultRows $optionalGaps -RuleId 'monitoring-optional-dataset-unknown' -ObjectType 'tenant' -CoverageGap
    }
    if ($staleCore.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Core Entra monitoring data appears stale' `
            -Evidence ("Core datasets whose newest returned event is older than seven days: {0}." -f (($staleCore | ForEach-Object { "{0} ({1} days)" -f $_.Dataset,$_.AgeDays }) -join '; ')) `
            -WhyItMatters 'Readable APIs do not demonstrate current telemetry if their newest record is unexpectedly old.' `
            -RecommendedAction 'Confirm current tenant activity, licensing and retention, export ingestion health, and any upstream collection delay.' `
            -SourceFile $probeSource -ResultRows $staleCore -RuleId 'monitoring-core-log-stale' -ObjectType 'tenant'
    }

    $breakGlassUpns = @()
    try { $breakGlassUpns = @(Normalize-StringList -Values $BreakGlassUpns) } catch {}
    $azureCoverage = Get-EAAzureMonitoringCoverage -EmergencyAccessUpns $breakGlassUpns

    $crossPlaneRows = @($azureCoverage.Rows.ToArray())
    foreach ($coverageError in @($azureCoverage.Errors.ToArray())) {
        $crossPlaneRows += [pscustomobject]@{
            Plane=$coverageError.Plane; Scope=$coverageError.Scope; Control=$coverageError.Control
            Name=''; Enabled=$null; State='Unknown'; Detail=$coverageError.Error
            IdentitySignal=$false; EmergencySignal=$false; ActionGroupReferences=''
        }
    }
    if ($crossPlaneRows.Count -eq 0) {
        $crossPlaneRows = @([pscustomobject]@{
            Plane='Azure Resource Manager'; Scope='Tenant/subscriptions'; Control='Diagnostic and alert coverage'
            Name=''; Enabled=$null; State=$azureCoverage.State; Detail=$azureCoverage.Detail
            IdentitySignal=$false; EmergencySignal=$false; ActionGroupReferences=''
        })
    }
    $crossPlaneSource = Write-Evidence -BaseName 'monitoring_cross_plane_coverage' -Rows $crossPlaneRows -Title 'Azure Monitoring Cross-Plane Coverage' `
        -Notes @(
            'Only a pre-existing matching-tenant Az context is consumed. This audit never signs in, changes the current context, installs Az modules, or writes an Azure resource.',
            'Rule keyword matches are review candidates; notification delivery still requires an end-to-end operational test.'
        )

    if ($azureCoverage.State -ne 'Complete') {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Azure diagnostic export, alert-rule, or action-group coverage is incomplete' `
            -Evidence ("Azure cross-plane state: {0}. {1}" -f $azureCoverage.State,$azureCoverage.Detail) `
            -WhyItMatters 'Graph log readability is not evidence that logs are retained externally or that critical identity events generate actionable notifications.' `
            -RecommendedAction 'Use a pre-existing matching-tenant Azure read-only context with Monitoring Reader (or narrower custom read permissions), resolve every failed dataset, and re-run; never grant Azure write access to the audit identity.' `
            -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-arm-cross-plane-incomplete' -ObjectType 'tenant' -CoverageGap
    } else {
        if ($azureCoverage.EnabledDiagnosticSettingCount -eq 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'No enabled Entra diagnostic export with a destination was found' `
                -Evidence ("{0} tenant diagnostic setting(s) were read; none had both enabled log categories and an export destination." -f $azureCoverage.DiagnosticSettingCount) `
                -WhyItMatters 'Native Entra retention is finite; without durable export, investigation and detection history can disappear before an incident is discovered.' `
                -RecommendedAction 'Export the licensed AuditLogs, SignInLogs, non-interactive/workload sign-ins, and risk logs to an approved Log Analytics workspace, event hub, or storage destination with governed retention.' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-no-entra-diagnostic-export' -ObjectType 'tenant'
        }
        if ($azureCoverage.EnabledDiagnosticSettingCount -gt 0 -and -not $azureCoverage.CoreDiagnosticCategoriesComplete) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'Entra diagnostic export does not cover both audit and sign-in logs' `
                -Evidence ("Destination-backed exported categories: {0}. AuditLogs and SignInLogs (or allLogs) were not both present." -f (($azureCoverage.ExportedLogCategories) -join ', ')) `
                -WhyItMatters 'A diagnostic setting that exports only a subset of identity telemetry leaves critical configuration changes or sign-ins outside the durable monitoring path.' `
                -RecommendedAction 'Enable both AuditLogs and SignInLogs, then add the licensed non-interactive, service-principal, managed-identity, and risk log categories required by the detection design.' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-entra-diagnostic-core-category-gap' -ObjectType 'tenant'
        }
        if ($azureCoverage.IdentityAlertCandidateCount -eq 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'No enabled Azure Monitor rule matching critical identity changes was found' `
                -Evidence ("{0} scheduled-query/activity-log alert rule(s) were read; none matched the identity/change monitoring classifier." -f $azureCoverage.AlertRuleCount) `
                -WhyItMatters 'High-impact role, Conditional Access, authentication, federation, credential, and consent changes should alert responders independently of a periodic audit.' `
                -RecommendedAction 'Create tested alerts for emergency-account use and critical identity changes, scoped to exported Entra logs and routed to an owned action group/Sentinel workflow.' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-no-critical-identity-alert-candidate' -ObjectType 'tenant'
        } elseif ($azureCoverage.IdentityAlertWithActionCount -eq 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'Identity alert candidates have no linked enabled action group' `
                -Evidence ("Identity-related enabled rule candidates={0}; candidates linked to an enabled action group={1}." -f $azureCoverage.IdentityAlertCandidateCount,$azureCoverage.IdentityAlertWithActionCount) `
                -WhyItMatters 'An enabled detection rule without a linked, enabled responder destination can create a portal-only signal that nobody receives.' `
                -RecommendedAction 'Link each critical identity rule to an owned enabled action group, or separately verify and document its Sentinel automation/incident-routing path.' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-identity-alert-action-link-gap' -ObjectType 'tenant'
        }
        if ($azureCoverage.EnabledActionGroupCount -eq 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'No enabled Azure Monitor action group was found' `
                -Evidence ("{0} action group(s) were read; none were returned as enabled." -f $azureCoverage.ActionGroupCount) `
                -WhyItMatters 'An alert rule without a functioning responder destination does not create an operational response.' `
                -RecommendedAction 'Configure an owned, enabled action group or Sentinel automation path and test delivery to the responsible responders.' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-no-enabled-action-group' -ObjectType 'tenant'
        }
        if ($azureCoverage.EnabledDiagnosticSettingCount -gt 0 -and $azureCoverage.CoreDiagnosticCategoriesComplete -and $azureCoverage.IdentityAlertWithActionCount -gt 0) {
            Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
                -Title 'Azure diagnostic and identity-alert configuration evidence was found' `
                -Evidence ("Enabled diagnostic exports={0}; identity-related rules linked to enabled action groups={1}; enabled action groups={2}; subscriptions read={3}." -f $azureCoverage.EnabledDiagnosticSettingCount,$azureCoverage.IdentityAlertWithActionCount,$azureCoverage.EnabledActionGroupCount,$azureCoverage.SubscriptionCount) `
                -WhyItMatters 'Durable export, detection rules, and responder routing provide the configuration chain needed for identity monitoring.' `
                -RecommendedAction 'Continue periodic configuration review and retain evidence of end-to-end alert delivery tests.' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows
        }
    }

    $emergencyRows = @(Get-EAEmergencyAccessMonitoringRows -UserPrincipalNames $breakGlassUpns)
    foreach ($row in $emergencyRows) {
        $row.AlertRuleState = if ($azureCoverage.State -ne 'Complete') { 'Unknown-CrossPlaneIncomplete' } `
            elseif ($azureCoverage.EmergencyAlertCandidateCount -eq 0) { 'Known-NoMatchingRuleCandidate' } `
            elseif ($azureCoverage.EmergencyAlertWithActionCount -eq 0) { 'RuleCandidate-NoLinkedEnabledActionGroup' } `
            else { 'ConfigurationCandidateFound-DeliveryNotTested' }
    }
    $emergencySource = Write-Evidence -BaseName 'emergency_access_monitoring' -Rows $emergencyRows -Title 'Emergency-Access Sign-In Monitoring Coverage' `
        -Notes @('Graph sign-in visibility and configured alert-rule delivery are separate controls; this check does not infer one from the other.')
    $unreadableEmergency = @($emergencyRows | Where-Object { $_.SignInLogState -like 'Unknown*' })
    if ($unreadableEmergency.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Emergency-access sign-in monitoring cannot be fully verified' `
            -Evidence ("{0} emergency-account monitoring row(s) lack verifiable sign-in-log coverage; Azure Monitor alert-rule state is also cross-plane and unknown." -f $unreadableEmergency.Count) `
            -WhyItMatters 'Emergency accounts are deliberately exempt from some preventive controls; every use must therefore create an immediate, independently routed alert.' `
            -RecommendedAction 'Supply the designated accounts with -BreakGlassUpns, confirm their sign-in logs are readable, and manually verify an Azure Monitor/Sentinel alert plus tested notification routing for every emergency-account sign-in.' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-monitoring-unknown' -ObjectType 'tenant' -CoverageGap
    } elseif ($azureCoverage.State -ne 'Complete') {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Emergency-access alert-rule delivery requires cross-plane verification' `
            -Evidence ("Sign-in log queries for the configured emergency accounts were readable, but Azure monitoring coverage is {0}; the Graph token alone cannot verify alert rules or action groups." -f $azureCoverage.State) `
            -WhyItMatters 'Log availability alone does not guarantee that an emergency-account sign-in wakes a responder.' `
            -RecommendedAction 'Using a separate Azure read-only context, validate the rule, action group/Sentinel automation, enabled state, scope, and a recent end-to-end test for each emergency account.' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-alert-cross-plane' -ObjectType 'tenant' -CoverageGap
    } elseif ($azureCoverage.EmergencyAlertCandidateCount -eq 0 -or $azureCoverage.EmergencyAlertWithActionCount -eq 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'No complete emergency-access alert configuration was found' `
            -Evidence ("Emergency rule candidates={0}; candidates linked to an enabled action group={1}." -f $azureCoverage.EmergencyAlertCandidateCount,$azureCoverage.EmergencyAlertWithActionCount) `
            -WhyItMatters 'Emergency accounts are preventive-control exceptions and require immediate, independently routed notification on every use.' `
            -RecommendedAction 'Create or correct an enabled rule that explicitly matches every configured emergency-account UPN, route it to an enabled responder destination, and test it end to end.' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-alert-missing' -ObjectType 'tenant'
    } else {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Emergency-access alert configuration found; delivery test remains manual' `
            -Evidence ("{0} matching enabled rule candidate(s) are linked to an enabled action group, but configuration reads cannot prove notification delivery." -f $azureCoverage.EmergencyAlertWithActionCount) `
            -WhyItMatters 'A syntactically configured rule can still fail because of a query, ingestion, action-group, recipient, or downstream automation problem.' `
            -RecommendedAction 'Perform and document a controlled end-to-end alert test without using the production emergency credential for routine work.' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-alert-delivery-untested' -ObjectType 'tenant' -CoverageGap
    }
}

function Get-EAChangeMonitoringClassification {
    param([Parameter(Mandatory)][object]$AuditEvent)

    $activity = [string](Get-EAApplicationCheckValue $AuditEvent 'activityDisplayName')
    $category = [string](Get-EAApplicationCheckValue $AuditEvent 'category')
    $service = [string](Get-EAApplicationCheckValue $AuditEvent 'loggedByService')
    $targetTypes = @((Get-EAApplicationCheckValue $AuditEvent 'targetResources') | ForEach-Object {
        [string](Get-EAApplicationCheckValue $_ 'type')
    }) -join ' '
    $text = @($activity, $category, $service, $targetTypes) -join ' | '

    $domain = $null
    $reason = $null
    $highRisk = $false

    if ($category -eq 'RoleManagement' -or $text -match '(?i)(directory role|unifiedRole|eligible role|role assignment schedule|PIM role)') {
        $domain = 'Privileged role'
        $reason = 'A privileged role assignment, eligibility, activation, policy, or role definition changed.'
        $highRisk = $true
    } elseif ($text -match '(?i)(conditional[ -]?access|conditionalAccessPolicy|named location)') {
        $domain = 'Conditional Access'
        $reason = 'A Conditional Access policy, named location, or related enforcement object changed.'
        $highRisk = $true
    } elseif ($text -match '(?i)(authentication methods? policy|authenticationMethodsPolicy|authentication method|authentication strength|security info|temporary access pass|FIDO2|passkey|software OATH|passwordless|authenticator app|phone method|email method|windows hello|certificate-based authentication|strong authentication method)') {
        $domain = 'Authentication method'
        $reason = 'An authentication method, registration, or tenant authentication-method policy changed.'
        $highRisk = $true
    } elseif ($text -match '(?i)(cross[ -]?tenant|federat|domain authentication|external identity provider|B2B.*trust|inbound trust|outbound trust)') {
        $domain = 'Federation or cross-tenant trust'
        $reason = 'A federation, domain-authentication, identity-provider, or cross-tenant trust control changed.'
        $highRisk = $true
    } elseif ($text -match '(?i)((application|service principal).*(credential|password|certificate|key)|(credential|password|certificate|key).*(application|service principal)|certificates and secrets)') {
        $domain = 'Application credential'
        $reason = 'A credential, password, certificate, or key on an application/service principal changed.'
        $highRisk = $true
    } elseif ($text -match '(?i)((add|remove|update).*(owner).*(application|service principal)|(application|service principal).*(owner).*(added|removed|updated)|application owner|service principal owner)') {
        $domain = 'Application or service-principal owner'
        $reason = 'An owner who can administer an application or enterprise application was added, removed, or changed.'
        $highRisk = $true
    } elseif ($text -match '(?i)(consent|oauth2PermissionGrant|delegated permission grant|app role assignment|permission grant)') {
        $domain = 'Application consent or permission grant'
        $reason = 'An OAuth consent, delegated grant, or application app-role grant changed.'
        $highRisk = $true
    } elseif ($text -match '(?i)((add|remove).*(member|owner).*(group)|(member|owner).*(added|removed).*(group)|group membership|group owner)') {
        $domain = 'Group owner or membership'
        $reason = 'A group owner or membership path changed; privileged/app access may flow transitively through that group.'
        $highRisk = $false
    }

    if (-not $domain) { return $null }
    return [pscustomobject]@{ Domain=$domain; HighRisk=[bool]$highRisk; Reason=$reason }
}

function Get-EAChangeMonitoringInitiator {
    param([object]$AuditEvent)

    $initiatedBy = Get-EAApplicationCheckValue $AuditEvent 'initiatedBy'
    $user = Get-EAApplicationCheckValue $initiatedBy 'user'
    $app = Get-EAApplicationCheckValue $initiatedBy 'app'
    $userName = [string](@(
        Get-EAApplicationCheckValue $user 'userPrincipalName'
        Get-EAApplicationCheckValue $user 'displayName'
        Get-EAApplicationCheckValue $user 'id'
    ) | Where-Object { $_ } | Select-Object -First 1)
    if ($userName) { return [pscustomobject]@{ Type='User'; Name=$userName; Id=[string](Get-EAApplicationCheckValue $user 'id') } }

    $appName = [string](@(
        Get-EAApplicationCheckValue $app 'displayName'
        Get-EAApplicationCheckValue $app 'servicePrincipalName'
        Get-EAApplicationCheckValue $app 'appId'
    ) | Where-Object { $_ } | Select-Object -First 1)
    if ($appName) { return [pscustomobject]@{ Type='Application'; Name=$appName; Id=[string](Get-EAApplicationCheckValue $app 'servicePrincipalId') } }
    return [pscustomobject]@{ Type='Unknown'; Name='Unknown initiator'; Id='' }
}

function Invoke-Check-ChangeMonitoring {
    $checkId = 'changemonitoring'
    $category = 'Change Monitoring'
    $recentDays = if (Get-Variable -Name RecentChangeDays -Scope Script -ErrorAction SilentlyContinue) { [int]$script:RecentChangeDays } `
        elseif (Get-Variable -Name RecentChangeDays -ErrorAction SilentlyContinue) { [int]$RecentChangeDays } else { 30 }
    $since = (Get-Date).ToUniversalTime().AddDays(-$recentDays)
    $sinceText = $since.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDateTime%20ge%20' + [uri]::EscapeDataString($sinceText) + '&$orderby=activityDateTime%20desc&$top=999&$select=id,activityDateTime,activityDisplayName,category,loggedByService,operationType,result,resultReason,correlationId,initiatedBy,targetResources'

    try {
        $events = @(Get-EAReadOnlyGraphCollection -Uri $uri)
    } catch {
        $gapRows = @([pscustomobject]@{ Dataset='directoryAudits'; Since=$since; State='Unknown'; Error=$_.Exception.Message })
        $gapSource = Write-Evidence -BaseName 'critical_change_monitoring_gaps' -Rows $gapRows -Title 'Critical Change Monitoring Coverage Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Critical directory change monitoring could not be assessed' `
            -Evidence 'The directoryAudits collection could not be completely read for the requested period; no-change cannot be concluded.' `
            -WhyItMatters 'Missing audit coverage can conceal role, Conditional Access, authentication, federation, app credential, consent, and group-access changes.' `
            -RecommendedAction 'Confirm AuditLog.Read.All, the supported Entra role and retention, resolve Graph errors/throttling, and re-run.' `
            -SourceFile $gapSource -ResultRows $gapRows -RuleId 'critical-change-monitoring-unknown' -ObjectType 'tenant' -CoverageGap
        return
    }

    # Native Graph audit-log retention is seven days on Entra Free and 30 days on
    # P1/P2. This check does not query an external archive, so a longer requested
    # lookback is explicitly incomplete instead of silently appearing event-free.
    $licenseKnownVariable = Get-Variable -Name LicenseKnown -Scope Script -ErrorAction SilentlyContinue
    $hasP1Variable = Get-Variable -Name HasP1 -Scope Script -ErrorAction SilentlyContinue
    $licenseKnown = if ($licenseKnownVariable) { [bool]$licenseKnownVariable.Value } else { $false }
    $hasP1 = if ($hasP1Variable) { [bool]$hasP1Variable.Value } else { $false }
    $nativeRetentionDays = if ($recentDays -le 7) { 7 } elseif (-not $licenseKnown) { $null } elseif ($hasP1) { 30 } else { 7 }
    if ($null -eq $nativeRetentionDays -or $recentDays -gt $nativeRetentionDays) {
        $retentionRows = @([pscustomobject]@{
            RequestedDays=$recentDays
            NativeRetentionDays=if ($null -eq $nativeRetentionDays) { 'Unknown' } else { $nativeRetentionDays }
            LicenseDetection=if ($licenseKnown) { 'Known' } else { 'Unknown' }
            ExternalArchiveQueried=$false
        })
        $retentionSource = Write-Evidence -BaseName 'critical_change_retention_gaps' -Rows $retentionRows -Title 'Critical Change Monitoring Retention Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Requested critical-change lookback exceeds verified Graph retention' `
            -Evidence ("Requested {0} days; verified native Graph audit retention for this run is {1} days. External Azure/Purview archives were not queried." -f $recentDays, $(if ($null -eq $nativeRetentionDays) { 'unknown' } else { $nativeRetentionDays })) `
            -WhyItMatters 'A completely paged Graph response is complete only within data still retained by Entra; older changes may have expired from the native API.' `
            -RecommendedAction 'Use seven days on Entra Free or up to 30 days on P1/P2, and query the governed Log Analytics, storage, event-hub/SIEM, or Purview archive for longer investigations.' `
            -SourceFile $retentionSource -ResultRows $retentionRows -RuleId 'critical-change-retention-incomplete' -ObjectType 'tenant' -CoverageGap
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($event in $events) {
        $classification = Get-EAChangeMonitoringClassification -AuditEvent $event
        if (-not $classification) { continue }
        $initiator = Get-EAChangeMonitoringInitiator -AuditEvent $event
        $targets = @()
        $targetTypes = @()
        $modifiedNames = @()
        foreach ($target in @(Get-EAApplicationCheckValue $event 'targetResources')) {
            $targetName = [string](@(
                Get-EAApplicationCheckValue $target 'userPrincipalName'
                Get-EAApplicationCheckValue $target 'displayName'
                Get-EAApplicationCheckValue $target 'id'
            ) | Where-Object { $_ } | Select-Object -First 1)
            if ($targetName) { $targets += $targetName }
            $targetType = [string](Get-EAApplicationCheckValue $target 'type')
            if ($targetType) { $targetTypes += $targetType }
            foreach ($property in @(Get-EAApplicationCheckValue $target 'modifiedProperties')) {
                $propertyName = [string](Get-EAApplicationCheckValue $property 'displayName')
                if ($propertyName) { $modifiedNames += $propertyName }
            }
        }
        $result = [string](Get-EAApplicationCheckValue $event 'result')
        $success = ($result -match '^(?i:success)$')
        $reviewPriority = if ($classification.HighRisk -and $success) { 'High' } elseif ($classification.HighRisk) { 'AttemptedHigh' } else { 'Standard' }
        $rows.Add([pscustomobject]@{
            ActivityDateTime=ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $event 'activityDateTime')
            Domain=$classification.Domain; ReviewPriority=$reviewPriority
            Activity=[string](Get-EAApplicationCheckValue $event 'activityDisplayName')
            Category=[string](Get-EAApplicationCheckValue $event 'category')
            OperationType=[string](Get-EAApplicationCheckValue $event 'operationType')
            Result=$result; ResultReason=[string](Get-EAApplicationCheckValue $event 'resultReason')
            InitiatorType=$initiator.Type; Initiator=$initiator.Name; InitiatorId=$initiator.Id
            Targets=($targets | Select-Object -Unique) -join ', '
            TargetTypes=($targetTypes | Select-Object -Unique) -join ', '
            ModifiedProperties=($modifiedNames | Select-Object -Unique) -join ', '
            CorrelationId=[string](Get-EAApplicationCheckValue $event 'correlationId')
            ClassificationReason=$classification.Reason
        }) | Out-Null
    }

    $resultRows = @($rows.ToArray())
    $source = Write-Evidence -BaseName 'critical_directory_changes' -Rows $resultRows `
        -Title ("Critical Identity and Access Changes (requested last {0} days; subject to native retention)" -f $recentDays) `
        -Notes @(
            ("Scanned {0} directory audit event(s); retained {1} event(s) in the requested change families." -f $events.Count, $resultRows.Count),
            'ReviewPriority is a triage classification, not a claim that the recorded change was malicious.'
        )

    $successfulHigh = @($resultRows | Where-Object { $_.ReviewPriority -eq 'High' })
    $successfulStandard = @($resultRows | Where-Object { $_.ReviewPriority -eq 'Standard' -and $_.Result -match '^(?i:success)$' })
    $attemptedHigh = @($resultRows | Where-Object { $_.ReviewPriority -eq 'AttemptedHigh' })

    if ($successfulHigh.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ("{0} successful high-risk identity/control-plane change(s) require validation" -f $successfulHigh.Count) `
            -Evidence ("Domains: {0}." -f (($successfulHigh.Domain | Group-Object | ForEach-Object { "{0}={1}" -f $_.Name,$_.Count }) -join '; ')) `
            -WhyItMatters 'Recent privileged role, Conditional Access, authentication, federation/trust, app credential, or consent changes are common persistence and defense-evasion paths even when performed through legitimate administration channels.' `
            -RecommendedAction 'Match each event to an approved change, validate the initiator and target, and investigate any unexpected application initiator or correlation ID.' `
            -SourceFile $source -ResultRows $successfulHigh -RuleId 'recent-high-risk-directory-change' -ObjectType 'auditEvent'
    }
    if ($successfulStandard.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ("{0} group owner/membership change(s) require access-path review" -f $successfulStandard.Count) `
            -Evidence 'Successful changes to group owners or members were recorded in the review period.' `
            -WhyItMatters 'Groups can confer privileged roles and application access transitively, so an apparently routine membership change can alter effective access.' `
            -RecommendedAction 'Validate each change against the group purpose and owner; prioritize role-assignable, PIM-managed, and enterprise-app-assigned groups.' `
            -SourceFile $source -ResultRows $successfulStandard -RuleId 'recent-group-access-change' -ObjectType 'auditEvent'
    }
    if ($attemptedHigh.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ("{0} unsuccessful high-risk change attempt(s) were recorded" -f $attemptedHigh.Count) `
            -Evidence 'A role, Conditional Access, authentication, federation/trust, application credential, or consent operation did not report success.' `
            -WhyItMatters 'Repeated or unexpected failed administrative operations can signal discovery, misuse of stale automation, or an attempted persistence/control change.' `
            -RecommendedAction 'Review the initiator, failure reason, targets, and correlated events; tune alerts for unexpected application initiators and repeated failures.' `
            -SourceFile $source -ResultRows $attemptedHigh -RuleId 'attempted-high-risk-directory-change' -ObjectType 'auditEvent'
    }
    if ($resultRows.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title ("No monitored critical change events found in the last {0} days" -f $recentDays) `
            -Evidence ("The directory audit endpoint was readable and {0} retained event(s) were scanned; none matched the role, CA, authentication method, federation/trust, app credential/owner, consent, or group owner/membership classifiers." -f $events.Count) `
            -WhyItMatters 'A readable, completely paged collection distinguishes no matching retained events from an API-read failure; the separate retention result defines the verified time boundary.' `
            -RecommendedAction 'Continue periodic review and configure independent alerting for the same high-risk change families.' `
            -SourceFile $source
    }
}
