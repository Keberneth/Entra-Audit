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

# Get-EAApplicationCheckValue returns collections comma-wrapped so an assignment keeps
# an empty value[] distinct from a missing property (Get-EAReadOnlyGraphCollection relies
# on that). Wrapping such a call directly in @() therefore yields ONE element - the whole
# array. Use this enumerating companion wherever the elements are iterated or counted.
function Get-EAApplicationCheckElement {
    param(
        [object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $value = Get-EAApplicationCheckValue -Object $Object -Name $Name
    if ($null -eq $value) { return }
    foreach ($item in @($value)) {
        if ($null -ne $item) { $item }
    }
}

function Format-EAApplicationCheckList {
    # "a, b, c (and 12 more)" for finding evidence: distinct, non-empty items in their
    # original order, capped at $First so a finding card stays readable. The full list
    # is always in the linked evidence file.
    param(
        [object[]]$Items,
        [ValidateRange(1, 100)][int]$First = 10
    )

    $all = @($Items | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { [string]$_ } | Select-Object -Unique)
    if ($all.Count -eq 0) { return 'none' }
    $text = ($all | Select-Object -First $First) -join ', '
    if ($all.Count -gt $First) { $text += (" (and {0} more)" -f ($all.Count - $First)) }
    return $text
}

function Format-EAApplicationCheckCount {
    # Count-led finding titles with singular/plural agreement, the same shape as the main
    # script's Format-EACount: -Count 1 -One 'app has' -Many 'apps have' -> '1 app has'.
    param([int]$Count, [string]$One, [string]$Many)

    if ($Count -eq 1) { return ('1 ' + $One) }
    return ('{0} {1}' -f $Count, $Many)
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

function Test-EAApplicationCheckThrottled {
    # HTTP 429 that is still returned after the Graph SDK's own retries: the service keeps
    # throttling this client.
    param([object]$ErrorRecord)

    if ((Get-EAApplicationCheckHttpStatus $ErrorRecord) -eq 429) { return $true }
    return ([string]$ErrorRecord.Exception.Message -match '(?i)\b429\b|TooManyRequests|throttl')
}

function Get-EAApplicationCheckStopReason {
    # Loops that send one GET per object stop early instead of hammering Graph when every
    # further read would fail the same way: after an access-denied error, or after
    # $ThrottleLimit throttled reads in a row. Returns the reason as plain text, or $null
    # to keep going. The caller records every object it did not read as a coverage gap.
    param(
        [object]$ErrorRecord,
        [Parameter(Mandatory)][ref]$ThrottleRun,
        [ValidateRange(1, 100)][int]$ThrottleLimit = 5
    )

    $status = Get-EAApplicationCheckHttpStatus $ErrorRecord
    if ($status -in 401,403) { return ("access was denied (HTTP {0})" -f $status) }
    if (Test-EAApplicationCheckThrottled $ErrorRecord) {
        $ThrottleRun.Value = [int]$ThrottleRun.Value + 1
        if ($ThrottleRun.Value -ge $ThrottleLimit) {
            return ("Microsoft Graph kept throttling the audit ({0} reads in a row failed with HTTP 429)" -f $ThrottleRun.Value)
        }
    } else {
        $ThrottleRun.Value = 0
    }
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

function Get-EAReportedElsewhereIndex {
    # Some objects are inspected by both an older main-script check (apps, appcredentials,
    # consentgrants) and a newer check in this file. Returns key -> highest severity rank
    # (Critical=4 ... Low=1) of the risk findings that CheckId has ALREADY added in this
    # run, keyed by $KeySelector over each finding's rows. A newer check skips an object
    # only when it is already reported at the same or a higher severity, so it is scored
    # once. Only reported rows are indexed: if the other check did not run, failed, or
    # could not read an object, nothing is skipped. Coverage-gap findings are ignored.
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][scriptblock]$KeySelector
    )

    $rank = @{ Critical=4; High=3; Medium=2; Low=1 }
    $index = @{}
    # Enumerate directly: @() over the New-Object List that holds the findings throws
    # "Argument types do not match" on PowerShell 7.4.
    foreach ($finding in $script:Findings) {
        if ($null -eq $finding -or [string](Get-EAApplicationCheckValue $finding 'CheckId') -ne $CheckId) { continue }
        if ([bool](Get-EAApplicationCheckValue $finding 'CoverageGap')) { continue }
        $severityRank = $rank[[string](Get-EAApplicationCheckValue $finding 'Severity')]
        if (-not $severityRank) { continue }
        foreach ($row in @(Get-EAApplicationCheckElement $finding 'ResultRows')) {
            foreach ($key in @(& $KeySelector $row)) {
                if ([string]::IsNullOrWhiteSpace([string]$key)) { continue }
                $key = ([string]$key).ToLowerInvariant()
                if (-not $index.ContainsKey($key) -or $index[$key] -lt $severityRank) { $index[$key] = $severityRank }
            }
        }
    }
    return $index
}

function ConvertTo-EAWorkloadCredentialIdentifier {
    # customKeyIdentifier arrives as byte[] (Graph SDK objects) or as base64 text (raw
    # JSON). Returns one comparable text form, or $null when it is empty, so an empty
    # identifier never pairs two unrelated credentials. Same normalisation as staleapps.
    param([object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) {
        if ($Value.Length -eq 0) { return $null }
        return [Convert]::ToBase64String($Value)
    }
    $text = ([string]$Value).Trim()
    if ($text) { return $text }
    return $null
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

        # A SAML (token-signing) certificate on a service principal is stored as three
        # entries: a private key (usage Sign), its public key (usage Verify), and a password
        # that only protects the private key. All three share customKeyIdentifier (the
        # certificate thumbprint), and the password also shares the Sign key's keyId.
        # Microsoft creates them with a three-year lifetime by default. Count the set once,
        # as one token-signing certificate, instead of one long-lived secret plus two
        # overlapping certificates. Pairing uses the normalised customKeyIdentifier only
        # (as the staleapps check does), so small differences in the stored dates of the
        # three halves cannot split one certificate into several findings.
        $signKeyIds = @{}
        $signIdentifiers = @{}
        if ($ObjectType -eq 'ServicePrincipal') {
            foreach ($key in @(Get-EAApplicationCheckElement $object 'KeyCredentials')) {
                if ([string](Get-EAApplicationCheckValue $key 'Usage') -ne 'Sign') { continue }
                $signKeyId = [string](Get-EAApplicationCheckValue $key 'KeyId')
                if ($signKeyId) { $signKeyIds[$signKeyId] = $true }
                $signIdentifier = ConvertTo-EAWorkloadCredentialIdentifier (Get-EAApplicationCheckValue $key 'CustomKeyIdentifier')
                if ($signIdentifier) { $signIdentifiers[$signIdentifier] = $true }
            }
        }

        foreach ($spec in @(
            [pscustomobject]@{ Property='PasswordCredentials'; Type='Secret'; LongDays=180 },
            [pscustomobject]@{ Property='KeyCredentials';      Type='Certificate'; LongDays=730 }
        )) {
            foreach ($credential in @(Get-EAApplicationCheckElement $object $spec.Property)) {
                if ($null -eq $credential) { continue }
                $usage = [string](Get-EAApplicationCheckValue $credential 'Usage')
                $credentialType = $spec.Type
                $longDays = $spec.LongDays
                if ($signKeyIds.Count -gt 0 -or $signIdentifiers.Count -gt 0) {
                    $credentialIdentifier = ConvertTo-EAWorkloadCredentialIdentifier (Get-EAApplicationCheckValue $credential 'CustomKeyIdentifier')
                    $isSigningSet = [bool]($credentialIdentifier -and $signIdentifiers.ContainsKey($credentialIdentifier))
                    if ($spec.Type -eq 'Secret' -and ($isSigningSet -or $signKeyIds.ContainsKey([string](Get-EAApplicationCheckValue $credential 'KeyId')))) { continue }
                    if ($usage -eq 'Verify' -and $isSigningSet) { continue }
                    if ($usage -eq 'Sign') {
                        $credentialType = 'Token-signing certificate'
                        # Three calendar years, including a leap day.
                        $longDays = 1096
                    }
                }
                $start = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $credential 'StartDateTime')
                $end = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $credential 'EndDateTime')
                $noExpiry = ($null -eq $end)
                $lifetime = if ($start -and $end) { [math]::Round(($end - $start).TotalDays, 1) } else { $null }
                $daysLeft = if ($end) { [math]::Floor(($end - $Now).TotalDays) } else { $null }
                $state = if ($noExpiry) { 'NoExpiry' } elseif ($end -lt $Now) { 'Expired' } elseif ($end -le $Now.AddDays($WarningDays)) { 'ExpiringSoon' } else { 'Valid' }
                $active = ((-not $start) -or $start -le $Now) -and ($noExpiry -or $end -gt $Now)
                # An expired credential can no longer be used to sign in (Entra rejects it),
                # so its long lifetime no longer widens any attack window. It is reported
                # once, as expired, instead of a second time as long-lived.
                $longLived = ($null -ne $lifetime -and $lifetime -gt $longDays -and $state -ne 'Expired')
                $rows.Add([pscustomobject]@{
                    ObjectType       = $ObjectType
                    ObjectName       = $displayName
                    ObjectId         = $objectId
                    AppId            = $appId
                    CredentialType   = $credentialType
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
                    LongLifeLimitDays= $longDays
                    ReportedUnder    = ''
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
            foreach ($restriction in @(Get-EAApplicationCheckElement $config $kind.Property)) {
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

function ConvertTo-EAFederatedCredentialRow {
    # One evidence row per federated identity credential (trust) of an application.
    param(
        [Parameter(Mandatory)][object]$Application,
        [Parameter(Mandatory)][object]$Trust
    )

    $audiences = @((Get-EAApplicationCheckValue $Trust 'audiences') | Where-Object { $_ })
    $issuer = [string](Get-EAApplicationCheckValue $Trust 'issuer')
    $subject = [string](Get-EAApplicationCheckValue $Trust 'subject')
    $claimsExpression = Get-EAApplicationCheckValue $Trust 'claimsMatchingExpression'
    $expressionValue = [string](Get-EAApplicationCheckValue $claimsExpression 'value')
    $expressionLanguageVersion = Get-EAApplicationCheckValue $claimsExpression 'languageVersion'
    return [pscustomobject]@{
        Application = [string](Get-EAApplicationCheckValue $Application 'DisplayName')
        AppId       = [string](Get-EAApplicationCheckValue $Application 'AppId')
        ObjectId    = [string](Get-EAApplicationCheckValue $Application 'Id')
        Credential  = [string](Get-EAApplicationCheckValue $Trust 'name')
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
    }
}

function Get-EAFederatedCredentialIssue {
    # Plain-language list of what is wrong with one trust row (for finding evidence).
    param([Parameter(Mandatory)][object]$Row)

    $issues = @()
    if ($Row.MissingTrustField) { $issues += 'missing issuer, subject or audience' }
    if ($Row.ConflictingSubjectAndExpression) { $issues += 'has both a subject and a claims expression' }
    if ($Row.InvalidExpressionLanguageVersion) { $issues += 'unsupported expression language version' }
    if ($Row.NonStandardAudience) { $issues += ("unusual audience '{0}'" -f $Row.Audiences) }
    return ($issues -join ', ')
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
            -SourceFile $credentialSource -ResultRows $expired -RuleId 'workload-credential-expired' -ObjectType 'workloadIdentity'
    }
    if ($expiring.Count -gt 0) {
        $expiringElsewhereNote = if (@($credentialsReportedElsewhere | Where-Object { $_.State -eq 'ExpiringSoon' }).Count -gt 0) { ' Expiring app registration credentials already reported by the appcredentials check are not repeated here.' } else { '' }
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $expiring.Count -One 'app or service principal secret or certificate expires' -Many 'app or service principal secrets and certificates expire') + (' within {0} days' -f $warningDays)) `
            -Evidence ("Expiring on {0}, soonest first: {1}.{2}" -f (Format-EAApplicationCheckCount -Count (@($expiring.ObjectId | Select-Object -Unique).Count) -One 'object' -Many 'objects'),
                (Format-EAApplicationCheckList @($expiring | Sort-Object DaysLeft | ForEach-Object { "{0} [{1}] {2}" -f $_.ObjectName, $_.CredentialType, (Format-EAApplicationCheckCount -Count $_.DaysLeft -One 'day left' -Many 'days left') })), $expiringElsewhereNote) `
            -WhyItMatters 'When a secret or certificate runs out without a planned renewal, the integration that uses it stops working without warning.' `
            -RecommendedAction ("Renew each credential before its end date: create the new one, update the system that uses it, test it, then delete the old one ({0})." -f $credentialPortalPath) `
            -SourceFile $credentialSource -ResultRows $expiring -RuleId 'workload-credential-expiring' -ObjectType 'workloadIdentity'
    }
    if ($longLived.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $longLived.Count -One 'app secret or certificate stays valid for too long' -Many 'app secrets or certificates stay valid for too long') `
            -Evidence ("Credentials over the lifetime limit (secrets 180 days, certificates 2 years, SAML token-signing certificates 3 years), longest first: {0}." -f
                (Format-EAApplicationCheckList @($longLived | Sort-Object LifetimeDays -Descending | ForEach-Object { "{0} [{1}] valid {2:N0} days" -f $_.ObjectName, $_.CredentialType, $_.LifetimeDays }))) `
            -WhyItMatters 'The longer a secret or certificate stays valid, the longer a stolen copy can be used to sign in as the app. Long lifetimes also usually mean nobody renews them on a schedule.' `
            -RecommendedAction 'Replace these credentials with shorter-lived ones (secrets 180 days or less, certificates 2 years or less) and automate renewal. Where the other system supports it, use workload identity federation so that no secret is stored at all. A tenant-wide app management policy can enforce maximum lifetimes.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation' `
            -SourceFile $credentialSource -ResultRows $longLived -RuleId 'workload-credential-long-lived' -ObjectType 'workloadIdentity'
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
            -SourceFile $overlapSource -ResultRows $overlaps -RuleId 'workload-credential-excessive-overlap' -ObjectType 'workloadIdentity'
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
            -SourceFile $ficSource -ResultRows $invalidFic -RuleId 'federated-credential-broad-trust' -ObjectType 'application'
    }
    $flexibleFic = @($ficRows.ToArray() | Where-Object { $_.FlexibleWildcardExpression })
    if ($flexibleFic.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $flexibleFic.Count -One 'federated credential trust uses' -Many 'federated credential trusts use') + ' wildcards that may trust more workloads than intended') `
            -Evidence ("Claim expressions with a wildcard (* or ?): {0}. A plain subject value is always an exact match and is not counted here." -f
                (Format-EAApplicationCheckList @($flexibleFic | ForEach-Object { "{0} / {1}: {2}" -f $_.Application, $_.Credential, $_.ClaimsMatchingExpression }))) `
            -WhyItMatters 'A wildcard can match many repositories, branches or workloads. If it is broader than intended, an outside workload you do not control may be able to sign in as the app.' `
            -RecommendedAction 'Review each expression and narrow the wildcard so it only covers your own organization and repositories; add exact branch or environment conditions where possible.' `
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
            -SourceFile $policySource -ResultRows $unassignedCustomPolicies -RuleId 'custom-app-management-policy-unassigned' -ObjectType 'policy'
    }

    $riskRows = @($credentialRows | Where-Object { $_.State -in @('Expired','ExpiringSoon','NoExpiry') -or $_.LongLived })
    $coverageComplete = ($applicationKnown -and $servicePrincipalKnown -and $ficErrors.Count -eq 0 -and $ficNotAttempted -eq 0 -and $policyErrors.Count -eq 0)
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

function Get-EAServicePrincipalSignInActivityState {
    # Prefer the run-wide cached read in the main script (shared with staleapps), so the
    # beta report is downloaded once per run. That helper never throws and returns the
    # same shape: Known, ByAppId (appId -> newest sign-in of all five sub-activities),
    # Error. This library's own read below is the fallback when the helper is absent
    # (older main script) or returns something unexpected.
    $shared = Get-Command -Name 'Get-EAServicePrincipalSignInActivity' -CommandType Function -ErrorAction Ignore
    if ($shared) {
        $sharedState = $null
        try { $sharedState = & $shared } catch { $sharedState = $null }
        if ($null -ne $sharedState -and $null -ne $sharedState.PSObject.Properties['Known'] -and
            $sharedState.ByAppId -is [System.Collections.IDictionary]) {
            return $sharedState
        }
    }

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
        [string]$ResourceName,
        [ValidateSet('Application','Delegated')][string]$GrantType = 'Application',
        [string]$ConsentType
    )

    $risk = Get-EAApplicationPermissionBaseRisk -PermissionValue $PermissionValue -ResourceName $ResourceName
    if ($GrantType -ne 'Delegated') {
        # The apps check's tier-0 list stays authoritative for APPLICATION permissions:
        # everything it rates Critical (for example Mail.Read or Files.ReadWrite.All, which
        # open every mailbox or file without a signed-in user) is Tier0 here too, so this
        # check never rates the same application grant lower than the apps check does.
        # Delegated grants are not affected: they act only as the signed-in user.
        if ($risk.Risk -ne 'Tier0' -and $PermissionValue -and @($script:DangerousAppPermissions) -contains $PermissionValue) {
            return [pscustomobject]@{ Risk='Tier0'; Reason='Top-risk application permission (tenant takeover, all mail, or all files) that works without a signed-in user.' }
        }
        return $risk
    }

    # Delegated scopes act as the signed-in user, never tenant-wide on their own.
    # User.ReadWrite only edits the signed-in user's own profile (the consentgrants check
    # deliberately does not treat it as high-impact either).
    if ($PermissionValue -eq 'User.ReadWrite') {
        return [pscustomobject]@{ Risk='Other'; Reason="Delegated self-profile scope; acts only on the signed-in user's own profile." }
    }
    # Delegated directory reads return only what the signed-in user can already read
    # (members can read the directory by default), so they are not high impact. The
    # consentgrants check treats them the same way. Content and security reads (mail,
    # files, chats, audit, risk, alerts) stay high: consent lets the app collect them.
    if ($risk.Risk -eq 'HighImpactRead' -and
        $PermissionValue -match '(?i)^(User|Directory|Group|GroupMember|Device|Domain|Organization|Application)\.Read(Basic)?\.All$') {
        return [pscustomobject]@{ Risk='Other'; Reason='Delegated directory read; limited to what the signed-in user can already read.' }
    }
    $plainScope = if ($risk.Risk -eq 'WriteHigh') { 'can change or send data' } else { 'can read sensitive data' }
    # A per-user (Principal) grant is bounded by that one user's own access, so it is
    # reported separately from tenant-wide application/admin-consented access. Only a
    # documented 'Principal' value downgrades; a missing or unrecognised consent type
    # keeps the full severity. Tier0 scopes stay Tier0: they are takeover primitives
    # whenever that user is privileged.
    if ($risk.Risk -in @('WriteHigh','HighImpactRead')) {
        if ($ConsentType -eq 'Principal') {
            return [pscustomobject]@{
                Risk='UserDelegatedSensitive'
                Reason=("Delegated permission for one specific user; the app acts only as that user ({0})." -f $plainScope)
            }
        }
        if ($ConsentType -ne 'AllPrincipals') {
            $risk.Reason = ("Delegated permission whose consent type is missing or not recognised, so it is treated as applying to every user ({0})." -f $plainScope)
            return $risk
        }
    }
    if ($risk.Risk -eq 'HighImpactRead') {
        $risk.Reason = ("Admin-consented delegated read of sensitive data or security/configuration on {0} for every user who signs in." -f ($ResourceName ?? 'resource API'))
    }
    return $risk
}

function Get-EAApplicationPermissionBaseRisk {
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
    $highImpactRead = [pscustomobject]@{ Risk='HighImpactRead'; Reason=("Tenant-wide sensitive-data or security/configuration read access on {0}." -f ($ResourceName ?? 'resource API')) }
    # The exact read list is authoritative and is evaluated before the write pattern.
    if ($PermissionValue -in $highImpactReadExact) { return $highImpactRead }

    # Write verbs must START a permission-name segment (Mail.Send, Group.Create,
    # User.DeleteRestore.All, user_impersonation). Unanchored substrings made read-only
    # names such as RoleManagement.Read.Directory, EntitlementManagement.Read.All or
    # WindowsUpdates.Read.All look like write access. "Managed" (ManagedTenants.Read.All)
    # is not a write verb; PrivilegedOperations (device wipe/retire) is.
    if ($PermissionValue -match '(?i)(^|[._])(ReadWrite|Write|Send|Create|Delete|Update|Manage(?!d)|Invite|AccessAsUser|Impersonat|PrivilegedOperations)\w*(?=[._]|$)') {
        return [pscustomobject]@{ Risk='WriteHigh'; Reason='Write, send, management, or impersonation capability.' }
    }

    if ($PermissionValue -match '(?i)^(Mail|Calendars|Contacts|Files|Sites|Chat|ChatMessage|ChannelMessage|CallRecords|OnlineMeetingArtifact)\.Read(?:\.All)?$' -or
        $PermissionValue -match '(?i)^(Directory|RoleManagement|Application|User|Group|GroupMember|Device|Domain|Organization|CrossTenant|AuditLog|Reports|IdentityRisk|SecurityAlert|SecurityIncident).*\.Read\.All$') {
        return $highImpactRead
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
    $appPortalPath = 'Entra admin center > Enterprise applications > app'

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
            -Title 'Enterprise apps could not be read, so app ownership and access were not checked' `
            -Evidence ("The list of service principals (enterprise apps) could not be read: {0}. Owners, assignments, permissions and activity of every enterprise app are unknown." -f $inventoryError) `
            -WhyItMatters 'Apps without an owner, with broad access or no longer in use cannot show up in this report. This is a gap in the audit, not a clean result.' `
            -RecommendedAction 'Make sure the audit account can read applications (Application.Read.All), fix the error shown, and run the enterpriseapps check again.' `
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
    $roleValueByResource = @{}
    foreach ($resourceSp in $servicePrincipals) {
        $resourceId = [string](Get-EAApplicationCheckValue $resourceSp 'id')
        if ($resourceId) { $resourceById[$resourceId] = $resourceSp }
    }
    $delegatedGrantsKnown = $true
    $delegatedGrants = @()
    try {
        # Reuse the run-wide grant cache of the main script (shared with consentgrants)
        # when it exists; it throws on a failed read, which lands in the catch below.
        # Otherwise read the list here. This list API documents $filter but not $top;
        # follow its nextLink rather than sending an unsupported page-size option.
        if (Get-Command -Name 'Get-EAOAuth2Grants' -CommandType Function -ErrorAction Ignore) {
            $delegatedGrants = @(Get-EAOAuth2Grants)
        } else {
            $delegatedGrants = @(Get-EAReadOnlyGraphCollection -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants')
        }
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
    # Each per-app read type stops on its own after an access-denied error or a run of
    # throttled reads (Get-EAApplicationCheckStopReason). Every app that is then not read
    # is counted and reported as a coverage gap, never as "nothing found".
    $ownerStopReason = $null; $assignmentStopReason = $null; $permissionStopReason = $null
    $ownerThrottleRun = 0; $assignmentThrottleRun = 0; $permissionThrottleRun = 0
    $ownerNotRead = 0; $assignmentNotRead = 0; $permissionNotRead = 0
    $managedIdentityAssignmentSkips = 0

    foreach ($sp in $candidates) {
        $spId = [string](Get-EAApplicationCheckValue $sp 'id')
        $appId = [string](Get-EAApplicationCheckValue $sp 'appId')
        $name = [string](Get-EAApplicationCheckValue $sp 'displayName')
        $servicePrincipalType = [string](Get-EAApplicationCheckValue $sp 'servicePrincipalType')
        $ownerTenant = [string](Get-EAApplicationCheckValue $sp 'appOwnerOrganizationId')
        # Graph sets appOwnerOrganizationId only on service principals that have an app
        # registration. Managed identities and agent identities (ServiceIdentity) have none,
        # so the owner-tenant rules (third party, not used) do not apply to them, and a
        # Legacy service principal can only be used in the tenant that created it. Only an
        # Application principal without the value is an unknown owner tenant.
        $ownerClass = if ($servicePrincipalType -in @('ManagedIdentity','ServiceIdentity')) { 'NotApplicable (no app registration)' } `
            elseif ($servicePrincipalType -eq 'Legacy' -and -not $ownerTenant) { 'TenantOwned' } `
            elseif ($ownerTenant -and $tenantId -and $ownerTenant -eq $tenantId) { 'TenantOwned' } `
            elseif (-not $tenantId) { 'OwnerTenantUnknown' } `
            elseif ($ownerTenant) { 'ThirdParty' } else { 'OwnerTenantUnknown' }

        $ownersKnown = $ownersExpanded
        # @(if ...) keeps a one-owner list an array; assigning the if statement directly
        # unrolls it to the owner object, whose Count is its number of fields.
        $owners = @(if ($ownersExpanded) { (Get-EAApplicationCheckValue $sp 'owners') | Where-Object { $_ } })
        if (-not $ownersExpanded) {
            if ($ownerStopReason) {
                $ownerNotRead++
            } else {
                try {
                    $ownerUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + [uri]::EscapeDataString($spId) + '/owners?$select=id,displayName,userPrincipalName,userType'
                    $owners = @(Get-EAReadOnlyGraphCollection -Uri $ownerUri -MaximumPages 50)
                    $ownersKnown = $true
                    $ownerThrottleRun = 0
                } catch {
                    $ownerErrors.Add([pscustomobject]@{ EnterpriseApplication=$name; ObjectId=$spId; StatusCode=(Get-EAApplicationCheckHttpStatus $_); Error=$_.Exception.Message }) | Out-Null
                    $ownerStopReason = Get-EAApplicationCheckStopReason -ErrorRecord $_ -ThrottleRun ([ref]$ownerThrottleRun)
                }
            }
        }

        # User and group assignments (appRoleAssignedTo). A managed identity is an Azure
        # resource's own identity, not an app that people sign in to, so it has no user or
        # group assignments to review; skipping that read saves one Graph request per
        # managed identity. Its row says NotApplicable, not Known.
        $userAssignments = 0
        $groupAssignments = 0
        $otherAssignments = 0
        $assignmentsKnown = $false
        $assignmentReadState = 'Unknown'
        if ($servicePrincipalType -eq 'ManagedIdentity') {
            $assignmentReadState = 'NotApplicable (managed identity)'
            $managedIdentityAssignmentSkips++
        } elseif ($assignmentStopReason) {
            $assignmentNotRead++
        } else {
            try {
                $assignmentUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + [uri]::EscapeDataString($spId) + '/appRoleAssignedTo?$select=id,principalId,principalDisplayName,principalType,appRoleId,createdDateTime'
                $assignments = @(Get-EAReadOnlyGraphCollection -Uri $assignmentUri -MaximumPages 100)
                $assignmentsKnown = $true
                $assignmentReadState = 'Known'
                $assignmentThrottleRun = 0
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
                $assignmentErrors.Add([pscustomobject]@{ EnterpriseApplication=$name; ObjectId=$spId; StatusCode=(Get-EAApplicationCheckHttpStatus $_); Error=$_.Exception.Message }) | Out-Null
                $assignmentStopReason = Get-EAApplicationCheckStopReason -ErrorRecord $_ -ThrottleRun ([ref]$assignmentThrottleRun)
            }
        }

        # appRoleAssignments are permissions HELD by this client service principal
        # (managed identities included: they are often granted Graph permissions).
        # Resolve every appRoleId against the actual resource service principal so the
        # report carries names rather than GUIDs and can classify new/custom permissions.
        if ($permissionStopReason) {
            $permissionNotRead++
        } else {
            try {
                $permissionUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + [uri]::EscapeDataString($spId) + '/appRoleAssignments?$select=id,resourceId,resourceDisplayName,appRoleId,createdDateTime'
                foreach ($grant in @(Get-EAReadOnlyGraphCollection -Uri $permissionUri -MaximumPages 100)) {
                    $resourceId = [string](Get-EAApplicationCheckValue $grant 'resourceId')
                    $appRoleId = [string](Get-EAApplicationCheckValue $grant 'appRoleId')
                    $resource = if ($resourceById.ContainsKey($resourceId)) { $resourceById[$resourceId] } else { $null }
                    $permissionValue = $null
                    if ($resource) {
                        # Index each resource's appRoles once (Microsoft Graph alone defines
                        # hundreds) instead of scanning them for every grant.
                        if (-not $roleValueByResource.ContainsKey($resourceId)) {
                            $roleMap = @{}
                            foreach ($role in @(Get-EAApplicationCheckElement $resource 'appRoles')) {
                                $roleId = [string](Get-EAApplicationCheckValue $role 'id')
                                if ($roleId) { $roleMap[$roleId] = [string](Get-EAApplicationCheckValue $role 'value') }
                            }
                            $roleValueByResource[$resourceId] = $roleMap
                        }
                        $roleMap = $roleValueByResource[$resourceId]
                        if ($roleMap.ContainsKey($appRoleId)) { $permissionValue = $roleMap[$appRoleId] }
                    }
                    $resourceName = [string](@(
                        Get-EAApplicationCheckValue $grant 'resourceDisplayName'
                        Get-EAApplicationCheckValue $resource 'displayName'
                        $resourceId
                    ) | Where-Object { $_ } | Select-Object -First 1)
                    $risk = Get-EAApplicationPermissionRisk -PermissionValue $permissionValue -ResourceName $resourceName
                    if (-not $permissionValue -and $appRoleId -eq '00000000-0000-0000-0000-000000000000') {
                        # Graph's documented default app role: the principal is assigned to
                        # the resource app without any specific app role or permission.
                        $permissionValue = '(default access)'
                        $risk = [pscustomobject]@{ Risk='Other'; Reason='Default access to the resource app (no specific app role or permission).' }
                    } elseif ($risk.Risk -eq 'Unknown') {
                        $risk.Reason = if (-not $resource) { 'The resource service principal is not in the readable inventory, so the granted appRoleId could not be resolved.' } `
                            else { 'The granted appRoleId is not defined in the resource service principal appRoles, so it could not be resolved to a permission value.' }
                    }
                    $permissionRows.Add([pscustomobject]@{
                        EnterpriseApplication=$name; ServicePrincipalId=$spId; AppId=$appId; ServicePrincipalType=$servicePrincipalType
                        GrantType='Application'; ConsentType='Application'; PrincipalId=''
                        Permission=$permissionValue; AppRoleId=$appRoleId; Resource=$resourceName; ResourceId=$resourceId
                        Risk=$risk.Risk; RiskReason=$risk.Reason
                        GrantedDateTime=ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $grant 'createdDateTime')
                        ReportedUnder=''
                    }) | Out-Null
                }
                $permissionThrottleRun = 0
            } catch {
                $permissionErrors.Add([pscustomobject]@{ EnterpriseApplication=$name; ObjectId=$spId; StatusCode=(Get-EAApplicationCheckHttpStatus $_); Error=$_.Exception.Message }) | Out-Null
                $permissionStopReason = Get-EAApplicationCheckStopReason -ErrorRecord $_ -ThrottleRun ([ref]$permissionThrottleRun)
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
        $hasCredentials = (@(Get-EAApplicationCheckElement $sp 'passwordCredentials').Count + @(Get-EAApplicationCheckElement $sp 'keyCredentials').Count) -gt 0
        $governanceRows.Add([pscustomobject]@{
            EnterpriseApplication=$name; ObjectId=$spId; AppId=$appId; ServicePrincipalType=$servicePrincipalType; OwnerClass=$ownerClass
            EnabledState=if ($null -eq $enabledState) { 'Unknown' } else { 'Known' }
            Enabled=$enabledState
            OwnerReadState=if ($ownersKnown) { 'Known' } else { 'Unknown' }
            OwnerCount=if ($ownersKnown) { @($owners).Count } else { $null }
            Owners=if ($ownersKnown) { (@($owners | ForEach-Object {
                [string](@(Get-EAApplicationCheckValue $_ 'userPrincipalName'; Get-EAApplicationCheckValue $_ 'displayName'; Get-EAApplicationCheckValue $_ 'id') | Where-Object { $_ } | Select-Object -First 1)
            }) -join ', ') } else { '' }
            AssignmentRequirementState=if ($assignmentRequiredKnown) { 'Known' } else { 'Unknown' }
            AppRoleAssignmentRequired=if ($assignmentRequiredKnown) { [bool]$assignmentRequiredValue } else { $null }
            AssignmentReadState=$assignmentReadState
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
            $consentType = [string](Get-EAApplicationCheckValue $grant 'consentType')
            foreach ($scope in $scopes) {
                $risk = Get-EAApplicationPermissionRisk -PermissionValue $scope -ResourceName $resourceName -GrantType Delegated -ConsentType $consentType
                $permissionRows.Add([pscustomobject]@{
                    EnterpriseApplication=$client.EnterpriseApplication; ServicePrincipalId=$clientId; AppId=$client.AppId; ServicePrincipalType=$client.ServicePrincipalType
                    GrantType='Delegated'; ConsentType=$consentType
                    PrincipalId=[string](Get-EAApplicationCheckValue $grant 'principalId')
                    Permission=$scope; AppRoleId=''; Resource=$resourceName; ResourceId=$resourceId
                    Risk=$risk.Risk; RiskReason=$risk.Reason
                    GrantedDateTime=$null
                    ReportedUnder=''
                }) | Out-Null
            }
        }
    }

    # The apps check (application permissions, over-privileged apps without an owner) and
    # the consentgrants check (delegated grants) run earlier and inspect the same grants.
    # A grant or missing owner they already reported at the same or a higher severity is
    # kept in the evidence (ReportedUnder column) but not scored a second time here.
    $appsIndex = Get-EAReportedElsewhereIndex -CheckId 'apps' -KeySelector {
        param($row)
        $spId = [string](Get-EAApplicationCheckValue $row 'SpId')
        $permission = [string](Get-EAApplicationCheckValue $row 'Permission')
        if ($spId -and $permission) { "permission|$spId|$permission" }
        $ownerCount = Get-EAApplicationCheckValue $row 'OwnerCount'
        $ownerAppId = [string](Get-EAApplicationCheckValue $row 'AppId')
        if ($null -ne $ownerCount -and [string]$ownerCount -eq '0' -and $ownerAppId) { "owner|$ownerAppId" }
    }
    # Only the scopes consentgrants itself rated high-impact (its HighImpactScopes column)
    # count as reported there: it reports every grant that holds one of them, for every
    # user, so a per-user grant of such a scope to the same app is always in its list. The
    # other scopes of the same grant string (for example Calendars.Read next to Mail.Read)
    # were never reported by it, and other users' grants of those scopes must still be
    # rated here. Clients are keyed by service-principal object id (ClientId).
    $consentIndex = Get-EAReportedElsewhereIndex -CheckId 'consentgrants' -KeySelector {
        param($row)
        $client = [string](Get-EAApplicationCheckValue $row 'ClientId')
        if (-not $client) { $client = [string](Get-EAApplicationCheckValue $row 'Client') }
        $resource = [string](Get-EAApplicationCheckValue $row 'Resource')
        $grantConsentType = [string](Get-EAApplicationCheckValue $row 'ConsentType')
        foreach ($grantScope in @([string](Get-EAApplicationCheckValue $row 'HighImpactScopes') -split '\s+' | Where-Object { $_ })) {
            if ($client) { "grant|$client|$resource|$grantConsentType|$grantScope" }
        }
    }
    $ownSeverityRank = @{ Tier0=4; WriteHigh=3; HighImpactRead=3; UserDelegatedSensitive=2 }
    # Older consentgrants rows without ClientId name clients by display name; a name shared
    # by two apps is ambiguous, so such apps are matched only by object id.
    $clientNameCount = @{}
    foreach ($governanceRow in $governanceRows) {
        $clientName = [string]$governanceRow.EnterpriseApplication
        if ($clientName) { $clientNameCount[$clientName] = 1 + [int]$clientNameCount[$clientName] }
    }
    foreach ($permissionRow in $permissionRows) {
        $neededRank = $ownSeverityRank[[string]$permissionRow.Risk]
        if (-not $neededRank) { continue }
        if ($permissionRow.GrantType -eq 'Application') {
            $key = ("permission|{0}|{1}" -f $permissionRow.ServicePrincipalId, $permissionRow.Permission).ToLowerInvariant()
            if ($appsIndex.ContainsKey($key) -and $appsIndex[$key] -ge $neededRank) { $permissionRow.ReportedUnder = 'apps' }
            continue
        }
        $clientKeys = @($permissionRow.ServicePrincipalId)
        if ($clientNameCount[[string]$permissionRow.EnterpriseApplication] -eq 1) { $clientKeys += $permissionRow.EnterpriseApplication }
        foreach ($clientKey in $clientKeys) {
            foreach ($resourceKey in @($permissionRow.Resource, $permissionRow.ResourceId)) {
                $key = ("grant|{0}|{1}|{2}|{3}" -f $clientKey, $resourceKey, $permissionRow.ConsentType, $permissionRow.Permission).ToLowerInvariant()
                if ($consentIndex.ContainsKey($key) -and $consentIndex[$key] -ge $neededRank) { $permissionRow.ReportedUnder = 'consentgrants' }
            }
        }
    }

    $rows = @($governanceRows.ToArray())

    # Apps registered in this tenant (by Graph, the CLI or Terraform) usually have their
    # owner on the app registration and none on the enterprise app. The registration owner
    # is the one who renews credentials and removes the app, and the apps check counts
    # registration owners too, so both lists count here. Third-party apps have no app
    # registration in this tenant; managed identities have none at all. A failed read of
    # the registrations is a coverage gap for the apps it matters to, never "no owner".
    $ownerRuleTypes = @('Application','Legacy','')
    $registrationOwnersKnown = $true
    $registrationOwnersError = $null
    $registrationOwnersByAppId = @{}
    if (@($rows | Where-Object { $_.OwnerClass -ne 'ThirdParty' -and $_.ServicePrincipalType -in $ownerRuleTypes }).Count -gt 0) {
        try {
            # Reuse the run-wide application cache of the main script (owners expanded)
            # when it exists; otherwise read the registrations here.
            $registrations = @(if (Get-Command -Name 'Get-EAApplications' -CommandType Function -ErrorAction Ignore) { Get-EAApplications } `
                else { Get-EAReadOnlyGraphCollection -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId&$expand=owners($select=id)&$top=100' })
            foreach ($registration in $registrations) {
                $registrationAppId = [string](Get-EAApplicationCheckValue $registration 'appId')
                if ($registrationAppId) {
                    $registrationOwnersByAppId[$registrationAppId.ToLowerInvariant()] = @((Get-EAApplicationCheckValue $registration 'owners') | Where-Object { $_ }).Count
                }
            }
        } catch {
            $registrationOwnersKnown = $false
            $registrationOwnersError = $_.Exception.Message
        }
    }
    $registrationOwnerGapCount = 0
    foreach ($row in $rows) {
        $registrationApplies = ($row.OwnerClass -ne 'ThirdParty' -and $row.ServicePrincipalType -in $ownerRuleTypes)
        $registrationOwnerCount = $null
        if ($registrationApplies -and $registrationOwnersKnown) {
            $registrationKey = ([string]$row.AppId).ToLowerInvariant()
            # Not in the list: no app registration in this tenant, so no registration owner.
            $registrationOwnerCount = if ($registrationKey -and $registrationOwnersByAppId.ContainsKey($registrationKey)) { [int]$registrationOwnersByAppId[$registrationKey] } else { 0 }
        }
        $effectiveOwnerCount = if ($null -eq $row.OwnerCount) { $null } `
            elseif (-not $registrationApplies) { $row.OwnerCount } `
            elseif ($null -eq $registrationOwnerCount) { $null } `
            else { $row.OwnerCount + $registrationOwnerCount }
        $row | Add-Member -NotePropertyName RegistrationOwnerCount -NotePropertyValue $registrationOwnerCount -Force
        $row | Add-Member -NotePropertyName EffectiveOwnerCount -NotePropertyValue $effectiveOwnerCount -Force
        if ($registrationApplies -and -not $registrationOwnersKnown -and $row.Enabled -and $row.OwnerReadState -eq 'Known' -and $row.OwnerCount -eq 0) {
            $registrationOwnerGapCount++
        }
    }

    $source = Write-Evidence -BaseName 'enterprise_app_governance' -Rows $rows -Title 'Enterprise Application Governance' `
        -Notes @(
            ("Excluded Microsoft first-party owner tenants and SocialIdp objects; reviewed {0}." -f (Format-EAApplicationCheckCount -Count $rows.Count -One 'tenant-owned, third-party, managed, or owner-tenant-unknown workload service principal' -Many 'tenant-owned, third-party, managed, or owner-tenant-unknown workload service principals')),
            ("AssignmentReadState = NotApplicable (managed identity): {0}" -f (Format-EAApplicationCheckCount -Count $managedIdentityAssignmentSkips -One 'managed identity is an Azure resource identity, not an app that people sign in to, so its user and group assignments were not read. Its granted permissions were read.' -Many 'managed identities are Azure resource identities, not apps that people sign in to, so their user and group assignments were not read. Their granted permissions were read.')),
            'OwnerClass = NotApplicable (no app registration): managed identities and agent identities have no app registration and therefore no owner tenant, so the third-party and unused-app rules do not apply to them. A Legacy service principal can only be used in the tenant that created it, so it counts as tenant-owned.',
            'EffectiveOwnerCount = enterprise-app owners (OwnerCount) plus, for apps registered in this tenant, the owners of the app registration (RegistrationOwnerCount), the same way the apps check counts owners. RegistrationOwnerCount is empty for third-party apps and managed identities, and EffectiveOwnerCount is empty when an owner list could not be read.',
            'NoRecordedActivity-UnknownUse is deliberately not treated as proof that an app is unused.'
        )
    $assignmentSource = Write-Evidence -BaseName 'enterprise_app_assignments' -Rows @($assignmentRows.ToArray()) -Title 'Enterprise Application User and Group Assignments'
    $permissionSource = Write-Evidence -BaseName 'enterprise_app_granted_permissions' -Rows @($permissionRows.ToArray()) `
        -Title 'Enterprise Application Granted Application and Delegated Permissions' `
        -Notes @(
            'Application permission names are resolved from each resource service principal app-role definition; delegated grants use their actual scope strings. Unresolved app-role IDs remain an explicit coverage gap.',
            'Application permissions on the apps check''s top-risk list (tenant takeover, all mail, all files) are rated Tier0 here as well, so both checks rate them the same.',
            'ReportedUnder = apps or consentgrants: the same grant was already reported by that check at the same or a higher severity; it is listed here but not counted again.'
        )

    $coverageRows = @()
    if (-not $ownersExpanded) { $coverageRows += @($ownerErrors.ToArray()) }
    if ($ownerNotRead -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=('Remaining ' + (Format-EAApplicationCheckCount -Count $ownerNotRead -One 'enterprise application' -Many 'enterprise applications')); ObjectId=''; StatusCode=''; Error=("Owners not read: owner reads stopped because {0}." -f $ownerStopReason) } }
    if ($registrationOwnerGapCount -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=(Format-EAApplicationCheckCount -Count $registrationOwnerGapCount -One 'enabled enterprise application without an enterprise-app owner' -Many 'enabled enterprise applications without an enterprise-app owner'); ObjectId=''; StatusCode=''; Error=("App-registration owners not read, so it is unknown whether these apps have an owner on their app registration: {0}" -f $registrationOwnersError) } }
    $coverageRows += @($assignmentErrors.ToArray())
    if ($assignmentNotRead -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=('Remaining ' + (Format-EAApplicationCheckCount -Count $assignmentNotRead -One 'enterprise application' -Many 'enterprise applications')); ObjectId=''; StatusCode=''; Error=("User and group assignments not read: assignment reads stopped because {0}." -f $assignmentStopReason) } }
    $coverageRows += @($permissionErrors.ToArray())
    if ($permissionNotRead -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=('Remaining ' + (Format-EAApplicationCheckCount -Count $permissionNotRead -One 'enterprise application' -Many 'enterprise applications')); ObjectId=''; StatusCode=''; Error=("Granted permissions not read: permission reads stopped because {0}." -f $permissionStopReason) } }
    if (-not $delegatedGrantsKnown) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='All reviewed enterprise applications'; ObjectId=''; StatusCode=''; Error=("Delegated OAuth grant inventory unavailable: {0}" -f $delegatedGrantError) } }
    $unresolvedPermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'Unknown' })
    if ($unresolvedPermissions.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=(Format-EAApplicationCheckCount -Count $unresolvedPermissions.Count -One 'grant' -Many 'grants'); ObjectId=''; StatusCode=''; Error='Granted appRoleId could not be resolved to a permission value.' } }
    if (-not $activity.Known) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='All non-Microsoft enterprise applications'; ObjectId=''; StatusCode=''; Error=("Service-principal sign-in activity unavailable: {0}" -f $activity.Error) } }
    if (-not $tenantId) { $coverageRows += [pscustomobject]@{ EnterpriseApplication='All reviewed enterprise applications'; ObjectId=''; StatusCode=''; Error='The Graph tenant id was unavailable, so tenant-owned versus third-party classification is unknown.' } }
    # Only an app-registration-backed principal is expected to carry appOwnerOrganizationId
    # (managed identities, agent identities and Legacy principals never do). Without the
    # tenant id every row is unknown, and the row above already says why.
    $unknownOwnerTenant = @(if ($tenantId) {
        $rows | Where-Object { $_.OwnerClass -eq 'OwnerTenantUnknown' -and $_.ServicePrincipalType -notin @('ManagedIdentity','ServiceIdentity','Legacy') }
    })
    if ($unknownOwnerTenant.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=(Format-EAApplicationCheckCount -Count $unknownOwnerTenant.Count -One 'application' -Many 'applications'); ObjectId=''; StatusCode=''; Error='appOwnerOrganizationId was not returned, so tenant-owned versus third-party lifecycle rules could not be applied.' } }
    $unknownEnabled = @($rows | Where-Object { $_.EnabledState -eq 'Unknown' })
    if ($unknownEnabled.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=(Format-EAApplicationCheckCount -Count $unknownEnabled.Count -One 'application' -Many 'applications'); ObjectId=''; StatusCode=''; Error='accountEnabled was not returned or was not a recognized boolean value.' } }
    $unknownRequirement = @($rows | Where-Object { $_.AssignmentRequirementState -eq 'Unknown' })
    if ($unknownRequirement.Count -gt 0) { $coverageRows += [pscustomobject]@{ EnterpriseApplication=(Format-EAApplicationCheckCount -Count $unknownRequirement.Count -One 'application' -Many 'applications'); ObjectId=''; StatusCode=''; Error='appRoleAssignmentRequired was not returned.' } }
    if ($coverageRows.Count -gt 0) {
        $gapKinds = @()
        if ($ownerErrors.Count -gt 0 -or $ownerNotRead -gt 0 -or $registrationOwnerGapCount -gt 0) { $gapKinds += 'owners' }
        if ($assignmentErrors.Count -gt 0 -or $assignmentNotRead -gt 0) { $gapKinds += 'user and group assignments' }
        if ($permissionErrors.Count -gt 0 -or $permissionNotRead -gt 0 -or -not $delegatedGrantsKnown -or $unresolvedPermissions.Count -gt 0) { $gapKinds += 'granted permissions' }
        if (-not $activity.Known) { $gapKinds += 'sign-in activity' }
        if (-not $tenantId -or $unknownOwnerTenant.Count -gt 0 -or $unknownEnabled.Count -gt 0 -or $unknownRequirement.Count -gt 0) { $gapKinds += 'app properties' }
        $stopText = @(
            if ($ownerStopReason) { "owner reads stopped because $ownerStopReason" }
            if ($assignmentStopReason) { "assignment reads stopped because $assignmentStopReason" }
            if ($permissionStopReason) { "permission reads stopped because $permissionStopReason" }
        ) -join '; '
        $coverageSource = Write-Evidence -BaseName 'enterprise_app_governance_gaps' -Rows $coverageRows -Title 'Enterprise Application Governance Coverage Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Some enterprise app details could not be read, so app findings may be incomplete' `
            -Evidence ("{0} recorded in: {1}.{2} Apps with a gap are not counted as clean." -f (Format-EAApplicationCheckCount -Count $coverageRows.Count -One 'gap' -Many 'gaps'), ($gapKinds -join ', '), $(if ($stopText) { " Reads were cut short: $stopText." } else { '' })) `
            -WhyItMatters 'Apps whose owners, assignments, permissions or sign-in activity could not be read were not fully checked, so some ownerless, over-permissioned or unused apps may be missing from this report.' `
            -RecommendedAction 'Check the gaps file for the exact errors. Usually: give the audit account Application.Read.All, Directory.Read.All and AuditLog.Read.All, confirm an Entra ID P1 license for sign-in activity, wait for throttling to clear, then run the enterpriseapps check again.' `
            -SourceFile $coverageSource -ResultRows $coverageRows -RuleId 'enterprise-app-governance-coverage-unknown' -ObjectType 'tenant' -CoverageGap
    }

    # EffectiveOwnerCount is empty (never 0) when an owner list could not be read, so such
    # apps are a coverage gap above, not "no owner".
    $ownerlessAll = @($rows | Where-Object {
        $_.Enabled -and $_.ServicePrincipalType -in $ownerRuleTypes -and $_.OwnerReadState -eq 'Known' -and $_.EffectiveOwnerCount -eq 0
    })
    # The apps check reports high-permission apps without an owner as Critical.
    $ownerlessReportedElsewhere = @($ownerlessAll | Where-Object { $_.AppId -and $appsIndex.ContainsKey(("owner|{0}" -f $_.AppId).ToLowerInvariant()) })
    $ownerless = @($ownerlessAll | Where-Object { $_ -notin $ownerlessReportedElsewhere })
    if ($ownerless.Count -gt 0) {
        # "Reported by the apps check instead" is only true when that check ran to the end in
        # this run (it runs before this one); otherwise high-permission apps without an owner
        # are listed here and nowhere else.
        $appsStatus = $null
        $checkStatusVariable = Get-Variable -Name CheckStatus -Scope Script -ErrorAction SilentlyContinue
        if ($checkStatusVariable -and $checkStatusVariable.Value -is [System.Collections.IDictionary] -and $checkStatusVariable.Value.Contains('apps')) {
            $appsStatus = [string](Get-EAApplicationCheckValue $checkStatusVariable.Value['apps'] 'Status')
        }
        $appsCheckCompleted = ($appsStatus -and $appsStatus -notlike 'Skipped*' -and $appsStatus -ne 'Error')
        $ownerlessNotes = @()
        if ($ownerlessReportedElsewhere.Count -gt 0) {
            $ownerlessNotes += (Format-EAApplicationCheckCount -Count $ownerlessReportedElsewhere.Count `
                -One 'other app without an owner also holds high-risk permissions and is' `
                -Many 'other apps without an owner also hold high-risk permissions and are') +
                " reported by the apps check (-apps) as Critical instead (listed in this check's 'already reported by another check' note)."
        } elseif ($appsCheckCompleted) {
            $ownerlessNotes += 'Apps that also hold high-risk permissions are reported by the apps check (-apps) as Critical instead.'
        }
        if (-not $appsCheckCompleted) {
            $ownerlessNotes += 'Run the apps check (-apps) to see which of these also hold high-risk permissions (reported there as Critical).'
        }
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $ownerless.Count -One 'enabled enterprise app has no owner' -Many 'enabled enterprise apps have no owner') `
            -Evidence ("Enabled apps with no owner: {0}. Neither the enterprise app nor, for apps registered in this tenant, the app registration has an owner. {1}" -f (Format-EAApplicationCheckList @($ownerless.EnterpriseApplication)), ($ownerlessNotes -join ' ')) `
            -WhyItMatters 'Without a named owner, nobody is responsible for reviewing who can use the app, renewing or removing its credentials, or deleting it when it is no longer needed.' `
            -RecommendedAction 'Assign at least one owner to each app and record what the app is for, or remove apps that are no longer used. For an app registered in this tenant, add the owner in Entra admin center > App registrations > app > Owners; for other apps, in Enterprise applications > app > Owners.' `
            -SourceFile $source -ResultRows $ownerless -RuleId 'enterprise-app-ownerless' -ObjectType 'servicePrincipal'
    }

    $unrestricted = @($rows | Where-Object {
        $_.Enabled -and $_.ServicePrincipalType -in @('Application','Legacy','') -and $_.OwnerClass -eq 'ThirdParty' -and
        $_.AssignmentRequirementState -eq 'Known' -and -not $_.AppRoleAssignmentRequired
    })
    if ($unrestricted.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $unrestricted.Count -One 'third-party app' -Many 'third-party apps') + ' can be used by every user because assignment is not required') `
            -Evidence ("'Assignment required' is off (appRoleAssignmentRequired = false) for: {0}." -f (Format-EAApplicationCheckList @($unrestricted.EnterpriseApplication))) `
            -WhyItMatters 'When assignment is not required, every user in the tenant can sign in to the app, not only the people who need it.' `
            -RecommendedAction ("For apps that only some people should use, turn on 'Assignment required?' ({0} > Properties) and assign the right users or groups. Apps that are not used for user sign-in can be left as they are." -f $appPortalPath) `
            -SourceFile $source -ResultRows $unrestricted -RuleId 'enterprise-app-assignment-not-required' -ObjectType 'servicePrincipal'
    }

    $groupAssigned = @($rows | Where-Object { $_.Enabled -and $_.AssignmentReadState -eq 'Known' -and $_.GroupAssignments -gt 0 })
    if ($groupAssigned.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $groupAssigned.Count -One 'enterprise app gives access through group membership' -Many 'enterprise apps give access through group membership') `
            -Evidence ("{0} on: {1}." -f (Format-EAApplicationCheckCount -Count (($groupAssigned | Measure-Object GroupAssignments -Sum).Sum) -One 'group assignment' -Many 'group assignments'), (Format-EAApplicationCheckList @($groupAssigned.EnterpriseApplication))) `
            -WhyItMatters 'Everyone in an assigned group, including members of nested groups, gets access to the app. Access can grow quietly as people are added to the group.' `
            -RecommendedAction ("Review the owners and members of each assigned group ({0} > Users and groups), and set up recurring access reviews for them where your license allows." -f $appPortalPath) `
            -SourceFile $assignmentSource -ResultRows @($assignmentRows.ToArray() | Where-Object { $_.PrincipalType -eq 'Group' }) -RuleId 'enterprise-app-group-assignment' -ObjectType 'servicePrincipal'
    }

    $tier0Permissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'Tier0' -and -not $_.ReportedUnder })
    $writePermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'WriteHigh' -and -not $_.ReportedUnder })
    $highReadPermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'HighImpactRead' -and -not $_.ReportedUnder })
    $userDelegatedPermissions = @($permissionRows.ToArray() | Where-Object { $_.Risk -eq 'UserDelegatedSensitive' -and -not $_.ReportedUnder })
    $permissionSummary = {
        param([object[]]$PermissionList)
        Format-EAApplicationCheckList @($PermissionList | Group-Object Permission | Sort-Object Count -Descending | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count })
    }
    if ($tier0Permissions.Count -gt 0) {
        Add-EntraFinding -Severity 'Critical' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $tier0Permissions.Count -One 'app permission allows' -Many 'app permissions allow') + ' tenant takeover or full access to all mail or files') `
            -Evidence ("Apps: {0}. Permissions (number of grants): {1}." -f (Format-EAApplicationCheckList @($tier0Permissions.EnterpriseApplication)), (& $permissionSummary $tier0Permissions)) `
            -WhyItMatters 'These permissions let an app take over the tenant (for example by making itself a Global Administrator) or read all mail or files. Anyone who steals the app''s secret, or controls a user who has signed in to the app, can do the same.' `
            -RecommendedAction ("Remove every one of these permissions that is not strictly needed ({0} > Permissions); replace the rest with narrower permissions, and make sure each app has a named owner and uses certificate credentials." -f $appPortalPath) `
            -SourceFile $permissionSource -ResultRows $tier0Permissions -RuleId 'enterprise-app-tier0-permission' -ObjectType 'servicePrincipal'
    }
    if ($writePermissions.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $writePermissions.Count -One 'app permission lets an app' -Many 'app permissions let apps') + ' change data, send mail or manage settings') `
            -Evidence ("Apps: {0}. Permissions (number of grants): {1}." -f (Format-EAApplicationCheckList @($writePermissions.EnterpriseApplication)), (& $permissionSummary $writePermissions)) `
            -WhyItMatters 'If the app or its secret is misused, it can change data, send mail or change settings in everything the permission covers.' `
            -RecommendedAction ("Remove write permissions the app does not need and replace broad ones with the narrowest permission that works ({0} > Permissions)." -f $appPortalPath) `
            -SourceFile $permissionSource -ResultRows $writePermissions -RuleId 'enterprise-app-write-permission' -ObjectType 'servicePrincipal'
    }
    if ($highReadPermissions.Count -gt 0) {
        Add-EntraFinding -Severity 'High' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $highReadPermissions.Count -One 'app permission lets an app' -Many 'app permissions let apps') + ' read sensitive data across the tenant') `
            -Evidence ("Read access to tenant-wide mail, files, chats, directory, audit or security data on {0}: {1}. Permissions (number of grants): {2}." -f (Format-EAApplicationCheckCount -Count (@($highReadPermissions.EnterpriseApplication | Select-Object -Unique).Count) -One 'app' -Many 'apps'),
                (Format-EAApplicationCheckList @($highReadPermissions.EnterpriseApplication)), (& $permissionSummary $highReadPermissions)) `
            -WhyItMatters 'Read-only access to all mail, files, chats or directory and security data is enough for large-scale data theft if the app or its secret is misused.' `
            -RecommendedAction ("Confirm each permission is really needed and remove the rest ({0} > Permissions); where the API supports it, limit access to specific mailboxes or sites." -f $appPortalPath) `
            -SourceFile $permissionSource -ResultRows $highReadPermissions -RuleId 'enterprise-app-high-impact-read' -ObjectType 'servicePrincipal'
    }
    if ($userDelegatedPermissions.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $userDelegatedPermissions.Count -One 'app permission granted by a single user gives' -Many 'app permissions granted by single users give') + ' access to their mail, files or data') `
            -Evidence ("{0} (usually because that user accepted a consent prompt): {1}. Each app can act only as that user, not for the whole tenant." -f (Format-EAApplicationCheckCount -Count (@($userDelegatedPermissions.EnterpriseApplication | Select-Object -Unique).Count) -One 'app holds these permissions for one specific user' -Many 'apps hold these permissions for one specific user each'),
                (Format-EAApplicationCheckList @($userDelegatedPermissions.EnterpriseApplication))) `
            -WhyItMatters 'Attackers trick users into accepting a malicious app (consent phishing). The app then keeps access to that user''s mail, files, or data until the permission is removed.' `
            -RecommendedAction ("Check each app in the evidence list ({0} > Permissions > User consent). Remove permissions for apps you do not recognise or no longer need, and limit user consent to verified publishers and low-risk permissions." -f $appPortalPath) `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions' `
            -SourceFile $permissionSource -ResultRows $userDelegatedPermissions -RuleId 'enterprise-app-user-delegated-sensitive' -ObjectType 'servicePrincipal'
    }

    if ($activity.Known) {
        $knownStale = @($rows | Where-Object { $_.Enabled -and $_.OwnerClass -eq 'ThirdParty' -and $_.ActivityState -eq 'KnownStale' })
        $noRecorded = @($rows | Where-Object {
            $_.Enabled -and $_.OwnerClass -eq 'ThirdParty' -and $_.ActivityState -eq 'NoRecordedActivity-UnknownUse' -and
            ((-not $_.CreatedDateTime) -or $_.CreatedDateTime -lt $cutoff)
        })
        if ($knownStale.Count -gt 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title ((Format-EAApplicationCheckCount -Count $knownStale.Count -One 'third-party app is still enabled but has' -Many 'third-party apps are still enabled but have') + (' not been used for over {0} days' -f $staleDays)) `
                -Evidence ("Last recorded sign-in is older than {0} days for: {1}." -f $staleDays, (Format-EAApplicationCheckList @($knownStale.EnterpriseApplication))) `
                -WhyItMatters 'An app that nobody uses still keeps its access to your data and any credentials it has. Forgotten apps are easy targets because nobody would notice if they were misused.' `
                -RecommendedAction ("Confirm with the app owner that the app is no longer needed, disable it first ({0} > Properties > 'Enabled for users to sign in?' = No), then delete it after a waiting period." -f $appPortalPath) `
                -SourceFile $source -ResultRows $knownStale -RuleId 'enterprise-app-known-stale' -ObjectType 'servicePrincipal'
        }
        if ($noRecorded.Count -gt 0) {
            Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
                -Title (Format-EAApplicationCheckCount -Count $noRecorded.Count -One 'older third-party app has no recorded sign-in, so its use is unknown' -Many 'older third-party apps have no recorded sign-in, so their use is unknown') `
                -Evidence ("The sign-in activity report was readable but had no usable timestamp for: {0}. Their use is unknown, not proven absent." -f (Format-EAApplicationCheckList @($noRecorded.EnterpriseApplication))) `
                -WhyItMatters 'These apps may never have been used or may be forgotten, but the activity report cannot prove that, so check before removing them.' `
                -RecommendedAction 'Ask the app owner whether the app is still used. If not, disable it first and delete it after a waiting period.' `
                -SourceFile $source -ResultRows $noRecorded -RuleId 'enterprise-app-no-recorded-activity' -ObjectType 'servicePrincipal' -CoverageGap
        }
    }

    $reportedElsewhere = @(
        foreach ($permissionRow in @($permissionRows.ToArray() | Where-Object { $_.ReportedUnder })) {
            [pscustomobject]@{
                EnterpriseApplication=$permissionRow.EnterpriseApplication; AppId=$permissionRow.AppId
                Item=("{0} permission {1} on {2}" -f $permissionRow.GrantType, $permissionRow.Permission, $permissionRow.Resource)
                ReportedUnder=$permissionRow.ReportedUnder
            }
        }
        foreach ($ownerlessRow in $ownerlessReportedElsewhere) {
            [pscustomobject]@{ EnterpriseApplication=$ownerlessRow.EnterpriseApplication; AppId=$ownerlessRow.AppId; Item='No owner'; ReportedUnder='apps' }
        }
    )
    if ($reportedElsewhere.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title ((Format-EAApplicationCheckCount -Count $reportedElsewhere.Count -One 'enterprise app issue is' -Many 'enterprise app issues are') + ' already reported by another check') `
            -Evidence ("These permissions or missing owners were already reported by the {0} at the same or a higher severity. They are listed here for completeness but not counted twice." -f $(
                $otherChecks = @($reportedElsewhere.ReportedUnder | Select-Object -Unique)
                if ($otherChecks.Count -eq 1) { "$($otherChecks[0]) check" } else { "{0} checks" -f ($otherChecks -join ' and ') })) `
            -WhyItMatters 'Counting the same app permission or missing owner in two checks would show one problem twice and inflate the risk score.' `
            -RecommendedAction 'Fix these items using the findings of the check named in the ReportedUnder column; nothing extra is needed here.' `
            -SourceFile $permissionSource -ResultRows $reportedElsewhere -RuleId 'enterprise-app-reported-elsewhere' -ObjectType 'tenant'
    }

    $riskFindings = @($script:Findings | Where-Object { $_.CheckId -eq $checkId -and $_.Severity -ne 'Information' })
    if ($riskFindings.Count -eq 0 -and $reportedElsewhere.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'No problems found with enterprise app ownership, access or activity' `
            -Evidence ("{0}, {1}, and {2} were inventoried." -f (Format-EAApplicationCheckCount -Count $rows.Count -One 'non-Microsoft enterprise application' -Many 'non-Microsoft enterprise applications'), (Format-EAApplicationCheckCount -Count $assignmentRows.Count -One 'direct access assignment' -Many 'direct access assignments'), (Format-EAApplicationCheckCount -Count $permissionRows.Count -One 'granted application/delegated permission entry' -Many 'granted application/delegated permission entries')) `
            -WhyItMatters 'Apps with a named owner, limited access and regular clean-up give attackers fewer forgotten ways into your data.' `
            -RecommendedAction 'Keep asking app owners to confirm their apps regularly, review access, and remove apps that are no longer used.' `
            -SourceFile $source -ResultRows $rows -RuleId 'enterpriseapps-reviewed' -ObjectType 'tenant'
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
    # $ObjectIdLookup: account -> object with ObjectId and State (Resolved / Unresolved),
    # from Invoke-Check-Monitoring. Alert rules may name the account by object id instead
    # of its sign-in name, so the evidence shows both.
    param([string[]]$UserPrincipalNames, [System.Collections.IDictionary]$ObjectIdLookup)

    $rows = New-Object System.Collections.Generic.List[object]
    if (@($UserPrincipalNames).Count -eq 0) {
        $rows.Add([pscustomobject]@{
            EmergencyAccount='Not supplied to this run'; ObjectId=''; ObjectIdLookup='NotApplicable'
            SignInLogState='Unknown-NoAccountInput'; LatestSignIn=$null
            AlertRuleState='Unknown-CrossPlane'; Detail='Use -BreakGlassUpns so sign-in log visibility can be tested for the designated emergency accounts.'
        }) | Out-Null
        return @($rows.ToArray())
    }

    foreach ($upn in @($UserPrincipalNames)) {
        $lookup = if ($ObjectIdLookup -and $ObjectIdLookup.Contains($upn)) { $ObjectIdLookup[$upn] } else { $null }
        $objectId = if ($lookup) { [string]$lookup.ObjectId } else { '' }
        $objectIdState = if ($lookup) { [string]$lookup.State } else { 'NotLookedUp' }
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
                EmergencyAccount=$upn; ObjectId=$objectId; ObjectIdLookup=$objectIdState
                SignInLogState=if ($events.Count -gt 0) { 'Readable-RecordFound' } else { 'Readable-NoRecordInRetention' }
                LatestSignIn=$latest; AlertRuleState='Unknown-CrossPlane'
                Detail='Graph confirms whether sign-in records can be queried; it does not expose Azure Monitor alert-rule routing for this account.'
            }) | Out-Null
        } catch {
            $rows.Add([pscustomobject]@{
                EmergencyAccount=$upn; ObjectId=$objectId; ObjectIdLookup=$objectIdState
                SignInLogState='Unknown-Unreadable'; LatestSignIn=$null
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

function Get-EAAlertRuleClassifierText {
    # Returns only the fields that describe WHAT an alert rule detects: its name, display
    # name, description, scheduled-query text, and activity-log conditions. The resource
    # id, resource group, location, tags, and managed-identity block are deliberately
    # excluded so, for example, a CPU alert in "rg-identity" is not counted as an
    # identity alert.
    param([object]$Resource)

    $pairs = New-Object System.Collections.Generic.List[object]
    $add = {
        param([string]$Field, [object]$Value)
        foreach ($text in @($Value)) {
            if ($null -ne $text -and -not [string]::IsNullOrWhiteSpace([string]$text)) {
                $pairs.Add([pscustomobject]@{ Field=$Field; Text=[string]$text }) | Out-Null
            }
        }
    }
    $properties = Get-EAApplicationCheckValue $Resource 'properties'
    & $add 'name' (Get-EAApplicationCheckValue $Resource 'name')
    & $add 'displayName' (Get-EAApplicationCheckValue $properties 'displayName')
    & $add 'description' (Get-EAApplicationCheckValue $properties 'description')
    $index = 0
    foreach ($criterion in @(Get-EAApplicationCheckElement (Get-EAApplicationCheckValue $properties 'criteria') 'allOf')) {
        & $add ("criteria.allOf[{0}].query" -f $index) (Get-EAApplicationCheckValue $criterion 'query')
        # "Split by dimensions" filters (for example UserPrincipalName Include <account>)
        # narrow what the rule detects just like the query text. Excluded values describe
        # what the rule ignores, so they are not used.
        foreach ($dimension in @(Get-EAApplicationCheckElement $criterion 'dimensions')) {
            if ([string](Get-EAApplicationCheckValue $dimension 'operator') -eq 'Exclude') { continue }
            & $add ("criteria.allOf[{0}].dimensions.{1}" -f $index, [string](Get-EAApplicationCheckValue $dimension 'name')) @(Get-EAApplicationCheckElement $dimension 'values')
        }
        $index++
    }
    & $add 'source.query' (Get-EAApplicationCheckValue (Get-EAApplicationCheckValue $properties 'source') 'query')
    # Microsoft Sentinel analytics rules keep their KQL in properties.query.
    & $add 'query' (Get-EAApplicationCheckValue $properties 'query')
    $index = 0
    foreach ($condition in @(Get-EAApplicationCheckElement (Get-EAApplicationCheckValue $properties 'condition') 'allOf')) {
        $conditionName = "condition.allOf[{0}]" -f $index
        & $add "$conditionName.field" (Get-EAApplicationCheckValue $condition 'field')
        & $add "$conditionName.equals" (Get-EAApplicationCheckValue $condition 'equals')
        & $add "$conditionName.containsAny" @(Get-EAApplicationCheckElement $condition 'containsAny')
        $anyIndex = 0
        foreach ($anyCondition in @(Get-EAApplicationCheckElement $condition 'anyOf')) {
            $anyName = "$conditionName.anyOf[$anyIndex]"
            & $add "$anyName.field" (Get-EAApplicationCheckValue $anyCondition 'field')
            & $add "$anyName.equals" (Get-EAApplicationCheckValue $anyCondition 'equals')
            & $add "$anyName.containsAny" @(Get-EAApplicationCheckElement $anyCondition 'containsAny')
            $anyIndex++
        }
        $index++
    }
    return @($pairs.ToArray())
}

function Find-EAAlertRuleSignal {
    # Returns a short "field contains 'token'" explanation for the first match, or $null.
    param([object[]]$Texts, [Parameter(Mandatory)][string]$Pattern)

    foreach ($pair in @($Texts)) {
        $match = [regex]::Match([string]$pair.Text, $Pattern)
        if ($match.Success) { return ("{0} contains '{1}'" -f $pair.Field, $match.Value) }
    }
    return $null
}

function Get-EAAlertRuleIdentitySignal {
    # Decides whether an alert rule really watches Entra identity activity.
    #   Strong   - a log-search or Microsoft Sentinel rule whose query reads an Entra log
    #              table, or an activity-log alert on an Entra (microsoft.aadiam) or
    #              role-assignment / role-definition operation. Only this counts as an
    #              identity alert.
    #   Weak     - identity words only in the name, description or other conditions, for
    #              example a Service Health alert that lists "Microsoft Entra ID", a storage
    #              alert on AuthenticationType, or a CPU alert for "web role" instances.
    #              Listed as a possible identity alert, never counted.
    #   Platform - an activity-log alert on Service Health, Resource Health, Advisor
    #              recommendations, autoscale or policy events: never an identity alert.
    #   None     - nothing identity-related.
    param(
        [object]$Resource,
        [Parameter(Mandatory)][string]$Control,
        [object[]]$Texts,
        [Parameter(Mandatory)][string]$WeakPattern
    )

    if ($Control -eq 'Activity log alert') {
        $properties = Get-EAApplicationCheckValue $Resource 'properties'
        $categories = @()
        $operations = @()
        foreach ($condition in @(Get-EAApplicationCheckElement (Get-EAApplicationCheckValue $properties 'condition') 'allOf')) {
            foreach ($leaf in @(@($condition) + @(Get-EAApplicationCheckElement $condition 'anyOf'))) {
                $field = [string](Get-EAApplicationCheckValue $leaf 'field')
                $values = @(@(Get-EAApplicationCheckValue $leaf 'equals') + @(Get-EAApplicationCheckElement $leaf 'containsAny') |
                    Where-Object { $null -ne $_ -and [string]$_ } | ForEach-Object { [string]$_ })
                if ($field -eq 'category') { $categories += $values }
                elseif ($field -eq 'operationName') { $operations += $values }
            }
        }
        $platformCategory = @($categories | Where-Object { $_ -in @('ServiceHealth','ResourceHealth','Recommendation','Autoscale','Policy') }) | Select-Object -First 1
        if ($platformCategory) {
            return [pscustomobject]@{ Strength='Platform'; Match=("category is '{0}'" -f $platformCategory) }
        }
        $identityOperation = @($operations | Where-Object { $_ -match '(?i)^(microsoft\.aadiam/|microsoft\.authorization/role(assignments|definitions)/)' }) | Select-Object -First 1
        $categoryAllowsIdentity = ($categories.Count -eq 0) -or (@($categories | Where-Object { $_ -in @('Administrative','Security') }).Count -gt 0)
        if ($identityOperation -and $categoryAllowsIdentity) {
            return [pscustomobject]@{ Strength='Strong'; Match=("operationName is '{0}'" -f $identityOperation) }
        }
    } else {
        # KQL table names are case-sensitive, so this match is too.
        $entraTablePattern = '(?<!\w)(SigninLogs|AADNonInteractiveUserSignInLogs|AADServicePrincipalSignInLogs|AADManagedIdentitySignInLogs|AuditLogs|AADProvisioningLogs|AADRiskyUsers|AADUserRiskEvents|AADRiskyServicePrincipals|AADServicePrincipalRiskEvents|MicrosoftGraphActivityLogs)(?!\w)'
        $tableMatch = Find-EAAlertRuleSignal -Texts @($Texts | Where-Object { [string]$_.Field -match '(^|\.)query$' }) -Pattern $entraTablePattern
        if ($tableMatch) { return [pscustomobject]@{ Strength='Strong'; Match=$tableMatch } }
    }
    $weakMatch = Find-EAAlertRuleSignal -Texts $Texts -Pattern $WeakPattern
    if ($weakMatch) { return [pscustomobject]@{ Strength='Weak'; Match=$weakMatch } }
    return [pscustomobject]@{ Strength='None'; Match=$null }
}

function Find-EAEmergencyAlertSignal {
    # Emergency (break-glass) account match: the rule's name, description, query or
    # conditions mention "break glass" / "emergency access", an account's sign-in name, or
    # its object id. Microsoft's own sample alerts match the account by object id.
    param(
        [object[]]$Texts,
        [Parameter(Mandatory)][string]$Pattern,
        [string[]]$UserPrincipalNames,
        [string[]]$ObjectIds
    )

    $match = Find-EAAlertRuleSignal -Texts $Texts -Pattern $Pattern
    if ($match) { return $match }
    foreach ($value in @(@($UserPrincipalNames) + @($ObjectIds) | Where-Object { $_ })) {
        $match = Find-EAAlertRuleSignal -Texts $Texts -Pattern ('(?i)' + [regex]::Escape([string]$value))
        if ($match) { return $match }
    }
    return $null
}

function Get-EAAzureMonitoringCoverage {
    param([string[]]$EmergencyAccessUpns, [string[]]$EmergencyAccessObjectIds)

    $rows = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]
    $exportedCategories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $enabledActionGroups = @{}
    # Subscriptions whose action groups were listed successfully. An action group that an
    # alert rule references in any OTHER subscription was not read, so it is neither
    # enabled nor disabled as far as this audit knows.
    $readActionGroupSubscriptions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $alertRuleRouting = New-Object System.Collections.Generic.List[object]
    $weakIdentityAlertNames = New-Object System.Collections.Generic.List[string]
    $result = [ordered]@{
        State='Unknown'; Detail=''; Rows=$rows; Errors=$errors; SubscriptionCount=0
        DiagnosticSettingCount=0; EnabledDiagnosticSettingCount=0
        AlertRuleCount=0; IdentityAlertCandidateCount=0; EmergencyAlertCandidateCount=0
        IdentityAlertWithActionCount=0; EmergencyAlertWithActionCount=0
        WeakIdentityAlertCount=0; WeakIdentityAlertNames=@()
        ActionGroupCount=0; EnabledActionGroupCount=0
        SentinelWorkspaceCount=0; SentinelEnabledWorkspaceCount=0; SentinelRuleCount=0
        SentinelIdentityRuleCount=0; SentinelEmergencyRuleCount=0
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
            if ($null -eq (Get-EAApplicationCheckValue $properties 'logs')) {
                # Fail closed: a setting whose log list cannot be parsed must not be read
                # as "no enabled export".
                $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope='Tenant'; Control='Entra diagnostic settings'; Error=("Diagnostic setting '{0}' returned no readable logs list, so its exported categories are unknown." -f [string](Get-EAApplicationCheckValue $setting 'name')) }) | Out-Null
            }
            foreach ($log in @(Get-EAApplicationCheckElement $properties 'logs')) {
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

    # $identityPattern only finds POSSIBLE identity alerts (identity words in a rule's
    # name, description or conditions); Get-EAAlertRuleIdentitySignal counts a rule only
    # when it reads Entra log tables or watches Entra or role-assignment operations. Short
    # tokens are word-bounded so unrelated text (for example SQL "auditingSettings",
    # region names such as "centralus", "assigning", or "Azure Advisor") does not match,
    # while camel-case names (EntraIDRoleChange, UserSignInLogs) and role operations do.
    $identityPattern = '(?i)((?<![a-z])entra(?![a-z])|(?-i:Entra(?![a-z]))|azure.?ad(?!v)|\bAAD\w*|identity|(?<![a-z])sign.?ins?(logs?)?(?![a-z])|(?-i:Sign.?[Ii]n(s|Logs?)?(?![a-z]))|\baudit(logs?)?\b|\brole(s|management\w*|assignment\w*|definition\w*|eligibility\w*)?\b|conditional.?access|authentication|credential|consent|federat|cross.?tenant)'
    $emergencyPattern = '(?i)(break.?glass|emergency.?(access|account|admin))'
    $emergencyUpnList = @($EmergencyAccessUpns | Where-Object { $_ })
    $emergencyIdList = @($EmergencyAccessObjectIds | Where-Object { $_ })
    # One evidence Detail text for every kind of alert rule (Azure Monitor or Sentinel).
    $ruleDetail = {
        param([object]$Identity, [string]$EmergencyMatch)
        $parts = @(
            if ($Identity.Strength -eq 'Strong') { "Identity match: $($Identity.Match)." }
            if ($Identity.Strength -eq 'Weak') { "Possible identity alert, not counted: $($Identity.Match), but the rule does not read the Entra sign-in or audit logs or watch Entra or role-assignment operations." }
            if ($Identity.Strength -eq 'Platform') { "Platform alert ($($Identity.Match)), not an identity alert." }
            if ($EmergencyMatch) { "Emergency-account match: $EmergencyMatch." }
        )
        if ($parts.Count -gt 0) { 'Rule read. ' + ($parts -join ' ') } else { 'Rule read. No identity or emergency-account keyword in its name, description, query, or conditions.' }
    }
    foreach ($subscription in $subscriptions) {
        $subscriptionId = [string]$subscription.Id
        $subscriptionName = [string]$subscription.Name
        $subscriptionScope = "{0} ({1})" -f $subscriptionName,$subscriptionId
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
                    $resourceName = [string](Get-EAApplicationCheckValue $resource 'name')
                    if ($endpoint.Control -eq 'Action group') {
                        $result.ActionGroupCount++
                        $actionGroupId = [string](Get-EAApplicationCheckValue $resource 'id')
                        if ($actionGroupId) { $enabledActionGroups[$actionGroupId.TrimEnd('/').ToLowerInvariant()] = [bool]$enabled }
                        if ($enabled) { $result.EnabledActionGroupCount++ }
                        $rows.Add([pscustomobject]@{
                            Plane='Azure Resource Manager'; Scope=$subscriptionScope; Control=$endpoint.Control; Name=$resourceName
                            Enabled=$enabled; State='Known'; Detail='Notification/action destination metadata read.'
                            IdentitySignal=$false; EmergencySignal=$false; ActionGroupReferences=''
                        }) | Out-Null
                        continue
                    }

                    $classifierTexts = @(Get-EAAlertRuleClassifierText -Resource $resource)
                    $identity = Get-EAAlertRuleIdentitySignal -Resource $resource -Control $endpoint.Control -Texts $classifierTexts -WeakPattern $identityPattern
                    $emergencyMatch = Find-EAEmergencyAlertSignal -Texts $classifierTexts -Pattern $emergencyPattern -UserPrincipalNames $emergencyUpnList -ObjectIds $emergencyIdList
                    $identitySignal = ($identity.Strength -eq 'Strong')
                    $emergencySignal = [bool]$emergencyMatch
                    $actionGroupReferences = @()
                    $actions = Get-EAApplicationCheckValue $properties 'actions'
                    foreach ($reference in @(Get-EAApplicationCheckElement $actions 'actionGroups')) {
                        $referenceId = if ($reference -is [string]) { [string]$reference } else { [string](Get-EAApplicationCheckValue $reference 'actionGroupId') }
                        if ($referenceId) { $actionGroupReferences += $referenceId.TrimEnd('/') }
                    }
                    $result.AlertRuleCount++
                    if ($enabled -and $identitySignal) { $result.IdentityAlertCandidateCount++ }
                    if ($enabled -and $emergencySignal) { $result.EmergencyAlertCandidateCount++ }
                    if ($enabled -and $identity.Strength -eq 'Weak') { $weakIdentityAlertNames.Add($resourceName) | Out-Null }
                    $alertRuleRouting.Add([pscustomobject]@{
                        Name=$resourceName; Scope=$subscriptionScope; Enabled=[bool]$enabled
                        IdentitySignal=$identitySignal; EmergencySignal=$emergencySignal
                        ActionGroupReferences=@($actionGroupReferences | Select-Object -Unique)
                    }) | Out-Null
                    $rows.Add([pscustomobject]@{
                        Plane='Azure Resource Manager'; Scope=$subscriptionScope; Control=$endpoint.Control; Name=$resourceName
                        Enabled=$enabled; State='Known'; Detail=(& $ruleDetail $identity $emergencyMatch)
                        IdentitySignal=$identitySignal; EmergencySignal=$emergencySignal
                        ActionGroupReferences=($actionGroupReferences -join ',')
                    }) | Out-Null
                }
                if ($endpoint.Control -eq 'Action group') { $readActionGroupSubscriptions.Add($subscriptionId) | Out-Null }
            } catch {
                $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope=$subscriptionScope; Control=$endpoint.Control; Error=$_.Exception.Message }) | Out-Null
            }
        }

        # Microsoft Sentinel analytics rules are a common home for identity and break-glass
        # alerts. They live on Log Analytics workspaces, not in Microsoft.Insights, and notify
        # people through Sentinel automation rules or playbooks instead of action groups.
        # A workspace without Sentinel answers 400 "not onboarded" (or 404); any other failed
        # read is a coverage gap. Monitoring Reader includes these reads (*/read).
        $workspaces = @()
        try {
            $workspacePath = '/subscriptions/' + [uri]::EscapeDataString($subscriptionId) + '/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01'
            $workspaces = @(Invoke-EAReadOnlyAzRestCollection -Path $workspacePath -DefaultProfile $azContext)
        } catch {
            $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope=$subscriptionScope; Control='Log Analytics workspaces (Microsoft Sentinel)'; Error=$_.Exception.Message }) | Out-Null
        }
        foreach ($workspace in $workspaces) {
            $workspaceId = ([string](Get-EAApplicationCheckValue $workspace 'id')).TrimEnd('/')
            $workspaceName = [string](Get-EAApplicationCheckValue $workspace 'name')
            if ($workspaceId -notmatch '(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/workspaces/[^/?#]+$') {
                $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope=$subscriptionScope; Control='Microsoft Sentinel analytics rules'; Error=("Workspace '{0}' has an unexpected resource id '{1}', so its Sentinel analytics rules were not read." -f $workspaceName, $workspaceId) }) | Out-Null
                continue
            }
            $result.SentinelWorkspaceCount++
            $sentinelRules = $null
            try {
                $sentinelRules = @(Invoke-EAReadOnlyAzRestCollection -Path ($workspaceId + '/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01') -DefaultProfile $azContext)
            } catch {
                $sentinelError = $_.Exception.Message
                if ($sentinelError -match 'returned HTTP 404\b' -or $sentinelError -match '(?i)not onboarded|MissingSubscriptionRegistration|not registered to use namespace') {
                    $rows.Add([pscustomobject]@{
                        Plane='Azure Resource Manager'; Scope=$subscriptionScope; Control='Log Analytics workspace'; Name=$workspaceName
                        Enabled=$false; State='Known'; Detail='Microsoft Sentinel is not enabled on this workspace.'
                        IdentitySignal=$false; EmergencySignal=$false; ActionGroupReferences=''
                    }) | Out-Null
                } else {
                    $errors.Add([pscustomobject]@{ Plane='Azure Resource Manager'; Scope=("{0} / workspace {1}" -f $subscriptionScope, $workspaceName); Control='Microsoft Sentinel analytics rules'; Error=$sentinelError }) | Out-Null
                }
                continue
            }
            $result.SentinelEnabledWorkspaceCount++
            $rows.Add([pscustomobject]@{
                Plane='Azure Resource Manager'; Scope=$subscriptionScope; Control='Log Analytics workspace'; Name=$workspaceName
                Enabled=$true; State='Known'; Detail=("Microsoft Sentinel is enabled; {0} read." -f (Format-EAApplicationCheckCount -Count $sentinelRules.Count -One 'analytics rule' -Many 'analytics rules'))
                IdentitySignal=$false; EmergencySignal=$false; ActionGroupReferences=''
            }) | Out-Null
            foreach ($sentinelRule in $sentinelRules) {
                $ruleProperties = Get-EAApplicationCheckValue $sentinelRule 'properties'
                $enabledValue = Get-EAApplicationCheckValue $ruleProperties 'enabled'
                $parsedEnabled = ConvertTo-EAApplicationCheckBoolean $enabledValue
                $enabled = if ($null -eq $enabledValue) { $true } elseif ($null -eq $parsedEnabled) { $false } else { $parsedEnabled }
                $ruleName = [string](@(Get-EAApplicationCheckValue $ruleProperties 'displayName'; Get-EAApplicationCheckValue $sentinelRule 'name') | Where-Object { $_ } | Select-Object -First 1)
                $classifierTexts = @(Get-EAAlertRuleClassifierText -Resource $sentinelRule)
                $identity = Get-EAAlertRuleIdentitySignal -Resource $sentinelRule -Control 'Sentinel analytics rule' -Texts $classifierTexts -WeakPattern $identityPattern
                $emergencyMatch = Find-EAEmergencyAlertSignal -Texts $classifierTexts -Pattern $emergencyPattern -UserPrincipalNames $emergencyUpnList -ObjectIds $emergencyIdList
                $result.SentinelRuleCount++
                if ($enabled -and $identity.Strength -eq 'Strong') { $result.SentinelIdentityRuleCount++ }
                if ($enabled -and $emergencyMatch) { $result.SentinelEmergencyRuleCount++ }
                if ($enabled -and $identity.Strength -eq 'Weak') { $weakIdentityAlertNames.Add("$ruleName (Microsoft Sentinel)") | Out-Null }
                $rows.Add([pscustomobject]@{
                    Plane='Azure Resource Manager'; Scope=("{0} / workspace {1}" -f $subscriptionScope, $workspaceName); Control='Sentinel analytics rule'; Name=$ruleName
                    Enabled=$enabled; State='Known'; Detail=(& $ruleDetail $identity $emergencyMatch)
                    IdentitySignal=($identity.Strength -eq 'Strong'); EmergencySignal=[bool]$emergencyMatch; ActionGroupReferences=''
                }) | Out-Null
            }
        }
    }

    # Does each enabled rule reach an enabled action group? A reference is one of three
    # things: an enabled group, a disabled / missing group in a subscription whose action
    # groups were read (a confirmed "notifies nobody"), or a group in a subscription this
    # audit did not read (unknown).
    foreach ($routing in @($alertRuleRouting.ToArray())) {
        $hasEnabledAction = $false
        $unreadReferences = @()
        foreach ($reference in @($routing.ActionGroupReferences)) {
            $key = ([string]$reference).TrimEnd('/').ToLowerInvariant()
            if ($enabledActionGroups.ContainsKey($key)) {
                if ($enabledActionGroups[$key]) { $hasEnabledAction = $true; break }
                continue
            }
            $referenceSubscription = [regex]::Match($key, '^/subscriptions/([^/]+)/')
            if (-not $referenceSubscription.Success -or -not $readActionGroupSubscriptions.Contains($referenceSubscription.Groups[1].Value)) {
                $unreadReferences += [string]$reference
            }
        }
        $routing | Add-Member -NotePropertyName HasEnabledAction -NotePropertyValue $hasEnabledAction -Force
        $routing | Add-Member -NotePropertyName UnreadActionGroupReferences -NotePropertyValue @($unreadReferences) -Force
        if ($routing.Enabled -and $hasEnabledAction -and $routing.IdentitySignal) { $result.IdentityAlertWithActionCount++ }
        if ($routing.Enabled -and $hasEnabledAction -and $routing.EmergencySignal) { $result.EmergencyAlertWithActionCount++ }
    }
    # An unread action group is only recorded as a gap where it could change a conclusion:
    # no identity (or emergency) alert is known to notify anyone, or no enabled action group
    # was found at all. The State then becomes Partial, so those results are reported as
    # coverage gaps instead of confirmed findings.
    foreach ($routing in @($alertRuleRouting.ToArray())) {
        if (-not $routing.Enabled -or $routing.HasEnabledAction -or @($routing.UnreadActionGroupReferences).Count -eq 0) { continue }
        if (($routing.IdentitySignal -and $result.IdentityAlertWithActionCount -eq 0) -or
            ($routing.EmergencySignal -and $result.EmergencyAlertWithActionCount -eq 0) -or
            $result.EnabledActionGroupCount -eq 0) {
            $errors.Add([pscustomobject]@{
                Plane='Azure Resource Manager'; Scope=$routing.Scope; Control='Action group reference'
                Error=("Alert rule '{0}' sends its alerts to {1} in a subscription this audit could not read ({2}), so whether it notifies anyone is unknown." -f $routing.Name, $(if (@($routing.UnreadActionGroupReferences).Count -eq 1) { 'an action group' } else { 'action groups' }), (@($routing.UnreadActionGroupReferences) -join ', '))
            }) | Out-Null
        }
    }
    $result.WeakIdentityAlertNames = @($weakIdentityAlertNames.ToArray() | Select-Object -Unique)
    $result.WeakIdentityAlertCount = $weakIdentityAlertNames.Count
    $result.ExportedLogCategories = @($exportedCategories | Sort-Object)
    $allLogsExported = $exportedCategories.Contains('allLogs')
    $result.CoreDiagnosticCategoriesComplete = [bool]($allLogsExported -or
        ($exportedCategories.Contains('AuditLogs') -and $exportedCategories.Contains('SignInLogs')))

    if ($errors.Count -gt 0) {
        $result.State = 'Partial'
        $result.Detail = "Azure read context matched, but {0} could not be read." -f (Format-EAApplicationCheckCount -Count $errors.Count -One 'ARM dataset or referenced object' -Many 'ARM datasets or referenced objects')
    } else {
        $result.State = 'Complete'
        $result.Detail = "Azure read context matched and all requested tenant/subscription datasets were read across {0}, including Microsoft Sentinel analytics rules in {1} of {2}." -f (Format-EAApplicationCheckCount -Count $subscriptions.Count -One 'subscription' -Many 'subscriptions'), $result.SentinelEnabledWorkspaceCount, (Format-EAApplicationCheckCount -Count $result.SentinelWorkspaceCount -One 'Log Analytics workspace' -Many 'Log Analytics workspaces')
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
        $firstCoreError = [string](@($coreUnknown.Error | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -First 1) -join '')
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Sign-in or audit logs could not be read' `
            -Evidence ("Could not read: {0}.{1}" -f (($coreUnknown.Dataset) -join ', '), $(if ($firstCoreError) { " Error: $firstCoreError" } else { '' })) `
            -WhyItMatters 'Without these logs the audit cannot confirm that sign-ins and admin changes are being recorded, and that record is what you need to spot and investigate an attack.' `
            -RecommendedAction 'Give the audit account AuditLog.Read.All and the Reports Reader or Security Reader role, confirm the tenant license, and run the monitoring check again.' `
            -SourceFile $probeSource -ResultRows $coreUnknown -RuleId 'monitoring-core-log-unreadable' -ObjectType 'tenant' -CoverageGap
    }
    if ($coreEmpty.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Sign-in or audit logs returned no entries at all' `
            -Evidence ("Readable but empty: {0}. An empty log is not treated as proof that logging works." -f (($coreEmpty.Dataset) -join ', ')) `
            -WhyItMatters 'An empty log can be normal in a new or very quiet tenant, but it can also mean logs are not being kept, so the audit cannot confirm that sign-ins and changes are recorded.' `
            -RecommendedAction 'Check for recent entries in Entra admin center > Monitoring & health > Sign-in logs and Audit logs, and confirm how long logs are kept and where they are exported.' `
            -SourceFile $probeSource -ResultRows $coreEmpty -RuleId 'monitoring-core-log-empty' -ObjectType 'tenant' -CoverageGap
    }
    if ($optionalUnknown.Count -gt 0 -or $optionalEmpty.Count -gt 0) {
        $optionalGaps = @($optionalUnknown) + @($optionalEmpty)
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Some security logs (provisioning, risk detections or alerts) could not be checked' `
            -Evidence ("Unreadable, without a timestamp, or empty (dataset [state] (permission needed)): {0}." -f (($optionalGaps | ForEach-Object { "{0} [{1}] ({2})" -f $_.Dataset,$_.State,$_.RequiredScope }) -join '; ')) `
            -WhyItMatters 'These logs help detect compromised accounts and apps. Where they are unavailable, the attacks they would reveal can go unnoticed.' `
            -RecommendedAction 'Where you have the license and need the data, give the audit account the read-only permission shown in the evidence and confirm the service is turned on, then run the monitoring check again.' `
            -SourceFile $probeSource -ResultRows $optionalGaps -RuleId 'monitoring-optional-dataset-unknown' -ObjectType 'tenant' -CoverageGap
    }
    if ($staleCore.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'The newest sign-in or audit log entry is more than 7 days old' `
            -Evidence ("Newest entry older than seven days: {0}." -f (($staleCore | ForEach-Object { "{0} ({1} days old)" -f $_.Dataset,$_.AgeDays }) -join '; ')) `
            -WhyItMatters 'In an active tenant, people sign in and settings change every day. A newest entry that is this old suggests logs are delayed or no longer being collected.' `
            -RecommendedAction 'Check whether there has been recent activity (Entra admin center > Monitoring & health), and confirm that licensing, log retention and any log export are working.' `
            -SourceFile $probeSource -ResultRows $staleCore -RuleId 'monitoring-core-log-stale' -ObjectType 'tenant'
    }

    # Must not be named $breakGlassUpns: PowerShell variable names are case-insensitive, so
    # a local of that name would hide the script's -BreakGlassUpns parameter.
    # Normalize-StringList cannot fail on string input; no try/catch, so a missing helper
    # stops the check with an error instead of silently looking like "no accounts given".
    $emergencyUpns = @(Normalize-StringList -Values $BreakGlassUpns)
    # Microsoft's own sample alerts for emergency accounts match the account's object id
    # (SigninLogs | where UserId == "<object id>"), so look each id up (GET, User.Read.All)
    # and match it as well. An id that cannot be looked up is recorded: a rule that matches
    # it cannot be ruled out, so "no alert" is then a coverage gap, not a finding.
    $emergencyIdLookup = @{}
    $emergencyIds = @()
    foreach ($emergencyUpn in $emergencyUpns) {
        try {
            $emergencyUser = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/users/' + [uri]::EscapeDataString($emergencyUpn) + '?$select=id') -ErrorAction Stop
            $emergencyObjectId = [string](Get-EAApplicationCheckValue $emergencyUser 'id')
            if (-not $emergencyObjectId) { throw 'The user read returned no object id.' }
            $emergencyIds += $emergencyObjectId
            $emergencyIdLookup[$emergencyUpn] = [pscustomobject]@{ ObjectId=$emergencyObjectId; State='Resolved'; Error='' }
        } catch {
            $emergencyIdLookup[$emergencyUpn] = [pscustomobject]@{ ObjectId=''; State='Unresolved'; Error=$_.Exception.Message }
        }
    }
    $unresolvedEmergencyUpns = @($emergencyUpns | Where-Object { $emergencyIdLookup[$_].State -ne 'Resolved' })
    $azureCoverage = Get-EAAzureMonitoringCoverage -EmergencyAccessUpns $emergencyUpns -EmergencyAccessObjectIds $emergencyIds

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
            'IdentitySignal = the rule reads the Entra sign-in or audit log tables, or (activity-log alert) watches Entra or role-assignment operations. Rules that only mention identity words in their name, description or conditions are listed as possible identity alerts and are not counted.',
            'Microsoft Sentinel analytics rules are read from every Log Analytics workspace in the readable subscriptions. Sentinel notifies people through automation rules or playbooks, which this audit does not read.',
            'Rule matches are review candidates; notification delivery still requires an end-to-end operational test.'
        )

    $sentinelNotificationText = 'Microsoft Sentinel notifies people through automation rules or playbooks, not action groups, and this audit does not read those.'
    if ($azureCoverage.State -ne 'Complete') {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'Azure log export and alert rules could not be fully checked' `
            -Evidence ("Azure state: {0}. {1}" -f $azureCoverage.State,$azureCoverage.Detail) `
            -WhyItMatters 'The audit could not confirm that Entra logs are kept outside Entra or that important identity changes raise an alert. Microsoft Graph alone cannot show this.' `
            -RecommendedAction 'Before running the audit, sign in to Azure (Connect-AzAccount) in the same tenant with a read-only account that has the Monitoring Reader role, fix any failed read shown in the evidence, and run the monitoring check again. Never give the audit account write access to Azure.' `
            -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-arm-cross-plane-incomplete' -ObjectType 'tenant' -CoverageGap
    } else {
        if ($azureCoverage.EnabledDiagnosticSettingCount -eq 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'Entra sign-in and audit logs are not exported anywhere' `
                -Evidence ("{0}; none had both an enabled log category and an export destination." -f (Format-EAApplicationCheckCount -Count $azureCoverage.DiagnosticSettingCount -One 'Entra diagnostic setting was read' -Many 'Entra diagnostic settings were read')) `
                -WhyItMatters 'Entra keeps its logs for only 7 to 30 days. Without an export, the evidence of an attack can be gone before anyone starts to investigate.' `
                -RecommendedAction 'Export AuditLogs, SignInLogs and the other sign-in and risk log categories you are licensed for to a Log Analytics workspace, storage account or event hub (Entra admin center > Monitoring & health > Diagnostic settings), and keep them as long as your policy requires.' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-configure-diagnostic-settings' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-no-entra-diagnostic-export' -ObjectType 'tenant'
        }
        if ($azureCoverage.EnabledDiagnosticSettingCount -gt 0 -and -not $azureCoverage.CoreDiagnosticCategoriesComplete) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'The Entra log export does not include both audit logs and sign-in logs' `
                -Evidence ("Exported log categories: {0}. AuditLogs and SignInLogs (or allLogs) are not both exported." -f (($azureCoverage.ExportedLogCategories) -join ', ')) `
                -WhyItMatters 'Logs that are not exported are lost once Entra''s own retention ends, so admin changes or sign-ins outside the export cannot be investigated later.' `
                -RecommendedAction 'Add AuditLogs and SignInLogs to the diagnostic setting (Entra admin center > Monitoring & health > Diagnostic settings), plus the non-interactive, service principal, managed identity and risk log categories you need.' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-configure-diagnostic-settings' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-entra-diagnostic-core-category-gap' -ObjectType 'tenant'
        }
        $weakIdentityText = if ($azureCoverage.WeakIdentityAlertCount -gt 0) {
            " Not counted: {0}: {1}." -f (Format-EAApplicationCheckCount -Count $azureCoverage.WeakIdentityAlertCount -One 'rule only mentions identity words in its name, description or conditions and does not read those logs' -Many 'rules only mention identity words in their name, description or conditions and do not read those logs'), (Format-EAApplicationCheckList @($azureCoverage.WeakIdentityAlertNames))
        } else { '' }
        if ($azureCoverage.IdentityAlertCandidateCount -eq 0 -and $azureCoverage.SentinelIdentityRuleCount -eq 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'No alert rule for important identity changes was found in Azure Monitor or Microsoft Sentinel' `
                -Evidence ("{0} and {1} were read; no enabled rule reads the Entra sign-in or audit logs (for example SigninLogs or AuditLogs) or watches admin role assignments.{2}" -f (Format-EAApplicationCheckCount -Count $azureCoverage.AlertRuleCount -One 'Azure Monitor alert rule' -Many 'Azure Monitor alert rules'), (Format-EAApplicationCheckCount -Count $azureCoverage.SentinelRuleCount -One 'Microsoft Sentinel analytics rule' -Many 'Microsoft Sentinel analytics rules'), $weakIdentityText) `
                -WhyItMatters 'Changes to admin roles, Conditional Access, sign-in methods, federation or app permissions are common attacker steps. Without an alert they are only found at the next audit, if at all.' `
                -RecommendedAction 'Create alert rules in Azure Monitor or Microsoft Sentinel on the exported Entra logs for these changes and for emergency-account sign-ins, send them to people who respond (an action group, or a Sentinel automation rule or playbook), and test that the alerts arrive.' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-no-critical-identity-alert-candidate' -ObjectType 'tenant'
        } elseif ($azureCoverage.IdentityAlertWithActionCount -eq 0) {
            if ($azureCoverage.SentinelIdentityRuleCount -gt 0) {
                Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
                    -Title 'Identity alerts are set up in Microsoft Sentinel; check that they notify someone' `
                    -Evidence ("Enabled Microsoft Sentinel analytics rules that read the Entra logs: {0}. {1} {2}" -f $azureCoverage.SentinelIdentityRuleCount,
                        $(if ($azureCoverage.IdentityAlertCandidateCount -gt 0) { (Format-EAApplicationCheckCount -Count $azureCoverage.IdentityAlertCandidateCount -One 'Azure Monitor identity alert rule also exists, but it is not linked to an enabled action group.' -Many 'Azure Monitor identity alert rules also exist, but none is linked to an enabled action group.') } else { 'No Azure Monitor identity alert rule was found.' }),
                        $sentinelNotificationText) `
                    -WhyItMatters 'An alert only helps if it reaches a person who can respond. Whether these Sentinel incidents notify anyone could not be read from the configuration.' `
                    -RecommendedAction 'In Microsoft Sentinel > Automation, confirm that an automation rule or playbook notifies your responders for incidents from these rules, and test it end to end.' `
                    -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-identity-alert-sentinel-notification-unverified' -ObjectType 'tenant' -CoverageGap
            } else {
                Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                    -Title 'Identity alert rules exist but do not notify anyone' `
                    -Evidence ("Enabled identity-related alert rules: {0}; of these, linked to an enabled action group: {1}." -f $azureCoverage.IdentityAlertCandidateCount,$azureCoverage.IdentityAlertWithActionCount) `
                    -WhyItMatters 'An alert rule that is not linked to an enabled action group only shows up in the Azure portal, so nobody is told when it fires.' `
                    -RecommendedAction 'Link each identity alert rule to an enabled action group that reaches your responders (Azure portal > Monitor > Alerts > Alert rules > rule > Actions), or document the Microsoft Sentinel automation that handles it.' `
                    -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-identity-alert-action-link-gap' -ObjectType 'tenant'
            }
        }
        # With Sentinel identity rules, notification runs through Sentinel automation, which
        # the Sentinel finding above covers; "cannot notify anyone" would not be proven.
        if ($azureCoverage.EnabledActionGroupCount -eq 0 -and $azureCoverage.SentinelIdentityRuleCount -eq 0) {
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'No enabled Azure Monitor action group was found, so alerts cannot notify anyone' `
                -Evidence ("{0}; none is enabled." -f (Format-EAApplicationCheckCount -Count $azureCoverage.ActionGroupCount -One 'action group was read' -Many 'action groups were read')) `
                -WhyItMatters 'Action groups send alert notifications by email, text message or to a ticketing system. Without an enabled one, alert rules cannot reach the people who must respond.' `
                -RecommendedAction 'Create or enable an action group that reaches your responders (Azure portal > Monitor > Alerts > Action groups), link your alert rules to it, and test that notifications arrive.' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-no-enabled-action-group' -ObjectType 'tenant'
        }
        if ($azureCoverage.EnabledDiagnosticSettingCount -gt 0 -and $azureCoverage.CoreDiagnosticCategoriesComplete -and $azureCoverage.IdentityAlertWithActionCount -gt 0) {
            Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
                -Title 'Entra logs are exported and identity alert rules notify an action group' `
                -Evidence ("Enabled diagnostic exports: {0}; identity alert rules linked to an enabled action group: {1}; enabled action groups: {2}; subscriptions read: {3}." -f $azureCoverage.EnabledDiagnosticSettingCount,$azureCoverage.IdentityAlertWithActionCount,$azureCoverage.EnabledActionGroupCount,$azureCoverage.SubscriptionCount) `
                -WhyItMatters 'Exported logs, alert rules and a working notification path together make sure important identity changes reach a person who can respond.' `
                -RecommendedAction 'Keep reviewing the configuration regularly and keep a record of end-to-end alert tests.' `
                -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-azure-configured' -ObjectType 'tenant'
        }
    }

    $emergencyRows = @(Get-EAEmergencyAccessMonitoringRows -UserPrincipalNames $emergencyUpns -ObjectIdLookup $emergencyIdLookup)
    foreach ($row in $emergencyRows) {
        $row.AlertRuleState = if ($azureCoverage.State -ne 'Complete') { 'Unknown-CrossPlaneIncomplete' } `
            elseif ($azureCoverage.EmergencyAlertWithActionCount -gt 0) { 'ConfigurationCandidateFound-DeliveryNotTested' } `
            elseif ($azureCoverage.SentinelEmergencyRuleCount -gt 0) { 'SentinelRuleFound-NotificationNotChecked' } `
            elseif ($azureCoverage.EmergencyAlertCandidateCount -gt 0) { 'RuleCandidate-NoLinkedEnabledActionGroup' } `
            elseif ($row.ObjectIdLookup -eq 'Unresolved') { 'Unknown-ObjectIdNotResolved' } `
            else { 'Known-NoMatchingRuleCandidate' }
    }
    $emergencySource = Write-Evidence -BaseName 'emergency_access_monitoring' -Rows $emergencyRows -Title 'Emergency-Access Sign-In Monitoring Coverage' `
        -Notes @(
            'Graph sign-in visibility and configured alert-rule delivery are separate controls; this check does not infer one from the other.',
            'An alert rule matches an emergency account when its name, description, query or conditions mention "break glass" / "emergency access", the account''s sign-in name, or its object id (ObjectId).'
        )
    # Describe what was actually learned about Azure Monitor instead of always calling it unknown.
    $azureAlertText = if ($azureCoverage.State -eq 'Complete') {
        "Azure Monitor was read: {0}, {1} linked to an enabled action group; Microsoft Sentinel analytics rules that mention the accounts: {2}." -f (Format-EAApplicationCheckCount -Count $azureCoverage.EmergencyAlertCandidateCount -One 'emergency-account alert rule candidate' -Many 'emergency-account alert rule candidates'),$azureCoverage.EmergencyAlertWithActionCount,$azureCoverage.SentinelEmergencyRuleCount
    } else {
        "Azure Monitor alert rules could not be fully read ({0})." -f $azureCoverage.State
    }
    $noAccountInput = @($emergencyRows | Where-Object { $_.SignInLogState -eq 'Unknown-NoAccountInput' })
    $unreadableEmergency = @($emergencyRows | Where-Object { $_.SignInLogState -like 'Unknown*' -and $_.SignInLogState -ne 'Unknown-NoAccountInput' })
    if ($noAccountInput.Count -gt 0) {
        # A missing command-line value is not a tenant weakness; the breakglass check
        # already reports undesignated emergency accounts. Record it without risk points.
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Emergency-account sign-in monitoring was not checked: no accounts were given' `
            -Evidence ("No emergency (break-glass) accounts were supplied with -BreakGlassUpns, so their sign-in logs and alerts could not be tested. {0}" -f $azureAlertText) `
            -WhyItMatters 'Emergency accounts skip some security controls, so every sign-in with one should raise an alert right away. This can only be verified when the audit knows which accounts they are.' `
            -RecommendedAction 'Run the audit again with -BreakGlassUpns (or the emergency-accounts field in the GUI) listing your emergency accounts.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-monitoring-no-account-input' -ObjectType 'tenant' -CoverageGap
    } elseif ($unreadableEmergency.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Sign-in logs of the emergency (break-glass) accounts could not be read' `
            -Evidence ("Sign-in logs could not be read for {0}: {1}. {2}" -f (Format-EAApplicationCheckCount -Count $unreadableEmergency.Count -One 'emergency account' -Many 'emergency accounts'), (Format-EAApplicationCheckList @($unreadableEmergency.EmergencyAccount)), $azureAlertText) `
            -WhyItMatters 'Emergency accounts skip some security controls, so every sign-in with one should raise an alert right away. The audit could not confirm that their sign-ins are even visible.' `
            -RecommendedAction 'Make sure the audit account can read sign-in logs (AuditLog.Read.All), check the account names given with -BreakGlassUpns, and confirm by hand that an alert fires and reaches your responders when an emergency account signs in.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-monitoring-unknown' -ObjectType 'tenant' -CoverageGap
    } elseif ($azureCoverage.State -ne 'Complete') {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Alerts for emergency-account sign-ins could not be checked in Azure' `
            -Evidence ("The sign-in logs of the given emergency accounts were readable, but Azure monitoring could not be fully read ({0}); Microsoft Graph alone cannot see alert rules or action groups." -f $azureCoverage.State) `
            -WhyItMatters 'Being able to read the sign-in logs does not mean anyone is alerted when an emergency account is used.' `
            -RecommendedAction 'Sign in to Azure with a read-only account in the same tenant before the audit and run it again, or check by hand that an enabled alert rule covers each emergency account, reaches your responders and has been tested.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-alert-cross-plane' -ObjectType 'tenant' -CoverageGap
    } elseif ($azureCoverage.EmergencyAlertWithActionCount -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'An alert for emergency-account sign-ins exists, but it must be tested by hand' `
            -Evidence ("{0} to an enabled action group. Reading the configuration cannot prove that notifications arrive." -f (Format-EAApplicationCheckCount -Count $azureCoverage.EmergencyAlertWithActionCount -One 'enabled alert rule that mentions the emergency accounts is linked' -Many 'enabled alert rules that mention the emergency accounts are linked')) `
            -WhyItMatters 'A correctly configured rule can still fail because of a broken query, missing log data or a wrong recipient. Only a test proves that the alert arrives.' `
            -RecommendedAction 'Test the alert end to end in a planned way (for example a supervised emergency-account sign-in), record the result, and repeat after changes.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-alert-delivery-untested' -ObjectType 'tenant' -CoverageGap
    } elseif ($azureCoverage.SentinelEmergencyRuleCount -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'An emergency-account sign-in alert exists in Microsoft Sentinel; confirm it notifies someone' `
            -Evidence ("{0} the emergency accounts. {1} {2}" -f (Format-EAApplicationCheckCount -Count $azureCoverage.SentinelEmergencyRuleCount -One 'enabled Microsoft Sentinel analytics rule mentions' -Many 'enabled Microsoft Sentinel analytics rules mention'), $sentinelNotificationText, $azureAlertText) `
            -WhyItMatters 'A correctly configured rule can still fail because of a broken query, missing log data, or an automation rule that does not reach anyone. Only a test proves that the alert arrives.' `
            -RecommendedAction 'In Microsoft Sentinel > Automation, confirm that an automation rule or playbook notifies your responders for incidents from these rules, then test it end to end (for example with a supervised emergency-account sign-in).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-alert-delivery-untested' -ObjectType 'tenant' -CoverageGap
    } elseif ($azureCoverage.EmergencyAlertCandidateCount -eq 0 -and $unresolvedEmergencyUpns.Count -gt 0) {
        $firstIdError = [string](@($unresolvedEmergencyUpns | ForEach-Object { $emergencyIdLookup[$_].Error } | Where-Object { $_ }) | Select-Object -First 1)
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'No emergency-account sign-in alert was found, but the accounts'' object IDs could not be read' `
            -Evidence ("No enabled alert rule mentions the emergency accounts by name. The object ID of {0} could not be looked up ({1}), so a rule that matches them by object ID, as in Microsoft's own examples, would not have been recognised.{2} {3}" -f (Format-EAApplicationCheckCount -Count $unresolvedEmergencyUpns.Count -One 'account' -Many 'accounts'), (Format-EAApplicationCheckList @($unresolvedEmergencyUpns)), $(if ($firstIdError) { " Lookup error: {0}." -f $firstIdError.TrimEnd('.', ' ') } else { '' }), $azureAlertText) `
            -WhyItMatters 'Emergency accounts skip some security controls, so every sign-in with one should alert your team right away. The audit could not confirm whether such an alert exists.' `
            -RecommendedAction 'Check the account names given with -BreakGlassUpns and make sure the audit account can read users (User.Read.All), then run the monitoring check again. If no alert exists, create one that matches a sign-in by any emergency account and test it end to end.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-alert-id-unresolved' -ObjectType 'tenant' -CoverageGap
    } else {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'No working alert for emergency (break-glass) account sign-ins was found' `
            -Evidence ("Enabled alert rules that mention the emergency accounts (by name, sign-in name or object ID): {0}; of these, linked to an enabled action group: {1}. Microsoft Sentinel analytics rules that mention them: {2}." -f $azureCoverage.EmergencyAlertCandidateCount,$azureCoverage.EmergencyAlertWithActionCount,$azureCoverage.SentinelEmergencyRuleCount) `
            -WhyItMatters 'Emergency accounts skip some security controls, so an attacker who gets one has wide access. Every sign-in with one should alert your team right away.' `
            -RecommendedAction 'Create an enabled alert rule that matches a sign-in by any of the emergency accounts, link it to an enabled action group that reaches your responders, and test it end to end.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-alert-missing' -ObjectType 'tenant'
    }
}

function Test-EAChangeMonitoringRoleActivation {
    # True for a PIM just-in-time activation / deactivation / activation-expiry event.
    # Uses the main script's shared Test-EARoleActivationEvent (defined above
    # Invoke-Check-RecentChanges) so recentchanges and changemonitoring classify the same
    # events the same way; the identical pattern is the fallback when this library is
    # loaded on its own.
    param([string]$ActivityDisplayName)

    $shared = Get-Command -Name 'Test-EARoleActivationEvent' -CommandType Function -ErrorAction Ignore
    if ($shared) { return [bool](& $shared -ActivityDisplayName $ActivityDisplayName) }
    return ([string]$ActivityDisplayName -match '(?i)PIM (de)?activat')
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

    # Activating an ELIGIBLE role just in time is the intended Privileged Identity
    # Management (PIM) posture, not a new grant: list it, but do not count it as a
    # high-risk change. The cheap 'PIM' pre-filter avoids a command lookup per event.
    if ($category -eq 'RoleManagement' -and $activity -match '(?i)\bPIM\b' -and (Test-EAChangeMonitoringRoleActivation -ActivityDisplayName $activity)) {
        return [pscustomobject]@{
            Domain='Privileged role activation (PIM)'; HighRisk=$false; Activation=$true
            Reason='An eligible administrator turned a privileged role on (or off) just in time through Privileged Identity Management (PIM). This is the intended use of an eligible role, not a new grant.'
        }
    }

    if ($category -eq 'RoleManagement' -or $text -match '(?i)(directory role|unifiedRole|eligible role|role assignment schedule|PIM role)') {
        $domain = 'Privileged role'
        $reason = 'A privileged role assignment, eligibility, activation, policy, or role definition changed.'
        $highRisk = $true
    } elseif ($text -match '(?i)(conditional[ -]?access|conditionalAccessPolicy|named location)') {
        $domain = 'Conditional Access'
        $reason = 'A Conditional Access policy, named location, or related enforcement object changed.'
        $highRisk = $true
    } elseif ($text -match '(?i)(authentication methods? policy|authenticationMethodsPolicy|authentication method|authentication strength|security info|temporary access pass|FIDO2|passkey|software OATH|passwordless|authenticator app|phone method|email method|windows hello|certificate-based authentication|strong authentication method)') {
        # A user managing their own sign-in methods (security info, passkeys, Windows Hello,
        # phone sign-in, password-reset info) is routine self-service, not a control-plane
        # change. Many such events match this branch only through loggedByService
        # 'Authentication Methods', so that alone must not make them high risk. Admin
        # actions ("Admin registered security info"), any event where the initiator is a
        # different user than the target user, and tenant policy changes stay high risk.
        $initiatorUser = Get-EAApplicationCheckValue (Get-EAApplicationCheckValue $AuditEvent 'initiatedBy') 'user'
        $initiatorKeys = @(
            [string](Get-EAApplicationCheckValue $initiatorUser 'id')
            [string](Get-EAApplicationCheckValue $initiatorUser 'userPrincipalName')
        ) | Where-Object { $_ }
        $targetUserKeys = @(foreach ($target in @(Get-EAApplicationCheckElement $AuditEvent 'targetResources')) {
            if ([string](Get-EAApplicationCheckValue $target 'type') -ne 'User') { continue }
            [string](Get-EAApplicationCheckValue $target 'id')
            [string](Get-EAApplicationCheckValue $target 'userPrincipalName')
        }) | Where-Object { $_ }
        $sameUser = @($initiatorKeys | Where-Object { $_ -in $targetUserKeys }).Count -gt 0
        $otherUser = (@($initiatorKeys).Count -gt 0 -and @($targetUserKeys).Count -gt 0 -and -not $sameUser)
        $selfServiceActivity = $activity -match '(?i)^User\b|self-service|^(Add|Delete|Remove|Update) (Passkey|Windows Hello for Business credential|passwordless phone sign-in credential|platform credential)|^Get passkey creation options|^(GET|POST|PUT|PATCH|DELETE) UserAuthMethod\.'
        if ($activity -notmatch '(?i)^Admin\b' -and -not $otherUser -and ($sameUser -or $selfServiceActivity)) {
            $domain = 'User authentication registration'
            $reason = 'A user added, changed, or removed their own sign-in method (for example MFA, a passkey, Windows Hello, or password-reset info).'
            $highRisk = $false
        } else {
            $domain = 'Authentication method'
            $reason = 'An authentication method, registration, or tenant authentication-method policy changed.'
            $highRisk = $true
        }
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
    } elseif ($activity -match '(?i)app role assignment( grant)? (to|from) (user|group)\b') {
        # "Add app role assignment grant to user", "Remove app role assignment from user",
        # "Add app role assignment to group": ordinary access to an enterprise app (helpdesk
        # work, access packages, group-based SaaS access), not an application permission.
        $domain = 'App access assignment'
        $reason = 'A user or group was given or lost access to an enterprise application (an app role assignment to a person or group, not an application permission grant).'
        $highRisk = $false
    } elseif ($text -match '(?i)(consent|oauth2PermissionGrant|delegated permission grant|app role assignment (to|from) service principal|permission grant)') {
        $domain = 'Application consent or permission grant'
        $reason = 'An OAuth consent, delegated grant, or application app-role grant changed.'
        $highRisk = $true
    } elseif ($text -match '(?i)((add|remove).*(member|owner).*(group)|(member|owner).*(added|removed).*(group)|group membership|group owner)') {
        $domain = 'Group owner or membership'
        $reason = 'A group owner or membership path changed; privileged/app access may flow transitively through that group.'
        $highRisk = $false
    }

    if (-not $domain) { return $null }
    return [pscustomobject]@{ Domain=$domain; HighRisk=[bool]$highRisk; Activation=$false; Reason=$reason }
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
    $auditLogPath = 'Entra admin center > Monitoring & health > Audit logs'
    $retentionDocumentation = 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention'

    try {
        $events = @(Get-EAReadOnlyGraphCollection -Uri $uri)
    } catch {
        $gapRows = @([pscustomobject]@{ Dataset='directoryAudits'; Since=$since; State='Unknown'; Error=$_.Exception.Message })
        $gapSource = Write-Evidence -BaseName 'critical_change_monitoring_gaps' -Rows $gapRows -Title 'Critical Change Monitoring Coverage Gaps'
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'The directory audit log could not be read, so security-sensitive changes were not checked' `
            -Evidence ("Reading the directory audit log since {0} failed: {1}. Changes in this period are unknown, not zero." -f $sinceText, $_.Exception.Message) `
            -WhyItMatters 'Changes to admin roles, Conditional Access, sign-in methods, federation, app credentials, consent and groups could not be checked, so unexpected changes cannot show up in this report.' `
            -RecommendedAction ("Give the audit account AuditLog.Read.All (and the Reports Reader or Security Reader role for a delegated run), wait for any throttling to clear, and run the changemonitoring check again. Until then, review {0} by hand." -f $auditLogPath) `
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
        # Retention unknown (license not determined) is a possible gap, not a proven one: a
        # P1/P2 tenant keeps 30 days, so the text must not claim the window is too long.
        if ($null -eq $nativeRetentionDays) {
            $retentionTitle = 'Could not confirm that Entra still keeps audit logs for the whole look-back period'
            $retentionEvidence = "Requested {0} days; the license could not be determined, so it is unknown whether Entra keeps audit logs for 7 days (Entra ID Free) or 30 days (P1/P2) in this tenant. Exported logs (Log Analytics, storage, SIEM or Purview) were not searched." -f $recentDays
            $retentionWhy = 'Entra deletes audit logs after 7 days on Entra ID Free and after 30 days with P1/P2. Because the license is unknown, changes older than 7 days may already be gone and missing from this report.'
            $retentionAction = 'Make sure the audit account can read the tenant subscriptions (Organization.Read.All) and run the changemonitoring check again, or use -RecentChangeDays 7. Search your exported logs (Log Analytics, SIEM, storage or Purview) for longer periods.'
        } else {
            $retentionTitle = 'The requested look-back period is longer than Entra keeps audit logs'
            $retentionEvidence = "Requested {0} days; Entra keeps audit logs for {1} days in this tenant. Exported logs (Log Analytics, storage, SIEM or Purview) were not searched." -f $recentDays, $nativeRetentionDays
            $retentionWhy = 'Changes older than the retention period have already been deleted from Entra, so they cannot appear in this report.'
            $retentionAction = 'Use 7 days on Entra ID Free or up to 30 days with P1/P2 (-RecentChangeDays), and search your exported logs (Log Analytics, SIEM, storage or Purview) for longer periods.'
        }
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title $retentionTitle `
            -Evidence $retentionEvidence `
            -WhyItMatters $retentionWhy `
            -RecommendedAction $retentionAction `
            -DocumentationUrl $retentionDocumentation `
            -SourceFile $retentionSource -ResultRows $retentionRows -RuleId 'critical-change-retention-incomplete' -ObjectType 'tenant' -CoverageGap
    }

    # Directory writes that the PIM service itself makes (initiator = the Microsoft
    # first-party "MS-PIM" app) carry out an activation, expiry or PIM assignment whose own
    # PIM audit event, with the real human initiator, is in the same result set. Such a
    # write is listed but not counted ONLY when (a) the initiator is verified as MS-PIM by
    # appId or service-principal id (never by display name, which any app registration
    # could copy) and (b) a PIM-service event for the same target exists within 15
    # minutes. Anything that cannot be matched both ways is counted as a change
    # (fail-safe). This is the same rule the recentchanges check uses.
    $msPimAppId = '01fc33a7-78ba-4d2f-a4b7-768e336e890e'
    $pimServiceTimes = @{}
    $needsPimSpLookup = $false
    foreach ($auditEvent in $events) {
        $eventCategory = [string](Get-EAApplicationCheckValue $auditEvent 'category')
        if ($eventCategory -eq 'RoleManagement' -and -not $needsPimSpLookup) {
            $initiatorApp = Get-EAApplicationCheckValue (Get-EAApplicationCheckValue $auditEvent 'initiatedBy') 'app'
            if ($initiatorApp -and -not [string](Get-EAApplicationCheckValue $initiatorApp 'appId') -and [string](Get-EAApplicationCheckValue $initiatorApp 'servicePrincipalId')) {
                $needsPimSpLookup = $true
            }
        }
        if ([string](Get-EAApplicationCheckValue $auditEvent 'loggedByService') -notmatch '(?i)^(PIM|Privileged Identity Management)$') { continue }
        $eventTime = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $auditEvent 'activityDateTime')
        if (-not $eventTime) { continue }
        foreach ($target in @(Get-EAApplicationCheckElement $auditEvent 'targetResources')) {
            $targetId = [string](Get-EAApplicationCheckValue $target 'id')
            if (-not $targetId -or [string](Get-EAApplicationCheckValue $target 'type') -eq 'Role') { continue }
            if (-not $pimServiceTimes.ContainsKey($targetId)) { $pimServiceTimes[$targetId] = New-Object System.Collections.Generic.List[datetime] }
            $pimServiceTimes[$targetId].Add($eventTime) | Out-Null
        }
    }
    # Only an initiator without an appId needs its service-principal id resolved.
    $msPimSpIds = @{}
    $pimLookupNote = $null
    if ($needsPimSpLookup -and $pimServiceTimes.Count -gt 0) {
        foreach ($cachedSp in $script:SpsCache) {
            if ($null -ne $cachedSp -and [string](Get-EAApplicationCheckValue $cachedSp 'AppId') -eq $msPimAppId) {
                $cachedSpId = [string](Get-EAApplicationCheckValue $cachedSp 'Id')
                if ($cachedSpId) { $msPimSpIds[$cachedSpId] = $true }
            }
        }
        if ($msPimSpIds.Count -eq 0) {
            try {
                $pimSpUri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=' + [uri]::EscapeDataString("appId eq '$msPimAppId'") + '&$select=id,appId'
                foreach ($pimSp in @(Get-EAReadOnlyGraphCollection -Uri $pimSpUri -MaximumPages 5)) {
                    $pimSpId = [string](Get-EAApplicationCheckValue $pimSp 'id')
                    if ($pimSpId) { $msPimSpIds[$pimSpId] = $true }
                }
            } catch {
                $pimLookupNote = ("The PIM service principal could not be looked up, so directory writes by the PIM service that carry only a service-principal id are counted as role changes: {0}" -f $_.Exception.Message)
            }
        }
    }
    $hasPimServiceTwin = {
        param($AuditEvent)
        $eventTime = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $AuditEvent 'activityDateTime')
        if (-not $eventTime) { return $false }
        foreach ($target in @(Get-EAApplicationCheckElement $AuditEvent 'targetResources')) {
            $targetId = [string](Get-EAApplicationCheckValue $target 'id')
            if (-not $targetId -or [string](Get-EAApplicationCheckValue $target 'type') -eq 'Role' -or -not $pimServiceTimes.ContainsKey($targetId)) { continue }
            foreach ($pimTime in $pimServiceTimes[$targetId]) {
                if ([math]::Abs(($pimTime - $eventTime).TotalMinutes) -le 15) { return $true }
            }
        }
        return $false
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($auditEvent in $events) {
        $classification = Get-EAChangeMonitoringClassification -AuditEvent $auditEvent
        if (-not $classification) { continue }
        $initiator = Get-EAChangeMonitoringInitiator -AuditEvent $auditEvent
        $targets = @()
        $targetTypes = @()
        $modifiedNames = @()
        foreach ($target in @(Get-EAApplicationCheckElement $auditEvent 'targetResources')) {
            $targetName = [string](@(
                Get-EAApplicationCheckValue $target 'userPrincipalName'
                Get-EAApplicationCheckValue $target 'displayName'
                Get-EAApplicationCheckValue $target 'id'
            ) | Where-Object { $_ } | Select-Object -First 1)
            if ($targetName) { $targets += $targetName }
            $targetType = [string](Get-EAApplicationCheckValue $target 'type')
            if ($targetType) { $targetTypes += $targetType }
            foreach ($property in @(Get-EAApplicationCheckElement $target 'modifiedProperties')) {
                $propertyName = [string](Get-EAApplicationCheckValue $property 'displayName')
                if ($propertyName) { $modifiedNames += $propertyName }
            }
        }
        $pimServiceWrite = $false
        if ($classification.Domain -eq 'Privileged role' -and $initiator.Type -eq 'Application' -and
            [string](Get-EAApplicationCheckValue $auditEvent 'category') -eq 'RoleManagement') {
            $initiatorApp = Get-EAApplicationCheckValue (Get-EAApplicationCheckValue $auditEvent 'initiatedBy') 'app'
            $initiatorAppId = [string](Get-EAApplicationCheckValue $initiatorApp 'appId')
            $initiatorSpId = [string](Get-EAApplicationCheckValue $initiatorApp 'servicePrincipalId')
            $isMsPim = ($initiatorAppId -eq $msPimAppId) -or ($initiatorSpId -and $msPimSpIds.ContainsKey($initiatorSpId))
            if ($isMsPim -and (& $hasPimServiceTwin $auditEvent)) { $pimServiceWrite = $true }
        }
        $result = [string](Get-EAApplicationCheckValue $auditEvent 'result')
        $success = ($result -match '^(?i:success)$')
        $reviewPriority = if ($classification.Activation) { 'Activation' } `
            elseif ($pimServiceWrite) { 'PIM service write' } `
            elseif ($classification.HighRisk -and $success) { 'High' } `
            elseif ($classification.HighRisk) { 'AttemptedHigh' } `
            else { 'Standard' }
        $rows.Add([pscustomobject]@{
            ActivityDateTime=ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $auditEvent 'activityDateTime')
            Domain=$classification.Domain; ReviewPriority=$reviewPriority
            Activity=[string](Get-EAApplicationCheckValue $auditEvent 'activityDisplayName')
            Category=[string](Get-EAApplicationCheckValue $auditEvent 'category')
            OperationType=[string](Get-EAApplicationCheckValue $auditEvent 'operationType')
            Result=$result; ResultReason=[string](Get-EAApplicationCheckValue $auditEvent 'resultReason')
            InitiatorType=$initiator.Type; Initiator=$initiator.Name; InitiatorId=$initiator.Id
            Targets=($targets | Select-Object -Unique) -join ', '
            TargetTypes=($targetTypes | Select-Object -Unique) -join ', '
            ModifiedProperties=($modifiedNames | Select-Object -Unique) -join ', '
            CorrelationId=[string](Get-EAApplicationCheckValue $auditEvent 'correlationId')
            ClassificationReason=if ($pimServiceWrite) { 'A directory write the PIM service made to carry out an activation or PIM assignment that has its own PIM event (listed, not counted).' } else { $classification.Reason }
        }) | Out-Null
    }

    $resultRows = @($rows.ToArray())
    $changeNotes = @(
        ("Scanned {0}; retained {1} in the requested change families." -f (Format-EAApplicationCheckCount -Count $events.Count -One 'directory audit event' -Many 'directory audit events'), (Format-EAApplicationCheckCount -Count $resultRows.Count -One 'event' -Many 'events')),
        'ReviewPriority is a triage label, not a claim that a change was malicious. High = successful security-sensitive change (counted); AttemptedHigh = the same, but it did not succeed (counted); Standard = group owner/member change, a user or group app access assignment, or a user''s own sign-in method change; Activation = just-in-time activation, deactivation or expiry of an eligible admin role in Privileged Identity Management (PIM), listed only; PIM service write = directory write the PIM service made for an activation or PIM assignment that has its own PIM event, listed only.'
    )
    if ($pimLookupNote) { $changeNotes += $pimLookupNote }
    $source = Write-Evidence -BaseName 'critical_directory_changes' -Rows $resultRows `
        -Title ("Critical Identity and Access Changes (requested last {0} days; subject to native retention)" -f $recentDays) `
        -Notes $changeNotes

    $successfulHigh = @($resultRows | Where-Object { $_.ReviewPriority -eq 'High' })
    $successfulStandard = @($resultRows | Where-Object { $_.ReviewPriority -eq 'Standard' -and $_.Domain -in @('Group owner or membership','App access assignment') -and $_.Result -match '^(?i:success)$' })
    $groupAccessChanges = @($successfulStandard | Where-Object { $_.Domain -eq 'Group owner or membership' })
    $appAccessChanges = @($successfulStandard | Where-Object { $_.Domain -eq 'App access assignment' })
    $userRegistrations = @($resultRows | Where-Object { $_.Domain -eq 'User authentication registration' })
    $attemptedHigh = @($resultRows | Where-Object { $_.ReviewPriority -eq 'AttemptedHigh' })
    $activations = @($resultRows | Where-Object { $_.ReviewPriority -eq 'Activation' })
    $pimServiceWrites = @($resultRows | Where-Object { $_.ReviewPriority -eq 'PIM service write' })
    $countSummary = {
        param([object[]]$ChangeRows, [string]$Property)
        (@($ChangeRows | Group-Object $Property | Sort-Object Count -Descending | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count }) | Select-Object -First 10) -join ', '
    }
    $activationNote = if ($activations.Count + $pimServiceWrites.Count -gt 0) { ' Just-in-time PIM role activations are listed separately and not counted here.' } else { '' }

    if ($successfulHigh.Count -gt 0) {
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $successfulHigh.Count -One 'security-sensitive admin change was made and should be confirmed' -Many 'security-sensitive admin changes were made and should be confirmed') `
            -Evidence ("Changes by area: {0}. Made by: {1}.{2}" -f (& $countSummary $successfulHigh 'Domain'), (& $countSummary $successfulHigh 'Initiator'), $activationNote) `
            -WhyItMatters 'Changes to admin roles, Conditional Access, sign-in methods, federation, app credentials or consent are also how attackers take over or keep access. Each change should match an approved request.' `
            -RecommendedAction ("Match each change in the evidence list to an approved change request, and investigate any made by a person or app you did not expect ({0})." -f $auditLogPath) `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs' `
            -SourceFile $source -ResultRows $successfulHigh -RuleId 'recent-high-risk-directory-change' -ObjectType 'auditEvent'
    }
    if ($successfulStandard.Count -gt 0) {
        $standardTitle = if ($appAccessChanges.Count -eq 0) {
            Format-EAApplicationCheckCount -Count $successfulStandard.Count -One 'group owner or member change was made and may have changed access' -Many 'group owner or member changes were made and may have changed access'
        } elseif ($groupAccessChanges.Count -eq 0) {
            Format-EAApplicationCheckCount -Count $successfulStandard.Count -One 'user or group was given or lost access to an enterprise app' -Many 'users or groups were given or lost access to enterprise apps'
        } else {
            Format-EAApplicationCheckCount -Count $successfulStandard.Count -One 'group membership or app access change was made and may have changed access' -Many 'group membership or app access changes were made and may have changed access'
        }
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title $standardTitle `
            -Evidence ("Successful changes in the last {0} days: {1} to group owners or members, {2} to which users or groups can use an enterprise app (app assignments). Made by: {3}." -f $recentDays, $groupAccessChanges.Count, $appAccessChanges.Count, (& $countSummary $successfulStandard 'Initiator')) `
            -WhyItMatters 'Groups can grant admin roles and app access, and an app assignment lets a person or group use that app, so these changes can give someone more access than it seems.' `
            -RecommendedAction ("Check each change against the purpose of the group or app, starting with groups that grant admin roles or app access and apps that hold sensitive data ({0})." -f $auditLogPath) `
            -SourceFile $source -ResultRows $successfulStandard -RuleId 'recent-group-access-change' -ObjectType 'auditEvent'
    }
    if ($attemptedHigh.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $attemptedHigh.Count -One 'security-sensitive admin change was attempted but did not succeed' -Many 'security-sensitive admin changes were attempted but did not succeed') `
            -Evidence ("Failed attempts by area: {0}. Attempted by: {1}." -f (& $countSummary $attemptedHigh 'Domain'), (& $countSummary $attemptedHigh 'Initiator')) `
            -WhyItMatters 'Failed attempts to change roles, security policies or app credentials can mean someone is probing for access, or that an old script is still running with the wrong rights.' `
            -RecommendedAction 'Find out who or what made each attempt and why it failed, and set up alerts for repeated failures or unexpected apps.' `
            -SourceFile $source -ResultRows $attemptedHigh -RuleId 'attempted-high-risk-directory-change' -ObjectType 'auditEvent'
    }
    if ($userRegistrations.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $userRegistrations.Count -One 'user self-service sign-in method (MFA) change was recorded' -Many 'user self-service sign-in method (MFA) changes were recorded') `
            -Evidence ("{0} their own sign-in methods (for example MFA, passkeys, Windows Hello, or password-reset info). These are listed for reference and are not counted as high-risk changes." -f (Format-EAApplicationCheckCount -Count (@($userRegistrations.Initiator | Select-Object -Unique).Count) -One 'user added, changed, or removed' -Many 'users added, changed, or removed')) `
            -WhyItMatters 'Users normally register and update their own MFA methods. A method added by an attacker who already has a user''s password is a warning sign, so unexpected entries are worth a look.' `
            -RecommendedAction 'Spot-check registrations for privileged users and for accounts with recent risky sign-ins. Ask the user to confirm any change they did not make.' `
            -SourceFile $source -ResultRows $userRegistrations -RuleId 'recent-user-auth-method-registration' -ObjectType 'auditEvent'
    }
    if ($activations.Count -gt 0 -or $pimServiceWrites.Count -gt 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count ($activations.Count + $pimServiceWrites.Count) -One 'just-in-time admin role (PIM) event was recorded - listed for review, not scored' -Many 'just-in-time admin role (PIM) events were recorded - listed for review, not scored') `
            -Evidence ("{0} by: {1}. {2} the PIM service made to carry out PIM activations or assignments that already have their own PIM event." -f (Format-EAApplicationCheckCount -Count $activations.Count -One 'role activation, deactivation or expiry event' -Many 'role activation, deactivation or expiry events'),
                $(if ($activations.Count -gt 0) { & $countSummary $activations 'Initiator' } else { 'none' }), (Format-EAApplicationCheckCount -Count $pimServiceWrites.Count -One 'directory write' -Many 'directory writes')) `
            -WhyItMatters 'Turning on an eligible admin role only when it is needed is the recommended way to use admin rights with Privileged Identity Management (PIM). An activation nobody expected can still point to a misused account.' `
            -RecommendedAction 'Spot-check activations of highly privileged roles such as Global Administrator, and ask the person to confirm any you cannot explain (Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles > Resource audit).' `
            -SourceFile $source -ResultRows @($activations + $pimServiceWrites) -RuleId 'changemonitoring-pim-activations' -ObjectType 'tenant'
    }
    $countedRows = @($resultRows | Where-Object { $_.ReviewPriority -notin @('Activation','PIM service write') -and $_.Domain -ne 'User authentication registration' })
    if ($countedRows.Count -eq 0) {
        $listedOnly = @()
        if ($activations.Count + $pimServiceWrites.Count -gt 0) { $listedOnly += (Format-EAApplicationCheckCount -Count ($activations.Count + $pimServiceWrites.Count) -One 'PIM role activation event' -Many 'PIM role activation events') }
        if ($userRegistrations.Count -gt 0) { $listedOnly += (Format-EAApplicationCheckCount -Count $userRegistrations.Count -One 'user self-service sign-in method change' -Many 'user self-service sign-in method changes') }
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title ("No security-sensitive changes were found in the last {0} days" -f $recentDays) `
            -Evidence ("The directory audit log was read completely: {0} scanned and none was a role, Conditional Access, sign-in method policy, federation, app credential or owner, consent, group owner/member, or app access assignment change.{1}" -f (Format-EAApplicationCheckCount -Count $events.Count -One 'event was' -Many 'events were'),
                $(if ($listedOnly.Count -gt 0) { " Listed separately, not counted: {0}." -f ($listedOnly -join ' and ') } else { '' })) `
            -WhyItMatters 'A complete read with no matching events means no such change is recorded for the period Entra still keeps. A separate finding says so if that period is shorter than requested.' `
            -RecommendedAction 'Keep reviewing regularly, and set up alerts for these kinds of changes so they are seen when they happen.' `
            -SourceFile $source -ResultRows $resultRows -RuleId 'changemonitoring-no-critical-changes' -ObjectType 'tenant'
    }
}
