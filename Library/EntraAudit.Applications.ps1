<#
EntraAudit shared definitions. Dot-source from the runner so script-scoped state is shared.
Do not execute check files with &: that creates a different script scope.
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

function Get-EACredentialRestrictionAssessment {
    # A custom restriction replaces the same default restriction, including an explicit
    # disabled state. Missing custom restrictions inherit the default. These policies
    # govern credential creation/update; they do not revoke existing credentials.
    param([object]$Restriction, [object]$PolicyEnabled, [datetime]$Created,
        [bool]$CreatedKnown, [int]$MaximumDays, [string]$PolicyName)

    $state = 'Unprotected'; $reason = 'No applicable restriction is configured'; $days = $null
    if ($null -eq $PolicyEnabled) { $state='Unknown'; $reason='Policy enabled state could not be established' }
    elseif (-not $PolicyEnabled) { $reason='Policy is disabled' }
    elseif ($null -ne $Restriction) {
        $restrictionState = [string](Get-EAApplicationCheckValue $Restriction 'state')
        $cutoffValue = Get-EAApplicationCheckValue $Restriction 'restrictForAppsCreatedAfterDateTime'
        $cutoff = ConvertTo-EAApplicationCheckUtcDate $cutoffValue
        $actorExemptions = Get-EAApplicationCheckValue $Restriction 'excludeActors'
        $exemptions = @(Get-EAApplicationCheckElement $actorExemptions 'customSecurityAttributes')
        if ($restrictionState -eq 'disabled') { $reason='Restriction is explicitly disabled' }
        elseif ($restrictionState -ne 'enabled') { $state='Unknown'; $reason='Restriction enabled state could not be established' }
        elseif ($null -ne $cutoffValue -and -not $cutoff) { $state='Unknown'; $reason='Restriction creation-date cutoff is invalid' }
        elseif ($cutoff -and -not $CreatedKnown) { $state='Unknown'; $reason='Object creation date is unavailable, so applicability is unknown' }
        elseif ($cutoff -and $Created -lt $cutoff) { $reason=('Object predates the restriction cutoff {0:yyyy-MM-dd}' -f $cutoff) }
        elseif ($exemptions.Count -gt 0) { $state='Unknown'; $reason='Actor exemptions permit some callers to bypass this restriction; exempt actors were not enumerated' }
        elseif ([string](Get-EAApplicationCheckValue $Restriction 'restrictionType') -in @('passwordAddition','symmetricKeyAddition')) {
            $state='Protected'; $reason='Creation of this credential type is blocked'
        } else {
            $days = ConvertTo-EAApplicationCheckDurationDays (Get-EAApplicationCheckValue $Restriction 'maxLifetime')
            if ($null -eq $days -or $days -le 0) { $state='Unknown'; $reason='Maximum credential lifetime is missing or invalid' }
            elseif ($days -gt $MaximumDays) { $reason=('Maximum lifetime {0} days exceeds the audit limit of {1} days' -f $days,$MaximumDays) }
            else { $state='Protected'; $reason=('Maximum lifetime is {0} days' -f $days) }
        }
    }
    [pscustomobject]@{ State=$state; Reason=$reason; Policy=$PolicyName; MaximumLifetimeDays=$days }
}

function Get-EAEffectiveCredentialPolicyRows {
    param([object[]]$Applications, [object[]]$ServicePrincipals, [object]$DefaultPolicy,
        [object[]]$CustomPolicies, [hashtable]$PolicyAssignments=@{}, [bool]$AssignmentsKnown=$true,
        [string]$TenantId, [int]$SecretMaximumDays=180, [int]$CertificateMaximumDays=730)

    $customByObject = @{}
    foreach ($policy in @($CustomPolicies)) {
        $policyId = [string](Get-EAApplicationCheckValue $policy 'id')
        if (-not $policyId -or -not $PolicyAssignments.ContainsKey($policyId)) { continue }
        foreach ($objectId in @($PolicyAssignments[$policyId])) {
            if (-not $customByObject.ContainsKey([string]$objectId)) { $customByObject[[string]$objectId] = @() }
            $customByObject[[string]$objectId] += $policy
        }
    }
    $localAppIds = @{}
    $objects = [System.Collections.Generic.List[object]]::new()
    foreach ($application in @($Applications)) {
        $appId = [string](Get-EAApplicationCheckValue $application 'appId')
        if ($appId) { $localAppIds[$appId] = $true }
        $objects.Add([pscustomobject]@{ Object=$application; Type='Application'; Scope='applicationRestrictions'; ApplicabilityKnown=$true })
    }
    foreach ($sp in @($ServicePrincipals)) {
        $appId = [string](Get-EAApplicationCheckValue $sp 'appId')
        # Local app registrations are governed on the application object. Applying the
        # service-principal defaults to their backing SP would create duplicate gaps.
        if ($appId -and $localAppIds.ContainsKey($appId)) { continue }
        $ownerTenant = [string](Get-EAApplicationCheckValue $sp 'appOwnerOrganizationId')
        $known = [bool]($TenantId -and $ownerTenant -and $ownerTenant -ne $TenantId)
        $objects.Add([pscustomobject]@{ Object=$sp; Type='ServicePrincipal'; Scope='servicePrincipalRestrictions'; ApplicabilityKnown=$known })
    }
    foreach ($entry in $objects) {
        $object = $entry.Object
        $objectId = [string](Get-EAApplicationCheckValue $object 'id')
        $created = ConvertTo-EAApplicationCheckUtcDate (Get-EAApplicationCheckValue $object 'createdDateTime')
        $linked = @($customByObject[$objectId] | Where-Object { $_ })
        $defaultEnabled = ConvertTo-EAApplicationCheckBoolean (Get-EAApplicationCheckValue $DefaultPolicy 'isEnabled')
        $defaultConfig = Get-EAApplicationCheckValue $DefaultPolicy $entry.Scope
        $custom = if ($linked.Count -eq 1) { $linked[0] } else { $null }
        $customEnabled = if ($custom) { ConvertTo-EAApplicationCheckBoolean (Get-EAApplicationCheckValue $custom 'isEnabled') } else { $false }
        $customConfig = Get-EAApplicationCheckValue $custom 'restrictions'
        foreach ($spec in @(
            @{ Name='Secret'; Property='passwordCredentials'; Types=@('passwordAddition','passwordLifetime'); Limit=$SecretMaximumDays },
            @{ Name='SymmetricKey'; Property='passwordCredentials'; Types=@('symmetricKeyAddition','symmetricKeyLifetime'); Limit=$SecretMaximumDays },
            @{ Name='Certificate'; Property='keyCredentials'; Types=@('asymmetricKeyLifetime'); Limit=$CertificateMaximumDays }
        )) {
            $assessments = @()
            foreach ($restrictionType in $spec.Types) {
                $defaultMatches = @(Get-EAApplicationCheckElement $defaultConfig $spec.Property | Where-Object { [string](Get-EAApplicationCheckValue $_ 'restrictionType') -eq $restrictionType })
                $customMatches = @(Get-EAApplicationCheckElement $customConfig $spec.Property | Where-Object { [string](Get-EAApplicationCheckValue $_ 'restrictionType') -eq $restrictionType })
                $matches = $defaultMatches; $enabled=$defaultEnabled; $policyName='Tenant default'
                if ($custom -and $customEnabled -ne $false -and $customMatches.Count -gt 0) {
                    $matches=$customMatches; $enabled=$customEnabled
                    $policyName='Custom: ' + [string](Get-EAApplicationCheckValue $custom 'displayName')
                }
                if ($matches.Count -gt 1) {
                    $assessments += [pscustomobject]@{ State='Unknown'; Reason='Duplicate restriction definitions'; Policy=$policyName; MaximumLifetimeDays=$null }
                } else {
                    $assessments += Get-EACredentialRestrictionAssessment -Restriction ($matches | Select-Object -First 1) -PolicyEnabled $enabled `
                        -Created $(if ($created) { $created } else { [datetime]::MinValue }) -CreatedKnown ([bool]$created) -MaximumDays $spec.Limit -PolicyName $policyName
                }
            }
            $protected = @($assessments | Where-Object State -eq 'Protected')
            $unknown = @($assessments | Where-Object State -eq 'Unknown')
            $state = if ($protected.Count -gt 0) { 'Protected' } elseif ($unknown.Count -gt 0) { 'Unknown' } else { 'Unprotected' }
            $reasons = @($assessments | ForEach-Object { '{0}: {1}' -f $_.Policy,$_.Reason })
            if (-not $objectId -or -not $AssignmentsKnown -or $linked.Count -gt 1 -or -not $entry.ApplicabilityKnown -or ($custom -and $null -eq $customEnabled)) {
                $state='Unknown'
                $reasons = @($(if (-not $objectId) { 'Object id is missing, so assigned custom policies cannot be established' }
                    elseif (-not $AssignmentsKnown) { 'Custom policy assignments could not be fully read' }
                    elseif ($linked.Count -gt 1) { 'More than one custom policy was linked to the object' }
                    elseif (-not $entry.ApplicabilityKnown) { 'Home tenant is unknown, so the applicable policy object could not be established' }
                    else { 'Assigned custom policy enabled state is unknown' }))
            }
            [pscustomobject]@{
                ObjectName=[string](Get-EAApplicationCheckValue $object 'displayName'); ObjectId=$objectId
                AppId=[string](Get-EAApplicationCheckValue $object 'appId'); ObjectType=$entry.Type
                CreatedDateTime=$created; CredentialType=$spec.Name; State=$state
                CustomPolicy=([string](Get-EAApplicationCheckValue $custom 'displayName'))
                AuditMaximumDays=$spec.Limit; Reason=($reasons -join '; ')
            }
        }
    }
}

function Get-EAApplicationAuthenticationRows {
    param([object[]]$Applications)

    foreach ($application in @($Applications)) {
        $web = Get-EAApplicationCheckValue $application 'web'
        $spa = Get-EAApplicationCheckValue $application 'spa'
        $public = Get-EAApplicationCheckValue $application 'publicClient'
        $implicit = Get-EAApplicationCheckValue $web 'implicitGrantSettings'
        $fallback = ConvertTo-EAApplicationCheckBoolean (Get-EAApplicationCheckValue $application 'isFallbackPublicClient')
        $api = Get-EAApplicationCheckValue $application 'api'
        $webUris = @(Get-EAApplicationCheckElement $web 'redirectUris')
        $spaUris = @(Get-EAApplicationCheckElement $spa 'redirectUris')
        $publicUris = @(Get-EAApplicationCheckElement $public 'redirectUris')
        $issues = [System.Collections.Generic.List[string]]::new()
        $review = [System.Collections.Generic.List[string]]::new()
        foreach ($uriText in @($webUris + $spaUris + $publicUris)) {
            $uri = $null
            if ([string]$uriText -match '\*') { $issues.Add('Wildcard redirect URI: ' + $uriText) }
            if (-not [uri]::TryCreate([string]$uriText,[UriKind]::Absolute,[ref]$uri)) { $issues.Add('Invalid redirect URI: ' + $uriText); continue }
            # Loopback HTTP and custom URI schemes are supported native-client designs.
            # Keep them visible without labelling every desktop/mobile app insecure.
            if ($uri.Scheme -eq 'http' -and -not $uri.IsLoopback) { $issues.Add('Non-loopback HTTP redirect URI: ' + $uriText) }
            elseif ($uri.Scheme -eq 'http' -and $uri.IsLoopback) { $review.Add('Loopback redirect: valid for native/development clients; confirm intended use') }
            elseif ($uri.Scheme -notin @('http','https') -and @($publicUris) -notcontains $uriText) { $review.Add('Non-HTTPS web/SPA redirect requires owner validation: ' + $uriText) }
        }
        $implicitAccess = ConvertTo-EAApplicationCheckBoolean (Get-EAApplicationCheckValue $implicit 'enableAccessTokenIssuance')
        if ($implicitAccess -eq $true) { $issues.Add('Implicit access-token issuance is enabled') }
        $hasCredential = (@(Get-EAApplicationCheckElement $application 'passwordCredentials').Count + @(Get-EAApplicationCheckElement $application 'keyCredentials').Count) -gt 0
        if ($fallback -eq $true) { $review.Add('Fallback public-client flow is enabled; confirm the intended desktop, device-code or password flow') }
        if ($hasCredential -and $publicUris.Count -gt 0 -and $webUris.Count -eq 0) { $review.Add('Native/public-client registration has credentials; confirm no secret is distributed in a client') }
        $unknown = @()
        if ($null -eq $web -or $null -eq $spa -or $null -eq $public) { $unknown += 'One or more platform settings were not returned' }
        if ($web -and $null -eq $implicitAccess) { $unknown += 'Implicit access-token issuance state was not returned' }
        [pscustomobject]@{
            Application=[string](Get-EAApplicationCheckValue $application 'displayName'); ObjectId=[string](Get-EAApplicationCheckValue $application 'id')
            AppId=[string](Get-EAApplicationCheckValue $application 'appId'); SignInAudience=[string](Get-EAApplicationCheckValue $application 'signInAudience')
            WebRedirectUris=($webUris -join '; '); SpaRedirectUris=($spaUris -join '; '); PublicClientRedirectUris=($publicUris -join '; ')
            ImplicitAccessTokens=$implicitAccess; FallbackPublicClient=$fallback
            IdentifierUris=(@(Get-EAApplicationCheckElement $application 'identifierUris') -join '; ')
            RequestedAccessTokenVersion=Get-EAApplicationCheckValue $api 'requestedAccessTokenVersion'
            Issues=($issues -join '; '); ReviewNotes=(@($review | Select-Object -Unique) -join '; ')
            CoverageGap=($unknown -join '; '); RedirectOwnership='Not verified; requires owner and DNS validation'
        }
    }
}

function Invoke-EAApplicationAuthenticationReview {
    param([object[]]$Applications, [string]$CheckId='workloadcredentials')
    $rows = @(Get-EAApplicationAuthenticationRows -Applications $Applications)
    $source = Write-Evidence -BaseName 'application_authentication_configuration' -Rows $rows -Title 'Application Authentication Configuration' `
        -Notes @('Redirect ownership and DNS validity are not established by Graph configuration. Loopback redirects and native client schemes are not automatically security failures. ID-token issuance alone may support valid hybrid authentication and is not treated as implicit access-token issuance.')
    foreach ($spec in @(
        @{ Field='Issues'; Severity='Medium'; Rule='application-authentication-configuration'; Title='Application sign-in configuration needs hardening'; Gap=$false; Why='Insecure redirect destinations and implicit access-token issuance can expose tokens or enable unintended access.'; Action='Review the listed app in Entra admin center > App registrations > Authentication. Replace non-loopback HTTP and wildcard redirects, remove obsolete destinations, and migrate implicit access tokens to authorization code with PKCE after testing.' },
        @{ Field='ReviewNotes'; Severity='Information'; Rule='application-authentication-context-review'; Title='Some application sign-in settings need owner confirmation'; Gap=$false; Why='Native client and mixed platform designs can be legitimate. Configuration alone cannot establish whether these flows or credentials are needed.'; Action='Confirm each listed flow and redirect with the app owner. Keep public-client secrets out of distributed clients and remove unused development redirects. No automatic failure is assigned to valid native-client designs.' },
        @{ Field='CoverageGap'; Severity='Information'; Rule='application-authentication-coverage-unknown'; Title='Application sign-in configuration could not be fully checked'; Gap=$true; Why='Missing platform properties can hide insecure redirects or enabled implicit flows.'; Action='Confirm Application.Read.All and re-run after resolving collection errors; inspect the application Authentication page until the missing fields can be read.' }
    )) {
        $affected = @($rows | Where-Object { $_.($spec.Field) })
        if ($affected.Count -eq 0) { continue }
        $population = if ($spec.Gap) {
            @{ UnknownCount=$affected.Count; PopulationLabel='app registrations with incomplete authentication configuration'; VerificationType='Collection' }
        } else {
            @{ AffectedObjectIds=@($affected.ObjectId | Where-Object { $_ } | Sort-Object -Unique); AffectedObjectType='application'; AffectedCount=$affected.Count; PopulationLabel='app registrations with the stated authentication configuration' }
        }
        if ($spec.Field -eq 'ReviewNotes') {
            $population.VerificationType = 'ManualTest'
            $population.VerificationSteps = 'Ask the application owner to confirm the supported client flows and redirect ownership; test the approved sign-in flows and record the result. Valid native-client settings may remain present after review.'
        }
        Add-EntraFinding -Severity $spec.Severity -CheckId $CheckId -Category 'Applications' -Title $spec.Title `
            -Evidence ("{0} app(s): {1}. See the affected rows for exact settings and reasons." -f $affected.Count,(Format-EAApplicationCheckList @($affected.Application))) `
            -WhyItMatters $spec.Why -RecommendedAction $spec.Action -SourceFile $source -ResultRows $affected `
            -RuleId $spec.Rule -ObjectType 'application' -CoverageGap:([bool]$spec.Gap) `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration' @population
    }
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
        $parameters = @{ ErrorAction='Stop' }
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
        $response = Invoke-AzRestMethod -Method GET @parameters
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
