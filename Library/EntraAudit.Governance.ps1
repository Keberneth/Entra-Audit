<#
EntraAudit shared definitions. Dot-source from the runner so script-scoped state is shared.
Do not execute check files with &: that creates a different script scope.
#>

function Get-EAGovProperty {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in @($InputObject.Keys)) {
            if ([string]$key -ieq $Name) { return $InputObject[$key] }
        }
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }

    $additional = $InputObject.PSObject.Properties['AdditionalProperties']
    if ($additional -and $additional.Value -is [System.Collections.IDictionary]) {
        foreach ($key in @($additional.Value.Keys)) {
            if ([string]$key -ieq $Name) { return $additional.Value[$key] }
        }
    }

    return $Default
}

function Test-EAGovPropertyPresent {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in @($InputObject.Keys)) {
            if ([string]$key -ieq $Name) { return $true }
        }
    }
    if ($null -ne $InputObject.PSObject.Properties[$Name]) { return $true }
    $additional = $InputObject.PSObject.Properties['AdditionalProperties']
    if ($additional -and $additional.Value -is [System.Collections.IDictionary]) {
        foreach ($key in @($additional.Value.Keys)) {
            if ([string]$key -ieq $Name) { return $true }
        }
    }
    return $false
}

function ConvertTo-EAGovArray {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

function ConvertTo-EAGovDateTime {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetimeoffset]) { return $Value }
    if ($Value -is [datetime]) {
        $utc = if ($Value.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }
        return [datetimeoffset]$utc
    }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { return $parsed }
    return $null
}

function Format-EAGovDateTime {
    param([AllowNull()]$Value)
    $d = ConvertTo-EAGovDateTime $Value
    if ($null -eq $d) { return $null }
    return $d.UtcDateTime.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function ConvertTo-EAGovCompactJson {
    param([AllowNull()]$Value, [int]$Depth = 12)
    if ($null -eq $Value) { return '' }
    try { return ($Value | ConvertTo-Json -Depth $Depth -Compress) }
    catch { return [string]$Value }
}

function Get-EAGovExceptionStatusCode {
    param([AllowNull()]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return $null }
    # Do not walk nested exception properties directly.  Callers can enable
    # StrictMode before invoking the audit, and many PowerShell exceptions don't
    # expose Response/StatusCode at all.
    $exception = Get-EAGovProperty -InputObject $ErrorRecord -Name 'Exception'
    $response = Get-EAGovProperty -InputObject $exception -Name 'Response'
    $responseStatus = Get-EAGovProperty -InputObject $response -Name 'StatusCode'
    $exceptionStatus = Get-EAGovProperty -InputObject $exception -Name 'StatusCode'
    foreach ($candidate in @(
        (Get-EAGovProperty -InputObject $responseStatus -Name 'value__'),
        $responseStatus,
        (Get-EAGovProperty -InputObject $exceptionStatus -Name 'value__'),
        $exceptionStatus
    )) {
        if ($null -eq $candidate) { continue }
        try { return [int]$candidate } catch {}
    }
    return $null
}

function Invoke-EAGovGraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateRange(1, 5000)][int]$MaxPages = 500,
        [hashtable]$Headers
    )

    if ($Uri -notmatch '^https://graph\.microsoft\.com/(v1\.0|beta)/') {
        throw "Refusing non-Microsoft-Graph URI: $Uri"
    }

    $rows = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $pages = 0
    try {
        while ($next -and $pages -lt $MaxPages) {
            if ([string]$next -notmatch '^https://graph\.microsoft\.com/(v1\.0|beta)/') {
                throw "Refusing non-Microsoft-Graph pagination URI: $next"
            }
            $request = @{ Uri = $next; ErrorAction = 'Stop' }
            if ($Headers) { $request.Headers = $Headers }
            $response = Invoke-MgGraphRequest -Method GET @request
            $valuePresent = Test-EAGovPropertyPresent -InputObject $response -Name 'value'
            if (-not $valuePresent) {
                throw 'Microsoft Graph collection response did not contain a value array.'
            }
            foreach ($item in @(Get-EAGovProperty -InputObject $response -Name 'value')) {
                if ($null -ne $item) { $rows.Add($item) | Out-Null }
            }
            $next = [string](Get-EAGovProperty -InputObject $response -Name '@odata.nextLink')
            $pages++
        }
        # Hitting the page safety limit is a partial read, not a failure: return the
        # rows read so far with Truncated=$true so callers emit their pagination
        # coverage finding instead of treating the partial set as complete.
        $truncated = [bool]$next

        return [pscustomobject]@{
            Success   = $true
            Rows      = $rows.ToArray()
            Pages     = $pages
            Truncated = $truncated
            Error     = $null
            StatusCode = 200
        }
    } catch {
        return [pscustomobject]@{
            Success   = $false
            Rows      = $rows.ToArray()
            Pages     = $pages
            Truncated = $false
            Error     = $_
            StatusCode = (Get-EAGovExceptionStatusCode -ErrorRecord $_)
        }
    }
}

function ConvertTo-EAGovBoolean {
    param([AllowNull()]$Value)
    if ($Value -is [bool]) { return $Value }
    if ($null -eq $Value) { return $null }
    $parsed = $false
    if ([bool]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
    return $null
}

function ConvertTo-EAGovSettingMap {
    param([AllowNull()]$Setting)
    $map = @{}
    foreach ($entry in @(Get-EAGovProperty $Setting 'values')) {
        $name = [string](Get-EAGovProperty $entry 'name')
        if ($name) { $map[$name] = Get-EAGovProperty $entry 'value' }
    }
    return $map
}

function Merge-EAGovSettingMap {
    param(
        [AllowNull()]$Template,
        [AllowNull()]$Setting
    )
    $map = @{}
    foreach ($entry in @(Get-EAGovProperty $Template 'values')) {
        $name = [string](Get-EAGovProperty $entry 'name')
        if ($name) { $map[$name] = Get-EAGovProperty $entry 'defaultValue' }
    }
    foreach ($entry in @(Get-EAGovProperty $Setting 'values')) {
        $name = [string](Get-EAGovProperty $entry 'name')
        if ($name) { $map[$name] = Get-EAGovProperty $entry 'value' }
    }
    return $map
}

function Invoke-EAGovGraphObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers
    )

    if ($Uri -notmatch '^https://graph\.microsoft\.com/(v1\.0|beta)/') {
        throw "Refusing non-Microsoft-Graph URI: $Uri"
    }
    try {
        $request = @{ Uri = $Uri; ErrorAction = 'Stop' }
        if ($Headers) { $request.Headers = $Headers }
        $response = Invoke-MgGraphRequest -Method GET @request
        return [pscustomobject]@{ Success=$true; Value=$response; Error=$null; StatusCode=200 }
    } catch {
        return [pscustomobject]@{
            Success=$false
            Value=$null
            Error=$_
            StatusCode=(Get-EAGovExceptionStatusCode -ErrorRecord $_)
        }
    }
}

function Add-EAGovFinding {
    param(
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$WhyItMatters,
        [Parameter(Mandatory)][string]$RecommendedAction,
        [Parameter(Mandatory)][string]$DocumentationUrl,
        [AllowNull()][string]$SourceFile,
        [AllowNull()][string]$AffectedPrincipal,
        [AllowNull()][object[]]$ResultRows,
        [AllowNull()][string]$RuleId,
        [AllowNull()][string]$ObjectType,
        [AllowNull()][string]$ObjectId,
        [switch]$CoverageGap,
        [string[]]$AffectedObjectIds, [string]$AffectedObjectType,
        [Nullable[int]]$AffectedCount, [Nullable[int]]$AssessedCount, [Nullable[int]]$UnknownCount,
        [string]$PopulationLabel,
        [ValidateSet('Configuration','HistoricalEvent','ManualTest','Collection')][string]$VerificationType,
        [string]$VerificationSteps
    )

    # The Microsoft reference travels only as its own field: the reports render it as a
    # link and Findings.json/.csv export it as a column, so it is no longer appended to
    # the RecommendedAction text. Actions end with a full stop like the main-script ones.
    $action = $RecommendedAction.Trim()
    if ($action -notmatch '[.!?]$') { $action += '.' }
    $parameters = @{
        Severity          = $Severity
        CheckId           = $CheckId
        Category          = $Category
        Title             = $Title
        Evidence          = $Evidence
        WhyItMatters      = $WhyItMatters
        RecommendedAction = $action
        DocumentationUrl  = $DocumentationUrl
        SourceFile        = $SourceFile
    }
    if ($AffectedPrincipal) { $parameters.AffectedPrincipal = $AffectedPrincipal }
    if ($null -ne $ResultRows) { $parameters.ResultRows = $ResultRows }
    if ($RuleId) { $parameters.RuleId = $RuleId }
    if ($ObjectType) { $parameters.ObjectType = $ObjectType }
    if ($ObjectId) { $parameters.ObjectId = $ObjectId }
    if ($CoverageGap) { $parameters.CoverageGap = $true }
    foreach ($name in @('AffectedObjectIds','AffectedObjectType','AffectedCount','AssessedCount','UnknownCount','PopulationLabel','VerificationType','VerificationSteps')) {
        if ($PSBoundParameters.ContainsKey($name)) { $parameters[$name] = $PSBoundParameters[$name] }
    }
    Add-EntraFinding @parameters
}

function Add-EAGovCoverageFinding {
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$DataSource,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][string]$RequiredScope,
        [Parameter(Mandatory)][string]$DocumentationUrl,
        [AllowNull()][string]$SourceFile,
        [AllowNull()][string]$Subject,
        [AllowNull()][string]$Impact,
        [switch]$Partial,
        [AllowNull()][string]$RecommendedAction,
        [AllowNull()][string]$ObjectType,
        [AllowNull()][string]$ObjectId,
        [AllowNull()][string]$AffectedPrincipal
    )

    $name = if ([string]::IsNullOrWhiteSpace($Subject)) { $DataSource } else { $Subject.Trim() }
    $sentenceName = if ($name.Length -gt 0) { $name.Substring(0, 1).ToUpperInvariant() + $name.Substring(1) } else { $name }
    $reasonText = ([string]$Reason).Trim()
    if ($reasonText -and $reasonText -notmatch '[.!?]$') { $reasonText += '.' }

    $title = if ($Partial) { "Only part of $name could be read" } else { "$sentenceName could not be read" }
    $evidence = if ($Partial) {
        "Data source: $DataSource. The read stopped early: $reasonText Only the part that was read was checked; this is a partial result, not a clean result."
    } else {
        "Data source: $DataSource. Reason: $reasonText This is an unknown result, not a clean result."
    }
    $why = if ([string]::IsNullOrWhiteSpace($Impact)) {
        'The audit could not check this part, so problems in it may be missing from this report. Treat it as not checked, not as clean.'
    } else {
        $impactText = $Impact.Trim()
        if ($impactText -notmatch '[.!?]$') { $impactText += '.' }
        "$impactText Treat this part as not checked, not as clean."
    }
    $action = if (-not [string]::IsNullOrWhiteSpace($RecommendedAction)) { $RecommendedAction }
        elseif ($Partial) { 'Review this area directly in the admin center, because the audit stopped reading after its page safety limit, then run the audit again to confirm' }
        else { "Make sure the audit account has $RequiredScope and the reader role or license this data needs, then run the audit again; if the evidence shows a different error, such as throttling, simply run it again" }

    Add-EAGovFinding -Severity 'Information' -CheckId $CheckId -Category $Category `
        -Title $title -Evidence $evidence -WhyItMatters $why -RecommendedAction $action `
        -DocumentationUrl $DocumentationUrl -SourceFile $SourceFile `
        -RuleId ("coverage-" + (($DataSource -replace '[^A-Za-z0-9]+','-').Trim('-').ToLowerInvariant())) `
        -ObjectType $ObjectType -ObjectId $ObjectId -AffectedPrincipal $AffectedPrincipal `
        -CoverageGap
}

function Get-EAGovOnPremisesSyncObject {
    $result = Invoke-EAGovGraphObject -Uri 'https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization'
    $object = $null
    $count = 0
    if ($result.Success) {
        $object = $result.Value
        if (Test-EAGovPropertyPresent $object 'value') {
            $items = @(Get-EAGovProperty $object 'value' | Where-Object { $null -ne $_ })
            $count = $items.Count
            $object = if ($count -gt 0) { $items[0] } else { $null }
        } elseif ($null -ne $object) {
            $count = 1
        }
    }
    [pscustomobject]@{ Success=$result.Success; Object=$object; Count=$count; Error=$result.Error; StatusCode=$result.StatusCode }
}

function Get-EAGovOnPremSyncAccess {
    [pscustomobject]@{
        Scope = 'OnPremDirectorySynchronization.Read.All (delegated only, signed in as a Global Administrator; app-only is not supported by Microsoft Graph for this API)'
        Note  = $(if ([string]$script:AuthType -eq 'AppOnly') { ' This run used an app-only sign-in, which Microsoft Graph does not support for this setting.' } else { '' })
    }
}

function Get-EAGovAccessReviewCategory {
    param([AllowNull()]$Definition)

    $scope = Get-EAGovProperty $Definition 'scope'
    $enumerationScope = Get-EAGovProperty $Definition 'instanceEnumerationScope'
    $scopeText = ((ConvertTo-EAGovCompactJson $scope) + ' ' + (ConvertTo-EAGovCompactJson $enumerationScope)).ToLowerInvariant()

    if ($scopeText -match 'roleassignmentscheduleinstances|rolemanagement/directory') { return 'PrivilegedRoles' }
    if ($scopeText -match 'accesspackageassignments|accesspackage') { return 'AccessPackages' }
    if ($scopeText -match 'inactiveuser|inactiveduration') { return 'InactiveUsers' }
    if ($scopeText -match "usertype(?:%20|\s)*eq(?:%20|\s)*(?:%27|')guest|guest") { return 'Guests' }
    if ($scopeText -match 'serviceprincipals|approleassignedto|applications') { return 'EnterpriseApps' }
    if ($scopeText -match '/groups|\.\/members') { return 'Groups' }
    return 'Other'
}

function ConvertFrom-EAGovDurationDays {
    param([AllowNull()]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return [math]::Round([System.Xml.XmlConvert]::ToTimeSpan([string]$Value).TotalDays, 1) }
    catch { return $null }
}

function Get-EAGovGdapCustomerLabel {
    param([AllowNull()]$Row)
    foreach ($name in @('CustomerDisplayName', 'CustomerTenantId')) {
        $candidate = [string](Get-EAGovProperty $Row $name)
        if (-not [string]::IsNullOrWhiteSpace($candidate)) { return $candidate.Trim() }
    }
    foreach ($name in @('DisplayName', 'Relationship')) {
        $candidate = [string](Get-EAGovProperty $Row $name)
        if (-not [string]::IsNullOrWhiteSpace($candidate)) { return ('relationship ' + $candidate.Trim()) }
    }
    return 'unknown customer'
}

function Get-EAGovDirectoryRoleRisk {
    # Classify a GDAP role through the main script's shared role model
    # (Get-EARoleDefMap/Get-EARoleInfo) so partner roles are tiered exactly like
    # directory roles elsewhere in the report: static fail-safe list, beta
    # isPrivileged, and any-write-action for custom roles.
    param([AllowNull()][string]$RoleDefinitionId)

    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) {
        return [pscustomobject]@{ Risk='Unknown'; Name=$null }
    }
    $info = Get-EARoleInfo -RoleDefinitionId $RoleDefinitionId
    $unresolved = [string]$info.ClassificationSource -eq 'unresolved-fail-closed'
    $risk = if ($info.IsTier0) { 'Critical' }
            elseif ($unresolved) { 'Unknown' }
            elseif ($info.IsPrivileged) { 'High' }
            else { 'Standard' }
    return [pscustomobject]@{ Risk=$risk; Name=$(if ($unresolved) { $null } else { [string]$info.Name }) }
}

function ConvertFrom-EAGovSigningCertificate {
    param([AllowNull()]$CertificateValue)

    if ([string]::IsNullOrWhiteSpace([string]$CertificateValue)) {
        return [pscustomobject]@{ Present=$false; Parsed=$false; Thumbprint=$null; NotBefore=$null; NotAfter=$null; Error='certificate value absent' }
    }
    try {
        $bytes = [Convert]::FromBase64String([string]$CertificateValue)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
        try {
            return [pscustomobject]@{
                Present    = $true
                Parsed     = $true
                Thumbprint = $certificate.Thumbprint
                NotBefore  = [datetimeoffset]$certificate.NotBefore.ToUniversalTime()
                NotAfter   = [datetimeoffset]$certificate.NotAfter.ToUniversalTime()
                Error      = $null
            }
        } finally {
            $certificate.Dispose()
        }
    } catch {
        return [pscustomobject]@{ Present=$true; Parsed=$false; Thumbprint=$null; NotBefore=$null; NotAfter=$null; Error=$_.Exception.Message }
    }
}

# Keep these bounds in one place so an operator maintaining a large-tenant profile
# can tune them without changing decision logic. Hitting a bound is always incomplete.
function Get-EAGovAssessmentLimits {
    [pscustomobject]@{
        ReviewApplySlaDays = 7
        ReviewDecisionMaxInstances = 500
        LifecycleLookbackDays = 30
        LifecycleStalledHours = 24
        LifecycleMaxWorkflows = 500
        PimMaxCandidateGroups = 2000
        CollectionMaxPages = 100
    }
}

function Get-EAGovReviewerAssessment {
    param([Parameter(Mandatory)]$Definition)
    $stages = @(Get-EAGovProperty $Definition 'stageSettings' | Where-Object { $null -ne $_ })
    $sources = if ($stages.Count -gt 0) { $stages } else { @($Definition) }
    foreach ($source in $sources) {
        $known = Test-EAGovPropertyPresent $source 'reviewers'
        $reviewers = @(Get-EAGovProperty $source 'reviewers' | Where-Object { $null -ne $_ })
        # Null is unreadable; an explicit empty collection means self-review.
        if ($known -and $null -eq (Get-EAGovProperty $source 'reviewers')) {
            # PowerShell unrolls an empty collection to null. Inspect the JSON to
            # distinguish an explicit [] from a null value without counting it as false.
            $known = (ConvertTo-EAGovCompactJson $source) -match '"reviewers"\s*:\s*\['
        }
        $fallbackKnown = Test-EAGovPropertyPresent $source 'fallbackReviewers'
        $fallback = @(Get-EAGovProperty $source 'fallbackReviewers' | Where-Object { $null -ne $_ })
        if ($fallbackKnown -and $null -eq (Get-EAGovProperty $source 'fallbackReviewers')) {
            $fallbackKnown = (ConvertTo-EAGovCompactJson $source) -match '"fallbackReviewers"\s*:\s*\['
        }
        $self = $known -and $reviewers.Count -eq 0
        $dynamic = $false
        $unknownReviewer = -not $known
        foreach ($reviewer in $reviewers) {
            $type = [string](Get-EAGovProperty $reviewer 'scopeType')
            $query = [string](Get-EAGovProperty $reviewer 'query')
            if ($type -ieq 'self') { $self = $true }
            if ($type -match '^(manager|sponsor|resourceOwner|managerOrSponsor)$' -or $query -match '(?i)(?:^|/)(manager|owners|sponsors)(?:$|[/?])') { $dynamic = $true }
            if ($type -ieq 'unknownFutureValue' -or (-not $type -and -not $query -and -not (Get-EAGovProperty $reviewer 'reviewerId'))) { $unknownReviewer = $true }
        }
        [pscustomobject]@{
            StageId = if ($stages.Count -gt 0) { Get-EAGovProperty $source 'stageId' } else { 'single' }
            DependsOn = ConvertTo-EAGovCompactJson (Get-EAGovProperty $source 'dependsOn')
            DecisionsThatWillMoveToNextStage = ConvertTo-EAGovCompactJson (Get-EAGovProperty $source 'decisionsThatWillMoveToNextStage')
            ReviewersKnown = $known -and -not $unknownReviewer
            ReviewerCount = if ($known) { $reviewers.Count } else { $null }
            SelfReview = $self
            DynamicReviewers = $dynamic
            FallbackKnown = $fallbackKnown
            FallbackReviewerCount = if ($fallbackKnown) { $fallback.Count } else { $null }
            NeedsFallback = $dynamic -and $fallbackKnown -and $fallback.Count -eq 0
            Reviewers = ConvertTo-EAGovCompactJson $reviewers
            FallbackReviewers = ConvertTo-EAGovCompactJson $fallback
        }
    }
}

function Get-EAGovReviewDecisionAssessment {
    param(
        [Parameter(Mandatory)]$Decision,
        [AllowNull()]$InstanceEnd,
        [datetimeoffset]$Now = [datetimeoffset]::UtcNow,
        [int]$SlaDays = 7
    )
    $decisionValue = [string](Get-EAGovProperty $Decision 'decision')
    $applyResult = [string](Get-EAGovProperty $Decision 'applyResult')
    $end = ConvertTo-EAGovDateTime $InstanceEnd
    $reviewed = ConvertTo-EAGovDateTime (Get-EAGovProperty $Decision 'reviewedDateTime')
    # The SLA starts only once the review has ended and this decision exists.
    $dueFrom = $end
    if ($reviewed -and (!$dueFrom -or $reviewed -gt $dueFrom)) { $dueFrom = $reviewed }
    $knownResult = $applyResult -in @('New','AppliedSuccessfully','AppliedWithUnknownFailure','AppliedSuccessfullyButObjectNotFound','ApplyNotSupported')
    [pscustomobject]@{
        IsDenied = $decisionValue -ieq 'Deny'
        Unknown = ($decisionValue -ieq 'Deny' -and (-not $knownResult -or -not $end))
        Applied = $applyResult -in @('AppliedSuccessfully','AppliedSuccessfullyButObjectNotFound')
        Overdue = $decisionValue -ieq 'Deny' -and $knownResult -and $end -and $end -lt $Now -and
            $applyResult -notin @('AppliedSuccessfully','AppliedSuccessfullyButObjectNotFound') -and
            $dueFrom -and $dueFrom.AddDays($SlaDays) -lt $Now
        ApplyResult = $applyResult
        DueDateTime = if ($dueFrom) { $dueFrom.AddDays($SlaDays) } else { $null }
    }
}

function Get-EAGovLifecycleRunAssessment {
    param([Parameter(Mandatory)]$Run, [datetimeoffset]$Now = [datetimeoffset]::UtcNow, [int]$StalledHours = 24)
    $status = [string](Get-EAGovProperty $Run 'processingStatus')
    $failedTasks = 0; $failedUsers = 0
    $tasksKnown = [int]::TryParse([string](Get-EAGovProperty $Run 'failedTasksCount'), [ref]$failedTasks)
    $usersKnown = [int]::TryParse([string](Get-EAGovProperty $Run 'failedUsersCount'), [ref]$failedUsers)
    $updated = ConvertTo-EAGovDateTime (Get-EAGovProperty $Run 'lastUpdatedDateTime')
    if (-not $updated) { $updated = ConvertTo-EAGovDateTime (Get-EAGovProperty $Run 'startedDateTime') }
    if (-not $updated) { $updated = ConvertTo-EAGovDateTime (Get-EAGovProperty $Run 'scheduledDateTime') }
    $nonterminal = $status -in @('queued','inProgress')
    $knownStatus = $status -in @('queued','inProgress','completed','completedWithErrors','canceled','cancelled','failed')
    [pscustomobject]@{
        Failed = ($tasksKnown -and $failedTasks -gt 0) -or ($usersKnown -and $failedUsers -gt 0) -or $status -in @('failed','completedWithErrors')
        Stalled = $nonterminal -and $updated -and $updated -lt $Now.AddHours(-$StalledHours)
        Unknown = -not $tasksKnown -or -not $usersKnown -or -not $knownStatus -or ($nonterminal -and -not $updated)
        FailedTasks = if ($tasksKnown) { $failedTasks } else { $null }
        FailedUsers = if ($usersKnown) { $failedUsers } else { $null }
        LastProgressDateTime = $updated
    }
}

function Test-EAGovPimCandidateGroup {
    param([Parameter(Mandatory)]$Group)
    if ((Get-EAGovProperty $Group 'isAssignableToRole') -eq $true) { return $true }
    if ((Get-EAGovProperty $Group 'onPremisesSyncEnabled') -eq $true) { return $false }
    $types = @(Get-EAGovProperty $Group 'groupTypes')
    if ($types -contains 'DynamicMembership') { return $false }
    return (Get-EAGovProperty $Group 'securityEnabled') -eq $true -or $types -contains 'Unified'
}

function Test-EAGovNextSigningCertificateReady {
    param([Parameter(Mandatory)]$Row, [datetimeoffset]$Now = [datetimeoffset]::UtcNow)
    $start = ConvertTo-EAGovDateTime (Get-EAGovProperty $Row 'NextSigningNotBefore')
    $end = ConvertTo-EAGovDateTime (Get-EAGovProperty $Row 'NextSigningNotAfter')
    $currentEnd = ConvertTo-EAGovDateTime (Get-EAGovProperty $Row 'SigningNotAfter')
    return $null -ne $start -and $null -ne $end -and $null -ne $currentEnd -and
        $start -le $Now -and $end -gt $Now -and $end -gt $currentEnd
}
