<#
Standalone governance check definitions for EntraAudit-PS7.ps1.

Read-only invariant:
  * Every Microsoft Graph request in this file is issued through
    Invoke-MgGraphRequest -Method GET.
  * No function creates, updates, activates, applies, revokes, or deletes data.
  * A failed or truncated data source is emitted as an explicit coverage finding;
    it is never interpreted as an empty (clean) result.

This file intentionally contains function definitions only. The main audit script
dot-sources it and registers the public Invoke-Check-* functions.
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

# Invoke-MgGraphRequest turns ISO timestamps into [datetime] values (Kind=Utc). Casting
# those to text drops the zone, and parsing that text again would read it as local time,
# moving every Graph timestamp by the machine's UTC offset. Keep typed values as they are
# (an Unspecified kind is Graph UTC) and read zone-less text as UTC, like the main script.
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

# A Graph timestamp as readable UTC text for evidence ("2026-09-23 12:00 UTC"); $null when
# the value is missing or unreadable.
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
            $request = @{ Method = 'GET'; Uri = $next; ErrorAction = 'Stop' }
            if ($Headers) { $request.Headers = $Headers }
            $response = Invoke-MgGraphRequest @request
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
        $request = @{ Method = 'GET'; Uri = $Uri; ErrorAction = 'Stop' }
        if ($Headers) { $request.Headers = $Headers }
        $response = Invoke-MgGraphRequest @request
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
        [switch]$CoverageGap
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
    Add-EntraFinding @parameters
}

# "Could not read" finding. The report must never present a failed or partial read as a
# clean result, so every one of these is an Information finding marked -CoverageGap.
#   -DataSource  technical name of the data. It is ALSO the source of the stable rule id
#                (coverage-<slug>), so existing values must never be reworded; change the
#                reader-facing wording through -Subject instead.
#   -Subject     everyday name of what could not be read ("the list of access reviews");
#                defaults to DataSource.
#   -Impact      one short sentence naming what may be missing from the report as a result.
#   -Partial     the read stopped at the page safety limit, so only part of the data was read.
#   -RecommendedAction  replaces the default "grant access and run again" advice when a
#                missing permission is not the likely cause.
#   -ObjectType/-ObjectId/-AffectedPrincipal  for a gap about ONE object (for example one
#                GDAP relationship): the object goes into the finding id instead of into
#                DataSource, so renaming the object never changes the rule id and gaps of
#                several objects group under one rule.
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

# GET /directory/onPremisesSynchronization is a collection navigation: Graph answers
# {"value":[{id, configuration, features}]} even though a tenant has at most one object.
# Reading 'configuration'/'features' from the top of that answer always gives $null, so
# unwrap the list (a single-entity answer is accepted too). Object is $null when Graph
# returned no object; callers report that as not checked, never as clean.
# Microsoft Graph supports this read only for a delegated sign-in by a Global
# Administrator with OnPremDirectorySynchronization.Read.All (app-only is not supported).
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

# Plain-language permission facts for the on-premises sync settings read above: the
# scope text for coverage findings, and a note added to the reason on app-only runs.
function Get-EAGovOnPremSyncAccess {
    [pscustomobject]@{
        Scope = 'OnPremDirectorySynchronization.Read.All (delegated only, signed in as a Global Administrator; app-only is not supported by Microsoft Graph for this API)'
        Note  = $(if ([string]$script:AuthType -eq 'AppOnly') { ' This run used an app-only sign-in, which Microsoft Graph does not support for this setting.' } else { '' })
    }
}

function Invoke-Check-EntraRecommendations {
    [CmdletBinding()]
    param()

    $checkId = 'recommendations'
    $doc = 'https://learn.microsoft.com/graph/api/directory-list-recommendation?view=graph-rest-beta'
    $guideDoc = 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/overview-recommendations'
    # Prefer include-unknown-enum-members so evolvable status/type members (riskAccepted,
    # needsMoreAction, longLivedCredentials, ...) arrive by name instead of collapsing to
    # unknownFutureValue, which would make them unclassifiable and collide on one rule id.
    $result = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/beta/directory/recommendations?$expand=impactedResources' `
        -Headers @{ Prefer = 'include-unknown-enum-members' }
    if (-not $result.Success) { throw $result.Error }

    $rows = foreach ($recommendation in @($result.Rows)) {
        $resources = @(Get-EAGovProperty $recommendation 'impactedResources' | Where-Object { $null -ne $_ })
        $steps = @(Get-EAGovProperty $recommendation 'actionSteps')
        [pscustomobject]@{
            Id                = Get-EAGovProperty $recommendation 'id'
            RecommendationType = Get-EAGovProperty $recommendation 'recommendationType'
            DisplayName       = Get-EAGovProperty $recommendation 'displayName'
            Status            = Get-EAGovProperty $recommendation 'status'
            Priority          = Get-EAGovProperty $recommendation 'priority'
            Category          = Get-EAGovProperty $recommendation 'category'
            FeatureAreas      = (@(Get-EAGovProperty $recommendation 'featureAreas') -join '; ')
            CurrentScore      = Get-EAGovProperty $recommendation 'currentScore'
            MaxScore          = Get-EAGovProperty $recommendation 'maxScore'
            ImpactType        = Get-EAGovProperty $recommendation 'impactType'
            ImpactedResources = $resources.Count
            CreatedDateTime   = Get-EAGovProperty $recommendation 'createdDateTime'
            LastModifiedDateTime = Get-EAGovProperty $recommendation 'lastModifiedDateTime'
            LastModifiedBy    = Get-EAGovProperty $recommendation 'lastModifiedBy'
            PostponeUntilDateTime = Get-EAGovProperty $recommendation 'postponeUntilDateTime'
            Insights          = Get-EAGovProperty $recommendation 'insights'
            ActionSteps       = (($steps | ForEach-Object { Get-EAGovProperty $_ 'text' }) -join ' | ')
        }
    }
    $src = Write-Evidence -BaseName 'entra_recommendations' -Rows @($rows) `
        -Title 'Microsoft Entra Recommendations (beta, read-only)' `
        -Notes @('The recommendations API is beta and can change. Active and needsMoreAction recommendations become risk findings; planned and postponed ones are not fixed yet and become findings one severity step lower.')

    if ($result.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Tenant Posture' -DataSource 'Entra recommendations pagination' `
            -Reason "pagination exceeded $($result.Pages) pages." -RequiredScope 'DirectoryRecommendations.Read.All' `
            -DocumentationUrl $doc -SourceFile $src -Partial -Subject 'the Microsoft Entra recommendations list' `
            -Impact 'Open Microsoft recommendations beyond the part that was read are missing from this report.'
    }

    # Documented recommendationStatus members (beta). active and needsMoreAction are open
    # (needsMoreAction = Microsoft re-verified that user-completed resources are still
    # impacted). planned and postponed are NOT fixed either: planned means the work has not
    # been done yet, and a postponed recommendation becomes active again on its
    # postponeUntilDateTime. They are reported one severity step lower under the same rule
    # and object id as the open finding, so the finding id and its trend history do not
    # change when an admin flips a recommendation between active, planned and postponed.
    # The remaining documented members close a recommendation (fixed, or closed by a
    # decision that the baseline lists by name). Anything else, including
    # unknownFutureValue, stays a coverage gap rather than a clean result.
    $openStatuses = @('active','needsMoreAction')
    $deferredStatuses = @('planned','postponed')
    $decisionStatuses = @('dismissed','riskAccepted','thirdParty','alternateMitigation')
    $knownStatuses = @($openStatuses) + @($deferredStatuses) + @($decisionStatuses) + @('completedBySystem','completedByUser')
    $unknownStatusRows = @($result.Rows | Where-Object {
        $status = [string](Get-EAGovProperty $_ 'status')
        [string]::IsNullOrWhiteSpace($status) -or $status -notin $knownStatuses
    })
    if ($unknownStatusRows.Count -gt 0) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Tenant Posture' -DataSource 'Entra recommendation status' `
            -Reason ((Format-EACount $unknownStatusRows.Count 'recommendation record has' 'recommendation records have') + ' a missing or unknown status and cannot be classified as active or resolved.') `
            -RequiredScope 'DirectoryRecommendations.Read.All' -DocumentationUrl $doc -SourceFile $src `
            -Subject 'the status of some Microsoft Entra recommendations' `
            -Impact 'The audit cannot tell whether these recommendations are still open, so open ones may be missing from this report.' `
            -RecommendedAction 'Open the listed recommendations in Entra admin center > Entra ID > Overview > Recommendations and check whether they are still open'
    }

    $active = @($result.Rows | Where-Object { [string](Get-EAGovProperty $_ 'status') -in $openStatuses })
    $deferred = @($result.Rows | Where-Object { [string](Get-EAGovProperty $_ 'status') -in $deferredStatuses })
    foreach ($recommendation in @($active) + @($deferred)) {
        $priority = [string](Get-EAGovProperty $recommendation 'priority')
        $status = [string](Get-EAGovProperty $recommendation 'status')
        $isDeferred = $status -in $deferredStatuses
        $severity = if ($isDeferred) {
            # One step lower than an open recommendation of the same priority.
            switch -Regex ($priority) {
                '^critical$' { 'High'; break }
                '^high$'   { 'Medium'; break }
                default    { 'Low' }
            }
        } else {
            switch -Regex ($priority) {
                '^critical$' { 'Critical'; break }
                '^high$'   { 'High'; break }
                '^medium$' { 'Medium'; break }
                '^low$'    { 'Low'; break }
                default    { 'Medium' }
            }
        }
        $name = [string](Get-EAGovProperty $recommendation 'displayName')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = [string](Get-EAGovProperty $recommendation 'recommendationType') }
        $steps = @(Get-EAGovProperty $recommendation 'actionSteps')
        $firstStep = if ($steps.Count -gt 0) { [string](Get-EAGovProperty $steps[0] 'text') } else { '' }
        # @(null) has Count 1, and a step can have no text; RecommendedAction is mandatory.
        $firstStep = $firstStep.Trim()
        $action = if ([string]::IsNullOrWhiteSpace($firstStep)) {
            'Open the recommendation in Entra admin center > Entra ID > Overview > Recommendations and follow its steps for each affected item'
        } else {
            if ($firstStep -notmatch '[.!?]$') { $firstStep += '.' }
            "$firstStep Microsoft lists every step and affected item in Entra admin center > Entra ID > Overview > Recommendations"
        }
        $insights = [string](Get-EAGovProperty $recommendation 'insights')
        # @($null) has Count 1, so drop nulls: a missing list is 0 affected items.
        $resourceCount = @(Get-EAGovProperty $recommendation 'impactedResources' | Where-Object { $null -ne $_ }).Count
        $id = [string](Get-EAGovProperty $recommendation 'id')
        $scoreText = "Microsoft priority={0}; affected items={1}; score={2}/{3}." -f $priority,$resourceCount,
            (Get-EAGovProperty $recommendation 'currentScore'),(Get-EAGovProperty $recommendation 'maxScore')

        if ($isDeferred) {
            $postponeUntil = Format-EAGovDateTime (Get-EAGovProperty $recommendation 'postponeUntilDateTime')
            $changedBy = [string](Get-EAGovProperty $recommendation 'lastModifiedBy')
            $changedAt = Format-EAGovDateTime (Get-EAGovProperty $recommendation 'lastModifiedDateTime')
            $title = "Microsoft Entra recommendation {0}, not fixed yet: {1}" -f $status.ToLowerInvariant(),$name
            $postponeText = if ($status -ieq 'postponed') { '; postponed until={0}' -f $(if ($postponeUntil) { $postponeUntil } else { 'not set' }) } else { '' }
            $evidence = ("Status={0}{1}; last changed {2} by {3}. {4} Planned and postponed recommendations are reported one severity step below Microsoft's priority. {5}" -f
                $status,$postponeText,$(if ($changedAt) { $changedAt } else { 'at an unknown time' }),
                $(if ($changedBy) { $changedBy } else { 'an unknown user' }),$scoreText,$insights).Trim()
            $why = if ($status -ieq 'postponed') {
                'Postponing a recommendation does not fix it: the weakness it describes is still in place. It becomes active again on its postpone date.'
            } else {
                'Marking a recommendation as planned does not fix it: the weakness it describes stays in place until the planned work is done.'
            }
        } else {
            $title = "Unresolved Microsoft Entra recommendation: $name"
            $evidence = ("Status={0}; {1} {2}" -f $status,$scoreText,$insights).Trim()
            $why = "Microsoft checks this tenant's settings and activity every day and flagged this as a gap that is still open. Until it is fixed, the weakness it describes stays in place."
        }

        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Tenant Posture' `
            -Title $title -Evidence $evidence -WhyItMatters $why `
            -RecommendedAction $action -DocumentationUrl $guideDoc -SourceFile $src `
            -RuleId ("entra-recommendation-" + [string](Get-EAGovProperty $recommendation 'recommendationType')) `
            -ObjectType 'recommendation' -ObjectId $id -ResultRows @($rows | Where-Object { $_.Id -eq $id })
    }

    if ($active.Count -eq 0 -and $deferred.Count -eq 0 -and $unknownStatusRows.Count -eq 0 -and -not $result.Truncated) {
        # RuleId equals the title slug this finding used before it had an explicit id, so
        # its stable finding id (and trend history) does not change.
        $statusCounts = @($rows | Group-Object { [string]$_.Status } | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name,$_.Count })
        $decisionRows = @($rows | Where-Object { [string]$_.Status -in $decisionStatuses })
        $decisionText = if ($decisionRows.Count -gt 0) {
            ' Closed by a decision rather than a fix (check these are still valid): ' +
                (@($decisionRows | ForEach-Object {
                    $label = if ([string]::IsNullOrWhiteSpace([string]$_.DisplayName)) { [string]$_.RecommendationType } else { [string]$_.DisplayName }
                    '{0} ({1})' -f $label,$_.Status
                }) -join '; ') + '.'
        } else { '' }
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Tenant Posture' `
            -Title ("No active, planned or postponed Microsoft Entra recommendations ({0} checked)" -f @($result.Rows).Count) `
            -Evidence ("{0} returned; none are active, need more action, planned or postponed. Records per status: {1}.{2}" -f (Format-EACount @($result.Rows).Count 'recommendation record' 'recommendation records'),$(if ($statusCounts.Count -gt 0) { $statusCounts -join ', ' } else { 'none' }),$decisionText) `
            -WhyItMatters "Microsoft's recommendation list tracks identity improvements for this tenant. None are open right now." `
            -RecommendedAction 'Check the list in Entra admin center > Entra ID > Overview > Recommendations regularly and act on new recommendations as they appear' `
            -DocumentationUrl $guideDoc -SourceFile $src -ResultRows @($rows) -RuleId 'microsoft-entra-recommendations-reviewed'
    }
}

function Invoke-Check-SecureScore {
    [CmdletBinding()]
    param()

    $checkId = 'securescore'
    $doc = 'https://learn.microsoft.com/graph/api/security-list-securescores?view=graph-rest-1.0'
    $guideDoc = 'https://learn.microsoft.com/en-us/defender-xdr/microsoft-secure-score'
    $result = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/security/secureScores?$top=30'
    if (-not $result.Success) { throw $result.Error }

    $normalized = foreach ($score in @($result.Rows)) {
        $current = Get-EAGovProperty $score 'currentScore'
        $maximum = Get-EAGovProperty $score 'maxScore'
        $percent = $null
        try { if ([double]$maximum -gt 0) { $percent = [math]::Round(([double]$current / [double]$maximum) * 100, 1) } } catch {}
        $vendor = Get-EAGovProperty $score 'vendorInformation'
        [pscustomobject]@{
            Id               = Get-EAGovProperty $score 'id'
            CreatedDateTime  = Get-EAGovProperty $score 'createdDateTime'
            CurrentScore     = $current
            MaxScore         = $maximum
            Percentage       = $percent
            ActiveUserCount  = Get-EAGovProperty $score 'activeUserCount'
            LicensedUserCount = Get-EAGovProperty $score 'licensedUserCount'
            EnabledServices  = (@(Get-EAGovProperty $score 'enabledServices') -join '; ')
            Vendor           = Get-EAGovProperty $vendor 'vendor'
            Provider         = Get-EAGovProperty $vendor 'provider'
            ControlCount     = @(Get-EAGovProperty $score 'controlScores').Count
            RawObject        = $score
        }
    }
    $ordered = @($normalized | Sort-Object { ConvertTo-EAGovDateTime $_.CreatedDateTime } -Descending)
    $evidenceRows = @($ordered | Select-Object Id,CreatedDateTime,CurrentScore,MaxScore,Percentage,ActiveUserCount,LicensedUserCount,EnabledServices,Vendor,Provider,ControlCount)
    $src = Write-Evidence -BaseName 'secure_score' -Rows $evidenceRows -Title 'Microsoft Secure Score (latest 30 records)'

    if ($result.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Security Posture' -DataSource 'Secure Score pagination' `
            -Reason "pagination exceeded $($result.Pages) pages." -RequiredScope 'SecurityEvents.Read.All' `
            -DocumentationUrl $doc -SourceFile $src -Partial -Subject 'the Microsoft Secure Score history' `
            -Impact 'The score trend was judged only on the records that were read.'
    }
    if ($ordered.Count -eq 0) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Security Posture' -DataSource 'Microsoft Secure Score' `
            -Reason 'the API succeeded but returned no score records.' -RequiredScope 'SecurityEvents.Read.All' `
            -DocumentationUrl $doc -SourceFile $src -Subject 'Microsoft Secure Score' `
            -Impact 'The overall security score and its trend were not checked.' `
            -RecommendedAction 'Open Microsoft Secure Score in the Microsoft Defender portal (security.microsoft.com/securescore) to confirm it is available for this tenant, then run the audit again'
        return
    }

    $latest = $ordered[0]
    $controls = foreach ($control in @(Get-EAGovProperty $latest.RawObject 'controlScores')) {
        [pscustomobject]@{
            ControlName = Get-EAGovProperty $control 'controlName'
            Score       = Get-EAGovProperty $control 'score'
            Description = Get-EAGovProperty $control 'description'
        }
    }
    $controlSrc = Write-Evidence -BaseName 'secure_score_controls' -Rows @($controls) -Title 'Microsoft Secure Score - latest control scores'

    if ($null -eq $latest.Percentage) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Security Posture' -DataSource 'Secure Score percentage' `
            -Reason "latest currentScore/maxScore could not be evaluated ($($latest.CurrentScore)/$($latest.MaxScore))." `
            -RequiredScope 'SecurityEvents.Read.All' -DocumentationUrl $doc -SourceFile $src `
            -Subject 'the latest Secure Score percentage' `
            -Impact 'Whether the score is low was not checked.' `
            -RecommendedAction 'Check the current score in the Microsoft Defender portal (security.microsoft.com/securescore)'
    } elseif ([double]$latest.Percentage -lt 50) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Security Posture' `
            -Title ("Microsoft Secure Score is low: {0}% of the maximum" -f $latest.Percentage) `
            -Evidence ("Latest score {0}/{1}, generated {2}. The 50% threshold is a triage threshold, not a compliance boundary." -f $latest.CurrentScore,$latest.MaxScore,$latest.CreatedDateTime) `
            -WhyItMatters 'Microsoft Secure Score measures how many of the security settings Microsoft recommends are in place. Below 50% means many of them are missing, which makes common attacks easier.' `
            -RecommendedAction 'Open Microsoft Secure Score in the Microsoft Defender portal (security.microsoft.com/securescore) and fix the open recommendations with the highest score impact first; record the reason for any you decide not to do' `
            -DocumentationUrl $guideDoc -SourceFile $controlSrc -RuleId 'secure-score-below-50'
    } elseif ([double]$latest.Percentage -lt 70) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Security Posture' `
            -Title ("Microsoft Secure Score has room to improve: {0}% of the maximum" -f $latest.Percentage) `
            -Evidence ("Latest score {0}/{1}, generated {2}. The 70% threshold is a prioritization aid, not a compliance boundary." -f $latest.CurrentScore,$latest.MaxScore,$latest.CreatedDateTime) `
            -WhyItMatters 'Some security settings Microsoft recommends are not in place yet. The score is a guide rather than a compliance result, but the remaining items often include cheap, useful fixes.' `
            -RecommendedAction 'Review the remaining recommendations in Microsoft Secure Score (security.microsoft.com/securescore), fix the low-effort, high-impact ones and record why you accept the rest' `
            -DocumentationUrl $guideDoc -SourceFile $controlSrc -RuleId 'secure-score-below-70'
    }

    # Without a latest percentage there is no trend to judge ([double]$null would be 0 and
    # report a false drop); the coverage finding above already says the score is unknown.
    $latestDate = ConvertTo-EAGovDateTime $latest.CreatedDateTime
    if ($latestDate -and $null -ne $latest.Percentage) {
        $older = @($ordered | Where-Object {
            $d = ConvertTo-EAGovDateTime $_.CreatedDateTime
            $d -and $d -le $latestDate.AddDays(-21) -and $null -ne $_.Percentage
        } | Select-Object -First 1)
        if ($older.Count -gt 0) {
            $delta = [math]::Round(([double]$latest.Percentage - [double]$older[0].Percentage), 1)
            if ($delta -le -5) {
                Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Security Posture' `
                    -Title ("Microsoft Secure Score dropped by {0} percentage points" -f ([math]::Abs($delta))) `
                    -Evidence ("Score changed from {0}% on {1} to {2}% on {3}." -f $older[0].Percentage,$older[0].CreatedDateTime,$latest.Percentage,$latest.CreatedDateTime) `
                    -WhyItMatters 'A drop usually means a security setting was turned off, a license changed or new recommendations now apply. Finding the cause early stops protection from being lost without anyone noticing.' `
                    -RecommendedAction 'Open the History tab of Microsoft Secure Score (security.microsoft.com/securescore), find which recommendations changed, and turn back on any protection that was switched off' `
                    -DocumentationUrl $guideDoc -SourceFile $src -RuleId 'secure-score-decline'
            }
        }
    }

    $percentText = if ($null -eq $latest.Percentage) { 'percentage unknown' } else { '{0}%' -f $latest.Percentage }
    $baselineTitle = if ($null -eq $latest.Percentage) { 'Microsoft Secure Score recorded (percentage unknown)' } else { "Microsoft Secure Score recorded: $percentText of the maximum" }
    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Security Posture' `
        -Title $baselineTitle `
        -Evidence ("Latest score={0}/{1} ({2}); generated={3}; {4} captured." -f $latest.CurrentScore,$latest.MaxScore,$percentText,$latest.CreatedDateTime,(Format-EACount @($controls).Count 'control score' 'control scores')) `
        -WhyItMatters 'The dated score lets you compare future audits with today. Use it to guide work, not as proof of compliance.' `
        -RecommendedAction 'Compare the score between audits and review individual recommendations, including ones you meet in other ways that Microsoft cannot detect' `
        -DocumentationUrl $guideDoc -SourceFile $src -ResultRows $evidenceRows -RuleId 'secure-score-baseline'
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

function Invoke-Check-AccessReviews {
    [CmdletBinding()]
    param()

    $checkId = 'accessreviews'
    $doc = 'https://learn.microsoft.com/graph/api/accessreviewset-list-definitions?view=graph-rest-1.0'
    $guideDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/create-access-review'
    $manageDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/manage-access-review'
    $reviewsPath = 'Entra admin center > ID Governance > Access reviews'
    $result = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?$top=100'
    if (-not $result.Success) { throw $result.Error }

    $now = [datetimeoffset]::UtcNow
    $rows = New-Object System.Collections.Generic.List[object]
    $overdue = New-Object System.Collections.Generic.List[object]
    $partialInstances = New-Object System.Collections.Generic.List[object]
    $settingGaps = New-Object System.Collections.Generic.List[object]
    $categories = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $effectiveCategories = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    # Groups named in the scope of a recurring review that has not ended (ongoing
    # coverage, the same rule as $effectiveCategories), and groups named in any review.
    $reviewedGroupIds = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $everReviewedGroupIds = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $groupIdPattern = '(?i)/groups/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'

    foreach ($definition in @($result.Rows)) {
        $id = [string](Get-EAGovProperty $definition 'id')
        $category = Get-EAGovAccessReviewCategory $definition
        [void]$categories.Add($category)
        $scope = Get-EAGovProperty $definition 'scope'
        $scopeText = ConvertTo-EAGovCompactJson $scope
        foreach ($match in [regex]::Matches($scopeText, $groupIdPattern)) {
            [void]$everReviewedGroupIds.Add($match.Groups[1].Value)
        }

        $settings = Get-EAGovProperty $definition 'settings'
        $recurrence = Get-EAGovProperty $settings 'recurrence'
        $pattern = Get-EAGovProperty $recurrence 'pattern'
        $range = Get-EAGovProperty $recurrence 'range'
        $autoApply = Get-EAGovProperty $settings 'autoApplyDecisionsEnabled'
        $defaultEnabled = Get-EAGovProperty $settings 'defaultDecisionEnabled'
        $defaultDecision = [string](Get-EAGovProperty $settings 'defaultDecision')
        $missingSettings = New-Object System.Collections.Generic.List[string]
        if ($null -eq $settings) { $missingSettings.Add('settings') | Out-Null }
        if (-not (Test-EAGovPropertyPresent $settings 'autoApplyDecisionsEnabled')) { $missingSettings.Add('autoApplyDecisionsEnabled') | Out-Null }
        if (-not (Test-EAGovPropertyPresent $settings 'defaultDecisionEnabled')) { $missingSettings.Add('defaultDecisionEnabled') | Out-Null }
        if ($defaultEnabled -eq $true -and [string]::IsNullOrWhiteSpace($defaultDecision)) { $missingSettings.Add('defaultDecision') | Out-Null }
        if ($missingSettings.Count -gt 0) {
            $settingGaps.Add([pscustomobject]@{
                DefinitionId=$id; DisplayName=(Get-EAGovProperty $definition 'displayName'); MissingFields=($missingSettings -join '; ')
            }) | Out-Null
        }
        $definitionStatus = [string](Get-EAGovProperty $definition 'status')
        $recurrencePattern = [string](Get-EAGovProperty $pattern 'type')
        $terminalDefinition = $definitionStatus -match '^(Completed|Inactive|Stopped|Cancelled|Canceled)$'
        if (-not $terminalDefinition -and -not [string]::IsNullOrWhiteSpace($recurrencePattern)) {
            [void]$effectiveCategories.Add($category)
            foreach ($match in [regex]::Matches($scopeText, $groupIdPattern)) {
                [void]$reviewedGroupIds.Add($match.Groups[1].Value)
            }
        }

        $instances = @()
        $instanceRead = $true
        if ($id) {
            $encodedId = [uri]::EscapeDataString($id)
            $instanceResult = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/{0}/instances?`$top=100" -f $encodedId)
            if ($instanceResult.Success) {
                $instances = @($instanceResult.Rows)
                if ($instanceResult.Truncated) {
                    $instanceRead = $false
                    $partialInstances.Add([pscustomobject]@{ DefinitionId=$id; DisplayName=(Get-EAGovProperty $definition 'displayName'); Reason='pagination limit reached' }) | Out-Null
                }
            } else {
                $instanceRead = $false
                $partialInstances.Add([pscustomobject]@{
                    DefinitionId=$id
                    DisplayName=(Get-EAGovProperty $definition 'displayName')
                    Reason=[string]$instanceResult.Error.Exception.Message
                }) | Out-Null
            }
        }

        foreach ($instance in $instances) {
            $end = ConvertTo-EAGovDateTime (Get-EAGovProperty $instance 'endDateTime')
            $status = [string](Get-EAGovProperty $instance 'status')
            if ($end -and $end -lt $now -and $status -notmatch '^(Completed|AutoReviewed|Applied|Cancelled|Canceled)$') {
                $overdue.Add([pscustomobject]@{
                    DefinitionId=$id
                    Definition=(Get-EAGovProperty $definition 'displayName')
                    Category=$category
                    InstanceId=(Get-EAGovProperty $instance 'id')
                    Status=$status
                    EndDateTime=$end
                }) | Out-Null
            }
        }

        $rows.Add([pscustomobject]@{
            Id                   = $id
            DisplayName          = Get-EAGovProperty $definition 'displayName'
            Status               = $definitionStatus
            Category             = $category
            Description          = Get-EAGovProperty $definition 'descriptionForAdmins'
            CreatedDateTime      = Get-EAGovProperty $definition 'createdDateTime'
            LastModifiedDateTime = Get-EAGovProperty $definition 'lastModifiedDateTime'
            InstanceDurationDays = Get-EAGovProperty $settings 'instanceDurationInDays'
            RecurrencePattern    = $recurrencePattern
            RecurrenceInterval   = Get-EAGovProperty $pattern 'interval'
            RecurrenceRange      = Get-EAGovProperty $range 'type'
            RecurrenceEndDate    = Get-EAGovProperty $range 'endDate'
            RecurrenceOccurrences = Get-EAGovProperty $range 'numberOfOccurrences'
            AutoApplyDecisions   = $autoApply
            DefaultDecisionEnabled = $defaultEnabled
            DefaultDecision      = $defaultDecision
            RecommendationsEnabled = Get-EAGovProperty $settings 'recommendationsEnabled'
            JustificationRequired  = Get-EAGovProperty $settings 'justificationRequiredOnApproval'
            InstanceCount        = $instances.Count
            InstanceReadComplete = $instanceRead
            Scope                = $scopeText
        }) | Out-Null
    }

    $src = Write-Evidence -BaseName 'access_reviews' -Rows $rows.ToArray() -Title 'Microsoft Entra Access Review Definitions'
    $overdueSrc = Write-Evidence -BaseName 'access_review_overdue_instances' -Rows $overdue.ToArray() -Title 'Overdue Access Review Instances'

    if ($result.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Access review definitions pagination' `
            -Reason "pagination exceeded $($result.Pages) pages." -RequiredScope 'AccessReview.Read.All' `
            -DocumentationUrl $doc -SourceFile $src -Partial -Subject 'the list of access reviews' `
            -Impact 'Problems with access reviews beyond the part that was read are missing from this report.'
    }
    if ($partialInstances.Count -gt 0) {
        $partialSrc = Write-Evidence -BaseName 'access_review_instance_errors' -Rows $partialInstances.ToArray() -Title 'Access Review Instance Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Access review instances' `
            -Reason ((Format-EACount $partialInstances.Count 'definition' 'definitions') + ' could not be enumerated completely.') `
            -RequiredScope 'AccessReview.Read.All' -DocumentationUrl $doc -SourceFile $partialSrc `
            -Subject 'the review rounds of some access reviews' `
            -Impact 'Overdue access reviews may be missing from this report.'
    }
    if ($settingGaps.Count -gt 0) {
        $settingGapSrc = Write-Evidence -BaseName 'access_review_setting_gaps' -Rows $settingGaps.ToArray() -Title 'Access Review Setting Coverage Gaps'
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("Some settings of {0} could not be read" -f (Format-EACount $settingGaps.Count 'access review' 'access reviews')) `
            -Evidence ((Format-EACount $settingGaps.Count 'definition' 'definitions') + ' omitted settings required to distinguish automatic application and default-decision behavior. Missing values are unknown, not false.') `
            -WhyItMatters 'The audit cannot tell whether these reviews keep access when reviewers do not answer, or whether their decisions are actually applied.' `
            -RecommendedAction ("Open the listed reviews in {0} and check their 'Upon completion settings'; confirm the audit account has AccessReview.Read.All, then run the audit again" -f $reviewsPath) `
            -DocumentationUrl $doc -SourceFile $settingGapSrc -ResultRows $settingGaps.ToArray() `
            -RuleId 'access-review-settings-unknown' -CoverageGap
    }

    if ($rows.Count -eq 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'No access reviews are set up' `
            -Evidence 'The definitions API returned zero access reviews. This is a known empty result, not an API failure. Access reviews require Microsoft Entra ID P2, Microsoft Entra ID Governance or Microsoft Entra Suite licensing.' `
            -WhyItMatters 'Without regular access reviews, people keep admin roles, group memberships, guest access and app access long after they stop needing them. That leftover access is what attackers and former staff misuse.' `
            -RecommendedAction ("Set up recurring access reviews in {0}, starting with admin roles, guests and sensitive groups. If the tenant is not licensed for access reviews, document the manual review process you use instead" -f $reviewsPath) `
            -DocumentationUrl $guideDoc -SourceFile $src -RuleId 'access-reviews-none'
        return
    }

    $defaultApprove = @($rows | Where-Object { $_.DefaultDecisionEnabled -eq $true -and [string]$_.DefaultDecision -ieq 'Approve' })
    if ($defaultApprove.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $defaultApprove.Count 'access review approves' 'access reviews approve') + ' access automatically when reviewers do not answer') `
            -Evidence 'DefaultDecisionEnabled=true and DefaultDecision=Approve causes non-responses to retain access.' `
            -WhyItMatters 'When a reviewer does not respond, the person keeps their access, so the stale access the review should remove survives it.' `
            -RecommendedAction ("In {0}, open each listed review and set 'If reviewers don't respond' to Remove access or Take recommendations; require reviewers to give a reason when they approve" -f $reviewsPath) `
            -DocumentationUrl $guideDoc -SourceFile $src -ResultRows $defaultApprove -RuleId 'access-review-default-approve'
    }

    $nonRecurring = @($rows | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.RecurrencePattern) -or
        $_.Status -match '^(Completed|Inactive|Stopped|Cancelled|Canceled)$'
    })
    $sensitiveNonRecurring = @($nonRecurring | Where-Object { $_.Category -in @('PrivilegedRoles','Guests','InactiveUsers','EnterpriseApps','Groups') })
    if ($sensitiveNonRecurring.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title (Format-EACount $sensitiveNonRecurring.Count 'access review of sensitive access ran only once or has ended' 'access reviews of sensitive access ran only once or have ended') `
            -Evidence 'The review covers admin roles, guests, inactive users, enterprise applications or groups, and its schedule is one-time, ended, or has no readable recurrence pattern.' `
            -WhyItMatters 'A one-time review cleans up access once. Anything granted afterwards is never checked again.' `
            -RecommendedAction ("Give these reviews a recurring schedule (for example quarterly) with a named reviewer in {0}" -f $reviewsPath) `
            -DocumentationUrl $guideDoc -SourceFile $src -ResultRows $sensitiveNonRecurring -RuleId 'access-review-sensitive-not-recurring'
    }

    $manualApply = @($rows | Where-Object { $_.AutoApplyDecisions -eq $false -and $_.Category -in @('PrivilegedRoles','Guests','InactiveUsers','EnterpriseApps') })
    if ($manualApply.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $manualApply.Count 'access review of sensitive access does not' 'access reviews of sensitive access do not') + ' remove denied access automatically') `
            -Evidence 'autoApplyDecisionsEnabled=false. Manual application can be intentional, but must be operationally tracked.' `
            -WhyItMatters "A reviewer's 'deny' does nothing until someone applies the results. If that manual step is forgotten, access that should be removed stays in place." `
            -RecommendedAction "Turn on 'Auto apply results to resource' for these reviews, or name an owner who applies the results within an agreed time" `
            -DocumentationUrl $manageDoc -SourceFile $src -ResultRows $manualApply -RuleId 'access-review-manual-apply'
    }

    if ($overdue.Count -gt 0) {
        $roleOverdue = @($overdue | Where-Object { $_.Category -eq 'PrivilegedRoles' })
        $severity = if ($roleOverdue.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $overdue.Count 'access review round is past its' 'access review rounds are past their') + ' end date but not finished') `
            -Evidence ("The scheduled end date has passed while status remains nonterminal; {0} privileged roles." -f (Format-EACount $roleOverdue.Count 'instance covers' 'instances cover')) `
            -WhyItMatters 'Access that reviewers should have removed stays in place while a review is overdue. It also shows the review process is not working as intended.' `
            -RecommendedAction 'Chase the reviewers, finish the listed reviews and apply the results; then fix reviewer assignments and reminders so reviews finish on time' `
            -DocumentationUrl $manageDoc -SourceFile $overdueSrc -ResultRows $overdue.ToArray() -RuleId 'access-review-overdue'
    }

    $desired = @(
        @{ Category='PrivilegedRoles'; Severity='Medium'; Label='admin (privileged) roles'
           Why='Admin roles that nobody re-confirms tend to stay assigned after people change jobs, leaving powerful accounts for attackers to target.' },
        @{ Category='Guests';          Severity='Low';    Label='guest users'
           Why='Guest accounts often outlive the project or contract they were created for, leaving outsiders with access to your data.' },
        @{ Category='InactiveUsers';   Severity='Low';    Label='inactive users'
           Why='Enabled accounts that nobody uses are easy to misuse, because nobody notices when someone else signs in with them.' },
        @{ Category='EnterpriseApps';  Severity='Low';    Label='enterprise applications'
           Why='People keep access to business applications after they stop needing it unless someone regularly checks who is assigned.' },
        @{ Category='Groups';          Severity='Low';    Label='group memberships'
           Why='Group memberships grant access to files, apps and sites; without regular review, people keep that access after they change roles.' }
    )
    foreach ($item in $desired) {
        if (-not $effectiveCategories.Contains($item.Category)) {
            Add-EAGovFinding -Severity $item.Severity -CheckId $checkId -Category 'Identity Governance' `
                -Title ("No recurring access review covers {0}" -f $item.Label) `
                -Evidence ("No nonterminal recurring definition scope was classified as {0}. One-time, stopped, or completed definitions don't count as ongoing coverage." -f $item.Category) `
                -WhyItMatters $item.Why `
                -RecommendedAction ("Create a recurring access review for {0} in {1}, or document the equivalent review process you use instead" -f $item.Label,$reviewsPath) `
                -DocumentationUrl $guideDoc -SourceFile $src -RuleId ("access-review-missing-" + $item.Category.ToLowerInvariant())
        }
    }

    # Role-assignable groups need explicit coverage. This enrichment is optional because
    # it requires Group.Read.All in addition to AccessReview.Read.All.
    $roleGroups = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole%20eq%20true&$select=id,displayName,isAssignableToRole&$top=999&$count=true' -Headers @{ ConsistencyLevel='eventual' }
    if ($roleGroups.Success) {
        $uncoveredRoleGroups = @($roleGroups.Rows | Where-Object { -not $reviewedGroupIds.Contains([string](Get-EAGovProperty $_ 'id')) })
        if ($uncoveredRoleGroups.Count -gt 0) {
            $roleRows = @($uncoveredRoleGroups | ForEach-Object {
                $groupId = [string](Get-EAGovProperty $_ 'id')
                [pscustomobject]@{
                    Id=$groupId; DisplayName=(Get-EAGovProperty $_ 'displayName')
                    OnlyOneTimeOrEndedReview=$everReviewedGroupIds.Contains($groupId)
                }
            })
            $onceReviewed = @($roleRows | Where-Object { $_.OnlyOneTimeOrEndedReview }).Count
            $roleSrc = Write-Evidence -BaseName 'access_review_uncovered_role_groups' -Rows $roleRows -Title 'Role-Assignable Groups Without a Recurring Access Review'
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title ((Format-EACount $roleRows.Count 'group that can hold admin roles has' 'groups that can hold admin roles have') + ' no recurring access review') `
                -Evidence ("These role-assignable groups (isAssignableToRole=true) were not found in the scope of any recurring access review that is still running. {0} reviewed only once or in a review that has ended (OnlyOneTimeOrEndedReview=True), which does not count as ongoing coverage. A broad all-groups review is not assumed to include them." -f (Format-EACount $onceReviewed 'of them was' 'of them were')) `
                -WhyItMatters 'Membership of these groups can give admin rights. Without a review, people who no longer need admin access stay in the group.' `
                -RecommendedAction ("Create a recurring access review of the members and owners of each listed group in {0}, with 'Auto apply results to resource' turned on" -f $reviewsPath) `
                -DocumentationUrl $guideDoc -SourceFile $roleSrc -ResultRows $roleRows -RuleId 'access-review-role-groups-uncovered'
        }
        if ($roleGroups.Truncated) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Role-assignable group access-review coverage' `
                -Reason "pagination exceeded $($roleGroups.Pages) pages; only the groups read were compared." -RequiredScope 'Group.Read.All' `
                -DocumentationUrl $doc -SourceFile $src -Partial -Subject 'the list of groups that can hold admin roles' `
                -Impact 'Admin-role groups without an access review may be missing from this report.'
        }
    } else {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Role-assignable group access-review coverage' `
            -Reason ([string]$roleGroups.Error.Exception.Message) -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $doc -SourceFile $src -Subject 'the list of groups that can hold admin roles' `
            -Impact 'Whether admin-role groups have an access review was not checked.'
    }

    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
        -Title ("Access review setup recorded ({0})" -f (Format-EACount $rows.Count 'review' 'reviews')) `
        -Evidence ("Definitions={0}; recurring nonterminal categories={1}; all categories={2}; overdue instances={3}." -f $rows.Count,($effectiveCategories -join ', '),($categories -join ', '),$overdue.Count) `
        -WhyItMatters 'The list shows which kinds of access are reviewed regularly and where reviews are running late.' `
        -RecommendedAction 'Compare the list with your own list of sensitive access and make sure each area has an owner and a recurring review' `
        -DocumentationUrl $guideDoc -SourceFile $src -ResultRows $rows.ToArray() -RuleId 'access-review-inventory'
}

function Invoke-Check-AuthRecovery {
    [CmdletBinding()]
    param()

    $checkId = 'authrecovery'
    $doc = 'https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0'
    $policyDoc = 'https://learn.microsoft.com/graph/api/authenticationmethodspolicy-get?view=graph-rest-1.0'
    $ssprDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr'
    $passwordlessDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-plan-prerequisites-phishing-resistant-passwordless-authentication'
    $systemPreferredDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-system-preferred-authentication'
    $migrationDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-methods-manage'
    $campaignDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-registration-campaign'
    $methodsPath = 'Entra admin center > Entra ID > Authentication methods'

    # authrecovery is registered as self-gating (Scopes=@()), so a missing
    # AuditLog.Read.All must not abort the independent policy, password-protection and
    # hybrid sub-controls below. Record the failure as a coverage gap instead.
    $registrationKnown = $true
    $registrationError = $null
    try {
        $registration = @(Get-EARegistrationDetails)
    } catch {
        $registration = @()
        $registrationKnown = $false
        $registrationError = [string]$_.Exception.Message
    }
    $rows = @(foreach ($record in $registration) {
        [pscustomobject]@{
            Id                 = Get-EAGovProperty $record 'id'
            UserPrincipalName  = Get-EAGovProperty $record 'userPrincipalName'
            UserDisplayName    = Get-EAGovProperty $record 'userDisplayName'
            UserType           = Get-EAGovProperty $record 'userType'
            IsAdmin            = Get-EAGovProperty $record 'isAdmin'
            IsSsprEnabled      = Get-EAGovProperty $record 'isSsprEnabled'
            IsSsprRegistered   = Get-EAGovProperty $record 'isSsprRegistered'
            IsSsprCapable      = Get-EAGovProperty $record 'isSsprCapable'
            IsMfaRegistered    = Get-EAGovProperty $record 'isMfaRegistered'
            IsMfaCapable       = Get-EAGovProperty $record 'isMfaCapable'
            IsPasswordlessCapable = Get-EAGovProperty $record 'isPasswordlessCapable'
            IsSystemPreferredAuthenticationMethodEnabled = Get-EAGovProperty $record 'isSystemPreferredAuthenticationMethodEnabled'
            SystemPreferredAuthenticationMethods = (@(Get-EAGovProperty $record 'systemPreferredAuthenticationMethods') -join '; ')
            MethodsRegistered  = (@(Get-EAGovProperty $record 'methodsRegistered') -join '; ')
            LastUpdatedDateTime = Get-EAGovProperty $record 'lastUpdatedDateTime'
        }
    })
    $src = Write-Evidence -BaseName 'authentication_recovery_registration' -Rows @($rows) `
        -Title 'Authentication Recovery, Passwordless, and System-Preferred Registration'

    if (-not $registrationKnown) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method user registration details' `
            -Reason ("the registration report read failed ({0}); SSPR, passwordless and system-preferred registration rules were not evaluated." -f $registrationError) `
            -RequiredScope 'AuditLog.Read.All' -DocumentationUrl $doc -SourceFile $src `
            -Subject "the report of users' registered sign-in methods" `
            -Impact 'Whether users can reset their own password or sign in without a password was not checked.'
    } elseif ($rows.Count -eq 0) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method user registration details' `
            -Reason 'the API returned no rows; disabled users are not represented by this API and tenant-wide recovery posture cannot be inferred.' `
            -RequiredScope 'AuditLog.Read.All' -DocumentationUrl $doc -SourceFile $src `
            -Subject "the report of users' registered sign-in methods" `
            -Impact 'Whether users can reset their own password or sign in without a password was not checked.' `
            -RecommendedAction ("Check the user registration details in {0} > Activity; if they are empty too, confirm the audit account has AuditLog.Read.All and a reader role, then run the audit again" -f $methodsPath)
    }
    # Registration-derived rules run only on a successful, non-empty read. The policy,
    # password-protection and hybrid sections below are independent and always run.
    $registrationAvailable = $registrationKnown -and $rows.Count -gt 0

    $members = @($rows | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.UserType) -or [string]$_.UserType -ieq 'member' })
    $admins = @($members | Where-Object { $_.IsAdmin -eq $true })
    $ssprEnabled = @($members | Where-Object { $_.IsSsprEnabled -eq $true })
    $ssprNotCapable = @($ssprEnabled | Where-Object { $_.IsSsprCapable -ne $true })
    $passwordless = @($members | Where-Object { $_.IsPasswordlessCapable -eq $true })
    $passwordlessAdmins = @($admins | Where-Object { $_.IsPasswordlessCapable -eq $true })
    $adminsWithoutPasswordless = @($admins | Where-Object { $_.IsPasswordlessCapable -ne $true })

    if ($registrationAvailable) {
        if ($ssprEnabled.Count -eq 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
                -Title 'Self-service password reset is not turned on for any user' `
                -Evidence ("The registration report contains {0}, with IsSsprEnabled=true for zero." -f (Format-EACount $members.Count 'member user' 'member users')) `
                -WhyItMatters 'Without self-service password reset (SSPR), every forgotten password goes through the helpdesk, where an attacker can pose as a user on the phone to get a password reset.' `
                -RecommendedAction 'Turn on self-service password reset for all users (a pilot group first if needed) in Entra admin center > Entra ID > Password reset > Properties, and require two methods to reset' `
                -DocumentationUrl $ssprDoc -SourceFile $src -RuleId 'sspr-no-enabled-members'
        } elseif ($ssprNotCapable.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
                -Title ((Format-EACount $ssprNotCapable.Count 'user allowed to reset their own password has' 'users allowed to reset their own password have') + ' not set up a way to do it') `
                -Evidence 'IsSsprEnabled=true but IsSsprCapable is not true: these users are enabled by policy but have not registered enough allowed recovery methods.' `
                -WhyItMatters 'These users cannot reset their own password, so they depend on helpdesk resets (which attackers try to abuse) and can be locked out when it matters most.' `
                -RecommendedAction "Ask these users to register reset methods at https://aka.ms/mysecurityinfo, and turn on 'Require users to register when signing in' in Entra admin center > Entra ID > Password reset > Registration" `
                -DocumentationUrl $ssprDoc -SourceFile $src -ResultRows $ssprNotCapable -RuleId 'sspr-enabled-not-capable'
        }

        if ($adminsWithoutPasswordless.Count -gt 0) {
            Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Authentication' `
                -Title ((Format-EACount $adminsWithoutPasswordless.Count 'admin account has' 'admin accounts have') + ' no passwordless sign-in method, such as a passkey, set up') `
                -Evidence ("Administrators with IsPasswordlessCapable=true: {0}/{1}; every remaining administrator is listed. Passwordless capability is not by itself proof that Conditional Access requires phishing-resistant authentication. Related: the 'MFA Capability & Method Strength' check (mfa) scores admins without a phishing-resistant method separately (rule mfa-admins-not-phishing-resistant); registering a passkey or Windows Hello for Business fixes both." -f $passwordlessAdmins.Count,$admins.Count) `
                -WhyItMatters 'Admins who still sign in with a password can have it stolen by a fake sign-in page or guessed, and a helpdesk password reset can be abused to take over the account.' `
                -RecommendedAction 'Register a passkey (FIDO2 security key or passkey in Microsoft Authenticator) or Windows Hello for Business for every admin, then require phishing-resistant sign-in for admins with a Conditional Access authentication strength (Entra admin center > Entra ID > Conditional Access)' `
                -DocumentationUrl $passwordlessDoc -SourceFile $src -ResultRows $adminsWithoutPasswordless -RuleId 'passwordless-admins-not-capable'
        }

        if ($members.Count -gt 0) {
            $passwordlessPercent = [math]::Round(($passwordless.Count * 100.0) / $members.Count, 1)
            if ($passwordlessPercent -lt 25) {
                Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Authentication' `
                    -Title ("Only {0}% of users can sign in without a password" -f $passwordlessPercent) `
                    -Evidence ("{0}/{1} member users are reported as passwordless capable. The 25% threshold is an adoption-prioritization threshold, not a compliance requirement." -f $passwordless.Count,$members.Count) `
                    -WhyItMatters 'Passwords are the main target of phishing and password-guessing attacks. The fewer users who can sign in without one, the more accounts stay exposed.' `
                    -RecommendedAction 'Roll out passwordless sign-in (passkeys, Windows Hello for Business or Microsoft Authenticator), starting with admins and other high-risk users, and track the share in each audit' `
                    -DocumentationUrl $passwordlessDoc -SourceFile $src -RuleId 'passwordless-low-adoption'
            }
        }

        $systemPreferredKnown = @($members | Where-Object { $null -ne $_.IsSystemPreferredAuthenticationMethodEnabled })
        if ($systemPreferredKnown.Count -eq 0) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'System-preferred authentication status' `
                -Reason 'the property was absent/null on every registration record.' -RequiredScope 'AuditLog.Read.All' `
                -DocumentationUrl $doc -SourceFile $src -Subject 'the system-preferred authentication status of users' `
                -Impact 'Whether users are steered to their strongest sign-in method was not checked.' `
                -RecommendedAction ("Check the System-preferred authentication setting in {0} > Settings" -f $methodsPath)
        } else {
            $memberSystemPreferredOff = @($members | Where-Object { $_.IsSystemPreferredAuthenticationMethodEnabled -eq $false })
            if ($memberSystemPreferredOff.Count -gt 0) {
                $adminSystemPreferredOff = @($memberSystemPreferredOff | Where-Object { $_.IsAdmin -eq $true })
                $severity = if ($adminSystemPreferredOff.Count -gt 0) { 'Medium' } else { 'Low' }
                Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Authentication' `
                    -Title ("System-preferred authentication is off for {0}" -f (Format-EACount $memberSystemPreferredOff.Count 'user' 'users')) `
                    -Evidence ("IsSystemPreferredAuthenticationMethodEnabled=false; {0}. The report exposes effective per-user state, not a user choice." -f (Format-EACount $adminSystemPreferredOff.Count 'affected record is an administrator' 'affected records are administrators')) `
                    -WhyItMatters 'System-preferred authentication makes Microsoft ask each user for the strongest method they registered. When it is off, users can choose a weaker method, such as a text message, even when a stronger one is available.' `
                    -RecommendedAction ("Turn on System-preferred authentication for all users in {0} > Settings, and exclude only groups with a documented reason" -f $methodsPath) `
                    -DocumentationUrl $systemPreferredDoc -SourceFile $src -ResultRows $memberSystemPreferredOff -RuleId 'system-preferred-member-disabled'
            }
        }
    }

    $policyResult = Invoke-EAGovGraphObject -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    if (-not $policyResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method migration and registration campaign policy' `
            -Reason ([string]$policyResult.Error.Exception.Message) -RequiredScope 'Policy.Read.All' `
            -DocumentationUrl $policyDoc -SourceFile $src -Subject 'the authentication methods policy' `
            -Impact 'The migration status and the registration campaign were not checked here.'
    } else {
        $policy = $policyResult.Value
        $enforcement = Get-EAGovProperty $policy 'registrationEnforcement'
        $campaign = Get-EAGovProperty $enforcement 'authenticationMethodsRegistrationCampaign'
        $policyRows = @([pscustomobject]@{
            PolicyMigrationState = Get-EAGovProperty $policy 'policyMigrationState'
            PolicyVersion        = Get-EAGovProperty $policy 'policyVersion'
            LastModifiedDateTime = Get-EAGovProperty $policy 'lastModifiedDateTime'
            CampaignState        = Get-EAGovProperty $campaign 'state'
            CampaignSnoozeDays   = Get-EAGovProperty $campaign 'snoozeDurationInDays'
            CampaignIncludeTargets = (ConvertTo-EAGovCompactJson (Get-EAGovProperty $campaign 'includeTargets'))
            CampaignExcludeTargets = (ConvertTo-EAGovCompactJson (Get-EAGovProperty $campaign 'excludeTargets'))
        })
        $policySrc = Write-Evidence -BaseName 'authentication_recovery_policy' -Rows $policyRows `
            -Title 'Authentication Methods Migration and Registration Campaign'

        $migration = [string](Get-EAGovProperty $policy 'policyMigrationState')
        if ($migration -and $migration -notmatch '^migrationComplete$') {
            $severity = if ($migration -match '^preMigration$') { 'Medium' } else { 'Low' }
            Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Authentication' `
                -Title ("Old MFA and password-reset method settings still apply (migration state: {0})" -f $migration) `
                -Evidence ("policyMigrationState={0} (finished = migrationComplete), so legacy MFA/SSPR policy settings may still affect which methods work. Related: the 'Authentication Methods Policy' check (authmethodpolicy) reports the same setting as rule authmethodpolicy-migration-incomplete; one fix resolves both." -f $migration) `
                -WhyItMatters 'Until the move to the single authentication methods policy is finished, the old multifactor authentication (MFA) and self-service password reset (SSPR) settings can still allow methods that the new policy has turned off.' `
                -RecommendedAction ("Move the old MFA and SSPR method settings into the authentication methods policy, then set {0} > Policies > Manage migration to Migration Complete" -f $methodsPath) `
                -DocumentationUrl $migrationDoc -SourceFile $policySrc -RuleId 'auth-method-policy-migration-not-complete'
        } elseif ([string]::IsNullOrWhiteSpace($migration)) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method migration state' `
                -Reason 'policyMigrationState was absent from the response.' -RequiredScope 'Policy.Read.All' `
                -DocumentationUrl $policyDoc -SourceFile $policySrc -Subject 'the authentication methods migration status' `
                -Impact 'Whether old MFA and password-reset method settings still apply was not checked.' `
                -RecommendedAction ("Check {0} > Policies > Manage migration in the admin center" -f $methodsPath)
        }

        # The main authmethodpolicy check already reports a disabled campaign on its own.
        # This rule only adds the population that is not yet passwordless, so it needs
        # registration data; without it the registration coverage finding above applies.
        # 'default' is the Microsoft managed state, which is an active campaign (the main
        # check treats it as on too), so only disabled or unreadable states count here.
        # An empty or unexpected state is not proof that the campaign is off: it is a
        # coverage gap under its own rule (coverage-registration-campaign-state), adds no
        # risk points, and never shares a trend identity with the known-off finding.
        # One-time id change, part of the finding-id migration: the unknown state used to
        # be reported under registration-campaign-disabled.
        $campaignState = [string](Get-EAGovProperty $campaign 'state')
        if ($campaignState -notmatch '^(enabled|default)$' -and $registrationAvailable -and $members.Count -gt $passwordless.Count) {
            $notPasswordless = $members.Count - $passwordless.Count
            if ($campaignState -match '^disabled$') {
                Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Authentication' `
                    -Title ("Users are not prompted to set up stronger sign-in methods ({0})" -f (Format-EACount $notPasswordless 'is not passwordless yet' 'are not passwordless yet')) `
                    -Evidence ("Campaign state={0}; {1} not passwordless capable. Related: the 'Authentication Methods Policy' check (authmethodpolicy) scores the campaign being off (rule authmethodpolicy-registration-campaign-off); this finding adds how many users it affects." -f $campaignState,(Format-EACount $notPasswordless 'member user is' 'member users are')) `
                    -WhyItMatters 'The registration campaign asks users to set up Microsoft Authenticator or a passkey when they sign in. Without it, many users never move away from weaker methods such as text messages.' `
                    -RecommendedAction ("Set the registration campaign to Microsoft managed or Enabled for all users in {0} > Registration campaign" -f $methodsPath) `
                    -DocumentationUrl $campaignDoc -SourceFile $policySrc -RuleId 'registration-campaign-disabled'
            } else {
                $stateText = if ([string]::IsNullOrWhiteSpace($campaignState)) { 'empty' } else { $campaignState }
                Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Registration campaign state' `
                    -Reason ("registrationEnforcement.authenticationMethodsRegistrationCampaign.state was '{0}' (missing or unexpected), so the campaign state is unknown, not proven off. Related: the 'Authentication Methods Policy' check (authmethodpolicy) reports the same unreadable setting (rule authmethodpolicy-registration-campaign-unknown)." -f $stateText) `
                    -RequiredScope 'Policy.Read.All' -DocumentationUrl $campaignDoc -SourceFile $policySrc `
                    -Subject 'the registration campaign state' `
                    -Impact ("Whether {0} prompted to set up stronger sign-in methods was not checked" -f (Format-EACount $notPasswordless 'member user who is not passwordless yet is' 'member users who are not passwordless yet are')) `
                    -RecommendedAction ("Check the registration campaign in {0} > Registration campaign and set it to Microsoft managed or Enabled for all users if it is off" -f $methodsPath)
            }
        }
    }

    # Password-protection settings are stored as tenant group settings.  Merge
    # explicit values over the template defaults because Graph returns no setting
    # object when the tenant still uses every default.
    $passwordProtectionDoc = 'https://learn.microsoft.com/graph/group-directory-settings'
    $customBannedDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-configure-custom-password-protection'
    $smartLockoutDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout'
    $onPremProtectionDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises-operations'
    $writebackDoc = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr-writeback'
    $passwordTemplateId = '5cf42378-d67d-4f36-ba46-e8b86229381d'
    $settingResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/groupSettings?$top=999'
    $templateResult = Invoke-EAGovGraphObject -Uri ("https://graph.microsoft.com/v1.0/groupSettingTemplates/{0}" -f $passwordTemplateId)
    $passwordSetting = $null
    if ($settingResult.Success -and -not $settingResult.Truncated) {
        $passwordSetting = @($settingResult.Rows | Where-Object {
            [string](Get-EAGovProperty $_ 'templateId') -ieq $passwordTemplateId -or
            [string](Get-EAGovProperty $_ 'displayName') -ieq 'Password Rule Settings'
        } | Select-Object -First 1)
        if ($passwordSetting.Count -gt 0) { $passwordSetting = $passwordSetting[0] } else { $passwordSetting = $null }
    }

    $passwordMap = if ($settingResult.Success -and -not $settingResult.Truncated -and $templateResult.Success) {
        Merge-EAGovSettingMap -Template $templateResult.Value -Setting $passwordSetting
    } elseif ($passwordSetting) {
        ConvertTo-EAGovSettingMap -Setting $passwordSetting
    } else { @{} }

    $bannedWords = @(if ($passwordMap.ContainsKey('BannedPasswordList')) {
        @(([string]$passwordMap['BannedPasswordList'] -split "`t") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    } else { @() })
    $passwordRows = @([pscustomobject]@{
        EffectiveValuesKnown                = ($passwordMap.Count -gt 0)
        UsesExplicitTenantSetting           = ($null -ne $passwordSetting)
        EnableCustomBannedPasswordCheck     = ConvertTo-EAGovBoolean $passwordMap['EnableBannedPasswordCheck']
        CustomBannedPasswordCount           = $bannedWords.Count
        EnableOnPremisesPasswordProtection  = ConvertTo-EAGovBoolean $passwordMap['EnableBannedPasswordCheckOnPremises']
        OnPremisesPasswordProtectionMode    = $passwordMap['BannedPasswordCheckOnPremisesMode']
        LockoutThreshold                    = $passwordMap['LockoutThreshold']
        LockoutDurationInSeconds            = $passwordMap['LockoutDurationInSeconds']
    })
    $passwordSrc = Write-Evidence -BaseName 'authentication_password_protection' -Rows $passwordRows `
        -Title 'Password Protection and Smart Lockout Settings' `
        -Notes @('The custom banned-password words themselves are deliberately not exported; only the count is retained.')

    if (-not $settingResult.Success -or $settingResult.Truncated -or (-not $templateResult.Success -and -not $passwordSetting)) {
        $reasons = New-Object System.Collections.Generic.List[string]
        if (-not $settingResult.Success) { $reasons.Add([string]$settingResult.Error.Exception.Message) | Out-Null }
        elseif ($settingResult.Truncated) { $reasons.Add('groupSettings pagination limit reached') | Out-Null }
        if (-not $templateResult.Success -and -not $passwordSetting) { $reasons.Add([string]$templateResult.Error.Exception.Message) | Out-Null }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Password protection and smart-lockout settings' `
            -Reason ($reasons -join '; ') -RequiredScope 'Directory.Read.All' `
            -DocumentationUrl $passwordProtectionDoc -SourceFile $passwordSrc `
            -Subject 'the password protection and account lockout settings' `
            -Impact 'The banned-password list, the lockout limit and on-premises password protection were not checked.'
    } elseif ($passwordMap.Count -gt 0) {
        $customEnabled = ConvertTo-EAGovBoolean $passwordMap['EnableBannedPasswordCheck']
        if ($bannedWords.Count -gt 0 -and $customEnabled -ne $true) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
                -Title 'Custom banned-password list is set up but not enforced' `
                -Evidence ("Custom banned-password entries={0}; EnableBannedPasswordCheck={1}." -f $bannedWords.Count,$customEnabled) `
                -WhyItMatters 'Users can still choose passwords built from your company, product or place names, which attackers try first when guessing passwords.' `
                -RecommendedAction ("Set 'Enforce custom list' to Yes in {0} > Password protection, and check that the list is still up to date" -f $methodsPath) `
                -DocumentationUrl $customBannedDoc -SourceFile $passwordSrc -RuleId 'custom-banned-password-check-disabled'
        }
        $lockoutThreshold = 0
        if ([int]::TryParse([string]$passwordMap['LockoutThreshold'], [ref]$lockoutThreshold) -and $lockoutThreshold -gt 10) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Authentication' `
                -Title ("Account lockout allows {0} wrong passwords before it starts (Microsoft default: 10)" -f $lockoutThreshold) `
                -Evidence ("The effective smart lockout LockoutThreshold is {0}, above the Microsoft default of 10 failed attempts; this is a review threshold, not a universal compliance boundary." -f $lockoutThreshold) `
                -WhyItMatters 'A higher limit gives attackers more password guesses per account before smart lockout temporarily blocks further attempts.' `
                -RecommendedAction ("Set 'Lockout threshold' back to 10 or lower in {0} > Password protection, unless you have a documented reason for the higher value" -f $methodsPath) `
                -DocumentationUrl $smartLockoutDoc -SourceFile $passwordSrc -RuleId 'smart-lockout-threshold-high'
        }
    }

    # Graph exposes the directory-sync feature flag for password writeback, but
    # Microsoft documents that this particular property isn't in use. Capture it
    # without treating true as proof of operational writeback health.
    $syncDoc = 'https://learn.microsoft.com/graph/api/resources/onpremisesdirectorysynchronizationfeature?view=graph-rest-1.0'
    $organizationResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,onPremisesSyncEnabled'
    $hybrid = $organizationResult.Success -and @($organizationResult.Rows | Where-Object { (Get-EAGovProperty $_ 'onPremisesSyncEnabled') -eq $true }).Count -gt 0
    if ($hybrid) {
        $syncResult = Get-EAGovOnPremisesSyncObject
        $syncAccess = Get-EAGovOnPremSyncAccess
        if (-not $syncResult.Success -or $null -eq $syncResult.Object) {
            $syncReason = if ($syncResult.Success) { 'Graph returned no on-premises synchronization object.' } else { [string]$syncResult.Error.Exception.Message }
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Hybrid SSPR password-writeback configuration' `
                -Reason ($syncReason + $syncAccess.Note) -RequiredScope $syncAccess.Scope `
                -DocumentationUrl $syncDoc -SourceFile $src -Subject 'the password writeback setting for accounts synced from on-premises' `
                -Impact 'Whether password resets reach on-premises Active Directory was not checked.' `
                -RecommendedAction 'Test a self-service password reset with a synced test account and check the writeback settings in Entra admin center > Entra ID > Password reset > On-premises integration; to let the audit read the sync settings, run it signed in as a Global Administrator with OnPremDirectorySynchronization.Read.All (app-only sign-in is not supported for this setting)'
        } else {
            $features = Get-EAGovProperty $syncResult.Object 'features'
            $writebackPresent = Test-EAGovPropertyPresent $features 'passwordWritebackEnabled'
            $writebackValue = Get-EAGovProperty $features 'passwordWritebackEnabled'
            Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Authentication' `
                -Title 'Password writeback to on-premises Active Directory must be tested by hand' `
                -Evidence ("Graph passwordWritebackEnabled present={0}; value={1}. Microsoft documents that this property isn't in use, so the audit does not interpret it as proof that resets are writing back." -f $writebackPresent,$writebackValue) `
                -WhyItMatters 'The audit cannot see whether password resets made in the cloud reach on-premises Active Directory (AD). If writeback is broken, synced users cannot reset their own password even though the report shows them as able to.' `
                -RecommendedAction 'Test a self-service password reset with a synced test account in each domain, and check the writeback settings and errors in Entra admin center > Entra ID > Password reset > On-premises integration' `
                -DocumentationUrl $writebackDoc -SourceFile $src -RuleId 'hybrid-password-writeback-manual-validation' -CoverageGap
        }

        if ($passwordMap.Count -gt 0) {
            $onPremProtection = ConvertTo-EAGovBoolean $passwordMap['EnableBannedPasswordCheckOnPremises']
            $onPremMode = [string]$passwordMap['BannedPasswordCheckOnPremisesMode']
            if ($onPremProtection -ne $true -or $onPremMode -notmatch '^(Enforce|Enforced)$') {
                # Same rule id either way (the exposure is identical), but tell the reader
                # whether this is an explicit choice or the untouched Microsoft default.
                $onPremSource = if ($null -ne $passwordSetting) {
                    'explicit tenant Password Rule Settings object'
                } else {
                    'Microsoft template defaults - the tenant has never saved Password protection settings, so domain controller agents are probably not deployed'
                }
                Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
                    -Title 'Banned-password check is not enforced in on-premises Active Directory' `
                    -Evidence ("EnableBannedPasswordCheckOnPremises={0}; mode={1}; source={2}." -f $onPremProtection,$onPremMode,$onPremSource) `
                    -WhyItMatters 'Users can still set weak, commonly guessed passwords in on-premises Active Directory (AD), and synced accounts then use the same weak password to sign in to Microsoft 365.' `
                    -RecommendedAction ("Install the Microsoft Entra Password Protection proxy and domain controller agents, review the audit-mode results, then set 'Mode' to Enforced in {0} > Password protection (Microsoft Entra ID P1 or P2 is required for synced users)" -f $methodsPath) `
                    -DocumentationUrl $onPremProtectionDoc -SourceFile $passwordSrc -RuleId 'onprem-password-protection-not-enforced'
            }
        }
    } elseif (-not $organizationResult.Success -or $organizationResult.Truncated) {
        $reason = if ($organizationResult.Success) { 'organization pagination limit reached' } else { [string]$organizationResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Hybrid status for password recovery controls' `
            -Reason $reason -RequiredScope 'Organization.Read.All' -DocumentationUrl $syncDoc -SourceFile $src `
            -Subject "the tenant's on-premises sync status" `
            -Impact 'Password writeback and on-premises password protection were not checked.'
    }

    if (-not $registrationAvailable) { return }
    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Authentication' `
        -Title 'Password reset and passwordless readiness recorded' `
        -Evidence ("Members={0}; SSPR enabled/registered/capable={1}/{2}/{3}; passwordless capable={4}; admins={5}." -f `
            $members.Count,$ssprEnabled.Count,@($members | Where-Object {$_.IsSsprRegistered -eq $true}).Count,
            @($members | Where-Object {$_.IsSsprCapable -eq $true}).Count,$passwordless.Count,$admins.Count) `
        -WhyItMatters 'Registration data shows whether users can actually reset their password and sign in without one, not just whether a policy exists.' `
        -RecommendedAction 'Compare these numbers between audits and help users who are not ready before you enforce stronger sign-in rules' `
        -DocumentationUrl $doc -SourceFile $src -ResultRows @($rows) -RuleId 'auth-recovery-baseline'
}

function Invoke-Check-GroupGovernance {
    [CmdletBinding()]
    param()

    $checkId = 'groupgovernance'
    $doc = 'https://learn.microsoft.com/entra/identity/users/groups-lifecycle'
    $reportDoc = 'https://learn.microsoft.com/graph/api/reportroot-getoffice365groupsactivitydetail?view=graph-rest-beta'
    $groupSettingsGuideDoc = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-settings-cmdlets'
    $namingDoc = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-naming-policy'
    $roleGroupDoc = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept'
    $dynamicDoc = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership'
    $groupsPath = 'Entra admin center > Entra ID > Groups'
    $groupUri = 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName,description,groupTypes,mailEnabled,securityEnabled,visibility,isAssignableToRole,membershipRule,membershipRuleProcessingState,createdDateTime,renewedDateTime,expirationDateTime,onPremisesSyncEnabled,resourceProvisioningOptions&$expand=owners($select=id,displayName,userPrincipalName)&$top=999'
    $result = Invoke-EAGovGraphCollection -Uri $groupUri
    if (-not $result.Success) { throw $result.Error }

    $activityById = @{}
    $activityCoverage = $false
    $activityResult = Invoke-EAGovGraphCollection -Uri "https://graph.microsoft.com/beta/reports/getOffice365GroupsActivityDetail(period='D180')?`$format=application/json&`$top=200"
    if ($activityResult.Success -and -not $activityResult.Truncated) {
        $activityCoverage = $true
        foreach ($activity in @($activityResult.Rows)) {
            $groupId = [string](Get-EAGovProperty $activity 'groupId')
            if ($groupId) { $activityById[$groupId] = $activity }
        }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    $ownerReadErrors = New-Object System.Collections.Generic.List[object]
    foreach ($group in @($result.Rows)) {
        $id = [string](Get-EAGovProperty $group 'id')
        $ownersKnown = Test-EAGovPropertyPresent $group 'owners'
        $owners = @(if ($ownersKnown) { @(Get-EAGovProperty $group 'owners') } else { @() })

        # An omitted expanded navigation is unknown, not ownerless. Retry through the
        # documented sponsors/owners-style navigation using another GET.
        if (-not $ownersKnown -and $id) {
            $ownerResult = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/owners?`$select=id,displayName,userPrincipalName" -f [uri]::EscapeDataString($id))
            if ($ownerResult.Success -and -not $ownerResult.Truncated) {
                $ownersKnown = $true
                $owners = @($ownerResult.Rows)
            } else {
                $reason = if ($ownerResult.Success) { 'pagination limit reached' } else { [string]$ownerResult.Error.Exception.Message }
                $ownerReadErrors.Add([pscustomobject]@{ GroupId=$id; DisplayName=(Get-EAGovProperty $group 'displayName'); Reason=$reason }) | Out-Null
            }
        }

        $types = @(Get-EAGovProperty $group 'groupTypes')
        $isM365 = $types -contains 'Unified'
        $isDynamic = $types -contains 'DynamicMembership'
        $activity = if ($activityById.ContainsKey($id)) { $activityById[$id] } else { $null }
        $activityKnownForGroup = $null -ne $activity
        $lastActivity = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'lastActivityDate' } else { $null }

        $rows.Add([pscustomobject]@{
            Id                    = $id
            DisplayName           = Get-EAGovProperty $group 'displayName'
            Description           = Get-EAGovProperty $group 'description'
            GroupKind             = if ($isM365) { 'Microsoft365' } elseif ((Get-EAGovProperty $group 'securityEnabled') -eq $true) { 'Security' } else { 'Other' }
            MailEnabled           = Get-EAGovProperty $group 'mailEnabled'
            SecurityEnabled       = Get-EAGovProperty $group 'securityEnabled'
            Visibility            = Get-EAGovProperty $group 'visibility'
            IsAssignableToRole    = Get-EAGovProperty $group 'isAssignableToRole'
            IsDynamic             = $isDynamic
            MembershipRule        = Get-EAGovProperty $group 'membershipRule'
            MembershipRuleState   = Get-EAGovProperty $group 'membershipRuleProcessingState'
            OnPremisesSyncEnabled = Get-EAGovProperty $group 'onPremisesSyncEnabled'
            CreatedDateTime       = Get-EAGovProperty $group 'createdDateTime'
            RenewedDateTime       = Get-EAGovProperty $group 'renewedDateTime'
            ExpirationDateTime    = Get-EAGovProperty $group 'expirationDateTime'
            OwnersKnown           = $ownersKnown
            OwnerCount            = if ($ownersKnown) { $owners.Count } else { $null }
            Owners                = (($owners | ForEach-Object {
                (Get-EAGovProperty $_ 'userPrincipalName') ?? (Get-EAGovProperty $_ 'displayName') ?? (Get-EAGovProperty $_ 'id')
            }) -join '; ')
            ActivityEvidenceKnown = $activityKnownForGroup
            LastActivityDate      = $lastActivity
            ExternalMemberCount   = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'externalMemberCount' } else { $null }
            ReportRefreshDate     = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'reportRefreshDate' } else { $null }
            # D180 activity counters. lastActivityDate only covers mail, SharePoint and
            # Yammer, so a Team used only for channel chat and meetings needs the Teams
            # counters to show as active.
            IsDeleted                   = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'isDeleted' } else { $null }
            TeamsChannelMessagesCount   = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'teamsChannelMessagesCount' } else { $null }
            TeamsMeetingsOrganizedCount = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'teamsMeetingsOrganizedCount' } else { $null }
            ExchangeReceivedEmailCount  = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'exchangeReceivedEmailCount' } else { $null }
            SharePointActiveFileCount   = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'sharePointActiveFileCount' } else { $null }
            YammerPostedMessageCount    = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'yammerPostedMessageCount' } else { $null }
            YammerReadMessageCount      = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'yammerReadMessageCount' } else { $null }
            YammerLikedMessageCount     = if ($activityKnownForGroup) { Get-EAGovProperty $activity 'yammerLikedMessageCount' } else { $null }
        }) | Out-Null
    }

    # A successful report call with zero rows isn't useful coverage when the
    # directory contains Microsoft 365 groups. Treat it as unknown rather than
    # silently making every group ineligible for inactivity evaluation.
    $m365GroupCount = @($rows | Where-Object { $_.GroupKind -eq 'Microsoft365' }).Count
    $activityReturnedNoRows = $activityCoverage -and $m365GroupCount -gt 0 -and @($activityResult.Rows).Count -eq 0
    if ($activityReturnedNoRows) { $activityCoverage = $false }

    $src = Write-Evidence -BaseName 'group_governance' -Rows $rows.ToArray() -Title 'Group Ownership, Lifecycle, Visibility, and Activity Governance' `
        -Notes @('A group is considered inactive only when the Microsoft 365 D180 activity report contains a row for it, the group was created before the 180-day window, every Teams, mail, SharePoint and Yammer counter in that row is zero, and LastActivityDate is empty or older than the window. Absence from that report, or an unknown creation date, is unknown, not stale.')

    if ($result.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Group inventory pagination' `
            -Reason "pagination exceeded $($result.Pages) pages." -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $doc -SourceFile $src -Partial -Subject 'the list of groups' `
            -Impact 'Problems with groups beyond the part that was read are missing from this report.'
    }
    if ($ownerReadErrors.Count -gt 0) {
        $ownerErrSrc = Write-Evidence -BaseName 'group_owner_collection_errors' -Rows $ownerReadErrors.ToArray() -Title 'Group Owner Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Group owners' `
            -Reason ("owner data was incomplete for {0}." -f (Format-EACount $ownerReadErrors.Count 'group' 'groups')) -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $doc -SourceFile $ownerErrSrc -Subject 'the owners of some groups' `
            -Impact 'Groups without an owner may be missing from this report.'
    }
    if (-not $activityCoverage) {
        $reason = if ($activityReturnedNoRows) {
            "the API returned zero report rows while {0}" -f (Format-EACount $m365GroupCount 'Microsoft 365 group exists' 'Microsoft 365 groups exist')
        } elseif ($activityResult.Success) { 'pagination limit reached' } else { [string]$activityResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Microsoft 365 group activity (D180)' `
            -Reason $reason -RequiredScope 'Reports.Read.All' -DocumentationUrl $reportDoc -SourceFile $src `
            -Subject 'the Microsoft 365 group activity report' `
            -Impact 'Microsoft 365 groups that nobody uses any more were not identified.'
    }

    # Tenant-level group settings and the Microsoft 365 group expiration policy
    # are separate resources; an object inventory alone cannot assess them.
    $groupSettingsDoc = 'https://learn.microsoft.com/graph/group-directory-settings'
    $unifiedTemplateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'
    $settingsResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/groupSettings?$top=999'
    $settingsTemplateResult = Invoke-EAGovGraphObject -Uri ("https://graph.microsoft.com/v1.0/groupSettingTemplates/{0}" -f $unifiedTemplateId)
    $unifiedSetting = $null
    if ($settingsResult.Success -and -not $settingsResult.Truncated) {
        $candidate = @($settingsResult.Rows | Where-Object {
            [string](Get-EAGovProperty $_ 'templateId') -ieq $unifiedTemplateId -or
            [string](Get-EAGovProperty $_ 'displayName') -ieq 'Group.Unified'
        } | Select-Object -First 1)
        if ($candidate.Count -gt 0) { $unifiedSetting = $candidate[0] }
    }
    $unifiedMap = if ($settingsResult.Success -and -not $settingsResult.Truncated -and $settingsTemplateResult.Success) {
        Merge-EAGovSettingMap -Template $settingsTemplateResult.Value -Setting $unifiedSetting
    } elseif ($unifiedSetting) { ConvertTo-EAGovSettingMap $unifiedSetting } else { @{} }
    $groupSettingRows = @([pscustomobject]@{
        EffectiveValuesKnown       = ($unifiedMap.Count -gt 0)
        UsesExplicitTenantSetting  = ($null -ne $unifiedSetting)
        EnableGroupCreation        = ConvertTo-EAGovBoolean $unifiedMap['EnableGroupCreation']
        GroupCreationAllowedGroupId = $unifiedMap['GroupCreationAllowedGroupId']
        AllowGuestsToBeGroupOwner  = ConvertTo-EAGovBoolean $unifiedMap['AllowGuestsToBeGroupOwner']
        AllowGuestsToAccessGroups  = ConvertTo-EAGovBoolean $unifiedMap['AllowGuestsToAccessGroups']
        AllowToAddGuests           = ConvertTo-EAGovBoolean $unifiedMap['AllowToAddGuests']
        PrefixSuffixNamingRequirement = $unifiedMap['PrefixSuffixNamingRequirement']
        CustomBlockedWordsConfigured = (-not [string]::IsNullOrWhiteSpace([string]$unifiedMap['CustomBlockedWordsList']))
        UsageGuidelinesConfigured  = (-not [string]::IsNullOrWhiteSpace([string]$unifiedMap['UsageGuidelinesUrl']))
        GuestUsageGuidelinesConfigured = (-not [string]::IsNullOrWhiteSpace([string]$unifiedMap['GuestUsageGuidelinesUrl']))
    })
    $groupSettingsSrc = Write-Evidence -BaseName 'group_governance_tenant_settings' -Rows $groupSettingRows -Title 'Tenant Group Governance Settings'
    if (-not $settingsResult.Success -or $settingsResult.Truncated -or (-not $settingsTemplateResult.Success -and -not $unifiedSetting)) {
        $reason = if (-not $settingsResult.Success) { [string]$settingsResult.Error.Exception.Message } `
            elseif ($settingsResult.Truncated) { 'groupSettings pagination limit reached' } `
            else { [string]$settingsTemplateResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Tenant Group.Unified settings' `
            -Reason $reason -RequiredScope 'Directory.Read.All' -DocumentationUrl $groupSettingsDoc -SourceFile $groupSettingsSrc `
            -Subject 'the tenant-wide Microsoft 365 group settings' `
            -Impact 'Who may create groups, whether guests may own groups and the naming policy were not checked.'
    } elseif ($unifiedMap.Count -gt 0) {
        if ((ConvertTo-EAGovBoolean $unifiedMap['AllowGuestsToBeGroupOwner']) -eq $true) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Group Governance' `
                -Title 'Guests are allowed to own Microsoft 365 groups' `
                -Evidence 'The effective Group.Unified setting AllowGuestsToBeGroupOwner=true.' `
                -WhyItMatters "A guest who owns a group can add members and control the group's files, mailbox and Teams content, even after the business relationship with them ends." `
                -RecommendedAction 'Set AllowGuestsToBeGroupOwner to false in the Group.Unified directory setting (only available through Microsoft Graph PowerShell) unless a documented need requires it, then review groups that already have guest owners' `
                -DocumentationUrl $groupSettingsGuideDoc -SourceFile $groupSettingsSrc -RuleId 'group-settings-guest-owners-allowed'
        }
        if ((ConvertTo-EAGovBoolean $unifiedMap['EnableGroupCreation']) -eq $true) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
                -Title 'Every user can create Microsoft 365 groups' `
                -Evidence 'The effective Group.Unified setting EnableGroupCreation=true; no restriction group is applied by this setting.' `
                -WhyItMatters 'Unrestricted creation leads to many groups and Teams with unclear owners, guests and data, which makes access hard to keep under control.' `
                -RecommendedAction 'Decide whether everyone should create groups. If yes, back it with expiration, naming and owner rules; if not, limit creation to an approved group (Group.Unified settings EnableGroupCreation=false and GroupCreationAllowedGroupId)' `
                -DocumentationUrl $groupSettingsGuideDoc -SourceFile $groupSettingsSrc -RuleId 'group-settings-creation-unrestricted'
        }
        if ([string]::IsNullOrWhiteSpace([string]$unifiedMap['PrefixSuffixNamingRequirement']) -and
            [string]::IsNullOrWhiteSpace([string]$unifiedMap['CustomBlockedWordsList'])) {
            Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Group Governance' `
                -Title 'No naming policy for Microsoft 365 groups' `
                -Evidence 'Both PrefixSuffixNamingRequirement and CustomBlockedWordsList are empty in the effective Group.Unified settings.' `
                -WhyItMatters 'A naming standard makes it easier to see what a group is for and who owns it. It helps cleanup but is not a security control on its own.' `
                -RecommendedAction ("If it helps your cleanup process, set a prefix/suffix or blocked words in {0} > Naming policy" -f $groupsPath) `
                -DocumentationUrl $namingDoc -SourceFile $groupSettingsSrc -RuleId 'group-settings-naming-policy-absent'
        }
    }

    $lifecycleDoc = 'https://learn.microsoft.com/graph/api/resources/grouplifecyclepolicy?view=graph-rest-1.0'
    $lifecycleResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/groupLifecyclePolicies?$top=100'
    $lifecycleRows = @(if ($lifecycleResult.Success) {
        @($lifecycleResult.Rows | ForEach-Object { [pscustomobject]@{
            Id=Get-EAGovProperty $_ 'id'; ManagedGroupTypes=Get-EAGovProperty $_ 'managedGroupTypes'
            GroupLifetimeInDays=Get-EAGovProperty $_ 'groupLifetimeInDays'
            AlternateNotificationEmailsConfigured=(-not [string]::IsNullOrWhiteSpace([string](Get-EAGovProperty $_ 'alternateNotificationEmails')))
        } })
    } else { @() })
    $lifecycleSrc = Write-Evidence -BaseName 'group_governance_lifecycle_policy' -Rows $lifecycleRows -Title 'Microsoft 365 Group Expiration Policy'
    if (-not $lifecycleResult.Success -or $lifecycleResult.Truncated) {
        $reason = if ($lifecycleResult.Success) { 'groupLifecyclePolicies pagination limit reached' } else { [string]$lifecycleResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Microsoft 365 group expiration policy' `
            -Reason $reason -RequiredScope 'Directory.Read.All' -DocumentationUrl $lifecycleDoc -SourceFile $lifecycleSrc `
            -Subject 'the Microsoft 365 group expiration policy' `
            -Impact 'Whether unused Microsoft 365 groups expire was not checked.'
    } elseif ($m365GroupCount -gt 0 -and ($lifecycleRows.Count -eq 0 -or @($lifecycleRows | Where-Object { [string]$_.ManagedGroupTypes -notmatch '^None$' }).Count -eq 0)) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
            -Title 'Microsoft 365 groups never expire' `
            -Evidence ("Microsoft 365 groups={0}; lifecycle policy records={1}; none apply to All or Selected groups." -f $m365GroupCount,$lifecycleRows.Count) `
            -WhyItMatters 'Without expiration, groups and the access they give stay forever after the project ends, unless someone cleans them up by hand.' `
            -RecommendedAction ("Turn on group expiration in {0} > Expiration (for example 365 days, with owners renewing by email), or document the cleanup process you use instead" -f $groupsPath) `
            -DocumentationUrl $doc -SourceFile $lifecycleSrc -RuleId 'm365-group-expiration-policy-absent'
    }

    $roleOwnerless = @($rows | Where-Object { $_.OwnersKnown -and $_.OwnerCount -eq 0 -and $_.IsAssignableToRole -eq $true })
    if ($roleOwnerless.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Group Governance' `
            -Title ((Format-EACount $roleOwnerless.Count 'group that can hold admin roles has' 'groups that can hold admin roles have') + ' no owner') `
            -Evidence 'Owner enumeration succeeded and returned zero owners for these role-assignable groups (isAssignableToRole=true).' `
            -WhyItMatters 'These groups can give admin rights. With no owner, nobody is accountable for who is in them, so unneeded admin access is not noticed or removed.' `
            -RecommendedAction 'Name an accountable owner for each listed group (two for resilience), manage that ownership through Privileged Identity Management (PIM) for Groups, and set up a recurring access review of the members' `
            -DocumentationUrl $roleGroupDoc -SourceFile $src -ResultRows $roleOwnerless -RuleId 'role-group-ownerless'
    }

    $cloudOwnerless = @($rows | Where-Object {
        $_.OwnersKnown -and $_.OwnerCount -eq 0 -and $_.IsAssignableToRole -ne $true -and
        $_.OnPremisesSyncEnabled -ne $true -and $_.GroupKind -in @('Security','Microsoft365')
    })
    if ($cloudOwnerless.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Group Governance' `
            -Title (Format-EACount $cloudOwnerless.Count 'cloud group has no owner' 'cloud groups have no owner') `
            -Evidence 'Security or Microsoft 365 groups created in the cloud: owner enumeration succeeded and returned zero owners. Groups synced from on-premises are reported separately.' `
            -WhyItMatters 'Nobody is responsible for approving members, checking guest access or deleting the group when it is no longer needed.' `
            -RecommendedAction ("Add an owner to each listed group in {0} > All groups > [group] > Owners, or delete groups that are no longer used" -f $groupsPath) `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $cloudOwnerless -RuleId 'cloud-group-ownerless'
    }

    $syncedOwnerless = @($rows | Where-Object { $_.OwnersKnown -and $_.OwnerCount -eq 0 -and $_.OnPremisesSyncEnabled -eq $true })
    if ($syncedOwnerless.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
            -Title ((Format-EACount $syncedOwnerless.Count 'group synced from on-premises has' 'groups synced from on-premises have') + ' no owner in the cloud') `
            -Evidence 'These groups are synchronized from on-premises, so ownership may be managed in the source directory; the cloud owner field is empty.' `
            -WhyItMatters 'Owners may be managed in on-premises Active Directory, but reviewers still need a named business owner to confirm who should be in each group.' `
            -RecommendedAction 'Confirm who owns these groups in on-premises Active Directory and record the owner where access reviewers can see it' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $syncedOwnerless -RuleId 'synced-group-ownerless'
    }

    $publicM365 = @($rows | Where-Object { $_.GroupKind -eq 'Microsoft365' -and [string]$_.Visibility -ieq 'Public' })
    if ($publicM365.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
            -Title ((Format-EACount $publicM365.Count 'Microsoft 365 group is' 'Microsoft 365 groups are') + ' public: anyone in the organization can join') `
            -Evidence 'Visibility=Public allows users in the organization to discover and join these groups without owner approval.' `
            -WhyItMatters "Anyone in the organization can join a public group without approval and then read its files, mail and Teams content. That is fine for open topics but not for sensitive work." `
            -RecommendedAction 'Check that each listed group is meant to be open, and make groups with sensitive content private (Microsoft 365 admin center > Teams & groups > Active teams & groups)' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $publicM365 -RuleId 'public-m365-groups'
    }

    $pausedDynamic = @($rows | Where-Object { $_.IsDynamic -and [string]$_.MembershipRuleState -notmatch '^(On|Processing)$' })
    if ($pausedDynamic.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Group Governance' `
            -Title (Format-EACount $pausedDynamic.Count 'dynamic group has stopped updating its members' 'dynamic groups have stopped updating their members') `
            -Evidence 'The group is DynamicMembership, but membershipRuleProcessingState is not On/Processing.' `
            -WhyItMatters 'Dynamic groups add and remove members automatically based on a rule. While processing is paused, people who left or changed jobs keep the access the group gives, and new people do not get it.' `
            -RecommendedAction 'Check the membership rule of each listed group, turn processing back on, and review the current members before relying on the group for access' `
            -DocumentationUrl $dynamicDoc -SourceFile $src -ResultRows $pausedDynamic -RuleId 'dynamic-group-processing-off'
    }

    $invalidPrivilegedDynamic = @($rows | Where-Object { $_.IsAssignableToRole -eq $true -and $_.IsDynamic })
    if ($invalidPrivilegedDynamic.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Group Governance' `
            -Title ((Format-EACount $invalidPrivilegedDynamic.Count 'group that can hold admin roles uses' 'groups that can hold admin roles use') + ' automatic (dynamic) membership') `
            -Evidence 'Graph returned both isAssignableToRole=true and DynamicMembership. This unsupported/high-risk combination requires validation.' `
            -WhyItMatters 'Anyone whose user details match the rule would get admin rights automatically, without approval. Microsoft does not normally allow this combination, so it needs checking.' `
            -RecommendedAction ("Check the listed groups in {0}, switch them to assigned membership, and manage admin access through Privileged Identity Management (PIM) for Groups" -f $groupsPath) `
            -DocumentationUrl $roleGroupDoc -SourceFile $src -ResultRows $invalidPrivilegedDynamic -RuleId 'role-group-dynamic'
    }

    if ($activityCoverage) {
        # The D180 window ends at the report's refresh date (the report lags by about two
        # days), so measure the window from there; fall back to now when it is unreadable.
        # A group counts as inactive only when every signal agrees: it existed for the
        # whole window, no activity counter is above zero, and lastActivityDate (mail,
        # SharePoint and Yammer only) is empty or older than the window.
        $activityCounters = @('TeamsChannelMessagesCount','TeamsMeetingsOrganizedCount','ExchangeReceivedEmailCount',
            'SharePointActiveFileCount','YammerPostedMessageCount','YammerReadMessageCount','YammerLikedMessageCount')
        $inactive = @($rows | Where-Object {
            if (-not $_.ActivityEvidenceKnown -or $_.IsDeleted -eq $true) { return $false }
            $windowEnd = ConvertTo-EAGovDateTime $_.ReportRefreshDate
            if (-not $windowEnd) { $windowEnd = [datetimeoffset]::UtcNow }
            $cutoff = $windowEnd.AddDays(-180)
            $created = ConvertTo-EAGovDateTime $_.CreatedDateTime
            if (-not $created -or $created -ge $cutoff) { return $false }
            foreach ($counter in $activityCounters) {
                $value = 0.0
                if ([double]::TryParse([string]$_.$counter, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$value) -and $value -gt 0) { return $false }
            }
            $last = ConvertTo-EAGovDateTime $_.LastActivityDate
            return (-not $last -or $last -lt $cutoff)
        })
        if ($inactive.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
                -Title ((Format-EACount $inactive.Count 'Microsoft 365 group has' 'Microsoft 365 groups have') + ' had no activity for 180 days') `
                -Evidence 'Microsoft 365 groups activity report (D180): only groups with an explicit report row were evaluated; missing report rows were treated as unknown. Groups created within the 180-day window (or with an unknown creation date), deleted groups, and groups with any Teams channel message, Teams meeting, received mail, active SharePoint file or Yammer activity counted in the report were excluded.' `
                -WhyItMatters 'Unused groups keep their members, guests, files and app access long after the work ended.' `
                -RecommendedAction 'Ask the owners whether each group is still needed, then archive or delete unused ones through your normal process (group expiration can do this automatically)' `
                -DocumentationUrl $doc -SourceFile $src -ResultRows $inactive -RuleId 'm365-groups-inactive-180d'
        }
    }

    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Group Governance' `
        -Title ("Group owners, visibility and activity recorded ({0})" -f (Format-EACount $rows.Count 'group' 'groups')) `
        -Evidence ("Groups={0}; role-assignable={1}; dynamic={2}; public M365={3}; activity coverage={4}." -f `
            $rows.Count,@($rows | Where-Object {$_.IsAssignableToRole -eq $true}).Count,
            @($rows | Where-Object {$_.IsDynamic}).Count,$publicM365.Count,$activityCoverage) `
        -WhyItMatters 'The list shows which groups have owners, who can join them and which are no longer used.' `
        -RecommendedAction 'Compare the list with your group standards for naming, owners, expiration and access reviews' `
        -DocumentationUrl $doc -SourceFile $src -ResultRows $rows.ToArray() -RuleId 'group-governance-inventory'
}

function ConvertFrom-EAGovDurationDays {
    param([AllowNull()]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return [math]::Round([System.Xml.XmlConvert]::ToTimeSpan([string]$Value).TotalDays, 1) }
    catch { return $null }
}

# Readable name of the customer tenant in a GDAP row (this tenant is the partner): the
# customer's display name, else its tenant id, else the relationship name.
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

function Invoke-Check-ExternalDelegation {
    [CmdletBinding()]
    param()

    $checkId = 'externaldelegation'
    $doc = 'https://learn.microsoft.com/graph/api/tenantrelationship-list-delegatedadminrelationships?view=graph-rest-1.0'
    $sponsorDoc = 'https://learn.microsoft.com/graph/api/user-list-sponsors?view=graph-rest-1.0'
    $guestDoc = 'https://learn.microsoft.com/graph/api/user-list?view=graph-rest-1.0'
    $gdapGuideDoc = 'https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction'
    $sponsorGuideDoc = 'https://learn.microsoft.com/en-us/entra/external-id/b2b-sponsors'
    $guestReviewDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/manage-guest-access-with-access-reviews'
    $customerPartnerDoc = 'https://learn.microsoft.com/en-us/microsoft-365/commerce/manage-partners'
    # Customer side: where this tenant sees and removes partners that manage it.
    $partnerPath = 'Microsoft 365 admin center > Settings > Partner relationships'
    # Partner side: where this tenant, as a partner, manages its access to customers.
    $partnerCenterPath = 'Partner Center > Customers > [customer] > Admin relationships'

    # ------------------------- GDAP relationships -------------------------
    # Direction matters. GET /tenantRelationships/delegatedAdminRelationships is the
    # PARTNER-side API: it lists the relationships this tenant holds, as a Microsoft
    # partner, with its customers, and the roles it can use in THEIR tenants. It returns
    # nothing about partners that hold admin roles in this tenant, and Microsoft Graph has
    # no read-only customer-side API for that. So every row below is outbound access
    # (customer = the other tenant), and a separate note always tells the reader that
    # inbound partner access must be checked by hand; an empty list never means "no
    # partner has admin access to this tenant".
    $relationshipResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships?$top=300'
    $relationships = @(if ($relationshipResult.Success) { @($relationshipResult.Rows) } else { @() })

    # Role definitions come from the main script's shared cache, and are only loaded
    # when there is at least one relationship to classify. If the read fails,
    # Get-EARoleInfo still recognises the static tier-0/privileged template ids and
    # reports everything else as Unknown (with a coverage finding), never Standard.
    $roleDefinitionsKnown = $true
    $roleDefinitionError = $null
    if ($relationships.Count -gt 0) {
        try { Get-EARoleDefMap | Out-Null }
        catch { $roleDefinitionsKnown = $false; $roleDefinitionError = [string]$_.Exception.Message }
    }

    $relationshipRows = New-Object System.Collections.Generic.List[object]
    foreach ($relationship in $relationships) {
        $access = Get-EAGovProperty $relationship 'accessDetails'
        $roles = @(Get-EAGovProperty $access 'unifiedRoles')
        if ($roles.Count -eq 0) { $roles = @($null) }
        foreach ($roleRef in $roles) {
            $roleId = [string](Get-EAGovProperty $roleRef 'roleDefinitionId')
            $roleClass = Get-EAGovDirectoryRoleRisk -RoleDefinitionId $roleId
            $relationshipRows.Add([pscustomobject]@{
                RelationshipId      = Get-EAGovProperty $relationship 'id'
                DisplayName         = Get-EAGovProperty $relationship 'displayName'
                Status              = Get-EAGovProperty $relationship 'status'
                CustomerTenantId    = Get-EAGovProperty (Get-EAGovProperty $relationship 'customer') 'tenantId'
                CustomerDisplayName = Get-EAGovProperty (Get-EAGovProperty $relationship 'customer') 'displayName'
                CreatedDateTime     = Get-EAGovProperty $relationship 'createdDateTime'
                ActivatedDateTime   = Get-EAGovProperty $relationship 'activatedDateTime'
                LastModifiedDateTime = Get-EAGovProperty $relationship 'lastModifiedDateTime'
                EndDateTime         = Get-EAGovProperty $relationship 'endDateTime'
                Duration            = Get-EAGovProperty $relationship 'duration'
                DurationDays        = ConvertFrom-EAGovDurationDays (Get-EAGovProperty $relationship 'duration')
                AutoExtendDuration  = Get-EAGovProperty $relationship 'autoExtendDuration'
                RoleDefinitionId    = $roleId
                RoleDisplayName     = $roleClass.Name
                RoleRisk            = $roleClass.Risk
            }) | Out-Null
        }
    }
    $relationshipSrc = Write-Evidence -BaseName 'external_delegated_admin_relationships' -Rows $relationshipRows.ToArray() `
        -Title 'Granular Delegated Admin Privileges (GDAP) Relationships and Approved Roles'

    # Relationship accessDetails describes the roles approved for the
    # relationship. Effective partner access is represented by active
    # accessAssignments that bind those roles to a partner security group.
    $accessAssignmentRows = New-Object System.Collections.Generic.List[object]
    $accessAssignmentErrors = New-Object System.Collections.Generic.List[object]
    $activeRelationshipsWithoutAssignments = New-Object System.Collections.Generic.List[object]
    foreach ($relationship in @($relationships | Where-Object { [string](Get-EAGovProperty $_ 'status') -ieq 'active' })) {
        $relationshipId = [string](Get-EAGovProperty $relationship 'id')
        $customer = Get-EAGovProperty $relationship 'customer'
        $customerTenantId = Get-EAGovProperty $customer 'tenantId'
        $customerDisplayName = Get-EAGovProperty $customer 'displayName'
        if (-not $relationshipId) {
            $accessAssignmentErrors.Add([pscustomobject]@{ RelationshipId=$null; Relationship=(Get-EAGovProperty $relationship 'displayName'); Reason='active relationship has no id' }) | Out-Null
            continue
        }
        $assignmentResult = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships/{0}/accessAssignments?`$top=300" -f [uri]::EscapeDataString($relationshipId))
        if (-not $assignmentResult.Success -or $assignmentResult.Truncated) {
            $reason = if ($assignmentResult.Success) { 'pagination limit reached' } else { [string]$assignmentResult.Error.Exception.Message }
            $accessAssignmentErrors.Add([pscustomobject]@{ RelationshipId=$relationshipId; Relationship=(Get-EAGovProperty $relationship 'displayName'); Reason=$reason }) | Out-Null
            continue
        }
        $activeAssignments = @($assignmentResult.Rows | Where-Object { [string](Get-EAGovProperty $_ 'status') -ieq 'active' })
        if ($activeAssignments.Count -eq 0) {
            $activeRelationshipsWithoutAssignments.Add([pscustomobject]@{
                RelationshipId=$relationshipId; Relationship=(Get-EAGovProperty $relationship 'displayName')
                CustomerTenantId=$customerTenantId; CustomerDisplayName=$customerDisplayName
                EndDateTime=Get-EAGovProperty $relationship 'endDateTime'; ApprovedRoleCount=@(Get-EAGovProperty (Get-EAGovProperty $relationship 'accessDetails') 'unifiedRoles').Count
            }) | Out-Null
            continue
        }
        foreach ($assignment in $activeAssignments) {
            $container = Get-EAGovProperty $assignment 'accessContainer'
            $assignmentRoles = @(Get-EAGovProperty (Get-EAGovProperty $assignment 'accessDetails') 'unifiedRoles')
            if ($assignmentRoles.Count -eq 0) {
                $accessAssignmentErrors.Add([pscustomobject]@{
                    RelationshipId=$relationshipId; Relationship=(Get-EAGovProperty $relationship 'displayName')
                    AssignmentId=Get-EAGovProperty $assignment 'id'; Reason='active access assignment has no readable unifiedRoles'
                }) | Out-Null
                continue
            }
            foreach ($roleRef in $assignmentRoles) {
                $roleId = [string](Get-EAGovProperty $roleRef 'roleDefinitionId')
                $roleClass = Get-EAGovDirectoryRoleRisk -RoleDefinitionId $roleId
                $accessAssignmentRows.Add([pscustomobject]@{
                    RelationshipId=$relationshipId
                    DisplayName=Get-EAGovProperty $relationship 'displayName'
                    CustomerTenantId=$customerTenantId
                    CustomerDisplayName=$customerDisplayName
                    Status=Get-EAGovProperty $relationship 'status'
                    EndDateTime=Get-EAGovProperty $relationship 'endDateTime'
                    Duration=Get-EAGovProperty $relationship 'duration'
                    DurationDays=ConvertFrom-EAGovDurationDays (Get-EAGovProperty $relationship 'duration')
                    AutoExtendDuration=Get-EAGovProperty $relationship 'autoExtendDuration'
                    AssignmentId=Get-EAGovProperty $assignment 'id'
                    AssignmentStatus=Get-EAGovProperty $assignment 'status'
                    AccessContainerId=Get-EAGovProperty $container 'accessContainerId'
                    AccessContainerType=Get-EAGovProperty $container 'accessContainerType'
                    RoleDefinitionId=$roleId
                    RoleDisplayName=$roleClass.Name
                    RoleRisk=$roleClass.Risk
                }) | Out-Null
            }
        }
    }
    $assignmentSrc = Write-Evidence -BaseName 'external_delegated_admin_access_assignments' -Rows $accessAssignmentRows.ToArray() `
        -Title 'Effective Active GDAP Access Assignments'

    if (-not $relationshipResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP delegated admin relationships' `
            -Reason ([string]$relationshipResult.Error.Exception.Message) -RequiredScope 'DelegatedAdminRelationship.Read.All' `
            -DocumentationUrl $doc -SourceFile $relationshipSrc -Subject 'the list of customer tenants this tenant manages as a partner (GDAP)' `
            -Impact 'This list only has data when this tenant is a Microsoft partner; admin roles this tenant holds in customer tenants were not checked. It never shows partners that hold admin roles in this tenant (see the note on partner access).' `
            -RecommendedAction 'If this tenant is a Microsoft partner (for example a Cloud Solution Provider), give the audit account DelegatedAdminRelationship.Read.All and run the audit again; if it is not a partner, this list does not apply and nothing needs to be done'
    } elseif ($relationshipResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP delegated admin relationship pagination' `
            -Reason "pagination exceeded $($relationshipResult.Pages) pages." -RequiredScope 'DelegatedAdminRelationship.Read.All' `
            -DocumentationUrl $doc -SourceFile $relationshipSrc -Partial -Subject 'the list of customer tenants this tenant manages as a partner (GDAP)' `
            -Impact 'Customer tenants beyond the part that was read are missing from this report.'
    }
    if (-not $roleDefinitionsKnown) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP role definitions and effective role risk' `
            -Reason $roleDefinitionError -RequiredScope 'RoleManagement.Read.Directory' -DocumentationUrl $doc -SourceFile $relationshipSrc `
            -Subject 'the admin role definitions used to rate roles in customer tenants' `
            -Impact 'Roles in customer tenants other than the well-known top admin roles are shown as of unknown risk, so some privileged roles this tenant holds in customer tenants may be missing from this report.'
    }
    if ($accessAssignmentErrors.Count -gt 0) {
        $assignmentErrorSrc = Write-Evidence -BaseName 'external_delegated_admin_access_assignment_errors' -Rows $accessAssignmentErrors.ToArray() -Title 'GDAP Access Assignment Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Effective GDAP access assignments' `
            -Reason ((Format-EACount $accessAssignmentErrors.Count 'active relationship or assignment read was' 'active relationship or assignment reads were') + ' incomplete.') `
            -RequiredScope 'DelegatedAdminRelationship.Read.All' -DocumentationUrl $doc -SourceFile $assignmentErrorSrc `
            -Subject 'the list of staff groups that hold the approved customer roles' `
            -Impact "Admin roles this tenant's staff can use in customer tenants today may be missing from this report."
    }
    if ($activeRelationshipsWithoutAssignments.Count -gt 0) {
        $noAssignmentSrc = Write-Evidence -BaseName 'external_delegated_admin_relationships_without_assignments' -Rows $activeRelationshipsWithoutAssignments.ToArray() -Title 'Active GDAP Relationships Without Active Access Assignments'
        $unusedCustomers = @($activeRelationshipsWithoutAssignments | ForEach-Object { Get-EAGovGdapCustomerLabel $_ } | Select-Object -Unique)
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'External Access' `
            -Title ((Format-EACount $activeRelationshipsWithoutAssignments.Count 'admin relationship with a customer tenant is' 'admin relationships with customer tenants are') + ' approved but not in use') `
            -Evidence ("This tenant, as a Microsoft partner, has active Granular Delegated Admin Privileges (GDAP) relationships with approved roles, but no staff security group is assigned to use them (accessAssignments returned no active binding). Customers: {0}." -f ($unusedCustomers -join ', ')) `
            -WhyItMatters "Nobody in this tenant uses these approved admin roles in the customers' tenants today, but staff can be given them at any time without asking the customer again." `
            -RecommendedAction ("End the relationships that are no longer needed in {0}" -f $partnerCenterPath) `
            -DocumentationUrl $gdapGuideDoc -SourceFile $noAssignmentSrc -ResultRows $activeRelationshipsWithoutAssignments.ToArray() -RuleId 'gdap-active-without-access-assignment'
    }

    $activeRows = @($accessAssignmentRows.ToArray())
    foreach ($group in @($activeRows | Group-Object RelationshipId)) {
        $relationship = @($group.Group)
        $customerLabel = Get-EAGovGdapCustomerLabel $relationship[0]
        $critical = @($relationship | Where-Object { $_.RoleRisk -eq 'Critical' })
        $high = @($relationship | Where-Object { $_.RoleRisk -eq 'High' })
        $unknown = @($relationship | Where-Object { $_.RoleRisk -eq 'Unknown' -and $_.RoleDefinitionId })
        $severity = if ($critical.Count -gt 0) { 'Critical' } elseif ($high.Count -gt 0) { 'High' } else { $null }
        if ($severity) {
            $roleNames = @($relationship | Where-Object { $_.RoleRisk -in @('Critical','High') } | ForEach-Object {
                $_.RoleDisplayName ?? $_.RoleDefinitionId
            } | Select-Object -Unique)
            Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'External Access' `
                -Title ("This tenant (as a partner) holds admin roles in customer tenant: {0}" -f $customerLabel) `
                -Evidence ("Customer tenant: {0} (tenant id {1}); relationship: {2}. Privileged roles in active GDAP access assignments: {3}; end={4}; autoExtend={5}." -f $customerLabel,$relationship[0].CustomerTenantId,$relationship[0].DisplayName,($roleNames -join ', '),$relationship[0].EndDateTime,$relationship[0].AutoExtendDuration) `
                -WhyItMatters "Members of this tenant's partner staff groups can use these admin roles in the customer's tenant (Granular Delegated Admin Privileges, GDAP). Anyone who takes over one of those groups or staff accounts gets the same admin access to the customer, and top roles such as Global Administrator allow a full takeover of the customer tenant." `
                -RecommendedAction ("In {0}, keep only the roles the customer's contract needs and end relationships you no longer use; keep the staff groups that hold these roles small and protected with phishing-resistant MFA" -f $partnerCenterPath) `
                -DocumentationUrl $gdapGuideDoc -SourceFile $assignmentSrc -ResultRows $relationship `
                -AffectedPrincipal $customerLabel -RuleId 'gdap-privileged-role' `
                -ObjectType 'delegatedAdminRelationship' -ObjectId ([string]$relationship[0].RelationshipId)
        }
        if ($unknown.Count -gt 0) {
            # One rule for every relationship (the relationship is the object, not part of
            # the rule id), so renaming a relationship never changes the finding id and all
            # relationships with unresolved roles group under one "could not be read" card.
            # One-time id change, part of the finding-id migration: the rule used to be
            # coverage-gdap-role-risk-for-relationship-<relationship name> with no object.
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP role risk for relationship' `
                -Reason ("{0} in relationship {1} could not be resolved." -f (Format-EACount $unknown.Count 'role definition' 'role definitions'),$relationship[0].DisplayName) `
                -RequiredScope 'RoleManagement.Read.Directory' -DocumentationUrl $doc -SourceFile $assignmentSrc `
                -Subject ("the roles this tenant holds in customer tenant {0}" -f $customerLabel) `
                -Impact 'Whether this tenant holds admin roles in this customer tenant was not fully checked.' `
                -ObjectType 'delegatedAdminRelationship' -ObjectId ([string]$relationship[0].RelationshipId) -AffectedPrincipal $customerLabel
        }
    }

    $now = [datetimeoffset]::UtcNow
    $expiredActive = @($activeRows | Where-Object {
        $end = ConvertTo-EAGovDateTime $_.EndDateTime
        $end -and $end -lt $now
    })
    if ($expiredActive.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'External Access' `
            -Title (Format-EACount $expiredActive.Count 'admin role grant in a customer tenant is still active after its end date' 'admin role grants in customer tenants are still active after their end date') `
            -Evidence ("This tenant, as a Microsoft partner, has GDAP relationships whose status is active while EndDateTime is earlier than the audit time. Each row is one role in a relationship. Customers: {0}." -f (@($expiredActive | ForEach-Object { Get-EAGovGdapCustomerLabel $_ } | Select-Object -Unique) -join ', ')) `
            -WhyItMatters "This tenant may still have admin access in the customers' tenants that should already have ended, and nobody is tracking it." `
            -RecommendedAction ("Check these relationships in {0} and end any access that should have expired" -f $partnerCenterPath) `
            -DocumentationUrl $gdapGuideDoc -SourceFile $relationshipSrc -ResultRows $expiredActive -RuleId 'gdap-active-past-end'
    }

    # Graph caps duration at P2Y (730 days), so "longer than two years" can never
    # occur; flag relationships set to the two-year maximum or with no readable end.
    $longLived = @($activeRows | Where-Object { $null -eq $_.EndDateTime -or ($null -ne $_.DurationDays -and $_.DurationDays -ge 730) })
    if ($longLived.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'External Access' `
            -Title (Format-EACount $longLived.Count 'admin role grant in a customer tenant lasts two years or has no readable end date' 'admin role grants in customer tenants last two years or have no readable end date') `
            -Evidence ("{0} no readable EndDateTime. Each row is one role in a relationship. Customers: {1}." -f (Format-EACount @($longLived | Select-Object -ExpandProperty RelationshipId -Unique).Count 'GDAP relationship this tenant holds as a Microsoft partner uses the maximum two-year duration or has' 'GDAP relationships this tenant holds as a Microsoft partner use the maximum two-year duration or have'),(@($longLived | ForEach-Object { Get-EAGovGdapCustomerLabel $_ } | Select-Object -Unique) -join ', ')) `
            -WhyItMatters 'The longer admin access to a customer lasts, the more likely it is to outlive the contract or the staff who needed it.' `
            -RecommendedAction ("Use shorter relationships with each customer in {0}, and re-approve the roles regularly against the current contract" -f $partnerCenterPath) `
            -DocumentationUrl $gdapGuideDoc -SourceFile $relationshipSrc -ResultRows $longLived -RuleId 'gdap-long-lived'
    }

    # autoExtendDuration (P0D/PT0S = off, P180D = on) is what makes a partner
    # relationship effectively permanent: it renews itself every 180 days unless
    # someone terminates it. Report once per relationship.
    foreach ($group in @($activeRows | Where-Object {
        $days = ConvertFrom-EAGovDurationDays $_.AutoExtendDuration
        $null -ne $days -and $days -gt 0
    } | Group-Object RelationshipId)) {
        $relationship = @($group.Group)
        $customerLabel = Get-EAGovGdapCustomerLabel $relationship[0]
        $privilegedRoles = @($relationship | Where-Object { $_.RoleRisk -in @('Critical','High') })
        # A role whose definition could not be resolved may be privileged: keep the High
        # severity and say so, rather than reporting "none" for data that was never read.
        $unknownRoles = @($relationship | Where-Object { $_.RoleRisk -eq 'Unknown' -and $_.RoleDefinitionId })
        $severity = if ($privilegedRoles.Count -gt 0 -or $unknownRoles.Count -gt 0) { 'High' } else { 'Medium' }
        $roleNames = @($privilegedRoles | ForEach-Object { $_.RoleDisplayName ?? $_.RoleDefinitionId } | Select-Object -Unique)
        $roleText = @(
            if ($roleNames.Count -gt 0) { $roleNames -join ', ' }
            if ($unknownRoles.Count -gt 0) {
                "{0} of unknown risk (role definitions could not be resolved)" -f (Format-EACount @($unknownRoles.RoleDefinitionId | Select-Object -Unique).Count 'role' 'roles')
            }
        )
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'External Access' `
            -Title ("Admin access to a customer tenant renews itself automatically: {0}" -f $customerLabel) `
            -Evidence ("Customer tenant: {0}; relationship: {1}. GDAP autoExtendDuration={2}; current end={3}; privileged roles: {4}." -f $customerLabel,$relationship[0].DisplayName,$relationship[0].AutoExtendDuration,$relationship[0].EndDateTime,$(if ($roleText.Count -gt 0) { $roleText -join '; plus ' } else { 'none' })) `
            -WhyItMatters "This tenant's admin access to the customer has no real end date: the relationship extends itself by six months every time it reaches its end, so nobody has to re-approve it." `
            -RecommendedAction ("Turn off auto extend for this relationship in {0}, or replace it with a relationship that has a fixed end date; re-approve customer access on a regular schedule" -f $partnerCenterPath) `
            -DocumentationUrl $gdapGuideDoc -SourceFile $assignmentSrc -ResultRows $relationship `
            -AffectedPrincipal $customerLabel -RuleId 'gdap-auto-extend' `
            -ObjectType 'delegatedAdminRelationship' -ObjectId ([string]$relationship[0].RelationshipId)
    }

    # Partners that hold admin roles in THIS tenant cannot be listed through Microsoft
    # Graph from the customer side, so this note is always added. It is an Information
    # note, not a coverage gap: no permission can fix it, and a permanent gap would mark
    # every run as incomplete. Its text states plainly that this part was not checked.
    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'External Access' `
        -Title 'Partners with admin access to this tenant must be checked by hand' `
        -Evidence 'Microsoft Graph has no read-only API that lists, from the customer side, the partners (GDAP or older DAP) that hold admin roles in this tenant. The GDAP list this check reads only shows the relationships this tenant holds as a partner with its own customers. Partner access to this tenant was therefore not checked; this is not a clean result.' `
        -WhyItMatters 'A partner with admin roles in your tenant can make changes from outside your organization, and a breach at the partner can reach your tenant. The audit cannot see these partners.' `
        -RecommendedAction ("Review every partner in {0}: remove admin roles a partner does not need (Remove roles), and ask partners you no longer work with to end the relationship" -f $partnerPath) `
        -DocumentationUrl $customerPartnerDoc -SourceFile $relationshipSrc -RuleId 'gdap-inbound-not-readable'

    # ------------------------- Accepted guest lifecycle -------------------------
    $inactiveThreshold = 90
    $thresholdVariable = Get-Variable -Name InactiveDays -Scope Script -ErrorAction SilentlyContinue
    if ($thresholdVariable -and [int]$thresholdVariable.Value -gt 0) { $inactiveThreshold = [int]$thresholdVariable.Value }
    # Keep the base guest/sponsor read separate from signInActivity. A missing P1
    # license or AuditLog.Read.All must not prevent sponsor governance from running.
    #
    # Sponsors come with the guest list through $expand: one request per page of guests
    # instead of one request per guest. Directory $expand returns at most 20 related
    # objects and no nextLink, so a guest whose expanded sponsor list is missing or exactly
    # at that cap is read again on its own. If the service refuses the expanded query, the
    # plain guest list is read and every accepted guest's sponsors are read one by one:
    # slower, but no guest is ever skipped, and every guest whose sponsors could not be
    # read is listed in the sponsor coverage gap.
    #
    # Page safety limits are sized so every guest read covers about 500,000 guests: the
    # plain list is served at up to 999 rows per page (500 pages), a directory list with
    # $expand may be served at only 100 rows per page (5000 pages), and a list that selects
    # signInActivity at up to 500 rows per page (1000 pages). A smaller limit on the
    # expanded or activity read would mark large guest lists as partial and skip rules the
    # plain read could still run.
    $sponsorExpandCap = 20
    $guestSelect = 'id,userPrincipalName,displayName,accountEnabled,userType,externalUserState,externalUserStateChangeDateTime,createdDateTime'
    $guestBaseUri = "https://graph.microsoft.com/v1.0/users?`$filter=userType%20eq%20'Guest'&`$select=$guestSelect&`$top=999"
    $guestActivityUri = "https://graph.microsoft.com/v1.0/users?`$filter=userType%20eq%20'Guest'&`$select=id,signInActivity&`$top=999"
    $sponsorsExpanded = $false
    $sponsorExpandErrors = New-Object System.Collections.Generic.List[string]
    $guestResult = $null
    foreach ($expandShape in @('sponsors($select=id,displayName,userPrincipalName)', 'sponsors')) {
        $attempt = Invoke-EAGovGraphCollection -Uri ($guestBaseUri + '&$expand=' + $expandShape) -MaxPages 5000
        if ($attempt.Success) { $guestResult = $attempt; $sponsorsExpanded = $true; break }
        $sponsorExpandErrors.Add(('$expand={0}: {1}' -f $expandShape, [string]$attempt.Error.Exception.Message)) | Out-Null
        # Only a rejected query (HTTP 400) is worth retrying in another shape; access
        # denied, throttling or a service error would fail the same way again.
        $queryRejected = $attempt.StatusCode -eq 400 -or ($null -eq $attempt.StatusCode -and (Test-EAPageSizeRejection $attempt.Error))
        if (-not $queryRejected) { break }
    }
    if (-not $sponsorsExpanded) { $guestResult = Invoke-EAGovGraphCollection -Uri $guestBaseUri }
    $guestActivityResult = Invoke-EAGovGraphCollection -Uri $guestActivityUri -MaxPages 1000
    $activityByGuestId = @{}
    $guestActivityComplete = $guestActivityResult.Success -and -not $guestActivityResult.Truncated
    if ($guestActivityComplete) {
        foreach ($activityGuest in @($guestActivityResult.Rows)) {
            $activityGuestId = [string](Get-EAGovProperty $activityGuest 'id')
            if ($activityGuestId) {
                $activityByGuestId[$activityGuestId] = [pscustomobject]@{
                    Present = Test-EAGovPropertyPresent $activityGuest 'signInActivity'
                    Value   = Get-EAGovProperty $activityGuest 'signInActivity'
                }
            }
        }
    }
    $guestRows = New-Object System.Collections.Generic.List[object]
    $sponsorErrors = New-Object System.Collections.Generic.List[object]
    $acceptedGuests = @(if ($guestResult.Success) {
        @($guestResult.Rows | Where-Object { [string](Get-EAGovProperty $_ 'externalUserState') -ieq 'Accepted' })
    } else { @() })

    # Decide up front which guests need their own sponsor read, so the console can show
    # how many there are and report progress on long runs.
    $needsOwnSponsorRead = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($guest in $acceptedGuests) {
        $guestId = [string](Get-EAGovProperty $guest 'id')
        if (-not $guestId) { continue }
        $expandedPresent = $sponsorsExpanded -and (Test-EAGovPropertyPresent $guest 'sponsors')
        $expandedCount = if ($expandedPresent) { @(Get-EAGovProperty $guest 'sponsors' | Where-Object { $null -ne $_ }).Count } else { 0 }
        if (-not $expandedPresent -or $expandedCount -ge $sponsorExpandCap) { [void]$needsOwnSponsorRead.Add($guestId) }
    }
    if ($needsOwnSponsorRead.Count -gt 0) {
        $whyOwnRead = if (-not $sponsorsExpanded) {
            'the guest list could not include sponsors'
        } else {
            "their sponsors were missing from the guest list or may have been cut off at $sponsorExpandCap"
        }
        Write-Info ("  Reading sponsors one guest at a time for {0} of {1}, because {2}." -f $needsOwnSponsorRead.Count,(Format-EACount $acceptedGuests.Count 'accepted guest' 'accepted guests'),$whyOwnRead)
    }

    $ownReads = 0
    $ownReadSucceeded = 0
    $ownReadDenied = 0
    $ownReadStopReason = $null
    $expandedSponsorGuests = 0
    foreach ($guest in $acceptedGuests) {
        $guestId = [string](Get-EAGovProperty $guest 'id')
        $sponsorsKnown = $false
        $sponsors = @()
        $sponsorSource = $null
        if (-not $guestId) {
            $sponsorErrors.Add([pscustomobject]@{ GuestId=$null; UserPrincipalName=(Get-EAGovProperty $guest 'userPrincipalName'); Reason='the guest record has no id, so its sponsors could not be read' }) | Out-Null
        } elseif (-not $needsOwnSponsorRead.Contains($guestId)) {
            $sponsorsKnown = $true
            $sponsors = @(Get-EAGovProperty $guest 'sponsors' | Where-Object { $null -ne $_ })
            $sponsorSource = 'GuestList'
            $expandedSponsorGuests++
        } elseif ($ownReadStopReason) {
            $sponsorErrors.Add([pscustomobject]@{ GuestId=$guestId; UserPrincipalName=(Get-EAGovProperty $guest 'userPrincipalName'); Reason=$ownReadStopReason }) | Out-Null
        } else {
            $ownReads++
            $sponsorResult = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/users/{0}/sponsors?`$select=id,displayName,userPrincipalName" -f [uri]::EscapeDataString($guestId))
            if ($sponsorResult.Success -and -not $sponsorResult.Truncated) {
                $sponsorsKnown = $true
                $sponsors = @($sponsorResult.Rows)
                $sponsorSource = 'PerGuest'
                $ownReadSucceeded++
            } else {
                $reason = if ($sponsorResult.Success) { 'pagination limit reached' } else { [string]$sponsorResult.Error.Exception.Message }
                $sponsorErrors.Add([pscustomobject]@{ GuestId=$guestId; UserPrincipalName=(Get-EAGovProperty $guest 'userPrincipalName'); Reason=$reason }) | Out-Null
                if (-not $sponsorResult.Success -and ($sponsorResult.StatusCode -in @(401, 403) -or (Test-EAAccessDenied $sponsorResult.Error))) { $ownReadDenied++ }
                # When the first reads are all refused, the rest would be refused too:
                # stop sending thousands of doomed requests, but still list every guest.
                if ($ownReadSucceeded -eq 0 -and $ownReadDenied -ge 5) {
                    $ownReadStopReason = "not attempted: the first $ownReadDenied per-guest sponsor reads were refused (access denied)"
                    Write-Warn2 ("  Guest sponsor reads are being refused (access denied); the remaining {0} reported as not checked." -f (Format-EACount ($needsOwnSponsorRead.Count - $ownReads) 'guest is' 'guests are'))
                }
            }
            if ($ownReads % 100 -eq 0) {
                Write-Info ("  Guest sponsors read one by one: {0} of {1}." -f $ownReads,$needsOwnSponsorRead.Count)
            }
        }

        $activityEnvelope = if ($activityByGuestId.ContainsKey($guestId)) { $activityByGuestId[$guestId] } else { $null }
        $activityKnown = $guestActivityComplete -and $activityEnvelope -and $activityEnvelope.Present
        $signIn = if ($activityKnown) { $activityEnvelope.Value } else { $null }
        $lastSuccessful = ConvertTo-EAGovDateTime (Get-EAGovProperty $signIn 'lastSuccessfulSignInDateTime')
        $lastSignIn = ConvertTo-EAGovDateTime (Get-EAGovProperty $signIn 'lastSignInDateTime')
        # A failed sign-in attempt can update lastSignInDateTime. It must not
        # make a dormant guest look active (for example during password spray).
        $lastActivity = $lastSuccessful
        $accepted = ConvertTo-EAGovDateTime (Get-EAGovProperty $guest 'externalUserStateChangeDateTime')
        if (-not $accepted) { $accepted = ConvertTo-EAGovDateTime (Get-EAGovProperty $guest 'createdDateTime') }

        $guestRows.Add([pscustomobject]@{
            Id                         = $guestId
            UserPrincipalName          = Get-EAGovProperty $guest 'userPrincipalName'
            DisplayName                = Get-EAGovProperty $guest 'displayName'
            AccountEnabled             = Get-EAGovProperty $guest 'accountEnabled'
            ExternalUserState          = Get-EAGovProperty $guest 'externalUserState'
            AcceptedDateTime           = $accepted
            LastSuccessfulSignInDateTime = $lastSuccessful
            LastSignInDateTime         = $lastSignIn
            LastActivityDateTime       = $lastActivity
            ActivityKnown              = $activityKnown
            SponsorsKnown              = $sponsorsKnown
            SponsorCount               = if ($sponsorsKnown) { $sponsors.Count } else { $null }
            SponsorSource              = $sponsorSource
            Sponsors                   = (($sponsors | ForEach-Object {
                (Get-EAGovProperty $_ 'userPrincipalName') ?? (Get-EAGovProperty $_ 'displayName') ?? (Get-EAGovProperty $_ 'id')
            }) -join '; ')
        }) | Out-Null
    }
    if ($ownReads -ge 100 -and $ownReads % 100 -ne 0) {
        Write-Info ("  Guest sponsors read one by one: {0} of {1}." -f $ownReads,$needsOwnSponsorRead.Count)
    }

    $sponsorReadNote = if (-not $guestResult.Success) {
        'Sponsors: not read, because the guest list itself could not be read.'
    } elseif ($sponsorsExpanded) {
        "Sponsors: read with the guest list for {0} (SponsorSource=GuestList) and one guest at a time for {1} (SponsorSource=PerGuest; expanded list missing or at the {2}-item limit)." -f (Format-EACount $expandedSponsorGuests 'guest' 'guests'),(Format-EACount $ownReadSucceeded 'guest' 'guests'),$sponsorExpandCap
    } else {
        "Sponsors: the guest list could not include sponsors ({0}), so they were read one guest at a time (SponsorSource=PerGuest) for {1}." -f ($sponsorExpandErrors -join ' | '),(Format-EACount $ownReadSucceeded 'guest' 'guests')
    }
    $guestSrc = Write-Evidence -BaseName 'accepted_guest_lifecycle' -Rows $guestRows.ToArray() `
        -Title 'Accepted Guest Activity and Sponsor Governance' `
        -Notes @(
            ("Inactive threshold: {0} days. Only LastSuccessfulSignInDateTime establishes activity; failed attempts in LastSignInDateTime do not reset the inactivity clock." -f $inactiveThreshold),
            $sponsorReadNote,
            'SponsorsKnown=False means the sponsors of that guest could not be read (see guest_sponsor_collection_errors); it never means the guest has no sponsor.'
        )

    if (-not $guestResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest inventory and sponsor population' `
            -Reason ([string]$guestResult.Error.Exception.Message) -RequiredScope 'User.Read.All' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc -Subject 'the list of guest users' `
            -Impact 'Guests without a sponsor and guests who no longer sign in were not checked.'
    } elseif ($guestResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest pagination' `
            -Reason "pagination exceeded $($guestResult.Pages) pages." -RequiredScope 'User.Read.All' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc -Partial -Subject 'the list of guest users' `
            -Impact 'Guests beyond the part that was read were not checked for a sponsor or for recent sign-ins.'
    }
    if (-not $guestActivityResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest sign-in activity' `
            -Reason ([string]$guestActivityResult.Error.Exception.Message) -RequiredScope 'AuditLog.Read.All plus Entra ID P1 or P2' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc -Subject 'the sign-in activity of guest users' `
            -Impact 'Guests who no longer sign in were not identified.'
    } elseif ($guestActivityResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest sign-in activity pagination' `
            -Reason "pagination exceeded $($guestActivityResult.Pages) pages." -RequiredScope 'AuditLog.Read.All plus Entra ID P1 or P2' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc -Partial -Subject 'the sign-in activity of guest users' `
            -Impact 'Guests who no longer sign in were not identified.'
    }
    if ($sponsorErrors.Count -gt 0) {
        $sponsorErrSrc = Write-Evidence -BaseName 'guest_sponsor_collection_errors' -Rows $sponsorErrors.ToArray() -Title 'Guest Sponsor Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest sponsors' `
            -Reason ("sponsor enumeration failed or truncated for {0}." -f (Format-EACount $sponsorErrors.Count 'accepted guest' 'accepted guests')) `
            -RequiredScope 'User.Read.All (a delegated sign-in also needs a role such as Directory Readers or Guest Inviter)' `
            -DocumentationUrl $sponsorDoc -SourceFile $sponsorErrSrc -Subject 'the sponsors of some guest users' `
            -Impact 'Guests without a sponsor may be missing from this report.' `
            -RecommendedAction 'Give the audit account User.Read.All and, when it signs in as a user, a role that can read sponsors (Directory Readers, Guest Inviter, Directory Writers or User Administrator), then run the audit again; if the evidence shows a different error, such as throttling, simply run it again'
    }

    $missingSponsors = @($guestRows | Where-Object { $_.SponsorsKnown -and $_.SponsorCount -eq 0 })
    if ($missingSponsors.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'External Access' `
            -Title (Format-EACount $missingSponsors.Count 'guest has no sponsor' 'guests have no sponsor') `
            -Evidence 'Accepted guests: sponsor enumeration succeeded and returned zero sponsors for these guests.' `
            -WhyItMatters 'A sponsor is the person or group inside your organization who answers for a guest. Without one, nobody checks whether the guest still needs access when the project or contract ends.' `
            -RecommendedAction 'Add a sponsor to each listed guest (Entra admin center > Entra ID > Users > [guest] > Properties > Job information > Sponsors), and make sponsors the reviewers in guest access reviews' `
            -DocumentationUrl $sponsorGuideDoc -SourceFile $guestSrc -ResultRows $missingSponsors -RuleId 'accepted-guests-no-sponsor'
    }

    if ($guestResult.Success -and -not $guestResult.Truncated -and $guestActivityComplete) {
        $cutoff = [datetimeoffset]::UtcNow.AddDays(-$inactiveThreshold)
        $inactiveGuests = @($guestRows | Where-Object {
            if ($_.AccountEnabled -ne $true -or -not $_.ActivityKnown) { return $false }
            $last = ConvertTo-EAGovDateTime $_.LastActivityDateTime
            if ($last) { return $last -lt $cutoff }
            $accepted = ConvertTo-EAGovDateTime $_.AcceptedDateTime
            return ($accepted -and $accepted -lt $cutoff)
        })
        if ($inactiveGuests.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'External Access' `
                -Title ("{0} not signed in for more than {1} days" -f (Format-EACount $inactiveGuests.Count 'guest has' 'guests have'),$inactiveThreshold) `
                -Evidence 'Guests are accepted and enabled, and their last successful sign-in is older than the threshold; never-successfully-signed-in guests are flagged only after the accepted/created date exceeds the threshold. Failed attempts do not count as activity.' `
                -WhyItMatters "Guest accounts nobody uses still have access to your groups, apps and files. If the guest's own account is taken over, an attacker can use that access without anyone noticing." `
                -RecommendedAction 'Ask each sponsor whether the guest still needs access, then block sign-in for or delete guests that do not; an access review of inactive guests can do this regularly' `
                -DocumentationUrl $guestReviewDoc -SourceFile $guestSrc -ResultRows $inactiveGuests -RuleId 'accepted-guests-inactive'
        }
    }

    # Counts come from the read results: a list that could not be read says so instead of
    # showing 0, and a partial list shows "N+".
    $customerCountText = if (-not $relationshipResult.Success) { 'customer tenants managed as partner not read' }
        elseif ($relationshipResult.Truncated) { '{0}+ customer tenants managed as partner' -f $relationships.Count }
        else { '{0} managed as partner' -f (Format-EACount $relationships.Count 'customer tenant' 'customer tenants') }
    $guestCountText = if (-not $guestResult.Success) { 'guests not read' }
        elseif ($guestResult.Truncated) { '{0}+ accepted guests' -f $guestRows.Count }
        else { Format-EACount $guestRows.Count 'accepted guest' 'accepted guests' }
    $relationshipEvidence = if ($relationshipResult.Success) { [string]$relationships.Count + $(if ($relationshipResult.Truncated) { ' (partial list)' } else { '' }) } else { 'not read' }
    $guestEvidence = if ($guestResult.Success) { [string]$guestRows.Count + $(if ($guestResult.Truncated) { ' (partial list)' } else { '' }) } else { 'not read' }
    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'External Access' `
        -Title ("External access recorded ({0}, {1})" -f $guestCountText,$customerCountText) `
        -Evidence ("Accepted guests={0}; sponsor read errors={1}; customer tenants this tenant manages as a Microsoft partner through GDAP={2}; active GDAP role rows={3}. Partners that hold admin roles in this tenant are not in these numbers: Microsoft Graph cannot list them (see 'Partners with admin access to this tenant must be checked by hand')." -f `
            $guestEvidence,$sponsorErrors.Count,$relationshipEvidence,$activeRows.Count) `
        -WhyItMatters 'Guest accounts and partner admin relationships are the two main ways outsiders get into a tenant. Each needs an owner, an end date and a regular review.' `
        -RecommendedAction ("Compare guest access with current sponsors and contracts, check partner access to this tenant in {0}, and review both on a regular schedule" -f $partnerPath) `
        -DocumentationUrl $gdapGuideDoc -SourceFile $relationshipSrc -ResultRows $relationshipRows.ToArray() -RuleId 'external-delegation-inventory'
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
                SigningNotAfter=$null; NextSigningThumbprint=$null; NextSigningNotAfter=$null; SigningCertificateUpdateStatus=$null
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
                SigningNotAfter=$null; NextSigningThumbprint=$null; NextSigningNotAfter=$null; SigningCertificateUpdateStatus=$null
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
            -DocumentationUrl $domainGuideDoc -SourceFile $src -ResultRows $unverifiedFederated -RuleId 'federated-domain-unverified'
    }

    $now = [datetimeoffset]::UtcNow
    $expired = @($rows | Where-Object { $_.ConfigRead -eq 'Complete' -and $_.SigningNotAfter -and (ConvertTo-EAGovDateTime $_.SigningNotAfter) -lt $now })
    if ($expired.Count -gt 0) {
        Add-EAGovFinding -Severity 'Critical' -CheckId $checkId -Category 'Federation' `
            -Title (Format-EACount $expired.Count 'federation signing certificate has expired' 'federation signing certificates have expired') `
            -Evidence 'The parsed signing-certificate NotAfter timestamp is earlier than the audit time.' `
            -WhyItMatters 'When the certificate that signs sign-ins for a federated domain has expired, users of that domain can be unable to sign in to Microsoft 365 at all. It can also mean nobody is looking after the federation setup.' `
            -RecommendedAction 'Renew the token-signing certificate at the identity provider (for example AD FS) now, update it in Microsoft Entra, and test sign-in' `
            -DocumentationUrl $certGuideDoc -SourceFile $src -ResultRows $expired -RuleId 'federation-signing-cert-expired'
    }
    $expiring30 = @($rows | Where-Object {
        $date = ConvertTo-EAGovDateTime $_.SigningNotAfter
        $date -and $date -ge $now -and $date -le $now.AddDays(30)
    })
    if ($expiring30.Count -gt 0) {
        $noReadyNext = @($expiring30 | Where-Object { -not $_.NextSigningNotAfter -or (ConvertTo-EAGovDateTime $_.NextSigningNotAfter) -le $now })
        $severity = if ($noReadyNext.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Federation' `
            -Title (Format-EACount $expiring30.Count 'federation signing certificate expires within 30 days' 'federation signing certificates expire within 30 days') `
            -Evidence ("{0} a parsed, currently valid next signing certificate." -f (Format-EACount $noReadyNext.Count 'does not have' 'do not have')) `
            -WhyItMatters 'If the certificate expires before it is replaced, users of the federated domain cannot sign in.' `
            -RecommendedAction 'Replace the certificate now (automatic renewal through federation metadata where possible) and test sign-in before the expiry date' `
            -DocumentationUrl $certGuideDoc -SourceFile $src -ResultRows $expiring30 -RuleId 'federation-signing-cert-expiring-30d'
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
            -DocumentationUrl $certGuideDoc -SourceFile $src -ResultRows $expiring90 -RuleId 'federation-signing-cert-expiring-90d'
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
            -DocumentationUrl $doc -SourceFile $src -ResultRows $multipleConfigs -RuleId 'federation-multiple-configs'
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
            -DocumentationUrl $certGuideDoc -SourceFile $src -ResultRows $manualRolloverRisk -RuleId 'federation-no-metadata-near-expiry'
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
            -DocumentationUrl $doc -SourceFile $src -ResultRows $unsignedSaml -RuleId 'federation-unsigned-saml-requests'
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

function Invoke-Check-IdentityGovernance {
    [CmdletBinding()]
    param()

    $checkId = 'identitygovernance'
    $entitlementDoc = 'https://learn.microsoft.com/graph/api/entitlementmanagement-list-accesspackages?view=graph-rest-1.0'
    $workflowDoc = 'https://learn.microsoft.com/graph/api/identitygovernance-lifecycleworkflowscontainer-list-workflows?view=graph-rest-1.0'
    $agreementDoc = 'https://learn.microsoft.com/graph/api/termsofusecontainer-list-agreements?view=graph-rest-1.0'
    $pimDoc = 'https://learn.microsoft.com/graph/api/privilegedaccessgroup-list-eligibilityscheduleinstances?view=graph-rest-1.0'
    $pimPolicyDoc = 'https://learn.microsoft.com/graph/api/policyroot-list-rolemanagementpolicyassignments?view=graph-rest-1.0'
    $requestPolicyDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-request-policy'
    $packageLifecycleDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-lifecycle-policy'
    $workflowGuideDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/manage-workflow-properties'
    $workflowOverviewDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/what-are-lifecycle-workflows'
    $termsGuideDoc = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/terms-of-use'
    $pimGroupSettingsDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/groups-role-settings'
    $pimGroupAssignDoc = 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/groups-assign-member-owner'
    $packagesPath = 'Entra admin center > ID Governance > Entitlement management > Access packages'
    $pimGroupsPath = 'Entra admin center > ID Governance > Privileged Identity Management > Groups'

    # ------------------------- Entitlement Management -------------------------
    $catalogResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/catalogs?$select=id,displayName,description,catalogType,state,isExternallyVisible,createdDateTime,modifiedDateTime&$top=999'
    $packageResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages?$select=id,displayName,description,isHidden,createdDateTime,modifiedDateTime&$expand=catalog&$top=999'
    $policyResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/assignmentPolicies?$expand=accessPackage&$top=999'

    $catalogRows = @(if ($catalogResult.Success) {
        @($catalogResult.Rows | ForEach-Object {
            [pscustomobject]@{
                Id=Get-EAGovProperty $_ 'id'; DisplayName=Get-EAGovProperty $_ 'displayName'; Description=Get-EAGovProperty $_ 'description'
                CatalogType=Get-EAGovProperty $_ 'catalogType'; State=Get-EAGovProperty $_ 'state'; IsExternallyVisible=Get-EAGovProperty $_ 'isExternallyVisible'
                CreatedDateTime=Get-EAGovProperty $_ 'createdDateTime'; ModifiedDateTime=Get-EAGovProperty $_ 'modifiedDateTime'
            }
        })
    } else { @() })
    $catalogSrc = Write-Evidence -BaseName 'governance_access_package_catalogs' -Rows $catalogRows -Title 'Entitlement Management - Access Package Catalogs'

    $policyRows = New-Object System.Collections.Generic.List[object]
    $policyCountByPackage = @{}
    if ($policyResult.Success) {
        foreach ($policy in @($policyResult.Rows)) {
            $accessPackage = Get-EAGovProperty $policy 'accessPackage'
            $packageId = [string]((Get-EAGovProperty $accessPackage 'id') ?? (Get-EAGovProperty $policy 'accessPackageId'))
            if ($packageId) {
                if (-not $policyCountByPackage.ContainsKey($packageId)) { $policyCountByPackage[$packageId] = 0 }
                $policyCountByPackage[$packageId]++
            }
            $requestor = Get-EAGovProperty $policy 'requestorSettings'
            $approval = Get-EAGovProperty $policy 'requestApprovalSettings'
            $expiration = Get-EAGovProperty $policy 'expiration'
            # v1.0 uses reviewSettings. Keep a beta-era fallback so historical
            # responses don't become unknown, but never infer enabled from the
            # mere presence of the object.
            $review = Get-EAGovProperty $policy 'reviewSettings'
            if ($null -eq $review) { $review = Get-EAGovProperty $policy 'accessReviewSettings' }
            $reviewSchedule = Get-EAGovProperty $review 'schedule'
            $reviewRecurrence = Get-EAGovProperty $reviewSchedule 'recurrence'
            $reviewPattern = Get-EAGovProperty $reviewRecurrence 'pattern'
            $policyRows.Add([pscustomobject]@{
                Id=Get-EAGovProperty $policy 'id'
                DisplayName=Get-EAGovProperty $policy 'displayName'
                AccessPackageId=$packageId
                AccessPackageName=Get-EAGovProperty $accessPackage 'displayName'
                AllowedTargetScope=((Get-EAGovProperty $policy 'allowedTargetScope') ?? (Get-EAGovProperty $requestor 'scopeType'))
                AcceptRequests=Get-EAGovProperty $requestor 'acceptRequests'
                EnableSelfAdd=Get-EAGovProperty $requestor 'enableTargetsToSelfAddAccess'
                ApprovalRequiredForAdd=Get-EAGovProperty $approval 'isApprovalRequiredForAdd'
                ApprovalRequiredForUpdate=Get-EAGovProperty $approval 'isApprovalRequiredForUpdate'
                ApprovalStageCount=@(Get-EAGovProperty $approval 'stages').Count
                ExpirationType=Get-EAGovProperty $expiration 'type'
                ExpirationDuration=Get-EAGovProperty $expiration 'duration'
                ExpirationEndDateTime=Get-EAGovProperty $expiration 'endDateTime'
                AccessReviewSettingsPresent=($null -ne $review)
                AccessReviewConfigured=((Get-EAGovProperty $review 'isEnabled') -eq $true)
                AccessReviewRecurrenceType=Get-EAGovProperty $reviewPattern 'type'
                AccessReviewExpirationBehavior=Get-EAGovProperty $review 'expirationBehavior'
                AccessReviewSelfReview=Get-EAGovProperty $review 'isSelfReview'
                AccessReviewJustificationRequired=Get-EAGovProperty $review 'isReviewerJustificationRequired'
                AccessReviewPrimaryReviewerCount=@(Get-EAGovProperty $review 'primaryReviewers').Count
                AccessReviewFallbackReviewerCount=@(Get-EAGovProperty $review 'fallbackReviewers').Count
                CanExtend=Get-EAGovProperty $policy 'canExtend'
                CreatedDateTime=Get-EAGovProperty $policy 'createdDateTime'
                ModifiedDateTime=Get-EAGovProperty $policy 'modifiedDateTime'
            }) | Out-Null
        }
    }
    $policySrc = Write-Evidence -BaseName 'governance_access_package_policies' -Rows $policyRows.ToArray() -Title 'Entitlement Management - Access Package Assignment Policies'

    $packageRows = @(if ($packageResult.Success) {
        @($packageResult.Rows | ForEach-Object {
            $catalog = Get-EAGovProperty $_ 'catalog'
            $id = [string](Get-EAGovProperty $_ 'id')
            [pscustomobject]@{
                Id=$id; DisplayName=Get-EAGovProperty $_ 'displayName'; Description=Get-EAGovProperty $_ 'description'; IsHidden=Get-EAGovProperty $_ 'isHidden'
                CatalogId=Get-EAGovProperty $catalog 'id'; CatalogName=Get-EAGovProperty $catalog 'displayName'
                AssignmentPolicyCount=if ($policyCountByPackage.ContainsKey($id)) { $policyCountByPackage[$id] } else { 0 }
                CreatedDateTime=Get-EAGovProperty $_ 'createdDateTime'; ModifiedDateTime=Get-EAGovProperty $_ 'modifiedDateTime'
            }
        })
    } else { @() })
    $packageSrc = Write-Evidence -BaseName 'governance_access_packages' -Rows $packageRows -Title 'Entitlement Management - Access Packages'

    foreach ($entry in @(
        @{ Result=$catalogResult; Name='Access package catalogs'; File=$catalogSrc; Subject='the access package catalogs' },
        @{ Result=$packageResult; Name='Access packages'; File=$packageSrc; Subject='the list of access packages' },
        @{ Result=$policyResult; Name='Access package assignment policies'; File=$policySrc; Subject='the access package request policies' }
    )) {
        if (-not $entry.Result.Success) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource $entry.Name `
                -Reason ([string]$entry.Result.Error.Exception.Message) -RequiredScope 'EntitlementManagement.Read.All' `
                -DocumentationUrl $entitlementDoc -SourceFile $entry.File -Subject $entry.Subject `
                -Impact 'Access packages that grant access too easily or for too long may be missing from this report.'
        } elseif ($entry.Result.Truncated) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource ($entry.Name + ' pagination') `
                -Reason "pagination exceeded $($entry.Result.Pages) pages." -RequiredScope 'EntitlementManagement.Read.All' `
                -DocumentationUrl $entitlementDoc -SourceFile $entry.File -Partial -Subject $entry.Subject `
                -Impact 'Access packages beyond the part that was read were not checked.'
        }
    }

    if ($policyResult.Success -and -not $policyResult.Truncated) {
        $broadNoApproval = @($policyRows | Where-Object {
            $_.AcceptRequests -ne $false -and $_.EnableSelfAdd -ne $false -and $_.ApprovalRequiredForAdd -ne $true -and
            [string]$_.AllowedTargetScope -match '(?i)(allDirectory|allMember|allExternal|allConfiguredConnectedOrganization|AllExistingDirectory)'
        })
        if ($broadNoApproval.Count -gt 0) {
            $external = @($broadNoApproval | Where-Object { [string]$_.AllowedTargetScope -match '(?i)(external|connectedorganization)' })
            $severity = if ($external.Count -gt 0) { 'High' } else { 'Medium' }
            Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Identity Governance' `
                -Title ((Format-EACount $broadNoApproval.Count 'access package policy lets' 'access package policies let') + ' a broad audience get access without approval') `
                -Evidence ("Self-service add is accepted for a broad target scope without add approval; {0} external/connected-organization targets." -f (Format-EACount $external.Count 'policy includes' 'policies include')) `
                -WhyItMatters "Large groups of users, and in some cases outside users, can give themselves access to the package's groups, apps and sites without anyone checking the business need." `
                -RecommendedAction ("Require approval in each listed policy ({0} > [package] > Policies), and keep packages small so each gives only what one role needs" -f $packagesPath) `
                -DocumentationUrl $requestPolicyDoc -SourceFile $policySrc -ResultRows $broadNoApproval -RuleId 'access-package-broad-no-approval'
        }

        $noExpiration = @($policyRows | Where-Object { [string]$_.ExpirationType -ieq 'noExpiration' })
        if ($noExpiration.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title (Format-EACount $noExpiration.Count 'access package policy gives access that never expires' 'access package policies give access that never expires') `
                -Evidence 'Expiration.Type=noExpiration. Access reviews can be compensating evidence but do not make indefinite assignment automatically low risk.' `
                -WhyItMatters 'Access that never expires stays after people change jobs or projects end, unless someone removes it by hand.' `
                -RecommendedAction ("Set an expiry (for example 180 or 365 days, renewable on request) in the Lifecycle settings of each listed policy ({0})" -f $packagesPath) `
                -DocumentationUrl $packageLifecycleDoc -SourceFile $policySrc -ResultRows $noExpiration -RuleId 'access-package-no-expiration'
        }

        $externalNoReview = @($policyRows | Where-Object {
            [string]$_.AllowedTargetScope -match '(?i)(external|connectedorganization)' -and $_.AccessReviewConfigured -ne $true
        })
        if ($externalNoReview.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title (Format-EACount $externalNoReview.Count 'access package policy for external users has no access review' 'access package policies for external users have no access review') `
                -Evidence 'The target scope includes external/connected-organization users and reviewSettings.isEnabled is not true.' `
                -WhyItMatters "External users' jobs and contracts change outside your view, so without a regular review they keep access after they no longer need it." `
                -RecommendedAction 'Turn on access reviews in the Lifecycle settings of each listed policy, with sponsors or resource owners as reviewers and a fallback reviewer' `
                -DocumentationUrl $packageLifecycleDoc -SourceFile $policySrc -ResultRows $externalNoReview -RuleId 'access-package-external-no-review'
        }


        $reviewKeepsAccess = @($policyRows | Where-Object {
            $_.AccessReviewConfigured -eq $true -and [string]$_.AccessReviewExpirationBehavior -ieq 'keepAccess'
        })
        if ($reviewKeepsAccess.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title ((Format-EACount $reviewKeepsAccess.Count 'access package review keeps' 'access package reviews keep') + ' access when reviewers do not answer') `
                -Evidence 'reviewSettings.isEnabled=true and expirationBehavior=keepAccess.' `
                -WhyItMatters 'If the reviewer does not respond, the access stays, so the review cannot remove access that nobody vouches for.' `
                -RecommendedAction 'Set these reviews to remove access (or take recommendations) when reviewers do not respond, and name backup reviewers' `
                -DocumentationUrl $packageLifecycleDoc -SourceFile $policySrc -ResultRows $reviewKeepsAccess -RuleId 'access-package-review-keeps-access'
        }

        $reviewNoFallback = @($policyRows | Where-Object {
            $_.AccessReviewConfigured -eq $true -and $_.AccessReviewPrimaryReviewerCount -gt 0 -and $_.AccessReviewFallbackReviewerCount -eq 0
        })
        if ($reviewNoFallback.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
                -Title (Format-EACount $reviewNoFallback.Count 'access package review has no backup reviewer' 'access package reviews have no backup reviewer') `
                -Evidence 'Access reviews are enabled and primary reviewers exist, but fallbackReviewers is empty.' `
                -WhyItMatters 'If the main reviewer has left or is away, the review stalls and access is kept or removed without a real decision.' `
                -RecommendedAction 'Add a fallback reviewer to the access review settings of each listed policy' `
                -DocumentationUrl $packageLifecycleDoc -SourceFile $policySrc -ResultRows $reviewNoFallback -RuleId 'access-package-review-no-fallback'
        }
    }

    if ($packageResult.Success -and $policyResult.Success -and -not $packageResult.Truncated -and -not $policyResult.Truncated) {
        $packagesWithoutPolicies = @($packageRows | Where-Object { $_.AssignmentPolicyCount -eq 0 })
        if ($packagesWithoutPolicies.Count -gt 0) {
            Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
                -Title (Format-EACount $packagesWithoutPolicies.Count 'access package has no policy, so nobody can request it' 'access packages have no policy, so nobody can request them') `
                -Evidence 'The packages exist but have no returned assignment policy. They are not assumed to grant access.' `
                -WhyItMatters 'These packages give nobody new access today; they may be unfinished or abandoned, and they clutter the list people choose from.' `
                -RecommendedAction 'Confirm whether each package is still being built, and delete the ones that are no longer needed' `
                -DocumentationUrl $requestPolicyDoc -SourceFile $packageSrc -ResultRows $packagesWithoutPolicies -RuleId 'access-packages-no-policy'
        }
    }

    # ------------------------- Lifecycle Workflows -------------------------
    $workflowResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows?$select=id,displayName,description,category,isEnabled,isSchedulingEnabled,createdDateTime,lastModifiedDateTime,executionConditions&$top=999'
    $workflowConditionErrors = New-Object System.Collections.Generic.List[object]
    $workflowRows = @(if ($workflowResult.Success) {
        @($workflowResult.Rows | ForEach-Object {
            # A workflow is on-demand only when its execution condition has the type
            # onDemandExecutionOnly (for example the 'Real-time employee termination'
            # template). Those run manually or from automation, so isSchedulingEnabled=false
            # is by design. executionConditions is required on every workflow, so a missing
            # value means it was not returned, not that the workflow is on-demand. Re-read the
            # workflow by id when the answer changes the result (enabled, scheduling off); if
            # the type is still unknown, IsOnDemand stays $null and the workflow is judged as
            # a scheduled one.
            $conditions = Get-EAGovProperty $_ 'executionConditions'
            $workflowId = [string](Get-EAGovProperty $_ 'id')
            if ($null -eq $conditions -and $workflowId -and (Get-EAGovProperty $_ 'isEnabled') -eq $true -and
                (Get-EAGovProperty $_ 'isSchedulingEnabled') -ne $true) {
                $detail = Invoke-EAGovGraphObject -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/{0}" -f [uri]::EscapeDataString($workflowId))
                if ($detail.Success) { $conditions = Get-EAGovProperty $detail.Value 'executionConditions' }
                if ($null -eq $conditions) {
                    $workflowConditionErrors.Add([pscustomobject]@{
                        WorkflowId=$workflowId; DisplayName=Get-EAGovProperty $_ 'displayName'; StatusCode=$detail.StatusCode
                        Reason=$(if ($detail.Success) { 'executionConditions was not returned' } else { [string]$detail.Error.Exception.Message })
                    }) | Out-Null
                }
            }
            $conditionType = [string](Get-EAGovProperty $conditions '@odata.type')
            $isOnDemand = if ($conditionType -match '(?i)onDemandExecutionOnly$') { $true } elseif ($conditionType) { $false } else { $null }
            [pscustomobject]@{
                Id=Get-EAGovProperty $_ 'id'; DisplayName=Get-EAGovProperty $_ 'displayName'; Description=Get-EAGovProperty $_ 'description'
                Category=Get-EAGovProperty $_ 'category'; IsEnabled=Get-EAGovProperty $_ 'isEnabled'; IsSchedulingEnabled=Get-EAGovProperty $_ 'isSchedulingEnabled'
                CreatedDateTime=Get-EAGovProperty $_ 'createdDateTime'; LastModifiedDateTime=Get-EAGovProperty $_ 'lastModifiedDateTime'
                ExecutionConditions=ConvertTo-EAGovCompactJson $conditions
                IsOnDemand=$isOnDemand
            }
        })
    } else { @() })
    $workflowSrc = Write-Evidence -BaseName 'governance_lifecycle_workflows' -Rows $workflowRows -Title 'Identity Governance - Lifecycle Workflows'
    if (-not $workflowResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Lifecycle workflows' `
            -Reason ([string]$workflowResult.Error.Exception.Message) -RequiredScope 'LifecycleWorkflows.Read.All' `
            -DocumentationUrl $workflowDoc -SourceFile $workflowSrc -Subject 'the lifecycle workflows' `
            -Impact 'Whether the workflow that removes access for leavers is running was not checked.'
    } elseif ($workflowResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Lifecycle workflow pagination' `
            -Reason "pagination exceeded $($workflowResult.Pages) pages." -RequiredScope 'LifecycleWorkflows.Read.All' `
            -DocumentationUrl $workflowDoc -SourceFile $workflowSrc -Partial -Subject 'the lifecycle workflows' `
            -Impact 'Workflows beyond the part that was read were not checked.'
    } elseif ($workflowRows.Count -eq 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'No lifecycle workflows are set up' `
            -Evidence 'The workflow API returned zero records. Feature absence is context, not automatically a control failure.' `
            -WhyItMatters 'Lifecycle workflows can automate joiner, mover and leaver tasks, such as removing access when someone leaves. You may already do this in another system, for example an HR-driven process.' `
            -RecommendedAction 'Document how leavers lose their access today, and consider lifecycle workflows if that process is slow or manual' `
            -DocumentationUrl $workflowOverviewDoc -SourceFile $workflowSrc -RuleId 'lifecycle-workflows-none'
    } else {
        # Scheduled workflows must be enabled and scheduled; on-demand workflows can never
        # be scheduled, so they are judged on IsEnabled only. An unknown trigger type
        # (IsOnDemand=$null) is judged like a scheduled workflow, never passed silently.
        $inactiveWorkflow = { param($w) $w.IsEnabled -ne $true -or ($w.IsOnDemand -ne $true -and $w.IsSchedulingEnabled -ne $true) }
        $unknownTriggerNote = {
            param($flagged)
            $count = @($flagged | Where-Object { $_.IsEnabled -eq $true -and $null -eq $_.IsOnDemand }).Count
            if ($count -gt 0) { " For {0} of them the trigger type (scheduled or on-demand) could not be read, so {1} treated as scheduled." -f $count,$(if ($count -eq 1) { 'it was' } else { 'they were' }) } else { '' }
        }
        $disabledLeavers = @($workflowRows | Where-Object {
            [string]$_.Category -ieq 'leaver' -and (& $inactiveWorkflow $_)
        })
        if ($disabledLeavers.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title ((Format-EACount $disabledLeavers.Count 'leaver workflow is' 'leaver workflows are') + ' turned off or not scheduled') `
                -Evidence ('The workflow category is leaver, but it is disabled, or it is a scheduled workflow whose scheduling is turned off. On-demand workflows (such as real-time termination) are checked for IsEnabled only.' + (& $unknownTriggerNote $disabledLeavers)) `
                -WhyItMatters 'The workflow meant to remove access when someone leaves is not running, so leavers may keep access while everyone assumes it is handled.' `
                -RecommendedAction 'Open each listed workflow in Entra admin center > ID Governance > Lifecycle workflows > Workflows, turn it on (and turn on its schedule if it is a scheduled workflow), and test it with a test account' `
                -DocumentationUrl $workflowGuideDoc -SourceFile $workflowSrc -ResultRows $disabledLeavers -RuleId 'leaver-workflow-disabled'
        }
        $otherDisabled = @($workflowRows | Where-Object {
            [string]$_.Category -ine 'leaver' -and (& $inactiveWorkflow $_)
        })
        if ($otherDisabled.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
                -Title ((Format-EACount $otherDisabled.Count 'lifecycle workflow is' 'lifecycle workflows are') + ' turned off or not scheduled') `
                -Evidence ('These workflows are disabled, or are scheduled workflows whose scheduling is turned off. On-demand workflows are checked for IsEnabled only.' + (& $unknownTriggerNote $otherDisabled)) `
                -WhyItMatters 'Switched-off workflows can be drafts, but old ones make it unclear which automation is really running.' `
                -RecommendedAction 'Turn on and test the workflows that are meant to be in use, and delete the ones that are no longer needed' `
                -DocumentationUrl $workflowGuideDoc -SourceFile $workflowSrc -ResultRows $otherDisabled -RuleId 'lifecycle-workflow-disabled'
        }
    }
    if ($workflowConditionErrors.Count -gt 0) {
        $workflowConditionSrc = Write-Evidence -BaseName 'governance_lifecycle_workflow_condition_errors' -Rows $workflowConditionErrors.ToArray() `
            -Title 'Identity Governance - Lifecycle Workflow Trigger Type Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Lifecycle workflow execution conditions' `
            -Reason ("the trigger type (scheduled or on-demand) of {0}." -f (Format-EACount $workflowConditionErrors.Count 'enabled workflow with scheduling turned off could not be read, so it was treated as a scheduled workflow' 'enabled workflows with scheduling turned off could not be read, so they were treated as scheduled workflows')) `
            -RequiredScope 'LifecycleWorkflows.Read.All' -DocumentationUrl $workflowDoc -SourceFile $workflowConditionSrc `
            -Subject 'the trigger type of some lifecycle workflows' `
            -Impact 'These workflows were judged as scheduled ones, so an on-demand workflow may be reported as not scheduled by mistake.' `
            -RecommendedAction 'Open the listed workflows in Entra admin center > ID Governance > Lifecycle workflows > Workflows and check whether they run on a schedule or on demand'
    }

    # ------------------------- Terms of Use -------------------------
    $agreementResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/termsOfUse/agreements?$select=id,displayName,isViewingBeforeAcceptanceRequired,isPerDeviceAcceptanceRequired,userReacceptRequiredFrequency,termsExpiration&$top=999'
    $agreementRows = @(if ($agreementResult.Success) {
        @($agreementResult.Rows | ForEach-Object {
            $expiration = Get-EAGovProperty $_ 'termsExpiration'
            [pscustomobject]@{
                Id=Get-EAGovProperty $_ 'id'; DisplayName=Get-EAGovProperty $_ 'displayName'
                IsViewingBeforeAcceptanceRequired=Get-EAGovProperty $_ 'isViewingBeforeAcceptanceRequired'
                IsPerDeviceAcceptanceRequired=Get-EAGovProperty $_ 'isPerDeviceAcceptanceRequired'
                UserReacceptRequiredFrequency=Get-EAGovProperty $_ 'userReacceptRequiredFrequency'
                TermsExpirationFrequency=Get-EAGovProperty $expiration 'frequency'
                TermsExpirationStartDateTime=Get-EAGovProperty $expiration 'startDateTime'
            }
        })
    } else { @() })
    $agreementSrc = Write-Evidence -BaseName 'governance_terms_of_use' -Rows $agreementRows -Title 'Identity Governance - Terms of Use Agreements'
    if (-not $agreementResult.Success) {
        $appOnlyNote = if ([string]$script:AuthType -eq 'AppOnly') { ' The list-agreements API may not support application access in the current Graph cloud/version.' } else { '' }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Terms of Use agreements' `
            -Reason (([string]$agreementResult.Error.Exception.Message) + $appOnlyNote) `
            -RequiredScope 'Agreement.Read.All (delegated sign-in with a supported reader role, such as Security Reader or Global Reader)' `
            -DocumentationUrl $agreementDoc -SourceFile $agreementSrc -Subject 'the terms of use' `
            -Impact 'Whether terms of use are set up and actually enforced was not checked.' `
            -RecommendedAction 'Sign in to the audit as a user who has Agreement.Read.All and the Security Reader or Global Reader role (an app-only sign-in cannot list terms of use), then run the audit again; if the evidence shows a different error, such as throttling, simply run it again'
    } elseif ($agreementResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Terms of Use agreement pagination' `
            -Reason "pagination exceeded $($agreementResult.Pages) pages." -RequiredScope 'Agreement.Read.All' `
            -DocumentationUrl $agreementDoc -SourceFile $agreementSrc -Partial -Subject 'the terms of use' `
            -Impact 'Terms of use beyond the part that was read were not checked.'
    } elseif ($agreementRows.Count -eq 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'No terms of use are set up' `
            -Evidence 'The agreement API returned zero records. Absence is context because not every tenant requires a Terms of Use control.' `
            -WhyItMatters 'Terms of use record that users, for example guests, accepted your rules before they could reach your data. Not every organization needs them.' `
            -RecommendedAction 'Check whether your legal or compliance rules require terms of use; if they do, create them in Entra admin center > Entra ID > Conditional Access > Terms of use and require them with a Conditional Access policy' `
            -DocumentationUrl $termsGuideDoc -SourceFile $agreementSrc -RuleId 'terms-of-use-none'
    } else {
        $notViewed = @($agreementRows | Where-Object { $_.IsViewingBeforeAcceptanceRequired -eq $false })
        if ($notViewed.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
                -Title (Format-EACount $notViewed.Count 'terms of use document can be accepted without opening it' 'terms of use documents can be accepted without opening them') `
                -Evidence 'isViewingBeforeAcceptanceRequired=false.' `
                -WhyItMatters 'Users can click Accept without seeing the text, which weakens your proof that they were shown the terms.' `
                -RecommendedAction "Turn on 'Require users to expand the terms of use' for these terms where your legal rules support it" `
                -DocumentationUrl $termsGuideDoc -SourceFile $agreementSrc -ResultRows $notViewed -RuleId 'terms-not-viewed-before-acceptance'
        }
        $noReaccept = @($agreementRows | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.UserReacceptRequiredFrequency) })
        if ($noReaccept.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
                -Title (Format-EACount $noReaccept.Count 'terms of use document never asks users to accept it again' 'terms of use documents never ask users to accept them again') `
                -Evidence 'userReacceptRequiredFrequency is empty.' `
                -WhyItMatters 'Users accept once and are never reminded, even years later or after the terms change.' `
                -RecommendedAction "Set 'Duration before re-acceptance required (days)' (for example 365) where your rules require regular acceptance, or record that one-time acceptance is intended" `
                -DocumentationUrl $termsGuideDoc -SourceFile $agreementSrc -ResultRows $noReaccept -RuleId 'terms-no-reacceptance'
        }

        # A Terms of Use object is only effective when an enabled Conditional Access
        # policy references its id. This remains a GET-only cross-check.
        $caResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=id,displayName,state,conditions,grantControls&$top=999'
        if ($caResult.Success -and -not $caResult.Truncated) {
            $enforcedIds = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($policy in @($caResult.Rows | Where-Object { [string](Get-EAGovProperty $_ 'state') -ieq 'enabled' })) {
                $grant = Get-EAGovProperty $policy 'grantControls'
                $termIds = @(Get-EAGovProperty $grant 'termsOfUse')
                if ($termIds.Count -eq 0) { continue }

                # If the grant operator is OR and another grant path exists, a
                # user can satisfy that other path without accepting the terms.
                $operator = [string](Get-EAGovProperty $grant 'operator')
                # Drop nulls: an omitted list must not count as another grant path.
                $otherGrantCount = @(Get-EAGovProperty $grant 'builtInControls' | Where-Object { $_ }).Count +
                    @(Get-EAGovProperty $grant 'customAuthenticationFactors' | Where-Object { $_ }).Count
                if ($null -ne (Get-EAGovProperty $grant 'authenticationStrength')) { $otherGrantCount++ }
                if ($operator -ieq 'OR' -and $otherGrantCount -gt 0) { continue }

                # Don't call an enabled but empty/fully excluded user scope an
                # enforcement path. This is intentionally conservative; complex
                # scopes still remain visible in the CA evidence from the CA check.
                $users = Get-EAGovProperty (Get-EAGovProperty $policy 'conditions') 'users'
                $includeUsers = @(Get-EAGovProperty $users 'includeUsers')
                $includeGroups = @(Get-EAGovProperty $users 'includeGroups')
                $includeRoles = @(Get-EAGovProperty $users 'includeRoles')
                # The portal's "Guest or external users" selection (the usual guest terms of
                # use policy) is a separate inclusion, includeGuestsOrExternalUsers, and
                # leaves the three lists above empty.
                $includeGuests = Get-EAGovProperty $users 'includeGuestsOrExternalUsers'
                $guestTypes = [string](Get-EAGovProperty $includeGuests 'guestOrExternalUserTypes')
                $hasGuestPopulation = -not [string]::IsNullOrWhiteSpace($guestTypes) -and $guestTypes.Trim() -ine 'none'
                $hasIncludedPopulation = $includeUsers.Count -gt 0 -or $includeGroups.Count -gt 0 -or $includeRoles.Count -gt 0 -or $hasGuestPopulation
                if (-not $hasIncludedPopulation) { continue }
                $excludeUsers = @(Get-EAGovProperty $users 'excludeUsers')
                if ($includeUsers -contains 'All' -and $excludeUsers -contains 'All' -and $includeGroups.Count -eq 0 -and $includeRoles.Count -eq 0) { continue }

                foreach ($id in $termIds) { if ($id) { [void]$enforcedIds.Add([string]$id) } }
            }
            $unenforced = @($agreementRows | Where-Object { -not $enforcedIds.Contains([string]$_.Id) })
            if ($unenforced.Count -gt 0) {
                Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                    -Title ((Format-EACount $unenforced.Count 'terms of use document is' 'terms of use documents are') + ' not required by any enabled Conditional Access policy') `
                    -Evidence 'No enabled Conditional Access policy grantControls.termsOfUse list contained these agreement IDs (policies where the terms can be bypassed through another OR grant, or that include no users, are not counted; users, groups, roles and guest or external user types all count as included users).' `
                    -WhyItMatters 'Users only see terms of use when a Conditional Access policy requires them, so these terms are never actually shown or enforced.' `
                    -RecommendedAction 'Require each needed terms of use in an enabled Conditional Access policy that covers the right users (Entra admin center > Entra ID > Conditional Access), and check its exclusions' `
                    -DocumentationUrl $termsGuideDoc -SourceFile $agreementSrc -ResultRows $unenforced -RuleId 'terms-of-use-not-enforced'
            }
        } else {
            $reason = if ($caResult.Success) { 'pagination limit reached' } else { [string]$caResult.Error.Exception.Message }
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Terms of Use Conditional Access enforcement' `
                -Reason $reason -RequiredScope 'Policy.Read.All' -DocumentationUrl $agreementDoc -SourceFile $agreementSrc `
                -Subject 'the Conditional Access policies that enforce the terms of use' `
                -Impact 'Whether the terms of use are actually shown to users was not checked.'
        }
    }

    # ------------------------- PIM for Groups -------------------------
    $roleGroupResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole%20eq%20true&$select=id,displayName,isAssignableToRole&$top=999&$count=true' -Headers @{ConsistencyLevel='eventual'}
    $pimRows = New-Object System.Collections.Generic.List[object]
    $pimPolicyRows = New-Object System.Collections.Generic.List[object]
    $pimErrors = New-Object System.Collections.Generic.List[object]
    if ($roleGroupResult.Success) {
        foreach ($group in @($roleGroupResult.Rows)) {
            $groupId = [string](Get-EAGovProperty $group 'id')
            $escaped = [uri]::EscapeDataString($groupId)
            $groupFilter = [uri]::EscapeDataString("groupId eq '$groupId'")
            $policyFilter = [uri]::EscapeDataString("scopeId eq '$groupId' and scopeType eq 'Group'")
            $members = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/members?`$select=id&`$top=999" -f $escaped)
            $owners = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/owners?`$select=id&`$top=999" -f $escaped)
            $eligibility = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter={0}&`$top=999" -f $groupFilter)
            $assignments = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter={0}&`$top=999" -f $groupFilter)
            $policies = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter={0}&`$expand=policy(`$expand=rules)&`$top=999" -f $policyFilter)

            foreach ($call in @(
                @{ Name='members'; Result=$members; Scope='Group.Read.All' },
                @{ Name='owners'; Result=$owners; Scope='Group.Read.All' },
                @{ Name='eligibility schedules'; Result=$eligibility; Scope='PrivilegedEligibilitySchedule.Read.AzureADGroup' },
                @{ Name='assignment schedules'; Result=$assignments; Scope='PrivilegedAssignmentSchedule.Read.AzureADGroup' },
                @{ Name='role management policies'; Result=$policies; Scope='RoleManagementPolicy.Read.AzureADGroup' }
            )) {
                if (-not $call.Result.Success -or $call.Result.Truncated) {
                    $reason = if ($call.Result.Success) { 'pagination limit reached' } else { [string]$call.Result.Error.Exception.Message }
                    $pimErrors.Add([pscustomobject]@{ GroupId=$groupId; Group=(Get-EAGovProperty $group 'displayName'); DataSource=$call.Name; RequiredScope=$call.Scope; Reason=$reason }) | Out-Null
                }
            }

            $membersKnown = $members.Success -and -not $members.Truncated
            $ownersKnown = $owners.Success -and -not $owners.Truncated
            $eligibilityKnown = $eligibility.Success -and -not $eligibility.Truncated
            $assignmentKnown = $assignments.Success -and -not $assignments.Truncated
            $policiesKnown = $policies.Success -and -not $policies.Truncated
            $eligibilityRows = @(if ($eligibilityKnown) { @($eligibility.Rows) } else { @() })
            $assignmentRows = @(if ($assignments.Success -and -not $assignments.Truncated) { @($assignments.Rows) } else { @() })
            $permanent = @($assignmentRows | Where-Object { [string]::IsNullOrWhiteSpace([string](Get-EAGovProperty $_ 'endDateTime')) })
            $permanentOwners = @($permanent | Where-Object { [string](Get-EAGovProperty $_ 'accessId') -ieq 'owner' })
            $policyKinds = @(if ($policiesKnown) {
                @($policies.Rows | ForEach-Object { Get-EAGovProperty $_ 'roleDefinitionId' } | Where-Object { $_ } | Select-Object -Unique)
            } else { @() })

            # Compare principal ids rather than aggregate counts. One scheduled
            # member must not conceal another direct member (or owner) who bypasses
            # PIM entirely.
            $scheduledMemberIds = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
            $scheduledOwnerIds = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
            if ($eligibilityKnown -and $assignmentKnown) {
                foreach ($schedule in @($eligibilityRows) + @($assignmentRows)) {
                    $principalId = [string](Get-EAGovProperty $schedule 'principalId')
                    $accessId = [string](Get-EAGovProperty $schedule 'accessId')
                    if (-not $principalId) { continue }
                    if ($accessId -ieq 'owner') { [void]$scheduledOwnerIds.Add($principalId) }
                    elseif ($accessId -ieq 'member') { [void]$scheduledMemberIds.Add($principalId) }
                }
            }
            $directMemberIds = @(if ($membersKnown) { @($members.Rows | ForEach-Object { [string](Get-EAGovProperty $_ 'id') } | Where-Object { $_ } | Select-Object -Unique) } else { @() })
            $directOwnerIds = @(if ($ownersKnown) { @($owners.Rows | ForEach-Object { [string](Get-EAGovProperty $_ 'id') } | Where-Object { $_ } | Select-Object -Unique) } else { @() })
            $unscheduledMemberIds = @(if ($membersKnown -and $eligibilityKnown -and $assignmentKnown) { @($directMemberIds | Where-Object { -not $scheduledMemberIds.Contains($_) }) } else { @() })
            $unscheduledOwnerIds = @(if ($ownersKnown -and $eligibilityKnown -and $assignmentKnown) { @($directOwnerIds | Where-Object { -not $scheduledOwnerIds.Contains($_) }) } else { @() })

            # PIM for Groups has separate member and owner policy assignments.
            # Parse their expanded rules so the audit assesses enforcement, not
            # merely the presence of two policy objects.
            if ($policiesKnown) {
                foreach ($policyAssignment in @($policies.Rows)) {
                    $policyKind = [string](Get-EAGovProperty $policyAssignment 'roleDefinitionId')
                    $policy = Get-EAGovProperty $policyAssignment 'policy'
                    $rulesPresent = Test-EAGovPropertyPresent $policy 'rules'
                    $rules = @(if ($rulesPresent) { @(Get-EAGovProperty $policy 'rules') } else { @() })
                    $mfa = $null; $justification = $null; $approval = $null; $maximumHours = $null
                    $authContextEnabled = $null; $authContextClaim = $null
                    $permanentActiveAllowed = $null; $permanentEligibleAllowed = $null
                    foreach ($rule in $rules) {
                        $ruleId = [string](Get-EAGovProperty $rule 'id')
                        switch -Regex ($ruleId) {
                            'Enablement_EndUser_Assignment' {
                                if (Test-EAGovPropertyPresent $rule 'enabledRules') {
                                    $enabledRules = @(Get-EAGovProperty $rule 'enabledRules')
                                    $mfa = $enabledRules -contains 'MultiFactorAuthentication'
                                    $justification = $enabledRules -contains 'Justification'
                                }
                            }
                            'AuthenticationContext_EndUser_Assignment' {
                                if (Test-EAGovPropertyPresent $rule 'isEnabled') { $authContextEnabled = [bool](Get-EAGovProperty $rule 'isEnabled') }
                                $authContextClaim = [string](Get-EAGovProperty $rule 'claimValue')
                            }
                            'Approval_EndUser_Assignment' {
                                $setting = Get-EAGovProperty $rule 'setting'
                                if (Test-EAGovPropertyPresent $setting 'isApprovalRequired') { $approval = [bool](Get-EAGovProperty $setting 'isApprovalRequired') }
                            }
                            'Expiration_EndUser_Assignment' {
                                $duration = [string](Get-EAGovProperty $rule 'maximumDuration')
                                if ($duration) {
                                    try { $maximumHours = [math]::Round(([System.Xml.XmlConvert]::ToTimeSpan($duration)).TotalHours, 1) }
                                    catch { $maximumHours = $null }
                                }
                            }
                            'Expiration_Admin_Assignment' {
                                if (Test-EAGovPropertyPresent $rule 'isExpirationRequired') { $permanentActiveAllowed = -not [bool](Get-EAGovProperty $rule 'isExpirationRequired') }
                            }
                            'Expiration_Admin_Eligibility' {
                                if (Test-EAGovPropertyPresent $rule 'isExpirationRequired') { $permanentEligibleAllowed = -not [bool](Get-EAGovProperty $rule 'isExpirationRequired') }
                            }
                        }
                    }
                    $unknown = New-Object System.Collections.Generic.List[string]
                    if (-not $rulesPresent) { $unknown.Add('expanded rules') | Out-Null }
                    if ($null -eq $mfa -and $authContextEnabled -ne $true) { $unknown.Add('MFA/authentication-context requirement') | Out-Null }
                    if ($null -eq $justification) { $unknown.Add('justification requirement') | Out-Null }
                    if ($null -eq $approval) { $unknown.Add('approval requirement') | Out-Null }
                    if ($null -eq $maximumHours) { $unknown.Add('maximum activation duration') | Out-Null }
                    if ($null -eq $permanentActiveAllowed) { $unknown.Add('active-assignment expiration') | Out-Null }
                    if ($null -eq $permanentEligibleAllowed) { $unknown.Add('eligible-assignment expiration') | Out-Null }
                    $pimPolicyRows.Add([pscustomobject]@{
                        GroupId=$groupId; DisplayName=Get-EAGovProperty $group 'displayName'; PolicyKind=$policyKind
                        MfaOnActivation=$mfa; AuthenticationContextEnabled=$authContextEnabled; AuthenticationContextClaim=$authContextClaim
                        JustificationRequired=$justification; ApprovalRequired=$approval; MaximumActivationHours=$maximumHours
                        PermanentActiveAllowed=$permanentActiveAllowed; PermanentEligibleAllowed=$permanentEligibleAllowed
                        UnknownFields=($unknown -join '; ')
                    }) | Out-Null
                }
            }

            $pimRows.Add([pscustomobject]@{
                GroupId=$groupId
                DisplayName=Get-EAGovProperty $group 'displayName'
                MembersKnown=$membersKnown
                DirectMemberCount=if ($membersKnown) { $directMemberIds.Count } else { $null }
                OwnersKnown=$ownersKnown
                DirectOwnerCount=if ($ownersKnown) { $directOwnerIds.Count } else { $null }
                EligibilityKnown=$eligibilityKnown
                EligibilityInstanceCount=if ($eligibilityKnown) { $eligibilityRows.Count } else { $null }
                AssignmentKnown=$assignmentKnown
                AssignmentInstanceCount=if ($assignmentKnown) { $assignmentRows.Count } else { $null }
                PermanentAssignmentCount=if ($assignmentKnown) { $permanent.Count } else { $null }
                PermanentOwnerCount=if ($assignmentKnown) { $permanentOwners.Count } else { $null }
                UnscheduledMemberCount=if ($membersKnown -and $eligibilityKnown -and $assignmentKnown) { $unscheduledMemberIds.Count } else { $null }
                UnscheduledMemberIds=($unscheduledMemberIds -join '; ')
                UnscheduledOwnerCount=if ($ownersKnown -and $eligibilityKnown -and $assignmentKnown) { $unscheduledOwnerIds.Count } else { $null }
                UnscheduledOwnerIds=($unscheduledOwnerIds -join '; ')
                PoliciesKnown=$policiesKnown
                PolicyAssignmentCount=if ($policiesKnown) { @($policies.Rows).Count } else { $null }
                HasMemberPolicy=if ($policiesKnown) { @($policyKinds | Where-Object { [string]$_ -ieq 'member' }).Count -gt 0 } else { $null }
                HasOwnerPolicy=if ($policiesKnown) { @($policyKinds | Where-Object { [string]$_ -ieq 'owner' }).Count -gt 0 } else { $null }
                PolicyKinds=($policyKinds -join '; ')
            }) | Out-Null
        }
    }
    $pimSrc = Write-Evidence -BaseName 'governance_pim_for_groups' -Rows $pimRows.ToArray() -Title 'PIM for Groups - Role-Assignable Group Coverage' `
        -Notes @('Unscheduled counts compare each direct member and owner id with both eligible and active schedule instances; aggregate schedule counts are not used as a proxy for principal coverage.')
    $pimPolicySrc = Write-Evidence -BaseName 'governance_pim_for_groups_policies' -Rows $pimPolicyRows.ToArray() -Title 'PIM for Groups - Member and Owner Policy Rules'
    if (-not $roleGroupResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Role-assignable groups for PIM coverage' `
            -Reason ([string]$roleGroupResult.Error.Exception.Message) -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $pimDoc -SourceFile $pimSrc -Subject 'the list of groups that can hold admin roles' `
            -Impact 'The Privileged Identity Management (PIM) settings of admin-role groups were not checked.'
    } elseif ($roleGroupResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Role-assignable group pagination for PIM coverage' `
            -Reason "pagination exceeded $($roleGroupResult.Pages) pages." -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $pimDoc -SourceFile $pimSrc -Partial -Subject 'the list of groups that can hold admin roles' `
            -Impact 'Admin-role groups beyond the part that was read were not checked.'
    }
    if ($pimErrors.Count -gt 0) {
        $pimErrorSrc = Write-Evidence -BaseName 'governance_pim_for_groups_errors' -Rows $pimErrors.ToArray() -Title 'PIM for Groups Collection Gaps'
        $scopeList = @($pimErrors | ForEach-Object { $_.RequiredScope } | Select-Object -Unique) -join ', '
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'PIM for Groups policy and schedule coverage' `
            -Reason ((Format-EACount $pimErrors.Count 'group/data-source read' 'group/data-source reads') + ' failed or truncated.') -RequiredScope $scopeList `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimErrorSrc -Subject 'the PIM settings and assignments of some admin-role groups' `
            -Impact 'Permanent or unmanaged admin access through these groups may be missing from this report.'
    }

    $standingPrivileged = @($pimRows | Where-Object { $_.AssignmentKnown -and $_.PermanentAssignmentCount -gt 0 })
    if ($standingPrivileged.Count -gt 0) {
        $ownerStanding = @($standingPrivileged | Where-Object { $_.PermanentOwnerCount -gt 0 })
        $severity = if ($ownerStanding.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $standingPrivileged.Count 'admin-role group has' 'admin-role groups have') + ' permanent members or owners in PIM') `
            -Evidence ("Role-assignable groups where EndDateTime is absent on one or more PIM assignment instances; {0} permanent owner assignments." -f (Format-EACount $ownerStanding.Count 'group includes' 'groups include')) `
            -WhyItMatters 'Privileged Identity Management (PIM) is meant to give admin access only when needed and for a limited time. Permanent assignments mean these people hold that access all the time, so a stolen account can use it at once.' `
            -RecommendedAction ("Change permanent assignments to eligible ones (switched on only when needed) in {0} > [group] > Assignments, and require MFA, approval and a reason to activate" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupAssignDoc -SourceFile $pimSrc -ResultRows $standingPrivileged -RuleId 'pim-group-permanent-assignments'
    }

    $unscheduledDirect = @($pimRows | Where-Object {
        ($null -ne $_.UnscheduledMemberCount -and $_.UnscheduledMemberCount -gt 0) -or
        ($null -ne $_.UnscheduledOwnerCount -and $_.UnscheduledOwnerCount -gt 0)
    })
    if ($unscheduledDirect.Count -gt 0) {
        $groupsWithUnscheduledOwners = @($unscheduledDirect | Where-Object { $_.UnscheduledOwnerCount -gt 0 })
        $unscheduledMemberTotal = ($unscheduledDirect | Measure-Object -Property UnscheduledMemberCount -Sum).Sum
        $unscheduledOwnerTotal = ($unscheduledDirect | Measure-Object -Property UnscheduledOwnerCount -Sum).Sum
        $severity = if ($groupsWithUnscheduledOwners.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $unscheduledDirect.Count 'admin-role group has' 'admin-role groups have') + ' members or owners added outside PIM') `
            -Evidence ("Per-principal comparison found {0} and {1} whose ids occur in neither an eligibility nor assignment schedule instance for the corresponding accessId." -f (Format-EACount $unscheduledMemberTotal 'direct member' 'direct members'),(Format-EACount $unscheduledOwnerTotal 'direct owner' 'direct owners')) `
            -WhyItMatters 'People added directly to these groups hold admin access without going through Privileged Identity Management (PIM): no time limit, no approval and no activation record.' `
            -RecommendedAction ("Remove direct members and owners who should not be there, and manage everyone else as eligible or time-limited assignments in {0}" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupAssignDoc -SourceFile $pimSrc -ResultRows $unscheduledDirect -RuleId 'role-groups-direct-principals-without-pim'
    }

    $pimWithoutPolicies = @($pimRows | Where-Object {
        $_.EligibilityKnown -and $_.AssignmentKnown -and ($_.EligibilityInstanceCount -gt 0 -or $_.AssignmentInstanceCount -gt 0) -and
        $_.PoliciesKnown -and (-not $_.HasMemberPolicy -or -not $_.HasOwnerPolicy)
    })
    if ($pimWithoutPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $pimWithoutPolicies.Count 'PIM-managed group is' 'PIM-managed groups are') + ' missing member or owner activation settings') `
            -Evidence 'PIM schedule instances exist, but fewer than two role-management policy assignments (member and owner) were returned.' `
            -WhyItMatters 'Without both settings there is no proof that switching on admin access in these groups requires multifactor authentication (MFA), approval or a time limit.' `
            -RecommendedAction ("Open each listed group in {0} > [group] > Settings and check the Member and Owner role settings" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimSrc -ResultRows $pimWithoutPolicies -RuleId 'pim-group-policy-missing'
    }

    $unknownPimPolicyRules = @($pimPolicyRows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.UnknownFields) })
    if ($unknownPimPolicyRules.Count -gt 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("Some PIM activation settings could not be read for {0}" -f (Format-EACount $unknownPimPolicyRules.Count 'group setting' 'group settings')) `
            -Evidence ((Format-EACount $unknownPimPolicyRules.Count 'member/owner policy assignment' 'member/owner policy assignments') + ' omitted or returned unreadable activation/expiration rule fields. This is unknown, not compliant.') `
            -WhyItMatters 'The audit cannot confirm whether switching on admin access in these groups requires MFA, a reason, approval or a time limit.' `
            -RecommendedAction ("Check the listed settings in {0} > [group] > Settings; confirm the audit account has RoleManagementPolicy.Read.AzureADGroup, then run the audit again" -f $pimGroupsPath) `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimPolicySrc -ResultRows $unknownPimPolicyRules `
            -RuleId 'pim-group-policy-rules-unknown' -CoverageGap
    }

    $weakActivationPolicies = @($pimPolicyRows | Where-Object {
        $_.MfaOnActivation -eq $false -and $_.AuthenticationContextEnabled -ne $true
    })
    if ($weakActivationPolicies.Count -gt 0) {
        $weakOwnerPolicies = @($weakActivationPolicies | Where-Object { [string]$_.PolicyKind -ieq 'owner' })
        $severity = if ($weakOwnerPolicies.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $weakActivationPolicies.Count 'PIM group setting lets' 'PIM group settings let') + ' people switch on admin access without MFA') `
            -Evidence ("MultiFactorAuthentication is absent from enabledRules and no enabled authentication-context rule was returned; affected owner policies={0}." -f $weakOwnerPolicies.Count) `
            -WhyItMatters 'Someone with a stolen password or session could switch on admin-level group membership or ownership without a fresh multifactor authentication (MFA) check.' `
            -RecommendedAction ("Turn on 'On activation, require multifactor authentication' (or a Conditional Access authentication context) for these settings in {0} > [group] > Settings" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $weakActivationPolicies -RuleId 'pim-group-activation-no-strong-auth'
    }

    $authContextPolicies = @($pimPolicyRows | Where-Object { $_.AuthenticationContextEnabled -eq $true })
    if ($authContextPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $authContextPolicies.Count 'PIM group setting relies' 'PIM group settings rely') + ' on Conditional Access that needs a manual check') `
            -Evidence ("{0} an authentication context. The PIM rule alone does not prove that the referenced context is available and protected by enabled Conditional Access with mandatory MFA/authentication strength." -f (Format-EACount $authContextPolicies.Count 'policy assignment uses' 'policy assignments use')) `
            -WhyItMatters 'Activation asks for an authentication context, but that only protects anything if an enabled Conditional Access policy requires MFA for it. A missing or narrow policy would leave activation unprotected.' `
            -RecommendedAction 'For each listed claim value, check that the authentication context exists and that an enabled Conditional Access policy requires MFA or an authentication strength for it (Entra admin center > Entra ID > Conditional Access > Authentication contexts)' `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $authContextPolicies `
            -RuleId 'pim-group-auth-context-validation' -CoverageGap
    }

    $noJustificationPolicies = @($pimPolicyRows | Where-Object { $_.JustificationRequired -eq $false })
    if ($noJustificationPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $noJustificationPolicies.Count 'PIM group setting does not' 'PIM group settings do not') + ' ask for a reason when admin access is switched on') `
            -Evidence 'Justification is absent from the policy enabledRules list.' `
            -WhyItMatters 'Without a stated reason it is hard to check later, or during an incident, whether an admin activation was for real work.' `
            -RecommendedAction ("Turn on 'Require justification on activation' for these member and owner settings in {0} > [group] > Settings" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $noJustificationPolicies -RuleId 'pim-group-activation-no-justification'
    }

    $ownerNoApprovalPolicies = @($pimPolicyRows | Where-Object { [string]$_.PolicyKind -ieq 'owner' -and $_.ApprovalRequired -eq $false })
    if ($ownerNoApprovalPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $ownerNoApprovalPolicies.Count 'PIM group owner setting allows' 'PIM group owner settings allow') + ' owner access to be switched on without approval') `
            -Evidence 'The owner policy approval rule has isApprovalRequired=false.' `
            -WhyItMatters 'Group owners can change who is in an admin-role group. Requiring approval means a second person agrees before someone gets that power.' `
            -RecommendedAction ("Turn on 'Require approval to activate' for the Owner setting of these groups in {0} > [group] > Settings, and name at least two approvers" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $ownerNoApprovalPolicies -RuleId 'pim-group-owner-activation-no-approval'
    }

    $longActivationPolicies = @($pimPolicyRows | Where-Object { $null -ne $_.MaximumActivationHours -and $_.MaximumActivationHours -gt 8 })
    if ($longActivationPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $longActivationPolicies.Count 'PIM group setting keeps' 'PIM group settings keep') + ' admin access switched on for more than 8 hours') `
            -Evidence 'maximumDuration parsed to more than eight hours. Eight hours is an audit review threshold, not a universal compliance boundary.' `
            -WhyItMatters 'The longer admin access stays switched on, the longer a stolen session or an unlocked computer can be misused.' `
            -RecommendedAction ("Lower 'Activation maximum duration (hours)' to the shortest workable value (8 hours or less) in {0} > [group] > Settings, and record any exceptions" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $longActivationPolicies -RuleId 'pim-group-activation-duration-long'
    }

    $permanentActivePolicies = @($pimPolicyRows | Where-Object { $_.PermanentActiveAllowed -eq $true })
    if ($permanentActivePolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $permanentActivePolicies.Count 'PIM group setting allows' 'PIM group settings allow') + ' permanent admin access') `
            -Evidence 'The active-assignment expiration rule has isExpirationRequired=false.' `
            -WhyItMatters 'Even if nobody has it today, an admin can later give someone admin-level group access that never ends.' `
            -RecommendedAction ("Turn off 'Allow permanent active assignment' for the member and owner settings in {0} > [group] > Settings, and review existing permanent assignments" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $permanentActivePolicies -RuleId 'pim-group-policy-allows-permanent-active'
    }

    $permanentEligiblePolicies = @($pimPolicyRows | Where-Object { $_.PermanentEligibleAllowed -eq $true })
    if ($permanentEligiblePolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $permanentEligiblePolicies.Count 'PIM group setting allows' 'PIM group settings allow') + ' eligibility for admin access that never expires') `
            -Evidence 'The eligible-assignment expiration rule has isExpirationRequired=false.' `
            -WhyItMatters 'People can stay able to switch on admin access long after they need it, unless a review removes them.' `
            -RecommendedAction ("Turn off 'Allow permanent eligible assignment' in {0} > [group] > Settings, or run recurring access reviews of eligible members" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $permanentEligiblePolicies -RuleId 'pim-group-policy-allows-permanent-eligibility'
    }

    # A list that could not be read says so instead of showing 0; a partial list shows "N+".
    $countText = {
        param($ReadResult, [int]$Count)
        if (-not $ReadResult.Success) { 'not read' } elseif ($ReadResult.Truncated) { '{0}+ (partial list)' -f $Count } else { [string]$Count }
    }
    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
        -Title 'Identity governance features recorded' `
        -Evidence ("Catalogs={0}; access packages={1}; assignment policies={2}; lifecycle workflows={3}; Terms of Use agreements={4}; role-assignable groups assessed for PIM={5}." -f `
            (& $countText $catalogResult $catalogRows.Count),(& $countText $packageResult $packageRows.Count),(& $countText $policyResult $policyRows.Count),
            (& $countText $workflowResult $workflowRows.Count),(& $countText $agreementResult $agreementRows.Count),(& $countText $roleGroupResult $pimRows.Count)) `
        -WhyItMatters 'Access packages, lifecycle workflows, terms of use and PIM for Groups each control a different stage of access: granting it, using it, reviewing it and removing it.' `
        -RecommendedAction 'Check that each feature you rely on is set up, and document what you use instead for the features you do not use' `
        -DocumentationUrl $entitlementDoc -SourceFile $packageSrc -ResultRows $packageRows -RuleId 'identity-governance-inventory'
}
