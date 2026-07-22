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

function ConvertTo-EAGovDateTime {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return [datetimeoffset]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture) }
    catch { return $null }
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
        if ($next) { throw "Microsoft Graph collection exceeded the $MaxPages-page safety limit; coverage is incomplete." }

        return [pscustomobject]@{
            Success   = $true
            Rows      = $rows.ToArray()
            Pages     = $pages
            Truncated = $false
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

    $parameters = @{
        Severity          = $Severity
        CheckId           = $CheckId
        Category          = $Category
        Title             = $Title
        Evidence          = $Evidence
        WhyItMatters      = $WhyItMatters
        RecommendedAction = (($RecommendedAction.TrimEnd('.')) + ". Microsoft source: $DocumentationUrl")
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

function Add-EAGovCoverageFinding {
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$DataSource,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][string]$RequiredScope,
        [Parameter(Mandatory)][string]$DocumentationUrl,
        [AllowNull()][string]$SourceFile
    )

    Add-EAGovFinding -Severity 'Information' -CheckId $CheckId -Category $Category `
        -Title "$DataSource coverage is unknown" `
        -Evidence "$DataSource could not be fully read: $Reason This is an unknown/partial result, not a clean result." `
        -WhyItMatters "Without $DataSource, this part of the control cannot be evaluated reliably." `
        -RecommendedAction "Grant the read-only scope $RequiredScope, confirm the required reader role/license, and rerun the audit" `
        -DocumentationUrl $DocumentationUrl -SourceFile $SourceFile `
        -RuleId ("coverage-" + (($DataSource -replace '[^A-Za-z0-9]+','-').Trim('-').ToLowerInvariant())) `
        -CoverageGap
}

function Get-EAGovernanceCheckScopeManifest {
    [CmdletBinding()]
    param()

    return [ordered]@{
        'recommendations' = @('DirectoryRecommendations.Read.All')
        'securescore'          = @('SecurityEvents.Read.All')
        'accessreviews'        = @('AccessReview.Read.All','Group.Read.All')
        'authrecovery'         = @(
            'AuditLog.Read.All','Policy.Read.All',
            'Directory.Read.All','OnPremDirectorySynchronization.Read.All','Organization.Read.All'
        )
        'groupgovernance'      = @('Group.Read.All','Reports.Read.All','Directory.Read.All')
        'externaldelegation'   = @('DelegatedAdminRelationship.Read.All','RoleManagement.Read.Directory','User.Read.All','AuditLog.Read.All')
        'federationhealth'     = @(
            'Domain.Read.All','Domain-InternalFederation.Read.All',
            'OnPremDirectorySynchronization.Read.All','Organization.Read.All'
        )
        'identitygovernance'   = @(
            'EntitlementManagement.Read.All','LifecycleWorkflows.Read.All','Agreement.Read.All',
            'Group.Read.All','PrivilegedAssignmentSchedule.Read.AzureADGroup',
            'PrivilegedEligibilitySchedule.Read.AzureADGroup','RoleManagementPolicy.Read.AzureADGroup',
            'Policy.Read.All'
        )
    }
}

function Invoke-Check-EntraRecommendations {
    [CmdletBinding()]
    param()

    $checkId = 'recommendations'
    $doc = 'https://learn.microsoft.com/graph/api/directory-list-recommendation?view=graph-rest-beta'
    $result = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/beta/directory/recommendations?$expand=impactedResources'
    if (-not $result.Success) { throw $result.Error }

    $rows = foreach ($recommendation in @($result.Rows)) {
        $resources = @(Get-EAGovProperty $recommendation 'impactedResources')
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
            PostponeUntilDateTime = Get-EAGovProperty $recommendation 'postponeUntilDateTime'
            Insights          = Get-EAGovProperty $recommendation 'insights'
            ActionSteps       = (($steps | ForEach-Object { Get-EAGovProperty $_ 'text' }) -join ' | ')
        }
    }
    $src = Write-Evidence -BaseName 'entra_recommendations' -Rows @($rows) `
        -Title 'Microsoft Entra Recommendations (beta, read-only)' `
        -Notes @('The recommendations API is beta and can change. Only active recommendations become risk findings.')

    if ($result.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Tenant Posture' -DataSource 'Entra recommendations pagination' `
            -Reason "pagination exceeded $($result.Pages) pages." -RequiredScope 'DirectoryRecommendations.Read.All' `
            -DocumentationUrl $doc -SourceFile $src
    }

    $knownStatuses = @('active','completed','dismissed','postponed')
    $unknownStatusRows = @($result.Rows | Where-Object {
        $status = [string](Get-EAGovProperty $_ 'status')
        [string]::IsNullOrWhiteSpace($status) -or $status -notin $knownStatuses
    })
    if ($unknownStatusRows.Count -gt 0) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Tenant Posture' -DataSource 'Entra recommendation status' `
            -Reason ("{0} recommendation record(s) have a missing or unknown status and cannot be classified as active or resolved." -f $unknownStatusRows.Count) `
            -RequiredScope 'DirectoryRecommendations.Read.All' -DocumentationUrl $doc -SourceFile $src
    }

    $active = @($result.Rows | Where-Object { [string](Get-EAGovProperty $_ 'status') -ieq 'active' })
    foreach ($recommendation in $active) {
        $priority = [string](Get-EAGovProperty $recommendation 'priority')
        $severity = switch -Regex ($priority) {
            '^high$'   { 'High'; break }
            '^medium$' { 'Medium'; break }
            '^low$'    { 'Low'; break }
            default    { 'Medium' }
        }
        $name = [string](Get-EAGovProperty $recommendation 'displayName')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = [string](Get-EAGovProperty $recommendation 'recommendationType') }
        $steps = @(Get-EAGovProperty $recommendation 'actionSteps')
        $firstStep = if ($steps.Count -gt 0) { [string](Get-EAGovProperty $steps[0] 'text') } else { 'Review the recommendation details and impacted resources in Microsoft Entra.' }
        $insights = [string](Get-EAGovProperty $recommendation 'insights')
        $resourceCount = @(Get-EAGovProperty $recommendation 'impactedResources').Count
        $id = [string](Get-EAGovProperty $recommendation 'id')

        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Tenant Posture' `
            -Title "Active Microsoft Entra recommendation: $name" `
            -Evidence ("Priority={0}; impacted resources={1}; score={2}/{3}. {4}" -f $priority,$resourceCount,
                (Get-EAGovProperty $recommendation 'currentScore'),(Get-EAGovProperty $recommendation 'maxScore'),$insights) `
            -WhyItMatters 'Microsoft computes these recommendations from tenant configuration and activity, providing a maintained backstop for controls that can evolve after this audit was released.' `
            -RecommendedAction $firstStep -DocumentationUrl $doc -SourceFile $src `
            -RuleId ("entra-recommendation-" + [string](Get-EAGovProperty $recommendation 'recommendationType')) `
            -ObjectType 'recommendation' -ObjectId $id -ResultRows @($rows | Where-Object { $_.Id -eq $id })
    }

    if ($active.Count -eq 0 -and $unknownStatusRows.Count -eq 0 -and -not $result.Truncated) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Tenant Posture' `
            -Title 'Microsoft Entra recommendations reviewed' `
            -Evidence ("{0} recommendation record(s) returned; none currently have status active." -f @($result.Rows).Count) `
            -WhyItMatters 'The recommendation feed is a Microsoft-maintained signal for tenant-specific identity improvements.' `
            -RecommendedAction 'Continue reviewing the feed regularly and investigate newly active recommendations' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows @($rows)
    }
}

function Invoke-Check-SecureScore {
    [CmdletBinding()]
    param()

    $checkId = 'securescore'
    $doc = 'https://learn.microsoft.com/graph/api/security-list-securescores?view=graph-rest-1.0'
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
            -DocumentationUrl $doc -SourceFile $src
    }
    if ($ordered.Count -eq 0) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Security Posture' -DataSource 'Microsoft Secure Score' `
            -Reason 'the API succeeded but returned no score records.' -RequiredScope 'SecurityEvents.Read.All' `
            -DocumentationUrl $doc -SourceFile $src
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
            -RequiredScope 'SecurityEvents.Read.All' -DocumentationUrl $doc -SourceFile $src
    } elseif ([double]$latest.Percentage -lt 50) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Security Posture' `
            -Title ("Microsoft Secure Score is {0}%" -f $latest.Percentage) `
            -Evidence ("Latest score {0}/{1}, generated {2}. The 50% threshold is a triage threshold, not a compliance boundary." -f $latest.CurrentScore,$latest.MaxScore,$latest.CreatedDateTime) `
            -WhyItMatters 'A low aggregate score indicates that a substantial share of applicable Microsoft security controls is not credited as implemented.' `
            -RecommendedAction 'Prioritize unimplemented high-impact controls in Microsoft Secure Score and validate each recommendation against business requirements' `
            -DocumentationUrl $doc -SourceFile $controlSrc -RuleId 'secure-score-below-50'
    } elseif ([double]$latest.Percentage -lt 70) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Security Posture' `
            -Title ("Microsoft Secure Score is {0}%" -f $latest.Percentage) `
            -Evidence ("Latest score {0}/{1}, generated {2}. The 70% threshold is a prioritization aid, not a compliance boundary." -f $latest.CurrentScore,$latest.MaxScore,$latest.CreatedDateTime) `
            -WhyItMatters 'Remaining unimplemented controls can identify useful hardening opportunities even when the aggregate score is not itself a compliance measure.' `
            -RecommendedAction 'Review the lowest-cost, highest-impact remaining controls and document accepted risk' `
            -DocumentationUrl $doc -SourceFile $controlSrc -RuleId 'secure-score-below-70'
    }

    $latestDate = ConvertTo-EAGovDateTime $latest.CreatedDateTime
    if ($latestDate) {
        $older = @($ordered | Where-Object {
            $d = ConvertTo-EAGovDateTime $_.CreatedDateTime
            $d -and $d -le $latestDate.AddDays(-21) -and $null -ne $_.Percentage
        } | Select-Object -First 1)
        if ($older.Count -gt 0) {
            $delta = [math]::Round(([double]$latest.Percentage - [double]$older[0].Percentage), 1)
            if ($delta -le -5) {
                Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Security Posture' `
                    -Title ("Microsoft Secure Score declined by {0} percentage points" -f ([math]::Abs($delta))) `
                    -Evidence ("Score changed from {0}% on {1} to {2}% on {3}." -f $older[0].Percentage,$older[0].CreatedDateTime,$latest.Percentage,$latest.CreatedDateTime) `
                    -WhyItMatters 'A material decline can indicate disabled controls, newly applicable controls, licensing changes, or posture regression.' `
                    -RecommendedAction 'Review the Secure Score history and changed control scores to identify and validate the cause of the decline' `
                    -DocumentationUrl $doc -SourceFile $src -RuleId 'secure-score-decline'
            }
        }
    }

    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Security Posture' `
        -Title 'Microsoft Secure Score baseline captured' `
        -Evidence ("Latest score={0}/{1} ({2}%); generated={3}; {4} control score(s) captured." -f $latest.CurrentScore,$latest.MaxScore,$latest.Percentage,$latest.CreatedDateTime,@($controls).Count) `
        -WhyItMatters 'The dated score and control inventory provide a trend baseline; the score should guide investigation rather than be treated as a compliance certificate.' `
        -RecommendedAction 'Trend the score and investigate individual controls, including compensating controls that Microsoft cannot detect automatically' `
        -DocumentationUrl $doc -SourceFile $src -ResultRows $evidenceRows -RuleId 'secure-score-baseline'
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
    $result = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?$top=100'
    if (-not $result.Success) { throw $result.Error }

    $now = [datetimeoffset]::UtcNow
    $rows = New-Object System.Collections.Generic.List[object]
    $overdue = New-Object System.Collections.Generic.List[object]
    $partialInstances = New-Object System.Collections.Generic.List[object]
    $settingGaps = New-Object System.Collections.Generic.List[object]
    $categories = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $effectiveCategories = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $reviewedGroupIds = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($definition in @($result.Rows)) {
        $id = [string](Get-EAGovProperty $definition 'id')
        $category = Get-EAGovAccessReviewCategory $definition
        [void]$categories.Add($category)
        $scope = Get-EAGovProperty $definition 'scope'
        $scopeText = ConvertTo-EAGovCompactJson $scope
        foreach ($match in [regex]::Matches($scopeText, '(?i)/groups/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')) {
            [void]$reviewedGroupIds.Add($match.Groups[1].Value)
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
            -DocumentationUrl $doc -SourceFile $src
    }
    if ($partialInstances.Count -gt 0) {
        $partialSrc = Write-Evidence -BaseName 'access_review_instance_errors' -Rows $partialInstances.ToArray() -Title 'Access Review Instance Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Access review instances' `
            -Reason ("{0} definition(s) could not be enumerated completely." -f $partialInstances.Count) `
            -RequiredScope 'AccessReview.Read.All' -DocumentationUrl $doc -SourceFile $partialSrc
    }
    if ($settingGaps.Count -gt 0) {
        $settingGapSrc = Write-Evidence -BaseName 'access_review_setting_gaps' -Rows $settingGaps.ToArray() -Title 'Access Review Setting Coverage Gaps'
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'Access review decision-setting coverage is incomplete' `
            -Evidence ("{0} definition(s) omitted settings required to distinguish automatic application and default-decision behavior. Missing values are unknown, not false." -f $settingGaps.Count) `
            -WhyItMatters 'Treating an omitted property as disabled can conceal a permissive default decision or an unapplied decision workflow.' `
            -RecommendedAction 'Confirm AccessReview.Read.All access, inspect the affected definitions, and rerun the audit' `
            -DocumentationUrl $doc -SourceFile $settingGapSrc -ResultRows $settingGaps.ToArray() `
            -RuleId 'access-review-settings-unknown' -CoverageGap
    }

    if ($rows.Count -eq 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'No access review definitions are configured' `
            -Evidence 'The definitions API returned zero access reviews. This is a known empty result, not an API failure.' `
            -WhyItMatters 'Without recurring reviews, privileged, guest, group, and application access can persist after its business need ends.' `
            -RecommendedAction 'Configure recurring access reviews for privileged roles, sensitive groups, guest access, and enterprise-application assignments' `
            -DocumentationUrl $doc -SourceFile $src -RuleId 'access-reviews-none'
        return
    }

    $defaultApprove = @($rows | Where-Object { $_.DefaultDecisionEnabled -eq $true -and [string]$_.DefaultDecision -ieq 'Approve' })
    if ($defaultApprove.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} access review definition(s) default unanswered decisions to Approve" -f $defaultApprove.Count) `
            -Evidence 'DefaultDecisionEnabled=true and DefaultDecision=Approve causes non-responses to retain access.' `
            -WhyItMatters 'A review that approves unanswered decisions can preserve exactly the stale access the review is intended to remove.' `
            -RecommendedAction 'Use Deny or Recommendation as the default decision and require reviewers to justify approvals' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $defaultApprove -RuleId 'access-review-default-approve'
    }

    $nonRecurring = @($rows | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.RecurrencePattern) -or
        $_.Status -match '^(Completed|Inactive|Stopped|Cancelled|Canceled)$'
    })
    $sensitiveNonRecurring = @($nonRecurring | Where-Object { $_.Category -in @('PrivilegedRoles','Guests','InactiveUsers','EnterpriseApps','Groups') })
    if ($sensitiveNonRecurring.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} sensitive-access review definition(s) are not recurring" -f $sensitiveNonRecurring.Count) `
            -Evidence 'The review schedule is one-time, ended, or has no readable recurrence pattern.' `
            -WhyItMatters 'One-time reviews do not control access that is granted or becomes stale after the review ends.' `
            -RecommendedAction 'Use a recurring schedule with accountable reviewers for privileged, external, inactive-user, and application access' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $sensitiveNonRecurring -RuleId 'access-review-sensitive-not-recurring'
    }

    $manualApply = @($rows | Where-Object { $_.AutoApplyDecisions -eq $false -and $_.Category -in @('PrivilegedRoles','Guests','InactiveUsers','EnterpriseApps') })
    if ($manualApply.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} sensitive-access review definition(s) require manual application of decisions" -f $manualApply.Count) `
            -Evidence 'autoApplyDecisionsEnabled=false. Manual application can be intentional, but must be operationally tracked.' `
            -WhyItMatters 'Completed review decisions do not remove access until they are applied; an untracked manual step can leave denied access in place.' `
            -RecommendedAction 'Enable automatic application where safe, or document and monitor the manual apply workflow with an SLA' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $manualApply -RuleId 'access-review-manual-apply'
    }

    if ($overdue.Count -gt 0) {
        $roleOverdue = @($overdue | Where-Object { $_.Category -eq 'PrivilegedRoles' })
        $severity = if ($roleOverdue.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} access review instance(s) are overdue" -f $overdue.Count) `
            -Evidence ("The scheduled end date has passed while status remains nonterminal; {0} instance(s) cover privileged roles." -f $roleOverdue.Count) `
            -WhyItMatters 'Overdue reviews delay access removal and indicate that the governance process is not completing as designed.' `
            -RecommendedAction 'Escalate overdue reviewers, complete the reviews, apply decisions, and fix reviewer/notification ownership' `
            -DocumentationUrl $doc -SourceFile $overdueSrc -ResultRows $overdue.ToArray() -RuleId 'access-review-overdue'
    }

    $desired = @(
        @{ Category='PrivilegedRoles'; Severity='Medium'; Label='privileged roles' },
        @{ Category='Guests';          Severity='Low';    Label='guest users' },
        @{ Category='InactiveUsers';   Severity='Low';    Label='inactive users' },
        @{ Category='EnterpriseApps';  Severity='Low';    Label='enterprise applications' },
        @{ Category='Groups';          Severity='Low';    Label='group membership' }
    )
    foreach ($item in $desired) {
        if (-not $effectiveCategories.Contains($item.Category)) {
            Add-EAGovFinding -Severity $item.Severity -CheckId $checkId -Category 'Identity Governance' `
                -Title ("No access review coverage detected for {0}" -f $item.Label) `
                -Evidence ("No nonterminal recurring definition scope was classified as {0}. One-time, stopped, or completed definitions don't count as ongoing coverage." -f $item.Category) `
                -WhyItMatters ("Recurring review of {0} limits access accumulation and orphaned assignments." -f $item.Label) `
                -RecommendedAction ("Create a recurring access review for {0}, or document the equivalent compensating review process" -f $item.Label) `
                -DocumentationUrl $doc -SourceFile $src -RuleId ("access-review-missing-" + $item.Category.ToLowerInvariant())
        }
    }

    # Role-assignable groups need explicit coverage. This enrichment is optional because
    # it requires Group.Read.All in addition to AccessReview.Read.All.
    $roleGroups = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole%20eq%20true&$select=id,displayName,isAssignableToRole&$top=999&$count=true' -Headers @{ ConsistencyLevel='eventual' }
    if ($roleGroups.Success) {
        $uncoveredRoleGroups = @($roleGroups.Rows | Where-Object { -not $reviewedGroupIds.Contains([string](Get-EAGovProperty $_ 'id')) })
        if ($uncoveredRoleGroups.Count -gt 0) {
            $roleRows = @($uncoveredRoleGroups | ForEach-Object { [pscustomobject]@{ Id=(Get-EAGovProperty $_ 'id'); DisplayName=(Get-EAGovProperty $_ 'displayName') } })
            $roleSrc = Write-Evidence -BaseName 'access_review_uncovered_role_groups' -Rows $roleRows -Title 'Role-Assignable Groups Without Explicit Access Review Scope'
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title ("{0} role-assignable group(s) lack an explicit access review" -f $roleRows.Count) `
                -Evidence 'The group IDs were not found in any access-review scope. A broad all-groups review is not assumed to include security role-assignable groups.' `
                -WhyItMatters 'Membership in a role-assignable group can confer privileged directory access, so stale membership is a privileged access path.' `
                -RecommendedAction 'Create recurring reviews for role-assignable group membership and ownership, with automatic removal or a monitored apply process' `
                -DocumentationUrl $doc -SourceFile $roleSrc -ResultRows $roleRows -RuleId 'access-review-role-groups-uncovered'
        }
    } else {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Role-assignable group access-review coverage' `
            -Reason ([string]$roleGroups.Error.Exception.Message) -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $doc -SourceFile $src
    }

    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
        -Title 'Access review inventory captured' `
        -Evidence ("Definitions={0}; recurring nonterminal categories={1}; all categories={2}; overdue instances={3}." -f $rows.Count,($effectiveCategories -join ', '),($categories -join ', '),$overdue.Count) `
        -WhyItMatters 'A complete definition and instance inventory makes review coverage, recurrence, and operational backlog visible.' `
        -RecommendedAction 'Reconcile the inventory with the organization security-tier model and access-review ownership register' `
        -DocumentationUrl $doc -SourceFile $src -ResultRows $rows.ToArray() -RuleId 'access-review-inventory'
}

function Invoke-Check-AuthRecovery {
    [CmdletBinding()]
    param()

    $checkId = 'authrecovery'
    $doc = 'https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0'
    $policyDoc = 'https://learn.microsoft.com/graph/api/authenticationmethodspolicy-get?view=graph-rest-1.0'

    $registration = @(Get-EARegistrationDetails)
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

    if ($rows.Count -eq 0) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method user registration details' `
            -Reason 'the API returned no rows; disabled users are not represented by this API and tenant-wide recovery posture cannot be inferred.' `
            -RequiredScope 'AuditLog.Read.All' -DocumentationUrl $doc -SourceFile $src
        return
    }

    $members = @($rows | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.UserType) -or [string]$_.UserType -ieq 'member' })
    $admins = @($members | Where-Object { $_.IsAdmin -eq $true })
    $ssprEnabled = @($members | Where-Object { $_.IsSsprEnabled -eq $true })
    $ssprNotCapable = @($ssprEnabled | Where-Object { $_.IsSsprCapable -ne $true })
    $passwordless = @($members | Where-Object { $_.IsPasswordlessCapable -eq $true })
    $passwordlessAdmins = @($admins | Where-Object { $_.IsPasswordlessCapable -eq $true })
    $adminsWithoutPasswordless = @($admins | Where-Object { $_.IsPasswordlessCapable -ne $true })

    if ($ssprEnabled.Count -eq 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
            -Title 'No member users are reported as enabled for self-service password reset' `
            -Evidence ("The registration report contains {0} member user(s), with IsSsprEnabled=true for zero." -f $members.Count) `
            -WhyItMatters 'Without governed self-service recovery, password resets depend on helpdesk intervention and are more exposed to social-engineering pressure.' `
            -RecommendedAction 'Enable SSPR for an appropriate pilot and then broad user population, requiring strong recovery methods and monitoring reset events' `
            -DocumentationUrl $doc -SourceFile $src -RuleId 'sspr-no-enabled-members'
    } elseif ($ssprNotCapable.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
            -Title ("{0} SSPR-enabled member user(s) are not capable of self-service reset" -f $ssprNotCapable.Count) `
            -Evidence 'These users are enabled by policy but do not have the required allowed recovery-method registration.' `
            -WhyItMatters 'Users who cannot complete SSPR remain dependent on helpdesk resets and may be locked out during an incident.' `
            -RecommendedAction 'Run a registration campaign and remediate method-policy or registration gaps for the affected users' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $ssprNotCapable -RuleId 'sspr-enabled-not-capable'
    }

    if ($adminsWithoutPasswordless.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Authentication' `
            -Title ("{0} administrator(s) are not reported as passwordless capable" -f $adminsWithoutPasswordless.Count) `
            -Evidence ("{0}/{1} administrator(s) have IsPasswordlessCapable=true; every remaining administrator is listed. Passwordless capability is not by itself proof that Conditional Access requires phishing-resistant authentication." -f $passwordlessAdmins.Count,$admins.Count) `
            -WhyItMatters 'Privileged accounts that still depend on passwords have more exposure to password theft, replay, and helpdesk recovery attacks.' `
            -RecommendedAction 'Register FIDO2/passkeys, Windows Hello for Business, or another allowed passwordless method for every administrator, then separately require phishing-resistant authentication strength through Conditional Access' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $adminsWithoutPasswordless -RuleId 'passwordless-admins-not-capable'
    }

    if ($members.Count -gt 0) {
        $passwordlessPercent = [math]::Round(($passwordless.Count * 100.0) / $members.Count, 1)
        if ($passwordlessPercent -lt 25) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Authentication' `
                -Title ("Passwordless-capable adoption is {0}%" -f $passwordlessPercent) `
                -Evidence ("{0}/{1} member users are reported as passwordless capable. The 25% threshold is an adoption-prioritization threshold, not a compliance requirement." -f $passwordless.Count,$members.Count) `
                -WhyItMatters 'Low adoption limits the tenant population that can move away from phishable password-based authentication.' `
                -RecommendedAction 'Expand registration and rollout of allowed passwordless methods, prioritizing privileged and high-risk populations' `
                -DocumentationUrl $doc -SourceFile $src -RuleId 'passwordless-low-adoption'
        }
    }

    $systemPreferredKnown = @($members | Where-Object { $null -ne $_.IsSystemPreferredAuthenticationMethodEnabled })
    if ($systemPreferredKnown.Count -eq 0) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'System-preferred authentication status' `
            -Reason 'the property was absent/null on every registration record.' -RequiredScope 'AuditLog.Read.All' `
            -DocumentationUrl $doc -SourceFile $src
    } else {
        $memberSystemPreferredOff = @($members | Where-Object { $_.IsSystemPreferredAuthenticationMethodEnabled -eq $false })
        if ($memberSystemPreferredOff.Count -gt 0) {
            $adminSystemPreferredOff = @($memberSystemPreferredOff | Where-Object { $_.IsAdmin -eq $true })
            $severity = if ($adminSystemPreferredOff.Count -gt 0) { 'Medium' } else { 'Low' }
            Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Authentication' `
                -Title ("System-preferred authentication is disabled for {0} member registration record(s)" -f $memberSystemPreferredOff.Count) `
                -Evidence ("IsSystemPreferredAuthenticationMethodEnabled=false; {0} affected record(s) are administrators. The report exposes effective per-user state, not a user choice." -f $adminSystemPreferredOff.Count) `
                -WhyItMatters 'System-preferred MFA helps select the strongest registered method and reduces authentication-strength downgrade.' `
                -RecommendedAction 'Enable system-preferred authentication tenant-wide after validating exception populations' `
                -DocumentationUrl $doc -SourceFile $src -ResultRows $memberSystemPreferredOff -RuleId 'system-preferred-member-disabled'
        }
    }

    $policyResult = Invoke-EAGovGraphObject -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    if (-not $policyResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method migration and registration campaign policy' `
            -Reason ([string]$policyResult.Error.Exception.Message) -RequiredScope 'Policy.Read.All' `
            -DocumentationUrl $policyDoc -SourceFile $src
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
                -Title ("Authentication-method policy migration is {0}" -f $migration) `
                -Evidence 'The tenant has not reached migrationComplete, so legacy MFA/SSPR policy settings may still affect effective behavior.' `
                -WhyItMatters 'Split legacy and modern policy sources complicate assurance and can leave unintended method availability or inconsistent recovery behavior.' `
                -RecommendedAction 'Complete the documented migration to the unified Authentication Methods policy after validating method targets and SSPR requirements' `
                -DocumentationUrl $policyDoc -SourceFile $policySrc -RuleId 'auth-method-policy-migration-not-complete'
        } elseif ([string]::IsNullOrWhiteSpace($migration)) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Authentication-method migration state' `
                -Reason 'policyMigrationState was absent from the response.' -RequiredScope 'Policy.Read.All' `
                -DocumentationUrl $policyDoc -SourceFile $policySrc
        }

        $campaignState = [string](Get-EAGovProperty $campaign 'state')
        if ($campaignState -notmatch '^enabled$' -and $members.Count -gt $passwordless.Count) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Authentication' `
                -Title 'Authentication-method registration campaign is not enabled' `
                -Evidence ("Campaign state={0}; {1} member user(s) are not passwordless capable." -f ($campaignState ?? 'unknown'),($members.Count - $passwordless.Count)) `
                -WhyItMatters 'Without a targeted registration campaign, users may not enroll in stronger methods despite being eligible to do so.' `
                -RecommendedAction 'Enable and scope a registration campaign for Microsoft Authenticator or passkeys, with controlled exclusions and communications' `
                -DocumentationUrl $policyDoc -SourceFile $policySrc -RuleId 'registration-campaign-disabled'
        }
    }

    # Password-protection settings are stored as tenant group settings.  Merge
    # explicit values over the template defaults because Graph returns no setting
    # object when the tenant still uses every default.
    $passwordProtectionDoc = 'https://learn.microsoft.com/graph/group-directory-settings'
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
            -DocumentationUrl $passwordProtectionDoc -SourceFile $passwordSrc
    } elseif ($passwordMap.Count -gt 0) {
        $customEnabled = ConvertTo-EAGovBoolean $passwordMap['EnableBannedPasswordCheck']
        if ($bannedWords.Count -gt 0 -and $customEnabled -ne $true) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
                -Title 'A custom banned-password list exists but its check is disabled' `
                -Evidence ("Custom banned-password entries={0}; EnableBannedPasswordCheck={1}." -f $bannedWords.Count,$customEnabled) `
                -WhyItMatters 'Configured organization-specific weak terms provide no protection when the custom banned-password check is disabled.' `
                -RecommendedAction 'Enable the tenant-specific banned-password check and validate the normalized custom-word list' `
                -DocumentationUrl $passwordProtectionDoc -SourceFile $passwordSrc -RuleId 'custom-banned-password-check-disabled'
        }
        $lockoutThreshold = 0
        if ([int]::TryParse([string]$passwordMap['LockoutThreshold'], [ref]$lockoutThreshold) -and $lockoutThreshold -gt 10) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Authentication' `
                -Title ("Smart lockout threshold is {0}" -f $lockoutThreshold) `
                -Evidence 'The effective LockoutThreshold exceeds the Microsoft default of 10 failed attempts; this is a review threshold, not a universal compliance boundary.' `
                -WhyItMatters 'A high threshold allows more password guesses before smart lockout begins delaying subsequent attempts.' `
                -RecommendedAction 'Validate the threshold against attack telemetry, user-impact requirements, and current Microsoft guidance' `
                -DocumentationUrl $passwordProtectionDoc -SourceFile $passwordSrc -RuleId 'smart-lockout-threshold-high'
        }
    }

    # Graph exposes the directory-sync feature flag for password writeback, but
    # Microsoft documents that this particular property isn't in use. Capture it
    # without treating true as proof of operational writeback health.
    $syncDoc = 'https://learn.microsoft.com/graph/api/resources/onpremisesdirectorysynchronizationfeature?view=graph-rest-1.0'
    $organizationResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,onPremisesSyncEnabled'
    $syncResult = Invoke-EAGovGraphObject -Uri 'https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization'
    $hybrid = $organizationResult.Success -and @($organizationResult.Rows | Where-Object { (Get-EAGovProperty $_ 'onPremisesSyncEnabled') -eq $true }).Count -gt 0
    if ($hybrid) {
        if (-not $syncResult.Success) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Hybrid SSPR password-writeback configuration' `
                -Reason ([string]$syncResult.Error.Exception.Message) -RequiredScope 'OnPremDirectorySynchronization.Read.All' `
                -DocumentationUrl $syncDoc -SourceFile $src
        } else {
            $features = Get-EAGovProperty $syncResult.Value 'features'
            $writebackPresent = Test-EAGovPropertyPresent $features 'passwordWritebackEnabled'
            $writebackValue = Get-EAGovProperty $features 'passwordWritebackEnabled'
            Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Authentication' `
                -Title 'Hybrid SSPR password writeback requires an operational validation' `
                -Evidence ("Graph passwordWritebackEnabled present={0}; value={1}. Microsoft documents that this property isn't in use, so the audit does not interpret it as proof that resets are writing back." -f $writebackPresent,$writebackValue) `
                -WhyItMatters 'Hybrid users can appear SSPR-capable while a connector, permission, or service failure prevents the reset from reaching on-premises AD.' `
                -RecommendedAction 'Perform a controlled SSPR writeback test for each synchronized domain and monitor connector/writeback failures' `
                -DocumentationUrl $syncDoc -SourceFile $src -RuleId 'hybrid-password-writeback-manual-validation' -CoverageGap
        }

        if ($passwordMap.Count -gt 0) {
            $onPremProtection = ConvertTo-EAGovBoolean $passwordMap['EnableBannedPasswordCheckOnPremises']
            $onPremMode = [string]$passwordMap['BannedPasswordCheckOnPremisesMode']
            if ($onPremProtection -ne $true -or $onPremMode -notmatch '^(Enforce|Enforced)$') {
                Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Authentication' `
                    -Title 'On-premises Microsoft Entra Password Protection is not in enforced mode' `
                    -Evidence ("EnableBannedPasswordCheckOnPremises={0}; mode={1}." -f $onPremProtection,$onPremMode) `
                    -WhyItMatters "Synchronized and on-premises-only users don't receive the same banned-password control when the DC agents are disabled or audit-only." `
                    -RecommendedAction 'Deploy healthy proxy/DC agents and enable enforced mode after reviewing audit results and licensing' `
                    -DocumentationUrl $passwordProtectionDoc -SourceFile $passwordSrc -RuleId 'onprem-password-protection-not-enforced'
            }
        }
    } elseif (-not $organizationResult.Success -or $organizationResult.Truncated) {
        $reason = if ($organizationResult.Success) { 'organization pagination limit reached' } else { [string]$organizationResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Authentication' -DataSource 'Hybrid status for password recovery controls' `
            -Reason $reason -RequiredScope 'Organization.Read.All' -DocumentationUrl $syncDoc -SourceFile $src
    }

    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Authentication' `
        -Title 'Authentication recovery and passwordless baseline captured' `
        -Evidence ("Members={0}; SSPR enabled/registered/capable={1}/{2}/{3}; passwordless capable={4}; admins={5}." -f `
            $members.Count,$ssprEnabled.Count,@($members | Where-Object {$_.IsSsprRegistered -eq $true}).Count,
            @($members | Where-Object {$_.IsSsprCapable -eq $true}).Count,$passwordless.Count,$admins.Count) `
        -WhyItMatters 'Registration-state evidence shows whether users can actually use recovery and strong authentication, not just whether a policy object exists.' `
        -RecommendedAction 'Track these adoption and capability measures over time and remediate affected users before enforcing stronger controls' `
        -DocumentationUrl $doc -SourceFile $src -ResultRows @($rows) -RuleId 'auth-recovery-baseline'
}

function Invoke-Check-GroupGovernance {
    [CmdletBinding()]
    param()

    $checkId = 'groupgovernance'
    $doc = 'https://learn.microsoft.com/entra/identity/users/groups-lifecycle'
    $reportDoc = 'https://learn.microsoft.com/graph/api/reportroot-getoffice365groupsactivitydetail?view=graph-rest-beta'
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
        }) | Out-Null
    }

    # A successful report call with zero rows isn't useful coverage when the
    # directory contains Microsoft 365 groups. Treat it as unknown rather than
    # silently making every group ineligible for inactivity evaluation.
    $m365GroupCount = @($rows | Where-Object { $_.GroupKind -eq 'Microsoft365' }).Count
    $activityReturnedNoRows = $activityCoverage -and $m365GroupCount -gt 0 -and @($activityResult.Rows).Count -eq 0
    if ($activityReturnedNoRows) { $activityCoverage = $false }

    $src = Write-Evidence -BaseName 'group_governance' -Rows $rows.ToArray() -Title 'Group Ownership, Lifecycle, Visibility, and Activity Governance' `
        -Notes @('A group is considered inactive only when the Microsoft 365 D180 activity report contains a row with no activity in the reporting window or an old LastActivityDate. Absence from that report is unknown, not stale.')

    if ($result.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Group inventory pagination' `
            -Reason "pagination exceeded $($result.Pages) pages." -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $doc -SourceFile $src
    }
    if ($ownerReadErrors.Count -gt 0) {
        $ownerErrSrc = Write-Evidence -BaseName 'group_owner_collection_errors' -Rows $ownerReadErrors.ToArray() -Title 'Group Owner Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Group owners' `
            -Reason ("owner data was incomplete for {0} group(s)." -f $ownerReadErrors.Count) -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $doc -SourceFile $ownerErrSrc
    }
    if (-not $activityCoverage) {
        $reason = if ($activityReturnedNoRows) {
            "the API returned zero report rows while $m365GroupCount Microsoft 365 group(s) exist"
        } elseif ($activityResult.Success) { 'pagination limit reached' } else { [string]$activityResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Group Governance' -DataSource 'Microsoft 365 group activity (D180)' `
            -Reason $reason -RequiredScope 'Reports.Read.All' -DocumentationUrl $reportDoc -SourceFile $src
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
            -Reason $reason -RequiredScope 'Directory.Read.All' -DocumentationUrl $groupSettingsDoc -SourceFile $groupSettingsSrc
    } elseif ($unifiedMap.Count -gt 0) {
        if ((ConvertTo-EAGovBoolean $unifiedMap['AllowGuestsToBeGroupOwner']) -eq $true) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Group Governance' `
                -Title 'Guests are allowed to own Microsoft 365 groups' `
                -Evidence 'The effective Group.Unified setting AllowGuestsToBeGroupOwner=true.' `
                -WhyItMatters 'An external identity can control membership and connected resources of a group after its sponsor or business relationship changes.' `
                -RecommendedAction 'Disable guest ownership unless a documented scenario requires it, and review all existing guest-owned groups' `
                -DocumentationUrl $groupSettingsDoc -SourceFile $groupSettingsSrc -RuleId 'group-settings-guest-owners-allowed'
        }
        if ((ConvertTo-EAGovBoolean $unifiedMap['EnableGroupCreation']) -eq $true) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
                -Title 'Microsoft 365 group creation is available to all users' `
                -Evidence 'The effective Group.Unified setting EnableGroupCreation=true; no restriction group is applied by this setting.' `
                -WhyItMatters 'Unrestricted creation can increase unmanaged groups, owners, guests, applications, and collaboration data.' `
                -RecommendedAction 'Confirm self-service creation is intentional and back it with expiration, naming, sensitivity, ownership, and access-review controls; otherwise restrict creation to a governed group' `
                -DocumentationUrl $groupSettingsDoc -SourceFile $groupSettingsSrc -RuleId 'group-settings-creation-unrestricted'
        }
        if ([string]::IsNullOrWhiteSpace([string]$unifiedMap['PrefixSuffixNamingRequirement']) -and
            [string]::IsNullOrWhiteSpace([string]$unifiedMap['CustomBlockedWordsList'])) {
            Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Group Governance' `
                -Title 'No Microsoft 365 group naming policy is configured' `
                -Evidence 'Both PrefixSuffixNamingRequirement and CustomBlockedWordsList are empty in the effective Group.Unified settings.' `
                -WhyItMatters 'Naming controls can improve ownership, purpose, search, automation, and cleanup, although they are not a standalone security boundary.' `
                -RecommendedAction 'Document the naming standard and configure a prefix/suffix or blocked terms when it supports the lifecycle process' `
                -DocumentationUrl $groupSettingsDoc -SourceFile $groupSettingsSrc -RuleId 'group-settings-naming-policy-absent'
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
            -Reason $reason -RequiredScope 'Directory.Read.All' -DocumentationUrl $lifecycleDoc -SourceFile $lifecycleSrc
    } elseif ($m365GroupCount -gt 0 -and ($lifecycleRows.Count -eq 0 -or @($lifecycleRows | Where-Object { [string]$_.ManagedGroupTypes -notmatch '^None$' }).Count -eq 0)) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
            -Title 'No active Microsoft 365 group expiration policy is configured' `
            -Evidence ("Microsoft 365 groups={0}; lifecycle policy records={1}; none apply to All or Selected groups." -f $m365GroupCount,$lifecycleRows.Count) `
            -WhyItMatters 'Groups can persist indefinitely after their purpose ends unless another governed process identifies and retires them.' `
            -RecommendedAction 'Configure an appropriate expiration/renewal policy or document an equivalent lifecycle process with owner notifications and cleanup evidence' `
            -DocumentationUrl $lifecycleDoc -SourceFile $lifecycleSrc -RuleId 'm365-group-expiration-policy-absent'
    }

    $roleOwnerless = @($rows | Where-Object { $_.OwnersKnown -and $_.OwnerCount -eq 0 -and $_.IsAssignableToRole -eq $true })
    if ($roleOwnerless.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Group Governance' `
            -Title ("{0} role-assignable group(s) have no owner" -f $roleOwnerless.Count) `
            -Evidence 'Owner enumeration succeeded and returned zero owners for these role-assignable groups.' `
            -WhyItMatters 'A role-assignable group is a privileged access path; without an accountable owner, membership review and incident response can be orphaned.' `
            -RecommendedAction 'Assign at least two accountable cloud owners, protect ownership with PIM for Groups, and establish recurring access review' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $roleOwnerless -RuleId 'role-group-ownerless'
    }

    $cloudOwnerless = @($rows | Where-Object {
        $_.OwnersKnown -and $_.OwnerCount -eq 0 -and $_.IsAssignableToRole -ne $true -and
        $_.OnPremisesSyncEnabled -ne $true -and $_.GroupKind -in @('Security','Microsoft365')
    })
    if ($cloudOwnerless.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Group Governance' `
            -Title ("{0} cloud security/Microsoft 365 group(s) have no owner" -f $cloudOwnerless.Count) `
            -Evidence 'Owner enumeration succeeded and returned zero owners; synchronized groups are excluded from this medium-severity population.' `
            -WhyItMatters 'Ownerless cloud groups lack a clear authority to approve membership, review external access, and retire the group.' `
            -RecommendedAction 'Assign accountable owners or retire unused groups; use expiration and ownerless-group notifications where appropriate' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $cloudOwnerless -RuleId 'cloud-group-ownerless'
    }

    $syncedOwnerless = @($rows | Where-Object { $_.OwnersKnown -and $_.OwnerCount -eq 0 -and $_.OnPremisesSyncEnabled -eq $true })
    if ($syncedOwnerless.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
            -Title ("{0} synchronized group(s) have no cloud owner" -f $syncedOwnerless.Count) `
            -Evidence 'These groups are synchronized from on-premises, so ownership may be managed in the source directory; the cloud owner field is empty.' `
            -WhyItMatters 'Even when lifecycle is managed on-premises, a documented business owner is needed for access certification and decommissioning.' `
            -RecommendedAction 'Confirm the source-directory ownership process and record accountable owners in a system used by access reviewers' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $syncedOwnerless -RuleId 'synced-group-ownerless'
    }

    $publicM365 = @($rows | Where-Object { $_.GroupKind -eq 'Microsoft365' -and [string]$_.Visibility -ieq 'Public' })
    if ($publicM365.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
            -Title ("{0} Microsoft 365 group(s) are public/self-service joinable" -f $publicM365.Count) `
            -Evidence 'Visibility=Public allows users in the organization to discover and join these groups without owner approval.' `
            -WhyItMatters 'Public membership is appropriate for open collaboration but can expose group-connected resources when the group is used for sensitive content or app access.' `
            -RecommendedAction 'Validate that each public group is intended for open membership and change sensitive groups to private with approval-based membership' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $publicM365 -RuleId 'public-m365-groups'
    }

    $pausedDynamic = @($rows | Where-Object { $_.IsDynamic -and [string]$_.MembershipRuleState -notmatch '^(On|Processing)$' })
    if ($pausedDynamic.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Group Governance' `
            -Title ("{0} dynamic group(s) do not have active membership-rule processing" -f $pausedDynamic.Count) `
            -Evidence 'The group is DynamicMembership, but membershipRuleProcessingState is not On/Processing.' `
            -WhyItMatters 'Paused or failed dynamic processing can leave obsolete users in access-bearing groups or omit users who require access.' `
            -RecommendedAction 'Validate each membership rule, restore processing, and review the effective membership before relying on the group for access' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $pausedDynamic -RuleId 'dynamic-group-processing-off'
    }

    $invalidPrivilegedDynamic = @($rows | Where-Object { $_.IsAssignableToRole -eq $true -and $_.IsDynamic })
    if ($invalidPrivilegedDynamic.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Group Governance' `
            -Title 'Role-assignable group reported with dynamic membership' `
            -Evidence 'Graph returned both isAssignableToRole=true and DynamicMembership. This unsupported/high-risk combination requires validation.' `
            -WhyItMatters 'Automatically evaluated attributes must not be able to grant privileged directory roles without direct privileged-access governance.' `
            -RecommendedAction 'Verify the anomalous objects in Entra, remove dynamic privilege assignment, and use assigned membership governed by PIM for Groups' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $invalidPrivilegedDynamic -RuleId 'role-group-dynamic'
    }

    if ($activityCoverage) {
        $cutoff = [datetimeoffset]::UtcNow.AddDays(-180)
        $inactive = @($rows | Where-Object {
            if (-not $_.ActivityEvidenceKnown) { return $false }
            $last = ConvertTo-EAGovDateTime $_.LastActivityDate
            return (-not $last -or $last -lt $cutoff)
        })
        if ($inactive.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Group Governance' `
                -Title ("{0} Microsoft 365 group(s) show no recent activity in the D180 report" -f $inactive.Count) `
                -Evidence 'Only groups with an explicit activity-report row were evaluated; missing report rows were treated as unknown.' `
                -WhyItMatters 'Inactive groups accumulate memberships, guests, content, and application access after their collaboration purpose ends.' `
                -RecommendedAction 'Confirm business need with owners, review memberships/content, and archive or delete groups through the approved lifecycle process' `
                -DocumentationUrl $reportDoc -SourceFile $src -ResultRows $inactive -RuleId 'm365-groups-inactive-180d'
        }
    }

    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Group Governance' `
        -Title 'Group governance inventory captured' `
        -Evidence ("Groups={0}; role-assignable={1}; dynamic={2}; public M365={3}; activity coverage={4}." -f `
            $rows.Count,@($rows | Where-Object {$_.IsAssignableToRole -eq $true}).Count,
            @($rows | Where-Object {$_.IsDynamic}).Count,$publicM365.Count,$activityCoverage) `
        -WhyItMatters 'Ownership, visibility, lifecycle, dynamic membership, and activity are complementary signals for group access governance.' `
        -RecommendedAction 'Reconcile this inventory with group naming, ownership, expiration, sensitivity, and access-review standards' `
        -DocumentationUrl $doc -SourceFile $src -ResultRows $rows.ToArray() -RuleId 'group-governance-inventory'
}

function ConvertFrom-EAGovDurationDays {
    param([AllowNull()]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return [math]::Round([System.Xml.XmlConvert]::ToTimeSpan([string]$Value).TotalDays, 1) }
    catch { return $null }
}

function Get-EAGovDirectoryRoleRisk {
    param(
        [AllowNull()][string]$RoleDefinitionId,
        [AllowNull()]$RoleDefinition
    )

    $tierZero = @(
        '62e90394-69f5-4237-9190-012177145e10', # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814', # Privileged Role Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'  # Privileged Authentication Administrator
    )
    $templateId = [string](Get-EAGovProperty $RoleDefinition 'templateId')
    if ($RoleDefinitionId -in $tierZero -or $templateId -in $tierZero) { return 'Critical' }

    $isPrivileged = Get-EAGovProperty $RoleDefinition 'isPrivileged'
    if ($isPrivileged -eq $true) { return 'High' }

    $actions = New-Object System.Collections.Generic.List[string]
    foreach ($permission in @(Get-EAGovProperty $RoleDefinition 'rolePermissions')) {
        foreach ($action in @(Get-EAGovProperty $permission 'allowedResourceActions')) {
            if ($action) { $actions.Add([string]$action) | Out-Null }
        }
    }
    $actionText = $actions -join ';'
    if ($actionText -match '(?i)(roleAssignments/.*/allTasks|roles/.*/allTasks|users/authenticationMethods/.*/allTasks|users/password/update|conditionalAccessPolicies/.*/allTasks|servicePrincipals/credentials/update|applications/credentials/update|entitlementManagement/.*/allTasks)') {
        return 'High'
    }
    if ($null -eq $RoleDefinition) { return 'Unknown' }
    return 'Standard'
}

function Invoke-Check-ExternalDelegation {
    [CmdletBinding()]
    param()

    $checkId = 'externaldelegation'
    $doc = 'https://learn.microsoft.com/graph/api/tenantrelationship-list-delegatedadminrelationships?view=graph-rest-1.0'
    $sponsorDoc = 'https://learn.microsoft.com/graph/api/user-list-sponsors?view=graph-rest-1.0'
    $guestDoc = 'https://learn.microsoft.com/graph/api/user-list?view=graph-rest-1.0'

    # ------------------------- GDAP relationships -------------------------
    $relationshipResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships?$top=300'
    $relationships = @(if ($relationshipResult.Success) { @($relationshipResult.Rows) } else { @() })

    $roleMap = @{}
    $roleDefinitionsKnown = $true
    $roleDefinitionResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn,isPrivileged,rolePermissions&$top=999'
    if (-not $roleDefinitionResult.Success) {
        $roleDefinitionResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn,rolePermissions&$top=999'
    }
    if ($roleDefinitionResult.Success -and -not $roleDefinitionResult.Truncated) {
        foreach ($role in @($roleDefinitionResult.Rows)) {
            $id = [string](Get-EAGovProperty $role 'id')
            if ($id) { $roleMap[$id] = $role }
            $templateId = [string](Get-EAGovProperty $role 'templateId')
            if ($templateId -and -not $roleMap.ContainsKey($templateId)) { $roleMap[$templateId] = $role }
        }
    } else {
        $roleDefinitionsKnown = $false
    }

    $relationshipRows = New-Object System.Collections.Generic.List[object]
    foreach ($relationship in $relationships) {
        $access = Get-EAGovProperty $relationship 'accessDetails'
        $roles = @(Get-EAGovProperty $access 'unifiedRoles')
        if ($roles.Count -eq 0) { $roles = @($null) }
        foreach ($roleRef in $roles) {
            $roleId = [string](Get-EAGovProperty $roleRef 'roleDefinitionId')
            $definition = if ($roleId -and $roleMap.ContainsKey($roleId)) { $roleMap[$roleId] } else { $null }
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
                RoleDisplayName     = if ($definition) { Get-EAGovProperty $definition 'displayName' } else { $null }
                RoleRisk            = Get-EAGovDirectoryRoleRisk -RoleDefinitionId $roleId -RoleDefinition $definition
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
                $definition = if ($roleId -and $roleMap.ContainsKey($roleId)) { $roleMap[$roleId] } else { $null }
                $accessAssignmentRows.Add([pscustomobject]@{
                    RelationshipId=$relationshipId
                    DisplayName=Get-EAGovProperty $relationship 'displayName'
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
                    RoleDisplayName=if ($definition) { Get-EAGovProperty $definition 'displayName' } else { $null }
                    RoleRisk=Get-EAGovDirectoryRoleRisk -RoleDefinitionId $roleId -RoleDefinition $definition
                }) | Out-Null
            }
        }
    }
    $assignmentSrc = Write-Evidence -BaseName 'external_delegated_admin_access_assignments' -Rows $accessAssignmentRows.ToArray() `
        -Title 'Effective Active GDAP Access Assignments'

    if (-not $relationshipResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP delegated admin relationships' `
            -Reason ([string]$relationshipResult.Error.Exception.Message) -RequiredScope 'DelegatedAdminRelationship.Read.All' `
            -DocumentationUrl $doc -SourceFile $relationshipSrc
    } elseif ($relationshipResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP delegated admin relationship pagination' `
            -Reason "pagination exceeded $($relationshipResult.Pages) pages." -RequiredScope 'DelegatedAdminRelationship.Read.All' `
            -DocumentationUrl $doc -SourceFile $relationshipSrc
    }
    if (-not $roleDefinitionsKnown -and $relationships.Count -gt 0) {
        $reason = if ($roleDefinitionResult.Success) { 'pagination limit reached' } else { [string]$roleDefinitionResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'GDAP role definitions and effective role risk' `
            -Reason $reason -RequiredScope 'RoleManagement.Read.Directory' -DocumentationUrl $doc -SourceFile $relationshipSrc
    }
    if ($accessAssignmentErrors.Count -gt 0) {
        $assignmentErrorSrc = Write-Evidence -BaseName 'external_delegated_admin_access_assignment_errors' -Rows $accessAssignmentErrors.ToArray() -Title 'GDAP Access Assignment Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Effective GDAP access assignments' `
            -Reason ("{0} active relationship or assignment read(s) were incomplete." -f $accessAssignmentErrors.Count) `
            -RequiredScope 'DelegatedAdminRelationship.Read.All' -DocumentationUrl $doc -SourceFile $assignmentErrorSrc
    }
    if ($activeRelationshipsWithoutAssignments.Count -gt 0) {
        $noAssignmentSrc = Write-Evidence -BaseName 'external_delegated_admin_relationships_without_assignments' -Rows $activeRelationshipsWithoutAssignments.ToArray() -Title 'Active GDAP Relationships Without Active Access Assignments'
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'External Access' `
            -Title ("{0} active GDAP relationship(s) have no active access assignment" -f $activeRelationshipsWithoutAssignments.Count) `
            -Evidence 'The relationships have approved accessDetails, but accessAssignments returned no active partner security-group binding; approved roles are not reported as effective grants.' `
            -WhyItMatters 'Separating approved relationship roles from effective assignments prevents both false alarms and false assurance about who can administer the tenant.' `
            -RecommendedAction 'Confirm the relationships are intentionally unassigned and terminate obsolete relationships rather than leaving dormant approvals' `
            -DocumentationUrl $doc -SourceFile $noAssignmentSrc -ResultRows $activeRelationshipsWithoutAssignments.ToArray() -RuleId 'gdap-active-without-access-assignment'
    }

    $activeRows = @($accessAssignmentRows.ToArray())
    foreach ($group in @($activeRows | Group-Object RelationshipId)) {
        $relationship = @($group.Group)
        $critical = @($relationship | Where-Object { $_.RoleRisk -eq 'Critical' })
        $high = @($relationship | Where-Object { $_.RoleRisk -eq 'High' })
        $unknown = @($relationship | Where-Object { $_.RoleRisk -eq 'Unknown' -and $_.RoleDefinitionId })
        $severity = if ($critical.Count -gt 0) { 'Critical' } elseif ($high.Count -gt 0) { 'High' } else { $null }
        if ($severity) {
            $roleNames = @($relationship | Where-Object { $_.RoleRisk -in @('Critical','High') } | ForEach-Object {
                $_.RoleDisplayName ?? $_.RoleDefinitionId
            } | Select-Object -Unique)
            Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'External Access' `
                -Title ("Active GDAP relationship grants privileged roles: {0}" -f $relationship[0].DisplayName) `
                -Evidence ("Privileged roles: {0}; end={1}; autoExtend={2}." -f ($roleNames -join ', '),$relationship[0].EndDateTime,$relationship[0].AutoExtendDuration) `
                -WhyItMatters 'A partner identity can exercise these tenant roles from outside the customer organization; tier-0 roles can lead to full tenant takeover.' `
                -RecommendedAction 'Confirm the partner business need, minimize roles and duration, require partner MFA/CA, monitor activity, and terminate unused relationships' `
                -DocumentationUrl $doc -SourceFile $assignmentSrc -ResultRows $relationship `
                -AffectedPrincipal ([string]$relationship[0].DisplayName) -RuleId 'gdap-privileged-role' `
                -ObjectType 'delegatedAdminRelationship' -ObjectId ([string]$relationship[0].RelationshipId)
        }
        if ($unknown.Count -gt 0) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource ("GDAP role risk for relationship " + $relationship[0].DisplayName) `
                -Reason ("{0} role definition(s) could not be resolved." -f $unknown.Count) `
                -RequiredScope 'RoleManagement.Read.Directory' -DocumentationUrl $doc -SourceFile $assignmentSrc
        }
    }

    $now = [datetimeoffset]::UtcNow
    $expiredActive = @($activeRows | Where-Object {
        $end = ConvertTo-EAGovDateTime $_.EndDateTime
        $end -and $end -lt $now
    })
    if ($expiredActive.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'External Access' `
            -Title ("{0} active GDAP role grant(s) have passed their relationship end time" -f $expiredActive.Count) `
            -Evidence 'The relationship status is active while EndDateTime is earlier than the audit time.' `
            -WhyItMatters 'A relationship that remains active beyond its expected end can preserve unintended external administrative access.' `
            -RecommendedAction 'Validate relationship state with the partner and Microsoft Partner Center, then terminate or correct expired access' `
            -DocumentationUrl $doc -SourceFile $relationshipSrc -ResultRows $expiredActive -RuleId 'gdap-active-past-end'
    }

    $longLived = @($activeRows | Where-Object { $null -eq $_.EndDateTime -or ($null -ne $_.DurationDays -and $_.DurationDays -gt 730) })
    if ($longLived.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'External Access' `
            -Title ("{0} active GDAP role grant(s) are very long-lived or have no readable end" -f $longLived.Count) `
            -Evidence 'The relationship duration exceeds two years or EndDateTime is absent. Duplicate rows represent individual roles in a relationship.' `
            -WhyItMatters 'Long-lived partner administration increases the chance that obsolete access survives contract, personnel, or service changes.' `
            -RecommendedAction 'Use the shortest practical GDAP duration and periodically reapprove partner roles against the active contract' `
            -DocumentationUrl $doc -SourceFile $relationshipSrc -ResultRows $longLived -RuleId 'gdap-long-lived'
    }

    # ------------------------- Accepted guest lifecycle -------------------------
    $inactiveThreshold = 90
    $thresholdVariable = Get-Variable -Name InactiveDays -Scope Script -ErrorAction SilentlyContinue
    if ($thresholdVariable -and [int]$thresholdVariable.Value -gt 0) { $inactiveThreshold = [int]$thresholdVariable.Value }
    # Keep the base guest/sponsor read separate from signInActivity. A missing P1
    # license or AuditLog.Read.All must not prevent sponsor governance from running.
    $guestBaseUri = "https://graph.microsoft.com/v1.0/users?`$filter=userType%20eq%20'Guest'&`$select=id,userPrincipalName,displayName,accountEnabled,userType,externalUserState,externalUserStateChangeDateTime,createdDateTime&`$top=999"
    $guestActivityUri = "https://graph.microsoft.com/v1.0/users?`$filter=userType%20eq%20'Guest'&`$select=id,signInActivity&`$top=999"
    $guestResult = Invoke-EAGovGraphCollection -Uri $guestBaseUri
    $guestActivityResult = Invoke-EAGovGraphCollection -Uri $guestActivityUri
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
    if ($guestResult.Success) {
        foreach ($guest in @($guestResult.Rows | Where-Object { [string](Get-EAGovProperty $_ 'externalUserState') -ieq 'Accepted' })) {
            $guestId = [string](Get-EAGovProperty $guest 'id')
            $sponsorsKnown = $false
            $sponsors = @()
            if ($guestId) {
                $sponsorResult = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/users/{0}/sponsors?`$select=id,displayName,userPrincipalName" -f [uri]::EscapeDataString($guestId))
                if ($sponsorResult.Success -and -not $sponsorResult.Truncated) {
                    $sponsorsKnown = $true
                    $sponsors = @($sponsorResult.Rows)
                } else {
                    $reason = if ($sponsorResult.Success) { 'pagination limit reached' } else { [string]$sponsorResult.Error.Exception.Message }
                    $sponsorErrors.Add([pscustomobject]@{ GuestId=$guestId; UserPrincipalName=(Get-EAGovProperty $guest 'userPrincipalName'); Reason=$reason }) | Out-Null
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
                Sponsors                   = (($sponsors | ForEach-Object {
                    (Get-EAGovProperty $_ 'userPrincipalName') ?? (Get-EAGovProperty $_ 'displayName') ?? (Get-EAGovProperty $_ 'id')
                }) -join '; ')
            }) | Out-Null
        }
    }
    $guestSrc = Write-Evidence -BaseName 'accepted_guest_lifecycle' -Rows $guestRows.ToArray() `
        -Title 'Accepted Guest Activity and Sponsor Governance' `
        -Notes @(("Inactive threshold: {0} days. Only LastSuccessfulSignInDateTime establishes activity; failed attempts in LastSignInDateTime do not reset the inactivity clock." -f $inactiveThreshold))

    if (-not $guestResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest inventory and sponsor population' `
            -Reason ([string]$guestResult.Error.Exception.Message) -RequiredScope 'User.Read.All' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc
    } elseif ($guestResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest pagination' `
            -Reason "pagination exceeded $($guestResult.Pages) pages." -RequiredScope 'User.Read.All' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc
    }
    if (-not $guestActivityResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest sign-in activity' `
            -Reason ([string]$guestActivityResult.Error.Exception.Message) -RequiredScope 'AuditLog.Read.All plus Entra ID P1 or P2' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc
    } elseif ($guestActivityResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest sign-in activity pagination' `
            -Reason "pagination exceeded $($guestActivityResult.Pages) pages." -RequiredScope 'AuditLog.Read.All plus Entra ID P1 or P2' `
            -DocumentationUrl $guestDoc -SourceFile $guestSrc
    }
    if ($sponsorErrors.Count -gt 0) {
        $sponsorErrSrc = Write-Evidence -BaseName 'guest_sponsor_collection_errors' -Rows $sponsorErrors.ToArray() -Title 'Guest Sponsor Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'External Access' -DataSource 'Accepted guest sponsors' `
            -Reason ("sponsor enumeration failed or truncated for {0} accepted guest(s)." -f $sponsorErrors.Count) `
            -RequiredScope 'User.Read.All plus a supported sponsor-reader directory role' `
            -DocumentationUrl $sponsorDoc -SourceFile $sponsorErrSrc
    }

    $missingSponsors = @($guestRows | Where-Object { $_.SponsorsKnown -and $_.SponsorCount -eq 0 })
    if ($missingSponsors.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'External Access' `
            -Title ("{0} accepted guest(s) have no sponsor" -f $missingSponsors.Count) `
            -Evidence 'Sponsor enumeration succeeded and returned zero sponsors for these accepted guests.' `
            -WhyItMatters 'Without an accountable sponsor, no internal owner is responsible for periodically validating the guest business need and access.' `
            -RecommendedAction 'Assign an accountable user or group sponsor and include sponsor accountability in guest access reviews and lifecycle workflows' `
            -DocumentationUrl $sponsorDoc -SourceFile $guestSrc -ResultRows $missingSponsors -RuleId 'accepted-guests-no-sponsor'
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
                -Title ("{0} enabled, accepted guest(s) are inactive for more than {1} days" -f $inactiveGuests.Count,$inactiveThreshold) `
                -Evidence 'Guests are accepted and enabled, and their last successful sign-in is older than the threshold; never-successfully-signed-in guests are flagged only after the accepted/created date exceeds the threshold. Failed attempts do not count as activity.' `
                -WhyItMatters 'Accepted guest accounts can retain group, application, and collaboration access after the external relationship ends.' `
                -RecommendedAction 'Have sponsors validate business need, review effective access, then disable or remove stale guests through the approved lifecycle process' `
                -DocumentationUrl $guestDoc -SourceFile $guestSrc -ResultRows $inactiveGuests -RuleId 'accepted-guests-inactive'
        }
    }

    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'External Access' `
        -Title 'External delegation and accepted-guest inventory captured' `
        -Evidence ("GDAP relationships={0}; active GDAP role rows={1}; accepted guests={2}; sponsor read errors={3}." -f `
            $relationships.Count,$activeRows.Count,$guestRows.Count,$sponsorErrors.Count) `
        -WhyItMatters 'Partner administration and guest accounts are separate external-access paths and need explicit owners, time limits, and review.' `
        -RecommendedAction 'Reconcile partner and guest access with contracts, sponsors, Conditional Access, monitoring, and recurring access reviews' `
        -DocumentationUrl $doc -SourceFile $relationshipSrc -ResultRows $relationshipRows.ToArray() -RuleId 'external-delegation-inventory'
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
        if (-not $configResult.Success) {
            $configErrors.Add([pscustomobject]@{ Domain=$domainId; StatusCode=$configResult.StatusCode; Reason=[string]$configResult.Error.Exception.Message }) | Out-Null
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
            -DocumentationUrl $domainDoc -SourceFile $src
    }
    if ($configErrors.Count -gt 0) {
        $errorSrc = Write-Evidence -BaseName 'federation_configuration_errors' -Rows $configErrors.ToArray() -Title 'Federation Configuration Collection Gaps'
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Federation' `
            -Title ("Federation configuration is unknown for {0} federated domain(s)" -f $configErrors.Count) `
            -Evidence 'The domain is marked Federated, but its federation configuration could not be read or was absent. This is unknown coverage, not a healthy result.' `
            -WhyItMatters 'Without the federation configuration, signing-certificate expiry, issuer, protocol, and MFA-claim behavior cannot be validated.' `
            -RecommendedAction 'Grant Domain-InternalFederation.Read.All, confirm a supported reader role, and repair any federated domain that has no configuration' `
            -DocumentationUrl $doc -SourceFile $errorSrc -ResultRows $configErrors.ToArray() -RuleId 'federation-config-unknown' -CoverageGap
    }

    $unverifiedFederated = @($rows | Where-Object { $_.AuthenticationType -eq 'Federated' -and $_.IsVerified -ne $true })
    if ($unverifiedFederated.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Federation' `
            -Title ("{0} federated domain(s) are not verified" -f $unverifiedFederated.Count) `
            -Evidence 'AuthenticationType=Federated while IsVerified is not true.' `
            -WhyItMatters 'An unverified or transitional federated namespace can indicate incomplete domain/federation lifecycle state and unreliable sign-in routing.' `
            -RecommendedAction 'Validate DNS ownership and federation intent, then verify or remove obsolete domains through the approved domain lifecycle process' `
            -DocumentationUrl $domainDoc -SourceFile $src -ResultRows $unverifiedFederated -RuleId 'federated-domain-unverified'
    }

    $now = [datetimeoffset]::UtcNow
    $expired = @($rows | Where-Object { $_.ConfigRead -eq 'Complete' -and $_.SigningNotAfter -and (ConvertTo-EAGovDateTime $_.SigningNotAfter) -lt $now })
    if ($expired.Count -gt 0) {
        Add-EAGovFinding -Severity 'Critical' -CheckId $checkId -Category 'Federation' `
            -Title ("{0} federation signing certificate(s) are expired" -f $expired.Count) `
            -Evidence 'The parsed signing-certificate NotAfter timestamp is earlier than the audit time.' `
            -WhyItMatters 'Expired federation signing certificates can disrupt authentication and may indicate an unmanaged federation trust.' `
            -RecommendedAction 'Validate the identity-provider rollover immediately, update metadata/certificates through the approved federation process, and test sign-in' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $expired -RuleId 'federation-signing-cert-expired'
    }
    $expiring30 = @($rows | Where-Object {
        $date = ConvertTo-EAGovDateTime $_.SigningNotAfter
        $date -and $date -ge $now -and $date -le $now.AddDays(30)
    })
    if ($expiring30.Count -gt 0) {
        $noReadyNext = @($expiring30 | Where-Object { -not $_.NextSigningNotAfter -or (ConvertTo-EAGovDateTime $_.NextSigningNotAfter) -le $now })
        $severity = if ($noReadyNext.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Federation' `
            -Title ("{0} federation signing certificate(s) expire within 30 days" -f $expiring30.Count) `
            -Evidence ("{0} do not have a parsed, currently valid next signing certificate." -f $noReadyNext.Count) `
            -WhyItMatters 'Federation certificate rollover failures can cause tenant-wide authentication outages or emergency trust changes.' `
            -RecommendedAction 'Complete and test certificate rollover before expiry; confirm metadata-based automatic rollover where supported' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $expiring30 -RuleId 'federation-signing-cert-expiring-30d'
    }
    $expiring90 = @($rows | Where-Object {
        $date = ConvertTo-EAGovDateTime $_.SigningNotAfter
        $date -and $date -gt $now.AddDays(30) -and $date -le $now.AddDays(90)
    })
    if ($expiring90.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Federation' `
            -Title ("{0} federation signing certificate(s) expire within 90 days" -f $expiring90.Count) `
            -Evidence 'Parsed certificate NotAfter is between 31 and 90 days from the audit time.' `
            -WhyItMatters 'Federation rollover needs planning, change control, and sign-in testing before the current certificate expires.' `
            -RecommendedAction 'Schedule rollover, validate the next certificate and metadata endpoint, and monitor the federation update status' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $expiring90 -RuleId 'federation-signing-cert-expiring-90d'
    }

    $unparsed = @($rows | Where-Object { $_.ConfigRead -eq 'Complete' -and $_.SigningCertificateParsed -ne $true })
    if ($unparsed.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Federation' `
            -Title ("Signing-certificate validity is unknown for {0} federation configuration(s)" -f $unparsed.Count) `
            -Evidence 'The signingCertificate property was absent or could not be parsed as a base64 DER X.509 certificate. This is not a healthy result.' `
            -WhyItMatters 'Certificate expiry cannot be monitored when the current signing certificate is missing or malformed.' `
            -RecommendedAction 'Validate the federation trust and signing certificate at the identity provider and in Entra, then rerun the audit' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $unparsed -RuleId 'federation-signing-cert-unreadable' -CoverageGap
    }

    $multipleConfigs = @($rows | Where-Object { $_.ConfigCount -gt 1 })
    if ($multipleConfigs.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Federation' `
            -Title 'A federated domain returned multiple federation configurations' `
            -Evidence 'The documented API normally returns one configuration per domain; multiple records require validation.' `
            -WhyItMatters 'Unexpected duplicate trust data can make issuer, endpoint, and certificate assurance ambiguous.' `
            -RecommendedAction 'Validate the domain federation state with Microsoft support or the approved federation tooling before changing it' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $multipleConfigs -RuleId 'federation-multiple-configs'
    }

    $manualRolloverRisk = @($rows | Where-Object {
        $_.ConfigRead -eq 'Complete' -and [string]::IsNullOrWhiteSpace([string]$_.MetadataExchangeUri) -and
        $_.SigningNotAfter -and (ConvertTo-EAGovDateTime $_.SigningNotAfter) -le $now.AddDays(90)
    })
    if ($manualRolloverRisk.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Federation' `
            -Title ("{0} federation trust(s) near certificate expiry have no metadata exchange URI" -f $manualRolloverRisk.Count) `
            -Evidence 'MetadataExchangeUri is empty and the current signing certificate expires within 90 days.' `
            -WhyItMatters 'Without a working metadata exchange endpoint, certificate rollover is more likely to require a manual, outage-prone trust update.' `
            -RecommendedAction 'Establish and validate metadata-based rollover or complete a controlled manual rollover well before expiry' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $manualRolloverRisk -RuleId 'federation-no-metadata-near-expiry'
    }

    # federatedIdpMfaBehavior supersedes SupportsMfa. Microsoft explicitly
    # documents that SupportsMfa is ignored once the newer property is set, so
    # differing values are not a conflict and must not generate a finding.

    $unsignedSaml = @($rows | Where-Object {
        [string]$_.PreferredAuthenticationProtocol -match '(?i)saml' -and $_.SignedAuthenticationRequestRequired -eq $false
    })
    if ($unsignedSaml.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Federation' `
            -Title ("{0} SAML federation trust(s) do not require signed authentication requests" -f $unsignedSaml.Count) `
            -Evidence 'The preferred protocol is SAML and isSignedAuthenticationRequestRequired=false.' `
            -WhyItMatters 'Signed authentication requests provide stronger request integrity when the federated identity provider supports and validates them.' `
            -RecommendedAction 'Confirm IdP support and require signed authentication requests where compatible; document any interoperability exception' `
            -DocumentationUrl $doc -SourceFile $src -ResultRows $unsignedSaml -RuleId 'federation-unsigned-saml-requests'
    }

    # Hybrid synchronization health affects federation recovery and identity
    # continuity even though it is stored outside the domain-federation object.
    $syncDoc = 'https://learn.microsoft.com/graph/api/resources/onpremisesdirectorysynchronization?view=graph-rest-1.0'
    $orgResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,onPremisesSyncEnabled,onPremisesLastSyncDateTime'
    if (-not $orgResult.Success -or $orgResult.Truncated) {
        $reason = if ($orgResult.Success) { 'organization pagination limit reached' } else { [string]$orgResult.Error.Exception.Message }
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Federation' -DataSource 'Hybrid directory synchronization status' `
            -Reason $reason -RequiredScope 'Organization.Read.All' -DocumentationUrl $syncDoc -SourceFile $src
    } else {
        $hybridOrg = @($orgResult.Rows | Where-Object { (Get-EAGovProperty $_ 'onPremisesSyncEnabled') -eq $true } | Select-Object -First 1)
        if ($hybridOrg.Count -gt 0) {
            $lastSync = ConvertTo-EAGovDateTime (Get-EAGovProperty $hybridOrg[0] 'onPremisesLastSyncDateTime')
            if (-not $lastSync) {
                Add-EAGovCoverageFinding -CheckId $checkId -Category 'Federation' -DataSource 'Last on-premises directory synchronization time' `
                    -Reason 'onPremisesSyncEnabled=true but onPremisesLastSyncDateTime is absent or invalid.' `
                    -RequiredScope 'Organization.Read.All' -DocumentationUrl $syncDoc -SourceFile $src
            } elseif ($lastSync -lt $now.AddHours(-24)) {
                Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Federation' `
                    -Title 'On-premises directory synchronization is older than 24 hours' `
                    -Evidence ("Last tenant sync={0:u}; age hours={1}." -f $lastSync,[math]::Round(($now - $lastSync).TotalHours,1)) `
                    -WhyItMatters 'Stale synchronization delays account disablement, credential changes, group membership updates, and hybrid incident response.' `
                    -RecommendedAction 'Investigate Microsoft Entra Connect or Cloud Sync service/agent health, connector errors, staging state, and export backlog' `
                    -DocumentationUrl $syncDoc -SourceFile $src -RuleId 'hybrid-directory-sync-stale'
            }

            $syncResult = Invoke-EAGovGraphObject -Uri 'https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization'
            if (-not $syncResult.Success) {
                Add-EAGovCoverageFinding -CheckId $checkId -Category 'Federation' -DataSource 'On-premises synchronization safeguards' `
                    -Reason ([string]$syncResult.Error.Exception.Message) -RequiredScope 'OnPremDirectorySynchronization.Read.All' `
                    -DocumentationUrl $syncDoc -SourceFile $src
            } else {
                $prevention = Get-EAGovProperty (Get-EAGovProperty $syncResult.Value 'configuration') 'accidentalDeletionPrevention'
                $preventionType = [string](Get-EAGovProperty $prevention 'synchronizationPreventionType')
                $threshold = Get-EAGovProperty $prevention 'alertThreshold'
                $syncRows = @([pscustomobject]@{
                    OnPremisesLastSyncDateTime=$lastSync
                    AccidentalDeletionPrevention=$preventionType
                    AccidentalDeletionAlertThreshold=$threshold
                    Features=ConvertTo-EAGovCompactJson (Get-EAGovProperty $syncResult.Value 'features')
                })
                $syncSrc = Write-Evidence -BaseName 'federation_hybrid_sync_health' -Rows $syncRows -Title 'Hybrid Directory Synchronization Health and Safeguards'
                if ([string]::IsNullOrWhiteSpace($preventionType)) {
                    Add-EAGovCoverageFinding -CheckId $checkId -Category 'Federation' -DataSource 'Accidental deletion prevention state' `
                        -Reason 'synchronizationPreventionType was absent.' -RequiredScope 'OnPremDirectorySynchronization.Read.All' `
                        -DocumentationUrl $syncDoc -SourceFile $syncSrc
                } elseif ($preventionType -match '^(disabled|unknownFutureValue)$') {
                    Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Federation' `
                        -Title 'Accidental deletion prevention is not enabled for directory synchronization' `
                        -Evidence ("synchronizationPreventionType={0}; alertThreshold={1}." -f $preventionType,$threshold) `
                        -WhyItMatters 'A bad scoping or source-directory change can otherwise export a large deletion set to Microsoft Entra ID without a configured stop threshold.' `
                        -RecommendedAction 'Enable count- or percentage-based accidental deletion prevention and test the operational alert/unblock process' `
                        -DocumentationUrl $syncDoc -SourceFile $syncSrc -RuleId 'hybrid-sync-accidental-delete-protection-disabled'
                }
            }
        }
    }

    if ($federatedDomains.Count -eq 0 -and -not $domainResult.Truncated) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Federation' `
            -Title 'No federated domains are configured' `
            -Evidence ("{0} domain(s) were read; all use managed or another non-federated authentication type." -f @($domainResult.Rows).Count) `
            -WhyItMatters 'With no federated domains, external federation signing-certificate and IdP endpoint risks are not applicable.' `
            -RecommendedAction 'Continue monitoring domain authentication-type changes and protect domain/federation administration roles' `
            -DocumentationUrl $domainDoc -SourceFile $src -ResultRows $rows.ToArray() -RuleId 'federation-none'
    } else {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Federation' `
            -Title 'Federation configuration inventory captured' `
            -Evidence ("Federated domains={0}; configuration read failures={1}; certificate metadata is exported without certificate bodies." -f $federatedDomains.Count,$configErrors.Count) `
            -WhyItMatters 'Issuer, endpoint, certificate, protocol, and MFA-claim settings collectively determine federation availability and trust behavior.' `
            -RecommendedAction 'Monitor certificate rollover and restrict/alert on federation configuration changes' `
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
        @{ Result=$catalogResult; Name='Access package catalogs'; File=$catalogSrc },
        @{ Result=$packageResult; Name='Access packages'; File=$packageSrc },
        @{ Result=$policyResult; Name='Access package assignment policies'; File=$policySrc }
    )) {
        if (-not $entry.Result.Success) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource $entry.Name `
                -Reason ([string]$entry.Result.Error.Exception.Message) -RequiredScope 'EntitlementManagement.Read.All' `
                -DocumentationUrl $entitlementDoc -SourceFile $entry.File
        } elseif ($entry.Result.Truncated) {
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource ($entry.Name + ' pagination') `
                -Reason "pagination exceeded $($entry.Result.Pages) pages." -RequiredScope 'EntitlementManagement.Read.All' `
                -DocumentationUrl $entitlementDoc -SourceFile $entry.File
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
                -Title ("{0} broad access-package request policy/policies do not require approval" -f $broadNoApproval.Count) `
                -Evidence ("Self-service add is accepted for a broad target scope without add approval; {0} policy/policies include external/connected-organization targets." -f $external.Count) `
                -WhyItMatters 'Broad self-service assignment without approval can grant governed resources without a resource owner or sponsor validating business need.' `
                -RecommendedAction 'Require appropriate approval for broad requestor scopes, use least-privilege packages, and test reviewer/fallback reviewer resolution' `
                -DocumentationUrl $entitlementDoc -SourceFile $policySrc -ResultRows $broadNoApproval -RuleId 'access-package-broad-no-approval'
        }

        $noExpiration = @($policyRows | Where-Object { [string]$_.ExpirationType -ieq 'noExpiration' })
        if ($noExpiration.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title ("{0} access-package assignment policy/policies allow no-expiration access" -f $noExpiration.Count) `
                -Evidence 'Expiration.Type=noExpiration. Access reviews can be compensating evidence but do not make indefinite assignment automatically low risk.' `
                -WhyItMatters 'Indefinite assignments can survive job, project, sponsor, and partner lifecycle changes.' `
                -RecommendedAction 'Use time-bound assignments appropriate to the business process, with renewal approval and recurring access review where needed' `
                -DocumentationUrl $entitlementDoc -SourceFile $policySrc -ResultRows $noExpiration -RuleId 'access-package-no-expiration'
        }

        $externalNoReview = @($policyRows | Where-Object {
            [string]$_.AllowedTargetScope -match '(?i)(external|connectedorganization)' -and $_.AccessReviewConfigured -ne $true
        })
        if ($externalNoReview.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title ("{0} external access-package policy/policies have no embedded access review" -f $externalNoReview.Count) `
                -Evidence 'The target scope includes external/connected-organization users and reviewSettings.isEnabled is not true.' `
                -WhyItMatters 'External assignments need periodic recertification because partner employment and sponsor relationships change outside the tenant.' `
                -RecommendedAction 'Add recurring review with sponsor/resource-owner reviewers, fallback reviewers, and automatic application or a monitored manual process' `
                -DocumentationUrl $entitlementDoc -SourceFile $policySrc -ResultRows $externalNoReview -RuleId 'access-package-external-no-review'
        }


        $reviewKeepsAccess = @($policyRows | Where-Object {
            $_.AccessReviewConfigured -eq $true -and [string]$_.AccessReviewExpirationBehavior -ieq 'keepAccess'
        })
        if ($reviewKeepsAccess.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title ("{0} access-package review policy/policies keep access when a review is unanswered" -f $reviewKeepsAccess.Count) `
                -Evidence 'reviewSettings.isEnabled=true and expirationBehavior=keepAccess.' `
                -WhyItMatters 'An unanswered review preserves access, weakening removal when reviewers or sponsors are unavailable.' `
                -RecommendedAction 'Use removeAccess or an appropriate recommendation behavior, and configure accountable primary and fallback reviewers' `
                -DocumentationUrl $entitlementDoc -SourceFile $policySrc -ResultRows $reviewKeepsAccess -RuleId 'access-package-review-keeps-access'
        }

        $reviewNoFallback = @($policyRows | Where-Object {
            $_.AccessReviewConfigured -eq $true -and $_.AccessReviewPrimaryReviewerCount -gt 0 -and $_.AccessReviewFallbackReviewerCount -eq 0
        })
        if ($reviewNoFallback.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
                -Title ("{0} access-package review policy/policies have no fallback reviewer" -f $reviewNoFallback.Count) `
                -Evidence 'Access reviews are enabled and primary reviewers exist, but fallbackReviewers is empty.' `
                -WhyItMatters 'Reviews can stall or default when every primary reviewer is unavailable or no longer resolves.' `
                -RecommendedAction 'Configure a governed fallback reviewer population and test reviewer resolution' `
                -DocumentationUrl $entitlementDoc -SourceFile $policySrc -ResultRows $reviewNoFallback -RuleId 'access-package-review-no-fallback'
        }
    }

    if ($packageResult.Success -and $policyResult.Success -and -not $packageResult.Truncated -and -not $policyResult.Truncated) {
        $packagesWithoutPolicies = @($packageRows | Where-Object { $_.AssignmentPolicyCount -eq 0 })
        if ($packagesWithoutPolicies.Count -gt 0) {
            Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
                -Title ("{0} access package(s) have no assignment policy" -f $packagesWithoutPolicies.Count) `
                -Evidence 'The packages exist but have no returned assignment policy. They are not assumed to grant access.' `
                -WhyItMatters 'Unused packages add governance inventory and can indicate abandoned design work, but do not by themselves create assignments.' `
                -RecommendedAction 'Confirm whether each package is intentionally staged; retire obsolete packages through normal change control' `
                -DocumentationUrl $entitlementDoc -SourceFile $packageSrc -ResultRows $packagesWithoutPolicies -RuleId 'access-packages-no-policy'
        }
    }

    # ------------------------- Lifecycle Workflows -------------------------
    $workflowResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows?$select=id,displayName,description,category,isEnabled,isSchedulingEnabled,createdDateTime,lastModifiedDateTime,executionConditions&$top=999'
    $workflowRows = @(if ($workflowResult.Success) {
        @($workflowResult.Rows | ForEach-Object {
            [pscustomobject]@{
                Id=Get-EAGovProperty $_ 'id'; DisplayName=Get-EAGovProperty $_ 'displayName'; Description=Get-EAGovProperty $_ 'description'
                Category=Get-EAGovProperty $_ 'category'; IsEnabled=Get-EAGovProperty $_ 'isEnabled'; IsSchedulingEnabled=Get-EAGovProperty $_ 'isSchedulingEnabled'
                CreatedDateTime=Get-EAGovProperty $_ 'createdDateTime'; LastModifiedDateTime=Get-EAGovProperty $_ 'lastModifiedDateTime'
                ExecutionConditions=ConvertTo-EAGovCompactJson (Get-EAGovProperty $_ 'executionConditions')
            }
        })
    } else { @() })
    $workflowSrc = Write-Evidence -BaseName 'governance_lifecycle_workflows' -Rows $workflowRows -Title 'Identity Governance - Lifecycle Workflows'
    if (-not $workflowResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Lifecycle workflows' `
            -Reason ([string]$workflowResult.Error.Exception.Message) -RequiredScope 'LifecycleWorkflows.Read.All' `
            -DocumentationUrl $workflowDoc -SourceFile $workflowSrc
    } elseif ($workflowResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Lifecycle workflow pagination' `
            -Reason "pagination exceeded $($workflowResult.Pages) pages." -RequiredScope 'LifecycleWorkflows.Read.All' `
            -DocumentationUrl $workflowDoc -SourceFile $workflowSrc
    } elseif ($workflowRows.Count -eq 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'No Lifecycle Workflows are configured' `
            -Evidence 'The workflow API returned zero records. Feature absence is context, not automatically a control failure.' `
            -WhyItMatters 'Lifecycle Workflows can automate joiner, mover, and leaver tasks, but organizations may use another governed identity lifecycle system.' `
            -RecommendedAction 'Document the authoritative joiner/mover/leaver process and consider Lifecycle Workflows where it improves timely deprovisioning' `
            -DocumentationUrl $workflowDoc -SourceFile $workflowSrc -RuleId 'lifecycle-workflows-none'
    } else {
        $disabledLeavers = @($workflowRows | Where-Object {
            [string]$_.Category -ieq 'leaver' -and ($_.IsEnabled -ne $true -or $_.IsSchedulingEnabled -ne $true)
        })
        if ($disabledLeavers.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title ("{0} configured leaver workflow(s) are disabled or not scheduled" -f $disabledLeavers.Count) `
                -Evidence 'The workflow category is leaver, but IsEnabled or IsSchedulingEnabled is not true.' `
                -WhyItMatters 'A configured but inactive leaver workflow can create false assurance while terminated-user cleanup tasks do not run.' `
                -RecommendedAction 'Validate execution conditions and task ownership, enable scheduling, and test the complete leaver path with a controlled account' `
                -DocumentationUrl $workflowDoc -SourceFile $workflowSrc -ResultRows $disabledLeavers -RuleId 'leaver-workflow-disabled'
        }
        $otherDisabled = @($workflowRows | Where-Object {
            [string]$_.Category -ine 'leaver' -and ($_.IsEnabled -ne $true -or $_.IsSchedulingEnabled -ne $true)
        })
        if ($otherDisabled.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
                -Title ("{0} lifecycle workflow(s) are disabled or not scheduled" -f $otherDisabled.Count) `
                -Evidence 'Configured workflows are not currently both enabled and scheduled.' `
                -WhyItMatters 'Disabled workflows can be intentional drafts, but stale workflow definitions create operational ambiguity.' `
                -RecommendedAction 'Document staged workflows and retire obsolete definitions; enable and test workflows intended for production' `
                -DocumentationUrl $workflowDoc -SourceFile $workflowSrc -ResultRows $otherDisabled -RuleId 'lifecycle-workflow-disabled'
        }
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
            -Reason (([string]$agreementResult.Error.Exception.Message) + $appOnlyNote) -RequiredScope 'Agreement.Read.All (delegated) and a supported reader role' `
            -DocumentationUrl $agreementDoc -SourceFile $agreementSrc
    } elseif ($agreementResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Terms of Use agreement pagination' `
            -Reason "pagination exceeded $($agreementResult.Pages) pages." -RequiredScope 'Agreement.Read.All' `
            -DocumentationUrl $agreementDoc -SourceFile $agreementSrc
    } elseif ($agreementRows.Count -eq 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'No Terms of Use agreements are configured' `
            -Evidence 'The agreement API returned zero records. Absence is context because not every tenant requires a Terms of Use control.' `
            -WhyItMatters 'Terms of Use can record explicit acceptance for populations such as guests or regulated-resource users when policy requires it.' `
            -RecommendedAction 'Document whether legal/compliance policy requires Terms of Use; configure and enforce it through Conditional Access when required' `
            -DocumentationUrl $agreementDoc -SourceFile $agreementSrc -RuleId 'terms-of-use-none'
    } else {
        $notViewed = @($agreementRows | Where-Object { $_.IsViewingBeforeAcceptanceRequired -eq $false })
        if ($notViewed.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
                -Title ("{0} Terms of Use agreement(s) do not require viewing before acceptance" -f $notViewed.Count) `
                -Evidence 'isViewingBeforeAcceptanceRequired=false.' `
                -WhyItMatters 'Acceptance without opening the agreement weakens evidence that users were presented with the terms.' `
                -RecommendedAction 'Require viewing before acceptance where legal/compliance requirements support it' `
                -DocumentationUrl $agreementDoc -SourceFile $agreementSrc -ResultRows $notViewed -RuleId 'terms-not-viewed-before-acceptance'
        }
        $noReaccept = @($agreementRows | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.UserReacceptRequiredFrequency) })
        if ($noReaccept.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
                -Title ("{0} Terms of Use agreement(s) do not require periodic reacceptance" -f $noReaccept.Count) `
                -Evidence 'userReacceptRequiredFrequency is empty.' `
                -WhyItMatters 'Long-lived access can outlast the user awareness or the policy version originally accepted.' `
                -RecommendedAction 'Set a risk-appropriate reacceptance frequency when policy requires periodic acknowledgement; document permanent acceptance where intentional' `
                -DocumentationUrl $agreementDoc -SourceFile $agreementSrc -ResultRows $noReaccept -RuleId 'terms-no-reacceptance'
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
                $otherGrantCount = @(Get-EAGovProperty $grant 'builtInControls').Count +
                    @(Get-EAGovProperty $grant 'customAuthenticationFactors').Count
                if ($null -ne (Get-EAGovProperty $grant 'authenticationStrength')) { $otherGrantCount++ }
                if ($operator -ieq 'OR' -and $otherGrantCount -gt 0) { continue }

                # Don't call an enabled but empty/fully excluded user scope an
                # enforcement path. This is intentionally conservative; complex
                # scopes still remain visible in the CA evidence from the CA check.
                $users = Get-EAGovProperty (Get-EAGovProperty $policy 'conditions') 'users'
                $includeUsers = @(Get-EAGovProperty $users 'includeUsers')
                $includeGroups = @(Get-EAGovProperty $users 'includeGroups')
                $includeRoles = @(Get-EAGovProperty $users 'includeRoles')
                $hasIncludedPopulation = $includeUsers.Count -gt 0 -or $includeGroups.Count -gt 0 -or $includeRoles.Count -gt 0
                if (-not $hasIncludedPopulation) { continue }
                $excludeUsers = @(Get-EAGovProperty $users 'excludeUsers')
                if ($includeUsers -contains 'All' -and $excludeUsers -contains 'All' -and $includeGroups.Count -eq 0 -and $includeRoles.Count -eq 0) { continue }

                foreach ($id in $termIds) { if ($id) { [void]$enforcedIds.Add([string]$id) } }
            }
            $unenforced = @($agreementRows | Where-Object { -not $enforcedIds.Contains([string]$_.Id) })
            if ($unenforced.Count -gt 0) {
                Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                    -Title ("{0} Terms of Use agreement(s) are not referenced by enabled Conditional Access" -f $unenforced.Count) `
                    -Evidence 'No enabled Conditional Access policy grantControls.termsOfUse list contained these agreement IDs.' `
                    -WhyItMatters 'An agreement object alone does not prompt users or enforce acceptance.' `
                    -RecommendedAction 'Reference each required agreement from an enabled, correctly scoped Conditional Access policy and validate exclusions' `
                    -DocumentationUrl $agreementDoc -SourceFile $agreementSrc -ResultRows $unenforced -RuleId 'terms-of-use-not-enforced'
            }
        } else {
            $reason = if ($caResult.Success) { 'pagination limit reached' } else { [string]$caResult.Error.Exception.Message }
            Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Terms of Use Conditional Access enforcement' `
                -Reason $reason -RequiredScope 'Policy.Read.All' -DocumentationUrl $agreementDoc -SourceFile $agreementSrc
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
            -DocumentationUrl $pimDoc -SourceFile $pimSrc
    } elseif ($roleGroupResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Role-assignable group pagination for PIM coverage' `
            -Reason "pagination exceeded $($roleGroupResult.Pages) pages." -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $pimDoc -SourceFile $pimSrc
    }
    if ($pimErrors.Count -gt 0) {
        $pimErrorSrc = Write-Evidence -BaseName 'governance_pim_for_groups_errors' -Rows $pimErrors.ToArray() -Title 'PIM for Groups Collection Gaps'
        $scopeList = @($pimErrors | ForEach-Object { $_.RequiredScope } | Select-Object -Unique) -join ', '
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'PIM for Groups policy and schedule coverage' `
            -Reason ("{0} group/data-source read(s) failed or truncated." -f $pimErrors.Count) -RequiredScope $scopeList `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimErrorSrc
    }

    $standingPrivileged = @($pimRows | Where-Object { $_.AssignmentKnown -and $_.PermanentAssignmentCount -gt 0 })
    if ($standingPrivileged.Count -gt 0) {
        $ownerStanding = @($standingPrivileged | Where-Object { $_.PermanentOwnerCount -gt 0 })
        $severity = if ($ownerStanding.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} role-assignable group(s) have permanent PIM assignment instances" -f $standingPrivileged.Count) `
            -Evidence ("EndDateTime is absent on one or more assignment instances; {0} group(s) include permanent owner assignments." -f $ownerStanding.Count) `
            -WhyItMatters 'Permanent membership or ownership in a role-assignable group creates standing privileged access instead of just-in-time activation.' `
            -RecommendedAction 'Convert standing assignments to eligibility where operationally possible, and require MFA/approval/justification through PIM for Groups policy' `
            -DocumentationUrl $pimDoc -SourceFile $pimSrc -ResultRows $standingPrivileged -RuleId 'pim-group-permanent-assignments'
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
            -Title ("{0} role-assignable group(s) contain direct principals without matching PIM schedules" -f $unscheduledDirect.Count) `
            -Evidence ("Per-principal comparison found {0} direct member(s) and {1} direct owner(s) whose ids occur in neither an eligibility nor assignment schedule instance for the corresponding accessId." -f $unscheduledMemberTotal,$unscheduledOwnerTotal) `
            -WhyItMatters 'A scheduled principal elsewhere in the same group does not protect a different direct member or owner; unmatched principals can retain standing privileged group access.' `
            -RecommendedAction 'Remove unapproved direct assignments or represent every required privileged member/owner through PIM for Groups, then validate each principal activation path' `
            -DocumentationUrl $pimDoc -SourceFile $pimSrc -ResultRows $unscheduledDirect -RuleId 'role-groups-direct-principals-without-pim'
    }

    $pimWithoutPolicies = @($pimRows | Where-Object {
        $_.EligibilityKnown -and $_.AssignmentKnown -and ($_.EligibilityInstanceCount -gt 0 -or $_.AssignmentInstanceCount -gt 0) -and
        $_.PoliciesKnown -and (-not $_.HasMemberPolicy -or -not $_.HasOwnerPolicy)
    })
    if ($pimWithoutPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} PIM-managed group(s) lack complete member/owner policy assignment evidence" -f $pimWithoutPolicies.Count) `
            -Evidence 'PIM schedule instances exist, but fewer than two role-management policy assignments (member and owner) were returned.' `
            -WhyItMatters 'Without readable member and owner policies, activation requirements and assignment lifetime controls cannot be assured.' `
            -RecommendedAction 'Validate both member and owner PIM for Groups policy assignments and their activation/expiration rules' `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimSrc -ResultRows $pimWithoutPolicies -RuleId 'pim-group-policy-missing'
    }

    $unknownPimPolicyRules = @($pimPolicyRows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.UnknownFields) })
    if ($unknownPimPolicyRules.Count -gt 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'PIM for Groups policy-rule coverage is incomplete' `
            -Evidence ("{0} member/owner policy assignment(s) omitted or returned unreadable activation/expiration rule fields. This is unknown, not compliant." -f $unknownPimPolicyRules.Count) `
            -WhyItMatters 'The existence of a policy assignment does not establish MFA, justification, approval, activation duration, or assignment-expiration requirements.' `
            -RecommendedAction 'Confirm RoleManagementPolicy.Read.AzureADGroup access, inspect the affected expanded policy rules, and rerun the audit' `
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
            -Title ("{0} PIM for Groups policy assignment(s) do not require strong authentication on activation" -f $weakActivationPolicies.Count) `
            -Evidence ("MultiFactorAuthentication is absent from enabledRules and no enabled authentication-context rule was returned; affected owner policies={0}." -f $weakOwnerPolicies.Count) `
            -WhyItMatters 'A compromised session or password can activate privileged group membership or ownership without a fresh strong-authentication control.' `
            -RecommendedAction 'Require MFA on activation, or use an authentication context protected by correctly scoped Conditional Access and validate that enforcement end to end' `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimPolicySrc -ResultRows $weakActivationPolicies -RuleId 'pim-group-activation-no-strong-auth'
    }

    $authContextPolicies = @($pimPolicyRows | Where-Object { $_.AuthenticationContextEnabled -eq $true })
    if ($authContextPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'PIM for Groups authentication-context enforcement requires Conditional Access validation' `
            -Evidence ("{0} policy assignment(s) use an authentication context. The PIM rule alone does not prove that the referenced context is available and protected by enabled Conditional Access with mandatory MFA/authentication strength." -f $authContextPolicies.Count) `
            -WhyItMatters 'A missing, disabled, narrowly scoped, or bypassable Conditional Access policy can make an authentication-context activation rule ineffective.' `
            -RecommendedAction 'Verify every claimValue against an available authentication context and an enabled Conditional Access policy whose grant cannot be satisfied without MFA/authentication strength' `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimPolicySrc -ResultRows $authContextPolicies `
            -RuleId 'pim-group-auth-context-validation' -CoverageGap
    }

    $noJustificationPolicies = @($pimPolicyRows | Where-Object { $_.JustificationRequired -eq $false })
    if ($noJustificationPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} PIM for Groups policy assignment(s) do not require activation justification" -f $noJustificationPolicies.Count) `
            -Evidence 'Justification is absent from the policy enabledRules list.' `
            -WhyItMatters 'Unjustified privileged activations are harder to review, correlate to work, and challenge during incident response.' `
            -RecommendedAction 'Require meaningful activation justification for privileged group member and owner policies' `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimPolicySrc -ResultRows $noJustificationPolicies -RuleId 'pim-group-activation-no-justification'
    }

    $ownerNoApprovalPolicies = @($pimPolicyRows | Where-Object { [string]$_.PolicyKind -ieq 'owner' -and $_.ApprovalRequired -eq $false })
    if ($ownerNoApprovalPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} PIM for Groups owner policy assignment(s) allow activation without approval" -f $ownerNoApprovalPolicies.Count) `
            -Evidence 'The owner policy approval rule has isApprovalRequired=false.' `
            -WhyItMatters 'Group owners can change privileged membership; approval provides separation of duties for that high-impact activation.' `
            -RecommendedAction 'Require approval for owner activation on groups that convey privileged access, with resilient approver coverage' `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimPolicySrc -ResultRows $ownerNoApprovalPolicies -RuleId 'pim-group-owner-activation-no-approval'
    }

    $longActivationPolicies = @($pimPolicyRows | Where-Object { $null -ne $_.MaximumActivationHours -and $_.MaximumActivationHours -gt 8 })
    if ($longActivationPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} PIM for Groups policy assignment(s) allow activation longer than eight hours" -f $longActivationPolicies.Count) `
            -Evidence 'maximumDuration parsed to more than eight hours. Eight hours is an audit review threshold, not a universal compliance boundary.' `
            -WhyItMatters 'Long activation windows increase the time during which a stolen session or unattended workstation retains privileged group access.' `
            -RecommendedAction 'Reduce maximum activation duration to the shortest operationally workable window and document justified exceptions' `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimPolicySrc -ResultRows $longActivationPolicies -RuleId 'pim-group-activation-duration-long'
    }

    $permanentActivePolicies = @($pimPolicyRows | Where-Object { $_.PermanentActiveAllowed -eq $true })
    if ($permanentActivePolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} PIM for Groups policy assignment(s) permit non-expiring active assignments" -f $permanentActivePolicies.Count) `
            -Evidence 'The active-assignment expiration rule has isExpirationRequired=false.' `
            -WhyItMatters 'Even if no permanent instance exists today, the policy permits creation of standing privileged group access later.' `
            -RecommendedAction 'Require expiration for active member and owner assignments and review existing permanent instances' `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimPolicySrc -ResultRows $permanentActivePolicies -RuleId 'pim-group-policy-allows-permanent-active'
    }

    $permanentEligiblePolicies = @($pimPolicyRows | Where-Object { $_.PermanentEligibleAllowed -eq $true })
    if ($permanentEligiblePolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} PIM for Groups policy assignment(s) permit non-expiring eligibility" -f $permanentEligiblePolicies.Count) `
            -Evidence 'The eligible-assignment expiration rule has isExpirationRequired=false.' `
            -WhyItMatters 'Permanent eligibility can outlast the business need unless periodic access reviews and ownership processes independently remove it.' `
            -RecommendedAction 'Require eligibility expiration or document equivalent recurring recertification with accountable owners' `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimPolicySrc -ResultRows $permanentEligiblePolicies -RuleId 'pim-group-policy-allows-permanent-eligibility'
    }

    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
        -Title 'Identity governance feature inventory captured' `
        -Evidence ("Catalogs={0}; access packages={1}; assignment policies={2}; lifecycle workflows={3}; Terms of Use agreements={4}; role-assignable groups assessed for PIM={5}." -f `
            $catalogRows.Count,$packageRows.Count,$policyRows.Count,$workflowRows.Count,$agreementRows.Count,$pimRows.Count) `
        -WhyItMatters 'Entitlement management, automated lifecycle tasks, legal acknowledgement, and PIM for Groups address different stages of access creation, use, certification, and removal.' `
        -RecommendedAction 'Map the available features to the organization identity lifecycle and document compensating controls for intentionally unused features' `
        -DocumentationUrl $entitlementDoc -SourceFile $packageSrc -ResultRows $packageRows -RuleId 'identity-governance-inventory'
}
