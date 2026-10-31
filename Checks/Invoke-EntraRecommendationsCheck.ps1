<#
Microsoft Entra Recommendations. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

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
            -ObjectType 'recommendation' -ObjectId $id -ResultRows @($rows | Where-Object { $_.Id -eq $id }) `
            -AffectedObjectIds @($id) -AffectedObjectType 'recommendation' -AffectedCount 1
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
