<#
Access Review Governance. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

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
    $limits = Get-EAGovAssessmentLimits
    $rows = New-Object System.Collections.Generic.List[object]
    $overdue = New-Object System.Collections.Generic.List[object]
    $partialInstances = New-Object System.Collections.Generic.List[object]
    $settingGaps = New-Object System.Collections.Generic.List[object]
    $reviewerRows = New-Object System.Collections.Generic.List[object]
    $decisionRows = New-Object System.Collections.Generic.List[object]
    $decisionGaps = New-Object System.Collections.Generic.List[object]
    $decisionInstancesRead = 0
    $decisionInstancesSkipped = 0
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
        foreach ($reviewer in @(Get-EAGovReviewerAssessment -Definition $definition)) {
            $reviewerRows.Add([pscustomobject]@{
                DefinitionId=$id; DisplayName=Get-EAGovProperty $definition 'displayName'; Category=$category
                StageId=$reviewer.StageId; ReviewersKnown=$reviewer.ReviewersKnown; ReviewerCount=$reviewer.ReviewerCount
                DependsOn=$reviewer.DependsOn; DecisionsThatWillMoveToNextStage=$reviewer.DecisionsThatWillMoveToNextStage
                SelfReview=$reviewer.SelfReview; DynamicReviewers=$reviewer.DynamicReviewers
                FallbackKnown=$reviewer.FallbackKnown; FallbackReviewerCount=$reviewer.FallbackReviewerCount
                NeedsFallback=$reviewer.NeedsFallback; Reviewers=$reviewer.Reviewers; FallbackReviewers=$reviewer.FallbackReviewers
            }) | Out-Null
        }
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
            if (-not $end -and $status -match '^(Completed|AutoReviewed|Applied)$') {
                $decisionGaps.Add([pscustomobject]@{ DefinitionId=$id; InstanceId=Get-EAGovProperty $instance 'id'; Reason='Completed review omitted a readable endDateTime; removal SLA could not be assessed.' }) | Out-Null
            }
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
            # Completed means the review ended, not that access was removed. Read
            # only denied decisions in ended instances old enough to breach the SLA.
            if ($end -and $end.AddDays($limits.ReviewApplySlaDays) -lt $now -and $status -notmatch '^(Cancelled|Canceled)$') {
                if ($decisionInstancesRead -ge $limits.ReviewDecisionMaxInstances) { $decisionInstancesSkipped++; continue }
                $instanceId = [string](Get-EAGovProperty $instance 'id')
                if (-not $instanceId) {
                    $decisionGaps.Add([pscustomobject]@{ DefinitionId=$id; InstanceId=$null; Reason='Ended review instance omitted its id.' }) | Out-Null
                    continue
                }
                $decisionInstancesRead++
                $decisionResult = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/{0}/instances/{1}/decisions?`$filter=decision%20eq%20'Deny'&`$top=100" -f [uri]::EscapeDataString($id),[uri]::EscapeDataString($instanceId)) -MaxPages $limits.CollectionMaxPages
                if (-not $decisionResult.Success -or $decisionResult.Truncated) {
                    $reason = if ($decisionResult.Success) { 'Decision pagination safety limit reached.' } else { [string]$decisionResult.Error.Exception.Message }
                    $decisionGaps.Add([pscustomobject]@{ DefinitionId=$id; InstanceId=$instanceId; Reason=$reason }) | Out-Null
                }
                foreach ($decision in @($decisionResult.Rows)) {
                    $assessment = Get-EAGovReviewDecisionAssessment -Decision $decision -InstanceEnd $end -Now $now -SlaDays $limits.ReviewApplySlaDays
                    if (-not $assessment.IsDenied) { continue }
                    $principal = Get-EAGovProperty $decision 'principal'
                    $resource = Get-EAGovProperty $decision 'resource'
                    $decisionRows.Add([pscustomobject]@{
                        DefinitionId=$id; Definition=Get-EAGovProperty $definition 'displayName'; Category=$category
                        InstanceId=$instanceId; InstanceStatus=$status; EndDateTime=$end; DecisionId=Get-EAGovProperty $decision 'id'
                        PrincipalId=Get-EAGovProperty $principal 'id'; Principal=Get-EAGovProperty $principal 'displayName'
                        Resource=Get-EAGovProperty $resource 'displayName'; ApplyResult=$assessment.ApplyResult
                        ApplyDescription=Get-EAGovProperty $decision 'applyDescription'; DueDateTime=$assessment.DueDateTime
                        Overdue=$assessment.Overdue; Unknown=$assessment.Unknown
                    }) | Out-Null
                }
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
    $reviewerSrc = Write-Evidence -BaseName 'access_review_reviewers' -Rows $reviewerRows.ToArray() -Title 'Access Reviewers and Fallback Reviewers (including stages)'
    $decisionSrc = Write-Evidence -BaseName 'access_review_denied_decisions' -Rows $decisionRows.ToArray() -Title 'Access Review Denied Decisions and Removal Status' `
        -Notes @(("Removal SLA: {0} days after the later of review end and the decision. Up to {1} ended instances are inspected; applyResult is evidence from Graph, not a fresh effective-access test." -f $limits.ReviewApplySlaDays,$limits.ReviewDecisionMaxInstances))

    $reviewerGaps = @($reviewerRows | Where-Object { -not $_.ReviewersKnown -or ($_.DynamicReviewers -and -not $_.FallbackKnown) })
    if ($reviewerGaps.Count -gt 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'Some access-review reviewer settings could not be assessed' `
            -Evidence ("{0} definition/stage rows have unreadable reviewers or dynamic-reviewer fallback settings." -f $reviewerGaps.Count) `
            -WhyItMatters 'The audit cannot establish whether an independent reviewer can complete these reviews.' `
            -RecommendedAction "Inspect the listed review stages and reviewer settings in $reviewsPath, then rerun the audit" `
            -DocumentationUrl 'https://learn.microsoft.com/graph/accessreviews-reviewers-concept' -SourceFile $reviewerSrc -ResultRows $reviewerGaps -RuleId 'access-review-reviewers-unknown' -CoverageGap
    }
    # A self-review stage followed by an independent stage can be intentional.
    # Do not call it a confirmed independence failure without evaluating the
    # stage routing; export that routing and request verification instead.
    $mixedStageDefinitionIds = @{}
    foreach ($definitionStages in @($reviewerRows | Group-Object DefinitionId)) {
        $stageRows = @($definitionStages.Group)
        if ($stageRows.Count -gt 1 -and @($stageRows | Where-Object SelfReview).Count -gt 0 -and
            @($stageRows | Where-Object { -not $_.SelfReview -or -not $_.ReviewersKnown }).Count -gt 0) {
            $mixedStageDefinitionIds[$definitionStages.Name] = $true
        }
    }
    $selfReviews = @($reviewerRows | Where-Object { $_.ReviewersKnown -and $_.SelfReview -and $_.Category -in @('PrivilegedRoles','EnterpriseApps','Groups','Guests') -and -not $mixedStageDefinitionIds.ContainsKey([string]$_.DefinitionId) })
    if ($selfReviews.Count -gt 0) {
        $selfSeverity = if (@($selfReviews | Where-Object Category -eq 'PrivilegedRoles').Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $selfSeverity -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} sensitive-access review stages allow people to review their own access" -f $selfReviews.Count) `
            -Evidence 'The reviewer list is explicitly empty (self-review), or contains a self reviewer. Each row identifies the review stage; another stage may provide independent review.' `
            -WhyItMatters 'People may retain access they no longer need when nobody independent checks their decision.' `
            -RecommendedAction "Give sensitive access an independent reviewer in $reviewsPath; for multistage reviews, verify that every approval must pass an independent stage" `
            -DocumentationUrl 'https://learn.microsoft.com/graph/accessreviews-reviewers-concept' -SourceFile $reviewerSrc -ResultRows $selfReviews -RuleId 'access-review-sensitive-self-review' `
            -AffectedObjectIds @($selfReviews | ForEach-Object { $_.DefinitionId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'accessReviewScheduleDefinition' -AffectedCount @($selfReviews | ForEach-Object { $_.DefinitionId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'access review definitions with a sensitive self-review stage'
    }
    $mixedStages = @($reviewerRows | Where-Object { $mixedStageDefinitionIds.ContainsKey([string]$_.DefinitionId) -and $_.Category -in @('PrivilegedRoles','EnterpriseApps','Groups','Guests') })
    if ($mixedStages.Count -gt 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title 'Multistage access reviews need an independent-approval routing check' `
            -Evidence 'These reviews combine self-review with other stages. Stage dependencies and decisions forwarded to the next stage are recorded; the audit has not proved that every approval reaches an independent reviewer.' `
            -WhyItMatters 'A later independent stage can make self-review appropriate, but only if the routing prevents self-approved access from bypassing that stage.' `
            -RecommendedAction "Inspect the stage routing in $reviewsPath and verify that every access-retention decision reaches an independent reviewer" `
            -DocumentationUrl 'https://learn.microsoft.com/graph/api/resources/accessreviewstagesettings?view=graph-rest-1.0' `
            -SourceFile $reviewerSrc -ResultRows $mixedStages -RuleId 'access-review-independent-stage-routing' -CoverageGap `
            -VerificationType ManualTest -VerificationSteps 'Inspect the recorded stage dependencies and test an approval route with the review owner. Confirm that every access-retention decision reaches an independent reviewer; document the result even when this configuration reminder remains.'
    }
    $noFallback = @($reviewerRows | Where-Object { $_.ReviewersKnown -and $_.NeedsFallback })
    if ($noFallback.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} access-review stages have no fallback reviewer" -f $noFallback.Count) `
            -Evidence 'A manager, sponsor or resource-owner reviewer is configured, but the explicit fallbackReviewers list is empty.' `
            -WhyItMatters 'When the person has no manager or the resource has no owner, nobody may receive the review.' `
            -RecommendedAction "Add a fallback reviewer to each listed stage in $reviewsPath and confirm the primary reviewers still exist" `
            -DocumentationUrl 'https://learn.microsoft.com/graph/accessreviews-reviewers-concept' -SourceFile $reviewerSrc -ResultRows $noFallback -RuleId 'access-review-no-fallback-reviewer' `
            -AffectedObjectIds @($noFallback | ForEach-Object { $_.DefinitionId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'accessReviewScheduleDefinition' -AffectedCount @($noFallback | ForEach-Object { $_.DefinitionId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'access review definitions missing a fallback reviewer'
    }
    $unapplied = @($decisionRows | Where-Object Overdue)
    if ($unapplied.Count -gt 0) {
        $removalSeverity = if (@($unapplied | Where-Object Category -eq 'PrivilegedRoles').Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $removalSeverity -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} denied access decisions have not been applied within {1} days" -f $unapplied.Count,$limits.ReviewApplySlaDays) `
            -Evidence 'Graph reports New, AppliedWithUnknownFailure or ApplyNotSupported after the removal SLA. A completed review alone does not confirm access removal.' `
            -WhyItMatters 'People whose access was denied may still have access because removal was never applied or failed.' `
            -RecommendedAction "Open each review result in $reviewsPath, apply or repair the removals, and verify effective access; investigate ApplyNotSupported through the resource's own access-management process" `
            -DocumentationUrl 'https://learn.microsoft.com/graph/api/resources/accessreviewinstancedecisionitem?view=graph-rest-1.0' -SourceFile $decisionSrc -ResultRows $unapplied -RuleId 'access-review-denied-removal-overdue' `
            -AffectedObjectIds @($unapplied | ForEach-Object { $_.PrincipalId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'directoryObject' -AffectedCount @($unapplied | ForEach-Object { $_.PrincipalId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'identified principals with overdue denied-access removal' -VerificationSteps 'Confirm the denied access has been removed from the actual resource or role, and check the review decision apply result. Keep the review decision and removal evidence as the audit trail.'
    }
    $unknownDecisions = @($decisionRows | Where-Object Unknown)
    foreach ($unknownDecision in $unknownDecisions) {
        $decisionGaps.Add([pscustomobject]@{ DefinitionId=$unknownDecision.DefinitionId; InstanceId=$unknownDecision.InstanceId; Reason=("Decision {0} returned an unreadable apply result: {1}." -f $unknownDecision.DecisionId,$unknownDecision.ApplyResult) }) | Out-Null
    }
    if ($decisionGaps.Count -gt 0 -or $decisionInstancesSkipped -gt 0 -or $unknownDecisions.Count -gt 0) {
        $decisionGapSrc = Write-Evidence -BaseName 'access_review_decision_gaps' -Rows $decisionGaps.ToArray() -Title 'Access Review Decision Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Access review denied-decision application' `
            -Reason ("Read failures/partial instances={0}; instances beyond scan limit={1}; decisions with unreadable apply status={2}." -f $decisionGaps.Count,$decisionInstancesSkipped,$unknownDecisions.Count) `
            -RequiredScope 'AccessReview.Read.All' -DocumentationUrl 'https://learn.microsoft.com/graph/api/accessreviewinstance-list-decisions?view=graph-rest-1.0' `
            -SourceFile $decisionGapSrc -Subject 'some access-review removal results' -Impact 'Overdue access removals may be missing from this report.' `
            -RecommendedAction 'Review the affected results in the admin center; fix read failures or adjust the documented limits in Get-EAGovAssessmentLimits for a larger scan, then rerun'
    }

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
            -DocumentationUrl $guideDoc -SourceFile $src -ResultRows $defaultApprove -RuleId 'access-review-default-approve' `
            -AffectedObjectIds @($defaultApprove | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'accessReviewScheduleDefinition' -AffectedCount @($defaultApprove | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'access review definitions with the stated configuration issue'
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
            -DocumentationUrl $guideDoc -SourceFile $src -ResultRows $sensitiveNonRecurring -RuleId 'access-review-sensitive-not-recurring' `
            -AffectedObjectIds @($sensitiveNonRecurring | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'accessReviewScheduleDefinition' -AffectedCount @($sensitiveNonRecurring | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'access review definitions with the stated configuration issue'
    }

    $manualApply = @($rows | Where-Object { $_.AutoApplyDecisions -eq $false -and $_.Category -in @('PrivilegedRoles','Guests','InactiveUsers','EnterpriseApps') })
    if ($manualApply.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $manualApply.Count 'access review of sensitive access does not' 'access reviews of sensitive access do not') + ' remove denied access automatically') `
            -Evidence 'autoApplyDecisionsEnabled=false. Manual application can be intentional, but must be operationally tracked.' `
            -WhyItMatters "A reviewer's 'deny' does nothing until someone applies the results. If that manual step is forgotten, access that should be removed stays in place." `
            -RecommendedAction "Turn on 'Auto apply results to resource' for these reviews, or name an owner who applies the results within an agreed time" `
            -DocumentationUrl $manageDoc -SourceFile $src -ResultRows $manualApply -RuleId 'access-review-manual-apply' `
            -AffectedObjectIds @($manualApply | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'accessReviewScheduleDefinition' -AffectedCount @($manualApply | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'access review definitions with the stated configuration issue'
    }

    if ($overdue.Count -gt 0) {
        $roleOverdue = @($overdue | Where-Object { $_.Category -eq 'PrivilegedRoles' })
        $severity = if ($roleOverdue.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $overdue.Count 'access review round is past its' 'access review rounds are past their') + ' end date but not finished') `
            -Evidence ("The scheduled end date has passed while status remains nonterminal; {0} privileged roles." -f (Format-EACount $roleOverdue.Count 'instance covers' 'instances cover')) `
            -WhyItMatters 'Access that reviewers should have removed stays in place while a review is overdue. It also shows the review process is not working as intended.' `
            -RecommendedAction 'Chase the reviewers, finish the listed reviews and apply the results; then fix reviewer assignments and reminders so reviews finish on time' `
            -DocumentationUrl $manageDoc -SourceFile $overdueSrc -ResultRows $overdue.ToArray() -RuleId 'access-review-overdue' `
            -AffectedObjectIds @($overdue | ForEach-Object { $_.DefinitionId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'accessReviewScheduleDefinition' -AffectedCount @($overdue | ForEach-Object { $_.DefinitionId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'access review definitions with an overdue instance'
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
                -DocumentationUrl $guideDoc -SourceFile $roleSrc -ResultRows $roleRows -RuleId 'access-review-role-groups-uncovered' `
                -AffectedObjectIds @($roleRows | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'group' -AffectedCount @($roleRows | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'role-assignable groups without an identified access review'
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
