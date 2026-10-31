<#
Identity Governance Controls. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-IdentityGovernance {
    [CmdletBinding()]
    param()

    $checkId = 'identitygovernance'
    $limits = Get-EAGovAssessmentLimits
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
                -DocumentationUrl $requestPolicyDoc -SourceFile $policySrc -ResultRows $broadNoApproval -RuleId 'access-package-broad-no-approval' -AffectedObjectIds @($broadNoApproval.Id) -AffectedObjectType 'accessPackageAssignmentPolicy' -PopulationLabel 'accessPackageAssignmentPolicy objects'
        }

        $noExpiration = @($policyRows | Where-Object { [string]$_.ExpirationType -ieq 'noExpiration' })
        if ($noExpiration.Count -gt 0) {
            Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
                -Title (Format-EACount $noExpiration.Count 'access package policy gives access that never expires' 'access package policies give access that never expires') `
                -Evidence 'Expiration.Type=noExpiration. Access reviews can be compensating evidence but do not make indefinite assignment automatically low risk.' `
                -WhyItMatters 'Access that never expires stays after people change jobs or projects end, unless someone removes it by hand.' `
                -RecommendedAction ("Set an expiry (for example 180 or 365 days, renewable on request) in the Lifecycle settings of each listed policy ({0})" -f $packagesPath) `
                -DocumentationUrl $packageLifecycleDoc -SourceFile $policySrc -ResultRows $noExpiration -RuleId 'access-package-no-expiration' -AffectedObjectIds @($noExpiration.Id) -AffectedObjectType 'accessPackageAssignmentPolicy' -PopulationLabel 'accessPackageAssignmentPolicy objects'
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
                -DocumentationUrl $packageLifecycleDoc -SourceFile $policySrc -ResultRows $externalNoReview -RuleId 'access-package-external-no-review' -AffectedObjectIds @($externalNoReview.Id) -AffectedObjectType 'accessPackageAssignmentPolicy' -PopulationLabel 'accessPackageAssignmentPolicy objects'
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
                -DocumentationUrl $packageLifecycleDoc -SourceFile $policySrc -ResultRows $reviewKeepsAccess -RuleId 'access-package-review-keeps-access' -AffectedObjectIds @($reviewKeepsAccess.Id) -AffectedObjectType 'accessPackageAssignmentPolicy' -PopulationLabel 'accessPackageAssignmentPolicy objects'
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
                -DocumentationUrl $packageLifecycleDoc -SourceFile $policySrc -ResultRows $reviewNoFallback -RuleId 'access-package-review-no-fallback' -AffectedObjectIds @($reviewNoFallback.Id) -AffectedObjectType 'accessPackageAssignmentPolicy' -PopulationLabel 'accessPackageAssignmentPolicy objects'
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
                -DocumentationUrl $requestPolicyDoc -SourceFile $packageSrc -ResultRows $packagesWithoutPolicies -RuleId 'access-packages-no-policy' -AffectedObjectIds @($packagesWithoutPolicies.Id) -AffectedObjectType 'accessPackage' -PopulationLabel 'accessPackage objects'
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
    # A scheduled/enabled workflow is not proof that leavers actually lose access.
    # Read the aggregate execution reports; all requests remain GET and the
    # existing LifecycleWorkflows.Read.All permission authorizes this sub-control.
    $runDoc = 'https://learn.microsoft.com/graph/api/identitygovernance-workflow-list-runs?view=graph-rest-1.0'
    $runRows = New-Object System.Collections.Generic.List[object]
    $runGaps = New-Object System.Collections.Generic.List[object]
    $runCutoff = [datetimeoffset]::UtcNow.AddDays(-$limits.LifecycleLookbackDays)
    $runFilter = [uri]::EscapeDataString(('scheduledDateTime ge {0}' -f $runCutoff.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')))
    $workflowsForRuns = @($workflowRows | Sort-Object @{Expression={ if ([string]$_.Category -ieq 'leaver') { 0 } else { 1 } }},Id | Select-Object -First $limits.LifecycleMaxWorkflows)
    foreach ($workflow in $workflowsForRuns) {
        if (-not $workflow.Id) {
            $runGaps.Add([pscustomobject]@{ WorkflowId=$null; Workflow=$workflow.DisplayName; Reason='Workflow id was absent.' }) | Out-Null
            continue
        }
        $runs = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/{0}/runs?`$filter={1}&`$select=id,scheduledDateTime,startedDateTime,lastUpdatedDateTime,completedDateTime,processingStatus,failedTasksCount,failedUsersCount,totalUsersCount,totalUnprocessedTasksCount,workflowExecutionType" -f [uri]::EscapeDataString([string]$workflow.Id),$runFilter) `
            -Headers @{ Prefer='include-unknown-enum-members' } -MaxPages $limits.CollectionMaxPages
        if (-not $runs.Success -or $runs.Truncated) {
            $reason = if ($runs.Success) { 'Workflow run pagination safety limit reached.' } else { [string]$runs.Error.Exception.Message }
            $runGaps.Add([pscustomobject]@{ WorkflowId=$workflow.Id; Workflow=$workflow.DisplayName; Reason=$reason }) | Out-Null
        }
        foreach ($run in @($runs.Rows)) {
            # Preview executions do not perform production account changes.
            if ([string](Get-EAGovProperty $run 'workflowExecutionType') -ieq 'preview') { continue }
            $assessment = Get-EAGovLifecycleRunAssessment -Run $run -StalledHours $limits.LifecycleStalledHours
            $runRows.Add([pscustomobject]@{
                WorkflowId=$workflow.Id; Workflow=$workflow.DisplayName; Category=$workflow.Category
                RunId=Get-EAGovProperty $run 'id'; ProcessingStatus=Get-EAGovProperty $run 'processingStatus'
                ExecutionType=Get-EAGovProperty $run 'workflowExecutionType'; ScheduledDateTime=Get-EAGovProperty $run 'scheduledDateTime'
                CompletedDateTime=Get-EAGovProperty $run 'completedDateTime'; LastProgressDateTime=$assessment.LastProgressDateTime
                FailedTasks=$assessment.FailedTasks; FailedUsers=$assessment.FailedUsers; TotalUsers=Get-EAGovProperty $run 'totalUsersCount'
                Failed=$assessment.Failed; Stalled=$assessment.Stalled; Unknown=$assessment.Unknown
            }) | Out-Null
        }
    }
    $runSrc = Write-Evidence -BaseName 'governance_lifecycle_workflow_runs' -Rows $runRows.ToArray() -Title 'Lifecycle Workflow Execution Results' `
        -Notes @(("Last {0} days; stalled means queued/in progress without progress for {1} hours. Failure counts describe executions and can count the same person more than once. Preview runs are excluded; no recent runs is not proof of failure or success." -f $limits.LifecycleLookbackDays,$limits.LifecycleStalledHours))
    $failedRuns = @($runRows | Where-Object { $_.Failed -or $_.Stalled })
    if ($failedRuns.Count -gt 0) {
        $failedLeavers = @($failedRuns | Where-Object Category -eq 'leaver')
        $runSeverity = if ($failedLeavers.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $runSeverity -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} lifecycle workflow runs failed or stopped making progress" -f $failedRuns.Count) `
            -Evidence ("{0} affected runs are leaver workflows. Reports include failed task/user counts and run status; stalled runs exceeded {1} hours without progress. Historical failures may have been repaired later and require confirmation." -f $failedLeavers.Count,$limits.LifecycleStalledHours) `
            -WhyItMatters 'An enabled workflow can still fail to disable an account or remove access, leaving leavers with access while the process appears configured correctly.' `
            -RecommendedAction 'Open Entra admin center > ID Governance > Lifecycle workflows > Workflows > [workflow] > Workflow history; inspect the listed runs and failed tasks, repair the cause, and confirm the affected users actually lost access' `
            -DocumentationUrl $runDoc -SourceFile $runSrc -ResultRows $failedRuns -RuleId 'lifecycle-workflow-execution-failed' `
            -AffectedObjectIds @($failedRuns | Where-Object RunId | ForEach-Object { "$($_.WorkflowId)/$($_.RunId)" }) -AffectedCount $failedRuns.Count -AffectedObjectType 'workflowRun' -PopulationLabel 'failed or stalled workflow executions in the lookback window' `
            -VerificationType HistoricalEvent -VerificationSteps 'Inspect each failed or stalled execution, correct its cause, and record a successful subsequent execution or approved compensating action. Verify the intended account/access changes for affected users. Historical failures remain in the lookback window after repair; their disappearance is not the completion test.'
    }
    $unknownRuns = @($runRows | Where-Object Unknown)
    foreach ($unknownRun in $unknownRuns) {
        $runGaps.Add([pscustomobject]@{ WorkflowId=$unknownRun.WorkflowId; Workflow=$unknownRun.Workflow; Reason=("Run {0} omitted readable failure counters or returned an unknown/incomplete processing status: {1}." -f $unknownRun.RunId,$unknownRun.ProcessingStatus) }) | Out-Null
    }
    $unscannedWorkflows = [math]::Max(0,$workflowRows.Count - $workflowsForRuns.Count)
    if ($runGaps.Count -gt 0 -or $unknownRuns.Count -gt 0 -or $unscannedWorkflows -gt 0) {
        $runGapSrc = Write-Evidence -BaseName 'governance_lifecycle_workflow_run_gaps' -Rows $runGaps.ToArray() -Title 'Lifecycle Workflow Execution Collection Gaps'
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Lifecycle workflow execution reports' `
            -Reason ("Failed or partial run reads={0}; runs with unknown status/counts={1}; workflows beyond scan limit={2}." -f $runGaps.Count,$unknownRuns.Count,$unscannedWorkflows) `
            -RequiredScope 'LifecycleWorkflows.Read.All' -DocumentationUrl $runDoc -SourceFile $runGapSrc `
            -Subject 'some lifecycle workflow execution results' -Impact 'Failed account-disable or access-removal tasks may be missing from this report.' `
            -RecommendedAction 'Inspect workflow history in the admin center; fix read failures or adjust the documented limits in Get-EAGovAssessmentLimits for a larger scan, then rerun'
    }
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
                -DocumentationUrl $workflowGuideDoc -SourceFile $workflowSrc -ResultRows $disabledLeavers -RuleId 'leaver-workflow-disabled' -AffectedObjectIds @($disabledLeavers.Id) -AffectedObjectType 'workflow' -PopulationLabel 'workflow objects'
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
                -DocumentationUrl $workflowGuideDoc -SourceFile $workflowSrc -ResultRows $otherDisabled -RuleId 'lifecycle-workflow-disabled' -AffectedObjectIds @($otherDisabled.Id) -AffectedObjectType 'workflow' -PopulationLabel 'workflow objects'
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
                -DocumentationUrl $termsGuideDoc -SourceFile $agreementSrc -ResultRows $notViewed -RuleId 'terms-not-viewed-before-acceptance' -AffectedObjectIds @($notViewed.Id) -AffectedObjectType 'agreement' -PopulationLabel 'agreement objects'
        }
        $noReaccept = @($agreementRows | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.UserReacceptRequiredFrequency) })
        if ($noReaccept.Count -gt 0) {
            Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
                -Title (Format-EACount $noReaccept.Count 'terms of use document never asks users to accept it again' 'terms of use documents never ask users to accept them again') `
                -Evidence 'userReacceptRequiredFrequency is empty.' `
                -WhyItMatters 'Users accept once and are never reminded, even years later or after the terms change.' `
                -RecommendedAction "Set 'Duration before re-acceptance required (days)' (for example 365) where your rules require regular acceptance, or record that one-time acceptance is intended" `
                -DocumentationUrl $termsGuideDoc -SourceFile $agreementSrc -ResultRows $noReaccept -RuleId 'terms-no-reacceptance' -AffectedObjectIds @($noReaccept.Id) -AffectedObjectType 'agreement' -PopulationLabel 'agreement objects'
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
                    -DocumentationUrl $termsGuideDoc -SourceFile $agreementSrc -ResultRows $unenforced -RuleId 'terms-of-use-not-enforced' -AffectedObjectIds @($unenforced.Id) -AffectedObjectType 'agreement' -PopulationLabel 'agreement objects'
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
    # PIM eligibility and role-assignability are independent. Inspect cloud
    # security/Microsoft 365 groups, excluding dynamic and synchronized groups.
    # Graph's policy API requires a group id; it has no tenant-wide group query.
    $roleGroupResult = Invoke-EAGovGraphCollection -Uri 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName,isAssignableToRole,groupTypes,securityEnabled,onPremisesSyncEnabled&$top=999' -MaxPages $limits.CollectionMaxPages
    $pimRows = New-Object System.Collections.Generic.List[object]
    $pimPolicyRows = New-Object System.Collections.Generic.List[object]
    $pimErrors = New-Object System.Collections.Generic.List[object]
    $pimDiscovery = New-Object System.Collections.Generic.List[object]
    $pimCandidates = @($roleGroupResult.Rows | Where-Object { Test-EAGovPimCandidateGroup $_ } | Sort-Object @{Expression={ if ((Get-EAGovProperty $_ 'isAssignableToRole') -eq $true) { 0 } else { 1 } }}, @{Expression={ Get-EAGovProperty $_ 'id' }})
    $pimSkippedCandidates = [math]::Max(0,$pimCandidates.Count - $limits.PimMaxCandidateGroups)
    if ($roleGroupResult.Success) {
        foreach ($group in @($pimCandidates | Select-Object -First $limits.PimMaxCandidateGroups)) {
            $groupId = [string](Get-EAGovProperty $group 'id')
            $roleAssignable = (Get-EAGovProperty $group 'isAssignableToRole') -eq $true
            if (-not $groupId) {
                $pimErrors.Add([pscustomobject]@{ GroupId=$null; Group=Get-EAGovProperty $group 'displayName'; DataSource='PIM discovery'; RequiredScope='Group.Read.All'; Reason='Group id was absent.' }) | Out-Null
                continue
            }
            $escaped = [uri]::EscapeDataString($groupId)
            $groupFilter = [uri]::EscapeDataString("groupId eq '$groupId'")
            $policyFilter = [uri]::EscapeDataString("scopeId eq '$groupId' and scopeType eq 'Group'")
            $policies = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter={0}&`$expand=policy(`$expand=rules)&`$top=100" -f $policyFilter) -MaxPages $limits.CollectionMaxPages
            $policyDiscoveryKnown = $policies.Success -and -not $policies.Truncated
            $pimManaged = $policyDiscoveryKnown -and @($policies.Rows).Count -gt 0
            $pimDiscovery.Add([pscustomobject]@{
                GroupId=$groupId; DisplayName=Get-EAGovProperty $group 'displayName'; IsAssignableToRole=$roleAssignable
                PolicyDiscoveryComplete=$policyDiscoveryKnown; PimPoliciesFound=if ($policyDiscoveryKnown) { @($policies.Rows).Count } else { $null }
                Assessed=$roleAssignable -or $pimManaged
            }) | Out-Null
            if (-not $roleAssignable -and -not $pimManaged) {
                if (-not $policyDiscoveryKnown) {
                    $reason = if ($policies.Success) { 'Policy discovery pagination limit reached.' } else { [string]$policies.Error.Exception.Message }
                    $pimErrors.Add([pscustomobject]@{ GroupId=$groupId; Group=Get-EAGovProperty $group 'displayName'; DataSource='PIM policy discovery'; RequiredScope='RoleManagementPolicy.Read.AzureADGroup'; Reason=$reason }) | Out-Null
                }
                # A successful empty policy list on an ordinary group means it
                # is not PIM-managed, not a missing-PIM-policy security finding.
                continue
            }
            $members = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/members?`$select=id&`$top=999" -f $escaped)
            $owners = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/owners?`$select=id&`$top=999" -f $escaped)
            $eligibility = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter={0}&`$top=999" -f $groupFilter)
            $assignments = Invoke-EAGovGraphCollection -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter={0}&`$top=999" -f $groupFilter)

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
                        GroupId=$groupId; DisplayName=Get-EAGovProperty $group 'displayName'; IsAssignableToRole=$roleAssignable; PolicyKind=$policyKind
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
                IsAssignableToRole=$roleAssignable
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
    $pimSrc = Write-Evidence -BaseName 'governance_pim_for_groups' -Rows $pimRows.ToArray() -Title 'PIM for Groups - Role-Assignable and Other PIM-Managed Groups' `
        -Notes @('Unscheduled counts compare each direct member and owner id with both eligible and active schedule instances; aggregate schedule counts are not used as a proxy for principal coverage.')
    $pimDiscoverySrc = Write-Evidence -BaseName 'governance_pim_group_discovery' -Rows $pimDiscovery.ToArray() -Title 'PIM Group Discovery Coverage' `
        -Notes @(("Cloud security and Microsoft 365 groups are eligible; dynamic/synchronized groups are excluded. Role-assignable groups are scanned first. Candidate limit={0}; candidates beyond limit={1}. Ordinary groups with a successfully read empty PIM policy list are not treated as PIM failures." -f $limits.PimMaxCandidateGroups,$pimSkippedCandidates))
    if ($pimSkippedCandidates -gt 0) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'PIM group discovery scan limit' `
            -Reason ("{0} candidate groups exceeded the {1}-group scan limit." -f $pimSkippedCandidates,$limits.PimMaxCandidateGroups) `
            -RequiredScope 'Group.Read.All and RoleManagementPolicy.Read.AzureADGroup' -DocumentationUrl $pimPolicyDoc -SourceFile $pimDiscoverySrc `
            -Subject 'PIM settings beyond the group scan limit' -Impact 'Weak activation settings in unscanned groups may be missing.' `
            -RecommendedAction 'Review the remaining groups in PIM or increase PimMaxCandidateGroups in Get-EAGovAssessmentLimits for a larger read-only run' -Partial
    }
    $pimPolicySrc = Write-Evidence -BaseName 'governance_pim_for_groups_policies' -Rows $pimPolicyRows.ToArray() -Title 'PIM for Groups - Member and Owner Policy Rules'
    if (-not $roleGroupResult.Success) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Role-assignable groups for PIM coverage' `
            -Reason ([string]$roleGroupResult.Error.Exception.Message) -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $pimDoc -SourceFile $pimSrc -Subject 'the list of groups eligible for PIM' `
            -Impact 'The Privileged Identity Management (PIM) settings of candidate groups were not checked.'
    } elseif ($roleGroupResult.Truncated) {
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'Role-assignable group pagination for PIM coverage' `
            -Reason "pagination exceeded $($roleGroupResult.Pages) pages." -RequiredScope 'Group.Read.All' `
            -DocumentationUrl $pimDoc -SourceFile $pimSrc -Partial -Subject 'the list of groups eligible for PIM' `
            -Impact 'Groups beyond the part that was read were not checked for PIM.'
    }
    if ($pimErrors.Count -gt 0) {
        $pimErrorSrc = Write-Evidence -BaseName 'governance_pim_for_groups_errors' -Rows $pimErrors.ToArray() -Title 'PIM for Groups Collection Gaps'
        $scopeList = @($pimErrors | ForEach-Object { $_.RequiredScope } | Select-Object -Unique) -join ', '
        Add-EAGovCoverageFinding -CheckId $checkId -Category 'Identity Governance' -DataSource 'PIM for Groups policy and schedule coverage' `
            -Reason ((Format-EACount $pimErrors.Count 'group/data-source read' 'group/data-source reads') + ' failed or truncated.') -RequiredScope $scopeList `
            -DocumentationUrl $pimPolicyDoc -SourceFile $pimErrorSrc -Subject 'the PIM settings and assignments of some groups' `
            -Impact 'Permanent or unmanaged group access through these groups may be missing from this report.'
    }

    $standingPrivileged = @($pimRows | Where-Object { $_.AssignmentKnown -and $_.PermanentAssignmentCount -gt 0 })
    if ($standingPrivileged.Count -gt 0) {
        $ownerStanding = @($standingPrivileged | Where-Object { $_.PermanentOwnerCount -gt 0 })
        $severity = if ($ownerStanding.Count -gt 0) { 'High' } else { 'Medium' }
        Add-EAGovFinding -Severity $severity -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $standingPrivileged.Count 'group has' 'groups have') + ' permanent members or owners in PIM') `
            -Evidence ("Groups where EndDateTime is absent on one or more PIM assignment instances; {0} permanent owner assignments." -f (Format-EACount $ownerStanding.Count 'group includes' 'groups include')) `
            -WhyItMatters 'Privileged Identity Management (PIM) is meant to give group access only when needed and for a limited time. Permanent assignments mean these people hold that access all the time, so a stolen account can use it at once.' `
            -RecommendedAction ("Change permanent assignments to eligible ones (switched on only when needed) in {0} > [group] > Assignments, and require MFA, approval and a reason to activate" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupAssignDoc -SourceFile $pimSrc -ResultRows $standingPrivileged -RuleId 'pim-group-permanent-assignments' -AffectedObjectIds @($standingPrivileged.GroupId) -AffectedObjectType 'group' -PopulationLabel 'groups with affected PIM configuration'
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
            -Title ((Format-EACount $unscheduledDirect.Count 'group has' 'groups have') + ' members or owners added outside PIM') `
            -Evidence ("Per-principal comparison found {0} and {1} whose ids occur in neither an eligibility nor assignment schedule instance for the corresponding accessId." -f (Format-EACount $unscheduledMemberTotal 'direct member' 'direct members'),(Format-EACount $unscheduledOwnerTotal 'direct owner' 'direct owners')) `
            -WhyItMatters 'People added directly to these groups hold group access without going through Privileged Identity Management (PIM): no time limit, no approval and no activation record.' `
            -RecommendedAction ("Remove direct members and owners who should not be there, and manage everyone else as eligible or time-limited assignments in {0}" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupAssignDoc -SourceFile $pimSrc -ResultRows $unscheduledDirect -RuleId 'role-groups-direct-principals-without-pim' -AffectedObjectIds @($unscheduledDirect.GroupId) -AffectedObjectType 'group' -PopulationLabel 'groups with affected PIM configuration'
    }

    $pimWithoutPolicies = @($pimRows | Where-Object {
        $_.EligibilityKnown -and $_.AssignmentKnown -and ($_.EligibilityInstanceCount -gt 0 -or $_.AssignmentInstanceCount -gt 0) -and
        $_.PoliciesKnown -and (-not $_.HasMemberPolicy -or -not $_.HasOwnerPolicy)
    })
    if ($pimWithoutPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $pimWithoutPolicies.Count 'PIM-managed group is' 'PIM-managed groups are') + ' missing member or owner activation settings') `
            -Evidence 'PIM schedule instances exist, but fewer than two role-management policy assignments (member and owner) were returned.' `
            -WhyItMatters 'Without both settings there is no proof that switching on group access in these groups requires multifactor authentication (MFA), approval or a time limit.' `
            -RecommendedAction ("Open each listed group in {0} > [group] > Settings and check the Member and Owner role settings" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimSrc -ResultRows $pimWithoutPolicies -RuleId 'pim-group-policy-missing' -AffectedObjectIds @($pimWithoutPolicies.GroupId) -AffectedObjectType 'group' -PopulationLabel 'groups with affected PIM configuration'
    }

    $unknownPimPolicyRules = @($pimPolicyRows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.UnknownFields) })
    if ($unknownPimPolicyRules.Count -gt 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title ("Some PIM activation settings could not be read for {0}" -f (Format-EACount $unknownPimPolicyRules.Count 'group setting' 'group settings')) `
            -Evidence ((Format-EACount $unknownPimPolicyRules.Count 'member/owner policy assignment' 'member/owner policy assignments') + ' omitted or returned unreadable activation/expiration rule fields. This is unknown, not compliant.') `
            -WhyItMatters 'The audit cannot confirm whether switching on group access in these groups requires MFA, a reason, approval or a time limit.' `
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
            -Title ((Format-EACount $weakActivationPolicies.Count 'PIM group setting lets' 'PIM group settings let') + ' people switch on group access without MFA') `
            -Evidence ("MultiFactorAuthentication is absent from enabledRules and no enabled authentication-context rule was returned; affected owner policies={0}." -f $weakOwnerPolicies.Count) `
            -WhyItMatters 'Someone with a stolen password or session could switch on group membership or ownership without a fresh multifactor authentication (MFA) check.' `
            -RecommendedAction ("Turn on 'On activation, require multifactor authentication' (or a Conditional Access authentication context) for these settings in {0} > [group] > Settings" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $weakActivationPolicies -RuleId 'pim-group-activation-no-strong-auth' -AffectedObjectIds @($weakActivationPolicies.GroupId) -AffectedObjectType 'group' -PopulationLabel 'groups with affected PIM configuration'
    }

    $authContextPolicies = @($pimPolicyRows | Where-Object { $_.AuthenticationContextEnabled -eq $true })
    if ($authContextPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $authContextPolicies.Count 'PIM group setting relies' 'PIM group settings rely') + ' on Conditional Access that needs a manual check') `
            -Evidence ("{0} an authentication context. The PIM rule alone does not prove that the referenced context is available and protected by enabled Conditional Access with mandatory MFA/authentication strength." -f (Format-EACount $authContextPolicies.Count 'policy assignment uses' 'policy assignments use')) `
            -WhyItMatters 'Activation asks for an authentication context, but that only protects anything if an enabled Conditional Access policy requires MFA for it. A missing or narrow policy would leave activation unprotected.' `
            -RecommendedAction 'For each listed claim value, check that the authentication context exists and that an enabled Conditional Access policy requires MFA or an authentication strength for it (Entra admin center > Entra ID > Conditional Access > Authentication contexts)' `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $authContextPolicies `
            -RuleId 'pim-group-auth-context-validation' -CoverageGap -VerificationType ManualTest `
            -VerificationSteps 'Verify the referenced authentication context is enforced by enabled Conditional Access policies for the relevant group activations. Test activation with a representative eligible account and record the result, tester and date. A read-only rerun cannot establish the complete interactive policy outcome.'
    }

    $noJustificationPolicies = @($pimPolicyRows | Where-Object { $_.JustificationRequired -eq $false })
    if ($noJustificationPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $noJustificationPolicies.Count 'PIM group setting does not' 'PIM group settings do not') + ' ask for a reason when group access is switched on') `
            -Evidence 'Justification is absent from the policy enabledRules list.' `
            -WhyItMatters 'Without a stated reason it is hard to check later, or during an incident, whether an group activation was for real work.' `
            -RecommendedAction ("Turn on 'Require justification on activation' for these member and owner settings in {0} > [group] > Settings" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $noJustificationPolicies -RuleId 'pim-group-activation-no-justification' -AffectedObjectIds @($noJustificationPolicies.GroupId) -AffectedObjectType 'group' -PopulationLabel 'groups with affected PIM configuration'
    }

    $ownerNoApprovalPolicies = @($pimPolicyRows | Where-Object { [string]$_.PolicyKind -ieq 'owner' -and $_.ApprovalRequired -eq $false })
    if ($ownerNoApprovalPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $ownerNoApprovalPolicies.Count 'PIM group owner setting allows' 'PIM group owner settings allow') + ' owner access to be switched on without approval') `
            -Evidence 'The owner policy approval rule has isApprovalRequired=false.' `
            -WhyItMatters 'Group owners can change who is in an group. Requiring approval means a second person agrees before someone gets that power.' `
            -RecommendedAction ("Turn on 'Require approval to activate' for the Owner setting of these groups in {0} > [group] > Settings, and name at least two approvers" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $ownerNoApprovalPolicies -RuleId 'pim-group-owner-activation-no-approval' -AffectedObjectIds @($ownerNoApprovalPolicies.GroupId) -AffectedObjectType 'group' -PopulationLabel 'groups with affected PIM configuration'
    }

    $memberNoApprovalPolicies = @($pimPolicyRows | Where-Object { [string]$_.PolicyKind -ieq 'member' -and $_.ApprovalRequired -eq $false })
    if ($memberNoApprovalPolicies.Count -gt 0) {
        $memberApprovalSeverity = if (@($memberNoApprovalPolicies | Where-Object IsAssignableToRole).Count -gt 0) { 'High' } else { 'Low' }
        Add-EAGovFinding -Severity $memberApprovalSeverity -CheckId $checkId -Category 'Identity Governance' `
            -Title ("{0} PIM group membership settings allow activation without approval" -f $memberNoApprovalPolicies.Count) `
            -Evidence 'The member activation policy has isApprovalRequired=false. IsAssignableToRole identifies groups that can grant Entra admin roles; other PIM groups may grant application or Azure access.' `
            -WhyItMatters 'A person able to use an eligible account can activate group access without a second person approving it. Microsoft recommends approval for groups used to elevate into Entra roles.' `
            -RecommendedAction ("Require approval for groups used for admin-role elevation in {0} > [group] > Settings > Member. For other groups, decide based on the resources they grant and document any exception" -f $pimGroupsPath) `
            -DocumentationUrl 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/concept-pim-for-groups' `
            -SourceFile $pimPolicySrc -ResultRows $memberNoApprovalPolicies -RuleId 'pim-group-member-activation-no-approval' -AffectedObjectIds @($memberNoApprovalPolicies.GroupId) -AffectedObjectType 'group' -PopulationLabel 'groups with affected PIM configuration'
    }

    $longActivationPolicies = @($pimPolicyRows | Where-Object { $null -ne $_.MaximumActivationHours -and $_.MaximumActivationHours -gt 8 })
    if ($longActivationPolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Medium' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $longActivationPolicies.Count 'PIM group setting keeps' 'PIM group settings keep') + ' group access switched on for more than 8 hours') `
            -Evidence 'maximumDuration parsed to more than eight hours. Eight hours is an audit review threshold, not a universal compliance boundary.' `
            -WhyItMatters 'The longer group access stays switched on, the longer a stolen session or an unlocked computer can be misused.' `
            -RecommendedAction ("Lower 'Activation maximum duration (hours)' to the shortest workable value (8 hours or less) in {0} > [group] > Settings, and record any exceptions" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $longActivationPolicies -RuleId 'pim-group-activation-duration-long' -AffectedObjectIds @($longActivationPolicies.GroupId) -AffectedObjectType 'group' -PopulationLabel 'groups with affected PIM configuration'
    }

    $permanentActivePolicies = @($pimPolicyRows | Where-Object { $_.PermanentActiveAllowed -eq $true })
    if ($permanentActivePolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'High' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $permanentActivePolicies.Count 'PIM group setting allows' 'PIM group settings allow') + ' permanent group access') `
            -Evidence 'The active-assignment expiration rule has isExpirationRequired=false.' `
            -WhyItMatters 'Even if nobody has it today, an admin can later give someone group access that never ends.' `
            -RecommendedAction ("Turn off 'Allow permanent active assignment' for the member and owner settings in {0} > [group] > Settings, and review existing permanent assignments" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $permanentActivePolicies -RuleId 'pim-group-policy-allows-permanent-active' -AffectedObjectIds @($permanentActivePolicies.GroupId) -AffectedObjectType 'group' -PopulationLabel 'groups with affected PIM configuration'
    }

    $permanentEligiblePolicies = @($pimPolicyRows | Where-Object { $_.PermanentEligibleAllowed -eq $true })
    if ($permanentEligiblePolicies.Count -gt 0) {
        Add-EAGovFinding -Severity 'Low' -CheckId $checkId -Category 'Identity Governance' `
            -Title ((Format-EACount $permanentEligiblePolicies.Count 'PIM group setting allows' 'PIM group settings allow') + ' eligibility for group access that never expires') `
            -Evidence 'The eligible-assignment expiration rule has isExpirationRequired=false.' `
            -WhyItMatters 'People can stay able to switch on group access long after they need it, unless a review removes them.' `
            -RecommendedAction ("Turn off 'Allow permanent eligible assignment' in {0} > [group] > Settings, or run recurring access reviews of eligible members" -f $pimGroupsPath) `
            -DocumentationUrl $pimGroupSettingsDoc -SourceFile $pimPolicySrc -ResultRows $permanentEligiblePolicies -RuleId 'pim-group-policy-allows-permanent-eligibility' -AffectedObjectIds @($permanentEligiblePolicies.GroupId) -AffectedObjectType 'group' -PopulationLabel 'groups with affected PIM configuration'
    }

    # A list that could not be read says so instead of showing 0; a partial list shows "N+".
    $countText = {
        param($ReadResult, [int]$Count)
        if (-not $ReadResult.Success) { 'not read' } elseif ($ReadResult.Truncated) { '{0}+ (partial list)' -f $Count } else { [string]$Count }
    }
    Add-EAGovFinding -Severity 'Information' -CheckId $checkId -Category 'Identity Governance' `
        -Title 'Identity governance features recorded' `
        -Evidence ("Catalogs={0}; access packages={1}; assignment policies={2}; lifecycle workflows={3}; Terms of Use agreements={4}; groups assessed for PIM={5}." -f `
            (& $countText $catalogResult $catalogRows.Count),(& $countText $packageResult $packageRows.Count),(& $countText $policyResult $policyRows.Count),
            (& $countText $workflowResult $workflowRows.Count),(& $countText $agreementResult $agreementRows.Count),(& $countText $roleGroupResult $pimRows.Count)) `
        -WhyItMatters 'Access packages, lifecycle workflows, terms of use and PIM for Groups each control a different stage of access: granting it, using it, reviewing it and removing it.' `
        -RecommendedAction 'Check that each feature you rely on is set up, and document what you use instead for the features you do not use' `
        -DocumentationUrl $entitlementDoc -SourceFile $packageSrc -ResultRows $packageRows -RuleId 'identity-governance-inventory'
}
