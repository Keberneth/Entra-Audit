<#
Security-Sensitive Change Monitoring. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

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
            EventId=[string](Get-EAApplicationCheckValue $auditEvent 'id')
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
            -SourceFile $source -ResultRows $successfulHigh -RuleId 'recent-high-risk-directory-change' -AffectedObjectIds @($successfulHigh.EventId) -AffectedCount $successfulHigh.Count -AffectedObjectType 'auditEvent' -PopulationLabel 'events in the retained lookback window' -VerificationType HistoricalEvent -VerificationSteps 'Match each event or attempt to its authorized purpose, investigate unexplained activity, and verify the current resource/access state after remediation. Record the review outcome; historical events remaining in the audit log are not evidence that remediation failed.' -ObjectType 'auditEvent'
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
            -SourceFile $source -ResultRows $successfulStandard -RuleId 'recent-group-access-change' -AffectedObjectIds @($successfulStandard.EventId) -AffectedCount $successfulStandard.Count -AffectedObjectType 'auditEvent' -PopulationLabel 'events in the retained lookback window' -VerificationType HistoricalEvent -VerificationSteps 'Match each event or attempt to its authorized purpose, investigate unexplained activity, and verify the current resource/access state after remediation. Record the review outcome; historical events remaining in the audit log are not evidence that remediation failed.' -ObjectType 'auditEvent'
    }
    if ($attemptedHigh.Count -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title (Format-EAApplicationCheckCount -Count $attemptedHigh.Count -One 'security-sensitive admin change was attempted but did not succeed' -Many 'security-sensitive admin changes were attempted but did not succeed') `
            -Evidence ("Failed attempts by area: {0}. Attempted by: {1}." -f (& $countSummary $attemptedHigh 'Domain'), (& $countSummary $attemptedHigh 'Initiator')) `
            -WhyItMatters 'Failed attempts to change roles, security policies or app credentials can mean someone is probing for access, or that an old script is still running with the wrong rights.' `
            -RecommendedAction 'Find out who or what made each attempt and why it failed, and set up alerts for repeated failures or unexpected apps.' `
            -SourceFile $source -ResultRows $attemptedHigh -RuleId 'attempted-high-risk-directory-change' -AffectedObjectIds @($attemptedHigh.EventId) -AffectedCount $attemptedHigh.Count -AffectedObjectType 'auditEvent' -PopulationLabel 'events in the retained lookback window' -VerificationType HistoricalEvent -VerificationSteps 'Match each event or attempt to its authorized purpose, investigate unexplained activity, and verify the current resource/access state after remediation. Record the review outcome; historical events remaining in the audit log are not evidence that remediation failed.' -ObjectType 'auditEvent'
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
