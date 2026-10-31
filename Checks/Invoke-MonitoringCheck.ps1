<#
Identity Monitoring & Alert Coverage. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

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
                    -SourceFile $crossPlaneSource -ResultRows $crossPlaneRows -RuleId 'monitoring-identity-alert-sentinel-notification-unverified' -VerificationType ManualTest -VerificationSteps 'Perform an approved end-to-end test, verify the expected notification reaches the designated responders and is acknowledged, and record the tester, date and evidence. This read-only audit cannot perform the test; rerunning it alone does not close this action.' -ObjectType 'tenant' -CoverageGap
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
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-alert-delivery-untested' -VerificationType ManualTest -VerificationSteps 'Perform an approved end-to-end test, verify the expected notification reaches the designated responders and is acknowledged, and record the tester, date and evidence. This read-only audit cannot perform the test; rerunning it alone does not close this action.' -ObjectType 'tenant' -CoverageGap
    } elseif ($azureCoverage.SentinelEmergencyRuleCount -gt 0) {
        Add-EntraFinding -Severity 'Low' -CheckId $checkId -Category $category `
            -Title 'An emergency-account sign-in alert exists in Microsoft Sentinel; confirm it notifies someone' `
            -Evidence ("{0} the emergency accounts. {1} {2}" -f (Format-EAApplicationCheckCount -Count $azureCoverage.SentinelEmergencyRuleCount -One 'enabled Microsoft Sentinel analytics rule mentions' -Many 'enabled Microsoft Sentinel analytics rules mention'), $sentinelNotificationText, $azureAlertText) `
            -WhyItMatters 'A correctly configured rule can still fail because of a broken query, missing log data, or an automation rule that does not reach anyone. Only a test proves that the alert arrives.' `
            -RecommendedAction 'In Microsoft Sentinel > Automation, confirm that an automation rule or playbook notifies your responders for incidents from these rules, then test it end to end (for example with a supervised emergency-account sign-in).' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' `
            -SourceFile $emergencySource -ResultRows $emergencyRows -RuleId 'emergency-access-alert-delivery-untested' -VerificationType ManualTest -VerificationSteps 'Perform an approved end-to-end test, verify the expected notification reaches the designated responders and is acknowledged, and record the tester, date and evidence. This read-only audit cannot perform the test; rerunning it alone does not close this action.' -ObjectType 'tenant' -CoverageGap
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
