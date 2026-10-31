<#
Identity Protection (Risky Users). Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-RiskyUsersOnly {
    # Filter server-side: without it every HISTORICALLY risky user (remediated/dismissed,
    # years of history) is downloaded just to be discarded client-side.
    $risky = @(Get-MgRiskyUser -All -Filter "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'" -ErrorAction Stop)
    # Risk detections are supporting detail. Track a failed read explicitly: an absent
    # detections file must never look like "no detections".
    $detections = @(); $detectionsKnown = $true; $detectionsError = $null
    # 30-day window server-side, consistent with the other log-based checks. ('gt' - the
    # documented detectedDateTime filter operators are eq/gt/lt, not ge.)
    $dsince = (Get-Date).ToUniversalTime().AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    try { $detections = @(Get-MgRiskDetection -All -Filter "detectedDateTime gt $dsince" -ErrorAction Stop) }
    catch { $detectionsKnown = $false; $detectionsError = $_.Exception.Message }
    $rows = $risky | Select-Object UserPrincipalName, UserDisplayName, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime, Id
    $src = Write-Evidence -BaseName 'risky_users' -Rows $rows -Title 'Identity Protection - Risky Users'
    $drows = @($detections | Select-Object UserPrincipalName, RiskEventType, RiskLevel, RiskState, DetectedDateTime, IPAddress)
    $dNotes = if ($detectionsKnown) { @() } else { @("READ FAILED: risk detections could not be read ($detectionsError). This list is unknown, not empty.") }
    Write-Evidence -BaseName 'risk_detections' -Rows $drows -Title 'Identity Protection - Risk Detections (last 30 days)' -Notes $dNotes | Out-Null
    if (-not $detectionsKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyusers' -Category 'Threat Signals' `
            -Title 'Recent risk detections could not be read' `
            -Evidence ("Reading risk detections for the last 30 days failed: {0}. The risky-user list was read successfully; only the detection details (what triggered each risk) are missing and unknown." -f $detectionsError) `
            -WhyItMatters 'Risk detections explain why a user was flagged, for example a leaked password or a sign-in from an anonymous IP address. Without them, investigating flagged users takes longer.' `
            -RecommendedAction 'Grant IdentityRiskEvent.Read.All to the audit account or app (or retry after a temporary error) and re-run the riskyusers check.' `
            -SourceFile $src -RuleId 'riskyusers-detections-unreadable' -ObjectType 'tenant' -CoverageGap
    }

    # privileged cross-ref (shared assignment cache - one Graph download per run)
    $privIds = @{}; $privMapError = $null
    try { foreach ($id in (Get-EAPrivilegedUserMap).Keys) { $privIds[$id] = $true } }
    catch { $privMapError = $_.Exception.Message }
    $privIncomplete = [bool]($privMapError -or $script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed -or $script:PrivilegedUserMapIncomplete)

    function _RiskyUserList($list) {
        $items = @($list | ForEach-Object { '{0} ({1} risk, {2})' -f $_.UserPrincipalName, $_.RiskLevel, $_.RiskState })
        $shown = @($items | Select-Object -First 10)
        $text = $shown -join ', '
        if ($items.Count -gt $shown.Count) { $text += (' (+{0} more)' -f ($items.Count - $shown.Count)) }
        return $text
    }

    if ($risky.Count -gt 0) {
        $privRisky = @($risky | Where-Object { $_.Id -and $privIds.ContainsKey($_.Id) })
        $other = @($risky | Where-Object { -not ($_.Id -and $privIds.ContainsKey($_.Id)) })
        # The classification gap matters only for risky users NOT recognised as administrators:
        # with an incomplete administrator list, one of them may be an admin.
        if ($privIncomplete -and $other.Count -gt 0) {
            $why = @()
            if ($privMapError) { $why += ("the administrator list could not be built ({0})" -f $privMapError) }
            if ($script:PrivAssignmentsFailed) { $why += 'active role assignments could not be read' }
            if ($script:PrivEligibilityAssignmentsFailed) { $why += 'eligible (PIM) role assignments could not be read' }
            if ($why.Count -eq 0) { $why += 'at least one privileged group could not be expanded' }
            Add-EntraFinding -Severity 'Information' -CheckId 'riskyusers' -Category 'Threat Signals' `
                -Title 'Could not confirm whether risky users are administrators' `
                -Evidence ("The administrator list is incomplete because {0}. {1}." -f ($why -join '; '), (Format-EACount -Count $other.Count -One 'risky user was reported at the normal-user severity but may be an administrator' -Many 'risky users were reported at the normal-user severity but one of them may be an administrator')) `
                -WhyItMatters 'A risky administrator is a tenant-takeover incident and must be reported as Critical; an incomplete administrator list can hide that.' `
                -RecommendedAction 'Restore read access to role assignments and privileged groups (RoleManagement.Read.Directory, Group.Read.All) and re-run the riskyusers check.' `
                -SourceFile $src -RuleId 'riskyusers-privileged-classification-incomplete' -ObjectType 'tenant' -CoverageGap
        }
        if ($privRisky.Count -gt 0) {
            Add-EntraFinding -Severity 'Critical' -CheckId 'riskyusers' -Category 'Threat Signals' `
                -Title ((Format-EACount -Count $privRisky.Count -One 'administrator account is' -Many 'administrator accounts are') + ' flagged as risky or compromised') `
                -Evidence ("Risky administrators: {0}." -f (_RiskyUserList $privRisky)) `
                -WhyItMatters 'Microsoft Entra ID Protection believes these administrator accounts may be in an attacker''s hands. An administrator compromise can give control of the whole tenant, so treat this as an active security incident.' `
                -RecommendedAction 'Investigate now: reset each account''s password, revoke its sessions, review its recent sign-ins and audit-log activity, then confirm the compromise or dismiss the risk in Entra admin center > ID Protection > Risky users.' `
                -SourceFile $src -ResultRows @($privRisky | Select-Object UserPrincipalName,RiskLevel,RiskState,RiskDetail,RiskLastUpdatedDateTime) `
                -RuleId 'riskyusers-privileged-at-risk' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk' `
                -AffectedObjectIds @($privRisky | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $privRisky.Count -PopulationLabel 'identified privileged users currently flagged at risk'
        }
        if ($other.Count -gt 0) {
            Add-EntraFinding -Severity 'High' -CheckId 'riskyusers' -Category 'Threat Signals' `
                -Title ((Format-EACount -Count $other.Count -One 'user is' -Many 'users are') + ' flagged as risky or compromised by Identity Protection') `
                -Evidence ("Risky users: {0}." -f (_RiskyUserList $other)) `
                -WhyItMatters 'Microsoft Entra ID Protection has seen signs that these accounts may be compromised, such as leaked passwords, password-spray attempts or unusual sign-ins.' `
                -RecommendedAction 'Investigate each user and reset passwords or revoke sessions where needed (Entra admin center > ID Protection > Risky users). Enable risk-based Conditional Access so new risks are handled automatically.' `
                -SourceFile $src -ResultRows @($other | Select-Object UserPrincipalName,RiskLevel,RiskState,RiskDetail,RiskLastUpdatedDateTime) `
                -RuleId 'riskyusers-users-at-risk' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock' `
                -AffectedObjectIds @($other | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'user' -AffectedCount $other.Count -PopulationLabel 'other users currently flagged at risk'
        }
    } else {
        $detText = if ($detectionsKnown) { ("{0} recorded in the last 30 days (see the risk detections evidence)." -f (Format-EACount -Count $detections.Count -One 'risk detection was' -Many 'risk detections were')) } else { 'Risk detections could not be read (see the separate finding).' }
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyusers' -Category 'Threat Signals' `
            -Title 'No users are currently flagged as risky' `
            -Evidence ("Identity Protection returned no users in the 'at risk' or 'confirmed compromised' state. {0}" -f $detText) `
            -WhyItMatters 'Microsoft Entra ID Protection flags accounts that show signs of compromise, such as leaked passwords or unusual sign-ins.' `
            -RecommendedAction 'Keep risk-based Conditional Access policies enabled so new risks are handled automatically, and review the Risky users report regularly.' `
            -SourceFile $src -RuleId 'riskyusers-none-flagged' -ObjectType 'tenant'
    }
}
