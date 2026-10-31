<#
Microsoft Identity Secure Score. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

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
