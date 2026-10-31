<#
App Registration Credential Expiry. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-AppCredentials {
    $apps = Get-EAApplications
    $now  = (Get-Date).ToUniversalTime()
    $warnDays = $ExpiringCredentialDays
    $soon = $now.AddDays($warnDays)
    # Rule ids: the expired/expiring findings keep their original RuleId + ObjectType so
    # their trend ids do not change; the two Information baselines got an explicit RuleId
    # (one-time migration from the old title-slug ids).

    $rows = @()
    $noEndCount = 0
    foreach ($a in $apps) {
        $creds = @()
        foreach ($c in @($a.PasswordCredentials | Where-Object { $_ })) { $creds += [pscustomobject]@{ C=$c; T='Secret' } }
        foreach ($c in @($a.KeyCredentials | Where-Object { $_ })) {
            $t = if ($c.Usage) { 'Certificate/' + $c.Usage } else { 'Certificate' }
            $creds += [pscustomobject]@{ C=$c; T=$t }
        }
        foreach ($cc in $creds) {
            $c = $cc.C
            if (-not $c.EndDateTime) { $noEndCount++; continue }   # no expiry date (counted in the evidence notes)
            $end = [datetime]$c.EndDateTime
            # Compare in UTC: a Local-kind value compared with UTC 'now' is off by the
            # machine's UTC offset (hours), which can flip a credential across a boundary.
            if ($end.Kind -eq [System.DateTimeKind]::Local) { $end = $end.ToUniversalTime() }
            $daysLeft = [int][math]::Round(($end - $now).TotalDays)
            $state = if ($end -lt $now) { 'Expired' } elseif ($end -lt $soon) { 'ExpiringSoon' } else { 'Valid' }
            $rows += [pscustomobject]@{
                App         = $a.DisplayName
                AppId       = $a.AppId
                AppObjectId = $a.Id
                CredType    = $cc.T
                CredName    = (@($c.DisplayName, [string]$c.KeyId) | Where-Object { $_ } | Select-Object -First 1)
                KeyId       = $c.KeyId
                End         = $c.EndDateTime
                DaysLeft    = $daysLeft
                State       = $state
            }
        }
    }
    $src = Write-Evidence -BaseName 'app_credentials' -Rows $rows `
        -Title 'App Registration Credentials - Secret & Certificate Expiry' `
        -Notes @(
            ("Expiry warning window: {0} days (-ExpiringCredentialDays)" -f $warnDays),
            'DaysLeft below 0 means the credential has already expired.',
            ("App registrations read: {0}; secrets/certificates with an expiry date: {1}; without an expiry date (not listed): {2}." -f @($apps).Count, $rows.Count, $noEndCount),
            'Scope: app registrations in this tenant only. The Workload Identity Credentials check (-workloadcredentials) also covers service-principal credentials, credentials without an expiry and long-lived secrets.'
        )

    if ($rows.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'appcredentials' -Category 'Applications' `
            -Title 'No app registration has a secret or certificate with an expiry date' `
            -Evidence ("{0} read; none carries a secret (password credential) or certificate (key credential) with an end date. Credentials without an end date: {1}." -f (Format-EACount -Count (@($apps).Count) -One 'app registration was' -Many 'app registrations were'), $noEndCount) `
            -WhyItMatters 'Nothing can expire, so no integration outage is expected from expiring credentials. Apps may sign in with federated (workload identity) credentials instead, or have no credentials yet.' `
            -RecommendedAction 'No action needed. Re-run this check after integrations start using secrets or certificates.' `
            -SourceFile $src -RuleId 'appcredentials-none-with-expiry' -ObjectType 'tenant'
        return
    }

    $expired  = @($rows | Where-Object { $_.State -eq 'Expired' })
    $expiring = @($rows | Where-Object { $_.State -eq 'ExpiringSoon' })

    # Apps whose EVERY dated credential is expired (no valid one left) - the strongest
    # "integration is broken / nobody cleaned it up" signal.
    $deadApps = @($rows | Group-Object AppId | Where-Object {
        @($_.Group | Where-Object { $_.State -eq 'Expired' }).Count -gt 0 -and
        @($_.Group | Where-Object { $_.State -ne 'Expired' }).Count -eq 0
    })

    if ($expired.Count -gt 0) {
        $expApps = @($expired.App | Select-Object -Unique)
        $worst = @($expired | Sort-Object DaysLeft | Select-Object -First 10 |
            ForEach-Object { "{0} [{1}] expired {2} days ago" -f $_.App, $_.CredType, [math]::Abs($_.DaysLeft) })
        $deadNote = if ($deadApps.Count -gt 0) { ' ' + (Format-EACount -Count $deadApps.Count -One 'app has NO valid secret or certificate left, so its integration has' -Many 'apps have NO valid secret or certificate left, so their integration has') + ' most likely stopped working.' } else { '' }
        Add-EntraFinding -Severity 'Medium' -CheckId 'appcredentials' -Category 'Applications' `
            -Title ("{0} expired on {1}" -f (Format-EACount -Count $expired.Count -One 'app secret or certificate has' -Many 'app secrets or certificates have'), (Format-EACount -Count $expApps.Count -One 'app registration' -Many 'app registrations')) `
            -Evidence ("Expired credentials (oldest first, up to 10): {0}.{1} The Workload Identity Credentials check (-workloadcredentials) may list the same credentials." -f ($worst -join '; '), $deadNote) `
            -WhyItMatters 'An expired secret or certificate usually means the connected integration has already stopped working, or that nobody removed a credential the app no longer uses. Either way, these app registrations are not being looked after.' `
            -RecommendedAction 'For each app, check whether the integration is still needed. If it is, create a new credential (preferably a certificate) and update the system that uses it; if not, delete the expired credential or the whole app (Entra admin center > App registrations > app > Certificates & secrets).' `
            -SourceFile $src -RuleId 'app-credential-expired' -ObjectType 'application' `
            -ResultRows @($expired | Select-Object App,AppId,CredType,CredName,End,DaysLeft | Sort-Object DaysLeft) `
            -AffectedObjectIds @($expired | ForEach-Object { $_.AppObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'application' -AffectedCount @($expired | ForEach-Object { $_.AppObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'app registrations with expired credentials'
    }
    if ($expiring.Count -gt 0) {
        $expApps = @($expiring.App | Select-Object -Unique)
        $next = @($expiring | Sort-Object DaysLeft | Select-Object -First 10 |
            ForEach-Object { "{0} [{1}] {2} days left" -f $_.App, $_.CredType, $_.DaysLeft })
        Add-EntraFinding -Severity 'Low' -CheckId 'appcredentials' -Category 'Applications' `
            -Title ("{0} within {1} days on {2}" -f (Format-EACount -Count $expiring.Count -One 'app secret or certificate expires' -Many 'app secrets or certificates expire'), $warnDays, (Format-EACount -Count $expApps.Count -One 'app registration' -Many 'app registrations')) `
            -Evidence ("Credentials expiring soon (soonest first, up to 10): {0}. The Workload Identity Credentials check (-workloadcredentials) may list the same credentials." -f ($next -join '; ')) `
            -WhyItMatters 'When a secret or certificate runs out without a planned renewal, the integration that uses it stops working without warning. Renewing it inside the warning window avoids that outage.' `
            -RecommendedAction 'Plan the renewal of each credential before its end date and update the system that uses it; prefer certificates with a defined renewal process, and delete credentials that are no longer used (Entra admin center > App registrations > app > Certificates & secrets).' `
            -SourceFile $src -RuleId 'app-credential-expiring' -ObjectType 'application' `
            -ResultRows @($expiring | Select-Object App,AppId,CredType,CredName,End,DaysLeft | Sort-Object DaysLeft) `
            -AffectedObjectIds @($expiring | ForEach-Object { $_.AppObjectId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'application' -AffectedCount @($expiring | ForEach-Object { $_.AppObjectId } | Where-Object { $_ } | Sort-Object -Unique).Count -PopulationLabel 'app registrations with expiring credentials'
    }
    if ($expired.Count -eq 0 -and $expiring.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'appcredentials' -Category 'Applications' `
            -Title $(if ($rows.Count -eq 1) { "The only app secret or certificate is valid for more than {0} days" -f $warnDays } else { "All {0} app secrets and certificates are valid for more than {1} days" -f $rows.Count, $warnDays }) `
            -Evidence ("Checked {0} on {1}: none has expired and none expires within {2} days." -f (Format-EACount -Count $rows.Count -One 'dated secret or certificate' -Many 'dated secrets and certificates'), (Format-EACount -Count (@($rows.AppId | Select-Object -Unique).Count) -One 'app registration' -Many 'app registrations'), $warnDays) `
            -WhyItMatters 'Current secrets and certificates are within their validity period, so no integration outage from an expiring credential is expected in the warning window.' `
            -RecommendedAction 'Keep a renewal calendar and re-run this check regularly to catch upcoming expiries.' `
            -SourceFile $src -ResultRows $rows -RuleId 'appcredentials-all-valid' -ObjectType 'tenant'
    }
}
