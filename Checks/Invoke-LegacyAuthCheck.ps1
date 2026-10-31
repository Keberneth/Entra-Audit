<#
Legacy Authentication Usage. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-LegacyAuth {
    # InvariantCulture: ':' in a format string is the CULTURE time separator, so e.g.
    # fi-FI/da-DK render '14.35.12' - an invalid OData timestamp that 400s the query.
    $since = (Get-Date).ToUniversalTime().AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $legacyClients = 'Exchange ActiveSync|Authenticated SMTP|IMAP4|POP3|MAPI Over HTTP|Other clients|AutoDiscover|Exchange Online PowerShell|Exchange Web Services|Outlook Anywhere'
    # Filter clientAppUsed SERVER-SIDE: downloading every sign-in for 30 days and
    # filtering locally pulls millions of rows on real tenants (hours / throttling).
    # The regex Where-Object stays as a defensive post-filter.
    $legacyList = @('Exchange ActiveSync','Authenticated SMTP','IMAP4','POP3','MAPI Over HTTP','Other clients','AutoDiscover','Exchange Online PowerShell','Exchange Web Services','Outlook Anywhere (RPC over HTTP)')
    $clientFilter = (($legacyList | ForEach-Object { "clientAppUsed eq '$_'" }) -join ' or ')
    $signins = @(Get-MgAuditLogSignIn -All -Filter "createdDateTime ge $since and ($clientFilter)" -ErrorAction Stop |
        Where-Object { $_.ClientAppUsed -and $_.ClientAppUsed -match $legacyClients })

    $rows = $signins | Select-Object CreatedDateTime, UserPrincipalName, ClientAppUsed, AppDisplayName,
        @{n='Status';e={ $_.Status.ErrorCode }}, IPAddress | Sort-Object CreatedDateTime -Descending
    $src = Write-Evidence -BaseName 'legacy_auth_signins' -Rows $rows -Title 'Legacy Authentication Sign-ins (last 30 days)' `
        -Notes @('Status 0 = successful sign-in; 53003 = blocked by Conditional Access; any other code = failed for another reason (for example a wrong password).')

    $success = @($signins | Where-Object { $_.Status.ErrorCode -eq 0 })
    $failOnly = @($signins | Where-Object { $_.Status.ErrorCode -ne 0 })

    if ($success.Count -gt 0) {
        $upns = @($success | Select-Object -ExpandProperty UserPrincipalName -Unique)
        Add-EntraFinding -Severity 'High' -CheckId 'legacyauth' -Category 'Authentication' -RuleId 'legacyauth-successful-signins' `
            -Title ((Format-EACount -Count $success.Count -One 'successful sign-in' -Many 'successful sign-ins') + ' used legacy authentication in the last 30 days') `
            -Evidence ("Successful legacy sign-ins by {0} via {1}. First {2}: {3}" -f (Format-EACount -Count $upns.Count -One 'account' -Many 'accounts'), (($success.ClientAppUsed | Select-Object -Unique) -join ', '), (Format-EACount -Count ([Math]::Min(10, $upns.Count)) -One 'account' -Many 'accounts'), (($upns | Select-Object -First 10) -join ', ')) `
            -WhyItMatters 'Legacy authentication (old protocols such as POP, IMAP, SMTP and older Exchange ActiveSync clients) cannot ask for multifactor authentication (MFA). A successful legacy sign-in shows that a password alone still works, which is exactly what password-spray attacks use.' `
            -RecommendedAction 'Block legacy authentication for all users with a Conditional Access policy (Entra admin center > Entra ID > Conditional Access; condition Client apps = Exchange ActiveSync clients + Other clients, grant = Block), after moving the listed users and devices to modern authentication.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication' `
            -SourceFile $src -ResultRows @($success | Select-Object CreatedDateTime,UserPrincipalName,ClientAppUsed | Select-Object -First 50) `
            -VerificationType HistoricalEvent -VerificationSteps 'Record the remediation time, confirm the intended legacy-authentication block applies, and review sign-ins after that time for new successful legacy use. Historical events remain in the rolling 30-day window; their immediate disappearance is not required.' `
            -AffectedObjectIds @($success | ForEach-Object { $_.UserId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType user -PopulationLabel 'identified users in successful legacy sign-in events (last 30 days)'
    } elseif ($failOnly.Count -gt 0) {
        $caBlocked = @($failOnly | Where-Object { $_.Status.ErrorCode -eq 53003 }).Count
        $codes = ($failOnly | Group-Object { $_.Status.ErrorCode } | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', '
        Add-EntraFinding -Severity 'Low' -CheckId 'legacyauth' -Category 'Authentication' -RuleId 'legacyauth-failed-attempts-only' `
            -Title ('Legacy authentication was tried {0} in 30 days - {1} failed' -f $(if ($failOnly.Count -eq 1) { 'once' } else { '{0} times' -f $failOnly.Count }), $(if ($failOnly.Count -eq 1) { 'the attempt' } else { 'every attempt' })) `
            -Evidence ("{0} by {1}; {2} blocked by Conditional Access (error 53003). Most common error codes: {3}." -f (Format-EACount -Count $failOnly.Count -One 'failed legacy sign-in attempt' -Many 'failed legacy sign-in attempts'), (Format-EACount -Count @($failOnly | Select-Object -ExpandProperty UserPrincipalName -Unique).Count -One 'account' -Many 'accounts'), $caBlocked, $codes) `
            -WhyItMatters 'No legacy sign-in succeeded, but devices or attackers are still trying. Failures that are not Conditional Access blocks (for example wrong passwords) do not prove a block exists, and the risk returns if a block is ever removed.' `
            -RecommendedAction 'Confirm a Conditional Access policy blocks legacy authentication for all users, and fix or retire the clients that still try it.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication' `
            -SourceFile $src -ResultRows @($failOnly | Select-Object CreatedDateTime,UserPrincipalName,ClientAppUsed,@{n='Status';e={ $_.Status.ErrorCode }} | Select-Object -First 50) `
            -VerificationType HistoricalEvent -VerificationSteps 'Record the remediation time, confirm the intended legacy-authentication block applies, and review sign-ins after that time for new successful legacy use. Historical events remain in the rolling 30-day window; their immediate disappearance is not required.' `
            -AffectedObjectIds @($failOnly | ForEach-Object { $_.UserId } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType user -PopulationLabel 'identified users in failed legacy sign-in events (last 30 days)'
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId 'legacyauth' -Category 'Authentication' -RuleId 'legacyauth-none-seen' `
            -Title 'No legacy-authentication sign-ins in the last 30 days' `
            -Evidence 'The sign-in logs for the last 30 days contain no sign-ins through legacy protocols.' `
            -WhyItMatters 'No legacy authentication was used in the period the logs cover, which suggests only modern sign-ins (that support MFA) are in use.' `
            -RecommendedAction 'Keep a Conditional Access policy that blocks legacy authentication for all users.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication' -SourceFile $src
    }
}
