<#
Identity Protection (Risky Service Principals). Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-RiskyServicePrincipals {
    # Risky service principals (v1.0, best-effort). Track read SUCCESS separately from
    # result count: an errored read must surface as a coverage gap, never as "clean".
    $readOk = $true; $readError = $null; $licenseDenied = $false
    $rsp = @()
    try {
        if (Get-Command Get-MgRiskyServicePrincipal -ErrorAction SilentlyContinue) {
            $rsp = @(Get-MgRiskyServicePrincipal -All -ErrorAction Stop | Where-Object { [string](Get-EAField $_ 'RiskState') -in @('atRisk','confirmedCompromised') })
        } else {
            # Raw fallback: paginate (first page only would under-report) against v1.0.
            $uri = 'https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals'
            $acc = @(); $guard = 0
            while ($uri -and $guard -lt 50) {
                $uri = Assert-EAGraphReadUri $uri
                $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                if ($resp['value']) { $acc += @($resp['value']) }
                $uri = $resp['@odata.nextLink']; $guard++
            }
            if ($uri) { throw 'Microsoft Graph risky-service-principal pagination exceeded the 50-page safety limit.' }
            $rsp = @($acc | Where-Object { [string](Get-EAField $_ 'riskState') -in @('atRisk','confirmedCompromised') })
        }
    } catch {
        $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch { $code = $null }
        $denied = ($code -in 401,403) -or ("$_" -match 'Authorization_RequestDenied|Insufficient privileges')
        # Graph answers 403 "not licensed" when the tenant lacks Workload ID Premium. That is a
        # licence gap reported by the service itself, not a missing permission - report it as
        # "not licensed" (coverage gap) instead of letting it surface as Skipped-NoPermission.
        if ($denied -and "$_" -match '(?i)licen[cs]') { $licenseDenied = $true }
        # Genuine permission failures land in the posture summary as Skipped-NoPermission.
        elseif ($denied) { throw }
        $readOk = $false; $readError = $_.Exception.Message
    }

    $rsprows = @($rsp | Select-Object @{n='DisplayName';e={ Get-EAField $_ 'DisplayName' }},
        @{n='AppId';e={ Get-EAField $_ 'AppId' }},
        @{n='RiskLevel';e={ Get-EAField $_ 'RiskLevel' }},
        @{n='RiskState';e={ Get-EAField $_ 'RiskState' }},
        @{n='RiskDetail';e={ Get-EAField $_ 'RiskDetail' }},
        @{n='RiskLastUpdatedDateTime';e={ Get-EAField $_ 'RiskLastUpdatedDateTime' }},
        @{n='Id';e={ Get-EAField $_ 'Id' }})
    $notes = @()
    if ($licenseDenied) { $notes += "NOT LICENSED: Microsoft Graph refused the read because the tenant is not licensed for risky workload identities ($readError). This list is not assessed, not empty." }
    elseif (-not $readOk) { $notes += "READ FAILED: risky service principals could not be read ($readError). This list is unknown, not empty." }
    if (-not $script:WorkloadIdP) {
        $notes += $(if ($script:LicenseKnown) { 'Workload ID Premium was not detected: an empty list does not mean no risky workload identities.' }
                    else { 'The licence read failed, so it is unknown whether Workload ID Premium is present: an empty list does not mean no risky workload identities.' })
    }
    # Always write the evidence, so an empty list is visible and distinguishable from a failed read.
    $src = Write-Evidence -BaseName 'risky_serviceprincipals' -Rows $rsprows -Title 'Identity Protection - Risky Service Principals' -Notes $notes

    if ($readOk -and $rsp.Count -gt 0) {
        $names = @($rsprows | ForEach-Object { '{0} ({1} risk, {2})' -f $_.DisplayName, $_.RiskLevel, $_.RiskState })
        $shown = @($names | Select-Object -First 10)
        $nameText = ($shown -join ', ') + $(if ($names.Count -gt $shown.Count) { ' (+{0} more)' -f ($names.Count - $shown.Count) } else { '' })
        Add-EntraFinding -Severity 'High' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title $(if ($rsp.Count -eq 1) { '1 app identity (service principal) is flagged as risky or compromised' } else { "{0} app identities (service principals) are flagged as risky or compromised" -f $rsp.Count }) `
            -Evidence ("Risky service principals: {0}." -f $nameText) `
            -WhyItMatters 'A compromised app identity (service principal) can use its granted permissions - often to mail, files or the directory - without any user signing in, so misuse is easy to miss.' `
            -RecommendedAction 'Investigate each flagged service principal: review its recent sign-ins and permissions, remove or rotate its secrets and certificates, then confirm the compromise or dismiss the risk in Entra admin center > ID Protection > Risky workload identities.' `
            -SourceFile $src -ResultRows $rsprows -RuleId 'riskyserviceprincipals-at-risk' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk' `
            -AffectedObjectIds @($rsprows | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'servicePrincipal' -AffectedCount $rsprows.Count -PopulationLabel 'service principals currently flagged at risk'
        return
    }

    # Risky service principals are licensed separately from P2 risky users (they need
    # Microsoft Entra Workload ID Premium). Report coverage explicitly: a failed read or a missing
    # (or unknown) licence is "not assessed", never clean; only a licensed, successful read is clean.
    if ($licenseDenied) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'Risky workload identities were not checked (needs Workload ID Premium)' `
            -Evidence ("Microsoft Graph refused to list risky service principals because the tenant is not licensed for it: {0}. Licence detection at the start of the audit: Workload ID Premium {1}. The result is not assessed, not clean." -f $readError, $(if ($script:WorkloadIdP) { 'was detected' } elseif ($script:LicenseKnown) { 'was not detected' } else { 'is unknown (the licence read failed)' })) `
            -WhyItMatters 'Risk detection for app identities (service principals) spots stolen app credentials. Entra ID P2 alone does not include it.' `
            -RecommendedAction 'License Microsoft Entra Workload ID Premium if you need automatic risk detection for app identities.' `
            -SourceFile $src -RuleId 'riskyserviceprincipals-not-licensed' -ObjectType 'tenant' -CoverageGap `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk'
    } elseif (-not $readOk) {
        $licText = if ($script:WorkloadIdP) { 'Workload ID Premium is present.' } elseif ($script:LicenseKnown) { 'Workload ID Premium was also not detected.' } else { 'The licence read also failed, so Workload ID Premium status is unknown.' }
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'Risky workload identities could not be read (result unknown, not clean)' `
            -Evidence ("Reading risky service principals failed: {0}. {1} The result is unknown, not ""no risky workload identities""." -f $readError, $licText) `
            -WhyItMatters 'A failed read must not be mistaken for a clean result: compromised app identities (service principals) may exist unseen.' `
            -RecommendedAction 'Re-run the audit (or just -riskyserviceprincipals) when Microsoft Graph is reachable.' `
            -SourceFile $src -RuleId 'riskyserviceprincipals-read-failed' -ObjectType 'tenant' -CoverageGap
    } elseif (-not $script:WorkloadIdP -and $script:LicenseKnown) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'Risky workload identities were not checked (needs Workload ID Premium)' `
            -Evidence 'The tenant''s licences were read and Microsoft Entra Workload ID Premium was not found. Without it Identity Protection does not report risky workload identities, so an empty list is "not assessed", not clean.' `
            -WhyItMatters 'Risk detection for app identities (service principals) spots stolen app credentials. Entra ID P2 alone does not include it.' `
            -RecommendedAction 'License Microsoft Entra Workload ID Premium if you need automatic risk detection for app identities.' `
            -SourceFile $src -RuleId 'riskyserviceprincipals-not-licensed' -ObjectType 'tenant' -CoverageGap `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk'
    } elseif (-not $script:WorkloadIdP) {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'Risky workload identities were not checked (licences could not be read)' `
            -Evidence 'The licence (subscribed SKU) read failed at the start of the audit, so it is unknown whether Microsoft Entra Workload ID Premium is present. The empty risky-service-principal list may simply reflect a missing licence; the result is unknown, not clean.' `
            -WhyItMatters 'Risk detection for app identities (service principals) spots stolen app credentials; the audit cannot tell whether it is active in this tenant.' `
            -RecommendedAction 'Make sure the audit account can read subscriptions (Organization.Read.All) and re-run the riskyserviceprincipals check.' `
            -SourceFile $src -RuleId 'riskyserviceprincipals-license-unknown' -ObjectType 'tenant' -CoverageGap
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId 'riskyserviceprincipals' -Category 'Threat Signals' `
            -Title 'No app identities (service principals) are flagged as risky' `
            -Evidence 'Workload ID Premium is present and Identity Protection currently flags no service principal as at risk or confirmed compromised.' `
            -WhyItMatters 'Identity Protection flags app identities (service principals) whose credentials show signs of compromise.' `
            -RecommendedAction 'Keep risk-based Conditional Access for workload identities enabled and review flagged service principals promptly.' `
            -SourceFile $src -RuleId 'riskyserviceprincipals-none-flagged' -ObjectType 'tenant'
    }
}
