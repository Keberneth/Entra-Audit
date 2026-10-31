<#
Tenant / Organization Overview. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-TenantInfo {
    # Finding ids in this region (tenant-info .. tenantposture) use explicit -RuleId values
    # ('<checkid>-<rule>'), introduced together with the plain-language titles as a one-time
    # id migration, so later wording changes can never change a finding id again.
    $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
    if (-not $org) { throw 'The organization object could not be read - the tenant overview is UNKNOWN, not clean.' }
    $script:Tenant = $org
    # The SKU list only enriches the evidence (licensing is detected at start-up), but a
    # failed read must show as "could not be read", never as "no subscriptions".
    $skus = @(); $skuError = $null
    try { $skus = @(Get-MgSubscribedSku -All -ErrorAction Stop) } catch { $skuError = $_.Exception.Message }

    $verified = @($org.VerifiedDomains | ForEach-Object { "$($_.Name)$(if($_.IsDefault){' (default)'})$(if($_.Type -eq 'Federated'){' [FEDERATED]'})" })
    # Filter empties: @($null) has Count 1, which would hide the "not configured" finding.
    $techMails = @($org.TechnicalNotificationMails | Where-Object { $_ })
    $secMails  = @((Get-EAField $org 'SecurityComplianceNotificationMails') | Where-Object { $_ })

    $rows = @()
    $rows += [pscustomobject]@{ Property='Tenant';            Value=$org.DisplayName }
    $rows += [pscustomobject]@{ Property='Tenant Id';         Value=$org.Id }
    $rows += [pscustomobject]@{ Property='Created';           Value=$org.CreatedDateTime }
    $rows += [pscustomobject]@{ Property='Country';           Value=$org.CountryLetterCode }
    $rows += [pscustomobject]@{ Property='Verified domains';  Value=($verified -join '; ') }
    $rows += [pscustomobject]@{ Property='Tech notification'; Value=($techMails -join '; ') }
    $rows += [pscustomobject]@{ Property='Security notification'; Value=($secMails -join '; ') }
    $rows += [pscustomobject]@{ Property='Licensing';         Value=("P1={0}; P2={1}; WorkloadId={2}" -f $script:HasP1,$script:HasP2,$script:WorkloadIdP) }
    if ($skuError) { $rows += [pscustomobject]@{ Property='Subscriptions (SKUs)'; Value=("Could not be read: {0}" -f $skuError) } }
    foreach ($s in $skus) {
        $rows += [pscustomobject]@{ Property=("SKU {0}" -f $s.SkuPartNumber); Value=("{0}/{1} consumed/enabled" -f $s.ConsumedUnits, $s.PrepaidUnits.Enabled) }
    }
    $notes = @()
    if ($skuError) { $notes += ("The subscription (SKU) list could not be read: {0}" -f $skuError) }
    $src = Write-Evidence -BaseName 'tenant_info' -Rows $rows -Title 'Tenant / Organization Overview' -Notes $notes

    if ($techMails.Count -eq 0 -or $secMails.Count -eq 0) {
        $title = if ($techMails.Count -eq 0 -and $secMails.Count -eq 0) { 'No email address is set for Microsoft security and technical notices' }
                 elseif ($secMails.Count -eq 0) { 'No email address is set for Microsoft security notices' }
                 else { 'No email address is set for Microsoft technical notices' }
        Add-EntraFinding -Severity 'Low' -CheckId 'tenant-info' -Category 'Tenant Posture' -RuleId 'tenant-info-notification-contacts-missing' `
            -Title $title `
            -Evidence ("Technical notification addresses (technicalNotificationMails): {0}; security and compliance notification addresses (securityComplianceNotificationMails): {1}." -f $techMails.Count, $secMails.Count) `
            -WhyItMatters 'Microsoft sends service, security and compliance warnings about the tenant to these addresses. If none is set, those warnings reach nobody.' `
            -RecommendedAction 'Set both notification addresses to a monitored shared mailbox or distribution list, not one person. The technical contact is under Entra admin center > Entra ID > Overview > Properties.' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/fundamentals/properties-area' `
            -SourceFile $src -ResultRows $rows
    } else {
        Add-EntraFinding -Severity 'Information' -CheckId 'tenant-info' -Category 'Tenant Posture' -RuleId 'tenant-info-overview' `
            -Title 'Tenant overview' `
            -Evidence ("{0} ({1}); verified domains: {2}; Entra ID P1: {3}; P2: {4}; subscriptions (SKUs): {5}." -f $org.DisplayName, $org.Id, $verified.Count, $script:HasP1, $script:HasP2, $(if ($skuError) { 'could not be read' } else { $skus.Count })) `
            -WhyItMatters 'Basic facts about the tenant - its domains and licences - which decide what security features (such as Conditional Access or Privileged Identity Management) it can use.' `
            -RecommendedAction 'No action needed - background for the rest of the report.' `
            -SourceFile $src -ResultRows $rows
    }
}
