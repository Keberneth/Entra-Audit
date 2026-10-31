<#
Directory-Sync / PHS Health. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-TenantHealth {
    $checkId = 'tenanthealth'; $category = 'Platform Health'
    $featuresDoc = 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-syncservice-features'

    # Organization object: reuse the tenant-info / start-up read when it succeeded. A failed
    # read is tracked - an unreadable organization must never be reported as "cloud-only".
    $orgError = $null
    if (-not $script:Tenant) {
        try { $script:Tenant = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1 } catch { $orgError = $_.Exception.Message }
    }
    $org = $script:Tenant
    $sync = $null; $syncError = $null
    try { $sync = Get-MgDirectoryOnPremiseSynchronization -ErrorAction Stop | Select-Object -First 1 } catch { $syncError = $_.Exception.Message }

    # organization.onPremisesSyncEnabled: true = syncing; false = WAS synced, sync since
    # switched off; null = never synced (cloud-only).
    $syncEnabled = if ($org) { Get-EAField $org 'OnPremisesSyncEnabled' } else { $null }
    $lastSync = if ($org) { Get-EAField $org 'OnPremisesLastSyncDateTime' } else { $null }
    $lastSyncUtc = $null
    if ($lastSync) {
        try {
            $lastSyncUtc = if ($lastSync -is [datetimeoffset]) { $lastSync.UtcDateTime }
                           else { $d = [datetime]$lastSync; if ($d.Kind -eq [System.DateTimeKind]::Local) { $d.ToUniversalTime() } else { $d } }
        } catch { $lastSyncUtc = $null }
    }
    $lastSyncText = if ($lastSyncUtc) { $lastSyncUtc.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { 'not returned' }
    # A $null feature value means "not returned" - it is reported as unknown, never as off.
    $features = if ($sync) { Get-EAField $sync 'Features' } else { $null }
    $phs       = if ($features) { Get-EAField $features 'PasswordSyncEnabled' } else { $null }
    $softBlock = if ($features) { Get-EAField $features 'BlockSoftMatchEnabled' } else { $null }
    $hardBlock = if ($features) { Get-EAField $features 'BlockCloudObjectTakeoverThroughHardMatchEnabled' } else { $null }
    $cloudPwd  = if ($features) { Get-EAField $features 'CloudPasswordPolicyForPasswordSyncedUsersEnabled' } else { $null }

    $rows = New-Object System.Collections.Generic.List[object]
    if ($org) {
        $rows.Add([pscustomobject]@{ Property='OnPremisesSyncEnabled'; Value=$(if ($null -eq $syncEnabled) { '(not set)' } else { $syncEnabled })
            Meaning='true = accounts sync from on-premises AD; false = sync was used but is now switched off; not set = never synced (cloud-only)' }) | Out-Null
        $rows.Add([pscustomobject]@{ Property='OnPremisesLastSyncDateTime'; Value=$lastSyncText; Meaning='Last time Entra Connect / Cloud Sync pushed changes (normally every 30 minutes)' }) | Out-Null
    }
    if ($sync) {
        foreach ($f in @(
            @{ Name='PasswordSyncEnabled'; Value=$phs; Meaning='Password hash sync (needed for leaked-credential detection and as a sign-in fallback)' }
            @{ Name='BlockSoftMatchEnabled'; Value=$softBlock; Meaning='true = on-premises accounts cannot take over cloud accounts by matching email address / UPN' }
            @{ Name='BlockCloudObjectTakeoverThroughHardMatchEnabled'; Value=$hardBlock; Meaning='true = on-premises accounts cannot take over cloud accounts by matching the immutable id' }
            @{ Name='CloudPasswordPolicyForPasswordSyncedUsersEnabled'; Value=$cloudPwd; Meaning='true = the cloud password-expiry policy also applies to password-synced users' }
        )) {
            $rows.Add([pscustomobject]@{ Property=$f.Name; Value=$(if ($null -eq $f.Value) { '(not returned)' } else { $f.Value }); Meaning=$f.Meaning }) | Out-Null
        }
    }
    $notes = @()
    if (-not $org) { $notes += ('The organization object could not be read: {0}' -f $(if ($orgError) { $orgError } else { 'no data returned' })) }
    if ($syncError) { $notes += ('The on-premises synchronization settings could not be read: {0}' -f $syncError) }
    elseif (-not $sync) { $notes += 'The on-premises synchronization settings returned no data.' }
    $src = Write-Evidence -BaseName 'tenant_health' -Rows $rows.ToArray() -Title 'Directory-Sync / PHS Platform Health' -Notes $notes

    if (-not $org) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Directory sync health could not be checked (organization details unreadable)' `
            -Evidence ("Reading the organization object failed: {0}. Whether the tenant syncs accounts from on-premises Active Directory, and how recently, is unknown - this is not a clean result." -f $(if ($orgError) { $orgError } else { 'no data returned' })) `
            -WhyItMatters 'If accounts sync from on-premises Active Directory (AD), a broken or weakly configured sync can leave departed staff active in the cloud or let on-premises accounts take over cloud accounts. None of this could be checked.' `
            -RecommendedAction 'Grant Organization.Read.All (Global Reader for a delegated run) and re-run the tenanthealth check.' `
            -SourceFile $src -RuleId 'tenanthealth-org-unreadable' -ObjectType 'tenant' -CoverageGap
        return
    }
    if ($null -eq $syncEnabled) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'No directory sync from on-premises AD (cloud-only tenant)' `
            -Evidence 'OnPremisesSyncEnabled is not set on the organization: the tenant has never synced from an on-premises directory.' `
            -WhyItMatters 'A cloud-only tenant has no on-premises Active Directory (AD) sync to monitor, so the sync health checks do not apply. This is expected, not an error.' `
            -RecommendedAction 'No action needed.' -SourceFile $src -RuleId 'tenanthealth-cloud-only' -ObjectType 'tenant'
        return
    }
    if ($syncEnabled -eq $false) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Directory sync from on-premises AD has been switched off' `
            -Evidence ("OnPremisesSyncEnabled = false: the tenant used to sync from an on-premises directory, but sync is now off. Last sync: {0}." -f $lastSyncText) `
            -WhyItMatters 'Accounts that came from on-premises Active Directory (AD) are now managed only in the cloud. If sync was switched off by mistake, staff disabled on-premises stay active in Microsoft 365.' `
            -RecommendedAction 'Confirm that switching off sync was a planned change. If it was not, find out who changed it (Entra admin center > Monitoring & health > Audit logs) and restore Entra Connect sync.' `
            -SourceFile $src -RuleId 'tenanthealth-sync-switched-off' -ObjectType 'tenant'
        return
    }

    # Hybrid tenant. The sync age comes from the organization object alone, so it is judged
    # even when the synchronization settings below cannot be read.
    $emitted = 0
    if ($lastSyncUtc) {
        $hoursAgo = ((Get-Date).ToUniversalTime() - $lastSyncUtc).TotalHours
        if ($hoursAgo -gt 3) {
            $emitted++
            $agoText = if ($hoursAgo -ge 48) { '{0} days' -f [int][math]::Floor($hoursAgo / 24) } else { '{0} hours' -f [int][math]::Floor($hoursAgo) }
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title ("Directory sync from on-premises AD has not run for {0}" -f $agoText) `
                -Evidence ("OnPremisesLastSyncDateTime = {0} ({1} ago). Entra Connect normally syncs every 30 minutes; this check flags anything older than 3 hours." -f $lastSyncText, $agoText) `
                -WhyItMatters 'While sync is stuck, accounts disabled or removed in on-premises Active Directory (AD) stay active in the cloud, so a departed employee or a locked-out attacker can keep signing in to Microsoft 365.' `
                -RecommendedAction 'Check the Entra Connect server and its sync service, fix the error it reports and confirm that sync runs every 30 minutes again (Entra admin center > Entra ID > Entra Connect).' `
                -SourceFile $src -RuleId 'tenanthealth-sync-stale' -ObjectType 'tenant' `
                -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler'
        }
    } else {
        $emitted++
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Time of the last directory sync is unknown' `
            -Evidence 'OnPremisesSyncEnabled = true, but OnPremisesLastSyncDateTime was not returned. Whether sync is running could not be assessed - this is not a clean result.' `
            -WhyItMatters 'Without the last sync time the audit cannot tell whether changes made in on-premises Active Directory (AD), such as disabled leavers, still reach the cloud.' `
            -RecommendedAction 'Check the last sync time in Entra admin center > Entra ID > Entra Connect.' `
            -SourceFile $src -RuleId 'tenanthealth-last-sync-unknown' -ObjectType 'tenant' -CoverageGap
    }

    if (-not $sync) {
        # Hybrid tenant, but the on-prem sync configuration could not be read - do NOT fall
        # through to the "healthy" baseline, which would be a false sense of coverage.
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Directory sync settings could not be read, so sync security was not checked' `
            -Evidence ("Tenant is hybrid (OnPremisesSyncEnabled = true), but Get-MgDirectoryOnPremiseSynchronization {0}. Password hash sync, soft-match blocking and the cloud password policy for synced users are unknown - this is not a clean result." -f $(if ($syncError) { 'failed: ' + $syncError } else { 'returned no data' })) `
            -WhyItMatters 'These settings decide whether leaked passwords can be detected and whether on-premises accounts can take over cloud accounts. Without them a "healthy" result would be misleading.' `
            -RecommendedAction 'Grant OnPremDirectorySynchronization.Read.All and re-run the tenanthealth check.' `
            -SourceFile $src -RuleId 'tenanthealth-sync-settings-unreadable' -ObjectType 'tenant' -CoverageGap
        return
    }

    $unknown = @()
    if ($null -eq $phs) { $unknown += 'PasswordSyncEnabled' }
    elseif (-not [bool]$phs) {
        $emitted++
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'Password hash sync is off, so leaked passwords are not detected' `
            -Evidence 'PasswordSyncEnabled = false on a tenant that syncs from on-premises AD (OnPremisesSyncEnabled = true).' `
            -WhyItMatters 'Without password hash sync (PHS), Microsoft cannot warn you when a user password appears in a known leak (leaked-credential detection), and there is no quick backup sign-in method if federation or pass-through authentication servers fail.' `
            -RecommendedAction 'Turn on password hash sync in Entra Connect, even if users sign in through federation or pass-through authentication; it is then used for leaked-credential detection and as a fallback.' `
            -SourceFile $src -RuleId 'tenanthealth-phs-disabled' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-phs'
    }
    if ($null -eq $softBlock) { $unknown += 'BlockSoftMatchEnabled' }
    elseif (-not [bool]$softBlock) {
        $emitted++
        Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
            -Title 'On-premises accounts can take over cloud accounts (soft-match not blocked)' `
            -Evidence ('BlockSoftMatchEnabled = false. Related: BlockCloudObjectTakeoverThroughHardMatchEnabled = {0}.' -f $(if ($null -eq $hardBlock) { '(not returned)' } else { $hardBlock })) `
            -WhyItMatters 'Anyone who can create or edit accounts in on-premises Active Directory (AD) can create one with the same email address or sign-in name as a cloud-only account. The next sync links the two and hands control of the cloud account to on-premises AD.' `
            -RecommendedAction 'Once the initial account matching is complete, block soft-match. There is no admin-center switch for this: in Microsoft Graph PowerShell run Update-MgDirectoryOnPremiseSynchronization -OnPremisesDirectorySynchronizationId (Get-MgDirectoryOnPremiseSynchronization).Id -Features @{ BlockSoftMatchEnabled = $true }. Turn it off only briefly when a new account or hybrid-joined device must be matched.' `
            -SourceFile $src -RuleId 'tenanthealth-softmatch-not-blocked' -ObjectType 'tenant' -DocumentationUrl $featuresDoc
    }
    if ($phs -ne $false) {
        if ($null -eq $cloudPwd) { $unknown += 'CloudPasswordPolicyForPasswordSyncedUsersEnabled' }
        elseif ($phs -eq $true -and -not [bool]$cloudPwd) {
            $emitted++
            Add-EntraFinding -Severity 'Medium' -CheckId $checkId -Category $category `
                -Title 'Synced users can keep signing in with passwords that expired on-premises' `
                -Evidence 'PasswordSyncEnabled = true and CloudPasswordPolicyForPasswordSyncedUsersEnabled = false, so the cloud password of password-synced users is set to never expire (DisablePasswordExpiration).' `
                -WhyItMatters 'When a password expires in on-premises Active Directory (AD), its synced cloud copy does not, so the user can keep signing in to Microsoft 365 with the old password. Forced password changes on-premises therefore do not protect cloud sign-ins.' `
                -RecommendedAction 'After checking the effect on federated and pass-through users, make synced passwords expire in the cloud too. There is no admin-center switch for this: in Microsoft Graph PowerShell run Update-MgDirectoryOnPremiseSynchronization -OnPremisesDirectorySynchronizationId (Get-MgDirectoryOnPremiseSynchronization).Id -Features @{ CloudPasswordPolicyForPasswordSyncedUsersEnabled = $true }, then align the cloud password-expiry policy with the on-premises one.' `
                -SourceFile $src -RuleId 'tenanthealth-cloud-password-policy-off' -ObjectType 'tenant' -DocumentationUrl $featuresDoc
        }
    }
    if ($unknown.Count -gt 0) {
        $emitted++
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Some directory sync settings were not returned, so they could not be checked' `
            -Evidence ("Not returned by Microsoft Graph: {0}. These settings are unknown, not assumed on or off." -f ($unknown -join ', ')) `
            -WhyItMatters 'These settings control password hash sync, whether on-premises accounts can take over cloud accounts, and whether synced passwords expire in the cloud. Unknown values could hide a weak configuration.' `
            -RecommendedAction 'Re-run with OnPremDirectorySynchronization.Read.All and verify the sync features in the Entra Connect configuration.' `
            -SourceFile $src -RuleId 'tenanthealth-sync-settings-unknown' -ObjectType 'tenant' -CoverageGap -DocumentationUrl $featuresDoc
    }
    if ($emitted -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId $checkId -Category $category `
            -Title 'Directory sync is healthy (recent, with password hash sync and soft-match blocking on)' `
            -Evidence ("Last sync: {0}. PasswordSyncEnabled = true; BlockSoftMatchEnabled = true; CloudPasswordPolicyForPasswordSyncedUsersEnabled = {1}." -f $lastSyncText, $(if ($null -eq $cloudPwd) { '(not returned)' } else { $cloudPwd })) `
            -WhyItMatters 'A healthy sync keeps cloud accounts in step with on-premises Active Directory (AD), so leavers are disabled everywhere and leaked passwords can be detected.' `
            -RecommendedAction 'Keep Entra Connect health monitoring and alerting in place.' `
            -SourceFile $src -RuleId 'tenanthealth-baseline' -ObjectType 'tenant'
    }
}
