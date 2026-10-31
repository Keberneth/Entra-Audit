<#
Stale / Unmanaged Devices. Definition only; dot-source through EntraAudit.Loader.ps1.
Shared caches and findings live in the runner's script scope. No tenant calls occur on load.
#>

function Invoke-Check-Devices {
    # RegistrationDateTime is needed to age a device that has NO sign-in on record: a device
    # registered yesterday (Autopilot pre-provisioning, a fresh join before its first token
    # refresh) has a null approximateLastSignInDateTime and must not be reported as
    # "no sign-in for 90 days". -PageSize 999: device inventories are among the largest
    # collections in a tenant and the service default page is only 100.
    $devices = @(Get-MgDevice -All -PageSize 999 -Property Id,DeviceId,DisplayName,AccountEnabled,ApproximateLastSignInDateTime,RegistrationDateTime,IsManaged,IsCompliant,TrustType,OperatingSystem,OperatingSystemVersion -ErrorAction Stop)
    $cut = (Get-Date).ToUniversalTime().AddDays(-$InactiveDays)
    $cutText = $cut.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)

    # Classify every device exactly once (Lists, not array +=: inventories can be 100k+).
    #   Stale       - last sign-in older than the window, or no sign-in on record AND
    #                 registered before the window (same rule as the staleapps check).
    #   Unknown age - neither timestamp returned: cannot be judged, never assumed active.
    #   Active      - everything else.
    $stale = New-Object System.Collections.Generic.List[object]
    $unknownAge = New-Object System.Collections.Generic.List[object]
    $activityById = @{}
    foreach ($d in $devices) {
        $last = $d.ApproximateLastSignInDateTime
        $registered = $d.RegistrationDateTime
        $activity = if ($last) { if ($last -lt $cut) { 'Stale' } else { 'Active' } }
                    elseif ($registered) { if ($registered -lt $cut) { 'Stale (never signed in)' } else { 'Active (newly registered)' } }
                    else { 'Unknown age' }
        if ($d.Id) { $activityById[[string]$d.Id] = $activity }
        if ($activity -like 'Stale*') { $stale.Add($d) | Out-Null }
        elseif ($activity -eq 'Unknown age') { $unknownAge.Add($d) | Out-Null }
    }
    $joinTypeText = {
        param($trustType)
        switch ([string]$trustType) {
            'Workplace' { 'Entra registered (personal / BYOD)' }
            'AzureAd'   { 'Entra joined' }
            'ServerAd'  { 'Hybrid joined (synced from on-prem AD)' }
            ''          { 'Unknown' }
            default     { [string]$trustType }
        }
    }
    $rows = @($devices | Select-Object DisplayName, AccountEnabled,
        @{n='Activity';e={ $activityById[[string]$_.Id] }},
        ApproximateLastSignInDateTime, RegistrationDateTime, IsManaged, IsCompliant,
        @{n='JoinType';e={ & $joinTypeText $_.TrustType }}, TrustType, OperatingSystem, OperatingSystemVersion, DeviceId)
    $src = Write-Evidence -BaseName 'devices' -Rows $rows -Title 'Devices' -Notes @(
        ("Stale = last sign-in (approximateLastSignInDateTime) before {0} ({1} days), or no sign-in on record and registered before that date." -f $cutText, $InactiveDays),
        'approximateLastSignInDateTime is only refreshed about every 14 days, so it is an approximate value.',
        'Unknown age = neither a sign-in time nor a registration date was returned for the device.',
        ("Devices: {0}; stale: {1}; unknown age: {2}." -f $devices.Count, $stale.Count, $unknownAge.Count))

    # A stale device is reported once, as stale. Counting it again as "unmanaged" would
    # double-score the same dead object and overstate the live Conditional Access surface.
    $staleIds = @{}
    foreach ($d in $stale) { if ($d.Id) { $staleIds[[string]$d.Id] = $true } }
    $unmanaged = @($devices | Where-Object {
        $_.AccountEnabled -and -not $staleIds.ContainsKey([string]$_.Id) -and ($_.IsManaged -eq $false -or $_.IsCompliant -eq $false)
    })
    # A false value establishes an issue even if the other property is missing.
    # A clean management/compliance result requires both values to be true.
    $managementPopulation = @($devices | Where-Object { $_.AccountEnabled -and -not $staleIds.ContainsKey([string]$_.Id) })
    $managementAssessed = @($managementPopulation | Where-Object {
        $_.IsManaged -eq $false -or $_.IsCompliant -eq $false -or ($_.IsManaged -eq $true -and $_.IsCompliant -eq $true)
    })

    if ($stale.Count -gt 0) {
        $staleEnabled = @($stale | Where-Object { $_.AccountEnabled }).Count
        $staleNever = @($stale | Where-Object { -not $_.ApproximateLastSignInDateTime }).Count
        $staleHybrid = @($stale | Where-Object { [string]$_.TrustType -eq 'ServerAd' }).Count
        Add-EntraFinding -Severity 'Medium' -CheckId 'devices' -Category 'Devices' `
            -Title ("{0} not signed in for more than {1} days" -f (Format-EACount -Count $stale.Count -One 'device has' -Many 'devices have'), $InactiveDays) `
            -Evidence ("Stale device records: {0} ({1} still enabled, {2} disabled). {3} registered before {4}. {5} hybrid joined (synced from on-premises AD). Cut-off: no sign-in since {4} ({6} days); the sign-in time is refreshed only about every 14 days." -f `
                $stale.Count, $staleEnabled, ($stale.Count - $staleEnabled), (Format-EACount -Count $staleNever -One 'of them never signed in and was' -Many 'of them never signed in and were'), $cutText, (Format-EACount -Count $staleHybrid -One 'is' -Many 'are'), $InactiveDays) `
            -WhyItMatters 'An old device record that is still enabled keeps counting as a known company device, so a lost, sold or rebuilt laptop can go on satisfying Conditional Access (CA) rules that require a registered or compliant device. Clutter also makes the device inventory hard to trust.' `
            -RecommendedAction ("Disable device records with no sign-in for more than {0} days, then delete them after a grace period (Entra admin center > Devices > All devices, filter on activity). Clean up hybrid-joined devices in on-premises Active Directory first, or sync will bring them back." -f $InactiveDays) `
            -SourceFile $src -ResultRows @($stale | Select-Object DisplayName, AccountEnabled, ApproximateLastSignInDateTime, RegistrationDateTime, @{n='JoinType';e={ & $joinTypeText $_.TrustType }}, OperatingSystem | Select-Object -First 100) `
            -RuleId 'devices-stale' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/devices/manage-stale-devices' `
            -AffectedObjectIds @($stale | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'device' -AffectedCount $stale.Count -PopulationLabel 'device records with known age' -AssessedCount ($devices.Count - $unknownAge.Count) -UnknownCount ($unknownAge.Count)
    }
    if ($unmanaged.Count -gt 0) {
        $notManaged = @($unmanaged | Where-Object { $_.IsManaged -eq $false }).Count
        $nonCompliantOther = @($unmanaged | Where-Object { $_.IsManaged -ne $false -and $_.IsCompliant -eq $false }).Count
        $byJoin = (@($unmanaged | Group-Object { & $joinTypeText $_.TrustType } | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) -join '; ')
        # Devices of unknown age are not proven stale, so they stay in this count - but they
        # are not known to be in use either, and the title must not call them "active".
        $unmanagedUnknownAge = @($unmanaged | Where-Object { -not $_.ApproximateLastSignInDateTime -and -not $_.RegistrationDateTime }).Count
        $unmanagedTitle = if ($unmanagedUnknownAge -gt 0) { Format-EACount -Count $unmanaged.Count -One 'device still in use or of unknown age is not managed or fails compliance' -Many 'devices still in use or of unknown age are not managed or fail compliance' }
                          else { Format-EACount -Count $unmanaged.Count -One 'active device is not managed or fails compliance' -Many 'active devices are not managed or fail compliance' }
        $unknownAgeText = if ($unmanagedUnknownAge -gt 0) { ' ' + (Format-EACount -Count $unmanagedUnknownAge -One 'of them has no sign-in or registration date, so whether it is still in use is unknown (it is also listed in the unknown-age finding).' -Many 'of them have no sign-in or registration date, so whether they are still in use is unknown (they are also listed in the unknown-age finding).') } else { '' }
        Add-EntraFinding -Severity 'Medium' -CheckId 'devices' -Category 'Devices' `
            -Title $unmanagedTitle `
            -Evidence ("Enabled devices that are not stale: {0} reported as not managed (IsManaged=false) and {1} more reported as non-compliant (IsCompliant=false).{2} By join type - {3}. Stale devices are excluded (reported separately); devices that report no management/compliance state at all are not counted." -f $notManaged, $nonCompliantOther, $unknownAgeText, $byJoin) `
            -WhyItMatters 'A device that no management tool controls, or that fails your security baseline (for example no disk encryption or missing updates), can still reach company data unless Conditional Access (CA) requires a compliant device. Compromised personal devices are a common way in.' `
            -RecommendedAction 'Require a compliant or hybrid-joined device in Conditional Access for sensitive apps (Entra admin center > Entra ID > Conditional Access), then enrol or fix the listed devices in Intune, or remove their access.' `
            -SourceFile $src -ResultRows @($unmanaged | Select-Object DisplayName, IsManaged, IsCompliant, @{n='Activity';e={ $activityById[[string]$_.Id] }}, @{n='JoinType';e={ & $joinTypeText $_.TrustType }}, OperatingSystem, ApproximateLastSignInDateTime | Select-Object -First 100) `
            -RuleId 'devices-unmanaged-or-noncompliant' -ObjectType 'tenant' `
            -DocumentationUrl 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance' `
            -AffectedObjectIds @($unmanaged | ForEach-Object { $_.Id } | Where-Object { $_ } | Sort-Object -Unique) -AffectedObjectType 'device' -AffectedCount $unmanaged.Count -PopulationLabel 'enabled, non-stale device records with known management or compliance outcome' -AssessedCount ($managementAssessed.Count) -UnknownCount ($managementPopulation.Count - $managementAssessed.Count)
    }
    if ($unknownAge.Count -gt 0) {
        $unknownEnabled = @($unknownAge | Where-Object { $_.AccountEnabled }).Count
        Add-EntraFinding -Severity 'Information' -CheckId 'devices' -Category 'Devices' `
            -Title (Format-EACount -Count $unknownAge.Count -One 'device has no sign-in or registration date, so its age is unknown' -Many 'devices have no sign-in or registration date, so their age is unknown') `
            -Evidence ("Neither approximateLastSignInDateTime nor registrationDateTime was returned for {0} ({1} enabled). Whether {2} stale could not be assessed - this is not a clean result." -f (Format-EACount -Count $unknownAge.Count -One 'device record' -Many 'device records'), $unknownEnabled, $(if ($unknownAge.Count -eq 1) { 'it is' } else { 'they are' })) `
            -WhyItMatters 'A missing date is not proof that a device is still in use; abandoned devices in this group would otherwise slip past the stale-device check.' `
            -RecommendedAction 'Review these devices in Entra admin center > Devices > All devices and disable or delete the ones nobody can account for.' `
            -SourceFile $src -ResultRows @($unknownAge | Select-Object DisplayName, AccountEnabled, @{n='JoinType';e={ & $joinTypeText $_.TrustType }}, OperatingSystem, DeviceId | Select-Object -First 100) `
            -RuleId 'devices-unknown-age' -ObjectType 'tenant' -CoverageGap `
            -UnknownCount $unknownAge.Count -AssessedCount ($devices.Count - $unknownAge.Count) -PopulationLabel 'device records evaluated for age' -VerificationType Collection
    }
    if ($stale.Count -eq 0 -and $unmanaged.Count -eq 0 -and $unknownAge.Count -eq 0) {
        Add-EntraFinding -Severity 'Information' -CheckId 'devices' -Category 'Devices' `
            -Title ("No stale or unmanaged devices found ({0} checked)" -f (Format-EACount -Count $devices.Count -One 'device' -Many 'devices')) `
            -Evidence ("{0} within the last {1} days, and no enabled device is reported as unmanaged or non-compliant." -f $(if ($devices.Count -eq 1) { 'The only device record signed in (or was registered)' } else { 'All {0} device records signed in (or were registered)' -f $devices.Count }), $InactiveDays) `
            -WhyItMatters 'A clean, current device list is what device-based Conditional Access (CA) rules rely on.' `
            -RecommendedAction 'Keep the scheduled clean-up of old device records and the device compliance policies in place.' -SourceFile $src `
            -RuleId 'devices-baseline' -ObjectType 'tenant'
    }
}
