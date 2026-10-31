<#
Offline follow-up helpers. Inputs are local JSON data only; no tenant operations.
Exceptions never delete findings, lower their severity or remove their score.
#>
function Read-EAFollowUpJson {
    param([Parameter(Mandatory)][string]$Path, [long]$MaximumBytes = 104857600)
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt $MaximumBytes) { throw "Expected a JSON file no larger than $MaximumBytes bytes." }
    $jsonOptions = @{AsHashtable=$true;Depth=40;ErrorAction='Stop'}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $jsonOptions.DateKind='String' }
    $value = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json @jsonOptions
    if ($value -isnot [System.Collections.IDictionary]) { throw 'The JSON root must be an object.' }
    return $value
}

function ConvertTo-EACanonicalValue {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in @($Value.Keys | Sort-Object)) { $out[[string]$key] = ConvertTo-EACanonicalValue $Value[$key] }
        return $out
    }
    if ($Value -is [pscustomobject]) {
        $out = [ordered]@{}
        foreach ($p in @($Value.PSObject.Properties | Sort-Object Name)) { $out[$p.Name] = ConvertTo-EACanonicalValue $p.Value }
        return $out
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $out = @(foreach ($v in $Value) { ConvertTo-EACanonicalValue $v })
        return ,$out
    }
    return $Value
}

function Get-EAComparisonSettings {
    param([object]$RunInfo)
    $settings = Get-EAField $RunInfo 'Settings'
    if ($null -eq $settings) { return $null }
    $copy = ConvertTo-EACanonicalValue $settings
    # Sign-in and module locations do not alter the rules. Collection coverage is
    # compared separately. All other recorded settings must match, including the
    # hash of the emergency-account list (a count alone is not sufficient).
    foreach ($k in @('DelegatedClientId','UseDeviceCode','OfflineModulesPath')) { if ($copy.Contains($k)) { $copy.Remove($k) } }
    ConvertTo-Json -InputObject $copy -Depth 20 -Compress
}

function Test-EAFollowUpCheckComplete {
    param([object]$Check, [string[]]$GapChecks = @())
    if ($null -eq $Check) { return $false }
    $id = [string](Get-EAField $Check 'CheckId')
    $status = [string](Get-EAField $Check 'Status')
    $selected = Get-EAField $Check 'Selected'
    return ($false -ne $selected -and $status -match '^(Pass|InfoOnly(?:\(\d+\))?|RiskFindings\(\d+\))$' -and
        -not [bool](Get-EAField $Check 'Partial') -and [int](Get-EAField $Check 'CoverageCount') -eq 0 -and $id -notin $GapChecks)
}

function Get-EAExceptionObjectId {
    param([object]$Finding)
    $id = [string](Get-EAField $Finding 'ObjectId')
    if ($id) { return $id }
    if ([string](Get-EAField $Finding 'ObjectType') -eq 'tenant' -or -not (Get-EAField $Finding 'AffectedPrincipal')) { return 'tenant' }
    return [string](Get-EAField $Finding 'AffectedPrincipal')
}

function Get-EAFollowUpTeam {
    param([string]$CheckId)
    switch -Regex ($CheckId) {
        '^(apps|appcredentials|workloadcredentials|enterpriseapps|consentgrants|staleapps|riskyserviceprincipals)$' { 'Application / workload identity team'; break }
        '^(monitoring|changemonitoring|riskyusers|legacyauth|recentchanges)$' { 'Security operations'; break }
        '^(tenanthealth|federationhealth)$' { 'Hybrid identity team'; break }
        '^devices$' { 'Endpoint management'; break }
        '^(guests|trusts|accessreviews|identitygovernance|externaldelegation|groupgovernance)$' { 'Identity governance team'; break }
        default { 'Identity administration team' }
    }
}

function Get-EAFollowUpUserAction {
    param([string]$CheckId, [bool]$CoverageGap, [string]$VerificationType)
    if ($VerificationType -eq 'ManualTest') { return 'The assigned team coordinates a controlled test with the affected owner and records the result; follow its instructions if your participation is needed.' }
    if ($CoverageGap) { return 'No direct end-user action; the assigned team restores audit coverage.' }
    switch -Regex ($CheckId) {
        '^(mfa|authmethodpolicy|authrecovery|capolicies)$' { 'When requested by your IT team, follow its approved authentication or device setup steps and confirm you can sign in. Administrators manage policy enforcement.'; break }
        '^(appcredentials|workloadcredentials)$' { 'Application owner: test the integration and dependent services after the administrator completes the approved credential change.'; break }
        '^(apps|enterpriseapps|consentgrants|staleapps)$' { 'Application owner: confirm the business need and required access, then test the application after the assigned team makes an approved change.'; break }
        '^(accounts|staleusers|guests|externaldelegation)$' { 'Account owner or sponsor: confirm whether access is still needed and identify any business dependencies for the assigned team to review.'; break }
        '^devices$' { 'Follow your IT team''s approved device enrollment or update steps and confirm business applications still work.'; break }
        '^riskyusers$' { 'Follow the security team''s verified account-recovery instructions and report unexpected sign-ins through your normal support channel.'; break }
        default { 'No direct end-user action; the assigned team handles this finding.' }
    }
}

function Get-EAFollowUpVerification {
    param([Parameter(Mandatory)]$Finding)
    $type = [string](Get-EAField $Finding 'VerificationType')
    $rule = [string](Get-EAField $Finding 'RuleId')
    $check = [string](Get-EAField $Finding 'CheckId')
    if ($type -notin @('Configuration','HistoricalEvent','ManualTest','Collection')) {
        if ($rule -match 'alert-delivery-untested|notification-unverified|auth-context-validation|independent-stage-routing|manual-validation') { $type='ManualTest' }
        elseif ($check -in @('recentchanges','changemonitoring','legacyauth') -or $rule -eq 'lifecycle-workflow-execution-failed') { $type='HistoricalEvent' }
        elseif (Test-EntraCoverageGap $Finding) { $type='Collection' }
        else { $type='Configuration' }
    }
    $steps = [string](Get-EAField $Finding 'VerificationSteps')
    if ([string]::IsNullOrWhiteSpace($steps)) {
        $steps = switch ($type) {
            'ManualTest' { 'Complete the controlled test or manual review described in the action. Record the tester, UTC date, affected objects, expected and actual outcome, and evidence in the work item. A read-only audit rerun cannot prove this test passed.' }
            'HistoricalEvent' { 'Investigate the recorded events and confirm the cause is contained or the approved activity is understood. Verify subsequent activity and effective access with the owner, and record dated evidence. Historical events can remain in the lookback window after remediation; disappearance is not required.' }
            'Collection' { "Resolve the collection issue or document the licensed scope and equivalent manual assessment. Rerun -select $check with the same tenant and settings, and verify the previously missing evidence is readable. Do not mark the control healthy merely because a permission error disappeared." }
            default { "After the change, rerun -select $check with the same tenant and settings. Verify the expected configuration in the evidence, confirm the affected finding is absent with complete assessment, and test required access with its owner." }
        }
    }
    [pscustomobject]@{ Type=$type; Steps=$steps }
}

function Format-EAFollowUpDate {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return 'Not recorded' }
    $date = ConvertTo-EAGovDateTime $Value
    if ($date) { return $date.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'",[cultureinfo]::InvariantCulture) }
    return [string]$Value
}

function Get-EAFollowUpRunMetadata {
    param([AllowNull()]$RunInfo)
    $runId = [string](Get-EAField $RunInfo 'RunId')
    if (-not $runId) {
        $identity = '{0}|{1}' -f (Get-EAField $RunInfo 'TenantId'),(Get-EAField $RunInfo 'StartedUtc')
        if (Get-EAField $RunInfo 'StartedUtc') {
            $hasher=[Security.Cryptography.SHA256]::Create()
            try { $hash=$hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity)) } finally { $hasher.Dispose() }
            $runId = 'derived-' + ([BitConverter]::ToString($hash) -replace '-','').Substring(0,24).ToLowerInvariant()
        } else { $runId = 'report-' + [guid]::NewGuid().ToString('N') }
    }
    $normalizeDate = { param($v) $d=ConvertTo-EAGovDateTime $v; if($d){$d.ToUniversalTime().ToString('o')}else{$null} }
    [pscustomobject][ordered]@{
        RunId=$runId; TenantId=[string](Get-EAField $RunInfo 'TenantId'); TenantName=[string](Get-EAField $RunInfo 'TenantName')
        AuditStartedUtc=(& $normalizeDate (Get-EAField $RunInfo 'StartedUtc')); AuditFinishedUtc=(& $normalizeDate (Get-EAField $RunInfo 'FinishedUtc'))
        ReportGeneratedUtc=[datetimeoffset]::UtcNow.ToString('o')
        ToolVersion=[string](Get-EAField $RunInfo 'ToolVersion'); RulesetVersion=[string](Get-EAField $RunInfo 'RulesetVersion')
    }
}

function Get-EAFollowUpPopulationSummary {
    param([object[]]$Members)
    $populations = @($Members | ForEach-Object { Get-EntraFindingPopulation $_ })
    $ids = @($populations | ForEach-Object { $_.Ids } | Where-Object { $_ } | Sort-Object -Unique)
    $affected = $null; $assessed=$null; $unknown=$null
    if ($populations.Count -eq 1) {
        $affected=$populations[0].AffectedCount; $assessed=$populations[0].AssessedCount; $unknown=$populations[0].UnknownCount
    } elseif ($populations.Count -gt 1 -and @($populations | Where-Object { -not $_.IdsComplete }).Count -eq 0) {
        $affected=$ids.Count
    }
    # Do not add denominators across findings: populations can overlap. Preserve
    # every supplied measurement in PopulationDetails instead.
    [pscustomobject]@{
        Ids=$ids; AffectedCount=$affected; AssessedCount=$assessed; UnknownCount=$unknown
        ObjectType=(@($populations | ForEach-Object ObjectType | Where-Object {$_} | Select-Object -Unique) -join '; ')
        Label=(@($populations | ForEach-Object Label | Where-Object {$_} | Select-Object -Unique) -join '; ')
        Details=@(for($i=0;$i -lt $Members.Count;$i++) { [pscustomobject]@{RuleId=[string](Get-EAField $Members[$i] 'RuleId');ObjectId=[string](Get-EAField $Members[$i] 'ObjectId');Population=$populations[$i]} })
    }
}

function Get-EAFollowUpPopulationChange {
    param($Previous,$Current,[bool]$PreviousCheckComplete,[bool]$CurrentCheckComplete)
    $old = Get-EntraFindingPopulation $Previous
    $new = Get-EntraFindingPopulation $Current
    $added=@(); $removed=@(); $status='Population not comparable'; $addedStatus='Not compared'; $removedStatus='Not compared'
    if ($old.IdsComplete -and $new.IdsComplete -and $old.ObjectType -eq $new.ObjectType) {
        $added=@($new.Ids | Where-Object { $_ -notin $old.Ids })
        $removed=@($old.Ids | Where-Object { $_ -notin $new.Ids })
        $status=if($added.Count -or $removed.Count){'Affected objects changed'}else{'Same affected objects'}
        $addedStatus=if($PreviousCheckComplete){'Newly affected'}else{'Newly observed; previous assessment incomplete'}
        $removedStatus=if($CurrentCheckComplete -and -not ($new.UnknownCount -gt 0)){'No longer affected in complete assessment'}else{'No longer observed; current assessment incomplete'}
        $historical=(Get-EAFollowUpVerification $Previous).Type -eq 'HistoricalEvent' -or (Get-EAFollowUpVerification $Current).Type -eq 'HistoricalEvent'
        if($historical){
            $addedStatus=if($PreviousCheckComplete){'Newly observed in current window'}else{'Newly observed; previous assessment incomplete'}
            if($CurrentCheckComplete -and -not ($new.UnknownCount -gt 0)){$removedStatus='No longer observed in current window; remediation not established'}
        }
    } elseif ($null -ne $old.AffectedCount -and $null -ne $new.AffectedCount) {
        $status=if($old.AffectedCount -ne $new.AffectedCount){'Affected count changed; object changes not comparable'}else{'Same affected count; object changes not comparable'}
    }
    [pscustomobject]@{
        PopulationStatus=$status; PreviousAffectedCount=$old.AffectedCount; CurrentAffectedCount=$new.AffectedCount
        AddedObjectIds=$added; RemovedObjectIds=$removed; AddedObjectStatus=$addedStatus; RemovedObjectStatus=$removedStatus
    }
}

function Initialize-EntraFollowUp {
    param([object[]]$Items, [object]$RunInfo, [object]$Score, [string]$PreviousRunPath, [string]$ExceptionsPath)
    $itemsArray = @($Items | Where-Object { $null -ne $_ })
    $tenantId = [string](Get-EAField $RunInfo 'TenantId')
    $warnings = [System.Collections.Generic.List[string]]::new()
    $exceptionRows = [System.Collections.Generic.List[object]]::new()
    $comparison = [System.Collections.Generic.List[object]]::new()
    $now = [datetimeoffset]::UtcNow
    $currentIds = @{}
    foreach ($f in $itemsArray) {
        foreach ($p in @{ ChangeStatus='Not compared'; PopulationChange=$null; AcceptedRisk=$false; ExceptionReason=''; ExceptionOwner=''; ExceptionExpiresUtc='' }.GetEnumerator()) {
            $f | Add-Member -NotePropertyName $p.Key -NotePropertyValue $p.Value -Force
        }
        if (-not (Test-EntraCoverageGap $f) -and (Normalize-Severity $f.Severity) -ne 'Information') {
            $id = New-FindingKey -TenantId $tenantId -Finding $f
            if ($currentIds.ContainsKey($id)) { $warnings.Add("Duplicate current finding id prevents reliable comparison: $id") }
            $currentIds[$id] = $f
        }
    }

    # Exceptions must explicitly name the tenant and exact rule/object. Wildcards
    # would turn an approved exception into a blanket waiver for future objects.
    if ($ExceptionsPath) {
        try {
            $doc = Read-EAFollowUpJson -Path $ExceptionsPath -MaximumBytes 10485760
            if ($doc.SchemaVersion -ne 1 -or [string]$doc.TenantId -ne $tenantId -or -not $tenantId) { throw 'Expected exceptions SchemaVersion 1 and the current TenantId.' }
            if ($doc.Exceptions -isnot [System.Collections.IList]) { throw 'Exceptions must be a JSON array.' }
            $seen = @{}
            foreach ($e in $doc.Exceptions) {
                $rule = [string](Get-EAField $e 'RuleId'); $obj = [string](Get-EAField $e 'ObjectId')
                $type = [string](Get-EAField $e 'ObjectType'); $reason = [string](Get-EAField $e 'Reason'); $owner = [string](Get-EAField $e 'Owner')
                # Direct access preserves a one-element JSON array; a pipeline
                # helper would unwrap it and lose the schema distinction.
                $exceptionPopulation=$e.AffectedObjectIds
                $exceptionPopulationIds=@($exceptionPopulation | Where-Object {-not [string]::IsNullOrWhiteSpace([string]$_)} | ForEach-Object {([string]$_).Trim()} | Sort-Object -Unique)
                $validPopulation=($null -eq $exceptionPopulation -or $exceptionPopulation -is [System.Collections.IList]) -and @($exceptionPopulationIds | Where-Object {$_ -match '[*?]'}).Count -eq 0
                $expiryValue = Get-EAField $e 'ExpiresUtc'
                # Older PowerShell JSON parsers materialize ISO timestamps as dates.
                # Only dates carrying a timezone can stand in for the source string.
                $expiryText = if ($expiryValue -is [datetimeoffset]) { $expiryValue.ToString('o') }
                    elseif ($expiryValue -is [datetime] -and $expiryValue.Kind -ne [DateTimeKind]::Unspecified) { $expiryValue.ToUniversalTime().ToString('o') }
                    else { [string]$expiryValue }
                $expiry = [datetimeoffset]::MinValue
                $validDate = $expiryText -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$' -and
                    [datetimeoffset]::TryParse($expiryText, [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$expiry)
                $key = "$rule|$type|$obj"; $state = 'Active'; $matched = 0
                if (-not $rule.Trim() -or -not $obj.Trim() -or -not $reason.Trim() -or -not $owner.Trim() -or -not $validDate -or -not $validPopulation -or $rule -match '[*?]' -or $obj -match '[*?]') {
                    $state = 'Invalid'; $warnings.Add("An exception was ignored: RuleId, exact ObjectId, Reason, Owner and an ISO 8601 ExpiresUtc with timezone are required; optional AffectedObjectIds must be an array of exact IDs without wildcards ($rule / $obj).")
                } elseif ($seen.ContainsKey($key)) {
                    $state = 'Duplicate'; $warnings.Add("Duplicate exception ignored: $rule / $obj.")
                } elseif ($expiry -le $now) { $state = 'Expired' }
                $seen[$key] = $true
                if ($state -eq 'Active') {
                    foreach ($f in $currentIds.Values) {
                        if ([string]$f.RuleId -eq $rule -and (Get-EAExceptionObjectId $f) -eq $obj -and (-not $type -or [string]$f.ObjectType -eq $type)) {
                            $population=Get-EntraFindingPopulation $f
                            $aggregate=($population.Ids.Count -gt 1 -or ($population.Ids.Count -eq 1 -and $population.Ids[0] -ne $obj) -or ($null -ne (Get-EAField $f 'AffectedCount') -and -not $population.Ids.Count))
                            # An approval for an aggregate tenant wrapper must not
                            # silently expand to newly affected people or apps.
                            if($aggregate -or $exceptionPopulationIds.Count){
                                $samePopulation=$population.IdsComplete -and -not ($population.UnknownCount -gt 0) -and $exceptionPopulationIds.Count -eq $population.Ids.Count -and @($population.Ids | Where-Object {$_ -notin $exceptionPopulationIds}).Count -eq 0
                                if(-not $samePopulation){
                                    $state='Population mismatch'
                                    $warnings.Add("Exception not applied: $rule / $obj requires AffectedObjectIds matching its complete current affected population. Unknown, incomplete or changed populations cannot be blanket accepted.")
                                    continue
                                }
                            }
                            $f.AcceptedRisk = $true; $f.ExceptionReason = $reason; $f.ExceptionOwner = $owner; $f.ExceptionExpiresUtc = $expiry.ToUniversalTime().ToString('o'); $matched++
                        }
                    }
                    if ($matched -eq 0 -and $state -eq 'Active') { $state = 'No current finding' }
                }
                $exceptionRows.Add([pscustomobject]@{ RuleId=$rule; ObjectId=$obj; ObjectType=$type; AffectedObjectIds=$exceptionPopulationIds; Reason=$reason; Owner=$owner; ExpiresUtc=$expiryText; Status=$state; MatchedFindings=$matched })
            }
        } catch {
            foreach ($f in $itemsArray) { $f.AcceptedRisk=$false; $f.ExceptionReason=''; $f.ExceptionOwner=''; $f.ExceptionExpiresUtc='' }
            $exceptionRows.Clear()
            $warnings.Add("Exceptions were not applied: $($_.Exception.Message)")
        }
    }

    $comparisonState = 'No previous run supplied'
    if ($PreviousRunPath) {
        try {
            if (@($warnings | Where-Object { $_ -like 'Duplicate current finding*' }).Count) { throw 'Current finding identifiers are not unique.' }
            $baseline = Read-EAFollowUpJson -Path $PreviousRunPath
            if ($baseline.SchemaVersion -ne 2 -or $baseline.Findings -isnot [System.Collections.IList] -or $baseline.CheckStatus -isnot [System.Collections.IList]) { throw 'Expected a Findings.json object with SchemaVersion 2, Findings and CheckStatus arrays.' }
            $previousInfo = $baseline.RunInfo
            if (-not $tenantId -or [string](Get-EAField $previousInfo 'TenantId') -ne $tenantId) { throw 'The previous report belongs to another tenant or has no tenant id.' }
            $ruleset = [string](Get-EAField $RunInfo 'RulesetVersion')
            if (-not $ruleset -or [string](Get-EAField $previousInfo 'RulesetVersion') -ne $ruleset) { throw 'Ruleset versions differ or were not recorded. Start a new baseline for this ruleset.' }
            $settings = Get-EAComparisonSettings $RunInfo; $oldSettings = Get-EAComparisonSettings $previousInfo
            if (-not $settings -or -not $oldSettings -or $settings -cne $oldSettings) { throw 'Audit settings differ or were not recorded. Use the same settings before comparing outcomes.' }
            $oldById = @{}; $oldChecks = @{}; $newChecks = @{}
            foreach ($c in $baseline.CheckStatus) { $oldChecks[[string](Get-EAField $c 'CheckId')] = $c }
            foreach ($c in @($Score.Coverage.Rows)) { $newChecks[[string]$c.CheckId] = $c }
            $oldGaps = @($baseline.Findings | Where-Object { [bool](Get-EAField $_ 'CoverageGap') } | ForEach-Object { [string](Get-EAField $_ 'CheckId') } | Select-Object -Unique)
            $newGaps = @($itemsArray | Where-Object { Test-EntraCoverageGap $_ } | ForEach-Object { [string]$_.CheckId } | Select-Object -Unique)
            foreach ($old in $baseline.Findings) {
                if ([bool](Get-EAField $old 'CoverageGap') -or (Normalize-Severity ([string](Get-EAField $old 'Severity'))) -eq 'Information') { continue }
                $id = [string](Get-EAField $old 'FindingId')
                if (-not $id -or $oldById.ContainsKey($id)) { throw 'The previous report has missing or duplicate finding identifiers.' }
                $oldById[$id] = $old
            }
            foreach ($id in $currentIds.Keys) {
                $f = $currentIds[$id]; $old = $oldById[$id]
                $state = if ($old) { 'Still present' } elseif (Test-EAFollowUpCheckComplete $oldChecks[[string]$f.CheckId] $oldGaps) { 'New' } else { 'Previously not assessed' }
                $populationChange = $null
                if ($old) {
                    $populationChange = Get-EAFollowUpPopulationChange -Previous $old -Current $f `
                        -PreviousCheckComplete (Test-EAFollowUpCheckComplete $oldChecks[[string]$f.CheckId] $oldGaps) `
                        -CurrentCheckComplete (Test-EAFollowUpCheckComplete $newChecks[[string]$f.CheckId] $newGaps)
                    if ($populationChange.PopulationStatus -match '^(Affected objects changed|Affected count changed)') { $state='Still present (population changed)' }
                    $f.PopulationChange = $populationChange
                }
                $f.ChangeStatus = $state
                $comparison.Add([pscustomobject]@{ FindingId=$id; CheckId=$f.CheckId; RuleId=$f.RuleId; ObjectId=(Get-EAExceptionObjectId $f); Title=$f.Title; Severity=$f.Severity; PreviousSeverity=$(if ($old) { Get-EAField $old 'Severity' } else { '' }); Status=$state; AcceptedRisk=[bool]$f.AcceptedRisk; PopulationChange=$populationChange })
            }
            foreach ($id in $oldById.Keys) {
                if ($currentIds.ContainsKey($id)) { continue }
                $old = $oldById[$id]; $checkId = [string](Get-EAField $old 'CheckId')
                $complete=Test-EAFollowUpCheckComplete $newChecks[$checkId] $newGaps
                $historical=(Get-EAFollowUpVerification $old).Type -eq 'HistoricalEvent'
                $state = if ($complete) { if($historical){'Outside current window'}else{'Resolved'} } else { 'No longer assessed' }
                $oldPopulation=Get-EntraFindingPopulation $old
                $populationChange=[pscustomobject]@{
                    PopulationStatus=if($state -eq 'Resolved'){'Finding absent after complete assessment'}elseif($state -eq 'Outside current window'){'No longer observed in current window; remediation not established'}else{'Current affected population not assessed'}
                    PreviousAffectedCount=$oldPopulation.AffectedCount;CurrentAffectedCount=if($state -eq 'Resolved'){0}else{$null}
                    AddedObjectIds=@();RemovedObjectIds=if($complete -and $oldPopulation.IdsComplete){@($oldPopulation.Ids)}else{@()}
                    AddedObjectStatus='Not applicable';RemovedObjectStatus=if($state -eq 'Resolved'){'No longer affected in complete assessment'}elseif($state -eq 'Outside current window'){'No longer observed in current window; remediation not established'}else{'Not compared; current assessment incomplete'}
                }
                $comparison.Add([pscustomobject]@{ FindingId=$id; CheckId=$checkId; RuleId=(Get-EAField $old 'RuleId'); ObjectId=(Get-EAField $old 'ObjectId'); Title=(Get-EAField $old 'Title'); Severity=(Get-EAField $old 'Severity'); PreviousSeverity=(Get-EAField $old 'Severity'); Status=$state; AcceptedRisk=$false;PopulationChange=$populationChange })
            }
            $comparisonState = 'Compared with compatible previous run'
        } catch {
            $comparisonState = 'Not compared'; $comparison.Clear()
            foreach ($f in $itemsArray) { $f.ChangeStatus = 'Not compared'; $f.PopulationChange=$null }
            $warnings.Add("Previous run was not compared: $($_.Exception.Message)")
        }
    }
    $script:FollowUp = [pscustomobject]@{
        SchemaVersion=2; Run=(Get-EAFollowUpRunMetadata $RunInfo); CheckStatus=@($Score.Coverage.Rows)
        ComparisonState=$comparisonState; Comparison=@($comparison.ToArray() | Sort-Object Status,CheckId,Title)
        Exceptions=$exceptionRows.ToArray(); Warnings=$warnings.ToArray(); Actions=@()
    }
    foreach ($warning in $warnings) { Write-Warn2 $warning }
    return $script:FollowUp
}

function Get-EntraActionRegister {
    param([object[]]$Items, [string]$TenantId, [object[]]$CheckStatuses)
    $run=if($script:FollowUp -and (Get-EAField $script:FollowUp 'Run')){$script:FollowUp.Run}else{Get-EAFollowUpRunMetadata $script:RunInfo}
    if ($null -eq $CheckStatuses) { $CheckStatuses=@(Get-EAField $script:FollowUp 'CheckStatus') }
    $collectionChecks=@{}
    $output=[System.Collections.Generic.List[object]]::new()
    $groups = @(Get-EntraResultGroup -Items $Items | Where-Object { $_.CoverageGap -or $_.Severity -ne 'Information' } |
        Sort-Object @{e={Get-SeverityRank $_.Severity};Descending=$true}, @{e={$_.Points};Descending=$true}, Title)
    foreach ($g in $groups) {
        $members = $g.Members.ToArray(); $first = $members[0]
        $accepted = @($members | Where-Object { [bool](Get-EAField $_ 'AcceptedRisk') })
        $verification=@($members | ForEach-Object { Get-EAFollowUpVerification $_ })
        $types=@($verification | ForEach-Object Type | Select-Object -Unique)
        $manual=$types -contains 'ManualTest'; $collection=$types -contains 'Collection'
        if ($collection) { $collectionChecks[[string]$g.CheckId]=$true }
        $state = if ($g.CoverageGap -and $manual) { 'Manual test required' } elseif ($g.CoverageGap) { 'Restore audit coverage' } elseif ($accepted.Count -eq $members.Count) { 'Accepted risk' } elseif ($accepted.Count) { 'Partly accepted risk' } else { 'Open' }
        $owners = @($accepted | ForEach-Object { $_.ExceptionOwner } | Select-Object -Unique)
        $changes = @($members | ForEach-Object { Get-EAField $_ 'ChangeStatus' } | Where-Object { $_ } | Select-Object -Unique)
        $actions = @($members | ForEach-Object { $_.RecommendedAction } | Where-Object { $_ } | Select-Object -Unique)
        $population=Get-EAFollowUpPopulationSummary $members
        $output.Add([pscustomobject][ordered]@{
            RunId=$run.RunId; TenantId=$run.TenantId; TenantName=$run.TenantName; AuditStartedUtc=$run.AuditStartedUtc; AuditFinishedUtc=$run.AuditFinishedUtc
            ReportGeneratedUtc=$run.ReportGeneratedUtc; ToolVersion=$run.ToolVersion; RulesetVersion=$run.RulesetVersion
            IssueKey=$g.Key; Severity=$g.Severity; CheckId=$g.CheckId; RuleId=$first.RuleId; Issue=$g.Title
            Status=$state; Owner=$(if ($owners.Count -eq 1 -and $accepted.Count -eq $members.Count) { $owners[0] } else { 'Unassigned' })
            Team=(Get-EAFollowUpTeam $g.CheckId); DueDate=''; FindingCount=$members.Count
            AffectedObjects=($population.Ids -join '; '); AffectedObjectIds=@($population.Ids); AffectedObjectType=$population.ObjectType
            AffectedCount=$population.AffectedCount; AssessedCount=$population.AssessedCount; UnknownCount=$population.UnknownCount; PopulationLabel=$population.Label
            PopulationDetails=@($population.Details)
            NextAction=($actions -join ' ')
            UserAction=(Get-EAFollowUpUserAction -CheckId $g.CheckId -CoverageGap $g.CoverageGap -VerificationType $(if($manual){'ManualTest'}else{$types[0]}))
            VerificationType=($types -join '; '); Verification=(@($verification | ForEach-Object Steps | Select-Object -Unique) -join ' ')
            Evidence=(@($members | ForEach-Object { $_.SourceFile } | Where-Object { $_ } | Select-Object -Unique) -join '; ')
            ReportLink=('HTML Reports/EntraAudit-Results.html#' + $g.Anchor)
            Changes=($changes -join '; '); AcceptedFindings=$accepted.Count
            ExceptionReason=(@($accepted | ForEach-Object { $_.ExceptionReason } | Select-Object -Unique) -join '; ')
            ExceptionExpiresUtc=(@($accepted | ForEach-Object { $_.ExceptionExpiresUtc } | Select-Object -Unique) -join '; ')
            FindingIds=(@($members | ForEach-Object { New-FindingKey -TenantId $TenantId -Finding $_ }) -join '; ')
        })
    }
    # A selected check may fail or be skipped before emitting any finding. Keep
    # that work visible, but avoid duplicating an existing collection action.
    foreach ($c in @($CheckStatuses | Where-Object { $null -ne $_ })) {
        $id=[string](Get-EAField $c 'CheckId'); $status=[string](Get-EAField $c 'Status')
        $group=[string](Get-EAField $c 'Group')
        if (-not [bool](Get-EAField $c 'Selected') -or ($status -notmatch '^(Skipped|Error|NoResult)' -and $group -notin @('skipped','error','noresult')) -or $collectionChecks.ContainsKey($id)) { continue }
        $collectionChecks[$id]=$true
        $reason=@((Get-EAField $c 'Reason'),(Get-EAField $c 'ErrorMessage')) | Where-Object {$_} | Select-Object -Unique
        $scopes=@((Get-EAField $c 'MissingScopes') | Where-Object {$_}) -join ', '
        $action="Review the check status ($status) and resolve the stated prerequisite, permission, licensing or collection failure. Rerun -select $id and inspect its evidence. If the check is outside the agreed scope, record the reason and an accountable owner."
        if($reason){$action+=' Details: '+($reason -join ' ')}
        if($scopes){$action+=" Missing read permissions: $scopes."}
        $output.Add([pscustomobject][ordered]@{
            RunId=$run.RunId;TenantId=$run.TenantId;TenantName=$run.TenantName;AuditStartedUtc=$run.AuditStartedUtc;AuditFinishedUtc=$run.AuditFinishedUtc
            ReportGeneratedUtc=$run.ReportGeneratedUtc;ToolVersion=$run.ToolVersion;RulesetVersion=$run.RulesetVersion
            IssueKey="coverage-status-$id";Severity='Information';CheckId=$id;RuleId='check-collection-status';Issue="Complete assessment: $(Get-EAField $c 'Title')"
            Status='Restore audit coverage';Owner='Unassigned';Team=(Get-EAFollowUpTeam $id);DueDate='';FindingCount=0
            AffectedObjects='';AffectedObjectIds=@();AffectedObjectType='';AffectedCount=$null;AssessedCount=$null;UnknownCount=$null;PopulationLabel='Not assessed';PopulationDetails=@()
            NextAction=$action;UserAction=(Get-EAFollowUpUserAction $id $true 'Collection');VerificationType='Collection'
            Verification="Rerun -select $id with the same tenant and settings. Confirm the evidence was collected and review the result; a successful collection does not itself prove the control is healthy."
            Evidence='';ReportLink='HTML Reports/EntraAudit-Results.html#check-coverage';Changes='Not compared';AcceptedFindings=0;ExceptionReason='';ExceptionExpiresUtc='';FindingIds=''
        })
    }
    $output.ToArray()
}

function Write-EntraFollowUpReport {
    param([Parameter(Mandatory)][string]$RunRoot, [object[]]$Items, [string]$TenantId)
    if (-not $script:FollowUp) { throw 'Initialize-EntraFollowUp must run before the action register is written.' }
    $actions = @(Get-EntraActionRegister -Items $Items -TenantId $TenantId)
    $script:FollowUp.Actions = $actions
    $csvPath = Join-Path $RunRoot 'Action-Register.csv'
    $csvRows=@(foreach($a in $actions){
        $row=[ordered]@{};foreach($p in $a.PSObject.Properties){
            $row[$p.Name]=if($p.Name -in @('AffectedObjectIds','PopulationDetails')){ConvertTo-Json -InputObject $p.Value -Depth 12 -Compress}else{$p.Value}
        };[pscustomobject]$row
    })
    if (-not $csvRows.Count) {
        # Keep a stand-alone empty register attributable to its run. This is an
        # informational CSV row only, not an action or a healthy-control claim.
        $emptyRow=[ordered]@{}
        foreach($name in @('RunId','TenantId','TenantName','AuditStartedUtc','AuditFinishedUtc','ReportGeneratedUtc','ToolVersion','RulesetVersion')){$emptyRow[$name]=Get-EAField $script:FollowUp.Run $name}
        foreach($name in @('IssueKey','Severity','CheckId','RuleId','Issue','Status','Owner','Team','DueDate','FindingCount','AffectedObjects','AffectedObjectIds','AffectedObjectType','AffectedCount','AssessedCount','UnknownCount','PopulationLabel','PopulationDetails','NextAction','UserAction','VerificationType','Verification','Evidence','ReportLink','Changes','AcceptedFindings','ExceptionReason','ExceptionExpiresUtc','FindingIds')){$emptyRow[$name]=''}
        $emptyRow.Issue='No current risk findings or coverage actions';$emptyRow.Status='No actions';$emptyRow.FindingCount=0
        $csvRows=@([pscustomobject]$emptyRow)
    }
    ConvertTo-SafeCsvRows $csvRows | Export-Csv -LiteralPath $csvPath -Encoding utf8BOM -NoTypeInformation -ErrorAction Stop
    ConvertTo-Json -InputObject $script:FollowUp -Depth 16 | Set-Content -LiteralPath (Join-Path $RunRoot 'Follow-Up.json') -Encoding UTF8 -ErrorAction Stop
    $detailHtml={param([string]$Text,[string]$Label)
        if($Text.Length -gt 360){"<p>$(HtmlEncode ($Text.Substring(0,240).TrimEnd()))&hellip;</p><details><summary>$(HtmlEncode $Label)</summary><p>$(HtmlEncode $Text)</p></details>"}else{"<p>$(HtmlEncode $Text)</p>"}
    }
    $rows = foreach ($a in $actions) {
        $href = [string]$a.ReportLink -replace '^HTML Reports/',''
        $evidenceLinks = @($a.Evidence -split '; ' | Where-Object { $_ } | ForEach-Object {
            # Links are limited to evidence files inside this run. JSON input never
            # supplies navigable file, UNC, javascript or remote URLs.
            $h = $_ -replace '\\','/'
            if ($h -match '^\.\./Raw Data/Source/[A-Za-z0-9_.-]+\.(html|csv|txt)$') { "<a href='$(HtmlAttrEncode $h)'>Open evidence</a>" }
            else { HtmlEncode $_ }
        }) -join ' &middot; '
        $affected=if($null -ne $a.AffectedCount){[string]$a.AffectedCount}else{'Not measured'}
        $assessed=if($null -ne $a.AssessedCount){[string]$a.AssessedCount}else{'Not recorded'}
        $unknown=if($null -ne $a.UnknownCount){[string]$a.UnknownCount}else{'Not recorded'}
        $populationHtml="<p><b>Affected:</b> $(HtmlEncode $affected) &middot; <b>Assessed:</b> $(HtmlEncode $assessed) &middot; <b>Unknown:</b> $(HtmlEncode $unknown)</p>"
        if($a.PopulationLabel){$populationHtml+="<p>$(HtmlEncode $a.PopulationLabel)</p>"}
        if($a.AffectedObjects){$populationHtml+="<details><summary>Affected object IDs ($($a.AffectedObjectIds.Count))</summary><p>$(HtmlEncode $a.AffectedObjects)</p></details>"}
        if($a.PopulationDetails.Count -gt 1){
            $populationHtml+='<details><summary>Measurements by finding (populations may overlap)</summary><ul>'
            foreach($d in $a.PopulationDetails){$p=$d.Population;$populationHtml+="<li>$(HtmlEncode $d.RuleId) / $(HtmlEncode $d.ObjectId): affected $(if($null -ne $p.AffectedCount){$p.AffectedCount}else{'not measured'}); assessed $(if($null -ne $p.AssessedCount){$p.AssessedCount}else{'not recorded'}); unknown $(if($null -ne $p.UnknownCount){$p.UnknownCount}else{'not recorded'}). $(HtmlEncode $p.Label)</li>"}
            $populationHtml+='</ul></details>'
        }
        $exceptionHtml=if($a.AcceptedFindings){
            $expiry=@($a.ExceptionExpiresUtc -split '; ' | ForEach-Object {Format-EAFollowUpDate $_}) -join '; '
            "<details><summary>Accepted risk: $($a.AcceptedFindings) of $($a.FindingCount) finding records; still scored</summary><p>$(HtmlEncode $a.ExceptionReason)</p><p>Expires: $(HtmlEncode $expiry)</p></details>"
        }else{''}
        "<tr data-status='$(HtmlAttrEncode $a.Status)' data-team='$(HtmlAttrEncode $a.Team)'><td data-label='Issue and population'><span class='pill sev-$(HtmlAttrEncode $a.Severity)'>$(HtmlEncode $a.Severity)</span><h3><a href='$(HtmlAttrEncode $href)'>$(HtmlEncode $a.Issue)</a></h3><span class='sub'>$(HtmlEncode $a.CheckId) / $(HtmlEncode $a.RuleId)</span>$populationHtml<span class='sub'>$($a.FindingCount) finding record(s)</span></td><td data-label='Assignment and status'><strong>$(HtmlEncode $a.Status)</strong><span class='sub'>$(HtmlEncode $a.Changes)</span><p><b>Owner:</b> $(HtmlEncode $a.Owner)<br><b>Suggested team:</b> $(HtmlEncode $a.Team)<br><b>Due:</b> $(if($a.DueDate){HtmlEncode (Format-EAFollowUpDate $a.DueDate)}else{'Unassigned (set in CSV)'})</p>$exceptionHtml</td><td data-label='Actions and verification'><b>Administrator / assigned team</b>$(& $detailHtml $a.NextAction 'Read the complete action')<details><summary>End user / application owner</summary><p>$(HtmlEncode $a.UserAction)</p></details><details><summary>Verification: $(HtmlEncode $a.VerificationType)</summary><p>$(HtmlEncode $a.Verification)</p></details><span class='sub'>$evidenceLinks</span></td></tr>"
    }
    if (-not $rows) { $rows = '<tr class="empty"><td colspan="3">No current risk findings or coverage actions.</td></tr>' }
    $changeRows = foreach ($c in $script:FollowUp.Comparison) {
        $p=Get-EAField $c 'PopulationChange';$populationChangeHtml='Not compared'
        if($p){
            $populationChangeHtml=HtmlEncode $p.PopulationStatus
            $previousCount=if($null -ne $p.PreviousAffectedCount){[string]$p.PreviousAffectedCount}else{'not measured'}
            $currentCount=if($null -ne $p.CurrentAffectedCount){[string]$p.CurrentAffectedCount}else{'not measured'}
            $populationChangeHtml+="<span class='sub'>Affected: $(HtmlEncode $previousCount) &rarr; $(HtmlEncode $currentCount)</span>"
            if($p.AddedObjectIds.Count){$populationChangeHtml+="<details><summary>$(HtmlEncode $p.AddedObjectStatus): $($p.AddedObjectIds.Count)</summary><p>$(HtmlEncode ($p.AddedObjectIds -join '; '))</p></details>"}
            if($p.RemovedObjectIds.Count){$populationChangeHtml+="<details><summary>$(HtmlEncode $p.RemovedObjectStatus): $($p.RemovedObjectIds.Count)</summary><p>$(HtmlEncode ($p.RemovedObjectIds -join '; '))</p></details>"}
        }
        "<tr><td data-label='Change'>$(HtmlEncode $c.Status)</td><td data-label='Finding'>$(HtmlEncode $c.Title)<span class='sub'>$(HtmlEncode $c.CheckId) / $(HtmlEncode $c.ObjectId)</span></td><td data-label='Current / previous severity'>$(HtmlEncode $c.Severity) / $(HtmlEncode $c.PreviousSeverity)</td><td data-label='Affected population'>$populationChangeHtml</td></tr>"
    }
    if (-not $changeRows) { $changeRows = '<tr><td colspan="4">No comparable finding changes.</td></tr>' }
    $exceptionRows = foreach ($e in $script:FollowUp.Exceptions) {
        $scopeHtml=if($e.AffectedObjectIds.Count){"<details><summary>Approved population ($($e.AffectedObjectIds.Count))</summary><p>$(HtmlEncode ($e.AffectedObjectIds -join '; '))</p></details>"}else{''}
        "<tr><td data-label='Status'>$(HtmlEncode $e.Status)</td><td data-label='Rule / object'>$(HtmlEncode $e.RuleId)<span class='sub'>$(HtmlEncode $e.ObjectId)</span>$scopeHtml</td><td data-label='Owner'>$(HtmlEncode $e.Owner)</td><td data-label='Reason'>$(HtmlEncode $e.Reason)</td><td data-label='Expires'>$(HtmlEncode (Format-EAFollowUpDate $e.ExpiresUtc))</td></tr>"
    }
    if (-not $exceptionRows) { $exceptionRows = '<tr><td colspan="5">No documented exceptions supplied.</td></tr>' }
    $warningHtml = if ($script:FollowUp.Warnings.Count) { "<div class='callout warn'><b>Follow-up input needs attention</b><ul>" + (($script:FollowUp.Warnings | ForEach-Object { '<li>' + (HtmlEncode $_) + '</li>' }) -join '') + '</ul></div>' } else { '' }
    $run=$script:FollowUp.Run
    $statusOptions=@($actions | ForEach-Object Status | Sort-Object -Unique | ForEach-Object {"<option value='$(HtmlAttrEncode $_)'>$(HtmlEncode $_)</option>"}) -join ''
    $teamOptions=@($actions | ForEach-Object Team | Sort-Object -Unique | ForEach-Object {"<option value='$(HtmlAttrEncode $_)'>$(HtmlEncode $_)</option>"}) -join ''
    $filterScript=@'
<script>(function(){const search=document.getElementById('actionSearch'),status=document.getElementById('actionStatus'),team=document.getElementById('actionTeam'),rows=Array.from(document.querySelectorAll('#actionRows tr[data-status]'));function filter(){const q=search.value.trim().toLowerCase();let count=0;rows.forEach(function(row){const show=(!q||row.textContent.toLowerCase().includes(q))&&(!status.value||row.dataset.status===status.value)&&(!team.value||row.dataset.team===team.value);row.hidden=!show;if(show)count++;});document.getElementById('actionCount').textContent=count+' of '+rows.length+' actions shown';document.getElementById('noActionMatches').hidden=count!==0||rows.length===0;}[search,status,team].forEach(function(el){el.addEventListener('input',filter);el.addEventListener('change',filter);});filter();})();</script>
'@
    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Entra Audit - Action Register</title>$(Get-EntraRiskCss)
<style>.container{max-width:1480px}.followup-table{table-layout:fixed;width:100%}.followup-table td{overflow-wrap:anywhere;line-height:1.5;vertical-align:top}.followup-table h3{font-size:1.05rem;margin:10px 0}.followup-table p{margin:8px 0}.followup-table details{margin:10px 0}.followup-table summary{cursor:pointer;color:var(--text);font-weight:600}.followup-table tr[hidden]{display:none!important}.action-filters{display:flex;flex-wrap:wrap;gap:16px;align-items:end;margin:20px 0}.action-filters label{display:flex;flex-direction:column;gap:6px;min-width:180px;font-weight:600}.action-filters label:first-child{flex:1}.action-filters input,.action-filters select{font:inherit;padding:9px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--text);max-width:100%}.run-meta{line-height:1.6;overflow-wrap:anywhere}.action-count{color:var(--muted)}@media(max-width:900px){.followup-table,.followup-table tbody{display:block;width:100%;overflow:visible}.followup-table colgroup,.followup-table thead{display:none}.followup-table tr{display:block;padding:10px;border-bottom:2px solid var(--line)}.followup-table td{display:block;width:auto;border:0;padding:8px 10px}.followup-table td[data-label]::before{content:attr(data-label);display:block;color:var(--muted);font-size:12px;font-weight:700;letter-spacing:.04em;margin-bottom:4px}.action-filters label{width:100%}}@media print{.action-filters{display:none}.followup-table tr[hidden]{display:table-row!important}}</style>
</head><body><div class="container">
$(Get-EntraPrimaryNav 'actions')
<div class="header"><div class="h-title"><div><h1>Action register &amp; changes</h1><p>Assign an owner and due date for each issue. Suggested teams are starting points, not assignments.</p><p class="no-print"><a href="../Action-Register.csv" download>Download action register (CSV)</a> &middot; <a href="../Follow-Up.json" download>Follow-up data (JSON)</a></p></div><button id="themeToggle" class="theme-toggle" type="button">Toggle theme</button></div></div>
<div class="callout run-meta"><b>Tenant:</b> $(HtmlEncode $run.TenantName) <span class="sub">$(HtmlEncode $run.TenantId)</span><br><b>Audit started:</b> $(HtmlEncode (Format-EAFollowUpDate $run.AuditStartedUtc)) &middot; <b>Finished:</b> $(HtmlEncode (Format-EAFollowUpDate $run.AuditFinishedUtc))<br><b>Tool:</b> $(HtmlEncode $run.ToolVersion) &middot; <b>Ruleset:</b> $(HtmlEncode $run.RulesetVersion)<br><b>Run ID:</b> $(HtmlEncode $run.RunId) &middot; <b>Report generated:</b> $(HtmlEncode (Format-EAFollowUpDate $run.ReportGeneratedUtc))</div>
$warningHtml
<section class="section"><h2>Current actions</h2><p>Accepted risks remain visible and retain their severity and score. Edit owner, team, due date and status in your copy of the CSV for the handoff; this report is a snapshot. All actions below are guidance; this audit makes no tenant changes.</p><p>Affected and assessed counts are shown only when measured. Unknown means objects whose outcome could not be established. Missing measurements are not zero; overlapping findings are not added into a population total.</p><div class="action-filters"><label for="actionSearch">Search actions<input id="actionSearch" type="search" placeholder="Issue, rule, object ID, owner or evidence"></label><label for="actionStatus">Status<select id="actionStatus"><option value="">All statuses</option>$statusOptions</select></label><label for="actionTeam">Suggested team<select id="actionTeam"><option value="">All teams</option>$teamOptions</select></label></div><p id="actionCount" class="action-count" role="status" aria-live="polite">$($actions.Count) actions</p><p id="noActionMatches" hidden>No actions match these filters.</p><table class="followup-table"><colgroup><col style="width:30%"><col style="width:23%"><col style="width:47%"></colgroup><thead><tr><th>Issue and population</th><th>Assignment and status</th><th>Actions and verification</th></tr></thead><tbody id="actionRows">$($rows -join "`n")</tbody></table></section>
<section class="section"><h2>Changes since previous run</h2><p>$(HtmlEncode $script:FollowUp.ComparisonState). Changes cover confirmed risk findings. Missing configuration findings are resolved only when their check was fully assessed with matching tenant, ruleset and settings. Historical events no longer observed are labelled Outside current window; their absence does not establish remediation. Object changes require complete ID lists; an object no longer observed during incomplete assessment is not confirmed resolved. Findings newly visible after an incomplete baseline are labelled Previously not assessed.</p><table class="followup-table"><thead><tr><th>Change</th><th>Finding</th><th>Current / previous severity</th><th>Affected population</th></tr></thead><tbody>$($changeRows -join "`n")</tbody></table></section>
<section class="section"><h2>Documented exceptions</h2><p>Expired, invalid and unmatched exceptions do not accept any current risk. Active exceptions must name the tenant, exact rule and object, accountable owner, reason and expiry. Aggregate findings also require an exact approved list of affected object IDs; changed or incomplete populations require a new review.</p><table class="followup-table"><thead><tr><th>Status</th><th>Rule / object</th><th>Owner</th><th>Reason</th><th>Expires (UTC)</th></tr></thead><tbody>$($exceptionRows -join "`n")</tbody></table></section>
</div>$(Get-EntraThemeScript)$filterScript</body></html>
"@
    Set-Content -LiteralPath (Join-Path $RunRoot 'HTML Reports/Action-Register.html') -Value $html -Encoding UTF8 -ErrorAction Stop
}
