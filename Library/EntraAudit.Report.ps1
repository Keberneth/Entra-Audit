<#
EntraAudit shared definitions. Dot-source from the runner so script-scoped state is shared.
Do not execute check files with &: that creates a different script scope.
#>

function New-FindingAnchor([object]$f) {
    # Anchor is assigned once at Add-EntraFinding time so every report writer resolves
    # the same finding to the same id; fall back for objects created outside it.
    if ($f.PSObject.Properties['Anchor'] -and $f.Anchor) { return $f.Anchor }
    # Fallback (objects built outside Add-EntraFinding): include the affected object so two
    # per-object findings with the same title and check do not share one HTML id.
    $obj = if ($f.ObjectId) { [string]$f.ObjectId } elseif ($f.AffectedPrincipal) { [string]$f.AffectedPrincipal } else { '' }
    'finding-' + (New-Slug ('{0}-{1}-{2}' -f $f.Title, $f.CheckId, $obj))
}

function Format-EntraNaturalSortKey([string]$Value) {
    if ($null -eq $Value) { return '' }
    [regex]::Replace($Value.ToLowerInvariant(), '\d+', { param($m) $m.Value.PadLeft(12, '0') })
}

function Test-EntraDocumentationUrl([string]$Url) {
    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
    $u = $null
    if (-not [uri]::TryCreate($Url.Trim(), [UriKind]::Absolute, [ref]$u)) { return $false }
    if ($u.Scheme -ne 'https' -or $u.UserInfo) { return $false }
    $h = $u.Host.ToLowerInvariant()
    return ($h -eq 'aka.ms' -or $h -eq 'microsoft.com' -or $h.EndsWith('.microsoft.com'))
}

function ConvertTo-EntraLinkedText([string]$Text) {
    $enc = HtmlEncode $Text
    if (-not $enc) { return '' }
    $pattern = 'https://(?:learn\.microsoft\.com|docs\.microsoft\.com|aka\.ms)/(?:(?!&quot;|&#39;|&lt;|&gt;)[^\s<>"''])+'
    [regex]::Replace($enc, $pattern, {
        param($m)
        $url = $m.Value
        $tail = ''
        while ($url.Length -gt 0 -and '.,;:)'.Contains($url[-1])) { $tail = [string]$url[-1] + $tail; $url = $url.Substring(0, $url.Length - 1) }
        "<a href='$url' target='_blank' rel='noopener noreferrer'>$url</a>$tail"
    })
}

function Get-EntraDisplayAction {
    param([string]$Text, [string[]]$DocumentationUrl)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $t = $Text
    foreach ($u in @($DocumentationUrl | Where-Object { $_ })) {
        $t = $t.Replace(" Microsoft source: $u", '').Replace("Microsoft source: $u", '')
    }
    $t.Trim()
}

function ConvertTo-EntraDocLinkHtml {
    param([string]$Url, [string]$Label = 'Microsoft guidance')
    if (-not (Test-EntraDocumentationUrl $Url)) { return '' }
    "<a class='doc' href='$(HtmlAttrEncode $Url.Trim())' target='_blank' rel='noopener noreferrer' title='$(HtmlAttrEncode $Url.Trim())'>$(HtmlEncode $Label)</a>"
}

function Get-EntraLicenseText {
    param([object]$RunInfo = $script:RunInfo)
    $p1 = $script:HasP1; $p2 = $script:HasP2; $wip = $script:WorkloadIdP; $known = $script:LicenseKnown
    $lic = Get-EntraRunValue $RunInfo 'Licenses'
    if ($lic) {
        $v = Get-EntraRunValue $lic 'P1'; if ($null -ne $v) { $p1 = $v }
        $v = Get-EntraRunValue $lic 'P2'; if ($null -ne $v) { $p2 = $v }
        $v = Get-EntraRunValue $lic 'WorkloadIdPremium'; if ($null -ne $v) { $wip = $v }
        $v = Get-EntraRunValue $lic 'Known'; if ($null -ne $v) { $known = $v }
    }
    if ($false -eq $known) { return 'unknown - the license lookup failed' }
    $yn = { param($b) if ($b) { 'yes' } else { 'no' } }
    'Entra ID P1: {0}, P2: {1}, Workload Identities Premium: {2}' -f (& $yn $p1), (& $yn $p2), (& $yn $wip)
}

function Get-EntraSearchText {
    param([object[]]$Parts, [int]$Max = 20000)
    $s = ((@($Parts) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ }) -join ' ') -replace '\s+', ' '
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) }
    $s.ToLowerInvariant()
}

function Get-EntraRowText {
    param($Rows, [int]$MaxRows = 50)
    $out = New-Object System.Text.StringBuilder
    foreach ($r in @($Rows | Select-Object -First $MaxRows)) {
        if ($null -eq $r) { continue }
        if ($r -is [System.Collections.IDictionary]) { foreach ($k in $r.Keys) { [void]$out.Append([string]$r[$k]).Append(' ') } }
        elseif ($r -is [string] -or $r -is [ValueType]) { [void]$out.Append([string]$r).Append(' ') }
        else { foreach ($p in $r.PSObject.Properties) { [void]$out.Append([string]$p.Value).Append(' ') } }
    }
    $out.ToString()
}

function Get-EntraFirstSentence([string]$Text, [int]$Max = 240) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    $m = [regex]::Match($t, '^.+?[.!?](?=\s|$)')
    $s = if ($m.Success) { $m.Value } else { $t }
    if ($s.Length -gt $Max) { $cut = $s.Substring(0, $Max); $sp = $cut.LastIndexOf(' '); if ($sp -gt 40) { $cut = $cut.Substring(0, $sp) }; $s = $cut.TrimEnd(',', ';', ':') + '...' }
    $s
}

function Get-EntraGroupTitle {
    param([hashtable]$TitleCounts)
    $titles = @($TitleCounts.GetEnumerator() | Sort-Object @{ e = { $_.Value }; Descending = $true }, @{ e = { Format-EntraNaturalSortKey $_.Key } } | ForEach-Object { [string]$_.Key })
    if ($titles.Count -le 1) { return [string]($titles | Select-Object -First 1) }
    $lists = New-Object System.Collections.Generic.List[object]
    foreach ($t in $titles) { $lists.Add([string[]]($t.Trim() -split '\s+')) }
    $min = [int]::MaxValue
    foreach ($w in $lists) { if ($w.Count -lt $min) { $min = $w.Count } }
    # Shared leading / trailing words, always leaving at least one differing word per title.
    $p = 0
    while ($p -lt ($min - 1)) {
        $same = $true
        foreach ($w in $lists) { if ($w[$p] -cne $lists[0][$p]) { $same = $false; break } }
        if (-not $same) { break }
        $p++
    }
    $sfx = 0
    while ($sfx -lt ($min - 1 - $p)) {
        $same = $true
        foreach ($w in $lists) { if ($w[$w.Count - 1 - $sfx] -cne $lists[0][$lists[0].Count - 1 - $sfx]) { $same = $false; break } }
        if (-not $same) { break }
        $sfx++
    }
    $middles = @(foreach ($w in $lists) { ($w[$p..($w.Count - 1 - $sfx)]) -join ' ' })
    $shown = @($middles | Select-Object -First 3)
    $mid = ($shown -join ' / ') + $(if ($middles.Count -gt 3) { " / +$($middles.Count - 3) more" } else { '' })
    $head = if ($p -gt 0) { ($lists[0][0..($p - 1)]) -join ' ' } else { '' }
    $tail = if ($sfx -gt 0) { ($lists[0][($lists[0].Count - $sfx)..($lists[0].Count - 1)]) -join ' ' } else { '' }
    (@($head, $mid, $tail) | Where-Object { $_ }) -join ' '
}

function Get-EntraResultGroup {
    param([object[]]$Items)
    $groups = [ordered]@{}
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }
        $issue = Get-EntraIssueKey $it
        $gap = [bool](Test-EntraCoverageGap -Finding $it)
        $key = if ($gap) { $issue.Key + '|not-assessed' } else { $issue.Key }
        if (-not $groups.Contains($key)) {
            $groups[$key] = [pscustomobject]@{
                Key = $key; Severity = $issue.Severity; CheckId = [string]$it.CheckId; Rule = $issue.Rule
                CoverageGap = $gap; Members = (New-Object System.Collections.Generic.List[object]); IssueTitles = @{}
                Title = ''; Anchor = ''; PerObject = $true; Points = 0.0; Population=$null; AcceptedRisk=$false; AcceptedFindings=0; ExceptionExpiresUtc=''
            }
        }
        $g = $groups[$key]
        $g.Members.Add($it)
        $t = [string]$issue.IssueTitle
        $g.IssueTitles[$t] = 1 + $(if ($g.IssueTitles.ContainsKey($t)) { $g.IssueTitles[$t] } else { 0 })
        if (-not ($it.AffectedPrincipal -or $it.ObjectId)) { $g.PerObject = $false }
    }
    $usedAnchors = @{}
    foreach ($g in $groups.Values) {
        $n = $g.Members.Count
        if ($n -eq 1) {
            $g.Title = [string]$g.Members[0].Title
            $g.Anchor = New-FindingAnchor $g.Members[0]
        } else {
            $g.Title = Get-EntraGroupTitle -TitleCounts $g.IssueTitles
            $base = 'issue-' + (New-Slug $g.Key)
            $a = $base; $i = 2
            while ($usedAnchors.ContainsKey($a)) { $a = "$base-$i"; $i++ }
            $g.Anchor = $a
        }
        $usedAnchors[$g.Anchor] = $true
        $g.Population = Get-EntraPopulationRollup $g.Members.ToArray()
        $accepted = @($g.Members | Where-Object { [bool](Get-EAField $_ 'AcceptedRisk') })
        $g.AcceptedFindings = $accepted.Count
        $g.AcceptedRisk = ($accepted.Count -eq $n -and $n -gt 0)
        $g.ExceptionExpiresUtc = @($accepted | ForEach-Object { Get-EAField $_ 'ExceptionExpiresUtc' } | Where-Object { $_ } | Sort-Object -Unique) -join '; '
        $pts = if ($script:RiskPoints -and $script:RiskPoints.ContainsKey($g.Severity)) { [double]$script:RiskPoints[$g.Severity] } else { 0 }
        $g.Points = if ($g.CoverageGap) { 0 } else { $pts * [math]::Sqrt($g.Population.ScoringCount) }
    }
    @($groups.Values)
}

function ConvertTo-EntraFindingCardHtml {
    param([Parameter(Mandatory)][object]$Group, [string]$TenantId, [hashtable]$CheckTitles = @{})
    # NB: .ToArray() rather than @($list) - wrapping a generic List in @() throws
    # "Argument types do not match" on some PowerShell 7 builds.
    $members = if ($Group.Members -is [System.Collections.IList] -and $Group.Members.GetType().IsGenericType) { $Group.Members.ToArray() } else { @($Group.Members) }
    $first = $members[0]
    $n = $members.Count
    $sev = Normalize-Severity $first.Severity
    $gap = [bool]$Group.CoverageGap
    $checkId = [string]$first.CheckId
    $checkTitle = if ($CheckTitles.ContainsKey($checkId)) { [string]$CheckTitles[$checkId] } else { '' }
    $category = [string]$first.Category
    $rule = Get-FindingRule $first
    $population = if ($Group.Population) { $Group.Population } else { Get-EntraPopulationRollup $members }
    $countLabel = if ($population.ScoringBasis -ne 'FindingRecord') { '{0} affected {1}' -f $population.AffectedCount, $population.Label } else { '{0} finding record{1}' -f $n, $(if ($n -eq 1) { '' } else { 's' }) }

    # --- summary line (always visible) ---
    $gapBadge = if ($gap) { "<span class='badge gap' title='The audit could not read or check this. It is not a pass, and it is kept apart from confirmed problems.'>Not assessed</span>" } else { '' }
    $countPill = if ($n -gt 1 -or $population.AffectedCount -gt 1) { "<span class='count-pill'>$(HtmlEncode $countLabel)</span>" } else { '' }
    $acceptedMembers = @($members | Where-Object { [bool](Get-EAField $_ 'AcceptedRisk') })
    $exceptionBadge = if ($acceptedMembers.Count) { "<span class='count-pill'>$($acceptedMembers.Count) accepted risk$(if ($acceptedMembers.Count -ne 1) { 's' })</span>" } else { '' }
    if ($n -gt 1) {
        $names = @($members | ForEach-Object { if ($_.AffectedPrincipal) { [string]$_.AffectedPrincipal } elseif ($_.ObjectId) { [string]$_.ObjectId } else { [string]$_.Title } } |
            Sort-Object { Format-EntraNaturalSortKey $_ } -Unique)
        $shown = @($names | Select-Object -First 4)
        $more = $names.Count - $shown.Count
        $preview = 'Affects: ' + ($shown -join ', ') + $(if ($more -gt 0) { " and $more more" } else { '' }) + '.'
        if ($Group.IssueTitles.Count -gt 1) {
            $variants = @($Group.IssueTitles.GetEnumerator() | Sort-Object @{ e = { $_.Value }; Descending = $true } | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value })
            $preview = 'Includes: ' + ($variants -join '; ') + '. ' + $preview
        }
    } else {
        $preview = [string]$first.Evidence
    }

    # --- identifiers line ---
    $meta = New-Object System.Collections.Generic.List[string]
    $checkLabel = "<a href='#check-$(HtmlAttrEncode $checkId)'><b>$(HtmlEncode $checkId)</b></a>" + $(if ($checkTitle) { " ($(HtmlEncode $checkTitle))" } else { '' })
    $meta.Add("Check: $checkLabel")
    $meta.Add("Rule: <b>$(HtmlEncode $rule)</b>")
    if ($n -eq 1) {
        if ($first.ObjectId -or $first.ObjectType) {
            $meta.Add(('Object: {0}<b>{1}</b>' -f $(if ($first.ObjectType) { (HtmlEncode $first.ObjectType) + ' ' } else { '' }), (HtmlEncode $first.ObjectId)))
        }
        if ($TenantId) {
            $fid = New-FindingKey -TenantId $TenantId -Finding $first
            $meta.Add("Finding id: <span class='fid' title='Stays the same between runs; matches FindingId in Findings.json and Findings.csv'>$(HtmlEncode $fid)</span>")
        }
    } else {
        $meta.Add("$n finding records (one finding id per row below)")
    }
    $meta.Add("Run only this check again: <code>-select $(HtmlEncode $checkId)</code>")
    $metaHtml = "<div class='finding-meta'>" + ($meta -join ' &middot; ') + '</div>'

    # --- panels ---
    $distinct = {
        param([string]$Prop)
        @($members | ForEach-Object { [string]$_.$Prop } | Where-Object { $_ } | Select-Object -Unique)
    }
    $docUrls = @(& $distinct 'DocumentationUrl')
    $whyHtml = (@(& $distinct 'WhyItMatters' | Select-Object -First 5) | ForEach-Object { "<p>$(ConvertTo-EntraLinkedText $_)</p>" }) -join ''
    $actions = @(& $distinct 'RecommendedAction' | Select-Object -First 5 | ForEach-Object { "<p>$(ConvertTo-EntraLinkedText (Get-EntraDisplayAction $_ $docUrls))</p>" })
    $docHtml = (@($docUrls | ForEach-Object {
        $link = ConvertTo-EntraDocLinkHtml $_ 'Microsoft guidance'
        if ($link) { "<div class='doc-link'>$link <span class='doc-url'>$(HtmlEncode $_)</span></div>" }
        else { "<div class='doc-link'>Reference: <span class='mono'>$(HtmlEncode $_)</span></div>" }
    })) -join ''
    $sources = @(& $distinct 'SourceFile')
    $srcHtml = if ($sources.Count -gt 0) {
        (@($sources | ForEach-Object {
            $href = Resolve-SourceHref $_
            $leaf = ($_ -split '[\\/]')[-1]
            if ($href) { "<a class='download-link' href='$(HtmlAttrEncode $href)' target='_blank' rel='noopener'>Open the evidence</a><div class='result-note mono'>$(HtmlEncode $leaf)</div>" }
            else { "<div class='result-note mono'>$(HtmlEncode $leaf)</div>" }
        })) -join ''
    } else { "<span class='result-note'>No separate evidence file for this finding.</span>" }

    $foundHeading = if ($gap) { 'What could not be checked' } else { 'What was found' }
    $grid = New-Object System.Collections.Generic.List[string]
    if ($n -eq 1) { $grid.Add("<div class='panel'><h4>$foundHeading</h4><p>$(HtmlEncode $first.Evidence)</p></div>") }
    $grid.Add("<div class='panel'><h4>Why it matters</h4>$whyHtml</div>")
    $grid.Add("<div class='panel'><h4>What to do</h4>$($actions -join '')$docHtml</div>")
    $grid.Add("<div class='panel'><h4>Evidence file</h4>$srcHtml</div>")
    $grid.Add("<div class='panel'><h4>Population assessed</h4><p>$(HtmlEncode (Get-EntraPopulationText $population))</p></div>")
    $verification = @($members | ForEach-Object { Get-EAField $_ 'VerificationSteps' } | Where-Object { $_ } | Select-Object -Unique)
    $verificationTypes = @($members | ForEach-Object { Get-EAField $_ 'VerificationType' } | Where-Object { $_ } | Select-Object -Unique)
    if ($verification.Count) { $grid.Add("<div class='panel'><h4>Verify the outcome</h4><p>$(HtmlEncode ($verificationTypes -join ', '))</p>" + (($verification | ForEach-Object { '<p>' + (HtmlEncode $_) + '</p>' }) -join '') + '</div>') }
    if ($acceptedMembers.Count) {
        $exceptionHtml = @($acceptedMembers | ForEach-Object { "<p><b>$(HtmlEncode (Get-EAExceptionObjectId $_))</b>: $(HtmlEncode $_.ExceptionReason)<br>Owner: $(HtmlEncode $_.ExceptionOwner); expires $(HtmlEncode $_.ExceptionExpiresUtc).</p>" }) -join ''
        $grid.Add("<div class='panel'><h4>Documented accepted risk</h4><p>The finding remains visible and retains its severity and score.</p>$exceptionHtml</div>")
    }

    # --- affected objects (groups) / affected object (single) ---
    $membersHtml = ''
    $affectedHtml = ''
    if ($n -gt 1) {
        $previewRows = 25
        $sorted = @($members | Sort-Object { Format-EntraNaturalSortKey ([string]$(if ($_.AffectedPrincipal) { $_.AffectedPrincipal } elseif ($_.ObjectId) { $_.ObjectId } else { $_.Title })) })
        $sb = New-Object System.Text.StringBuilder
        $headObj = if ($Group.PerObject) { 'Affected object' } else { 'Finding' }
        [void]$sb.Append("<div class='panel evidence members'><h4>Finding records <span class='section-count'>($n)</span></h4>")
        [void]$sb.Append("<div class='filter-note'>Showing only the rows that match the search.</div>")
        [void]$sb.Append("<div class='result-block'><div class='result-scroll'><table class='result-table members-table'><thead><tr><th>#</th><th>$headObj</th><th>Object id</th><th>$(if ($gap) { 'What could not be checked' } else { 'What was found' })</th></tr></thead><tbody>")
        $i = 0
        foreach ($m in $sorted) {
            $i++
            $ma = New-FindingAnchor $m
            $fid = if ($TenantId) { New-FindingKey -TenantId $TenantId -Finding $m } else { '' }
            $label = if ($m.AffectedPrincipal) { [string]$m.AffectedPrincipal } elseif ($m.ObjectId) { [string]$m.ObjectId } else { [string]$m.Title }
            # Finding id before the (possibly long) evidence so the cap never cuts it off.
            $rowSearch = Get-EntraSearchText -Parts @($label, $m.ObjectType, $m.ObjectId, $fid, $m.Title, $m.Evidence) -Max 4000
            $cls = if ($i -gt $previewRows) { " class='extra'" } else { '' }
            $fidTitle = if ($fid) { " title='Finding id: $(HtmlAttrEncode $fid)'" } else { '' }
            $memberPopulation = Get-EntraPopulationText (Get-EntraPopulationRollup @($m))
            [void]$sb.Append("<tr id='$(HtmlAttrEncode $ma)'$cls data-search='$(HtmlAttrEncode $rowSearch)'><td class='nw'$fidTitle>$i</td><td>$(HtmlEncode $label)$(if ($m.ObjectType) { "<span class='idx-check'>$(HtmlEncode $m.ObjectType)</span>" })</td><td class='nw oid'>$(HtmlEncode $m.ObjectId)</td><td>$(HtmlEncode $m.Evidence)<div class='result-note'>$(HtmlEncode $memberPopulation)</div></td></tr>")
        }
        [void]$sb.Append('</tbody></table></div>')
        if ($n -gt $previewRows) { [void]$sb.Append("<button type='button' class='show-more' data-more='Show all $n rows' data-less='Show the first $previewRows rows only'>Show all $n rows</button>") }
        [void]$sb.Append('</div></div>')
        $membersHtml = $sb.ToString()
    } elseif ($first.AffectedPrincipal -or $first.ObjectId) {
        $affectedHtml = "<div class='result-note'>Affected object: <span class='mono'>$(HtmlEncode $(if ($first.AffectedPrincipal) { $first.AffectedPrincipal } else { $first.ObjectId }))</span>$(if ($first.ObjectType) { ' (' + (HtmlEncode $first.ObjectType) + ')' })</div>"
    }

    # --- result rows (merged across members; the linked CSV/TXT holds every row) ---
    $allRows = New-Object System.Collections.Generic.List[object]
    foreach ($m in $members) { foreach ($r in @($m.ResultRows)) { if ($null -ne $r) { $allRows.Add($r) } } }
    $rowCount = $allRows.Count
    $maxRows = 200
    $rowNote = if ($rowCount -gt $maxRows) { ", first $maxRows shown - the evidence file has all rows" } else { '' }
    $rowsHeading = if ($rowCount -gt 0) { "Result details <span class='section-count'>$rowCount row$(if ($rowCount -ne 1) { 's' })$rowNote</span>" } else { 'Result details' }
    # .result-rows + .hits-note: when only these rows explain a search match, the page shows
    # just the matching rows with this note (Get-EntraMainJs revealHits).
    $tableHtml = if ($rowCount -gt 0) { "<div class='result-rows'><div class='hits-note'>Showing only the result rows that match the search.</div>" + (New-EvidenceTableHtml -rows $allRows.ToArray() -maxRows $maxRows -PreviewRows 25) + '</div>' } else { "<div class='result-empty'>No detail rows were recorded for this finding.</div>" }
    $resultHtml = if ($n -gt 1) {
        if ($rowCount -gt 0) { "<details class='sub-details'><summary>$rowsHeading</summary>$tableHtml</details>" } else { '' }
    } else {
        "<div class='panel evidence'><h4>$rowsHeading</h4>$affectedHtml $tableHtml</div>"
    }

    # --- search index (includes text inside the collapsed body) ---
    # Capped (Get-EntraSearchText), so card-level facts go first, then member identifiers,
    # then member titles/evidence, then result rows. Whatever falls past the cap is still
    # found: the page search (Get-EntraMainJs) also checks every member row's own index and
    # the rendered text of the card (evidence, result tables), so a big group never hides
    # a member that is on the page.
    $searchParts = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($Group.Title, $category, $checkId, $checkTitle, $rule, $sev, $(if ($gap) { 'not assessed coverage gap' }))) { $searchParts.Add($x) }
    if ($n -eq 1 -and $TenantId) { $searchParts.Add((New-FindingKey -TenantId $TenantId -Finding $first)) }
    $whyAll = @(& $distinct 'WhyItMatters'); $actAll = @(& $distinct 'RecommendedAction' | ForEach-Object { Get-EntraDisplayAction $_ $docUrls })
    foreach ($x in @($whyAll | Select-Object -First 5) + @($actAll | Select-Object -First 5) + $docUrls + @($sources | ForEach-Object { ($_ -split '[\\/]')[-1] })) { $searchParts.Add($x) }
    foreach ($m in $members) { foreach ($x in @($m.AffectedPrincipal, $m.ObjectId, $m.ObjectType)) { $searchParts.Add($x) } }
    foreach ($m in $members) { foreach ($x in @($m.Title, $m.Evidence)) { $searchParts.Add($x) } }
    foreach ($x in @($whyAll | Select-Object -Skip 5) + @($actAll | Select-Object -Skip 5)) { $searchParts.Add($x) }
    $searchParts.Add((Get-EntraRowText -Rows $allRows.ToArray() -MaxRows 50))
    $search = Get-EntraSearchText -Parts $searchParts.ToArray()

    $gapClass = if ($gap) { ' coverage-gap' } else { '' }
    $checkChip = if ($checkId) { "<span class='category check mono' title='Check id'>$(HtmlEncode $checkId)</span>" } else { '' }
    $sevBadge = "<span class='badge sev-$sev'>$sev</span>"
@"
<details class="finding sev-$sev$gapClass" data-sev="$sev" data-gap="$([int]$gap)" data-check="$(HtmlAttrEncode $checkId)" data-category="$(HtmlAttrEncode $category)" data-count="$n" data-search="$(HtmlAttrEncode $search)" id="$(HtmlAttrEncode $Group.Anchor)">
  <summary>
    <div class="finding-head">
      <div class="finding-title-wrap">
        $sevBadge$gapBadge$exceptionBadge<span class="category">$(HtmlEncode $category)</span>$checkChip
        <span class="finding-title">$(HtmlEncode $Group.Title)</span>$countPill
      </div>
      <div class="finding-summary">$(HtmlEncode $preview)</div>
    </div>
  </summary>
  <div class="finding-body">
    $metaHtml
    <div class="finding-grid">
      $($grid -join "`n      ")
    </div>
    $membersHtml
    $resultHtml
  </div>
</details>
"@
}

function Get-EntraPrimaryNav([string]$Active, [string]$HrefPrefix = '') {
    # $HrefPrefix lets pages OUTSIDE the 'HTML Reports' folder (the per-dataset raw
    # pages live in 'Raw Data\Source') point back at the reports with '../../HTML Reports/'.
    $links = @(
        @{ Key='audit';   Href='EntraAudit-Results.html'; Label='Audit Results' }
        @{ Key='risk';    Href='Risk-Report.html';        Label='Risk Report' }
        @{ Key='posture'; Href='Posture-Summary.html';    Label='Posture Summary' }
        @{ Key='actions'; Href='Action-Register.html';    Label='Action Register' }
        @{ Key='raw';     Href='Raw-Data.html';           Label='Raw Data' }
    )
    $css = @'
<style>
.primary-nav{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 20px;padding:10px 14px;background:var(--panel,#fff);border:1px solid var(--line,#d9e0ea);border-radius:12px;box-shadow:var(--shadow,0 10px 24px rgba(15,23,42,.08))}
.primary-nav-link{padding:6px 12px;border-radius:999px;font-size:.85rem;font-weight:600;text-decoration:none;color:var(--text,#1b2430);border:1px solid transparent}
.primary-nav-link:hover{background:var(--accent-soft,#dbeafe);text-decoration:none}
.primary-nav-link.active{background:var(--accent,#3b82f6);color:#fff;border-color:var(--accent,#3b82f6)}
@media print{.primary-nav{display:none}}
</style>
'@
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($css)
    [void]$sb.Append("<nav class='primary-nav' aria-label='Audit reports'>")
    foreach ($l in $links) {
        $cls = if ($l.Key -eq $Active) { 'primary-nav-link active' } else { 'primary-nav-link' }
        $current = if ($l.Key -eq $Active) { " aria-current='page'" } else { '' }
        [void]$sb.Append("<a class='$cls' href='$(HtmlAttrEncode ($HrefPrefix + $l.Href))'$current>$(HtmlEncode $l.Label)</a>")
    }
    [void]$sb.Append('</nav>')
    $sb.ToString()
}

function New-EvidenceTableHtml {
    param($rows, [int]$maxRows = 200, [int]$PreviewRows = 0)
    $empty = "<div class='result-empty'>No matching objects were found for this check.</div>"
    if ($null -eq $rows) { return $empty }
    $arr = @(foreach ($r in @($rows)) {
        if ($null -eq $r) { continue }
        if ($r -is [System.Collections.IDictionary]) { [pscustomobject]$r }
        elseif ($r -is [string] -or $r -is [ValueType]) { [pscustomobject]@{ Value = $r } }
        else { $r }
    })
    if ($arr.Count -eq 0) { return $empty }
    if ($maxRows -lt 1) { $maxRows = 1 }
    $shownRows = @($arr | Select-Object -First $maxRows)

    $cols = New-Object System.Collections.Generic.List[string]
    $seenCols = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $shownRows) { foreach ($p in $r.PSObject.Properties) { if ($seenCols.Add($p.Name)) { $cols.Add($p.Name) } } }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='result-block'>")
    if ($arr.Count -gt $maxRows) {
        [void]$sb.Append("<div class='result-note'>Showing the first $maxRows of $($arr.Count) rows. The evidence file (CSV or TXT) has all of them.</div>")
    }
    [void]$sb.Append("<div class='result-scroll'><table class='result-table'><thead><tr>")
    foreach ($c in $cols) { [void]$sb.Append("<th>$(HtmlEncode $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    $i = 0
    foreach ($r in $shownRows) {
        $rowCls = if ($PreviewRows -gt 0 -and $i -ge $PreviewRows) { " class='extra'" } else { '' }
        [void]$sb.Append("<tr$rowCls>")
        foreach ($c in $cols) {
            $prop = $r.PSObject.Properties[$c]
            $s = if ($prop) { ConvertTo-EntraEvidenceCell $prop.Value } else { '' }
            # Keep identifiers, dates and other short single tokens (GUIDs, UPNs) on one line
            # instead of wrapping them over several; long text wraps normally.
            $nw = ($s.Length -gt 0 -and $s.Length -le 64 -and ($s -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-' -or $s -match '^\d{4}-\d{2}-\d{2}' -or ($s -notmatch '\s' -and $s.Length -le 48)))
            $tdCls = if ($nw) { " class='nw'" } else { '' }
            [void]$sb.Append("<td$tdCls>$(HtmlEncode $s)</td>")
        }
        [void]$sb.Append('</tr>'); $i++
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($PreviewRows -gt 0 -and $shownRows.Count -gt $PreviewRows) {
        $n = $shownRows.Count
        [void]$sb.Append("<button type='button' class='show-more' data-more='Show all $n rows' data-less='Show the first $PreviewRows rows only'>Show all $n rows</button>")
    }
    [void]$sb.Append('</div>')
    $sb.ToString()
}

function Get-EntraThemeScript {
@'
<script>
(function(){
  var KEY='entraaudit-theme';
  function stored(){var s=null;try{s=localStorage.getItem(KEY);}catch(e){}return (s==='light'||s==='dark')?s:null;}
  function osDark(){return !!(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);}
  function apply(t,save){document.documentElement.setAttribute('data-theme',t);if(document.body)document.body.setAttribute('data-theme',t);var b=document.getElementById('themeToggle');if(b)b.textContent=(t==='dark')?'Light mode':'Dark mode';if(save){try{localStorage.setItem(KEY,t);}catch(e){}}}
  apply(stored()||(osDark()?'dark':'light'),false);
  var b=document.getElementById('themeToggle');if(b)b.addEventListener('click',function(){apply(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark',true);});
  if(window.matchMedia){var mq=window.matchMedia('(prefers-color-scheme: dark)');var h=function(e){if(!stored())apply(e.matches?'dark':'light',false);};if(mq.addEventListener)mq.addEventListener('change',h);else if(mq.addListener)mq.addListener(h);}
  // One print lifecycle for every page, including report-only tables and raw data.
  var printDetails=null;
  window.addEventListener('beforeprint',function(){if(printDetails)return;printDetails=Array.prototype.map.call(document.querySelectorAll('details'),function(d){var state={element:d,open:d.open};d.open=true;return state;});});
  window.addEventListener('afterprint',function(){if(!printDetails)return;printDetails.forEach(function(s){s.element.open=s.open;});printDetails=null;});
})();
</script>
'@
}

function Get-EntraRawJs {
@'
<script>
(function(){
  function q(s){return document.querySelector(s);}
  function qa(s){return Array.prototype.slice.call(document.querySelectorAll(s));}
  var table=q('table.sortable');var body=(table&&table.tBodies.length)?table.tBodies[0]:null;
  function dataRows(){return body?Array.prototype.slice.call(body.rows).filter(function(r){return !r.classList.contains('no-data');}):[];}
  var checkFilter=null;try{var m=/[?&]check=([^&#]*)/.exec(location.search||'');if(m&&m[1])checkFilter=decodeURIComponent(m[1].replace(/\+/g,' '));}catch(e){}
  function apply(){var inp=q('#rawSearch');var v=((inp&&inp.value)||'').toLowerCase().trim();var shown=0,total=0;dataRows().forEach(function(r){total++;var ok=(!v||(r.textContent||'').toLowerCase().indexOf(v)>=0)&&(!checkFilter||r.getAttribute('data-check')===checkFilter);r.style.display=ok?'':'none';if(ok)shown++;});var c=q('#rawCount');if(c)c.textContent=shown+' of '+total+' '+((total===1&&c.getAttribute('data-noun-one'))||c.getAttribute('data-noun')||'rows')+' shown';}
  var note=q('#checkFilterNote');
  if(note&&checkFilter){note.style.display='';var nm=q('#checkFilterName');if(nm)nm.textContent=checkFilter;}
  var clr=q('#clearCheckFilter');if(clr)clr.addEventListener('click',function(e){e.preventDefault();checkFilter=null;if(note)note.style.display='none';try{history.replaceState(null,'',location.pathname+location.hash);}catch(_){}apply();});
  function val(r,i){var c=r.cells[i];if(!c)return '';var s=c.getAttribute('data-sort');return (s!==null?s:(c.textContent||'')).trim();}
  function kind(vals){var num=true,date=true,any=false;vals.forEach(function(x){if(x==='')return;any=true;if(num&&!/^-?\d+(\.\d+)?%?$/.test(x))num=false;if(date&&(!/^\d{4}-\d{2}-\d{2}/.test(x)||isNaN(Date.parse(x.replace(' ','T')))))date=false;});if(!any)return 'text';return num?'num':(date?'date':'text');}
  function sortCol(th,i){var dir=th.getAttribute('data-sort-dir')==='asc'?'desc':'asc';qa('table.sortable thead th').forEach(function(o){o.removeAttribute('data-sort-dir');o.removeAttribute('aria-sort');});th.setAttribute('data-sort-dir',dir);th.setAttribute('aria-sort',dir==='asc'?'ascending':'descending');var rows=dataRows();var vals=rows.map(function(r){return val(r,i);});var k=kind(vals);var idx=rows.map(function(r,j){return j;});idx.sort(function(a,b){var x=vals[a],y=vals[b];if(x===''&&y==='')return a-b;if(x==='')return 1;if(y==='')return -1;var c;if(k==='num'){c=parseFloat(x)-parseFloat(y);}else if(k==='date'){c=Date.parse(x.replace(' ','T'))-Date.parse(y.replace(' ','T'));}else{c=x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});}if(c===0)return a-b;return dir==='asc'?c:-c;});var frag=document.createDocumentFragment();idx.forEach(function(j){frag.appendChild(rows[j]);});body.appendChild(frag);}
  if(table&&body){qa('table.sortable thead th').forEach(function(th,i){th.setAttribute('title','Click to sort');th.setAttribute('tabindex','0');th.addEventListener('click',function(){sortCol(th,i);});th.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();sortCol(th,i);}});});}
  var inp=q('#rawSearch');if(inp)inp.addEventListener('input',apply);
  apply();
})();
</script>
'@
}

function Get-EntraRawCss {
@'
<style>
.container.raw-page{max-width:none}
.raw-table-wrap{border:1px solid var(--line);border-radius:10px;background:var(--panel);margin-top:8px}
.raw-table td{overflow-wrap:anywhere;white-space:pre-line}
.raw-table th{cursor:pointer;user-select:none;white-space:normal}
.raw-table th:hover{color:var(--text)}
.raw-table th[data-sort-dir="asc"]::after{content:" \25B2";font-size:10px}
.raw-table th[data-sort-dir="desc"]::after{content:" \25BC";font-size:10px}
.raw-status{margin-top:10px;font-size:13px;color:var(--muted);line-height:1.6}
.raw-status b{color:var(--text)}
.raw-notes{margin:8px 0 0;padding-left:18px;color:var(--muted);font-size:14px;line-height:1.6}
.raw-used{margin-top:14px;border-top:1px solid var(--line);padding-top:12px;font-size:14px;line-height:1.5}
.raw-used ul{margin:6px 0 0;padding-left:18px}.raw-used li{margin:4px 0}
.raw-used .badge{padding:2px 8px;font-size:11px}
.raw-err{color:var(--critical);font-size:13px;margin-top:4px}
.raw-empty{background:var(--panel);border:1px dashed var(--line);border-radius:14px;padding:16px;color:var(--muted);margin-top:8px;line-height:1.5}
.sub{display:block;color:var(--muted);font-size:12px;margin-top:2px}
.check-note{background:var(--accent-soft);border-radius:10px;padding:8px 12px;margin-top:10px;font-size:13px}
body[data-theme="dark"] .check-note{background:rgba(59,130,246,.22)}
.num,.raw-table td.num,.raw-table th.num{text-align:right;white-space:nowrap}
.raw-page .toolbar{margin-top:16px}
@media (max-width:700px){.raw-table-wrap{overflow-x:auto}}
.raw-used summary{cursor:pointer;font-weight:700}
</style>
'@
}

function New-RawDataHtml {
    param([string]$Path, [string]$Title, [object[]]$Rows, [string[]]$Notes, [string]$CsvName, [string]$TxtName,
          [string]$CheckId, [string]$CheckTitle, [bool]$CsvAvailable = $true, [bool]$TxtAvailable = $true, [int]$MaxRows = 2000)
    $css = (Get-EntraMainCss) + "`n" + (Get-EntraRawCss)
    $nav = Get-EntraPrimaryNav 'raw' '../../HTML Reports/'
    $js  = (Get-EntraThemeScript) + (Get-EntraRawJs)
    $arr = if ($null -eq $Rows) { @() } else { @($Rows.Where({ $null -ne $_ })) }
    $count = $arr.Count
    $shownCount = [math]::Min($count, $MaxRows)
    $truncated = $count -gt $MaxRows

    $tableHtml = ''
    if ($count -eq 0) {
        $tableHtml = "<div class='raw-empty'><b>This dataset is empty:</b> the check found nothing to list here. If the data could not be read, the audit says so in a &quot;Not assessed&quot; finding (listed above when there is one) and marks the check as incomplete on the Posture Summary; an empty table alone never hides a failed read.</div>"
    } else {
        $shown = if ($truncated) { $arr[0..($MaxRows - 1)] } else { $arr }
        # Columns = union of every shown row's properties (the first row alone can miss some).
        $cols = New-Object System.Collections.Generic.List[string]
        $seen = @{}
        foreach ($r in $shown) { foreach ($p in $r.PSObject.Properties) { if (-not $seen.ContainsKey($p.Name)) { $seen[$p.Name] = $true; $cols.Add($p.Name) | Out-Null } } }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append("<div class='raw-table-wrap'><table class='result-table raw-table sortable' id='rawTable'><thead><tr>")
        foreach ($c in $cols) { [void]$sb.Append("<th scope='col'>$(HtmlEncode $c)</th>") }
        [void]$sb.Append('</tr></thead><tbody>')
        foreach ($r in $shown) {
            [void]$sb.Append('<tr>')
            foreach ($c in $cols) {
                $p = $r.PSObject.Properties[$c]
                $s = if (-not $p -or $null -eq $p.Value) { '' }
                     elseif ($p.Value -is [string]) { $p.Value }
                     else { ConvertTo-EntraEvidenceCell $p.Value }
                [void]$sb.Append("<td>$(HtmlEncode $s)</td>")
            }
            [void]$sb.Append('</tr>')
        }
        [void]$sb.Append('</tbody></table></div>')
        $tableHtml = $sb.ToString()
    }

    $capNote = if ($truncated) { "<br><b>This page shows the first $MaxRows of $count rows.</b> Download the CSV or TXT file for every row." } else { '' }
    $notesHtml = if ($Notes.Count -gt 0) { "<ul class='raw-notes'>" + (($Notes | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join '') + '</ul>' } else { '' }
    $checkHtml = if ($CheckId) {
        $label = if ($CheckTitle) { "$(HtmlEncode $CheckTitle) (<span class='mono'>$(HtmlEncode $CheckId)</span>)" } else { "<span class='mono'>$(HtmlEncode $CheckId)</span>" }
        "From check: <a href='../../HTML Reports/Posture-Summary.html#check-$(HtmlAttrEncode $CheckId)'>$label</a><br>"
    } else { '' }
    $dl = @()
    if ($CsvAvailable) { $dl += "<a href='$(HtmlAttrEncode $CsvName)' download>CSV</a>" }
    if ($TxtAvailable) { $dl += "<a href='$(HtmlAttrEncode $TxtName)' download>TXT</a>" }
    $dlHtml = if ($dl.Count -gt 0) { 'Download all rows: ' + ($dl -join ' &middot; ') } else { "<span class='raw-err'>The CSV and TXT files for this dataset could not be written.</span>" }
    if ($dl.Count -eq 1) { $dlHtml += " <span class='raw-err'>($(if ($CsvAvailable) { 'TXT' } else { 'CSV' }) file could not be written.)</span>" }
    $gen = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
    $toolbar = if ($count -gt 0) {
@"
  <section class="toolbar">
    <div class="toolbar-row">
      <div class="filter"><label for="rawSearch">Filter rows</label><input id="rawSearch" type="text" placeholder="Type to filter the table"></div>
    </div>
    <div class="raw-status"><span id="rawCount" data-noun="rows" data-noun-one="row">$shownCount of $shownCount $(if ($shownCount -eq 1) { 'row' } else { 'rows' }) shown</span> &middot; Click a column heading to sort.$capNote</div>
  </section>
"@
    } else { '' }
    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Audit - $(HtmlEncode $Title)</title>
$css
</head>
<body data-theme="light">
<div class="container raw-page">
$nav
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>$(HtmlEncode $Title)</h1>
        <div class="meta">
          Evidence data: <b>$count</b> row$(if ($count -ne 1) { 's' }) &middot; Generated: $(HtmlEncode $gen)<br>
          $checkHtml$dlHtml &middot; <a href="../../HTML Reports/Raw-Data.html">All datasets</a> &middot; <a href="../../HTML Reports/EntraAudit-Results.html">Audit results</a>
        </div>
        $notesHtml
        <!--EA-USEDBY-->
      </div>
      <div class="hero-actions"><button type="button" class="theme-toggle" id="themeToggle">Dark mode</button></div>
    </div>
  </section>
$toolbar
  $tableHtml
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Get-EntraSharedPresentationCss {
@'
<style>
a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible,th[tabindex]:focus-visible{outline:3px solid var(--accent,#2563eb)!important;outline-offset:3px}
button.metric{font:inherit;color:var(--text);text-align:left;cursor:pointer;width:100%}
.quick-actions{margin:14px 0 0;padding:14px!important}.quick-actions h2,.quick-actions h3{margin:0 0 8px;font-size:16px}.quick-actions ul,.quick-actions ol{margin:6px 0 0;padding-left:22px}.quick-actions li{margin:8px 0;line-height:1.45}
.change-summary{font-size:13px;line-height:1.6;margin:12px 0}.risk-line>.result-note{display:block;margin-top:5px}
@media screen and (max-width:520px){.metrics,.metrics.small{grid-template-columns:repeat(3,minmax(0,1fr));gap:6px;margin-top:12px}.metric{padding:9px 7px}.metric-label{font-size:10px;letter-spacing:.02em}.metric-value{font-size:22px}.metric-sub{font-size:10px}.grid>.card{grid-column:span 6;min-height:70px;padding:10px}.card .k{font-size:10px;letter-spacing:.04em}.card .v{font-size:20px}.quick-actions{padding:12px!important}.quick-actions .section-header{display:block}.quick-actions .section-count{margin-top:4px}.h-main{flex-basis:auto}.header,.hero{padding:16px}.meta{font-size:12px}}
@page{margin:12mm}
@media print{
html,html[data-theme],body,body[data-theme]{color-scheme:light!important;--bg:#fff!important;--bg-glow1:transparent!important;--bg-glow2:transparent!important;--panel:#fff!important;--panel-soft:#f4f4f4!important;--text:#111!important;--muted:#444!important;--line:#bbb!important;--shadow:none!important;--result-panel:#fff!important;--link:#174f91!important;--accent:#174f91!important;--accent-soft:#edf2f8!important;--accent-text:#174f91!important;--critical:#a00!important;--high:#9a4300!important;--medium:#005b8d!important;--low:#245c27!important;--information:#444!important;--critical-soft:#fff!important;--high-soft:#fff!important;--medium-soft:#fff!important;--low-soft:#fff!important;--information-soft:#fff!important;--critical-bg:#fff!important;--high-bg:#fff!important;--medium-bg:#fff!important;--low-bg:#fff!important;--info-bg:#fff!important;--critical-text:#a00!important;--high-text:#9a4300!important;--medium-text:#005b8d!important;--low-text:#245c27!important;--info-text:#444!important;--pre-bg:#fff!important;--pre-text:#111!important;background:#fff!important;color:#111!important}
body{font-size:10pt!important}a,body[data-theme] a{color:#174f91!important}.container{max-width:none!important;width:auto!important;padding:0!important}.primary-nav,.sidebar,.toolbar,.filters,.theme-toggle,.show-more,.no-print,a[download],button:not(.metric),input,select{display:none!important}
.header,.hero,.card,.metric,.finding,.panel,.priority,.callout,.quick-actions{box-shadow:none!important;background:#fff!important}.layout{display:block!important}.result-scroll,.result-block,.raw-table-wrap{overflow:visible!important;max-height:none!important}
table,.followup-table{display:table!important;width:100%!important;max-width:100%!important;table-layout:fixed!important;overflow:visible!important;font-size:8pt!important}thead,.followup-table thead{display:table-header-group!important}tbody,.followup-table tbody{display:table-row-group!important}tfoot{display:table-footer-group!important}.followup-table tr{display:table-row!important}.followup-table td{display:table-cell!important}.followup-table td::before{display:none!important}th,td,.nw{white-space:normal!important;overflow-wrap:anywhere!important;word-break:normal!important;padding:5px!important}
thead,tr,.panel,.metric,.card{break-inside:avoid}.finding,.section,.callout,.priority,.quick-actions{break-inside:auto}h1,h2,h3,h4,summary,thead{break-after:avoid}p,li{orphans:3;widows:3}.result-block tr.extra{display:table-row}.print-only{display:block!important}
}
</style>
'@
}

function Get-EntraMainCss {
@'
<style>
:root{
  --bg:#f5f7fb;--panel:#ffffff;--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;
  --shadow:0 10px 24px rgba(15,23,42,.08);
  --critical:#c62828;--high:#ef6c00;--medium:#0277bd;--low:#2e7d32;--information:#6c757d;
  --critical-soft:#fdecec;--high-soft:#fff2e5;--medium-soft:#e8f4fd;--low-soft:#edf8ee;--information-soft:#f2f4f6;
  --result-panel:#ffffff;--accent:#3b82f6;--accent-soft:#dbeafe;--accent-text:#1e40af;
}
body[data-theme="dark"]{
  --bg:#0f172a;--panel:#111827;--text:#e5e7eb;--muted:#94a3b8;--line:#334155;
  --shadow:0 10px 24px rgba(0,0,0,.35);
  --critical:#f87171;--high:#fb923c;--medium:#60a5fa;--low:#4ade80;--information:#cbd5e1;
  --critical-soft:rgba(248,113,113,.15);--high-soft:rgba(251,146,60,.14);--medium-soft:rgba(96,165,250,.14);
  --low-soft:rgba(74,222,128,.14);--information-soft:rgba(203,213,225,.12);--result-panel:#0b1220;
  --accent-soft:rgba(59,130,246,.22);--accent-text:#bfdbfe;
}
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);}
a{color:#0f5cb8;text-decoration:none}
body[data-theme="dark"] a{color:#93c5fd}
a:hover{text-decoration:underline}
.container{max-width:1280px;margin:0 auto;padding:28px 22px 48px}
.hero{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:24px;}
.hero-top{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;align-items:flex-start;}
.hero-actions{display:flex;flex-direction:column;align-items:flex-end;gap:12px;}
.theme-toggle{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:999px;padding:10px 14px;font-size:13px;font-weight:700;cursor:pointer;}
.theme-toggle:hover{transform:translateY(-1px)}
h1{margin:0 0 8px;font-size:28px}
.meta{color:var(--muted);font-size:14px;line-height:1.6}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:22px}
.metric{border:1px solid var(--line);border-radius:14px;padding:14px 16px;background:var(--panel);}
.metric-label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
.metric-value{font-size:30px;font-weight:800;margin-top:6px}
.metric.sev-Critical{background:var(--critical-soft)}
.metric.sev-High{background:var(--high-soft)}
.metric.sev-Medium{background:var(--medium-soft)}
.metric.sev-Low{background:var(--low-soft)}
.metric.sev-Information{background:var(--information-soft)}
.layout{display:grid;grid-template-columns:280px minmax(0,1fr);gap:20px;margin-top:20px}
.sidebar{position:sticky;top:18px;align-self:start;background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;}
.sidebar h3,.content h2{margin-top:0}
.sidebar ul{list-style:none;padding:0;margin:0}
.sidebar li{margin:10px 0}
.index-group{margin-top:18px;padding-top:18px;border-top:1px solid var(--line)}
.index-group h4{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.index-detail{border:1px solid var(--line);border-radius:12px;padding:8px 10px;background:#f8fafc;margin-bottom:10px}
body[data-theme="dark"] .index-detail{background:var(--result-panel)}
.index-detail summary{cursor:pointer;font-weight:700;list-style:none}
.index-detail summary::-webkit-details-marker{display:none}
.index-detail ol{margin:10px 0 0 18px;padding:0;max-height:260px;overflow:auto}
.index-detail li{margin:6px 0}
.index-detail a{color:var(--text)}
.badge{display:inline-flex;align-items:center;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:800;letter-spacing:.02em;margin-right:8px;border:1px solid transparent;}
.badge.sev-Critical{background:var(--critical-soft);color:var(--critical);border-color:rgba(198,40,40,.25)}
.badge.sev-High{background:var(--high-soft);color:var(--high);border-color:rgba(239,108,0,.25)}
.badge.sev-Medium{background:var(--medium-soft);color:var(--medium);border-color:rgba(2,119,189,.25)}
.badge.sev-Low{background:var(--low-soft);color:var(--low);border-color:rgba(46,125,50,.25)}
.badge.sev-Information{background:var(--information-soft);color:var(--information);border-color:rgba(108,117,125,.25)}
.category{display:inline-flex;align-items:center;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:700;color:var(--muted);background:#f4f6f9;border:1px solid var(--line);margin-right:8px;}
body[data-theme="dark"] .category{background:#1f2937}
.toolbar{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:16px;margin-bottom:18px;}
.toolbar-row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;}
label{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
select,input{width:100%;min-height:42px;border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:var(--panel);color:var(--text);}
.filter{min-width:220px;flex:1}
.section-header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:0 0 12px;}
.section-header h2{margin:0;font-size:24px}
.section-count{color:var(--muted);font-size:14px;font-weight:700}
.finding{background:var(--panel);border:1px solid var(--line);border-left:6px solid var(--information);border-radius:16px;box-shadow:var(--shadow);margin-bottom:14px;overflow:hidden;}
.finding.sev-Critical{border-left-color:var(--critical)}
.finding.sev-High{border-left-color:var(--high)}
.finding.sev-Medium{border-left-color:var(--medium)}
.finding.sev-Low{border-left-color:var(--low)}
.finding.sev-Information{border-left-color:var(--information)}
.finding summary{list-style:none;cursor:pointer;padding:18px 18px 16px;}
.finding summary::-webkit-details-marker{display:none}
.finding-head{display:flex;flex-direction:column;gap:10px}
.finding-title-wrap{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.finding-title{font-size:18px;font-weight:800}
.finding-summary{color:var(--muted);line-height:1.5}
.finding-body{padding:0 18px 18px}
.finding-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.panel{background:#f8fafc;border:1px solid var(--line);border-radius:12px;padding:14px;}
body[data-theme="dark"] .panel{background:var(--result-panel)}
.panel h4{margin:0 0 8px;font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.panel p{margin:0;line-height:1.55}
.panel.evidence{margin-top:12px}
.priority{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;margin-bottom:18px}
.priority ul{margin:0;padding-left:18px}
.priority li{margin:10px 0;line-height:1.5}
.priority-title{font-weight:700;color:var(--text)}
.priority-evidence{display:block;color:var(--muted);margin-top:4px}
.empty{background:var(--panel);border:1px dashed var(--line);border-radius:14px;padding:16px;color:var(--muted)}
.mono{font-family:Consolas,Menlo,Monaco,monospace}
.download-link{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:10px 14px;border-radius:10px;border:1px solid var(--line);background:var(--panel);color:var(--text);font-weight:700;max-width:260px;}
.result-note{font-size:13px;color:var(--muted);margin:10px 0}
.result-scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel);}
.result-table{width:100%;border-collapse:collapse;font-size:13px;}
.result-table th,.result-table td{border-bottom:1px solid var(--line);padding:10px 12px;vertical-align:top;text-align:left;overflow-wrap:break-word;}
.result-table th{position:sticky;top:0;background:#eef2f7;z-index:1;}
body[data-theme="dark"] .result-table th{background:#0b1220}
.result-table td.nw{white-space:nowrap}
.result-block tr.extra{display:none}
.result-block.show-all tr.extra{display:table-row}
.result-empty{color:var(--muted);line-height:1.5}
.status-table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.status-table th,.status-table td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;font-size:14px}
.status-table th{color:var(--muted);text-transform:uppercase;font-size:12px;letter-spacing:.06em}
.pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:800;border:1px solid var(--line)}
.pill.ok{background:var(--low-soft);color:var(--low)}
.pill.info{background:var(--information-soft);color:var(--information)}
.pill.find{background:var(--high-soft);color:var(--high)}
.pill.skip{background:var(--information-soft);color:var(--information)}
.pill.err{background:var(--critical-soft);color:var(--critical)}
.pill.gap{background:var(--information-soft);color:var(--information);border-style:dashed}
.pill.notrun{background:transparent;color:var(--muted);border-style:dotted}
/* Results page: coverage, grouping, filters, print */
.risk-line{margin-top:6px;font-size:15px;color:var(--text)}
.risk-line .band{font-weight:800}
.callout{border:1px solid var(--line);border-left:6px solid var(--accent);border-radius:14px;padding:14px 16px;background:var(--panel);margin-top:18px;line-height:1.55;box-shadow:var(--shadow)}
.callout.warn{border-left-color:var(--high);background:var(--high-soft)}
.callout.ok{border-left-color:var(--low);background:var(--low-soft)}
.callout b{color:var(--text)}
button.metric{font:inherit;color:inherit;text-align:left;cursor:pointer;width:100%;display:flex;flex-direction:column;justify-content:flex-start}
button.metric:hover{transform:translateY(-1px)}
.metric.active{outline:3px solid var(--accent);outline-offset:1px}
.metric.gap{background:var(--information-soft);border-style:dashed}
.metric-sub{font-size:12px;color:var(--muted);margin-top:4px}
.metrics-caption{margin:18px 0 0;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
.metrics.small{margin-top:8px;grid-template-columns:repeat(auto-fit,minmax(118px,1fr))}
.metrics.small .metric{padding:10px 12px}
.metrics.small .metric-value{font-size:22px;margin-top:2px}
.metrics.small a.metric,body[data-theme="dark"] .metrics.small a.metric{color:var(--text);text-decoration:none}
.metric.warn{background:var(--high-soft)}
.metric.bad{background:var(--critical-soft)}
.badge.gap{background:var(--information-soft);color:var(--information);border:1px dashed var(--information)}
.finding.coverage-gap{border-left-style:dashed;border-left-color:var(--information)}
.finding.coverage-gap>summary{background:repeating-linear-gradient(135deg,transparent 0 14px,var(--information-soft) 14px 16px)}
.count-pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:800;background:var(--accent-soft);color:var(--accent-text);border:1px solid rgba(59,130,246,.3)}
.category.check{font-size:11px}
.finding-summary{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.finding[open] .finding-summary{display:none}
.finding{scroll-margin-top:16px}
.finding-meta{font-size:12px;color:var(--muted);margin:0 0 12px;line-height:1.8;overflow-wrap:anywhere}
.finding-meta b{color:var(--text)}
.finding-meta code,.howto code{font-family:Consolas,Menlo,Monaco,monospace;background:var(--information-soft);border-radius:6px;padding:1px 6px}
.panel p{overflow-wrap:break-word}
.panel p+p{margin-top:8px}
.doc-link{margin-top:10px;font-size:13px;overflow-wrap:anywhere}
.doc-link .doc-url{display:none}
.members-table td:first-child{color:var(--muted);width:1%}
.members-table td:nth-child(2){min-width:150px}
.members-table td.oid{font-size:12px;color:var(--muted)}
.members-table td:last-child{min-width:300px}
.filter-note{display:none;font-size:13px;color:var(--accent-text);background:var(--accent-soft);border-radius:8px;padding:6px 10px;margin:0 0 8px}
.finding.rows-filtered .filter-note{display:block}
.finding.rows-filtered tr[data-search]{display:none}
.finding.rows-filtered tr[data-search].row-match{display:table-row}
.finding.rows-filtered .show-more{display:none}
.result-table tr.row-target td{background:var(--accent-soft)}
.result-table tr.row-hit td{background:var(--accent-soft)}
.hits-note{display:none;font-size:13px;color:var(--accent-text);background:var(--accent-soft);border-radius:8px;padding:6px 10px;margin:0 0 8px}
.finding.reveal-hits .result-rows .hits-note{display:block}
.finding.reveal-hits .result-rows tbody tr{display:none}
.finding.reveal-hits .result-rows tbody tr.row-hit{display:table-row}
.finding.reveal-hits .result-rows .show-more{display:none}
.show-more,.btn{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:10px;padding:8px 12px;font-size:13px;font-weight:700;cursor:pointer}
.show-more{margin-top:8px}
.show-more:hover,.btn:hover{border-color:var(--accent)}
.sub-details{margin-top:12px;border:1px solid var(--line);border-radius:12px;padding:10px 14px;background:#f8fafc}
body[data-theme="dark"] .sub-details{background:var(--result-panel)}
.sub-details>summary{cursor:pointer;font-weight:700;font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:0;display:list-item;list-style:disclosure-closed inside}
.sub-details[open]>summary{margin-bottom:10px;list-style-type:disclosure-open}
.toolbar-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px}
.visible-count{margin-left:auto;color:var(--muted);font-size:13px;font-weight:700}
.howto,.checks{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:16px 18px;margin-bottom:18px}
.howto>summary,.checks>summary{cursor:pointer;font-weight:800;font-size:18px}
.howto ul{margin:10px 0 0;padding-left:18px;line-height:1.6}
.howto li{margin:6px 0}
.checks .status-table{margin-top:12px}
.checks .result-block{overflow-x:auto}
.checks .status-table td{vertical-align:top}
.checks .status-table tr:target td,.checks .status-table tr.row-target td{background:var(--accent-soft)}
.check-reason{color:var(--muted);font-size:13px;line-height:1.5}
.check-error{font-size:12px;color:var(--critical);margin-top:4px;overflow-wrap:anywhere}
.idx-check{display:block;font-size:11px;color:var(--muted)}
.print-only{display:none}
@media (max-width: 980px){.layout{grid-template-columns:minmax(0,1fr)}.sidebar{position:static}.hero-actions{align-items:flex-start}}
@media (max-width: 520px){.container{padding:20px 12px 40px}.hero{padding:18px}h1{font-size:24px}.metric-value{font-size:24px}}
.sidebar,.content,.hero-top>div{min-width:0}
.index-detail a,.priority-title,.finding-title,.meta{overflow-wrap:anywhere}
@media print{
  body,body[data-theme="dark"]{--bg:#fff;--panel:#fff;--text:#111;--muted:#444;--line:#ccc;--result-panel:#fff;--shadow:none;--accent-soft:#e8f0fe;--accent-text:#1e40af;background:#fff;color:#111}
  .sidebar,.toolbar,.theme-toggle,.show-more,.no-print{display:none!important}
  .container{max-width:none;padding:0}
  .layout{display:block;margin-top:12px}
  .hero,.priority,.finding,.howto,.checks,.callout{box-shadow:none}
  .finding summary{cursor:auto}
  .finding[open] .finding-summary{display:none}
  .panel,.metric,.priority li,.result-table tr{break-inside:avoid}
  .finding summary{break-after:avoid}
  .result-block tr.extra{display:table-row}
  .result-scroll{overflow:visible}
  .doc-link .doc-url{display:inline;color:#444}
  .print-only{display:block}
}
</style>
'@ + (Get-EntraSharedPresentationCss)
}

function Get-EntraMainJs {
@'
<script>
(function(){
  function q(s){return document.querySelector(s);}
  function qa(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s));}
  function findings(){return qa('.finding');}
  var sf=q('#severityFilter'),cf=q('#categoryFilter'),kf=q('#checkFilter'),se=q('#searchFilter');
  function val(el){return el?el.value:'All';}
  // Search text: lower case, whitespace collapsed (data-search attributes are built the same way).
  function norm(s){return (s||'').toLowerCase().replace(/\s+/g,' ');}
  // The pre-built data-search text also matches content inside closed cards. It is capped,
  // so a card also matches on any affected-object row (own index + cell text) and on the
  // rendered data in its body (evidence, result tables); headings and buttons are not searched.
  function hay(el){return el.getAttribute('data-search')||norm(el.textContent);}
  function cached(el,k,fn){k='__search_'+k;if(el[k]===undefined)el[k]=fn();return el[k];}
  function cellText(tr){return cached(tr,'cells',function(){var member=tr.hasAttribute('data-search');return norm(qa('td',tr).filter(function(td,i){return !(member&&i===0);}).map(function(td){return td.textContent;}).join(' '));});}
  function memberRows(it){return qa('tr[data-search]',it);}
  function resultRows(it){return qa('.result-rows tbody tr',it);}
  function rowHit(r,query){return hay(r).indexOf(query)>=0||cellText(r).indexOf(query)>=0;}
  function bodyText(it){return cached(it,'body',function(){return norm(qa('.finding-body .panel p,.finding-body .doc-url,.finding-body .mono',it).map(function(e){return e.textContent;}).join(' '));});}
  function cardHit(it,query){return !query||hay(it).indexOf(query)>=0||memberRows(it).some(function(r){return rowHit(r,query);})||resultRows(it).some(function(r){return cellText(r).indexOf(query)>=0;})||bodyText(it).indexOf(query)>=0;}
  // Severity filter: one severity, 'Risk' (Critical to Low), 'Gap' (only "Not assessed") or 'NoGap' (all but "Not assessed").
  function sevMatch(it,sev){var s=it.getAttribute('data-sev');var gap=it.getAttribute('data-gap')==='1';if(sev==='All')return true;if(sev==='Gap')return gap;if(gap)return false;if(sev==='NoGap')return true;if(sev==='Risk')return s!=='Information';return s===sev;}
  function filterRows(it,query){var rows=memberRows(it);if(!rows.length)return;var m=rows.map(function(r){return !!query&&rowHit(r,query);});var on=m.indexOf(true)>=0;it.classList.toggle('rows-filtered',on);rows.forEach(function(r,i){r.classList.toggle('row-match',on&&m[i]);});}
  // Result rows holding the search text are highlighted. When the visible summary and the
  // affected-objects table do not explain the match (reveal), the result table shows only
  // the matching rows (with a note) and a closed "Result details" section is opened. Undone
  // when the search changes or is cleared, unless the reader opened or closed it by hand.
  function revealHits(it,query,reveal){
    var any=false;resultRows(it).forEach(function(r){var h=!!query&&cellText(r).indexOf(query)>=0;r.classList.toggle('row-hit',h);if(h)any=true;});
    reveal=!!(reveal&&any);it.classList.toggle('reveal-hits',reveal);
    qa('.sub-details',it).forEach(function(d){var want=reveal&&!!d.querySelector('tr.row-hit');if(want&&!d.open){d.open=true;d.setAttribute('data-auto-open','1');}else if(!want&&d.getAttribute('data-auto-open')==='1'){d.open=false;d.removeAttribute('data-auto-open');}});
  }
  function isShown(el){while(el&&el!==document.body){if(el.style&&el.style.display==='none')return false;el=el.parentElement;}return true;}
  function applyFilters(){
    var sev=val(sf),cat=val(cf),chk=val(kf),query=norm((se&&se.value)||'').trim();
    var active=sev!=='All'||cat!=='All'||chk!=='All'||!!query;var cards=0,items=0,allCards=0,allItems=0;
    findings().forEach(function(it){
      var n=parseInt(it.getAttribute('data-count')||'1',10)||1;allCards++;allItems+=n;
      var show=sevMatch(it,sev)&&(cat==='All'||it.getAttribute('data-category')===cat)&&(chk==='All'||it.getAttribute('data-check')===chk)&&cardHit(it,query);
      it.style.display=show?'':'none';if(show){cards++;items+=n;}
      var hit=show&&!!query;
      filterRows(it,hit?query:'');
      var sm=it.querySelector('summary');var inSummary=hit&&!!sm&&norm(sm.textContent).indexOf(query)>=0;var memberHit=it.classList.contains('rows-filtered');
      revealHits(it,hit?query:'',hit&&!inSummary&&!memberHit);
      if(hit){if((!inSummary||memberHit)&&!it.open){it.open=true;it.setAttribute('data-auto-open','1');}}
      else if(it.getAttribute('data-auto-open')==='1'){it.open=false;it.removeAttribute('data-auto-open');}
    });
    qa('.severity-section').forEach(function(sec){var cs=qa('.finding',sec);var n=cs.filter(function(c){return c.style.display!=='none';}).length;var sc=sec.querySelector('.section-count');if(sc){if(!sc.hasAttribute('data-base'))sc.setAttribute('data-base',sc.textContent);sc.textContent=active?(n+' of '+cs.length+' shown'):sc.getAttribute('data-base');}sec.style.display=(active&&n===0)?'none':'';});
    var vc=q('#visibleFindings');if(vc)vc.textContent=active?('Showing '+cards+' of '+allCards+(allCards===1?' card (':' cards (')+items+' of '+allItems+(allItems===1?' finding)':' findings)')):((allCards===1?'Showing 1 card (':'Showing all '+allCards+' cards (')+allItems+(allItems===1?' finding)':' findings)'));
    var nr=q('#noResults');if(nr)nr.style.display=(active&&cards===0)?'':'none';
    var pn=q('#printFilterNote');if(pn){var parts=[];if(sev!=='All')parts.push('severity = '+(sf.options[sf.selectedIndex]||{}).text);if(chk!=='All')parts.push('check = '+chk);if(cat!=='All')parts.push('category = '+cat);if(query)parts.push('search = "'+query+'"');pn.textContent=parts.length?('Printed with filters applied: '+parts.join(', ')+'. Some findings are not shown.'):'';}
    qa('.metric[data-sev-filter]').forEach(function(m){var selected=active&&m.getAttribute('data-sev-filter')===sev;m.setAttribute('aria-pressed',selected?'true':'false');if(selected)m.classList.add('active');else m.classList.remove('active');});
  }
  function resetFilters(){if(sf)sf.value='All';if(cf)cf.value='All';if(kf)kf.value='All';if(se)se.value='';applyFilters();}
  function setOption(sel,v){if(!sel||v===null||v===undefined)return false;v=String(v).toLowerCase();for(var i=0;i<sel.options.length;i++){if(sel.options[i].value.toLowerCase()===v){sel.selectedIndex=i;return true;}}return false;}
  if(sf)sf.addEventListener('change',applyFilters);
  if(cf)cf.addEventListener('change',applyFilters);
  if(kf)kf.addEventListener('change',applyFilters);
  if(se)se.addEventListener('input',applyFilters);
  var rs=q('#resetFilters');if(rs)rs.addEventListener('click',resetFilters);
  function visibleCards(){return findings().filter(function(d){return d.style.display!=='none';});}
  // A card or "Result details" section the reader opens or closes by hand stays that way when the search is cleared.
  document.addEventListener('click',function(e){var s=e.target&&e.target.closest?e.target.closest('summary'):null;if(s&&s.parentNode&&s.parentNode.removeAttribute)s.parentNode.removeAttribute('data-auto-open');},true);
  var ea=q('#expandAll');if(ea)ea.addEventListener('click',function(){visibleCards().forEach(function(d){d.open=true;d.removeAttribute('data-auto-open');});});
  var ca=q('#collapseAll');if(ca)ca.addEventListener('click',function(){visibleCards().forEach(function(d){d.open=false;d.removeAttribute('data-auto-open');});});
  qa('.metric[data-sev-filter]').forEach(function(m){m.addEventListener('click',function(){var v=m.getAttribute('data-sev-filter');if(!sf)return;sf.value=(sf.value===v)?'All':v;applyFilters();var t=q('#findings-start');if(t)t.scrollIntoView({block:'start'});});});
  qa('[data-filter-check]').forEach(function(a){a.addEventListener('click',function(e){e.preventDefault();resetFilters();setOption(kf,a.getAttribute('data-filter-check'));applyFilters();var t=q('#findings-start');if(t)t.scrollIntoView({block:'start'});});});
  qa('.show-more').forEach(function(btn){btn.addEventListener('click',function(){var blk=btn.closest('.result-block');if(!blk)return;var on=!blk.classList.contains('show-all');if(on)blk.classList.add('show-all');else blk.classList.remove('show-all');btn.textContent=on?btn.getAttribute('data-less'):btn.getAttribute('data-more');});});
  // Deep links: open the target card (and a grouped card's row), clearing filters that hide it.
  function openTarget(){var id='';try{id=decodeURIComponent((location.hash||'').slice(1));}catch(e){id=(location.hash||'').slice(1);}if(!id)return;var t=document.getElementById(id);if(!t)return;
    if(!isShown(t))resetFilters();
    var p=t;while(p&&p!==document.body){if(p.tagName==='DETAILS')p.open=true;p=p.parentElement;}
    qa('.row-target').forEach(function(r){r.classList.remove('row-target');});
    if(t.tagName==='TR'){var blk=t.closest('.result-block');if(blk){blk.classList.add('show-all');var btn=blk.querySelector('.show-more');if(btn)btn.textContent=btn.getAttribute('data-less');}t.classList.add('row-target');}
    setTimeout(function(){t.scrollIntoView({block:(t.tagName==='TR'?'center':'start')});},0);}
  window.addEventListener('hashchange',openTarget);
  document.addEventListener('click',function(e){var a=e.target&&e.target.closest?e.target.closest('a[href^="#"]'):null;if(!a||a.hasAttribute('data-filter-check'))return;var id=a.getAttribute('href').slice(1);if(id&&('#'+id)===location.hash){e.preventDefault();openTarget();}});
  // Shared print expansion/restoration is installed by Get-EntraThemeScript.
  // URL parameters preselect the filters (links from the other report pages):
  // ?check=<check id>  ?sev=Critical|High|Medium|Low|Information|Risk|Gap|NoGap  ?q=<search text>
  try{var ps=new URLSearchParams(location.search);setOption(kf,ps.get('check'));setOption(sf,ps.get('sev'));if(se&&ps.get('q'))se.value=ps.get('q');}catch(e){}
  applyFilters();
  openTarget();
})();
</script>
'@
}

function Get-EntraRiskCss {
@'
<style>
:root{--bg:#f5f7fb;--bg-glow1:rgba(105,177,255,.10);--bg-glow2:rgba(255,169,64,.10);--panel:#ffffff;--panel-soft:rgba(15,23,42,.04);--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;--shadow:0 10px 24px rgba(15,23,42,.08);--radius:14px;--critical-bg:#fdecec;--critical-text:#c62828;--high-bg:#fff2e5;--high-text:#ef6c00;--medium-bg:#e8f4fd;--medium-text:#0277bd;--low-bg:#edf8ee;--low-text:#2e7d32;--info-bg:#f2f4f6;--info-text:#6c757d;--link:#0f5cb8;--pre-bg:#f8fafc;--pre-text:#1b2430;--accent:#3b82f6;--accent-soft:#dbeafe;}
@media (prefers-color-scheme: dark){:root{--bg:#0b1220;--bg-glow1:rgba(105,177,255,.18);--bg-glow2:rgba(255,169,64,.16);--panel:#111827;--panel-soft:rgba(255,255,255,.06);--text:#e8edf6;--muted:#b7c0d6;--line:rgba(255,255,255,.10);--shadow:0 10px 30px rgba(0,0,0,.35);--critical-bg:rgba(255,77,79,.18);--critical-text:#fecaca;--high-bg:rgba(255,169,64,.18);--high-text:#fed7aa;--medium-bg:rgba(105,177,255,.18);--medium-text:#bfdbfe;--low-bg:rgba(149,222,100,.18);--low-text:#bbf7d0;--info-bg:rgba(160,160,160,.18);--info-text:#e2e8f0;--link:#cfe1ff;--pre-bg:rgba(0,0,0,.25);--pre-text:#dbe6ff;--accent-soft:rgba(59,130,246,.22);}}
html[data-theme="light"]{--bg:#f5f7fb;--panel:#ffffff;--panel-soft:rgba(15,23,42,.04);--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;--shadow:0 10px 24px rgba(15,23,42,.08);--critical-bg:#fdecec;--critical-text:#c62828;--high-bg:#fff2e5;--high-text:#ef6c00;--medium-bg:#e8f4fd;--medium-text:#0277bd;--low-bg:#edf8ee;--low-text:#2e7d32;--info-bg:#f2f4f6;--info-text:#6c757d;--link:#0f5cb8;--pre-bg:#f8fafc;--pre-text:#1b2430;--accent-soft:#dbeafe;}
html[data-theme="dark"]{--bg:#0b1220;--panel:#111827;--panel-soft:rgba(255,255,255,.06);--text:#e8edf6;--muted:#b7c0d6;--line:rgba(255,255,255,.10);--shadow:0 10px 30px rgba(0,0,0,.35);--critical-bg:rgba(255,77,79,.18);--critical-text:#fecaca;--high-bg:rgba(255,169,64,.18);--high-text:#fed7aa;--medium-bg:rgba(105,177,255,.18);--medium-text:#bfdbfe;--low-bg:rgba(149,222,100,.18);--low-text:#bbf7d0;--info-bg:rgba(160,160,160,.18);--info-text:#e2e8f0;--link:#cfe1ff;--pre-bg:rgba(0,0,0,.25);--pre-text:#dbe6ff;--accent-soft:rgba(59,130,246,.22);}
*{box-sizing:border-box}
body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:radial-gradient(1200px 700px at 20% 10%,var(--bg-glow1),transparent 60%),radial-gradient(1200px 700px at 80% 0%,var(--bg-glow2),transparent 55%),var(--bg);color:var(--text);}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
.container{max-width:1200px;margin:0 auto;padding:28px 20px 60px}
.header{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:22px 22px 18px;}
.h-title{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;flex-wrap:wrap}
.h-main{flex:1 1 520px;min-width:0}
.h-side{flex:0 0 auto;margin-left:auto;display:flex;flex-direction:column;align-items:flex-end;gap:10px}
h1{font-size:22px;margin:0 0 6px;letter-spacing:.2px}
.meta{color:var(--muted);font-size:13px;line-height:1.5}
.theme-toggle{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:999px;padding:8px 14px;font-size:13px;font-weight:700;cursor:pointer;margin-bottom:10px;}
.theme-toggle:hover{filter:brightness(1.05)}
.badge{display:inline-flex;align-items:center;gap:10px;padding:10px 12px;border-radius:999px;border:1px solid var(--line);background:var(--panel-soft);font-weight:700;}
.badge .grade{font-size:13px;color:var(--muted);font-weight:600}
.badge .value{font-size:15px}
.badge.Critical{background:var(--critical-bg);color:var(--critical-text)}
.badge.High{background:var(--high-bg);color:var(--high-text)}
.badge.Medium{background:var(--medium-bg);color:var(--medium-text)}
.badge.Low{background:var(--low-bg);color:var(--low-text)}
.badge.Information{background:var(--info-bg);color:var(--info-text);border-style:dashed}
.badge-note{font-size:12px;color:var(--muted);text-align:right;max-width:340px;line-height:1.4}
.badge-sep{width:1px;height:28px;background:var(--line)}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin-top:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:14px 14px 12px;min-height:88px;}
a.card{display:block;color:inherit;text-decoration:none}a.card:hover{border-color:var(--accent);text-decoration:none}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em}
.card .v{font-size:22px;font-weight:800;margin-top:6px}
.card .s{margin-top:4px;color:var(--muted);font-size:12px;line-height:1.4}
.card.warn{border-color:var(--high-text);background:var(--high-bg)}
.card.warn .k,.card.warn .s{color:var(--text)}
.span-2{grid-column:span 2}.span-3{grid-column:span 3}.span-4{grid-column:span 4}.span-6{grid-column:span 6}.span-12{grid-column:span 12}
@media (max-width:900px){.grid>.card{grid-column:span 6}}
@media (max-width:520px){.grid>.card{grid-column:span 12}.h-side{flex:1 1 100%;margin-left:0;align-items:flex-start}.badge{flex-wrap:wrap}.badge-sep{display:none}.badge-note{text-align:left}.container{padding:20px 12px 48px}}
.pill{display:inline-flex;align-items:center;justify-content:center;padding:4px 10px;border-radius:999px;font-weight:800;font-size:12px;border:1px solid var(--line);min-width:86px;}
.pill.mini{min-width:0;max-width:100%;padding:2px 8px;font-size:11px;margin:1px 3px 1px 0;white-space:normal;overflow-wrap:anywhere}
.pill.ok{background:var(--low-bg);color:var(--low-text)}
.pill.info{background:var(--info-bg);color:var(--info-text)}
.pill.find{background:var(--high-bg);color:var(--high-text)}
.pill.skip{background:var(--info-bg);color:var(--info-text)}
.pill.err{background:var(--critical-bg);color:var(--critical-text)}
.pill.gap{background:var(--info-bg);color:var(--info-text);border-style:dashed}
.pill.notrun{background:transparent;color:var(--muted);border-style:dotted}
.sev-Critical{background:var(--critical-bg);color:var(--critical-text)}
.sev-High{background:var(--high-bg);color:var(--high-text)}
.sev-Medium{background:var(--medium-bg);color:var(--medium-text)}
.sev-Low{background:var(--low-bg);color:var(--low-text)}
.sev-Information{background:var(--info-bg);color:var(--info-text)}
.section{margin-top:18px}.section h2{margin:0 0 10px;font-size:16px}
.section-lead{margin:-4px 0 10px;color:var(--muted);font-size:13px;line-height:1.5}
.callout{border:1px solid var(--line);border-radius:var(--radius);padding:14px;background:var(--panel)}
.callout p{margin:0;line-height:1.5}.callout p+p{margin-top:8px}.callout ul{margin:10px 0 0 18px}.callout li{margin:6px 0}
.callout ol{margin:8px 0 0 20px;padding:0}.callout ol li{margin:6px 0;line-height:1.45}
.callout.warn{border-left:5px solid var(--high-text)}
.callout.ok{border-left:5px solid var(--low-text)}
.callout h3{margin:14px 0 4px;font-size:14px}
.summary-lead{font-size:15px}
.risk-list{list-style:none;margin:0 !important;padding:0}
.risk-list li{display:flex;gap:10px;align-items:flex-start;padding:9px 0;border-bottom:1px solid var(--line);margin:0 !important}
.risk-list li:last-child{border-bottom:0}
.risk-list .pill{flex:0 0 auto}
.risk-list li>div{min-width:0;overflow-wrap:anywhere}
.li-sub{display:block;color:var(--muted);font-size:12px;margin-top:2px;line-height:1.4}
.muted{color:var(--muted)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin:10px 0}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
select,input{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:8px 10px;outline:none;}
input{min-width:240px}
small{color:var(--muted)}
table{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;background:var(--panel)}
th,td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em;background:var(--panel-soft);text-align:left}
th[data-sort]{cursor:pointer;user-select:none}
tr:hover td{background:var(--panel-soft)}
tr:target td{background:var(--accent-soft)}
#checkTable td{font-size:14px;line-height:1.45}
#checkTable th:nth-child(1){width:21%}#checkTable th:nth-child(2){width:15%}#checkTable th:nth-child(3){width:13%}#checkTable th:nth-child(4){width:32%}#checkTable th:nth-child(5){width:19%}
td.title{font-weight:700}
td .sub{display:block;color:var(--muted);font-size:12px;margin-top:3px;font-weight:400}
td.num{text-align:right;white-space:nowrap}
table.kv th{width:230px;text-align:left;text-transform:none;letter-spacing:0;font-size:13px;color:var(--muted);font-weight:600}
table.kv td{font-size:13px;line-height:1.5}
.chip{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:1px 6px;margin:2px 4px 2px 0;font-size:12px;background:var(--panel-soft)}
.status-code{display:block;font-size:11px;color:var(--muted);margin-top:4px}
.err-msg{display:block;font-size:12px;color:var(--muted);margin-top:4px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;overflow-wrap:anywhere}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
td.source .mono{font-size:12px;color:var(--link)}
details.more>summary{cursor:pointer;color:var(--link);margin:10px 0;font-weight:600}
details.all-findings>summary{cursor:pointer;font-size:16px;font-weight:700;margin:0 0 10px}
details.all-findings>summary small{font-weight:400}
.footer{margin-top:16px;color:var(--muted);font-size:12px;line-height:1.5}
.matrix-wrap{margin-top:10px}
table.matrix{table-layout:fixed;}
table.matrix th,table.matrix td{padding:14px 18px;}
table.matrix th{cursor:default;}
table.matrix th:nth-child(1),table.matrix td:nth-child(1){width:22%;padding-left:22px;}
table.matrix th:nth-child(2),table.matrix td:nth-child(2){width:16%;text-align:center;}
table.matrix th:nth-child(3),table.matrix td:nth-child(3){width:62%;padding-left:22px;}
.matrix-row.active td{background:var(--panel-soft);font-weight:600}
@media (max-width:700px){table{display:block;overflow-x:auto}}
</style>
'@ + (Get-EntraSharedPresentationCss)
}

function Get-EntraRiskJs {
@'
<script>
(function(){
  function q(s){return document.querySelector(s);}
  function qa(s){return Array.prototype.slice.call(document.querySelectorAll(s));}
  var tbody=q('#findings-body');
  if(tbody){
    var sf=q('#sevFilter'),se=q('#search'),vc=q('#visibleCount');
    var rows=function(){return qa('#findings-body tr');};
    var applyFilters=function(){var sev=sf?sf.value:'All';var s=((se&&se.value)||'').toLowerCase().trim();var visible=0;rows().forEach(function(r){var rs=r.getAttribute('data-sev');var gap=r.getAttribute('data-gap')==='1';var okSev=(sev==='All')||(sev==='Not assessed'?gap:rs===sev);var text=(r.textContent||'').toLowerCase();var show=okSev&&((!s)||(text.indexOf(s)>=0));r.style.display=show?'':'none';if(show)visible++;});if(vc)vc.textContent=visible;};
    var sortCol=null,sortAsc=false,order=['Critical','High','Medium','Low','Information'];
    var sortBy=function(col){sortAsc=(sortCol===col)?!sortAsc:true;sortCol=col;qa('th[data-sort]').forEach(function(th){th.setAttribute('aria-sort',th.getAttribute('data-sort')===col?(sortAsc?'ascending':'descending'):'none');});var arr=rows().slice().sort(function(a,b){var ka,kb;if(col==='severity'){ka=order.indexOf(a.getAttribute('data-sev'));kb=order.indexOf(b.getAttribute('data-sev'));}else if(col==='title'){ka=((a.querySelector('.title')||{}).textContent||'').toLowerCase();kb=((b.querySelector('.title')||{}).textContent||'').toLowerCase();}else{ka=a.textContent;kb=b.textContent;}if(ka<kb)return sortAsc?-1:1;if(ka>kb)return sortAsc?1:-1;return 0;});arr.forEach(function(r){tbody.appendChild(r);});applyFilters();};
    if(sf)sf.addEventListener('change',applyFilters);
    if(se)se.addEventListener('input',applyFilters);
    qa('th[data-sort]').forEach(function(th){th.setAttribute('title','Sort with Enter, Space or click');th.setAttribute('tabindex','0');th.setAttribute('scope','col');th.addEventListener('click',function(){sortBy(th.getAttribute('data-sort'));});th.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();sortBy(th.getAttribute('data-sort'));}});});
    sortBy('severity');
  }
  var cf=q('#checkFilter');
  if(cf){
    var applyChecks=function(){var v=cf.value;var shown=0;qa('#checkTable tbody tr').forEach(function(r){var g=(r.getAttribute('data-group')||'').split(' ');var ok=v==='all'||(v==='attention'?(g.indexOf('findings')>=0||g.indexOf('gaps')>=0):g.indexOf(v)>=0);if(!ok&&location.hash==='#'+r.id)ok=true;r.style.display=ok?'':'none';if(ok)shown++;});var c=q('#checkCount');if(c)c.textContent=shown;};
    cf.addEventListener('change',applyChecks);
    window.addEventListener('hashchange',applyChecks);
    applyChecks();
  }
})();
</script>
'@
}

$script:RiskPoints = @{ Critical = 25; High = 10; Medium = 4; Low = 1; Information = 0 }

$script:RiskBands = @(
    [pscustomobject]@{ Level='Critical'; Min=150; Meaning='Very high accumulated finding points. Highest confirmed severity and action priority are shown separately.' }
    [pscustomobject]@{ Level='High';     Min=60;  Meaning='High accumulated finding points. Highest confirmed severity and action priority are shown separately.' }
    [pscustomobject]@{ Level='Moderate'; Min=20;  Meaning='Moderate accumulated finding points. A single Critical issue can fall in this band and still needs immediate action.' }
    [pscustomobject]@{ Level='Low';      Min=1;   Meaning='Low accumulated finding points. A single High issue can fall in this band and still needs prompt action.' }
    [pscustomobject]@{ Level='Clean';    Min=0;   Meaning='No problems found, and every selected check ran and read all of its data. Keep monitoring.' }
)

function Get-EntraRemediationUrgency {
    param([object]$Score)
    if (Get-EAField $Score 'OpenRemediationUrgency') { return [string](Get-EAField $Score 'OpenRemediationUrgency') }
    foreach ($severity in @('Critical','High','Medium','Low')) {
        if ([int](Get-EAField $Score.ConfirmedCounts $severity) -gt 0) { return $severity }
    }
    if (-not $Score.CoverageComplete) { return 'Assessment needed' }
    return 'No confirmed issues'
}

$script:RiskCoverageBands = @(
    [pscustomobject]@{ Level='Not fully assessed'; Meaning='No problems were found in the data that could be read, but some checks were skipped, stopped with an error or could not read all of their data (or it is not known which checks ran). This is NOT a clean result.' }
    [pscustomobject]@{ Level='Not assessed';       Meaning='None of the selected checks gave a result (all were skipped or stopped with an error). Nothing can be concluded about the tenant.' }
)

function Get-EntraIssueKey([object]$f) {
    $sev = Normalize-Severity $f.Severity
    $issueTitle = [string]$f.Title
    if (($f.AffectedPrincipal -or $f.ObjectId) -and $issueTitle.Contains(':')) { $issueTitle = (($issueTitle -split ':', 2)[0]).Trim() }
    $rule = if ($f.RuleId) { [string]$f.RuleId } else { (($issueTitle -replace '\d+','') -replace '[^A-Za-z]+','-').Trim('-').ToLowerInvariant() }
    [pscustomobject]@{ Key = ('{0}|{1}|{2}' -f [string]$f.CheckId, $rule, $sev); Rule = $rule; Severity = $sev; IssueTitle = $issueTitle }
}

function Get-EntraRunCoverage {
    param(
        [System.Collections.IDictionary]$CheckStatus = $script:CheckStatus,
        [object]$RunInfo = $script:RunInfo,
        [System.Collections.IDictionary]$Registry = $script:Registry
    )
    if ($null -eq $CheckStatus) { $CheckStatus = [ordered]@{} }
    if ($null -eq $Registry) { $Registry = [ordered]@{} }
    # Selected = the run's selection plus anything that recorded a status.
    $selected = New-Object System.Collections.Generic.List[string]
    $runSel = if ($RunInfo) { Get-EAField $RunInfo 'SelectedChecks' } else { $null }
    foreach ($k in @($runSel) + @($CheckStatus.Keys)) { $id = [string]$k; if ($id -and -not $selected.Contains($id)) { $selected.Add($id) } }
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Registry.Keys) { $ids.Add([string]$k) }
    foreach ($k in $selected) { if (-not $ids.Contains($k)) { $ids.Add($k) } }
    $known = $selected.Count -gt 0

    $rows = foreach ($id in $ids) {
        $reg = if ($Registry.Contains($id)) { $Registry[$id] } else { $null }
        $st = if ($CheckStatus.Contains($id)) { $CheckStatus[$id] } else { $null }
        $sv = { param($n) if ($null -ne $st) { Get-EAField $st $n } else { $null } }
        $isSelected = $selected.Contains($id)
        $title = if (& $sv 'Title') { [string](& $sv 'Title') } elseif ($reg) { [string]$reg.Title } else { $id }
        $status = if ($st) { [string](& $sv 'Status') } elseif ($isSelected) { 'NoResult' } else { 'NotRun' }
        $count = [int](& $sv 'Count')
        $info = [int](& $sv 'InfoCount')
        $cov = [int](& $sv 'CoverageCount')
        $partial = [bool](& $sv 'Partial')
        $missing = @(& $sv 'MissingScopes' | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $err = [string](& $sv 'ErrorMessage'); if (-not $err) { $err = $null }
        $reason = [string](& $sv 'Reason')
        $incomplete = $status -match 'Incomplete'
        $tier = if ($reg -and $reg.P2) { 'P2' } elseif ($reg -and $reg.P1) { 'P1' } else { 'P1 or P2' }

        $group = switch -Regex ($status) {
            '^NotRun$'         { 'notrun'; break }
            '^Error'           { 'error'; break }
            '^Skipped'         { 'skipped'; break }
            '^RiskFindings'    { 'findings'; break }
            'Incomplete'       { 'incomplete'; break }
            '^(Pass|InfoOnly)' { 'clean'; break }
            default            { 'noresult' }   # NoResult, or a status this report does not know
        }
        # A count of findings, not of issues (the report's grouped cards) - see Invoke-AuditCheck.
        $issues = if ($count -eq 1) { '1 finding' } else { "$count findings" }
        $label = switch ($group) {
            'notrun'     { if ($known) { 'Not run' } else { 'Unknown' } }
            'noresult'   { 'No result' }
            'error'      { if ($partial) { 'Stopped part-way' } else { 'Error' } }
            'skipped'    {
                switch ($status) {
                    'Skipped-NoScope'        { 'Skipped: missing permission' }
                    'Skipped-NoPermission'   { 'Skipped: access denied' }
                    'Skipped-NoLicense'      { 'Skipped: no license' }
                    'Skipped-LicenseUnknown' { 'Skipped: license unknown' }
                    default                  { 'Skipped' }
                }
            }
            'findings'   { if ($incomplete) { "$issues, incomplete" } else { $issues } }
            'incomplete' { 'Incomplete' }
            default      { if ($info -gt 0) { 'Passed (with notes)' } else { 'Passed' } }
        }
        if (-not $reason) {
            $verb = if ($count -eq 1) { 'needs' } else { 'need' }
            $reason = switch ($group) {
                'notrun'     { if ($known) { 'Not selected for this run, so this area was not checked.' } else { 'No check status was recorded, so it is not known whether this check ran.' } }
                'noresult'   { if ($status -and $status -ne 'NoResult') { "Recorded a status this report does not recognise ($status), so treat this area as not checked." } else { 'Was selected but recorded no result (the run may have stopped early), so this area was not checked.' } }
                'error'      {
                    if ($partial) { "Stopped part-way after recording $issues. The findings shown are real, but there may be more." }
                    elseif ($err) { "Stopped with an error, so this area was not checked: $err" } else { 'Stopped with an error, so this area was not checked.' }
                }
                'skipped'    {
                    switch ($status) {
                        'Skipped-NoScope' {
                            $need = if ($missing.Count -gt 0) { $missing } elseif ($reg -and $reg.Scopes) { @($reg.Scopes) } else { @() }
                            if ($need.Count -gt 0) { "The sign-in is missing a permission this check needs: $($need -join ', ')." } else { 'The sign-in is missing a permission this check needs.' }
                        }
                        'Skipped-NoPermission'   { 'Microsoft Graph denied access: the audit account or app lacks a permission or admin role this check needs.' }
                        'Skipped-NoLicense'      { "Needs a Microsoft Entra ID $tier license, which was not found in this tenant." }
                        'Skipped-LicenseUnknown' { "Needs a Microsoft Entra ID $tier license. The license lookup failed, so it is unknown whether the tenant has one." }
                        default                  { 'Skipped, so this area was not checked.' }
                    }
                }
                'findings'   { if ($incomplete) { "$issues $verb attention. Some data could not be read, so there may be more." } else { "$issues $verb attention." } }
                'incomplete' { 'No problems found in the data that could be read, but some data could not be read. This is not a clean result.' }
                default      { 'No problems found.' }
            }
        }
        $class = switch ($group) { 'clean' { 'ok' } 'findings' { 'find' } 'incomplete' { 'gap' } 'skipped' { 'skip' } 'notrun' { 'notrun' } default { 'err' } }
        # Worst first: did not run, then skipped, then partly read, then problems, then passed.
        $order = switch ($group) { 'error' { 0 } 'noresult' { 0 } 'skipped' { 1 } 'incomplete' { 2 } 'findings' { if ($incomplete) { 2 } else { 3 } } 'clean' { 4 } default { 5 } }
        [pscustomobject]@{
            CheckId = $id; Title = $title; Selected = $isSelected; Status = $status; Group = $group; Label = $label; Class = $class
            Reason = $reason; ErrorMessage = $err; MissingScopes = $missing
            Count = $count; InfoCount = $info; CoverageCount = $cov; Incomplete = $incomplete; Partial = $partial; SortOrder = $order
            DurationSeconds = (& $sv 'DurationSeconds')
        }
    }
    $rows = @($rows)
    $sel = @($rows | Where-Object { $_.Selected })
    $clean = @($sel | Where-Object { $_.Group -eq 'clean' }).Count
    # A check that stopped part-way still found real problems: it counts here AND as an error.
    $withFindings = @($sel | Where-Object { $_.Group -eq 'findings' -or ($_.Group -eq 'error' -and $_.Count -gt 0) }).Count
    $incompleteN = @($sel | Where-Object { $_.Incomplete }).Count
    $skipped = @($sel | Where-Object { $_.Group -eq 'skipped' }).Count
    $errored = @($sel | Where-Object { $_.Group -in @('error','noresult') }).Count
    $evaluated = @($sel | Where-Object { $_.Group -in @('clean','findings','incomplete') }).Count
    [pscustomobject]@{
        Known = $known
        Rows = $rows
        Total = $Registry.Count
        Selected = $sel.Count
        Evaluated = $evaluated                          # ran to the end (possibly with data gaps)
        FullyEvaluated = $evaluated - $incompleteN      # ran to the end and read all of its data
        Clean = $clean; WithFindings = $withFindings; Incomplete = $incompleteN
        Skipped = $skipped; Errored = $errored
        NotRun = @($rows | Where-Object { $_.Group -eq 'notrun' }).Count
        Complete = ($sel.Count -gt 0 -and ($skipped + $errored + $incompleteN) -eq 0)
    }
}

function Get-EntraCoverageGapText {
    param([Parameter(Mandatory)][object]$Coverage, [switch]$Short)
    $parts = @()
    if ($Coverage.Skipped -gt 0)    { $parts += "$($Coverage.Skipped) skipped$(if (-not $Short) { ' (missing permission or license)' })" }
    if ($Coverage.Errored -gt 0)    { $parts += "$($Coverage.Errored) stopped with an error" }
    if ($Coverage.Incomplete -gt 0) { $parts += "$($Coverage.Incomplete) incomplete$(if (-not $Short) { ' (some data could not be read)' })" }
    if ($parts.Count -le 1) { return ($parts -join '') }
    ($parts[0..($parts.Count - 2)] -join ', ') + ' and ' + $parts[-1]
}

function Get-EntraCoverageTile {
    param([Parameter(Mandatory)][object]$Coverage)
    $c = $Coverage
    @(
        [pscustomobject]@{ Key = 'selected'; Label = 'Checks selected'; Value = $c.Selected; Hint = 'Chosen for this run'; State = '' }
        [pscustomobject]@{ Key = 'pass'; Label = 'Passed'; Value = $c.Clean; Hint = 'Fully checked, no problems'; State = '' }
        [pscustomobject]@{ Key = 'findings'; Label = 'Problems found'; Value = $c.WithFindings; Hint = 'Need action'; State = '' }
        [pscustomobject]@{ Key = 'incomplete'; Label = 'Incomplete'; Value = $c.Incomplete; Hint = 'Some data could not be read'; State = $(if ($c.Incomplete) { 'warn' } else { '' }) }
        [pscustomobject]@{ Key = 'skipped'; Label = 'Skipped'; Value = $c.Skipped; Hint = 'Missing permission or license'; State = $(if ($c.Skipped) { 'warn' } else { '' }) }
        [pscustomobject]@{ Key = 'errors'; Label = 'Errors'; Value = $c.Errored; Hint = 'Stopped before finishing'; State = $(if ($c.Errored) { 'bad' } else { '' }) }
        [pscustomobject]@{ Key = 'notrun'; Label = 'Not run'; Value = $c.NotRun; Hint = 'Not selected this time'; State = '' }
    )
}

function Get-EntraPopulationRollup {
    param([object[]]$Items)
    $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $largest = 0; $fallback = 0; $hasCountOnly = $false; $hasObjects = $false
    $assessed = $null; $unknown = $null; $labels = [System.Collections.Generic.List[string]]::new()
    $measurements = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @($Items)) {
        $p = Get-EntraFindingPopulation $f
        $measurements.Add($p)
        if ($p.Label -and -not $labels.Contains([string]$p.Label)) { $labels.Add([string]$p.Label) }
        if ($p.ScoringBasis -eq 'FindingRecord') { $fallback++; continue }
        $hasObjects = $true
        foreach ($id in @($p.Ids)) { if ($id) { [void]$ids.Add(('{0}|{1}' -f $p.ObjectType, $id)) } }
        if (-not $p.IdsComplete) { $hasCountOnly = $true; $largest = [math]::Max($largest, [int]$p.ScoringCount) }
    }
    # Count-only populations may overlap one another and the named objects. Take
    # the largest known population rather than adding unverifiable duplicates.
    $affected = if ($hasObjects) { [math]::Max($ids.Count, $largest) } else { $null }
    # Record-only members do not prove that any additional distinct objects exist.
    $units = if ($hasObjects) { [int]$affected } else { $fallback }
    $basis = if (-not $hasObjects) { 'FindingRecord' } elseif ($hasCountOnly -or $fallback) { 'PopulationLowerBound' } else { 'ObjectIds' }
    # A maximum denominator silently merges scopes. Keep a denominator only when
    # every record supplies the same measurement and it can contain the union.
    $m = $measurements.ToArray()
    $labelsAgree = @($m | ForEach-Object { '{0}|{1}' -f $_.ObjectType,$_.Label } | Sort-Object -Unique).Count -eq 1
    $assessedValues = @($m | Where-Object { $null -ne $_.AssessedCount } | ForEach-Object { [int]$_.AssessedCount })
    if ($assessedValues.Count -eq $m.Count -and $m.Count -gt 0 -and $labelsAgree -and @($assessedValues | Sort-Object -Unique).Count -eq 1 -and $assessedValues[0] -ge [int]$affected) {
        $assessed = $assessedValues[0]
    }
    $unknownValues = @($m | Where-Object { $null -ne $_.UnknownCount } | ForEach-Object { [int]$_.UnknownCount })
    # Equal unknown totals from different populations are not evidence of a shared
    # unknown population. Only repeated complete identifier sets establish that.
    $samePopulation = $m.Count -eq 1
    if ($m.Count -gt 1 -and $labelsAgree -and @($m | Where-Object { -not $_.IdsComplete }).Count -eq 0) {
        $signatures = @($m | ForEach-Object { (@($_.Ids | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object) -join "`n") } | Sort-Object -Unique)
        $samePopulation = $signatures.Count -eq 1
    }
    if ($samePopulation -and $unknownValues.Count -eq $m.Count -and $m.Count -gt 0 -and @($unknownValues | Sort-Object -Unique).Count -eq 1) { $unknown = $unknownValues[0] }
    $measurementNote = if (($assessedValues.Count -and $null -eq $assessed) -or ($unknownValues.Count -and $null -eq $unknown)) { 'Shared assessed/unknown totals could not be established; see the individual finding measurements.' } else { '' }
    [pscustomobject]@{
        AffectedCount=$affected; AssessedCount=$assessed; UnknownCount=$unknown
        ScoringCount=[math]::Max(0,$units); ScoringBasis=$basis; DistinctIdCount=$ids.Count
        Label=$(if ($labels.Count -eq 1) { $labels[0] } else { 'objects' })
        MeasurementNote=$measurementNote
    }
}

function Get-EntraPopulationText {
    param([object]$Population)
    if ($Population.ScoringBasis -eq 'FindingRecord') { return "Population not recorded; $($Population.ScoringCount) finding record(s) used for scoring." }
    $text = "Affected: $($Population.AffectedCount) $($Population.Label)"
    if ($null -ne $Population.AssessedCount) { $text += " of $($Population.AssessedCount) assessed" } else { $text += '; assessed total not established' }
    if ($null -ne $Population.UnknownCount) { $text += "; $($Population.UnknownCount) unknown" } else { $text += '; unknown total not established' }
    if ($Population.ScoringBasis -eq 'PopulationLowerBound') { $text += '. Estimated lower bound: object identifiers are incomplete and overlap cannot be fully resolved' }
    if ($Population.MeasurementNote) { $text += '. ' + $Population.MeasurementNote.TrimEnd('.') }
    return ($text + '.')
}

function Get-EntraChangeSummaryHtml {
    $follow = Get-Variable -Name FollowUp -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not $follow) { return '' }
    $state = [string](Get-EAField $follow 'ComparisonState')
    if ($state -ne 'Compared with compatible previous run') { return "<p class='change-summary'><a href='Action-Register.html'>Changes since previous run:</a> $(HtmlEncode $state).</p>" }
    $rows = @(Get-EAField $follow 'Comparison')
    $parts = foreach ($status in @('New','Still present','Resolved','No longer assessed','Previously not assessed','Outside current window')) {
        $n = @($rows | Where-Object { [string](Get-EAField $_ 'Status') -eq $status }).Count
        "<b>$n</b> $(HtmlEncode $status.ToLowerInvariant())"
    }
    "<p class='change-summary'><a href='Action-Register.html'>Changes since previous run:</a> $($parts -join ' &middot; ').</p>"
}

function Get-EntraRiskScore {
    param([object[]]$findings, [System.Collections.IDictionary]$CheckStatus = $script:CheckStatus)
    # Ruleset 2.2 scores each check/rule/severity as weight * sqrt(scoring population).
    # Explicit identifiers are deduplicated within each confirmed or gap part. Counts
    # without complete identifiers use a conservative lower bound; only groups with
    # no population evidence fall back to finding records. ResultRows never supply N.
    # ConfirmedScore is the headline. The legacy combined Score also includes the
    # marginal contribution of unknowns: weight * (sqrt(confirmed + gap) - sqrt(confirmed)).
    # Gaps are not confirmed weaknesses and remain separate, even if they name an
    # object with a confirmed weakness. Rounded components add to the combined score.
    # Coverage prevents an unassessed zero from being labelled Clean. Accepted risks
    # retain severity and points; only open-work priority changes. Severity counts
    # remain finding-record counts for compatibility with the detailed Results page.
    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0 }
    $confirmedCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0 }
    $gapCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0 }
    $openCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0 }
    $buckets = [ordered]@{}
    foreach ($f in $findings) {
        if ($null -eq $f) { continue }
        $sev = Normalize-Severity $f.Severity
        $counts[$sev]++
        $isGap = [bool](Test-EntraCoverageGap $f)
        if ($isGap) { $gapCounts[$sev]++ } else { $confirmedCounts[$sev]++ }
        if (-not $isGap -and -not [bool](Get-EAField $f 'AcceptedRisk')) { $openCounts[$sev]++ }
        if ($sev -eq 'Information') { continue }
        # One scoring bucket per issue (see Get-EntraIssueKey): 28 permanent Global Admins
        # score 25 x sqrt(28) instead of 28 single-count buckets, which would defeat the
        # diminishing returns entirely. The confirmed and the not-assessed findings of an
        # issue are tracked as two report parts (internal key only - the published issue
        # key is unchanged) but scored together, see DESIGN CHOICE above.
        $issue = Get-EntraIssueKey $f
        $k = $issue.Key + $(if ($isGap) { '|gap' } else { '' })
        if ($buckets.Contains($k)) {
            $buckets[$k].Count++
            $buckets[$k].Members.Add($f)
            if ($f.AffectedPrincipal -and $buckets[$k].Principals.Count -lt 5) { $buckets[$k].Principals.Add([string]$f.AffectedPrincipal) | Out-Null }
        } else {
            $pr = New-Object System.Collections.Generic.List[string]
            if ($f.AffectedPrincipal) { $pr.Add([string]$f.AffectedPrincipal) | Out-Null }
            $buckets[$k] = @{
                Key = $issue.Key; Rule = $issue.Rule; Severity = $sev; Count = 1; CheckId = [string]$f.CheckId
                Title = $issue.IssueTitle; FirstTitle = [string]$f.Title; FirstAnchor = (New-FindingAnchor $f)
                RecommendedAction = [string]$f.RecommendedAction; WhyItMatters = [string]$f.WhyItMatters
                SourceFile = [string]$f.SourceFile; DocumentationUrl = [string]$f.DocumentationUrl
                CoverageGap = $isGap; Principals = $pr
                Members = [System.Collections.Generic.List[object]]::new()
            }
            $buckets[$k].Members.Add($f)
        }
    }
    $confirmedPopulations = @{}
    foreach ($b in $buckets.Values) {
        $b.Population = Get-EntraPopulationRollup $b.Members.ToArray()
        if (-not $b.CoverageGap) { $confirmedPopulations[$b.Key] = $b.Population.ScoringCount }
    }
    $raw = 0.0; $gapRaw = 0.0
    foreach ($b in $buckets.Values) {
        # Both parts of an issue share its severity (it is part of the key), so the parts
        # add up to points * sqrt(total) - the single-bucket score.
        $unit = $script:RiskPoints[$b.Severity]
        $b.Points = if ($b.CoverageGap) {
            # Unknown sub-controls remain a separate dimension, even if they name
            # an object with another confirmed weakness. Deduplicate within each
            # part, never erase a gap just because the object has a known finding.
            $confirmedN = if ($confirmedPopulations.ContainsKey($b.Key)) { [int]$confirmedPopulations[$b.Key] } else { 0 }
            $unit * ([math]::Sqrt($confirmedN + $b.Population.ScoringCount) - [math]::Sqrt($confirmedN))
        } else { $unit * [math]::Sqrt($b.Population.ScoringCount) }
        $raw += $b.Points
        if ($b.CoverageGap) { $gapRaw += $b.Points }
    }
    $drivers = foreach ($b in $buckets.Values) {
        $pts = $b.Points
        $accepted = @($b.Members | Where-Object { [bool](Get-EAField $_ 'AcceptedRisk') })
        [pscustomobject]@{
            Key = $b.Key; Rule = $b.Rule; Severity = $b.Severity; CheckId = $b.CheckId; Title = $b.Title; Count = $b.Count
            Points = [math]::Round($pts, 1)
            Share = $(if ($raw -gt 0) { [int][math]::Round(100 * $pts / $raw) } else { 0 })
            CoverageGap = [bool]$b.CoverageGap
            AffectedCount=$b.Population.AffectedCount; AssessedCount=$b.Population.AssessedCount; UnknownCount=$b.Population.UnknownCount
            ScoringCount=$b.Population.ScoringCount; ScoringBasis=$b.Population.ScoringBasis; PopulationLabel=$b.Population.Label
            PopulationText=(Get-EntraPopulationText $b.Population)
            AcceptedRisk=($accepted.Count -eq $b.Count -and $accepted.Count -gt 0); AcceptedFindings=$accepted.Count
            ExceptionExpiresUtc=(@($accepted | ForEach-Object { Get-EAField $_ 'ExceptionExpiresUtc' } | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
            FirstTitle = $b.FirstTitle; FirstAnchor = $b.FirstAnchor
            RecommendedAction = $b.RecommendedAction; WhyItMatters = $b.WhyItMatters
            SourceFile = $b.SourceFile; DocumentationUrl = $b.DocumentationUrl
            Principals = $b.Principals.ToArray()
        }
    }
    $drivers = @($drivers | Sort-Object @{e={$_.Points};Descending=$true}, @{e={Get-SeverityRank $_.Severity};Descending=$true}, @{e={$_.Count};Descending=$true}, Title)
    $score = [int][math]::Round($raw)
    $scoreBand = 'Clean'
    foreach ($bd in $script:RiskBands) { if ($score -ge $bd.Min) { $scoreBand = $bd.Level; break } }

    # Coverage-aware band: a zero score is only 'Clean' when every selected check ran and
    # read all of its data. 'Not assessed' = checks were selected but none gave a result;
    # 'Not fully assessed' = anything skipped, errored, incomplete, a coverage-gap finding,
    # or no check status at all (it is then unknown what was checked). ScoreBand keeps the
    # plain threshold band.
    $coverage = Get-EntraRunCoverage -CheckStatus $CheckStatus
    $gapTotal = 0; foreach ($v in $gapCounts.Values) { $gapTotal += $v }
    $band = $scoreBand
    if ($scoreBand -eq 'Clean') {
        if ($coverage.Known -and $coverage.Evaluated -eq 0) { $band = 'Not assessed' }
        elseif (-not $coverage.Complete -or $gapTotal -gt 0) { $band = 'Not fully assessed' }
    }
    $urgency = 'No confirmed issues'
    foreach ($severity in @('Critical','High','Medium','Low')) { if ($confirmedCounts[$severity] -gt 0) { $urgency = $severity; break } }
    if ($urgency -eq 'No confirmed issues' -and (-not $coverage.Complete -or $gapTotal -gt 0)) { $urgency = 'Assessment needed' }
    $openUrgency = 'No open remediation'
    foreach ($severity in @('Critical','High','Medium','Low')) { if ($openCounts[$severity] -gt 0) { $openUrgency=$severity; break } }
    if ($openUrgency -eq 'No open remediation') {
        if (@($drivers | Where-Object { $_.AcceptedRisk }).Count) { $openUrgency='Review accepted risks' }
        elseif (-not $coverage.Complete -or $gapTotal -gt 0) { $openUrgency='Assessment needed' }
    }
    $confirmedScore = [int][math]::Round($raw - $gapRaw)
    [pscustomobject]@{
        Score = $score; Band = $band; ScoreBand = $scoreBand
        RemediationUrgency = $urgency
        OpenRemediationUrgency = $openUrgency
        ScoringVersion = '2.2.0'
        HighestConfirmedSeverity = $(if ($urgency -in @('Critical','High','Medium','Low')) { $urgency } else { 'Information' })
        ConfirmedScore = $confirmedScore
        NotAssessedPoints = $score - $confirmedScore
        Critical = $counts.Critical; High = $counts.High; Medium = $counts.Medium; Low = $counts.Low; Information = $counts.Information
        ConfirmedCounts = $confirmedCounts
        NotAssessedCounts = $gapCounts
        NotAssessedFindings = $gapTotal
        CoverageComplete = [bool]($coverage.Complete -and $gapTotal -eq 0)
        Coverage = $coverage
        # Per-issue contributions, largest first, so the report can show WHAT drives the score.
        Drivers = $drivers
        ConfirmedDrivers = @($drivers | Where-Object { -not $_.CoverageGap })
        NotAssessedDrivers = @($drivers | Where-Object { $_.CoverageGap })
    }
}

function Get-BandBadgeClass([string]$band) {
    switch ($band) { 'Clean' { 'Low' } 'Low' { 'Low' } 'Moderate' { 'Medium' } 'High' { 'High' } 'Critical' { 'Critical' } default { 'Information' } }
}

function Resolve-SourceHref([string]$src) {
    if ([string]::IsNullOrWhiteSpace($src)) { return '' }
    # Evidence paths are relative ('../Raw Data/Source/x.html'). Anything with a URI scheme
    # or a rooted path is refused so a stored value can never become a javascript: or remote
    # link; each segment is percent-encoded so spaces, '#', '%' and '?' resolve correctly.
    $s = $src.Trim() -replace '\\', '/'
    if ($s -match '^[A-Za-z][A-Za-z0-9+.\-]*:' -or $s.StartsWith('/')) { return '' }
    (@($s -split '/') | ForEach-Object { if ($_ -eq '..' -or $_ -eq '.') { $_ } else { [uri]::EscapeDataString($_) } }) -join '/'
}

function Write-EntraResultsReport {
    param([string]$Path, [object[]]$Items, [hashtable]$Counts, [string]$TenantName, [string]$GeneratedOn, [string]$Subtitle, [string]$TenantId,
          [pscustomobject]$Score)
    # Every parameter and finding field is treated as untrusted text and HTML-encoded where
    # it is written (tenant, principal and policy names are tenant-controlled).

    $severityOrder = @('Critical','High','Medium','Low','Information')
    $all = @($Items | Where-Object { $null -ne $_ })
    $total = $all.Count
    $runInfo = $script:RunInfo
    if (-not $TenantId) { $TenantId = [string](Get-EntraRunValue $runInfo 'TenantId') }
    if (-not $TenantId -and $script:Tenant -and $script:Tenant.Id) { $TenantId = [string]$script:Tenant.Id }

    # Check titles for labels and the check filter.
    $checkTitles = @{}
    if ($script:Registry -is [System.Collections.IDictionary]) { foreach ($k in $script:Registry.Keys) { $checkTitles[[string]$k] = [string]$script:Registry[$k].Title } }
    if ($script:CheckStatus -is [System.Collections.IDictionary]) { foreach ($k in $script:CheckStatus.Keys) { if (-not $checkTitles.ContainsKey([string]$k) -and $script:CheckStatus[$k].Title) { $checkTitles[[string]$k] = [string]$script:CheckStatus[$k].Title } } }

    # One entry per issue; coverage gaps separate from confirmed findings.
    $groups = @(Get-EntraResultGroup -Items $all)
    $riskGroups = @($groups | Where-Object { -not $_.CoverageGap })
    $gapGroups = @($groups | Where-Object { $_.CoverageGap } | Sort-Object @{ e = { Get-SeverityRank $_.Severity }; Descending = $true }, @{ e = { $_.Members.Count }; Descending = $true }, @{ e = { Format-EntraNaturalSortKey $_.Title } })
    $sumMembers = { param($gs) [int](@($gs | ForEach-Object { $_.Members.Count }) | Measure-Object -Sum).Sum }
    $gapCount = & $sumMembers $gapGroups
    $sevCounts = @{}; $sevIssues = @{}
    foreach ($sev in $severityOrder) {
        $gs = @($riskGroups | Where-Object { $_.Severity -eq $sev })
        $sevIssues[$sev] = $gs.Count
        $sevCounts[$sev] = & $sumMembers $gs
    }
    # Counts supplied without findings (older callers): show them rather than zeros.
    if ($null -eq $Items -and $Counts) { foreach ($sev in $severityOrder) { if ($Counts.ContainsKey($sev)) { $sevCounts[$sev] = [int]$Counts[$sev] } } }
    $riskTotal = $sevCounts.Critical + $sevCounts.High + $sevCounts.Medium + $sevCounts.Low
    $infoTotal = $sevCounts.Information

    # Score, band and check coverage come from the same functions every page uses
    # (Get-EntraRiskScore / Get-EntraRunCoverage), so this page cannot disagree with the
    # Risk Report or the Posture Summary. The band is never 'Clean' while a selected check
    # was skipped, errored or incomplete, or while it is unknown which checks ran.
    if ($null -eq $Score -or -not $Score.PSObject.Properties['Coverage'] -or $null -eq $Score.Coverage) { $Score = Get-EntraRiskScore $all }
    $cov = $Score.Coverage
    $partial = -not $Score.CoverageComplete
    $bandLabel = [string]$Score.Band
    $bandClass = Get-BandBadgeClass $bandLabel
    $riskNote = if ($partial -and $bandLabel -ne 'Not assessed') { " It covers only what could be checked &mdash; see <a href='#check-coverage'>Check coverage</a>." } else { '' }
    $urgency = Get-EntraRemediationUrgency $Score
    $urgencyClass = if ($urgency -in @('Critical','High','Medium','Low')) { $urgency } else { 'Information' }
    $highestSeverity = [string]$Score.HighestConfirmedSeverity
    $riskLine = "<div class='risk-line'>Highest confirmed severity: <span class='badge sev-$highestSeverity band'>$(HtmlEncode $highestSeverity)</span> Action priority: <span class='badge sev-$urgencyClass band'>$(HtmlEncode $urgency)</span> Confirmed risk index: <b>$([int]$Score.ConfirmedScore)</b>. Coverage: <b>$($cov.FullyEvaluated) of $($cov.Selected)</b> selected checks fully assessed.$riskNote <span class='result-note'>Combined index (including gaps): $([int]$Score.Score), $(HtmlEncode $bandLabel). Accepted risks retain their severity and points.</span> <a href='Action-Register.html'>Action register and changes</a>.</div>"
    $changeSummaryHtml = Get-EntraChangeSummaryHtml

    $notFull = $cov.Skipped + $cov.Errored + $cov.Incomplete
    $gapText = Get-EntraCoverageGapText -Coverage $cov
    $coverageCallout = if (-not $cov.Known) {
        "<div class='callout warn'><b>It is not known which checks ran.</b> This report did not receive the list of checks, so a missing finding means &quot;unknown&quot;, not &quot;passed&quot;.</div>"
    } elseif ($cov.Selected -gt 0 -and $cov.Evaluated -le 0) {
        "<div class='callout warn'><b>Nothing was checked.</b> None of the $($cov.Selected) selected checks could run: $gapText. This is <b>not</b> a clean result. <a href='#check-coverage'>See why</a>.</div>"
    } elseif ($notFull -gt 0) {
        "<div class='callout warn'><b>Partial result:</b> $notFull of $($cov.Selected) selected checks did not fully run: $gapText. Problems in those areas cannot show up below, so a missing finding there does <b>not</b> mean all is well. <a href='#check-coverage'>See which checks and why</a>.</div>"
    } elseif ($gapCount -gt 0) {
        "<div class='callout warn'><b>Some items could not be checked:</b> $gapCount $(if ($gapCount -eq 1) { 'is' } else { 'are' }) listed under <a href='#section-not-assessed'>Not assessed</a>, apart from the confirmed problems.</div>"
    } else {
        $notRunText = if ($cov.NotRun -gt 0) { " $($cov.NotRun) other check$(if ($cov.NotRun -eq 1) { ' was' } else { 's were' }) not selected for this run." } else { '' }
        "<div class='callout ok'><b>All $($cov.Selected) selected checks ran and read all of their data.</b>$notRunText</div>"
    }

    # --- hero metrics ---
    $countCards = foreach ($sev in $severityOrder) {
        $issuesText = if ($sev -eq 'Information') { 'background, no action' } else { '{0} issue{1}' -f $sevIssues[$sev], $(if ($sevIssues[$sev] -eq 1) { '' } else { 's' }) }
        "<button type='button' class='metric sev-$sev' data-sev-filter='$sev' title='Show only $sev findings'><div class='metric-label'>$sev</div><div class='metric-value'>$($sevCounts[$sev])</div><div class='metric-sub'>$issuesText</div></button>"
    }
    # Checks skipped before they started (missing permission or licence) add no finding, so
    # the tile names them next to its count - the Risk Report's "Not assessed" list includes
    # them. Checks that stopped with an error already have a "did not finish" finding here.
    $didNotFinish = @{}
    foreach ($it in $all) { if ((Test-EntraCoverageGap $it) -and [string]$it.RuleId -eq ('{0}-check-did-not-finish' -f $it.CheckId)) { $didNotFinish[[string]$it.CheckId] = $true } }
    $ncChecks = if ($cov.Known) { @($cov.Rows | Where-Object { $_.Selected -and $_.Group -in @('skipped','error','noresult') -and -not $didNotFinish.ContainsKey([string]$_.CheckId) }).Count } else { 0 }
    $gapSub = if ($ncChecks -gt 0) { "could not be checked &middot; plus $ncChecks check$(if ($ncChecks -eq 1) { '' } else { 's' }) that did not run" } else { 'could not be checked' }
    $countCards += "<button type='button' class='metric gap' data-sev-filter='Gap' title='Show only what could not be checked'><div class='metric-label'>Not assessed</div><div class='metric-value'>$gapCount</div><div class='metric-sub'>$gapSub</div></button>"
    $covCards = if ($cov.Known) {
        $tiles = @(Get-EntraCoverageTile -Coverage $cov | Where-Object { $_.Key -ne 'notrun' -or $_.Value -gt 0 })
        "<div class='metrics-caption'>Checks</div><div class='metrics small'>" + (($tiles | ForEach-Object { "<a class='metric $($_.State)' href='#check-coverage' title='$(HtmlAttrEncode $_.Hint)'><div class='metric-label'>$(HtmlEncode $_.Label)</div><div class='metric-value'>$($_.Value)</div></a>" }) -join '') + '</div>'
    } else { '' }

    # --- run details (RunInfo is optional; full details are on the Posture Summary) ---
    $runBits = @()
    $account = [string](Get-EntraRunValue $runInfo 'Account'); $authMode = [string](Get-EntraRunValue $runInfo 'AuthMode')
    if ($account -or $authMode) { $runBits += ('Signed in as: <span class="mono">{0}</span>{1}' -f (HtmlEncode $account), $(if ($authMode) { ' (' + (HtmlEncode $authMode) + ')' } else { '' })) }
    $toolVersion = [string](Get-EntraRunValue $runInfo 'ToolVersion'); if (-not $toolVersion) { $toolVersion = [string]$script:Version }
    $durText = Get-EntraRunDurationText $runInfo
    if ($toolVersion) { $runBits += "Tool: $(HtmlEncode $toolVersion)$(if ($durText) { ' &middot; run time ' + (HtmlEncode $durText) }) &middot; <a href='Posture-Summary.html#run-details'>Run details</a>" }
    $runHtml = if ($runBits.Count) { ($runBits -join '<br>') + '<br>' } else { '' }
    $tenantIdHtml = if ($TenantId) { " <span class='mono'>($(HtmlEncode $TenantId))</span>" } else { '' }
    # The caller's subtitle is only shown when this report has no check status of its own.
    $subtitleHtml = if (-not $cov.Known -and $Subtitle) { (HtmlEncode ([System.Net.WebUtility]::HtmlDecode($Subtitle))) + '<br>' } else { '' }

    # --- priority actions: distinct issues, not individual findings ---
    $sortIssues = { param($gs) @($gs | Sort-Object @{ e = { [int][bool]$_.AcceptedRisk } }, @{ e = { Get-SeverityRank $_.Severity }; Descending = $true }, @{ e = { $_.Points }; Descending = $true }, @{ e = { Format-EntraNaturalSortKey $_.Title } }) }
    $prioIntro = ''
    $prioPool = & $sortIssues @($riskGroups | Where-Object { $_.Severity -ne 'Information' })
    $prio = @($prioPool | Select-Object -First 3)
    $priorityHtml = if ($prio.Count -gt 0) {
        $li = @(foreach ($g in $prio) {
            $m0 = $g.Members[0]
            $n = $g.Members.Count
            $populationLabel = if ($g.Population.ScoringBasis -ne 'FindingRecord') { '{0} affected {1}' -f $g.Population.AffectedCount, $g.Population.Label } else { "$n finding records" }
            $pill = if ($n -gt 1 -or $g.Population.AffectedCount -gt 1) { " <span class='count-pill'>$(HtmlEncode $populationLabel)</span>" } else { '' }
            $act = Get-EntraFirstSentence (Get-EntraDisplayAction ([string]$m0.RecommendedAction) @([string]$m0.DocumentationUrl))
            $acceptedTag = ''
            if ($g.AcceptedRisk) {
                $acceptedTag = " <span class='count-pill'>Accepted risk</span>"
                $act = "Review the accepted-risk justification and expiry ($($g.ExceptionExpiresUtc)) with its owner."
            } elseif ($g.AcceptedFindings -gt 0) { $acceptedTag = " <span class='count-pill'>Partly accepted</span>" }
            $doc = ConvertTo-EntraDocLinkHtml ([string]$m0.DocumentationUrl)
            $actHtml = if ($act) { "<span class='priority-evidence'>What to do: $(HtmlEncode $act)$(if ($doc) { " &middot; $doc" })</span>" } else { '' }
            "<li><span class='badge sev-$($g.Severity)'>$($g.Severity)</span><a class='priority-title' href='#$(HtmlAttrEncode $g.Anchor)'>$(HtmlEncode $g.Title)</a>$acceptedTag$pill$actHtml</li>"
        })
        $rest = @($prioPool).Count - $prio.Count
        if ($rest -gt 0) { $li += "<li class='result-note'><a href='Action-Register.html'>$rest more issues in the action register</a>.</li>" }
        $li -join "`n"
    } elseif ($riskGroups.Count -gt 0) {
        '<li>Only information notes were recorded. They need no action.</li>'
    } elseif ($cov.Known -and $cov.Selected -gt 0 -and $cov.Evaluated -le 0) {
        '<li>Nothing could be checked, so there is nothing to fix yet. Fix the problems listed under Check coverage and run the audit again.</li>'
    } else {
        if ($partial) { '<li>No problems were found in the checks that could run. This is not a clean result while checks are missing or incomplete &mdash; see Check coverage.</li>' }
        else { '<li>No problems were found.</li>' }
    }

    # --- sections, index, cards ---
    $sectionDefs = @(foreach ($sev in $severityOrder) {
        [pscustomobject]@{ Key = $sev; Id = 'section-' + (New-Slug $sev); Heading = $sev; Groups = (& $sortIssues @($riskGroups | Where-Object { $_.Severity -eq $sev })); Gap = $false }
    }) + @([pscustomobject]@{ Key = 'Not assessed'; Id = 'section-not-assessed'; Heading = 'Not assessed'; Groups = $gapGroups; Gap = $true })

    $indexHtml = New-Object System.Collections.Generic.List[string]
    $sectionHtml = New-Object System.Collections.Generic.List[string]
    foreach ($sd in $sectionDefs) {
        $gs = @($sd.Groups)
        $nFind = & $sumMembers $gs
        if ($gs.Count -gt 0) {
            $rows = foreach ($g in $gs) {
                $cnt = if ($g.Members.Count -gt 1) { " <span class='count-pill'>$($g.Members.Count)</span>" } else { '' }
                "<li><a href='#$(HtmlAttrEncode $g.Anchor)'>$(HtmlEncode $g.Title)</a>$cnt<span class='idx-check mono'>$(HtmlEncode $g.CheckId)</span></li>"
            }
            $indexHtml.Add("<details class='index-detail'><summary>$(HtmlEncode $sd.Heading) ($nFind)</summary><ol>$($rows -join "`n")</ol></details>") | Out-Null
        }
        $cards = New-Object System.Collections.Generic.List[string]
        if ($gs.Count -eq 0) {
            $emptyText = if ($sd.Gap) {
                if ($cov.Skipped + $cov.Errored -gt 0) { "The checks that ran could read everything they needed. $($cov.Skipped + $cov.Errored) selected check(s) did not run at all &mdash; see <a href='#check-coverage'>Check coverage</a>." }
                elseif (-not $cov.Known) { 'It is not known which checks ran, so nothing can be said about data that could not be read.' }
                else { 'Every selected check could read the data it needed.' }
            } elseif ($partial) { 'No findings at this severity from the checks that ran.' } else { 'No findings at this severity.' }
            $cards.Add("<div class='empty'>$emptyText</div>") | Out-Null
        } else {
            foreach ($g in $gs) { $cards.Add((ConvertTo-EntraFindingCardHtml -Group $g -TenantId $TenantId -CheckTitles $checkTitles)) | Out-Null }
        }
        $countText = if ($gs.Count -eq 0) { '0 findings' } elseif ($gs.Count -eq $nFind) { "$nFind finding$(if ($nFind -ne 1) { 's' })" } else { "$($gs.Count) issue$(if ($gs.Count -ne 1) { 's' }) &middot; $nFind findings" }
        $intro = if ($sd.Gap) {
            $ncNote = if ($ncChecks -gt 0 -and $gs.Count -gt 0) { " In addition, $ncChecks selected check$(if ($ncChecks -eq 1) { '' } else { 's' }) did not run (for example skipped for a missing permission or licence) and $(if ($ncChecks -eq 1) { 'is' } else { 'are' }) not listed here &mdash; see <a href='#check-coverage'>Check coverage</a>." } else { '' }
            "<p class='result-note'>What the audit could not read or check, for example because of a missing permission, a missing license or an error. These are <b>not</b> passes. They are kept apart from the confirmed problems, although a serious gap still adds to the risk score. Fix the access problem and run the audit again.$ncNote</p>"
        } else { '' }
        $sectionHtml.Add("<section class='severity-section' id='$($sd.Id)'><div class='section-header'><h2>$(HtmlEncode $sd.Heading)</h2><div class='section-count'>$countText</div></div>$intro$($cards -join "`n")</section>") | Out-Null
    }
    if ($indexHtml.Count -eq 0) { $indexHtml.Add("<div class='empty'>No findings.</div>") | Out-Null }

    # --- check coverage table (every available check, worst first) ---
    $findingsByCheck = @{}
    foreach ($it in $all) { $cid = [string]$it.CheckId; $findingsByCheck[$cid] = 1 + $(if ($findingsByCheck.ContainsKey($cid)) { $findingsByCheck[$cid] } else { 0 }) }
    $isProblem = { param($v) $v.Group -in @('error','noresult','skipped','incomplete') -or $v.Incomplete }
    $problemRows = @($cov.Rows | Where-Object { & $isProblem $_ }).Count
    $regOrder = @{}; $o = 0; foreach ($r in $cov.Rows) { $regOrder[$r.CheckId] = $o++ }
    $covRows = foreach ($v in @($cov.Rows | Sort-Object @{ e = { $_.SortOrder } }, @{ e = { $regOrder[$_.CheckId] } })) {
        # With problems present, only those rows show until "Show all checks" is clicked.
        $rowCls = if ($problemRows -gt 0 -and -not (& $isProblem $v)) { " class='extra'" } else { '' }
        $nf = if ($findingsByCheck.ContainsKey($v.CheckId)) { $findingsByCheck[$v.CheckId] } else { 0 }
        $link = if ($nf -gt 0) { "<a href='#findings-start' data-filter-check='$(HtmlAttrEncode $v.CheckId)'>Show $nf</a>" } else { "<span class='result-note'>none</span>" }
        $err = if ($v.ErrorMessage -and $v.Group -in @('error','skipped')) { $m = $v.ErrorMessage; if ($m.Length -gt 400) { $m = $m.Substring(0, 400) + '...' }; "<div class='check-error mono'>$(HtmlEncode $m)</div>" } else { '' }
        $statusTitle = if ($v.Group -ne 'notrun') { " title='Status code: $(HtmlAttrEncode $v.Status)'" } else { '' }
        "<tr id='check-$(HtmlAttrEncode $v.CheckId)'$rowCls><td><b>$(HtmlEncode $v.Title)</b><div class='idx-check mono'>$(HtmlEncode $v.CheckId)</div></td><td><span class='pill $($v.Class)'$statusTitle>$(HtmlEncode $v.Label)</span></td><td><div class='check-reason'>$(HtmlEncode $v.Reason)</div>$err</td><td>$link</td></tr>"
    }
    $checksSummary = if (-not $cov.Known) { 'Check coverage: unknown' } else { "Check coverage: $($cov.FullyEvaluated) of $($cov.Selected) selected checks gave a full result" }
    $checksOpen = if ($total -eq 0 -or $problemRows -gt 0 -or -not $cov.Known) { ' open' } else { '' }
    $nCov = @($covRows).Count
    $moreBtn = if ($problemRows -gt 0 -and $nCov -gt $problemRows) { "<button type='button' class='show-more' data-more='Show all $nCov checks' data-less='Show only the checks with problems'>Show all $nCov checks</button>" } else { '' }
    $covIntro = if ($problemRows -gt 0) { "Below: the $problemRows check(s) that did not fully run, and why. " } else { '' }
    $checksBody = if ($nCov -gt 0) {
        "<p class='result-note'>$($covIntro)Skipped, failed and incomplete checks are gaps in the audit, not passes. &quot;Not run&quot; means the check was not selected this time. <a href='Posture-Summary.html#checks'>Posture Summary</a> has the evidence for each check.</p><div class='result-block'><table class='status-table'><thead><tr><th>Check</th><th>Result</th><th>Why</th><th>Findings</th></tr></thead><tbody>$($covRows -join "`n")</tbody></table>$moreBtn</div>"
    } else { "<p class='result-note'>No check status was recorded. See <a href='Posture-Summary.html'>Posture Summary</a>.</p>" }

    # --- filter options ---
    $sevOptions = "<option value='All'>All findings</option><option value='NoGap'>All except not assessed</option><option value='Risk'>Problems only (Critical to Low)</option>" +
        (($severityOrder | ForEach-Object { "<option value='$_'>$_</option>" }) -join '') + "<option value='Gap'>Not assessed only</option>"
    $catOptions = @("<option value='All'>All categories</option>") + @($all | ForEach-Object { [string]$_.Category } | Where-Object { $_ } |
        Sort-Object -Unique | ForEach-Object { "<option value='$(HtmlAttrEncode $_)'>$(HtmlEncode $_)</option>" })
    $checkOptions = @("<option value='All'>All checks</option>") + @($all | ForEach-Object { [string]$_.CheckId } | Where-Object { $_ } | Select-Object -Unique |
        Sort-Object { if ($regOrder.ContainsKey($_)) { $regOrder[$_] } else { 1000 } }, { $_ } |
        ForEach-Object { $t = if ($checkTitles.ContainsKey($_)) { "$($checkTitles[$_]) ($_)" } else { $_ }; "<option value='$(HtmlAttrEncode $_)'>$(HtmlEncode $t)</option>" })

    $findingsLine = "Findings: <b>$total</b><br>$riskTotal problem$(if ($riskTotal -ne 1) { 's' }) &middot; $infoTotal information &middot; $gapCount not assessed"

    $css = Get-EntraMainCss
    $js  = (Get-EntraThemeScript) + (Get-EntraMainJs)
    $nav = Get-EntraPrimaryNav 'audit'

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Audit - Results</title>
$css
</head>
<body data-theme="light">
<div class="container">
$nav
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>Microsoft Entra ID Audit Results</h1>
        <div class="meta">
          Tenant: <span class="mono">$(HtmlEncode $TenantName)</span>$tenantIdHtml<br>
          Generated: $(HtmlEncode $GeneratedOn)<br>
          $runHtml$subtitleHtml
          Read-only audit: nothing in the tenant was changed.
        </div>
        $riskLine
      </div>
      <div class="hero-actions">
        <button type="button" class="theme-toggle" id="themeToggle">Dark mode</button>
        <div class="meta">$findingsLine</div>
      </div>
    </div>
    <section class="priority quick-actions" id="priority-actions">
      <div class="section-header"><h2>Do first</h2><div class="section-count">Open remediation first; accepted risks remain visible for review</div></div>
      $prioIntro<ul>$priorityHtml</ul>
    </section>
    $changeSummaryHtml
    <div class="metrics">$($countCards -join "`n")</div>
    $covCards
  </section>
  $coverageCallout
  <div class="layout">
    <aside class="sidebar">
      <h3>On this page</h3>
      <ul>
        <li><a href="#how-to-read">How to read this report</a></li>
        <li><a href="#priority-actions">Priority actions</a></li>
        <li><a href="#check-coverage">Check coverage</a></li>
        <li><a href="#section-critical">Critical</a></li>
        <li><a href="#section-high">High</a></li>
        <li><a href="#section-medium">Medium</a></li>
        <li><a href="#section-low">Low</a></li>
        <li><a href="#section-information">Information</a></li>
        <li><a href="#section-not-assessed">Not assessed</a></li>
      </ul>
      <div class="index-group"><h4>All findings</h4>$($indexHtml -join "`n")</div>
    </aside>
    <main class="content">
      <details class="howto" id="how-to-read">
        <summary>How to read this report</summary>
        <ul>
          <li><b>One card per problem.</b> If the same problem affects several users, apps or policies, they share one card with a count (for example &quot;10 objects&quot;). Open the card to see each one.</li>
          <li><b>Severity:</b> Critical &ndash; fix now, it can lead to a takeover of the tenant or its admin accounts. High &ndash; fix soon. Medium &ndash; plan a fix. Low &ndash; minor clean-up. Information &ndash; background only, no action needed.</li>
          <li><b>Not assessed</b> (dashed cards): the audit could not read or check this, for example because of a missing permission or license. It is not a pass, and it is kept apart from the confirmed problems.</li>
          <li>Open a card to see <b>why it matters</b>, <b>what to do</b> and the <b>evidence</b>. The search also looks inside closed cards. Click a box at the top to show only that severity. Printing opens every card.</li>
          <li>The small grey line in a card names the check, the rule and the finding id (the same id as in <span class="mono">Findings.json</span> and <span class="mono">Findings.csv</span>), and shows how to run only that check again.</li>
        </ul>
      </details>
      <details class="checks" id="check-coverage"$checksOpen>
        <summary>$(HtmlEncode $checksSummary)</summary>
        $checksBody
      </details>
      <section class="toolbar" id="findings-start">
        <div class="toolbar-row">
          <div class="filter"><label for="severityFilter">Severity</label>
            <select id="severityFilter">$sevOptions</select></div>
          <div class="filter"><label for="checkFilter">Check</label>
            <select id="checkFilter">$($checkOptions -join '')</select></div>
          <div class="filter"><label for="categoryFilter">Category</label>
            <select id="categoryFilter">$($catOptions -join '')</select></div>
          <div class="filter"><label for="searchFilter">Search</label><input id="searchFilter" type="search" placeholder="Title, user, app, object id or any text"></div>
        </div>
        <div class="toolbar-actions">
          <button type="button" class="btn" id="expandAll">Expand all</button>
          <button type="button" class="btn" id="collapseAll">Collapse all</button>
          <button type="button" class="btn" id="resetFilters">Clear filters</button>
          <span class="visible-count" id="visibleFindings" aria-live="polite"></span>
        </div>
      </section>
      <div class="empty" id="noResults" style="display:none">No findings match these filters. Click <b>Clear filters</b> to show everything.</div>
      <div class="print-only result-note" id="printFilterNote"></div>
      $($sectionHtml -join "`n")
    </main>
  </div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Write-EntraRiskReport {
    param([string]$Path, [object[]]$Items, [hashtable]$Counts, [string]$TenantName, [string]$GeneratedOn, [pscustomobject]$Score, [hashtable]$Stats,
          [object]$RunInfo = $script:RunInfo)

    if ($null -eq $Items) { $Items = @() }
    if ($null -eq $Score -or -not $Score.PSObject.Properties['ConfirmedDrivers']) { $Score = Get-EntraRiskScore $Items }
    if ($null -eq $Stats) { $Stats = Get-EntraReportStatistic }
    $cov = if ($Score.PSObject.Properties['Coverage'] -and $Score.Coverage) { $Score.Coverage } else { Get-EntraRunCoverage -RunInfo $RunInfo }
    $bandClass = Get-BandBadgeClass $Score.Band
    $confirmed = @($Score.ConfirmedDrivers | Sort-Object @{e={[int][bool]$_.AcceptedRisk}}, @{e={Get-SeverityRank $_.Severity};Descending=$true}, @{e={$_.Points};Descending=$true}, Title)
    $urgency = Get-EntraRemediationUrgency $Score
    $urgencyClass = if ($urgency -in @('Critical','High','Medium','Low')) { $urgency } else { 'Information' }
    $changeSummaryHtml = Get-EntraChangeSummaryHtml
    $gapDrivers = @($Score.NotAssessedDrivers)
    $cc = $Score.ConfirmedCounts; $gc = $Score.NotAssessedCounts
    $resultsHref = 'EntraAudit-Results.html'
    $checkTitle = { param($id) if ($id -and $script:Registry -and $script:Registry.Contains([string]$id)) { [string]$script:Registry[[string]$id].Title } else { [string]$id } }
    $plural = { param([int]$n, [string]$one, [string]$many) if ($n -eq 1) { "1 $one" } else { "$n $many" } }

    # Higher score = worse. Ranges derive from the single $script:RiskBands definition
    # (worst-first), so this matrix always matches the thresholds the code applied. The
    # coverage labels are appended as score-0 rows that replace 'Clean' when the audit
    # did not see everything.
    $bands = for ($i = 0; $i -lt $script:RiskBands.Count; $i++) {
        $b = $script:RiskBands[$i]
        $range = if ($i -eq 0) { "$($b.Min)+" }
                 elseif ($b.Min -eq ($script:RiskBands[$i-1].Min - 1)) { "$($b.Min)" }
                 else { "$($b.Min) - $($script:RiskBands[$i-1].Min - 1)" }
        [pscustomobject]@{ Level=$b.Level; Range=$range; Meaning=$b.Meaning }
    }
    $bands = @($bands) + @($script:RiskCoverageBands | ForEach-Object { [pscustomobject]@{ Level=$_.Level; Range='0'; Meaning=$_.Meaning } })
    $matrixRows = foreach ($b in $bands) {
        $bc = Get-BandBadgeClass $b.Level
        $cls = if ($b.Level -eq $Score.Band) { "matrix-row active sev-$bc" } else { "matrix-row sev-$bc" }
        "<tr class='$cls'><td><span class='pill sev-$bc'>$(HtmlEncode $b.Level)</span></td><td class='mono'>$($b.Range)</td><td>$(HtmlEncode $b.Meaning)</td></tr>"
    }

    # ---- not assessed: checks that did not give a result + data that could not be read ----
    # Computed first: the summary links to this section only when it exists. A check that
    # did not run is listed once, under its check, not again as its '<check>-check-did-not-finish'
    # coverage finding.
    $checkGapRows = @($cov.Rows | Where-Object { $_.Selected -and $_.Group -in @('skipped','error','noresult') })
    $listedChecks = @{}; foreach ($r in $checkGapRows) { $listedChecks[[string]$r.CheckId] = $true }
    $gapItems = @($Items | Where-Object { (Test-EntraCoverageGap $_) -and -not ($listedChecks.ContainsKey([string]$_.CheckId) -and [string]$_.RuleId -eq ('{0}-check-did-not-finish' -f $_.CheckId)) })
    $hasNotAssessed = ($checkGapRows.Count + $gapItems.Count) -gt 0
    $naLink = if ($hasNotAssessed) { "<a href='#not-assessed'>Not assessed</a>" } else { "<a href='Posture-Summary.html#checks'>Check results</a>" }

    # ---- plain-language summary (what the score means, what drives it, what to do first) ----
    $confFindings = @($Items | Where-Object { (Normalize-Severity $_.Severity) -ne 'Information' -and -not (Test-EntraCoverageGap $_) })
    $confChecks = @($confFindings | ForEach-Object { [string]$_.CheckId } | Select-Object -Unique).Count
    $issueName = { param($d) if ($d.Count -gt 1) { '{0} ({1} findings)' -f $d.Title, $d.Count } else { $d.FirstTitle } }
    $summary = New-Object System.Collections.Generic.List[string]
    if ($confirmed.Count -gt 0) {
        $top = @($confirmed | Select-Object -First 3)
        $share = 0; foreach ($d in $top) { $share += $d.Share }
        $names = @($top | ForEach-Object { '<b>' + (HtmlEncode (& $issueName $_)) + '</b>' + $(if ($_.AcceptedRisk) { ' (accepted risk)' } elseif ($_.AcceptedFindings -gt 0) { ' (partly accepted)' } else { '' }) })
        $nameList = if ($names.Count -le 1) { $names -join '' } else { ($names[0..($names.Count - 2)] -join ', ') + ' and ' + $names[-1] }
        $lead = if ($top.Count -eq 1) { "The highest-priority issue accounts for $share% of the combined index: $nameList." } else { "The $($top.Count) highest-priority issues account for $share% of the combined index: $nameList." }
        $summary.Add("<p class='summary-lead'>Highest confirmed severity is <b>$(HtmlEncode $Score.HighestConfirmedSeverity)</b>; action priority is <b>$(HtmlEncode $urgency)</b>. The confirmed risk index is <b>$($Score.ConfirmedScore)</b>; the combined index including assessment gaps is $($Score.Score) (band: $(HtmlEncode $Score.Band)). $lead</p>") | Out-Null
        $acceptedCount = @($confFindings | Where-Object { [bool](Get-EAField $_ 'AcceptedRisk') }).Count
        if ($acceptedCount -gt 0) {
            $summary.Add("<p><span class='pill mini gap'>Accepted risk</span> $acceptedCount confirmed finding record(s) have a documented exception. They retain their severity and score contribution. Open remediation comes first; review accepted-risk owners, justification and expiry in the <a href='Action-Register.html'>Action Register</a>.</p>") | Out-Null
        }
        if ($Score.NotAssessedPoints -gt 0) {
            $summary.Add("<p>$($Score.NotAssessedPoints) of the $($Score.Score) points come from things the audit could not check (marked <span class='pill mini gap'>Not assessed</span>). Not knowing is a risk in itself, but these are not confirmed problems.</p>") | Out-Null
        }
        $distinct = $confirmed.Count
        $counted = "The audit confirmed <b>$($cc.Critical)</b> critical, <b>$($cc.High)</b> high, <b>$($cc.Medium)</b> medium and <b>$($cc.Low)</b> low findings ($(& $plural $distinct 'distinct issue' 'distinct issues')) in $(& $plural $confChecks 'check' 'checks')."
        if ($cc.Information -gt 0) { $counted += " $(& $plural $cc.Information 'information note is' 'information notes are') listed in the detailed results; they do not change the score." }
        $summary.Add("<p>$counted</p>") | Out-Null
    } elseif ($gapDrivers.Count -gt 0 -or $Score.NotAssessedFindings -gt 0) {
        $summary.Add("<p class='summary-lead'>The confirmed risk index is <b>0</b>. No problems were confirmed, but the audit could not check everything. The combined index is <b>$($Score.Score)</b> (band: $(HtmlEncode $Score.Band)); all points represent assessment gaps. See $naLink.</p>") | Out-Null
    } elseif ($cov.Selected -gt 0 -and $cov.Evaluated -eq 0) {
        $summary.Add("<p class='summary-lead'>The result is <b>$(HtmlEncode $Score.Band)</b>. A confirmed index of 0 does not establish safety: none of the selected checks gave a result. See $naLink for the reasons.</p>") | Out-Null
    } elseif ($Score.CoverageComplete) {
        $summary.Add("<p class='summary-lead'>The confirmed risk index is <b>$($Score.ConfirmedScore)</b>. No problems were found in the selected checks.</p>") | Out-Null
    } else {
        $summary.Add("<p class='summary-lead'>The confirmed risk index is <b>$($Score.ConfirmedScore)</b>. No problems were found in the checks that ran, but this is <b>not</b> a clean result: not everything could be checked.</p>") | Out-Null
    }
    # Coverage sentence - always stated, so a reader never mistakes a partial audit for a full one.
    if (-not $cov.Known) {
        $summary.Add("<p>It is not known which checks ran (no check status was recorded), so treat a missing finding as unknown, not as a pass.</p>") | Out-Null
    } elseif ($cov.Selected -gt 0) {
        $partText = Get-EntraCoverageGapText -Coverage $cov
        $covText = if ($cov.Complete) { "All $($cov.Selected) selected checks ran and read all of their data." }
            elseif ($cov.FullyEvaluated -eq 0) { "None of the $($cov.Selected) selected checks gave a full result: $partText. Problems in those areas cannot show up in this report. <a href='Posture-Summary.html#checks'>See which checks</a>." }
            else { "Only <b>$($cov.FullyEvaluated) of $($cov.Selected)</b> selected checks gave a full result: $partText. Problems in those areas cannot show up in this report, so treat the score as a minimum. <a href='Posture-Summary.html#checks'>See which checks</a>." }
        if ($cov.NotRun -gt 0) { $covText += " $(& $plural $cov.NotRun 'other check was' 'other checks were') not selected for this run, so $(if ($cov.NotRun -eq 1) { 'that area was' } else { 'those areas were' }) not checked." }
        $summary.Add("<p>$covText</p>") | Out-Null
    }
    # "Do first": highest confirmed severity first, then issue points; one per distinct action.
    $doFirst = New-Object System.Collections.Generic.List[string]
    $seenActions = @{}
    foreach ($d in $confirmed) {
        if ($doFirst.Count -ge 3) { break }
        # Older governance findings repeat the DocumentationUrl as "Microsoft source: <url>" in
        # the action text; it is shown once, as the link.
        $act = Get-EntraDisplayAction ([string]$d.RecommendedAction) @([string]$d.DocumentationUrl)
        $acceptedTag = ''
        if ($d.AcceptedRisk) {
            $acceptedTag = " <span class='pill mini gap'>Accepted risk</span>"
            $act = "Review the accepted-risk justification and expiry ($($d.ExceptionExpiresUtc)) with its owner; retain monitoring."
        } elseif ($d.AcceptedFindings -gt 0) { $acceptedTag = " <span class='pill mini gap'>Partly accepted</span>" }
        if (-not $act -or $seenActions.ContainsKey($act)) { continue }
        $seenActions[$act] = $true
        $doc = ConvertTo-EntraDocLinkHtml ([string]$d.DocumentationUrl)
        $doFirst.Add("<li><b>$(HtmlEncode $d.Title)</b>$acceptedTag &mdash; $(HtmlEncode $act) <a href='$resultsHref#$(HtmlAttrEncode $d.FirstAnchor)'>Details</a>$(if ($doc) { " &middot; $doc" })</li>") | Out-Null
    }
    $coverageAction = if (-not $cov.Complete -and $cov.Selected -gt 0 -and ($cov.Skipped + $cov.Errored) -gt 0) {
        "<p><b>Restore audit coverage:</b> review the missing permissions or licenses listed under $naLink, then run the skipped checks again.</p>"
    } else { '' }
    $doFirstHtml = $(if ($doFirst.Count -gt 0) { "<h3>Do first</h3><ol>$($doFirst -join "`n")</ol>" } else { '' }) + $coverageAction
    $calloutCls = if ($cov.Complete -and $Score.NotAssessedFindings -eq 0) { 'callout' } else { 'callout warn' }

    # ---- top risks: DISTINCT confirmed issues, severity first, then issue points ----
    $topHtml = if ($confirmed.Count -gt 0) {
        $li = foreach ($d in @($confirmed | Select-Object -First 8)) {
            $who = ''
            $pr = @($d.Principals)
            if ($d.Count -gt 1 -and $pr.Count -gt 0) {
                $more = $d.Count - $pr.Count
                $who = ' &middot; e.g. ' + (($pr | ForEach-Object { HtmlEncode $_ }) -join ', ') + $(if ($more -gt 0) { " and $more more" } else { '' })
            }
            $name = if ($d.Count -gt 1) { HtmlEncode $d.Title } else { HtmlEncode $d.FirstTitle }
            $cnt = if ($d.Count -gt 1) { " <span class='muted'>&times; $($d.Count)</span>" } else { '' }
            $acceptedTag = if ($d.AcceptedRisk) { " <span class='pill mini gap'>Accepted risk &mdash; review expiry $(HtmlEncode $d.ExceptionExpiresUtc)</span>" } elseif ($d.AcceptedFindings -gt 0) { " <span class='pill mini gap'>Partly accepted</span>" } else { '' }
            "<li><span class='pill sev-$($d.Severity)'>$($d.Severity)</span><div><a href='$resultsHref#$(HtmlAttrEncode $d.FirstAnchor)'><b>$name</b></a>$acceptedTag$cnt<span class='li-sub'>$(HtmlEncode $d.PopulationText) $(& $plural $d.Count 'finding record' 'finding records') in $(HtmlEncode (& $checkTitle $d.CheckId)) &middot; $($d.Points) points ($($d.Share)% of the combined index)$who</span></div></li>"
        }
        $extra = if ($confirmed.Count -gt 8) { "<p class='muted' style='margin-top:8px'>$($confirmed.Count - 8) more issue(s) are listed under <a href='#drivers'>What drives the score</a>.</p>" } else { '' }
        "<ul class='risk-list'>$($li -join "`n")</ul>$extra"
    } elseif ($cov.Complete -and $Score.NotAssessedFindings -eq 0) {
        "<p>No problems were found in the checks that ran.</p>"
    } elseif ($cov.Selected -gt 0 -and $cov.Evaluated -eq 0) {
        "<p>Nothing could be checked, so there is nothing to list here. This is <b>not</b> a clean result &mdash; see $naLink.</p>"
    } else {
        "<p>No problems were confirmed in the data the audit could read. This is <b>not</b> a clean result: part of the tenant could not be checked &mdash; see $naLink.</p>"
    }

    # ---- not assessed section ----
    $gapGroups = [ordered]@{}
    foreach ($f in $gapItems) {
        $k = (Get-EntraIssueKey $f).Key
        if ($gapGroups.Contains($k)) { $gapGroups[$k].Count++ }
        else { $gapGroups[$k] = @{ Finding = $f; Count = 1; Severity = (Normalize-Severity $f.Severity) } }
    }
    $gapPoints = @{}; foreach ($d in $gapDrivers) { $gapPoints[$d.Key] = $d.Points }
    $gapLis = foreach ($k in $gapGroups.Keys) {
        $g = $gapGroups[$k]; $f = $g.Finding
        $pts = if ($gapPoints.ContainsKey($k)) { " &middot; adds $($gapPoints[$k]) points" } else { '' }
        $t = if ($g.Count -gt 1) { "$(HtmlEncode (Get-EntraIssueKey $f).IssueTitle) <span class='muted'>&times; $($g.Count)</span>" } else { HtmlEncode $f.Title }
        "<li><span class='pill sev-$($g.Severity)'>$($g.Severity)</span><div><a href='$resultsHref#$(HtmlAttrEncode (New-FindingAnchor $f))'><b>$t</b></a> <span class='pill mini gap'>Not assessed</span><span class='li-sub'>$(HtmlEncode (& $checkTitle $f.CheckId))$pts</span></div></li>"
    }
    $checkLis = foreach ($r in $checkGapRows) {
        "<li><span class='pill $($r.Class)'>$(HtmlEncode $r.Label)</span><div><a href='Posture-Summary.html#check-$(HtmlAttrEncode $r.CheckId)'><b>$(HtmlEncode $r.Title)</b></a><span class='li-sub'>$(HtmlEncode $r.Reason)</span></div></li>"
    }
    $notAssessedHtml = ''
    if ($hasNotAssessed) {
        $parts = @()
        if (@($checkLis).Count -gt 0) { $parts += "<h3>Checks that were skipped or did not finish</h3><ul class='risk-list'>$(@($checkLis) -join "`n")</ul>" }
        if (@($gapLis).Count -gt 0) { $parts += "<h3>Data that could not be read <small>(<a href='$resultsHref`?sev=Gap'>open in the detailed results</a>)</small></h3><ul class='risk-list'>$(@($gapLis) -join "`n")</ul>" }
        $notAssessedHtml = @"
  <div class="section" id="not-assessed">
    <h2>Not assessed</h2>
    <p class="section-lead">What the audit could not check. These are gaps in the audit, not clean results: a problem there would not show up anywhere in this report.</p>
    <div class="callout warn">$($parts -join "`n")</div>
  </div>
"@
    }

    # ---- score drivers: every issue behind the score, biggest first; coverage gaps flagged ----
    $driverRow = {
        param($d)
        # The share computed by Get-EntraRiskScore from the UNROUNDED points - the same number
        # Top risks, the Summary sentence and Findings.json show.
        $pct = if ($d.PSObject.Properties['Share'] -and $null -ne $d.Share) { [int]$d.Share }
               elseif ($Score.Score -gt 0) { [math]::Round(100 * $d.Points / $Score.Score) } else { 0 }
        $gap = if ($d.CoverageGap) { " <span class='pill mini gap'>Not assessed</span>" } else { '' }
        # A one-finding issue shows the finding's own title (as Top risks and the summary do):
        # the issue title drops the object name, so per-type rules would all read the same.
        $name = if ($d.Count -eq 1 -and $d.FirstTitle) { $d.FirstTitle } else { $d.Title }
        $acceptedTag = if ($d.AcceptedRisk) { " <span class='pill mini gap'>Accepted risk</span>" } elseif ($d.AcceptedFindings -gt 0) { " <span class='pill mini gap'>Partly accepted</span>" } else { '' }
        "<tr><td><span class='pill sev-$($d.Severity)'>$($d.Severity)</span></td><td class='title'><a href='$resultsHref#$(HtmlAttrEncode $d.FirstAnchor)'>$(HtmlEncode $name)</a>$gap$acceptedTag<span class='sub'>$(HtmlEncode $d.PopulationText)</span></td><td>$(HtmlEncode (& $checkTitle $d.CheckId))<span class='sub mono'>$(HtmlEncode $d.CheckId)</span></td><td class='num'>$($d.ScoringCount)<span class='sub'>$($d.Count) finding record(s)</span></td><td class='num mono'>$($d.Points)</td><td class='num mono'>$pct%</td></tr>"
    }
    $allDrivers = @($Score.Drivers)
    $driverRows = @($allDrivers | Select-Object -First 10 | ForEach-Object { & $driverRow $_ })
    $moreRows = @($allDrivers | Select-Object -Skip 10 | ForEach-Object { & $driverRow $_ })
    if ($driverRows.Count -eq 0) { $driverRows = @("<tr><td colspan='6'>Nothing adds to the score: there are no Critical, High, Medium or Low findings.</td></tr>") }
    $driverHead = "<thead><tr><th>Severity</th><th style='text-align:left'>Issue / population</th><th style='text-align:left'>Check</th><th style='text-align:right'>Scoring units</th><th style='text-align:right'>Points</th><th style='text-align:right'>Combined share</th></tr></thead>"
    $moreHtml = if ($moreRows.Count -gt 0) { "<details class='more'><summary>Show all $($allDrivers.Count) issues</summary><table>$driverHead<tbody>$($moreRows -join "`n")</tbody></table></details>" } else { '' }
    $gapNote = if ($Score.NotAssessedPoints -gt 0) { "<div style='margin-top:6px'><small>$($Score.NotAssessedPoints) of the $($Score.Score) points come from issues marked Not assessed (things that could not be checked).</small></div>" } else { '' }

    # ---- findings by category (confirmed counts; coverage gaps in their own column) ----
    $catGroups = $Items | ForEach-Object { [pscustomobject]@{ Category=[string]$_.Category; Severity=(Normalize-Severity $_.Severity); Gap=[bool](Test-EntraCoverageGap $_) } } |
        Group-Object Category | Sort-Object Name
    $catRows = foreach ($cg in $catGroups) {
        $conf = @($cg.Group | Where-Object { -not $_.Gap })
        $ncC=@($conf|Where-Object{$_.Severity -eq 'Critical'}).Count; $ncH=@($conf|Where-Object{$_.Severity -eq 'High'}).Count
        $ncM=@($conf|Where-Object{$_.Severity -eq 'Medium'}).Count; $ncL=@($conf|Where-Object{$_.Severity -eq 'Low'}).Count
        $ncG=@($cg.Group | Where-Object { $_.Gap }).Count
        # Total counts only the confirmed risk columns - Information findings have no
        # column here, and including them made rows appear not to sum.
        $ct = $ncC + $ncH + $ncM + $ncL
        if ($ct -eq 0 -and $ncG -eq 0) { continue }   # Information-only category: nothing to show
        $cell = { param($n, $sev) if ($n) { "<span class='pill sev-$sev'>$n</span>" } else { '-' } }
        $gapCell = if ($ncG) { "<span class='pill gap'>$ncG</span>" } else { '-' }
        "<tr><td>$(HtmlEncode $cg.Name)</td><td style='text-align:center'>$(& $cell $ncC 'Critical')</td><td style='text-align:center'>$(& $cell $ncH 'High')</td><td style='text-align:center'>$(& $cell $ncM 'Medium')</td><td style='text-align:center'>$(& $cell $ncL 'Low')</td><td style='text-align:center;font-weight:700'>$ct</td><td style='text-align:center'>$gapCell</td></tr>"
    }
    if (-not $catRows) { $catRows = @("<tr><td colspan='7'>No findings that add to the score.</td></tr>") }

    # ---- all findings (collapsed; the Results page is the full view) ----
    $sorted = $Items | Sort-Object @{e={Get-SeverityRank $_.Severity};Descending=$true}, Title
    $tableRows = foreach ($f in $sorted) {
        $sev = Normalize-Severity $f.Severity
        $isGap = [bool](Test-EntraCoverageGap $f)
        $href = Resolve-SourceHref $f.SourceFile
        $links = "<a href='$resultsHref#$(HtmlAttrEncode (New-FindingAnchor $f))'>Details</a>"
        if ($href) { $links += " &middot; <a href='$(HtmlAttrEncode $href)' target='_blank' rel='noopener'>Evidence</a>" }
        $gapTag = if ($isGap) { " <span class='pill mini gap'>Not assessed</span>" } else { '' }
        if ([bool](Get-EAField $f 'AcceptedRisk')) { $gapTag += " <span class='pill mini gap'>Accepted risk; review $(HtmlEncode (Get-EAField $f 'ExceptionExpiresUtc'))</span>" }
        "<tr data-sev='$sev' data-gap='$(if ($isGap) { '1' } else { '0' })'><td><span class='pill sev-$sev'>$sev</span></td><td class='title'>$(HtmlEncode $f.Title)$gapTag</td><td class='evidence'>$(HtmlEncode $f.Evidence)</td><td class='source'>$links</td></tr>"
    }

    # ---- header cards ----
    # Each severity card opens the detailed results filtered to that severity.
    $sevCard = {
        param([string]$sev, [string]$hint)
        $n = [int]$cc[$sev]; $g = [int]$gc[$sev]
        $accepted = @($Items | Where-Object { (Normalize-Severity $_.Severity) -eq $sev -and -not (Test-EntraCoverageGap $_) -and [bool](Get-EAField $_ 'AcceptedRisk') }).Count
        $openCount = $n - $accepted
        $sub = "$openCount open"
        if ($accepted -gt 0) { $sub += " &middot; $accepted accepted" }
        if ($openCount -gt 0) { $sub += "<br>$hint" } elseif ($accepted -gt 0) { $sub += '<br>Review accepted risks' }
        if ($g -gt 0) { $sub += "<br>+$g not assessed" }
        "<a class='card span-3' href='$resultsHref`?sev=$sev' title='Show the $sev findings in the detailed results'><div class='k'>$sev</div><div class='v'>$n</div><div class='s'>$sub</div></a>"
    }
    $covSub = @()
    if ($cov.Incomplete -gt 0) { $covSub += "$($cov.Incomplete) incomplete" }
    if ($cov.Skipped -gt 0)    { $covSub += "$($cov.Skipped) skipped" }
    if ($cov.Errored -gt 0)    { $covSub += "$($cov.Errored) with errors" }
    if ($cov.NotRun -gt 0)     { $covSub += "$($cov.NotRun) not selected" }
    $covSubText = if (-not $cov.Known) { 'Unknown: no check status was recorded' } elseif ($covSub.Count -gt 0) { $covSub -join ' &middot; ' } else { 'Every selected check ran fully' }
    $covCardCls = if ($cov.Complete) { 'card span-6' } else { 'card span-6 warn' }
    $covValue = if ($cov.Selected -gt 0) { "$($cov.FullyEvaluated) of $($cov.Selected)" } else { '-' }
    $badgeNote = if ($Score.Band -in @('Not assessed','Not fully assessed')) { 'Not a clean result: some things could not be checked.' }
                 elseif (-not $Score.CoverageComplete) { 'Not everything could be checked, so the real risk may be higher.' }
                 else { '' }
    $badgeNoteHtml = if ($badgeNote) { "<div class='badge-note'>$badgeNote</div>" } else { '' }

    # ---- one-line run context (full details are on the Posture Summary) ----
    $runBits = @()
    $tid = Get-EntraRunValue $RunInfo 'TenantId'
    if ($tid) { $runBits += "Tenant id: <span class='mono'>$(HtmlEncode $tid)</span>" }
    $acct = Get-EntraRunValue $RunInfo 'Account'
    $mode = Get-EntraRunValue $RunInfo 'AuthMode'; if (-not $mode) { $mode = $script:AuthType }
    if ($acct) { $runBits += "Signed in as: <span class='mono'>$(HtmlEncode $acct)</span> ($(HtmlEncode $mode))" } elseif ($mode) { $runBits += "Sign-in: <span class='mono'>$(HtmlEncode $mode)</span>" }
    $dur = Get-EntraRunDurationText $RunInfo
    if ($dur) { $runBits += "Run time: $(HtmlEncode $dur)" }
    $ver = Get-EntraRunValue $RunInfo 'ToolVersion'; if (-not $ver) { $ver = $script:Version }
    $runBits += "$(HtmlEncode $ver) &middot; <a href='Posture-Summary.html#run-details'>Run details</a>"

    $css = Get-EntraRiskCss
    $js  = (Get-EntraThemeScript) + (Get-EntraRiskJs)
    $nav = Get-EntraPrimaryNav 'risk'
    $total = @($Items).Count
    # Totals per severity as on the Results page (confirmed + not assessed).
    $allCounts = if ($Counts -and $Counts.ContainsKey('Critical')) { $Counts } else { @{ Critical = $Score.Critical; High = $Score.High; Medium = $Score.Medium; Low = $Score.Low; Information = $Score.Information } }
    # A severity filter shows every row of that severity, not-assessed ones included, so the
    # number here must match what the filter shows; the not-assessed part is named in brackets.
    $allText = (@('Critical','High','Medium','Low','Information') | ForEach-Object {
        $g = if ($gc) { [int]$gc[$_] } else { 0 }
        '{0} {1}{2}' -f [int]$allCounts[$_], $_.ToLowerInvariant(), $(if ($g -gt 0) { " (incl. $g not assessed)" } else { '' })
    }) -join ', '

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Audit - Risk Report</title>
$css
</head>
<body>
<div class="container">
$nav
  <div class="header">
    <div class="h-title">
      <div class="h-main">
        <h1>Microsoft Entra ID Audit - Risk Report</h1>
        <div class="meta">Tenant: <span class="mono">$(HtmlEncode $TenantName)</span> | Generated: $(HtmlEncode $GeneratedOn) | <a href="$resultsHref">Detailed findings</a></div>
        <div class="meta" style="margin-top:4px">$($runBits -join ' | ')</div>
        <div class="meta" style="margin-top:4px">Licenses: $(HtmlEncode (Get-EntraLicenseText $RunInfo))</div>
      </div>
      <div class="h-side">
        <button id="themeToggle" type="button" class="theme-toggle">Dark mode</button>
        <div class="badge $($Score.HighestConfirmedSeverity)">
          <div><div class="grade">Highest confirmed severity</div><div class="value">$(HtmlEncode $Score.HighestConfirmedSeverity)</div></div>
          <div class="badge-sep"></div>
          <div><div class="grade">Action priority</div><div class="value">$(HtmlEncode $urgency)</div></div>
          <div class="badge-sep"></div>
          <div><div class="grade">Confirmed risk index</div><div class="value">$($Score.ConfirmedScore)</div></div>
        </div>
        $badgeNoteHtml
      </div>
    </div>
    <div class="callout quick-actions">$doFirstHtml$changeSummaryHtml</div>
    <div class="grid">
      $(& $sevCard 'Critical' 'Fix immediately')
      $(& $sevCard 'High' 'Fix promptly')
      $(& $sevCard 'Medium' 'Plan the fix')
      $(& $sevCard 'Low' 'Routine clean-up')
      <a class="$covCardCls" href="Posture-Summary.html#checks" title="Open the check results"><div class="k">Checks with a full result</div><div class="v">$covValue</div><div class="s">$covSubText</div></a>
      <div class="card span-2"><div class="k">Users</div><div class="v">$($Stats.Users)</div><div class="s">Members and guests</div></div>
      <div class="card span-2"><div class="k">Guests</div><div class="v">$($Stats.Guests)</div><div class="s">People from outside</div></div>
      <div class="card span-2"><div class="k">Applications</div><div class="v">$($Stats.Apps)</div><div class="s">App registrations</div></div>
    </div>
  </div>

  <div class="section" id="summary">
    <h2>Summary</h2>
    <div class="$calloutCls">$($summary -join "`n")</div>
  </div>

  <div class="section" id="top-risks">
    <h2>Top risks</h2>
    <p class="section-lead">Open remediation first, then severity and affected population. Accepted risks retain their severity and points and remain visible for expiry review.</p>
    <div class="callout">$topHtml</div>
  </div>
$notAssessedHtml
  <div class="section" id="drivers">
    <h2>What drives the score</h2>
    <p class="section-lead">Every problem behind the score, biggest first. &quot;How the score works&quot; below explains the points.</p>
    <table>$driverHead<tbody>$($driverRows -join "`n")</tbody></table>
    $moreHtml
    $gapNote
  </div>

  <div class="section" id="how-scored">
    <h2>How the score works</h2>
    <div class="callout">
      <p>Every problem adds points by severity: Critical $($script:RiskPoints.Critical), High $($script:RiskPoints.High), Medium $($script:RiskPoints.Medium) and Low $($script:RiskPoints.Low). Information notes add $($script:RiskPoints.Information). <b>A higher score is worse</b>, and there is no upper limit.</p>
      <p>For each rule and severity, points are multiplied by &radic;N. N uses explicit affected-object populations, with repeated object identifiers counted once. For example, 9 affected administrators contribute 3 times the points of one. When identifiers are incomplete, overlapping population counts use the largest known count as a lower bound. When no population is recorded, scoring falls back to finding records; the driver names that limitation. Evidence-table rows are never assumed to be distinct affected objects.</p>
      <p>Things the audit could not check (<span class='pill mini gap'>Not assessed</span>) also add points at their severity, because not being able to see something is a risk in itself. They are always shown apart from confirmed problems. If a problem is confirmed on some objects and could not be checked on others, it still counts as one problem; the part that could not be checked only adds the extra points. Checks that were skipped or stopped with an error add no points. Instead, the risk level is never shown as Clean while any selected check was skipped, failed or could not read all of its data.</p>
      <p>Confirmed risk index: <b>$($Score.ConfirmedScore)</b>. Assessment-gap contribution: <b>$($Score.NotAssessedPoints)</b>. Combined index: <b>$($Score.Score)</b> (<b>$(HtmlEncode $Score.Band)</b>). The combined index is a secondary measure; missing evidence is not a confirmed tenant weakness. The current scoring ruleset is 2.2.0; compare numeric scores only within the same ruleset and scope.</p>
      <div class="matrix-wrap"><br>
        <table class="matrix"><thead><tr><th>Combined index band</th><th>Score</th><th>What it means</th></tr></thead><tbody>$($matrixRows -join "`n")</tbody></table>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>Findings by category</h2>
    <table><thead><tr><th style="text-align:left">Category</th><th style="text-align:center">Critical</th><th style="text-align:center">High</th><th style="text-align:center">Medium</th><th style="text-align:center">Low</th><th style="text-align:center">Total</th><th style="text-align:center">Not assessed</th></tr></thead><tbody>$($catRows -join "`n")</tbody></table>
    <div style="margin-top:6px"><small>Counts confirmed problems only. Information notes add no points and are left out. &quot;Not assessed&quot; counts things that could not be checked.</small></div>
  </div>

  <div class="section" id="all-findings">
    <details class="all-findings">
      <summary>All findings ($total) <small>- $allText. The same findings as the <a href="$resultsHref">detailed results</a>, as one sortable list.</small></summary>
      <div class="toolbar">
        <div class="filters">
          <label><small>Severity</small><br><select id="sevFilter"><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Information</option><option>Not assessed</option></select></label>
          <label><small>Search</small><br><input id="search" type="text" placeholder="Search the title or evidence"></label>
        </div>
        <div><small>Showing <span id="visibleCount">0</span> of $total</small></div>
      </div>
      <table id="findings"><thead><tr><th data-sort="severity">Severity</th><th data-sort="title">Finding</th><th>Evidence</th><th>Links</th></tr></thead><tbody id="findings-body">$($tableRows -join "`n")</tbody></table>
    </details>
  </div>

  <div class="footer">Generated by $(HtmlEncode $ver) &mdash; a read-only audit through Microsoft Graph (and, when connected, Azure Resource Manager). The score sums up the findings in this report and covers only the checks that ran; the Posture Summary shows which ones did.</div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Write-PostureSummaryReport {
    param([string]$Path, [string]$TenantName, [string]$GeneratedOn, [hashtable]$Stats,
          [object]$RunInfo = $script:RunInfo, [object[]]$Items, [pscustomobject]$Score)

    if ($null -eq $Items) { $Items = Get-EntraFindingList }
    if ($null -eq $Stats) { $Stats = Get-EntraReportStatistic }
    # Same coverage object as the score (and so the Results page and the Risk Report).
    $cov = if ($Score -and $Score.PSObject.Properties['Coverage'] -and $Score.Coverage) { $Score.Coverage } else { Get-EntraRunCoverage -RunInfo $RunInfo }
    $datasets = @(Get-EntraDatasetIndex -Items $Items)

    # Per-check finding breakdown (confirmed by severity + coverage gaps) and first anchor.
    $byCheck = @{}
    foreach ($f in $Items) {
        $id = [string]$f.CheckId
        if (-not $byCheck.ContainsKey($id)) { $byCheck[$id] = @{ Critical=0; High=0; Medium=0; Low=0; Information=0; Gap=0; GapListable=0; GapTitles=(New-Object System.Collections.Generic.List[string]); First=$null; FirstRank=-1 } }
        $e = $byCheck[$id]
        $sev = Normalize-Severity $f.Severity
        if (Test-EntraCoverageGap $f) {
            $e.Gap++
            # The "check did not finish" gap repeats the row's own reason, so it is not listed again.
            if ([string]$f.RuleId -ne ('{0}-check-did-not-finish' -f $id)) {
                $e.GapListable++
                if ($e.GapTitles.Count -lt 5) { $e.GapTitles.Add([string]$f.Title) | Out-Null }
            }
        } else { $e[$sev]++ }
        $rank = Get-SeverityRank $sev
        if ($rank -gt $e.FirstRank) { $e.First = $f; $e.FirstRank = $rank }
    }
    $dsByCheck = @{}
    foreach ($d in $datasets) {
        if (-not $d.CheckId) { continue }
        if (-not $dsByCheck.ContainsKey($d.CheckId)) { $dsByCheck[$d.CheckId] = New-Object System.Collections.Generic.List[object] }
        $dsByCheck[$d.CheckId].Add($d) | Out-Null
    }

    $regOrder = @{}; $i = 0; foreach ($r in $cov.Rows) { $regOrder[$r.CheckId] = $i++ }
    $rowsSorted = @($cov.Rows | Sort-Object @{e={$_.SortOrder}}, @{e={$regOrder[$_.CheckId]}})
    $statusRows = foreach ($r in $rowsSorted) {
        $e = if ($byCheck.ContainsKey($r.CheckId)) { $byCheck[$r.CheckId] } else { $null }
        $pills = ''
        $link = ''
        if ($e) {
            foreach ($sev in @('Critical','High','Medium','Low','Information')) {
                if ($e[$sev] -gt 0) { $pills += "<span class='pill mini sev-$sev' title='$sev'>$($e[$sev]) $($sev.Substring(0, $(if ($sev -eq 'Information') { 4 } else { 1 })))</span>" }
            }
            if ($e.Gap -gt 0) { $pills += "<span class='pill mini gap'>$($e.Gap) not assessed</span>" }
            if ($e.First) {
                $link = "<br><a href='EntraAudit-Results.html?check=$([uri]::EscapeDataString($r.CheckId))#$(HtmlAttrEncode (New-FindingAnchor $e.First))'>View findings</a>"
            }
        }
        if (-not $pills) { $pills = if ($r.Group -in @('clean')) { "<span class='muted'>None</span>" } else { "<span class='muted'>-</span>" } }
        $detail = if ($r.Reason) { HtmlEncode $r.Reason } elseif ($r.Group -eq 'clean') { "<span class='muted'>No problems found.</span>" } else { '' }
        if ($e -and $e.GapTitles.Count -gt 0) {
            $more = $e.GapListable - $e.GapTitles.Count
            $detail += "<span class='sub'>Could not check: " + (($e.GapTitles | ForEach-Object { HtmlEncode $_ }) -join '; ') + $(if ($more -gt 0) { " (+$more more)" } else { '' }) + '</span>'
        }
        # Permission names as chips, unless the reason already names every one of them.
        $missing = @($r.MissingScopes)
        if ($missing.Count -gt 0 -and @($missing | Where-Object { ([string]$r.Reason).IndexOf([string]$_, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 }).Count -gt 0) {
            $detail += "<span class='sub'>Missing permission: " + (($missing | ForEach-Object { "<span class='chip mono'>$(HtmlEncode $_)</span>" }) -join '') + '</span>'
        }
        if ($r.ErrorMessage -and $r.Group -in @('error','skipped')) {
            $msg = [string]$r.ErrorMessage; if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }
            $detail += "<span class='err-msg'>$(HtmlEncode $msg)</span>"
        }
        $ev = ''
        if ($dsByCheck.ContainsKey($r.CheckId)) {
            $list = $dsByCheck[$r.CheckId]
            $ev = (@($list | Select-Object -First 3 | ForEach-Object {
                $h = if ($_.HtmlHref) { $_.HtmlHref } elseif ($_.CsvHref) { $_.CsvHref } else { $null }
                $lbl = "$(HtmlEncode $_.Title) <span class='muted'>($($_.Rows) row$(if ($_.Rows -ne 1) { 's' }))</span>"
                if ($h) { "<a href='$(HtmlAttrEncode (Resolve-SourceHref $h))' target='_blank' rel='noopener'>$lbl</a>" } else { $lbl }
            }) -join '<br>')
            if ($list.Count -gt 3) { $ev += "<br><a href='Raw-Data.html?check=$([uri]::EscapeDataString($r.CheckId))'>All $($list.Count) datasets</a>" }
        } elseif ($r.Group -notin @('notrun','skipped')) { $ev = "<span class='muted'>-</span>" }
        # The raw status code (as in Findings.json) is a tooltip, not extra text on the page.
        $codeTitle = if ($r.Group -ne 'notrun') { " title='Status code: $(HtmlAttrEncode $r.Status)'" } else { '' }
        $dataGroup = switch ($r.Group) {
            'clean' { 'pass' }
            'findings' { if ($r.Incomplete) { 'findings gaps' } else { 'findings' } }
            'error' { if ($r.Count -gt 0) { 'findings gaps' } else { 'gaps' } }
            'notrun' { 'notrun' }
            default { 'gaps' }
        }
        "<tr id='check-$(HtmlAttrEncode $r.CheckId)' data-group='$dataGroup'><td><b>$(HtmlEncode $r.Title)</b><span class='sub mono'>$(HtmlEncode $r.CheckId)</span></td><td><span class='pill $($r.Class)'$codeTitle>$(HtmlEncode $r.Label)</span></td><td>$pills$link</td><td>$detail</td><td>$ev</td></tr>"
    }

    # ---- licensing: which checks each license gates, derived from the registry ----
    $notFound  = if ($script:LicenseKnown) { 'not found' } else { 'not confirmed (the license lookup failed)' }
    $skipLabel = if ($script:LicenseKnown) { 'Skipped: no license' } else { 'Skipped: license unknown' }
    $p1Ids = @($script:Registry.Keys | Where-Object { $script:Registry[$_].P1 }) -join ', '
    $p2Ids = @($script:Registry.Keys | Where-Object { $script:Registry[$_].P2 }) -join ', '
    $wipIds = @($script:Registry.Keys | Where-Object { $script:Registry[$_].WIP })
    if ($wipIds.Count -eq 0 -and $script:Registry.Contains('riskyserviceprincipals')) { $wipIds = @('riskyserviceprincipals') }
    $licNote = @()
    if ($script:LicenseKnown -and $script:HasP1 -and $script:HasP2) { $licNote += 'Microsoft Entra ID P1 and P2 found: no check was blocked by a missing Entra ID license.' }
    if (-not $script:LicenseKnown) { $licNote += 'The license lookup FAILED (the list of subscribed licenses could not be read). The tenant may well have P1 or P2; checks that need them show as "Skipped: license unknown", not as "no license".' }
    if (-not $script:HasP1) { $licNote += ("Microsoft Entra ID P1 {0}. The checks that need it ({1}) could not run and show as ""{2}"" below. Checks that use sign-in activity (guests, break-glass, enterprise apps and monitoring) report that part as incomplete, not clean." -f $notFound, $p1Ids, $skipLabel) }
    if (-not $script:HasP2) { $licNote += ("Microsoft Entra ID P2 {0}. The checks that need it ({1}) could not run and show as ""{2}"" below. The privileged-roles check still runs, but without Privileged Identity Management (PIM) eligibility data, so every privileged assignment is treated as permanent." -f $notFound, $p2Ids, $skipLabel) }
    if (-not $script:WorkloadIdP -and $wipIds.Count -gt 0) { $licNote += ("Workload Identities Premium {0}. {1} (risky workload identities) needs it and reports a coverage gap instead of a result. This is a separate license from Entra ID P2." -f $notFound, ($wipIds -join ', ')) }
    # License notes from detection (e.g. a suspended or grace-period subscription).
    $notes = @($script:LicenseNotes | Where-Object { $_ })
    if ($notes.Count -eq 0) { $lic = Get-EntraRunValue $RunInfo 'Licenses'; if ($lic) { $notes = @(Get-EntraRunValue $lic 'Notes' | Where-Object { $_ }) } }
    foreach ($n in $notes) { $licNote += [string]$n }
    $licHtml = '<ul>' + (($licNote | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join '') + '</ul>'
    $skuHtml = ConvertTo-EntraLicenseSkuHtml -RunInfo $RunInfo

    $runHtml = ConvertTo-EntraRunDetailsHtml -RunInfo $RunInfo -TenantName $TenantName -Coverage $cov

    $css = Get-EntraRiskCss
    $nav = Get-EntraPrimaryNav 'posture'
    $js  = (Get-EntraThemeScript) + (Get-EntraRiskJs)
    $mode = Get-EntraRunValue $RunInfo 'AuthMode'; if (-not $mode) { $mode = $script:AuthType }
    $ver = Get-EntraRunValue $RunInfo 'ToolVersion'; if (-not $ver) { $ver = $script:Version }
    $checkLine = if (-not $cov.Known) { 'Checks: unknown - no check status was recorded' } else {
        $gapShort = Get-EntraCoverageGapText -Coverage $cov -Short
        "Checks: <b>$($cov.FullyEvaluated) of $($cov.Selected)</b> selected checks gave a full result" +
            $(if ($gapShort) { " ($gapShort)" }) + " &middot; $($cov.NotRun) of $($cov.Total) available checks were not selected"
    }
    # Coverage tiles shared with the Results page (the "checks selected" count is in the line
    # above). Without a check status the counts would all read 0 / "not selected", which
    # contradicts the "Unknown" rows below, so one "Unknown" tile stands in for them.
    $tileHtml = if (-not $cov.Known) {
        "<div class='card span-12 warn'><div class='k'>Checks</div><div class='v'>Unknown</div><div class='s'>No check status was recorded, so it is not known which checks ran or passed. A missing finding does not mean all is well.</div></div>"
    } else {
        $tiles = @(Get-EntraCoverageTile -Coverage $cov | Where-Object { $_.Key -ne 'selected' })
        ($tiles | ForEach-Object {
            $cls = if ($_.State) { ' warn' } else { '' }
            $hint = if ($_.Key -eq 'incomplete') { 'Some data could not be read (can overlap &quot;Problems found&quot;)' } else { HtmlEncode $_.Hint }
            "<div class='card span-4$cls'><div class='k'>$(HtmlEncode $_.Label)</div><div class='v'>$($_.Value)</div><div class='s'>$hint</div></div>"
        }) -join "`n      "
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Audit - Posture Summary</title>
$css
</head>
<body>
<div class="container">
$nav
  <div class="header">
    <div class="h-title">
      <div class="h-main">
        <h1>Microsoft Entra ID Audit - Posture Summary</h1>
        <div class="meta">Tenant: <span class="mono">$(HtmlEncode $TenantName)</span> | Generated: $(HtmlEncode $GeneratedOn) | Sign-in: <span class="mono">$(HtmlEncode $mode)</span> | <a href="#run-details">Run details</a></div>
        <div class="meta" style="margin-top:4px">$checkLine</div>
        <div class="meta" style="margin-top:4px">Licenses: $(HtmlEncode (Get-EntraLicenseText $RunInfo))</div>
      </div>
      <button id="themeToggle" type="button" class="theme-toggle">Dark mode</button>
    </div>
    <div class="grid">
      $tileHtml
      <div class="card span-4"><div class="k">Users</div><div class="v">$($Stats.Users)</div><div class="s">Members and guests</div></div>
      <div class="card span-4"><div class="k">Guests</div><div class="v">$($Stats.Guests)</div><div class="s">People from outside</div></div>
      <div class="card span-4"><div class="k">Applications</div><div class="v">$($Stats.Apps)</div><div class="s">App registrations</div></div>
    </div>
  </div>

  <div class="section" id="licensing">
    <h2>Licenses and what they allow the audit to check</h2>
    <div class="callout">$licHtml$skuHtml<p style="margin-top:8px"><small>Skipped, failed and incomplete checks are gaps in the audit, not clean results. A check that found problems can also be incomplete when another data source could not be read. &quot;Not run&quot; means the check was not selected this time, so it says nothing about the tenant.</small></p></div>
  </div>

  <div class="section" id="checks">
    <h2>Check results</h2>
    <p class="section-lead">One row per check, problems first. The Findings column counts confirmed problems by severity (C = Critical, H = High, M = Medium, L = Low, Info = information notes) and things that could not be checked.</p>
    <div class="toolbar"><div class="filters"><label><small>Show</small><br><select id="checkFilter"><option value="all">All checks</option><option value="attention">Needs attention</option><option value="findings">Problems found</option><option value="gaps">Gaps (incomplete, skipped or failed)</option><option value="pass">Passed</option><option value="notrun">Not run</option></select></label></div><div><small>Showing <span id="checkCount">$($cov.Rows.Count)</span> of $($cov.Rows.Count)</small></div></div>
    <table id="checkTable"><thead><tr><th style="text-align:left">Check</th><th style="text-align:left">Result</th><th style="text-align:left">Findings</th><th style="text-align:left">Details</th><th style="text-align:left">Evidence</th></tr></thead><tbody>$($statusRows -join "`n")</tbody></table>
  </div>

  <div class="section" id="run-details">
    <h2>Run details</h2>
    $runHtml
  </div>

  <div class="footer">Generated by $(HtmlEncode $ver) &mdash; a read-only audit through Microsoft Graph (and, when connected, Azure Resource Manager).</div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Write-RawDataIndexReport {
    param([string]$Path, [string]$TenantName, [string]$GeneratedOn, [object[]]$Items)
    if ($null -eq $Items) { $Items = Get-EntraFindingList }
    $css = (Get-EntraMainCss) + "`n" + (Get-EntraRawCss)
    $nav = Get-EntraPrimaryNav 'raw'
    $js  = (Get-EntraThemeScript) + (Get-EntraRawJs)
    $datasets = @(Get-EntraDatasetIndex -Items $Items)
    # The "used by findings" list on each dataset page can only be filled in now that
    # every check has finished.
    Write-EntraDatasetUsage -Datasets $datasets

    $rows = foreach ($d in $datasets) {
        $checkCell = if ($d.CheckId) { "<a href='Posture-Summary.html#check-$(HtmlAttrEncode $d.CheckId)'>$(HtmlEncode $(if ($d.CheckTitle) { $d.CheckTitle } else { $d.CheckId }))</a><span class='sub mono'>$(HtmlEncode $d.CheckId)</span>" } else { "<span class='muted'>-</span>" }
        $notes = if (@($d.Notes).Count -gt 0) { "<span class='sub'>$((@($d.Notes) | ForEach-Object { HtmlEncode $_ }) -join ' &middot; ')</span>" } else { '' }
        $errs = if (@($d.Errors).Count -gt 0) { "<div class='raw-err'>$((@($d.Errors) | ForEach-Object { HtmlEncode $_ }) -join '<br>')</div>" } else { '' }
        $rowsCell = if ($d.Rows -eq 0) { "0 <span class='muted'>(empty)</span>" } else { [string]$d.Rows }
        $used = $d.UsedBy.Count
        $usedCell = if ($used -gt 0) {
            $first = $d.UsedBy[0]
            "<a href='EntraAudit-Results.html#$(HtmlAttrEncode (New-FindingAnchor $first))'>$used finding$(if ($used -ne 1) { 's' })</a>"
        } else { "<span class='muted'>none</span>" }
        $links = @()
        foreach ($l in @(@{ H = $d.HtmlHref; L = 'HTML'; D = $false }, @{ H = $d.CsvHref; L = 'CSV'; D = $true }, @{ H = $d.TxtHref; L = 'TXT'; D = $true })) {
            if ($l.H) { $links += "<a href='$(HtmlAttrEncode (Resolve-SourceHref $l.H))'$(if ($l.D) { ' download' })>$($l.L)</a>" }
            else { $links += "<span class='raw-err' title='This file could not be saved'>$($l.L) missing</span>" }
        }
        "<tr data-check='$(HtmlAttrEncode $d.CheckId)'><td><b>$(HtmlEncode $d.Title)</b><span class='sub mono'>$(HtmlEncode $d.BaseName)</span>$notes$errs</td><td>$checkCell</td><td class='num' data-sort='$($d.Rows)'>$rowsCell</td><td class='num' data-sort='$used'>$usedCell</td><td>$($links -join ' &middot; ')</td></tr>"
    }
    if (-not $rows) { $rows = @("<tr class='no-data'><td colspan='5'>No evidence was saved in this run.</td></tr>") }
    $total = $datasets.Count
    $empty = @($datasets | Where-Object { $_.Rows -eq 0 }).Count
    $failed = @($datasets | Where-Object { @($_.Errors).Count -gt 0 }).Count
    $failedText = if ($failed -gt 0) { " <b class='raw-err'>$failed dataset(s) could not be saved completely - see the red notes below.</b>" } else { '' }
    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Audit - Raw Data</title>
$css
</head>
<body data-theme="light">
<div class="container">
$nav
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>Raw Data &mdash; the evidence behind the findings</h1>
        <div class="meta">
          Tenant: <span class="mono">$(HtmlEncode $TenantName)</span><br>
          Generated: $(HtmlEncode $GeneratedOn)<br>
          Every check saves what it read in three forms: a web page (HTML), a spreadsheet file (CSV) and a plain-text file (TXT). <b>$total</b> dataset(s), $empty of them empty (the check found nothing to list).$failedText
        </div>
      </div>
      <div class="hero-actions"><button type="button" class="theme-toggle" id="themeToggle">Dark mode</button></div>
    </div>
  </section>
  <section class="toolbar">
    <div class="toolbar-row"><div class="filter"><label for="rawSearch">Filter datasets</label><input id="rawSearch" type="text" placeholder="Type to filter by name, check or note"></div></div>
    <div class="raw-status"><span id="rawCount" data-noun="datasets">$total of $total datasets shown</span> &middot; Click a column heading to sort.</div>
    <div class="check-note" id="checkFilterNote" style="display:none">Showing only the datasets from check <b class="mono" id="checkFilterName"></b>. <a href="#" id="clearCheckFilter">Show all datasets</a></div>
  </section>
  <div class="raw-table-wrap">
  <table class="result-table raw-table sortable">
    <thead><tr><th>Dataset</th><th>From check</th><th class="num">Rows</th><th class="num">Used by findings</th><th>Open or download</th></tr></thead>
    <tbody>
      $($rows -join "`n")
    </tbody>
  </table>
  </div>
</div>
$js
</body>
</html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8 -ErrorAction Stop
}

function Get-EntraFindingList {
    if ($null -eq $script:Findings) { return ,@() }
    if ($script:Findings -is [System.Collections.Generic.List[object]]) { return ,$script:Findings.ToArray() }
    return ,@($script:Findings | ForEach-Object { $_ })
}

function Get-EntraReportStatistic {
    $users = $script:UsersCache
    $apps = if ($null -ne $script:AppsCache) { $script:AppsCache.Count }
            elseif ($null -ne $script:AppCount -and [string]$script:AppCount -match '^\d+$') { [int]$script:AppCount }
            else { '-' }
    @{
        Users  = $(if ($null -ne $users) { $users.Count } else { '-' })
        Guests = $(if ($null -ne $users) { ($users | Where-Object { $_.UserType -eq 'Guest' } | Measure-Object).Count } else { '-' })
        Apps   = $apps
    }
}

function Get-EntraRunValue {
    param([object]$RunInfo, [string]$Name)
    if ($null -eq $RunInfo) { return $null }
    try { return (Get-EAField $RunInfo $Name) } catch { return $null }
}

function Format-EntraRunTime {
    param($Value)
    if ($null -eq $Value -or '' -eq [string]$Value) { return '' }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }
    if ($Value -is [datetime]) {
        $v = if ($Value.Kind -eq [System.DateTimeKind]::Local) { $Value.ToUniversalTime() } else { $Value }
        return $v.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    }
    return [string]$Value
}

function Format-EntraDuration {
    param([double]$Seconds)
    $ts = [timespan]::FromSeconds([math]::Max(0, $Seconds))
    if ($ts.TotalHours -ge 1) { return ('{0} h {1} min' -f [int][math]::Floor($ts.TotalHours), $ts.Minutes) }
    if ($ts.TotalMinutes -ge 1) { return ('{0} min {1} s' -f $ts.Minutes, $ts.Seconds) }
    return ('{0} s' -f [int][math]::Round($ts.TotalSeconds))
}

function Get-EntraRunDurationText {
    param([object]$RunInfo)
    $d = Get-EntraRunValue $RunInfo 'DurationSeconds'
    if ($null -ne $d -and '' -ne [string]$d) { try { return (Format-EntraDuration ([double]$d)) } catch { Write-Verbose "Unreadable DurationSeconds: $d" } }
    $start = Get-EntraRunValue $RunInfo 'StartedUtc'
    if (-not $start) { return '' }
    try {
        $s = if ($start -is [datetime]) { $start } else { [datetime]::Parse([string]$start, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) }
        if ($s.Kind -eq [System.DateTimeKind]::Local) { $s = $s.ToUniversalTime() }
        $end = Get-EntraRunValue $RunInfo 'FinishedUtc'
        if ($end) {
            $e = if ($end -is [datetime]) { $end } else { [datetime]::Parse([string]$end, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) }
            if ($e.Kind -eq [System.DateTimeKind]::Local) { $e = $e.ToUniversalTime() }
            return (Format-EntraDuration ($e - $s).TotalSeconds)
        }
        return ((Format-EntraDuration ([datetime]::UtcNow - $s).TotalSeconds) + ' (until the reports were written)')
    } catch { return '' }
}

function ConvertTo-EntraLicenseSkuHtml {
    param([object]$RunInfo)
    $skus = @($script:LicenseSkus | Where-Object { $null -ne $_ })
    if ($skus.Count -gt 0 -and -not ($skus[0] -is [string])) {
        $headers = @{
            SkuPartNumber = 'License (SKU)'; Sku = 'License (SKU)'; CapabilityStatus = 'Subscription status'; Status = 'Subscription status'
            ActiveUnits = 'Licenses bought'; EnabledUnits = 'Licenses bought'; ConsumedUnits = 'Licenses assigned'
            Provides = 'Gives the audit'; CountedAsLicensed = 'Counted by the audit'
        }
        $cols = New-Object System.Collections.Generic.List[string]
        foreach ($s in $skus) { foreach ($p in $s.PSObject.Properties) { if (-not $cols.Contains($p.Name)) { $cols.Add($p.Name) | Out-Null } } }
        $head = ($cols | ForEach-Object { $h = if ($headers.ContainsKey($_)) { $headers[$_] } else { $_ }; "<th style='text-align:left' title='$(HtmlAttrEncode $_)'>$(HtmlEncode $h)</th>" }) -join ''
        $cell = { param($v) if ($v -is [bool]) { if ($v) { 'Yes' } else { 'No' } } else { ConvertTo-EntraEvidenceCell $v } }
        $body = foreach ($s in $skus) {
            '<tr>' + (($cols | ForEach-Object { $p = $s.PSObject.Properties[$_]; "<td>$(HtmlEncode $(if ($p) { & $cell $p.Value } else { '' }))</td>" }) -join '') + '</tr>'
        }
        return "<h3>Licenses in the tenant ($($skus.Count))</h3><table>$("<thead><tr>$head</tr></thead>")<tbody>$($body -join '')</tbody></table>"
    }
    $names = @()
    if ($skus.Count -gt 0) { $names = @($skus | ForEach-Object { [string]$_ }) }
    else {
        $lic = Get-EntraRunValue $RunInfo 'Licenses'
        $ls = if ($lic) { Get-EntraRunValue $lic 'Skus' } else { $null }
        if ($ls) { $names = @($ls | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
    }
    if ($names.Count -gt 0) { return "<h3>Licenses in the tenant ($($names.Count))</h3><p>" + (($names | ForEach-Object { "<span class='chip mono'>$(HtmlEncode $_)</span>" }) -join '') + '</p>' }
    return ''
}

function ConvertTo-EntraRunDetailsHtml {
    param([object]$RunInfo, [string]$TenantName, [object]$Coverage)
    $chips = { param($list) $l = @($list | Where-Object { $_ } | ForEach-Object { [string]$_ }); if ($l.Count -eq 0) { "<span class='muted'>None</span>" } else { ($l | ForEach-Object { "<span class='chip mono'>$(HtmlEncode $_)</span>" }) -join '' } }
    $kv = New-Object System.Collections.Generic.List[string]
    $add = { param([string]$k, [string]$vHtml) if ($vHtml) { $kv.Add("<tr><th>$(HtmlEncode $k)</th><td>$vHtml</td></tr>") | Out-Null } }
    $val = { param($n) Get-EntraRunValue $RunInfo $n }
    $ver = & $val 'ToolVersion'; if (-not $ver) { $ver = $script:Version }
    & $add 'Tool version' (HtmlEncode $ver)
    $tn = & $val 'TenantName'; if (-not $tn) { $tn = $TenantName }
    & $add 'Tenant' (HtmlEncode $tn)
    $tid = & $val 'TenantId'; if ($tid) { & $add 'Tenant id' "<span class='mono'>$(HtmlEncode $tid)</span>" }
    $mode = & $val 'AuthMode'; if (-not $mode) { $mode = $script:AuthType }
    $modeText = switch ([string]$mode) { 'AppOnly' { 'App-only (an app with a certificate, no person signed in)' } 'Delegated' { 'Delegated (a person signed in)' } default { [string]$mode } }
    & $add 'Sign-in' (HtmlEncode $modeText)
    $acct = & $val 'Account'; if ($acct) { & $add 'Account / app' "<span class='mono'>$(HtmlEncode $acct)</span>" }
    $st = & $val 'StartedUtc'; if ($st) { & $add 'Started' (HtmlEncode (Format-EntraRunTime $st)) }
    $fi = & $val 'FinishedUtc'; if ($fi) { & $add 'Finished' (HtmlEncode (Format-EntraRunTime $fi)) }
    $dur = Get-EntraRunDurationText $RunInfo; if ($dur) { & $add 'Duration' (HtmlEncode $dur) }
    if ($Coverage) {
        $selIds = @($Coverage.Rows | Where-Object { $_.Selected } | ForEach-Object { $_.CheckId })
        & $add 'Checks selected' ("<b>$($selIds.Count)</b> of $($Coverage.Total)<br>" + (& $chips $selIds))
    }
    $exc = & $val 'ExcludedChecks'
    if ($null -ne $exc) { & $add 'Checks excluded' (& $chips $exc) }
    $settings = & $val 'Settings'
    if ($settings -is [System.Collections.IDictionary] -and $settings.Count -gt 0) {
        $srows = foreach ($k in $settings.Keys) { "<span class='chip'>$(HtmlEncode ([string]$k)) = <span class='mono'>$(HtmlEncode (ConvertTo-EntraEvidenceCell $settings[$k]))</span></span>" }
        & $add 'Settings used' ($srows -join '')
    } elseif ($settings) {
        $srows = foreach ($p in $settings.PSObject.Properties) { "<span class='chip'>$(HtmlEncode $p.Name) = <span class='mono'>$(HtmlEncode (ConvertTo-EntraEvidenceCell $p.Value))</span></span>" }
        & $add 'Settings used' ($srows -join '')
    }
    $scopes = & $val 'GrantedScopes'
    if ($null -ne $scopes) {
        $sl = @($scopes | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        & $add 'Permissions the sign-in had' ("<b>$($sl.Count)</b><br>" + (& $chips $sl))
    }
    & $add 'Licenses' (HtmlEncode (Get-EntraLicenseText $RunInfo))
    $ps = & $val 'PowerShellVersion'; if (-not $ps) { $ps = [string]$PSVersionTable.PSVersion }
    & $add 'PowerShell' (HtmlEncode $ps)
    $gv = & $val 'GraphModuleVersion'; if ($gv) { & $add 'Microsoft Graph SDK' (HtmlEncode $gv) }
    $log = & $val 'LogFile'
    if ($log) {
        $lh = '../' + (([string]$log) -replace '\\', '/')
        & $add 'Run log' "<a href='$(HtmlAttrEncode (Resolve-SourceHref $lh))'>$(HtmlEncode $log)</a>"
    }
    $partial = if ($null -eq $RunInfo -or -not (& $val 'StartedUtc')) { "<p style='margin-top:8px'><small>Some run details (start time, account, permissions) were not recorded for this report.</small></p>" } else { '' }
    "<table class='kv'><tbody>$($kv -join '')</tbody></table>$partial"
}

function Get-EntraDatasetIndex {
    param([object[]]$Items)
    if ($null -eq $Items) { $Items = Get-EntraFindingList }
    $byName = [ordered]@{}
    foreach ($d in $script:RawDatasets) {
        if ($null -eq $d) { continue }
        $prop = { param($n) if ($d.PSObject.Properties[$n]) { $d.$n } else { $null } }
        $html = & $prop 'HtmlHref'; $csv = & $prop 'CsvHref'; $txt = & $prop 'TxtHref'
        $src = & $prop 'SourceHref'; if (-not $src) { $src = if ($html) { $html } else { $csv } }
        $cid = [string](& $prop 'CheckId')
        $ct = [string](& $prop 'CheckTitle')
        if ($byName.Contains([string]$d.BaseName)) { $byName.Remove([string]$d.BaseName) }
        $byName[[string]$d.BaseName] = [pscustomobject]@{
            BaseName = [string]$d.BaseName; Title = [string]$d.Title; Rows = [int]$d.Rows
            CheckId = $cid; CheckTitle = $ct
            Notes = @(& $prop 'Notes' | Where-Object { $_ })
            HtmlHref = $html; CsvHref = $csv; TxtHref = $txt; SourceHref = $src
            Errors = @(& $prop 'Errors' | Where-Object { $_ })
            UsedBy = (New-Object System.Collections.Generic.List[object])
        }
    }
    $byHref = @{}
    foreach ($e in $byName.Values) { foreach ($h in @($e.HtmlHref, $e.CsvHref, $e.SourceHref)) { if ($h) { $byHref[[string]$h] = $e } } }
    foreach ($f in $Items) {
        $s = [string]$f.SourceFile
        if ($s -and $byHref.ContainsKey($s)) { $byHref[$s].UsedBy.Add($f) | Out-Null }
    }
    foreach ($e in $byName.Values) {
        if (-not $e.CheckId -and $e.UsedBy.Count -gt 0) {
            $e.CheckId = [string](@($e.UsedBy | Group-Object { [string]$_.CheckId } | Sort-Object Count -Descending)[0].Name)
        }
        if ($e.CheckId -and -not $e.CheckTitle -and $script:Registry -and $script:Registry.Contains($e.CheckId)) { $e.CheckTitle = [string]$script:Registry[$e.CheckId].Title }
    }
    foreach ($e in $byName.Values) { $e }
}

function Write-EntraDatasetUsage {
    param([object[]]$Datasets)
    if (-not $script:RawDir) { return }
    foreach ($e in $Datasets) {
        if (-not $e.HtmlHref) { continue }
        $file = Join-Path $script:RawDir ($e.BaseName + '.html')
        try {
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
            $html = Get-Content -LiteralPath $file -Raw -Encoding UTF8 -ErrorAction Stop
            if ($html.IndexOf('<!--EA-USEDBY-->') -lt 0) { continue }
            $n = $e.UsedBy.Count
            $block = if ($n -gt 0) {
                $li = foreach ($f in @($e.UsedBy | Select-Object -First 50)) {
                    $sev = Normalize-Severity $f.Severity
                    $gap = if (Test-EntraCoverageGap $f) { " <span class='badge sev-Information'>Not assessed</span>" } else { '' }
                    "<li><span class='badge sev-$sev'>$sev</span><a href='../../HTML Reports/EntraAudit-Results.html#$(HtmlAttrEncode (New-FindingAnchor $f))'>$(HtmlEncode $f.Title)</a>$gap</li>"
                }
                $more = if ($n -gt 50) { "<li>... and $($n - 50) more in the <a href='../../HTML Reports/EntraAudit-Results.html'>audit results</a>.</li>" } else { '' }
                # Long lists start collapsed so the table stays near the top of the page.
                "<details class='raw-used'$(if ($n -le 8) { ' open' })><summary>Findings that use this dataset ($n)</summary><ul>$($li -join '')$more</ul></details>"
            } else {
                "<div class='raw-used muted'>No finding points to this dataset. It is background data saved by the check.</div>"
            }
            Set-Content -LiteralPath $file -Value $html.Replace('<!--EA-USEDBY-->', $block) -Encoding UTF8 -NoNewline -ErrorAction Stop
        } catch {
            Write-Warn2 "Could not add the 'used by findings' list to '$($e.BaseName).html': $($_.Exception.Message)"
        }
    }
}

function Export-EntraAuditData {
    param([string]$RunRoot, [string]$TenantId, [pscustomobject]$Score, [object[]]$Items, [object]$RunInfo = $script:RunInfo)
    if ($null -eq $Items) { $Items = Get-EntraFindingList }
    if ($null -eq $Score) { $Score = Get-EntraRiskScore $Items }
    $rows = foreach ($f in $Items) {
        $population = Get-EntraFindingPopulation $f
        [pscustomobject][ordered]@{
            FindingId         = (New-FindingKey -TenantId $TenantId -Finding $f)
            Severity          = $f.Severity
            Category          = $f.Category
            CheckId           = $f.CheckId
            RuleId            = $f.RuleId
            Rule              = (Get-FindingRule $f)
            IssueKey          = (Get-EntraIssueKey $f).Key
            ObjectType        = $f.ObjectType
            ObjectId          = $f.ObjectId
            AffectedObjectIds = @($population.Ids)
            AffectedObjectType = $population.ObjectType
            AffectedCount     = $population.AffectedCount
            AssessedCount     = $population.AssessedCount
            UnknownCount      = $population.UnknownCount
            PopulationLabel   = $population.Label
            ScoringCount      = $population.ScoringCount
            ScoringBasis      = $population.ScoringBasis
            PopulationIdsComplete = $population.IdsComplete
            VerificationType  = [string](Get-EAField $f 'VerificationType')
            VerificationSteps = [string](Get-EAField $f 'VerificationSteps')
            Title             = $f.Title
            AffectedPrincipal = $f.AffectedPrincipal
            Evidence          = $f.Evidence
            WhyItMatters      = $f.WhyItMatters
            RecommendedAction = $f.RecommendedAction
            DocumentationUrl  = $f.DocumentationUrl
            SourceFile        = $f.SourceFile
            CoverageGap       = [bool](Test-EntraCoverageGap $f)
            ChangeStatus      = [string](Get-EAField $f 'ChangeStatus')
            AcceptedRisk      = [bool](Get-EAField $f 'AcceptedRisk')
            ExceptionReason   = [string](Get-EAField $f 'ExceptionReason')
            ExceptionOwner    = [string](Get-EAField $f 'ExceptionOwner')
            ExceptionExpiresUtc = [string](Get-EAField $f 'ExceptionExpiresUtc')
        }
    }
    $rows = @($rows)
    # Both files are attempted; a failure of either is collected and THROWN at the end, so
    # the caller (Invoke-EntraAudit's $writeOutput) lists it, does not print "Audit complete"
    # and exits 1 - automation must not trust a Findings.json that was never written.
    $exportFailures = [System.Collections.Generic.List[string]]::new()
    try {
        # utf8BOM so Excel decodes non-ASCII display names / UPNs correctly.
        $csvRows = foreach ($row in $rows) {
            $flat = [ordered]@{}
            foreach ($p in $row.PSObject.Properties) { $flat[$p.Name] = if ($p.Value -is [array]) { $p.Value -join '; ' } else { $p.Value } }
            [pscustomobject]$flat
        }
        ConvertTo-SafeCsvRows $csvRows | Export-Csv -LiteralPath (Join-Path $RunRoot 'Findings.csv') -NoTypeInformation -Encoding utf8BOM -ErrorAction Stop
    } catch { $exportFailures.Add("Findings.csv - $($_.Exception.Message)") }

    try {
        $cov = if ($Score.PSObject.Properties['Coverage'] -and $Score.Coverage) { $Score.Coverage } else { Get-EntraRunCoverage -RunInfo $RunInfo }
        $datasets = @(Get-EntraDatasetIndex -Items $Items)
        $idByAnchor = @{}
        for ($i = 0; $i -lt $rows.Count; $i++) { $idByAnchor[(New-FindingAnchor $Items[$i])] = $rows[$i].FindingId }
        $toRunRel = { param($h) if ($h) { ([string]$h) -replace '^\.\./', '' } else { $null } }
        $dsJson = foreach ($d in $datasets) {
            [ordered]@{
                BaseName = $d.BaseName; Title = $d.Title; CheckId = $(if ($d.CheckId) { $d.CheckId } else { $null }); Rows = $d.Rows
                Notes = @($d.Notes); Errors = @($d.Errors)
                Files = [ordered]@{ Html = (& $toRunRel $d.HtmlHref); Csv = (& $toRunRel $d.CsvHref); Txt = (& $toRunRel $d.TxtHref) }
                UsedByFindingIds = @($d.UsedBy | ForEach-Object { $idByAnchor[(New-FindingAnchor $_)] } | Where-Object { $_ })
            }
        }
        $checks = foreach ($r in $cov.Rows) {
            [ordered]@{
                CheckId = $r.CheckId; Title = $r.Title; Selected = $r.Selected
                Status = $(if ($r.Group -eq 'notrun') { 'NotRun' } else { $r.Status }); Result = $r.Label; Reason = $r.Reason
                ErrorMessage = $r.ErrorMessage; MissingScopes = @($r.MissingScopes)
                Count = $r.Count; InfoCount = $r.InfoCount; CoverageCount = $r.CoverageCount; Partial = $r.Partial
                DurationSeconds = $r.DurationSeconds
                Datasets = @($datasets | Where-Object { $_.CheckId -eq $r.CheckId } | ForEach-Object { $_.BaseName })
            }
        }
        $findingsJson = for ($i = 0; $i -lt $rows.Count; $i++) {
            $o = [ordered]@{}
            foreach ($p in $rows[$i].PSObject.Properties) { $o[$p.Name] = $p.Value }
            $o['ReportLink'] = 'HTML Reports/EntraAudit-Results.html#' + (New-FindingAnchor $Items[$i])
            $o
        }
        $doc = [ordered]@{
            SchemaVersion = 2
            GeneratedUtc  = [datetime]::UtcNow.ToString('o')
            RunInfo       = $RunInfo
            Score         = [ordered]@{
                Score = $Score.Score; Band = $Score.Band; ScoreBand = $Score.ScoreBand
                ScoringVersion = $Score.ScoringVersion
                RemediationUrgency = (Get-EntraRemediationUrgency $Score)
                OpenRemediationUrgency = $Score.OpenRemediationUrgency
                HighestConfirmedSeverity = $Score.HighestConfirmedSeverity
                ConfirmedScore = $Score.ConfirmedScore; NotAssessedPoints = $Score.NotAssessedPoints
                CoverageComplete = $Score.CoverageComplete
                Counts = [ordered]@{ Critical = $Score.Critical; High = $Score.High; Medium = $Score.Medium; Low = $Score.Low; Information = $Score.Information }
                ConfirmedCounts = $Score.ConfirmedCounts; NotAssessedCounts = $Score.NotAssessedCounts
                Coverage = [ordered]@{ Known = $cov.Known; Complete = $cov.Complete; Total = $cov.Total; Selected = $cov.Selected; Evaluated = $cov.Evaluated; FullyEvaluated = $cov.FullyEvaluated; Clean = $cov.Clean; WithFindings = $cov.WithFindings; Incomplete = $cov.Incomplete; Skipped = $cov.Skipped; Errored = $cov.Errored; NotRun = $cov.NotRun }
                Drivers = @($Score.Drivers | ForEach-Object { [ordered]@{ IssueKey = $_.Key; Severity = $_.Severity; CheckId = $_.CheckId; Rule = $_.Rule; Title = $_.Title; DisplayTitle = $(if ($_.Count -eq 1 -and $_.FirstTitle) { [string]$_.FirstTitle } else { $_.Title }); Count = $_.Count; AffectedCount=$_.AffectedCount; AssessedCount=$_.AssessedCount; UnknownCount=$_.UnknownCount; PopulationLabel=$_.PopulationLabel; ScoringCount=$_.ScoringCount; ScoringBasis=$_.ScoringBasis; Points = $_.Points; Share = $_.Share; CoverageGap = $_.CoverageGap; AcceptedRisk=$_.AcceptedRisk; AcceptedFindings=$_.AcceptedFindings; ExceptionExpiresUtc=$_.ExceptionExpiresUtc; DocumentationUrl = $(if ($_.DocumentationUrl) { $_.DocumentationUrl } else { $null }) } })
            }
            CheckStatus   = @($checks)
            Datasets      = @($dsJson)
            Findings      = @($findingsJson)
        }
        ConvertTo-Json -InputObject $doc -Depth 8 | Set-Content -LiteralPath (Join-Path $RunRoot 'Findings.json') -Encoding UTF8 -ErrorAction Stop
    } catch { $exportFailures.Add("Findings.json - $($_.Exception.Message)") }
    if ($exportFailures.Count -gt 0) { throw ($exportFailures -join '; ') }
}
