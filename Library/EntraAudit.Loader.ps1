<#
Definition-only bootstrap. Dot-source in the runner or offline tests; loading does
not authenticate, install modules, collect evidence, or execute audit checks.
The manifest is the shared source for the CLI registry and GUI check list.
#>
$script:EntraAuditRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $script:EntraAuditRoot 'EntraAudit.Checks.psd1'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Missing $manifestPath. Copy the whole EntraAudit folder, including Checks and Library."
}
$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
$libraryFiles = @('EntraAudit.Common.ps1','EntraAudit.Graph.ps1','EntraAudit.Governance.ps1','EntraAudit.Applications.ps1','EntraAudit.FollowUp.ps1','EntraAudit.Report.ps1')
$ids = @{}; $switches = @{}; $functions = @{}
foreach ($check in $manifest.Checks) {
    if (-not $check.Id -or -not $check.Switch -or -not $check.Func -or
        $check.File -notmatch '^Invoke-[A-Za-z0-9]+Check\.ps1$') {
        throw 'Invalid check manifest entry.'
    }
    if ($ids.ContainsKey($check.Id) -or $switches.ContainsKey($check.Switch) -or $functions.ContainsKey($check.Func)) {
        throw "Duplicate check ID, switch or function: $($check.Id)"
    }
    $ids[$check.Id]=$true; $switches[$check.Switch]=$true; $functions[$check.Func]=$true
}
# Validate the entire package before loading any definitions or making a connection.
foreach ($relative in @($libraryFiles | ForEach-Object { 'Library/' + $_ }) + @($manifest.Checks | ForEach-Object { 'Checks/' + $_.File })) {
    if (-not (Test-Path -LiteralPath (Join-Path $script:EntraAuditRoot $relative) -PathType Leaf)) {
        throw "Required audit file is missing: $relative. Copy the whole EntraAudit folder, including Checks and Library."
    }
}
foreach ($file in $libraryFiles) { . (Join-Path $PSScriptRoot $file) }
$script:Registry = [ordered]@{}
$script:CheckAliases = @{}
foreach ($check in $manifest.Checks) {
    $script:Registry[$check.Id] = $check
    $script:CheckAliases[$check.Switch] = $check.Id
    . (Join-Path (Join-Path $script:EntraAuditRoot 'Checks') $check.File)
    if (-not (Get-Command -Name $check.Func -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "Check function missing: $($check.Func) in $($check.File)"
    }
}
