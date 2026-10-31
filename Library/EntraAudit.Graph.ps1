<#
EntraAudit shared definitions. Dot-source from the runner so script-scoped state is shared.
Do not execute check files with &: that creates a different script scope.
#>

function Assert-EAGraphReadUri {
    param([Parameter(Mandatory)][string]$Uri)
    $absolute = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$absolute) -or
        -not [string]::Equals($absolute.Scheme, 'https', [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($absolute.GetLeftPart([UriPartial]::Authority), 'https://graph.microsoft.com', [System.StringComparison]::OrdinalIgnoreCase) -or
        $absolute.AbsolutePath -notmatch '^/(v1\.0|beta)(?:/|$)' -or
        $absolute.Fragment) {
        throw "Refusing unsafe Microsoft Graph pagination URI: $Uri"
    }
    return $absolute.AbsoluteUri
}

function Get-EAHttpStatus {
    param($ErrorRecord)
    $code = 0
    try { $code = [int]$ErrorRecord.Exception.Response.StatusCode } catch { $code = 0 }
    return $code
}

function Test-EAAccessDenied {
    param($ErrorRecord)
    if (-not $ErrorRecord) { return $false }
    if ((Get-EAHttpStatus $ErrorRecord) -in 401, 403) { return $true }
    $details = if ($ErrorRecord.ErrorDetails) { [string]$ErrorRecord.ErrorDetails.Message } else { '' }
    $text = '{0} {1} {2}' -f [string]$ErrorRecord.Exception.Message, $details, [string]$ErrorRecord.FullyQualifiedErrorId
    return ($text -match '(?i)Authorization_RequestDenied|Insufficient privileges|does not have the required|Forbidden|Unauthorized')
}

function Test-EAPageSizeRejection {
    param($ErrorRecord)
    if (-not $ErrorRecord) { return $false }
    if (Test-EAAccessDenied $ErrorRecord) { return $false }
    $status = Get-EAHttpStatus $ErrorRecord
    if ($status -eq 400) { return $true }
    if ($status -gt 0) { return $false }
    $details = if ($ErrorRecord.ErrorDetails) { [string]$ErrorRecord.ErrorDetails.Message } else { '' }
    $text = '{0} {1} {2}' -f [string]$ErrorRecord.Exception.Message, $details, [string]$ErrorRecord.FullyQualifiedErrorId
    return ($text -match '(?i)\$top|Top query|PageSize|page size|Request_UnsupportedQuery|\bBadRequest\b')
}

function Invoke-EAListAll {
    param(
        [Parameter(Mandatory)][string]$Command,
        [hashtable]$Parameters = @{},
        [int]$PageSize = 999
    )
    $p = @{}
    foreach ($k in $Parameters.Keys) { $p[$k] = $Parameters[$k] }
    $p['All'] = $true
    $p['ErrorAction'] = 'Stop'
    if ($null -eq $script:EAPageSizeRejected) { $script:EAPageSizeRejected = @{} }
    if ($PageSize -gt 0 -and -not $script:EAPageSizeRejected.ContainsKey($Command)) {
        $paged = @{}
        foreach ($k in $p.Keys) { $paged[$k] = $p[$k] }
        $paged['PageSize'] = $PageSize
        try {
            $items = @(& $Command @paged)
            return $items
        } catch {
            if (-not (Test-EAPageSizeRejection $_)) { throw }
            $firstError = $_.Exception.Message
        }
        Write-Warn2 "  $Command failed with a query error at page size $PageSize ($firstError) - retrying once with the default page size, in case the large page caused it."
        $items = @(& $Command @p)
        # The default page size worked, so the page size was the problem: remember it, so a
        # per-object call (e.g. one per user) does not pay twice every time.
        $script:EAPageSizeRejected[$Command] = $true
        Write-Info "  $Command worked with the default page size, which is used for this command for the rest of the run."
        return $items
    }
    $items = @(& $Command @p)
    return $items
}

function Get-EAUserScopeIds {
    param([string]$UserId)
    if (-not $script:UserScopeCache) { $script:UserScopeCache = @{} }
    if ($script:UserScopeCache.ContainsKey($UserId)) { return $script:UserScopeCache[$UserId] }
    $gids = New-Object System.Collections.Generic.HashSet[string]
    $rtids = New-Object System.Collections.Generic.HashSet[string]
    # Surface fetch failures and do NOT cache them - a silently-cached empty scope would
    # make every later CA-applicability answer for this user wrong for the whole run.
    $ok = $true
    try {
        foreach ($m in @(Invoke-EAListAll -Command 'Get-MgUserTransitiveMemberOf' -Parameters @{ UserId = $UserId })) {
            $t = [string](Get-Ap $m '@odata.type')
            if ($t -eq '#microsoft.graph.group') { [void]$gids.Add($m.Id) }
            elseif ($t -eq '#microsoft.graph.directoryRole') { $rt = Get-Ap $m 'roleTemplateId'; if ($rt) { [void]$rtids.Add([string]$rt) } }
        }
    } catch {
        $ok = $false
        Write-Warn2 "  Could not resolve memberships for user $UserId ($($_.Exception.Message)) - CA applicability may be incomplete."
    }
    $r = [pscustomobject]@{ Groups = $gids; Roles = $rtids; Known = $ok }
    if ($ok) { $script:UserScopeCache[$UserId] = $r }
    return $r
}

function Assert-GraphModuleVersions {
    $installed = foreach ($m in $script:RequiredModules) {
        Get-Module -ListAvailable -Name $m | Sort-Object Version -Descending | Select-Object -First 1 Name, Version
    }
    $installed = @($installed | Where-Object { $_ })
    if ($installed.Count -eq 0) { return }
    $majors = @($installed | Group-Object { $_.Version.Major })
    if ($majors.Count -gt 1) {
        $detail = ($installed | ForEach-Object { "$($_.Name)=$($_.Version)" }) -join ', '
        throw "Microsoft.Graph modules have mixed major versions: $detail. Align them to one major version (uninstall the older majors) before running the audit."
    }
}

function Install-EntraModules {
    Write-Info "Installing Microsoft Graph SDK sub-modules (CurrentUser scope)..."
    $prevPolicy = $null   # restore PSGallery trust afterwards - do not leave it permanently trusted
    try {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }
        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
            $prevPolicy = $repo.InstallationPolicy
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        foreach ($m in $script:RequiredModules) {
            # Pin to the supported major so a fresh -installdeps cannot mix majors
            # (Assert-GraphModuleVersions would otherwise fail right after installing).
            $existing = Get-Module -ListAvailable -Name $m | Sort-Object Version -Descending | Select-Object -First 1
            if ($existing -and $existing.Version.Major -eq $script:GraphModuleMajor) { Write-Good "$m already installed ($($existing.Version))."; continue }
            Write-Info "Installing $m ..."
            Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -Repository PSGallery `
                -MinimumVersion "$($script:GraphModuleMajor).0.0" -MaximumVersion "$($script:GraphModuleMajor).999.999" -ErrorAction Stop
            Write-Good "$m installed."
        }
        Assert-GraphModuleVersions
    } catch {
        throw "Module installation failed: $($_.Exception.Message)"
    } finally {
        # Restore the PSGallery installation policy we changed, so running the audit does not
        # silently leave PSGallery trusted for the user's whole session/profile.
        if ($prevPolicy) {
            try { Set-PSRepository -Name PSGallery -InstallationPolicy $prevPolicy -ErrorAction Stop }
            catch { Write-Warn2 "Could not restore the PSGallery installation policy to '$prevPolicy' ($($_.Exception.Message)) - PSGallery is still Trusted; reset it with: Set-PSRepository -Name PSGallery -InstallationPolicy $prevPolicy" }
        }
    }
}

function Add-EAOfflineModulesPath {
    if ($ModulesPath -and (Test-Path $ModulesPath)) {
        $resolved = (Resolve-Path $ModulesPath).Path
        if (-not (($env:PSModulePath -split [IO.Path]::PathSeparator) -contains $resolved)) {
            $env:PSModulePath = $resolved + [IO.Path]::PathSeparator + $env:PSModulePath
            Write-Info "Prepended offline modules path: $ModulesPath"
        }
    }
}

function Import-EntraModules {
    Add-EAOfflineModulesPath
    $missing = @()
    foreach ($m in $script:RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $m)) { $missing += $m; continue }
        try { Import-Module $m -ErrorAction Stop }
        catch { $missing += $m; Write-Warn2 "Module $m is installed but failed to import: $($_.Exception.Message)" }
    }
    if ($missing.Count -gt 0) {
        throw "Required module(s) not available: $($missing -join ', '). Run with -installdeps (online) or see PREREQUISITE.md for offline install."
    }
    # Warn (do not abort) on mixed Graph module majors - the audit may still work, but this is
    # the most common cause of confusing downstream SDK errors.
    try { Assert-GraphModuleVersions } catch { Write-Warn2 $_.Exception.Message }
}

function Connect-EntraAuditGraph {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    # Half an app-only pair must not silently fall back to an interactive prompt -
    # that surprises unattended runs and signs in as the wrong identity.
    if (([bool]$ClientId) -ne ([bool]$CertificateThumbprint)) {
        throw 'App-only authentication requires BOTH -ClientId and -CertificateThumbprint; only one was supplied. Provide both for unattended runs, or neither for interactive sign-in (use -DelegatedClientId to sign in interactively through your own app registration).'
    }
    if ($DelegatedClientId) {
        if ($ClientId -or $CertificateThumbprint) {
            throw 'Use EITHER -DelegatedClientId (interactive sign-in through your own read-only app) OR -ClientId with -CertificateThumbprint (unattended app-only), not both.'
        }
        $parsedClientId = [guid]::Empty
        if (-not [guid]::TryParse($DelegatedClientId, [ref]$parsedClientId)) {
            throw "-DelegatedClientId must be the Application (client) ID of your app registration - a GUID. Got: '$DelegatedClientId'."
        }
        # Without a tenant, Connect-MgGraph signs in on the shared multi-tenant endpoint, and
        # Microsoft refuses that for a single-tenant app (the default for a new registration)
        # with AADSTS50194 - and the device-code retry below fails the same way.
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            throw '-DelegatedClientId also needs -TenantId <your tenant ID or domain, e.g. contoso.onmicrosoft.com>, because app registrations are single-tenant by default and Microsoft refuses their sign-in without a tenant.'
        }
    }
    $appOnly = ($ClientId -and $CertificateThumbprint)
    if ($appOnly) {
        Write-Info "Connecting to Microsoft Graph (app-only, certificate)..."
        $cp = @{ ClientId = $ClientId; CertificateThumbprint = $CertificateThumbprint; NoWelcome = $true }
        if ($TenantId) { $cp.TenantId = $TenantId }
        Connect-MgGraph @cp -ErrorAction Stop
        $script:GraphConnectedByScript = $true
        $script:AuthType = 'AppOnly'
    } else {
        $viaApp = if ($DelegatedClientId) { "app $DelegatedClientId" } else { "the shared 'Microsoft Graph Command Line Tools' app" }
        Write-Info "Connecting to Microsoft Graph (interactive, read-only scopes, via $viaApp)..."
        $cp = @{ Scopes = $script:ScopesRO; NoWelcome = $true }
        if ($TenantId)      { $cp.TenantId = $TenantId }
        if ($UseDeviceCode) { $cp.UseDeviceCode = $true }
        # Binding consent to a dedicated read-only app keeps the token free of write scopes
        # the admin once consented to the shared SDK app for unrelated work.
        if ($DelegatedClientId) { $cp.ClientId = $DelegatedClientId }
        try {
            Connect-MgGraph @cp -ErrorAction Stop
        } catch {
            # WAM/window-handle failures (VS Code terminal, SSH, elevated) -> device code
            Write-Warn2 "Interactive sign-in failed ($($_.Exception.Message)). Retrying with device code..."
            $cp.UseDeviceCode = $true
            Connect-MgGraph @cp -ErrorAction Stop
        }
        $script:GraphConnectedByScript = $true
        $script:AuthType = 'Delegated'
    }

    $ctx = Get-MgContext
    if (-not $ctx) { throw 'Not connected to Microsoft Graph.' }

    # --- READ-ONLY SELF-CHECK: refuse to run unless every granted scope is read-only ---
    # Delegated: fail-closed allowlist (Test-EAReadOnlyScope) - a scope must be recognisably
    # read-only; a deny list missed real write-capable scopes (User.DeleteRestore.All,
    # User.EnableDisableAccount.All, User.RevokeSessions.All, Sites.Selected, Device.Command).
    # App-only: Get-MgContext.Scopes is sparse, so only the write-token filter runs here and
    # Assert-AppOnlyReadOnly below enforces the exact permission allowlist.
    $grantedScopes = @($ctx.Scopes | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    if ($appOnly) {
        $bad = @($grantedScopes | Where-Object { $_ -match $script:WriteScopePattern })
    } else {
        if ($grantedScopes.Count -eq 0) {
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { Write-Warn2 "Disconnect after the refused sign-in failed: $($_.Exception.Message)" }
            throw 'Refusing to run: the sign-in returned no permission (scope) list, so the read-only guarantee cannot be verified.'
        }
        $bad = @($grantedScopes | Where-Object { -not (Test-EAReadOnlyScope $_) })
    }
    if ($bad.Count -gt 0) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { Write-Warn2 "Disconnect after the refused sign-in failed: $($_.Exception.Message)" }
        if ($appOnly) {
            throw "Refusing to run: the audit app holds permission(s) that are not read-only -> $($bad -join ', '). Remove them from the app registration (Entra admin center > App registrations > <app> > API permissions) and run again."
        }
        $consentApp = if ($DelegatedClientId) { "your app registration $DelegatedClientId" } else { "the shared 'Microsoft Graph Command Line Tools' app" }
        $fix = if ($DelegatedClientId) {
            "Remove those permissions from that app (Entra admin center > App registrations > <app> > API permissions, and revoke any consent under Enterprise applications > <app> > Permissions), then run again."
        } else {
            "Either revoke them (Entra admin center > Enterprise applications > 'Microsoft Graph Command Line Tools' > Permissions, admin consent and user consent tabs), or register a dedicated read-only app (public client, redirect URI http://localhost, only the scopes in PREREQUISITE.md) and run with -DelegatedClientId <its application id>."
        }
        throw ("Refusing to run: this sign-in holds permission(s) that are not read-only -> {0}. This audit only runs with read-only permissions. Signing in again with fewer scopes does not help, because Microsoft Graph keeps every permission ever consented to {1}. {2}" -f ($bad -join ', '), $consentApp, $fix)
    }

    # App-only: Get-MgContext.Scopes is sparse, so the scope regex above is not a
    # reliable read-only guarantee. Inspect the running app's actual app-role assignments
    # across ALL resource APIs and FAIL CLOSED if any granted permission is write-capable.
    if ($appOnly) {
        try { Assert-AppOnlyReadOnly -ClientId $ClientId }
        catch {
            $refusal = $_
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { Write-Warn2 "Disconnect after the refused sign-in failed: $($_.Exception.Message)" }
            throw $refusal
        }
    }

    Write-Good ("Connected. Auth: {0} | Tenant: {1} | Account: {2}" -f $script:AuthType, $ctx.TenantId, ($ctx.Account ?? $ctx.AppName))
    return $ctx
}

function Assert-AppOnlyReadOnly {
    param([Parameter(Mandatory)][string]$ClientId)
    $self = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ConsistencyLevel eventual -CountVariable c -Property 'id,appId,displayName' -ErrorAction Stop | Select-Object -First 1
    if (-not $self) { throw "Cannot verify app-only read-only posture: no service principal found for ClientId $ClientId." }
    $assignments = @(Invoke-EAListAll -Command 'Get-MgServicePrincipalAppRoleAssignment' -Parameters @{ ServicePrincipalId = $self.Id })

    # An app with NO application permissions would pass the allowlist vacuously and then skip
    # nearly every check behind a green "verified" message. Refuse it with the real fix.
    if ($assignments.Count -eq 0) {
        throw ("Refusing app-only run: the audit app '{0}' ({1}) has NO Microsoft Graph application permissions granted, so almost every check would be skipped. Grant the read-only application permissions listed in PREREQUISITE.md, section B.1 (step 2) to the app registration and admin-consent them, then run again." -f $self.DisplayName, $ClientId)
    }

    # Resolve only the resource service principals actually referenced by the assignments.
    $roleMapByResourceId = @{}
    $resourceAppIdById = @{}
    $resourceReadError = @{}
    foreach ($rid in (@($assignments | ForEach-Object { $_.ResourceId }) | Where-Object { $_ } | Select-Object -Unique)) {
        try {
            $rsp = Get-MgServicePrincipal -ServicePrincipalId $rid -Property 'id,appId,appRoles' -ErrorAction Stop
            $m = @{}; foreach ($role in @($rsp.AppRoles)) { if ($role.Id) { $m[[string]$role.Id] = $role.Value } }
            $roleMapByResourceId[$rid] = $m
            $resourceAppIdById[$rid] = [string]$rsp.AppId
        } catch {
            # Unreadable resource -> its assignments stay unresolved below and the run fails closed.
            $roleMapByResourceId[$rid] = @{}; $resourceAppIdById[$rid] = $null
            $resourceReadError[$rid] = $_.Exception.Message
        }
    }

    $unapproved = @(); $unresolved = @(); $resolvedValues = @()
    foreach ($a in $assignments) {
        $value = $null
        if ($roleMapByResourceId.ContainsKey($a.ResourceId)) { $value = $roleMapByResourceId[$a.ResourceId][[string]$a.AppRoleId] }
        if (-not $value) {   # cannot verify -> unsafe
            $why = if ($resourceReadError.ContainsKey($a.ResourceId)) { " [read error: $($resourceReadError[$a.ResourceId])]" } else { '' }
            $unresolved += ("{0}:appRole {1}{2}" -f $a.ResourceDisplayName, $a.AppRoleId, $why)
            continue
        }
        if ($resourceAppIdById[$a.ResourceId] -ne '00000003-0000-0000-c000-000000000000') {
            $unapproved += ("{0}:{1} (non-Microsoft-Graph resource)" -f $a.ResourceDisplayName, $value)
            continue
        }
        $resolvedValues += [string]$value
        if (-not (Test-AppRoleIsApprovedForAudit -Value $value)) { $unapproved += ("{0}:{1}" -f $a.ResourceDisplayName, $value) }
    }
    if ($unapproved.Count -gt 0 -or $unresolved.Count -gt 0) {
        # Exact-allowlist, fail-closed: refuse anything not on the documented audit list -
        # including broad-but-read permissions (e.g. Mail.Read) that over-expose data, and
        # any unresolvable/custom app role. Distinguish the two so operators can tell which.
        $msg = "Refusing app-only run. Unapproved application permission detected - the audit app must contain ONLY the documented read-only audit permissions."
        if ($unapproved.Count -gt 0) { $msg += " Unapproved (write-capable or excessive read): $($unapproved -join ', ')." }
        if ($unresolved.Count -gt 0) { $msg += " Could NOT verify (resource app-role not readable) - treated as unsafe: $($unresolved -join ', ')." }
        throw $msg
    }
    # Retain the values we just resolved so every later check can perform the same
    # permission gate in app-only mode. Without this, Test-MgScope unconditionally passed
    # and missing application permissions surfaced only as inconsistent 403s mid-check.
    $script:AppOnlyGrantedPermissions = @($resolvedValues | Sort-Object -Unique)
    Write-Good ("App-only read-only verified: {0} application permission(s) granted, all on the approved audit allowlist." -f $assignments.Count)
    # Warn early when the core audit permissions are missing: the checks that need them will
    # be skipped (Invoke-EntraAudit also lists the affected selected checks).
    # Same rule as the real gate (Get-EAMissingScope), so Directory.Read.All counts as covering
    # Application.Read.All here too and the warning never names a permission no check needs.
    $core = @('Directory.Read.All','Policy.Read.All','AuditLog.Read.All','RoleManagement.Read.Directory','Application.Read.All')
    $missingCore = @(Get-EAMissingScope -Required $core -Granted $script:AppOnlyGrantedPermissions)
    if ($missingCore.Count -gt 0) {
        Write-Warn2 ("The audit app is missing core read permission(s): {0}. Checks that need them will be skipped - grant them (the application permission list in PREREQUISITE.md, section B.1) for a complete audit." -f ($missingCore -join ', '))
    }
}

function Get-EAMissingScope {
    param(
        [string[]]$Required,
        # Optional explicit permission list (used by Assert-AppOnlyReadOnly); by default the
        # current sign-in's permissions are used.
        [string[]]$Granted
    )
    # The outer @() keeps a one-permission list an array: otherwise $have becomes a plain
    # string and "+=" below concatenates text, so even the granted permission looks missing.
    [string[]]$have = @(if ($PSBoundParameters.ContainsKey('Granted')) {
        @($Granted)
    } elseif ($script:AuthType -eq 'AppOnly') {
        @($script:AppOnlyGrantedPermissions)
    } else {
        @((Get-MgContext).Scopes)
    })
    if ($have -contains 'Directory.Read.All') {
        $have += @('User.Read.All','Group.Read.All','Organization.Read.All','Device.Read.All','Application.Read.All')
    }
    return @($Required | Where-Object { $_ -and $_ -notin $have })
}

function Test-MgScope {
    param([string[]]$Required, [switch]$Quiet)
    $missing = @(Get-EAMissingScope -Required $Required)
    if ($missing.Count -gt 0) {
        if (-not $Quiet) { Write-Warn2 "Skipping - missing $($script:AuthType.ToLowerInvariant()) permission(s): $($missing -join ', ')" }
        return $false
    }
    return $true
}

function Get-EAMissingScopeReason {
    param([string[]]$Missing)
    $list = (@($Missing) -join ', ')
    $one = (@($Missing).Count -eq 1)
    $noun = if ($one) { 'permission' } else { 'permissions' }
    $it = if ($one) { 'it' } else { 'them' }
    if ($script:AuthType -eq 'AppOnly') {
        return "Missing $noun`: $list - add $it to the audit app as application $noun, grant admin consent and run again."
    }
    return "Missing $noun`: $list - an administrator must consent to $it for the app used to sign in, then run again."
}

function Get-EAUsers {
    # The property set is decided by the LICENSE/SCOPE GATE, not the caller switch: when
    # P1 + AuditLog.Read.All are present the very first fetch already includes
    # signInActivity, so later sign-in callers (staleusers/breakglass) hit the cache
    # instead of re-downloading the entire directory a second time. If the superset
    # fetch fails anyway (app-only without the AuditLog app permission - Test-MgScope
    # cannot see that), the failure is remembered: base callers degrade once to the
    # plain property set, sign-in callers keep today's throw/Skipped-NoPermission path.
    # -IncludeSignInActivity remains for call-site compatibility.
    # Every user also carries its manager's id (Manager.Id) when $script:UsersCacheHasManager
    # is $true - see Get-EAUserList. The manager is expanded only when the accounts check
    # (its only reader) is part of the run, or when the selection is unknown.
    param([switch]$IncludeSignInActivity)

    $gateSignIn = $script:HasP1 -and (Test-MgScope @('AuditLog.Read.All') -Quiet)
    if ($IncludeSignInActivity -and $gateSignIn -and $script:SignInFetchError) { throw $script:SignInFetchError }
    $wantSignIn = $gateSignIn -and -not $script:SignInFetchError

    # Serve from cache when the cached population already satisfies the request. The
    # sign-in variant is a superset of properties, so a base caller can reuse it freely.
    if ($wantSignIn) {
        if ($script:UsersCacheHasSignIn) { return $script:UsersCache }
    } elseif ($null -ne $script:UsersCache) {
        return $script:UsersCache
    }

    # LicenseAssignmentStates is deliberately NOT selected: no check reads it, and it is a
    # nested per-SKU array - one of the largest properties on the largest collection.
    $props = @('Id','UserPrincipalName','DisplayName','AccountEnabled','UserType',
               'AssignedLicenses','PasswordPolicies',
               'OnPremisesSyncEnabled','CreatedDateTime',
               'ExternalUserState','ExternalUserStateChangeDateTime')
    $selectedChecks = @(if ($script:RunInfo) { Get-EAField $script:RunInfo 'SelectedChecks' | Where-Object { $_ } })
    $withManager = ($selectedChecks.Count -eq 0 -or $selectedChecks -contains 'accounts')
    if ($wantSignIn) {
        try {
            # Graph caps list pages that include signInActivity at 120 users (documented
            # limit for $select=signInActivity), so ask for exactly that page size.
            $read = Get-EAUserList -Property ($props + 'SignInActivity') -PageSize 120 -IncludeManager:$withManager
            $script:UsersCacheHasSignIn = $true
        } catch {
            $script:SignInFetchError = $_.Exception
            if ($IncludeSignInActivity) { throw }   # sign-in caller: same failure path as before
            Write-Warn2 "  Sign-in activity could not be read with the user list ($($_.Exception.Message)) - continuing with the user list only; sign-in based checks will report the gap."
            $read = Get-EAUserList -Property $props -IncludeManager:$withManager   # base caller: degrade once
            $script:UsersCacheHasSignIn = $false
        }
    } else {
        $read = Get-EAUserList -Property $props -IncludeManager:$withManager
        $script:UsersCacheHasSignIn = $false
    }
    $script:UsersCache = $read.Users
    $script:UsersCacheHasManager = [bool]$read.HasManager
    $script:UserById = @{}
    foreach ($u in $script:UsersCache) { if ($u.Id) { $script:UserById[$u.Id] = $u } }
    return $script:UsersCache
}

function Get-EAUserList {
    param([Parameter(Mandatory)][string[]]$Property, [int]$PageSize = 999, [switch]$IncludeManager)
    if ($IncludeManager -and -not $script:ManagerExpansionFailed) {
        $expandError = $null
        try {
            $users = @(Invoke-EAListAll -Command 'Get-MgUser' -Parameters @{ Property = $Property; ExpandProperty = 'manager($select=id)' } -PageSize $PageSize)
            return [pscustomobject]@{ Users = $users; HasManager = $true }
        } catch { $expandError = $_.Exception.Message }
        $users = @(Invoke-EAListAll -Command 'Get-MgUser' -Parameters @{ Property = $Property } -PageSize $PageSize)
        $script:ManagerExpansionFailed = $true
        $script:ManagerExpansionError = $expandError
        Write-Warn2 "  The user list could not be read together with each user's manager ($expandError) - it was read without the manager; the accounts check reads the manager separately."
        return [pscustomobject]@{ Users = $users; HasManager = $false }
    }
    $users = @(Invoke-EAListAll -Command 'Get-MgUser' -Parameters @{ Property = $Property } -PageSize $PageSize)
    return [pscustomobject]@{ Users = $users; HasManager = $false }
}

function Get-EARegistrationDetails {
    if ($null -ne $script:RegCache) { return $script:RegCache }
    $script:RegCache = @(Invoke-EAListAll -Command 'Get-MgReportAuthenticationMethodUserRegistrationDetail')
    $script:MfaCapableById = @{}
    foreach ($r in $script:RegCache) { if ($r.Id) { $script:MfaCapableById[$r.Id] = [bool]$r.IsMfaCapable } }
    return $script:RegCache
}

function Get-EARoleDefMap {
    if ($script:RoleDefById.Count -gt 0) { return $script:RoleDefById }
    # (No -PageSize: role definitions are a small, unpaged collection.)
    $definitions = @(Get-MgRoleManagementDirectoryRoleDefinition -All -Property 'id,templateId,displayName,isBuiltIn,isEnabled,rolePermissions' -ErrorAction Stop)
    foreach ($rd in $definitions) {
        $script:RoleDefById[$rd.Id] = $rd
        # Built-in policy/assignment APIs sometimes return the template id rather than the
        # tenant role-definition id. Index both without losing support for custom roles,
        # whose TemplateId is normally empty.
        if ($rd.TemplateId) { $script:RoleDefById[[string]$rd.TemplateId] = $rd }
    }
    # isPrivileged is currently exposed on the beta unifiedRoleDefinition shape. Read it
    # separately (GET only) and retain v1.0 objects for every other operation. If beta is
    # unavailable, custom/unlisted roles fall back to conservative action inspection.
    try {
        $u = 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,templateId,isPrivileged'; $guard = 0
        while ($u -and $guard -lt 50) {
            $u = Assert-EAGraphReadUri $u
            $resp = Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop
            foreach ($brd in @($resp['value'])) {
                $bid = [string]$brd['id']; $btid = [string]$brd['templateId']
                if ($bid -and $brd.ContainsKey('isPrivileged')) { $script:RolePrivilegedById[$bid] = [bool]$brd['isPrivileged'] }
                if ($btid -and $brd.ContainsKey('isPrivileged')) { $script:RolePrivilegedById[$btid] = [bool]$brd['isPrivileged'] }
            }
            $u = $resp['@odata.nextLink']; $guard++
        }
        if ($u) { throw 'Microsoft Graph role-definition pagination exceeded the 50-page safety limit.' }
        $script:RolePrivilegedMetadataKnown = $true
        $script:RolePrivilegedMetadataError = $null
    } catch {
        # Not a clean result, but not a blind spot either: without Graph's isPrivileged flag
        # every role with any non-read action is treated as privileged (broader, fail-safe).
        $script:RolePrivilegedMetadataKnown = $false
        $script:RolePrivilegedMetadataError = $_.Exception.Message
        Write-Warn2 "  Could not read the 'isPrivileged' flag for directory roles ($($_.Exception.Message)) - roles are classified by the built-in list and their allowed actions instead (may over-count privileged roles)."
    }
    # Prime the dynamic privileged map. Existing well-known IDs remain the fail-safe
    # fallback, while Graph's isPrivileged flag and custom role actions catch new/unlisted
    # roles without waiting for this script's static list to be updated.
    foreach ($rd in $definitions) { Get-EARoleInfo -RoleDefinitionId ([string]$rd.Id) | Out-Null }
    return $script:RoleDefById
}

function Get-EARoleInfo {
    param([Parameter(Mandatory)][string]$RoleDefinitionId)
    $rd = $script:RoleDefById[$RoleDefinitionId]
    if (-not $rd -and $script:RoleDefById.Count -gt 0) {
        $rd = $script:RoleDefById.Values | Where-Object { $_.Id -eq $RoleDefinitionId -or $_.TemplateId -eq $RoleDefinitionId } | Select-Object -First 1
    }
    $templateId = if ($rd -and $rd.TemplateId) { [string]$rd.TemplateId } else { $RoleDefinitionId }
    $definitionId = if ($rd -and $rd.Id) { [string]$rd.Id } else { $RoleDefinitionId }
    $name = if ($rd -and $rd.DisplayName) { [string]$rd.DisplayName }
            elseif ($script:PrivilegedRoleTemplates.ContainsKey($templateId)) { [string]$script:PrivilegedRoleTemplates[$templateId] }
            else { $RoleDefinitionId }

    $fallback = ($templateId -in $script:StaticPrivilegedRoleTemplateIds)
    $rawPrivileged = if ($script:RolePrivilegedById.ContainsKey($definitionId)) { $script:RolePrivilegedById[$definitionId] }
                     elseif ($script:RolePrivilegedById.ContainsKey($templateId)) { $script:RolePrivilegedById[$templateId] }
                     elseif ($rd) { Get-EAField $rd 'IsPrivileged' } else { $null }
    if ($null -eq $rawPrivileged -and $rd) { $rawPrivileged = Get-EAField $rd 'isPrivileged' }
    $explicitKnown = ($null -ne $rawPrivileged)
    $explicitPrivileged = ($explicitKnown -and [bool]$rawPrivileged)
    $isBuiltInRaw = if ($rd) { Get-EAField $rd 'IsBuiltIn' } else { $null }

    $allowedActions = @()
    if ($rd) {
        foreach ($perm in @((Get-EAField $rd 'RolePermissions'))) {
            $allowedActions += @((Get-EAField $perm 'AllowedResourceActions') | Where-Object { $_ })
        }
    }
    # A custom/unclassified role with any non-read action is privileged. This is
    # deliberately broad and fail-safe: credential, membership, policy and assignment
    # actions use many different path names, whereas read actions consistently end /read.
    $writeActions = @($allowedActions | Where-Object {
        $s = [string]$_
        $s -eq '*' -or $s -notmatch '(?i)/(read|readBasic)$'
    })
    $actionPrivileged = ($writeActions.Count -gt 0 -and -not $explicitKnown)
    $unresolved = (-not $rd)
    $isPrivileged = ($fallback -or $explicitPrivileged -or $actionPrivileged -or $unresolved)
    # Action-based tier-0 escalation applies to custom roles only. Built-in User/Helpdesk/
    # Password/Authentication Administrator carry users/password/update (non-admin resets)
    # and are tier-1 by the documented model; built-in tier-0 roles are listed by template id.
    $isTier0 = (($templateId -in $script:Tier0RoleTemplateIds) -or (($isBuiltInRaw -ne $true) -and @($writeActions | Where-Object {
        [string]$_ -match '(?i)^microsoft\.directory/(roleAssignments|roleDefinitions)/.*(allTasks|create|update)$' -or
        [string]$_ -match '(?i)^microsoft\.directory/users/(authenticationMethods|password)/.*(allTasks|create|update)$'
    }).Count -gt 0))
    $source = if ($fallback) { 'static-fallback' } elseif ($explicitPrivileged) { 'role-definition-isPrivileged' } elseif ($actionPrivileged) { 'custom-role-write-actions' } elseif ($unresolved) { 'unresolved-fail-closed' } else { 'role-definition-nonprivileged' }

    if ($isPrivileged -and -not $script:PrivilegedRoleTemplates.ContainsKey($templateId)) {
        $script:PrivilegedRoleTemplates[$templateId] = $name
    }
    return [pscustomobject]@{
        Name=$name; TemplateId=$templateId; RoleDefinitionId=$definitionId
        IsPrivileged=$isPrivileged; IsGA=($templateId -eq $script:GlobalAdminTemplateId); IsTier0=$isTier0
        IsBuiltIn=$(if ($null -eq $isBuiltInRaw) { $null } else { [bool]$isBuiltInRaw })
        ClassificationSource=$source; WriteActions=($writeActions -join '; ')
    }
}

function Get-EAApplications {
    if ($null -ne $script:AppsCache) { return $script:AppsCache }
    $appProps = 'id,appId,displayName,passwordCredentials,keyCredentials,signInAudience,verifiedPublisher,createdDateTime,web,spa,publicClient,isFallbackPublicClient,identifierUris,api'
    # owners expanded (ids only) in the same enumeration: the apps check tests only
    # "has NO owner", which would otherwise cost one Graph call per credentialed app.
    $script:AppsCache = @(Invoke-EAListAll -Command 'Get-MgApplication' -Parameters @{ Property = $appProps; ExpandProperty = 'owners($select=id)' })
    return $script:AppsCache
}

function Get-EAServicePrincipals {
    if ($null -ne $script:SpsCache) { return $script:SpsCache }
    $spProps = 'id,appId,displayName,appRoles,servicePrincipalType,accountEnabled,passwordCredentials,keyCredentials,appOwnerOrganizationId,createdDateTime,verifiedPublisher,signInAudience'
    $script:SpsCache = @(Invoke-EAListAll -Command 'Get-MgServicePrincipal' -Parameters @{ Property = $spProps })
    return $script:SpsCache
}

function Get-EACaPolicies {
    if ($null -ne $script:CaPoliciesCache) { return $script:CaPoliciesCache }
    # 'Prefer: include-unknown-enum-members' makes Graph return newer ("evolvable") enum
    # values by name - for example the grant control 'riskRemediation' in Microsoft's current
    # user-risk template - instead of 'unknownFutureValue'. Sent only when the installed
    # cmdlet has -Headers; without it the capolicies check reports such a policy as
    # "not confirmed" rather than passing or failing it.
    $caParams = @{ All = $true; ErrorAction = 'Stop' }
    $caCmd = Get-Command -Name 'Get-MgIdentityConditionalAccessPolicy' -ErrorAction SilentlyContinue
    if ($caCmd -and $caCmd.Parameters -and $caCmd.Parameters.ContainsKey('Headers')) {
        $caParams.Headers = @{ Prefer = 'include-unknown-enum-members' }
    }
    $script:CaPoliciesCache = @(Get-MgIdentityConditionalAccessPolicy @caParams)
    $script:AuthenticationStrengthById = @{}
    $script:AuthenticationStrengthReadErrors = @{}
    foreach ($policy in $script:CaPoliciesCache) {
        $strength = Get-EAField $policy.GrantControls 'AuthenticationStrength'
        $id = [string](Get-EAField $strength 'Id')
        if (-not $id -or $script:AuthenticationStrengthById.ContainsKey($id) -or $script:AuthenticationStrengthReadErrors.ContainsKey($id)) { continue }
        if ($id -in @('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004')) { continue }
        if ([string](Get-EAField $strength 'RequirementsSatisfied') -in @('none','mfa') -and @((Get-EAField $strength 'AllowedCombinations') | Where-Object { $_ }).Count -gt 0) { continue }
        try {
            $uri = 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies/' + [uri]::EscapeDataString($id)
            $uri = Assert-EAGraphReadUri $uri
            $script:AuthenticationStrengthById[$id] = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        } catch { $script:AuthenticationStrengthReadErrors[$id] = $_.Exception.Message }
    }
    return $script:CaPoliciesCache
}

function Get-EAOAuth2Grants {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Shared-cache contract name, like Get-EAUsers.')]
    param()
    if ($null -ne $script:OAuthGrantsCache) { return $script:OAuthGrantsCache }
    $grants = @(Invoke-EAListAll -Command 'Get-MgOauth2PermissionGrant')
    $script:OAuthGrantsCache = $grants
    return $grants
}

function Get-EAServicePrincipalSignInActivity {
    if ($null -ne $script:SpSignInActivity) { return $script:SpSignInActivity }
    $byAppId = @{}
    $unreadable = 0
    $subActivities = @('lastSignInActivity', 'delegatedClientSignInActivity', 'delegatedResourceSignInActivity',
                       'applicationAuthenticationClientSignInActivity', 'applicationAuthenticationResourceSignInActivity')
    try {
        $uri = 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities'
        $page = 0
        while ($uri) {
            # Loop guard only (a nextLink that never ends); real tenants stay far below it.
            if ($page -ge 2000) { throw 'The service-principal sign-in activity report exceeded the 2000-page safety limit, so it was not read completely.' }
            $uri = Assert-EAGraphReadUri $uri
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            # A collection response without value[] is unknown, not an empty report.
            if ($resp -isnot [System.Collections.IDictionary] -or -not $resp.Contains('value')) {
                throw 'The service-principal sign-in activity report returned a response without a value list.'
            }
            foreach ($r in @($resp['value'])) {
                $appId = [string](Get-EAField $r 'appId')
                if (-not $appId) { continue }
                $newest = $null
                foreach ($name in $subActivities) {
                    $sub = Get-EAField $r $name
                    if ($null -eq $sub) { continue }
                    $raw = Get-EAField $sub 'lastSignInDateTime'
                    if ($null -eq $raw -or [string]::IsNullOrWhiteSpace([string]$raw)) { continue }
                    $when = $null
                    if ($raw -is [datetime]) {
                        $when = if ($raw.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($raw, [DateTimeKind]::Utc) } else { $raw.ToUniversalTime() }
                    } elseif ($raw -is [datetimeoffset]) {
                        $when = $raw.UtcDateTime
                    } else {
                        $parsed = [datetimeoffset]::MinValue
                        if ([datetimeoffset]::TryParse([string]$raw, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { $when = $parsed.UtcDateTime }
                        else { $unreadable++ }   # counted for the callers' evidence, never dropped silently
                    }
                    if ($when -and ($null -eq $newest -or $when -gt $newest)) { $newest = $when }
                }
                if ($null -ne $newest) {
                    if (-not $byAppId.ContainsKey($appId) -or $null -eq $byAppId[$appId] -or $newest -gt $byAppId[$appId]) { $byAppId[$appId] = $newest }
                } elseif (-not $byAppId.ContainsKey($appId)) {
                    $byAppId[$appId] = $null
                }
            }
            $uri = [string]$resp['@odata.nextLink']
            $page++
        }
    } catch {
        return [pscustomobject]@{ Known = $false; ByAppId = $byAppId; Error = [string]$_.Exception.Message; UnreadableDates = $unreadable }
    }
    $script:SpSignInActivity = [pscustomobject]@{ Known = $true; ByAppId = $byAppId; Error = $null; UnreadableDates = $unreadable }
    return $script:SpSignInActivity
}

function Get-EAPrivAssignments {
    if ($null -ne $script:PrivAssignments) { return $script:PrivAssignments }
    try {
        Get-EARoleDefMap | Out-Null
    } catch {
        # Without role definitions no assignment can be classified. Flag it so callers that
        # only read the flags (not the exception) also report "unknown", then rethrow.
        $script:PrivAssignmentsFailed = $true
        $script:PrivilegedUserMapIncomplete = $true
        $script:PrivAssignmentsError = "The directory role definitions could not be read: $($_.Exception.Message)"
        throw
    }
    # The user list only ANNOTATES assignments (UPN, and 'user' when Graph omits the
    # principal type). A failed read is recorded and printed, not swallowed: principals
    # whose type then stays unknown make the privileged-user map incomplete.
    try { Get-EAUsers | Out-Null; $script:PrivUserLookupError = $null }
    catch {
        $script:PrivUserLookupError = $_.Exception.Message
        Write-Warn2 "  The user list could not be read while resolving role holders ($($_.Exception.Message)) - some role holders may show without a name or type."
    }
    $list = [System.Collections.Generic.List[object]]::new()

    function _Add($a, $state) {
        $ri = Get-EARoleInfo -RoleDefinitionId ([string]$a.RoleDefinitionId)
        $p = $a.Principal
        $id = if ($a.PrincipalId) { $a.PrincipalId } elseif ($p) { $p.Id } else { $null }
        $odt = Get-Ap $p '@odata.type'
        if (-not $odt -and $p -and $p.PSObject.Properties['OdataType']) { $odt = $p.OdataType }
        $upn = Get-Ap $p 'userPrincipalName'
        $pname = Get-Ap $p 'displayName'
        if (-not $pname -and $p -and $p.PSObject.Properties['DisplayName']) { $pname = $p.DisplayName }
        if (-not $upn -and $id -and $script:UserById.ContainsKey($id)) { $upn = $script:UserById[$id].UserPrincipalName }
        $ptype = if ($odt) { ($odt -replace '#microsoft.graph.','') }
                 elseif ($upn) { 'user' }
                 elseif ($id -and $script:UserById.ContainsKey($id)) { 'user' }
                 elseif ($p -and $p.GetType().Name -match '(?i)Group') { 'group' }
                 elseif ($p -and $p.GetType().Name -match '(?i)ServicePrincipal') { 'servicePrincipal' }
                 elseif ((Get-Ap $p 'groupTypes') -or $null -ne (Get-Ap $p 'securityEnabled')) { 'group' }
                 elseif (Get-Ap $p 'appId') { 'servicePrincipal' }
                 else { 'unknown' }

        # 'State' stays the COARSE Active/Eligible distinction the access-path correlation
        # relies on. 'ActivationModel' is the fine-grained classification needed to tell a
        # PERMANENT standing assignment apart from a time-bound or JIT-activated one - the
        # break-glass check needs "permanent active GA", not merely "currently active GA".
        $assignmentType = $null
        if ($a.PSObject.Properties['AssignmentType']) { $assignmentType = [string]$a.AssignmentType }
        $endDateTime = $null
        if ($a.PSObject.Properties['EndDateTime']) { $endDateTime = $a.EndDateTime }
        $memberType = $null
        if ($a.PSObject.Properties['MemberType']) { $memberType = [string]$a.MemberType }
        if (-not $memberType) { $memberType = 'Direct' }
        $activationModel =
            if ($state -eq 'Eligible')              { 'Eligible' }
            elseif ($assignmentType -eq 'Activated') { 'TimeBound-Active-JIT' }
            elseif ($null -eq $endDateTime)          { 'Permanent' }
            else                                     { 'TimeBound-Assigned' }

        $list.Add([pscustomobject]@{
            PrincipalId=$id; PrincipalType=$ptype; PrincipalUpn=$upn; PrincipalName=$pname
            RoleTemplateId=$ri.TemplateId; RoleDefinitionId=$ri.RoleDefinitionId; RoleName=$ri.Name; State=$state
            ActivationModel=$activationModel; AssignmentType=$assignmentType; EndDateTime=$endDateTime; MemberType=$memberType
            DirectoryScopeId=$a.DirectoryScopeId; AppScopeId=$a.AppScopeId
            ScopeKey=('{0}~{1}' -f ([string]$a.DirectoryScopeId),([string]$a.AppScopeId))
            IsPrivileged=$ri.IsPrivileged; IsGA=$ri.IsGA; IsTier0=$ri.IsTier0; RoleClassification=$ri.ClassificationSource
        }) | Out-Null
    }

    # ACTIVE assignments: PIM schedule instances first (they carry the time-bound / JIT
    # detail). The classic roleAssignments list is read when that failed OR returned no
    # rows - Microsoft Entra always has an active Global Administrator, so zero active rows
    # is a failed or incomplete read, never proof that there are no standing admins.
    $script:PrivActiveFetchError = $null; $script:PrivClassicFetchError = $null
    $script:PrivActiveSource = 'none (every read failed or returned nothing)'
    $active = @(); $activeFailed = $false
    try {
        $active = @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)
        if ($active.Count -gt 0) { $script:PrivActiveSource = 'PIM role-assignment schedule instances' }
    } catch { $script:PrivActiveFetchError = $_.Exception.Message }
    if ($active.Count -eq 0) {
        try {
            $active = @(Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop)
            $script:PrivActiveSource = 'classic role assignments (roleManagement/directory/roleAssignments)'
        } catch {
            $script:PrivClassicFetchError = $_.Exception.Message
            $activeFailed = $true
        }
    }
    if (-not $activeFailed -and $active.Count -eq 0) {
        # Both reads "worked" but returned nothing. Entra always has an active Global
        # Administrator, so this is unknown, not "no admins" - the same rule the
        # privileged-roles and directory-roles checks apply. Not cached (see below).
        $activeFailed = $true
        $script:PrivClassicFetchError = 'the read returned no active role assignments, but Microsoft Entra always has an active Global Administrator, so the result is unknown, not empty'
    }
    foreach ($a in $active) { _Add $a 'Active' }
    # Eligibility is P2-gated; on a licensed tenant a failed read is a coverage gap, not
    # evidence that no eligible administrators exist. When the licence read itself failed
    # (LicenseKnown = false) HasP2 is only a default, so the failure is a gap there too.
    # The raw error is kept either way ($script:PrivEligibilityFetchError).
    try {
        foreach ($a in @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop)) { _Add $a 'Eligible' }
        $script:PrivEligibilityAssignmentsFailed = $false
        $script:PrivEligibilityFetchError = $null
    } catch {
        $script:PrivEligibilityFetchError = $_.Exception.Message
        $script:PrivEligibilityAssignmentsFailed = ([bool]$script:HasP2 -or -not $script:LicenseKnown)
        if ($script:PrivEligibilityAssignmentsFailed) { Write-Warn2 "  Privileged eligibility-assignment fetch failed: $($_.Exception.Message)" }
    }

    if ($activeFailed) {
        # Every ACTIVE-assignment read FAILED - this is "unknown", not "no admins", even
        # when the eligibility read above returned rows. Do not cache (a later check may
        # retry successfully) and flag the failure so consumers report "could not
        # validate" instead of findings built on blindness.
        $why = @()
        if ($script:PrivActiveFetchError) { $why += "PIM schedule instances: $($script:PrivActiveFetchError)" }
        $why += "role assignments: $($script:PrivClassicFetchError)"
        $script:PrivAssignmentsFailed = $true
        $script:PrivAssignmentsError = "The active role assignments could not be read ($($why -join '; '))."
        Write-Warn2 "  Privileged-assignment fetch failed: $($script:PrivAssignmentsError)"
        return $list
    }
    $script:PrivAssignmentsFailed = $false
    $script:PrivAssignmentsError = $null
    $script:PrivAssignments = $list
    return $list
}

function Get-EAGroupTransitiveMember {
    param([Parameter(Mandatory)][string]$GroupId)
    if ($null -eq $script:GroupMembersCache) { $script:GroupMembersCache = @{} }
    $key = $GroupId.ToLowerInvariant()
    if ($script:GroupMembersCache.ContainsKey($key)) { return $script:GroupMembersCache[$key] }
    $members = @(Get-MgGroupTransitiveMember -GroupId $GroupId -All -PageSize 999 -ErrorAction Stop)
    $script:GroupMembersCache[$key] = $members
    return $members
}

function Get-EAGroupOwner {
    param([Parameter(Mandatory)][string]$GroupId)
    if ($null -eq $script:GroupOwnersCache) { $script:GroupOwnersCache = @{} }
    $key = $GroupId.ToLowerInvariant()
    if ($script:GroupOwnersCache.ContainsKey($key)) { return $script:GroupOwnersCache[$key] }
    $owners = @(Get-MgGroupOwner -GroupId $GroupId -All -PageSize 999 -ErrorAction Stop)
    $script:GroupOwnersCache[$key] = $owners
    return $owners
}

function Get-EAPrivilegedUserMap {
    if ($null -ne $script:PrivilegedUserMap) { return $script:PrivilegedUserMap }
    # Without the user list, a group member Graph returns without a type cannot be told
    # apart from a non-user; such members make the map incomplete (below), never silently
    # dropped. The failure itself is recorded and printed.
    $usersKnown = $true
    try { Get-EAUsers | Out-Null }
    catch {
        $usersKnown = $false
        $script:PrivUserLookupError = $_.Exception.Message
        Write-Warn2 "  The user list could not be read while listing privileged users ($($_.Exception.Message)) - group members without a type are treated as unknown."
    }
    $map = @{}
    $script:PrivilegedUserMapIncomplete = $false

    function _AddUserPrivilege([string]$UserId, $Assignment) {
        if (-not $UserId) { return }
        # ::new(), not New-Object: consumers wrap these lists in @(), which throws on pwsh
        # 7.4 for a List[object] created with New-Object.
        if (-not $map.ContainsKey($UserId)) { $map[$UserId] = [System.Collections.Generic.List[object]]::new() }
        $map[$UserId].Add($Assignment) | Out-Null
    }

    foreach ($a in @(Get-EAPrivAssignments)) {
        if (-not $a.IsPrivileged -or -not $a.PrincipalId) { continue }
        if ($a.PrincipalType -eq 'user') {
            _AddUserPrivilege ([string]$a.PrincipalId) $a
            continue
        }
        if ($a.PrincipalType -ne 'group') {
            if ($a.PrincipalType -eq 'unknown') { $script:PrivilegedUserMapIncomplete = $true }
            continue
        }
        try {
            foreach ($m in @(Get-EAGroupTransitiveMember -GroupId ([string]$a.PrincipalId))) {
                $mtype = [string](Get-Ap $m '@odata.type')
                $upn = Get-Ap $m 'userPrincipalName'
                if ($mtype -eq '#microsoft.graph.user' -or $upn -or ($m.Id -and $script:UserById.ContainsKey([string]$m.Id))) {
                    _AddUserPrivilege ([string]$m.Id) $a
                } elseif (-not $mtype -and -not $usersKnown) {
                    # No type on the member and no user list to look it up in: it may be a
                    # privileged user, so the population is not complete.
                    $script:PrivilegedUserMapIncomplete = $true
                }
            }
        } catch {
            $script:PrivilegedUserMapIncomplete = $true
            Write-Warn2 "  Could not expand privileged group $($a.PrincipalName ?? $a.PrincipalId): $($_.Exception.Message)"
        }
    }
    if ($script:PrivAssignmentsFailed -or $script:PrivEligibilityAssignmentsFailed) { $script:PrivilegedUserMapIncomplete = $true }
    $script:PrivilegedUserMap = $map
    return $map
}
