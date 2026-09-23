# PREREQUISITE — Permissions & Setup for EntraAudit-PS7

This document lists exactly what EntraAudit-PS7 needs to run. All **audit/data-collection API calls are read-only**: the tool requests only documented Graph read permissions, issues only `GET` requests, and **refuses to run unless every permission on the sign-in is read-only** (see [Verifying it's read-only](#verifying-its-read-only)). Optional Azure-monitoring enrichment also uses retrieval-only Azure Resource Manager calls. First-time interactive OAuth consent is a separate operator-authorized setup grant for the requested read permissions; pre-consent them before the audit window when literal zero setup changes during execution is required.

There are two ways to authenticate — pick one:

- **A. Interactive (delegated)** — an admin signs in. Best for ad-hoc audits. → [Section A](#a-interactive-delegated-sign-in)
- **B. App-only (certificate)** — a dedicated app registration, no human. Best for scheduled/unattended runs. → [Section B](#b-app-only-unattended-sign-in)

---

## 0. Software prerequisites

- **PowerShell 7.x** (`pwsh.exe`) on Windows.
- `EntraAudit-PS7.ps1` and both companion check libraries (`EntraAudit-Checks-Governance.ps1` and `EntraAudit-Checks-Applications.ps1`) in the same folder. Keep `EntraAudit-GUI.ps1` there too when using the GUI.
- **Microsoft Graph PowerShell SDK v2.x** — the script uses these 8 sub-modules (not the giant meta-module):

  | Module | Provides |
  |---|---|
  | `Microsoft.Graph.Authentication` | `Connect-MgGraph`, `Get-MgContext`, `Invoke-MgGraphRequest` (auth plumbing) |
  | `Microsoft.Graph.Identity.DirectoryManagement` | org/tenant, SKUs, directory roles, devices, on-prem sync |
  | `Microsoft.Graph.Identity.SignIns` | Conditional Access, policies, Identity Protection, cross-tenant |
  | `Microsoft.Graph.Identity.Governance` | **PIM** role eligibility/assignment schedule instances (flagship check) |
  | `Microsoft.Graph.Users` | users, authentication methods |
  | `Microsoft.Graph.Groups` | groups, role-assignable groups, group owners |
  | `Microsoft.Graph.Applications` | applications, service principals, OAuth grants |
  | `Microsoft.Graph.Reports` | auth-method registration report, sign-in logs, directory audit |

  `Microsoft.Graph.DirectoryObjects` is **no longer needed** (no check uses it).

### Install the modules

**Online (simplest):**
```powershell
.\EntraAudit-PS7.ps1 -installdeps
```
What `-installdeps` does:
- installs the 8 modules above from the PowerShell Gallery **for the current user only** (no administrator rights), pinned to major version 2 so sub-module majors can't mix;
- keeps any module that is already installed at v2;
- installs the NuGet package provider if it is missing, and marks PSGallery as trusted **only for the install** — the original setting is put back afterwards (if that fails, a warning shows the command to reset it);
- checks afterwards that all Graph modules share one major version;
- with no check switch it only installs and stops; with `-all` (or other check switches) it installs and then runs the audit. A failed install stops the run with exit code 1.

Or manually (pin to v2.x, like `-installdeps` does, so sub-module majors can't mix):
```powershell
$modules = @(
  'Microsoft.Graph.Authentication','Microsoft.Graph.Identity.DirectoryManagement',
  'Microsoft.Graph.Identity.SignIns','Microsoft.Graph.Identity.Governance',
  'Microsoft.Graph.Users','Microsoft.Graph.Groups','Microsoft.Graph.Applications',
  'Microsoft.Graph.Reports')
Install-Module $modules -Scope CurrentUser -Repository PSGallery -Force `
  -MinimumVersion 2.0.0 -MaximumVersion 2.999.999
```

**Offline (air-gapped):** on an internet-connected machine, run `Save-Module` into a folder, copy the folder across, then point the script at it:
```powershell
# online machine
Save-Module Microsoft.Graph.Authentication,Microsoft.Graph.Identity.DirectoryManagement,`
  Microsoft.Graph.Identity.SignIns,Microsoft.Graph.Identity.Governance,Microsoft.Graph.Users,`
  Microsoft.Graph.Groups,Microsoft.Graph.Applications,Microsoft.Graph.Reports `
  -Path C:\GraphModules -Repository PSGallery

# audit machine (copy C:\GraphModules across first)
.\EntraAudit-PS7.ps1 -all -ModulesPath C:\GraphModules
```

`-ModulesPath` also works together with `-installdeps`: the offline folder is searched first, so the installer finds the offline modules and skips the gallery download instead of trying to go online.

> Keep all Microsoft.Graph sub-modules at the **same version** to avoid assembly-load conflicts. `-installdeps` pins to v2.x and the script warns at import time if it finds mixed majors. A missing module stops the run with a message telling you to use `-installdeps` or this section.

---

## A. Interactive (delegated) sign-in

### A.1 Directory roles for the auditor account

Assign the account these two **read-only** directory roles. Together they cover nearly all Microsoft Graph evidence with zero write ability; the optional Azure-monitoring enrichment is covered separately in [Section C](#c-optional-azure-diagnostic-setting-and-alert-coverage):

| Role | Why |
|---|---|
| **Global Reader** | Read-only mirror of Global Administrator: configuration, policies, applications, directory objects, sync status. |
| **Security Reader** | Identity Protection (risky users/detections), security policies, Secure Score. |

Do **not** use Global Administrator. A few sub-controls can still be refused with these two roles. The audit never treats that as clean — it reports the sub-control as **Not assessed** and says what is missing:

- **Federated identity credentials (`workloadcredentials`):** tenant-wide delegated `federatedIdentityCredentials` enumeration does not list Global Reader or Security Reader as supported roles. Use the read-only **app-only** mode with `Application.Read.All` when complete tenant-wide federated-credential coverage is required; do not grant a write-capable application-admin role merely to run an audit.
- **Guest sponsors (`externaldelegation`):** the delegated sponsor read needs `User.Read.All` plus a directory role such as **Directory Readers** or **Guest Inviter** (Directory Writers and User Administrator also work). If sponsors cannot be read, the guests are listed as *not read* — never as "no sponsor". Directory Readers is read-only and is the safe addition if you need this.
- **Terms of Use (`identitygovernance`):** listing agreements needs a **user** sign-in with `Agreement.Read.All` and the **Security Reader** or **Global Reader** role; app-only sign-ins cannot list them.
- **Directory-sync settings (hybrid tenants: `tenanthealth`, `federationhealth`, `authrecovery`):** Password Hash Sync, soft-match blocking, accidental-deletion protection and password writeback come from Microsoft Graph's on-premises synchronization API (`OnPremDirectorySynchronization.Read.All`). The audit's findings for this read say it needs a delegated sign-in as Global Administrator and that app-only is not supported for it. If the read is refused, those sub-controls are *Not assessed* and the finding shows how to check them by hand in Entra Connect. Prefer that manual check over running the whole audit as Global Administrator.

### A.2 Delegated scopes requested at sign-in

The script requests exactly these (all read-only). On first run, an administrator consents once for the tenant:

```
Directory.Read.All
AuditLog.Read.All
Policy.Read.All
RoleManagement.Read.Directory
Application.Read.All
User.Read.All
Group.Read.All
Organization.Read.All
Device.Read.All
IdentityRiskyUser.Read.All
IdentityRiskEvent.Read.All
IdentityRiskyServicePrincipal.Read.All
CrossTenantInformation.ReadBasic.All
OnPremDirectorySynchronization.Read.All
Reports.Read.All
RoleManagementPolicy.Read.Directory
Member.Read.Hidden
DirectoryRecommendations.Read.All
SecurityEvents.Read.All
SecurityAlert.Read.All
AccessReview.Read.All
EntitlementManagement.Read.All
LifecycleWorkflows.Read.All
Agreement.Read.All
PrivilegedAssignmentSchedule.Read.AzureADGroup
PrivilegedEligibilitySchedule.Read.AzureADGroup
RoleManagementPolicy.Read.AzureADGroup
DelegatedAdminRelationship.Read.All
Domain.Read.All
Domain-InternalFederation.Read.All
```

> `RoleEligibilitySchedule.Read.Directory` and `RoleAssignmentSchedule.Read.Directory` are **no longer requested**: `RoleManagement.Read.Directory` already covers the PIM schedule-instance reads. If they were consented earlier they do no harm — they are read-only and still accepted.

### A.3 Run it

```powershell
.\EntraAudit-PS7.ps1 -all
```
A browser / WAM sign-in window appears. If that window fails (VS Code terminal, SSH, elevated session), the script automatically retries with a device code. In a terminal with no browser, ask for the device code straight away:
```powershell
.\EntraAudit-PS7.ps1 -all -UseDeviceCode
```

> If the sign-in is missing a permission a check needs, that check is shown as **Skipped: missing permission** (`Skipped-NoScope`, with the missing permission named), or a composite check marks only the affected sub-control **Not assessed**. If Microsoft Graph itself refuses a read (a permission or admin role is missing), the check is **Skipped: access denied** (`Skipped-NoPermission`); if Graph says the tenant is not licensed for the feature, it is **Skipped: no license**. The rest of the audit still runs, and the Posture Summary and `EntraAudit-Run.log` give the reason for each.

### A.4 Optional: sign in through your own read-only app (-DelegatedClientId)

By default, interactive sign-in uses Microsoft's shared **Microsoft Graph Command Line Tools** app. Microsoft Graph gives a sign-in **every permission ever consented to that app** — including write permissions someone consented for unrelated scripts — and the audit then refuses to run ([A.5](#a5-if-the-audit-refuses-to-run-permission-that-is-not-read-only)). A dedicated app registration keeps the audit's sign-in limited to the read-only list above.

1. **Entra admin center → App registrations → New registration.** Name it e.g. `Entra Read-Only Audit (interactive)`. Supported account types: **this organizational directory only** (single tenant).
   **Redirect URI:** platform **Public client/native (mobile & desktop)**, value `http://localhost`.
2. **Authentication → Advanced settings → Allow public client flows = Yes.** This is needed for `-UseDeviceCode` and for the automatic device-code retry.
3. **API permissions → Add a permission → Microsoft Graph → Delegated permissions.** Add exactly the scopes in [A.2](#a2-delegated-scopes-requested-at-sign-in) — nothing that can write.
4. Click **Grant admin consent** (or let an administrator consent at the first sign-in).
5. Run the audit with the app's **Application (client) ID** and your tenant:

```powershell
.\EntraAudit-PS7.ps1 -all -TenantId contoso.onmicrosoft.com -DelegatedClientId 22222222-3333-4444-5555-666666666666
```

> - `-TenantId` is **required** with `-DelegatedClientId`: new app registrations are single-tenant, and Microsoft refuses their sign-in without a tenant (error AADSTS50194). The script stops with a clear message if `-TenantId` is missing or the id is not a GUID.
> - `-DelegatedClientId` is for **interactive** sign-in only; it cannot be combined with `-ClientId` / `-CertificateThumbprint` (app-only, section B).
> - The person signing in still needs the directory roles in [A.1](#a1-directory-roles-for-the-auditor-account); the app only limits which permissions the sign-in can have.
> - In the GUI, enter the app ID in Step 2 under **Own sign-in app ID (optional)** together with the tenant ID or domain.
> - The app id used is recorded in the report's *Run details* and in `Findings.json` (`RunInfo.Settings.DelegatedClientId`).

### A.5 If the audit refuses to run (permission that is not read-only)

Right after sign-in the script checks the sign-in's permission list. If any permission is not clearly read-only, it signs out again and stops (exit code 1) **before any check runs**, with a message like:

```
Refusing to run: this sign-in holds permission(s) that are not read-only -> User.ReadWrite.All. ...
```

Signing in again with fewer scopes does **not** help, because Microsoft Graph keeps every permission ever consented to the app you sign in through. Fix it in one of two ways:

1. **Revoke the extra permissions** from the shared app: Entra admin center → **Enterprise applications** → *Microsoft Graph Command Line Tools* → **Permissions** (both the admin consent and the user consent tabs). Note that this also removes them for anyone else who uses that app for their own scripts.
2. **Or use a dedicated read-only app** and run with `-DelegatedClientId` ([A.4](#a4-optional-sign-in-through-your-own-read-only-app--delegatedclientid)). This leaves the shared app untouched.

If the refusal names **your own** app (`-DelegatedClientId`), remove the listed permissions from that app registration (App registrations → *app* → API permissions) and revoke any consent for them (Enterprise applications → *app* → Permissions), then run again.

---

## B. App-only (unattended) sign-in

For scheduled runs with no human present. You create one dedicated, read-only app registration with a certificate.

### B.1 Create the app registration

1. **Entra admin center → App registrations → New registration.** Name it e.g. `Entra Read-Only Audit Tool`. Single tenant.
2. **API permissions → Add a permission → Microsoft Graph → Application permissions.** Add exactly these (all read-only):

   ```
   Directory.Read.All
   RoleManagement.Read.Directory
   Policy.Read.All
   AuditLog.Read.All
   Application.Read.All
   User.Read.All
   Group.Read.All
   Organization.Read.All
   Device.Read.All
   IdentityRiskyUser.Read.All
   IdentityRiskEvent.Read.All
   IdentityRiskyServicePrincipal.Read.All
   CrossTenantInformation.ReadBasic.All
   OnPremDirectorySynchronization.Read.All
   Reports.Read.All
   RoleManagementPolicy.Read.Directory
   Member.Read.Hidden
   DirectoryRecommendations.Read.All
   SecurityEvents.Read.All
   SecurityAlert.Read.All
   AccessReview.Read.All
   EntitlementManagement.Read.All
   LifecycleWorkflows.Read.All
   PrivilegedAssignmentSchedule.Read.AzureADGroup
   PrivilegedEligibilitySchedule.Read.AzureADGroup
   RoleManagementPolicy.Read.AzureADGroup
   DelegatedAdminRelationship.Read.All
   Domain.Read.All
   Domain-InternalFederation.Read.All
   ```

   > **App-only read-only enforcement (exact allowlist, fail-closed):** on every app-only run the script reads this app's *actual* granted app-role assignments (across all resource APIs) and **refuses to run** unless **every** one is on the list above (plus the two optional PIM scopes in the notes below). It is an allowlist, not a denylist: anything else is refused — write/send/create/delete/update/invite/manage/impersonate or full-control permissions, broad read permissions such as `Mail.Read`, any permission on an API other than Microsoft Graph, **and any unknown or custom app role it cannot resolve**. An app with **no** permissions at all is refused too (almost every check would be skipped). So an accidentally over-permissioned app registration fails closed at startup rather than running with write access. If core read permissions (`Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All`) are missing, the run warns and lists the checks that will be skipped.
3. Click **Grant admin consent**.
4. *(Optional, belt-and-suspenders)* also assign the **Global Reader** directory role to this app's service principal.

> **Notes:**
> - There is no read-only `AppRoleAssignment.Read.All`; this profile authorizes the direct service-principal app-role-assignment reads with `Directory.Read.All`, **not** the write-capable `AppRoleAssignment.ReadWrite.All`.
> - The Terms of Use agreements list currently supports **delegated** `Agreement.Read.All` only. Microsoft publishes an application permission with that name, but the agreements-list operation documents app-only as unsupported. Therefore the unattended permission list deliberately omits it — **do not add it**: it is not on the startup allowlist, so the run would be refused. That sub-control is reported as *Not assessed* in app-only runs.
> - The optional read-only PIM scopes `RoleEligibilitySchedule.Read.Directory` and `RoleAssignmentSchedule.Read.Directory` are accepted by the startup allowlist when already granted (for app registrations set up from an older version of this list), but are not required because `RoleManagement.Read.Directory` covers these reads.
> - In app-only mode `Get-MgContext().Scopes` is sparse, so the script resolves the running app's actual Graph app-role assignments at startup and uses that verified set for per-check permission gates. A later `403` is still recorded as unavailable evidence (*Skipped: access denied* or *Not assessed*) when an API has an additional role, license, or service constraint.
> - The directory-sync settings read ([A.1](#a1-directory-roles-for-the-auditor-account)) may be refused for an app-only sign-in; those sub-controls are then *Not assessed*.

### B.2 Add a certificate

Create a self-signed cert (or use your PKI), upload the **public** key to the app registration, and keep the private key in the audit machine's certificate store:

```powershell
$cert = New-SelfSignedCertificate -Subject "CN=EntraAudit" -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyExportPolicy Exportable -KeySpec Signature -NotAfter (Get-Date).AddMonths(12)
Export-Certificate -Cert $cert -FilePath C:\temp\EntraAudit.cer   # upload this .cer to the app registration
$cert.Thumbprint                                                  # use this with -CertificateThumbprint
```

### B.3 Run it

```powershell
.\EntraAudit-PS7.ps1 -all -NoLaunch `
  -TenantId   contoso.onmicrosoft.com `
  -ClientId   11111111-2222-3333-4444-555555555555 `
  -CertificateThumbprint A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0
```

> `-ClientId` and `-CertificateThumbprint` must be supplied **together**. If only one is given the script stops with an error — it deliberately does **not** fall back to an interactive sign-in prompt, which would hang a scheduled run (and sign in as the wrong identity).
>
> For scheduled runs, check the **exit code** (1 = the run failed: sign-in refused, unknown `-select` id, output not written, …) and keep `EntraAudit-Run.log` from the run folder. The report is never opened automatically in a non-interactive session.

---

## C. Optional Azure diagnostic-setting and alert coverage

The `-monitoring` check always evaluates the Microsoft Graph evidence it can read. To also inventory Microsoft Entra diagnostic exports (where the sign-in and audit logs are sent), Azure Monitor alert rules (scheduled query rules and activity log alerts), action groups, and Microsoft Sentinel analytics rules in Log Analytics workspaces, prepare a **separate, existing read-only Azure context** before starting the audit:

```powershell
Install-Module Az.Accounts -Scope CurrentUser       # one-time, only if not already installed
Connect-AzAccount -Tenant <tenant-id>               # interactive example
Get-AzContext                                       # verify the intended tenant/subscription
.\EntraAudit-PS7.ps1 -monitoring
```

Assign that Azure identity **Monitoring Reader** (or an equally narrow custom role containing the required `*/read` actions) at every subscription whose alert configuration should be inspected. The tenant-scoped `Microsoft.AADIAM/diagnosticSettings` read also needs appropriate read-only Entra/tenant authorization for that Azure-context principal (for example Global Reader or Security Reader where supported). The audit does not create an Azure context, change subscriptions, or install `Az.Accounts`; it only consumes a matching context that is already available, and every ARM call is a `GET`. If any tenant or subscription read permission is absent, the ARM portion is marked **incomplete/manual verification required**, never passed.

The alert for **break-glass sign-ins** is looked for only when you name the accounts with `-BreakGlassUpns`; without them that part is *Not assessed*.

For unattended runs, establish the Azure context with your normal certificate/managed-identity automation before invoking the audit. Keep that identity read-only as well.

---

## Licensing — what each tier unlocks

The script detects your subscriptions (`Get-MgSubscribedSku`) from their enabled **service plans** (so P1/P2 inside EMS / Microsoft 365 bundles is recognised) and shows the result in the Posture Summary's license table. Only subscriptions that can actually serve licenses count: **suspended, deleted or locked-out** subscriptions and subscriptions with **no active licenses** are listed but not counted. A subscription in its **grace period** (status *Warning*) still counts, with a note that the features stop when the grace period ends.

License-gated checks are reported as **Skipped: no license** (`Skipped-NoLicense`), never as "clean". If the SKU read itself **fails**, gated checks are reported as **Skipped: license unknown** (`Skipped-LicenseUnknown`) instead — the tenant may well be licensed, so a failed detection is never presented as "no license". If Microsoft Graph refuses data at run time because the tenant is not licensed (for example Identity Protection after a P2 subscription lapsed), the check is also **Skipped: no license**, with Graph's message as the reason.

| Tier | Unlocks |
|---|---|
| **Entra ID Free** | Most posture checks: roles (classic), accounts, guests, apps, consent grants, Conditional Access inventory, Security Defaults, devices, tenant health. The directory audit log is kept 7 days, so a longer `-RecentChangeDays` window is *Not assessed*. |
| **Entra ID P1** | `signInActivity` and sign-in logs → **stale users**, **legacy auth** and **stale applications** (skipped without P1); also the disabled-account age in `accounts`, the last test sign-in in `breakglass`, inactive guests in `externaldelegation`, and the sign-in/activity portions of `enterpriseapps` and `monitoring` (*Not assessed* without P1). Audit logs are kept 30 days. |
| **Entra ID P2** | **PIM** eligibility/assignment schedules → the permanent-vs-eligible classification and **PIM policy quality** (`pimpolicies`); **Identity Protection** → risky users/detections (`riskyusers`); sign-in-risk and user-risk Conditional Access baselines. |
| **Workload Identities Premium** | Risky **service principals** (`riskyserviceprincipals`) and the workload-identity Conditional Access baselines. `riskyserviceprincipals` is **not skipped** without it: it runs and reports *Incomplete* with a *Not assessed* note. |
| **Entra ID Governance / applicable governance feature licenses** | Access reviews, entitlement management, lifecycle workflows, Terms of Use, and PIM for Groups evidence. The checks still run without these features and report unavailable sub-controls as *Not assessed*. |
| **Applicable Microsoft Defender workload/service licensing** | Microsoft 365 Defender identity-security alert evidence in `monitoring`; this optional sub-control is marked *Not assessed* when the service or license is unavailable. |

> Without P2, the privileged-roles check falls back to classic role assignments (everything appears as **permanent**) and notes that PIM/just-in-time isn't in use — which is itself a finding.

---

## Scope → check reference

This is a per-data-source map, not a promise that the script dynamically requests a smaller delegated token. Interactive runs request the complete read-only scope set in section A.2; app-only runs use the documented application-permission profile in section B.1 and need `Directory.Read.All` for the startup permission self-check.

- **Required by** — the check is **skipped** (*Skipped: missing permission*) when the sign-in does not have this permission. `Directory.Read.All` counts as covering `User.Read.All`, `Group.Read.All`, `Organization.Read.All`, `Device.Read.All` and `Application.Read.All` for this gate.
- **Also used by** — the check still runs without it; the part that needs it is reported as *Not assessed*.

| Scope / permission | Required by | Also used by |
|---|---|---|
| `Directory.Read.All` | consentgrants | underpins most checks; the app-only startup permission self-check; apps, enterpriseapps and workloadcredentials relationships; group-governance lifecycle policy; authrecovery; monitoring provisioning evidence |
| `Organization.Read.All` | tenant-info, tenanthealth | license detection for every check; authrecovery, federationhealth, changemonitoring (audit-log retention) |
| `RoleManagement.Read.Directory` | privroles, directoryroles, breakglass, accesspaths | guests (admin roles), mfa and capolicies (admin list), apps (owner classification), riskyusers and staleusers (admin x-ref), externaldelegation. Also covers the PIM schedule-instance reads |
| `User.Read.All` | accounts, staleusers, guests, recentchanges, breakglass | privroles (guest/on-prem status), mfa, accesspaths, externaldelegation (guest sponsors — plus a directory role, see A.1) |
| `AuditLog.Read.All` | staleusers, mfa, legacyauth, recentchanges, staleapps, monitoring, changemonitoring | accounts (disabled-account age), breakglass (last sign-in), guests, authrecovery, externaldelegation, enterpriseapps |
| `Policy.Read.All` | tenantposture, capolicies, trusts, authmethodpolicy | guests, breakglass, pimpolicies and accesspaths (Conditional Access), authrecovery, workloadcredentials, identitygovernance, consentgrants (admin consent workflow) |
| `Application.Read.All` | apps, appcredentials, staleapps, workloadcredentials, enterpriseapps | |
| `Group.Read.All` | accesspaths, groupgovernance | apps, guests, recentchanges, accessreviews, identitygovernance, capolicies (group-based exclusions) |
| `Device.Read.All` | devices | |
| `IdentityRiskyUser.Read.All` | riskyusers | |
| `IdentityRiskEvent.Read.All` | | riskyusers (recent detections), monitoring (optional risk-detection evidence) |
| `IdentityRiskyServicePrincipal.Read.All` | riskyserviceprincipals | |
| `CrossTenantInformation.ReadBasic.All` | | trusts (partner names; tenant ids are shown otherwise) |
| `OnPremDirectorySynchronization.Read.All` | tenanthealth | authrecovery, federationhealth (hybrid sync settings, see A.1) |
| `Reports.Read.All` | | groupgovernance (Microsoft 365 group activity) |
| `RoleManagementPolicy.Read.Directory` | pimpolicies | |
| `Member.Read.Hidden` | | accesspaths, breakglass, capolicies (expand hidden-membership groups) |
| `DirectoryRecommendations.Read.All` | recommendations | |
| `SecurityEvents.Read.All` | securescore | |
| `SecurityAlert.Read.All` | | monitoring (Microsoft 365 Defender alert evidence) |
| `AccessReview.Read.All` | accessreviews | |
| `EntitlementManagement.Read.All` | | identitygovernance (catalogs, access packages and assignments) |
| `LifecycleWorkflows.Read.All` | | identitygovernance (lifecycle workflows) |
| `Agreement.Read.All` | | identitygovernance (Terms of Use; delegated only, so app-only reports this sub-control *Not assessed*) |
| `PrivilegedAssignmentSchedule.Read.AzureADGroup` / `PrivilegedEligibilitySchedule.Read.AzureADGroup` | | identitygovernance (PIM for Groups assignment/eligibility schedules) |
| `RoleManagementPolicy.Read.AzureADGroup` | | identitygovernance (PIM for Groups policy rules) |
| `DelegatedAdminRelationship.Read.All` | | externaldelegation (GDAP relationships) |
| `Domain.Read.All` | federationhealth | |
| `Domain-InternalFederation.Read.All` | | federationhealth (federation settings and signing certificates) |

> **Least-privilege note:** the `-authmethodpolicy` and `-authrecovery` checks are satisfied by the broad `Policy.Read.All` (which the tool already requests for the CA / posture checks). In a separately maintained subset profile, `Policy.Read.AuthenticationMethod` is the least-privileged Graph permission for reading the authentication-methods policy — but note that the audit's own gate for `-authmethodpolicy` checks for `Policy.Read.All`.

---

## Verifying it's read-only

Right after sign-in, before any check runs, the script inspects the permissions on the sign-in and **stops** (signing out again, exit code 1) unless all of them are read-only:

- **Interactive (delegated) — allow-list, fail-closed.** Every scope in `Get-MgContext().Scopes` must be *recognisably* read-only: one part of its name is exactly `Read`, `ReadBasic` or `ReadFor…` (for example `Directory.Read.All`, `Member.Read.Hidden`, `CrossTenantInformation.ReadBasic.All`), **and** it contains no write or action word — `ReadWrite`, `.Write`, `.Send`, `.Create`, `.Delete`, `.Update`, `.Invite`, `.Manage…`, `PrivilegedOperations`, `ManageAsApp`, `AccessAsUser`, `FullControl`, `full_access`, `Impersonation`, `EnableDisableAccount`, `RevokeSessions`, `Command`, `Export`, `.Selected`, `Restore`, `Assign…`, `Migrate…`, `Submit…`, `Execute…`, `Invoke…`, `Remove…`, `Reset…`, `Approve…`. The sign-in scopes `openid`, `profile`, `email` and `offline_access` are also allowed. Anything else, including a permission shape the script does not recognise, is refused — a deny list could never name every current and future write permission. An **empty** permission list is refused too, because the guarantee cannot be verified. See [A.5](#a5-if-the-audit-refuses-to-run-permission-that-is-not-read-only) for how to fix a refusal.
- **App-only — exact allowlist.** The app's actual granted application permissions must all be on the list in [B.1](#b1-create-the-app-registration) (see the enforcement note there).

You can confirm at any time:

```powershell
(Get-MgContext).Scopes      # should be only *.Read.* / *.ReadBasic.* entries (plus openid, profile, email, offline_access)
```

The permissions the sign-in actually had are also recorded in every report's **Run details** and in `Findings.json` (`RunInfo.GrantedScopes`).

Every tenant/API call in the audit is a read (`Get-Mg*` / `Get-Az*` cmdlets, `Invoke-MgGraphRequest -Method GET`, and Azure Resource Manager `GET` via `Invoke-AzRestMethod`). Graph page links are followed only when they point back to `https://graph.microsoft.com`. No `New-`, `Set-`, `Update-`, `Remove-`, `Add-`, `Revoke-` or `Disable-` Graph/Azure management cmdlet is used by an audit check. (A few *What to do* texts show an `Update-Mg…` command for the operator to run where the admin center has no switch; the audit itself never runs them.)
