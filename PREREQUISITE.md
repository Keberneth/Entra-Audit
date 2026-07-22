# PREREQUISITE — Permissions & Setup for EntraAudit-PS7

This document lists exactly what EntraAudit-PS7 needs to run. All **audit/data-collection API calls are read-only**: the tool requests only documented Graph read permissions, issues only `GET` requests, and **refuses to run if it is ever granted a write-capable Graph permission**. Optional Azure-monitoring enrichment also uses retrieval-only Azure Resource Manager calls. First-time interactive OAuth consent is a separate operator-authorized setup grant for the requested read permissions; pre-consent them before the audit window when literal zero setup changes during execution is required.

There are two ways to authenticate — pick one:

- **A. Interactive (delegated)** — an admin signs in. Best for ad-hoc audits. → [Section A](#a-interactive-delegated-sign-in)
- **B. App-only (certificate)** — a dedicated app registration, no human. Best for scheduled/unattended runs. → [Section B](#b-app-only-unattended-sign-in)

---

## 0. Software prerequisites

- **PowerShell 7.x** (`pwsh.exe`) on Windows.
- `EntraAudit-PS7.ps1` and both companion check libraries (`EntraAudit-Checks-Governance.ps1` and `EntraAudit-Checks-Applications.ps1`) in the same folder. Keep `EntraAudit-GUI.ps1` there too when using the GUI.
- **Microsoft Graph PowerShell SDK v2.x** — the script uses these sub-modules (not the giant meta-module):

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
  | `Microsoft.Graph.DirectoryObjects` | resolve `id`-only directory object references |

### Install the modules

**Online (simplest):**
```powershell
.\EntraAudit-PS7.ps1 -installdeps
```
or manually (pin to v2.x, like `-installdeps` does, so sub-module majors can't mix):
```powershell
$modules = @(
  'Microsoft.Graph.Authentication','Microsoft.Graph.Identity.DirectoryManagement',
  'Microsoft.Graph.Identity.SignIns','Microsoft.Graph.Identity.Governance',
  'Microsoft.Graph.Users','Microsoft.Graph.Groups','Microsoft.Graph.Applications',
  'Microsoft.Graph.Reports','Microsoft.Graph.DirectoryObjects')
Install-Module $modules -Scope CurrentUser -Repository PSGallery -Force `
  -MinimumVersion 2.0.0 -MaximumVersion 2.999.999
```

**Offline (air-gapped):** on an internet-connected machine, run `Save-Module` into a folder, copy the folder across, then point the script at it:
```powershell
# online machine
Save-Module Microsoft.Graph.Authentication,Microsoft.Graph.Identity.DirectoryManagement,`
  Microsoft.Graph.Identity.SignIns,Microsoft.Graph.Identity.Governance,Microsoft.Graph.Users,`
  Microsoft.Graph.Groups,Microsoft.Graph.Applications,Microsoft.Graph.Reports,Microsoft.Graph.DirectoryObjects `
  -Path C:\GraphModules -Repository PSGallery

# audit machine (copy C:\GraphModules across first)
.\EntraAudit-PS7.ps1 -all -ModulesPath C:\GraphModules
```

`-ModulesPath` also works together with `-installdeps`: the installer sees the offline modules and skips the gallery download instead of trying to go online.

> Keep all Microsoft.Graph sub-modules at the **same version** to avoid assembly-load conflicts. `-installdeps` pins to v2.x and the script warns at import time if it finds mixed majors.

---

## A. Interactive (delegated) sign-in

### A.1 Directory roles for the auditor account

Assign the account these two **read-only** directory roles. Together they cover nearly all Microsoft Graph evidence with zero write ability; the optional Azure-monitoring enrichment is covered separately in [Section C](#c-optional-azure-diagnostic-setting-and-alert-coverage):

| Role | Why |
|---|---|
| **Global Reader** | Read-only mirror of Global Administrator: configuration, policies, applications, directory objects, sync status. |
| **Security Reader** | Identity Protection (risky users/detections), security policies, Secure Score. |

Do **not** use Global Administrator. One documented exception remains: tenant-wide delegated `federatedIdentityCredentials` enumeration does not list Global Reader or Security Reader as supported roles. The `workloadcredentials` check reports that relationship evidence as incomplete rather than clean. Use the read-only **app-only** mode with `Application.Read.All` when complete tenant-wide federated-credential coverage is required; do not grant a write-capable application-admin role merely to run an audit.

### A.2 Delegated scopes requested at sign-in

The script requests exactly these (all read-only). On first run, an administrator consents once for the tenant:

```
Directory.Read.All
AuditLog.Read.All
Policy.Read.All
RoleManagement.Read.Directory
RoleEligibilitySchedule.Read.Directory
RoleAssignmentSchedule.Read.Directory
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

### A.3 Run it

```powershell
.\EntraAudit-PS7.ps1 -all
```
A browser / WAM sign-in window appears. In a terminal with no browser (SSH, some VS Code setups), use:
```powershell
.\EntraAudit-PS7.ps1 -all -UseDeviceCode
```

> If the auditor account is missing a scope, the affected check is shown as **Skipped-NoScope**, or a composite check marks only the affected sub-control **Incomplete**. The rest of the audit still runs.

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

   > **App-only read-only enforcement (allowlist, fail-closed):** on every app-only run the script reads this app's *actual* granted app-role assignments (across all resource APIs) and **refuses to run** unless **every** one is clearly read-only. It is an allowlist, not a denylist: anything that writes/sends/creates/deletes/updates/invites/manages/impersonates or grants full control — **and any unknown or custom app role it cannot resolve** — is treated as unsafe. So an accidentally over-permissioned app registration fails closed at startup rather than running with write access.
3. Click **Grant admin consent**.
4. *(Optional, belt-and-suspenders)* also assign the **Global Reader** directory role to this app's service principal.

> **Notes:**
> - There is no read-only `AppRoleAssignment.Read.All`; this profile authorizes the direct service-principal app-role-assignment reads with `Directory.Read.All`, **not** the write-capable `AppRoleAssignment.ReadWrite.All`.
> - The Terms of Use agreements list currently supports **delegated** `Agreement.Read.All` only. Microsoft publishes an application permission with that name, but the agreements-list operation documents app-only as unsupported. Therefore the unattended permission list deliberately omits it, and that sub-control is reported as incomplete in app-only runs.
> - The optional read-only PIM scopes `RoleEligibilitySchedule.Read.Directory` and `RoleAssignmentSchedule.Read.Directory` are accepted by the startup allowlist when already granted, but are not required in the list above because `RoleManagement.Read.Directory` covers these reads in app-only mode.
> - In app-only mode `Get-MgContext().Scopes` is sparse, so the script resolves the running app's actual Graph app-role assignments at startup and uses that verified set for per-check scope gates. A later `403` is still recorded as unavailable evidence when an API has an additional role, license, or service constraint.

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

---

## C. Optional Azure diagnostic-setting and alert coverage

The `-monitoring` check always evaluates the Microsoft Graph evidence it can read. To also inventory Microsoft Entra diagnostic exports and Azure Monitor scheduled-query alert rules, prepare a **separate, existing read-only Azure context** before starting the audit:

```powershell
Install-Module Az.Accounts -Scope CurrentUser       # one-time, only if not already installed
Connect-AzAccount -Tenant <tenant-id>               # interactive example
Get-AzContext                                       # verify the intended tenant/subscription
.\EntraAudit-PS7.ps1 -monitoring
```

Assign that Azure identity **Monitoring Reader** (or an equally narrow custom role containing the required `*/read` actions) at every subscription whose alert configuration should be inspected. The tenant-scoped `Microsoft.AADIAM/diagnosticSettings` read also needs appropriate read-only Entra/tenant authorization for that Azure-context principal (for example Global Reader or Security Reader where supported). The audit does not create an Azure context, change subscriptions, or install `Az.Accounts`; it only consumes a matching context that is already available. If any tenant or subscription read permission is absent, the ARM portion is marked **incomplete/manual verification required**, never passed.

For unattended runs, establish the Azure context with your normal certificate/managed-identity automation before invoking the audit. Keep that identity read-only as well.

---

## Licensing — what each tier unlocks

The script detects your SKUs (`Get-MgSubscribedSku`) and records the tier in the report. License-gated checks are reported as **Skipped-NoLicense**, never as "clean". If the SKU read itself **fails**, gated checks are reported as **Skipped-LicenseUnknown** instead — the tenant may well be licensed, so a failed detection is never presented as "no license".

| Tier | Unlocks |
|---|---|
| **Entra ID Free** | Most posture checks: roles (classic), accounts, guests, apps, consent grants, Conditional Access inventory, Security Defaults, devices, tenant health. |
| **Entra ID P1** | `signInActivity` and sign-in logs → **stale users**, **legacy auth**, and **stale applications**; also enriches sign-in/activity portions of enterprise-app, external-delegation, and monitoring checks. |
| **Entra ID P2** | **PIM** eligibility/assignment schedules → the permanent-vs-eligible classification; **Identity Protection** → risky users/detections. |
| **Workload Identities Premium** | Risky **service principals**. |
| **Entra ID Governance / applicable governance feature licenses** | Access reviews, entitlement management, lifecycle workflows, Terms of Use, and PIM for Groups evidence. The checks still run without these features and report unavailable sub-controls as incomplete. |
| **Applicable Microsoft Defender workload/service licensing** | Microsoft 365 Defender identity-security alert evidence in `monitoring`; this optional sub-control is marked incomplete when the service or license is unavailable. |

> Without P2, the privileged-roles check falls back to classic role assignments (everything appears as **permanent**) and notes that PIM/just-in-time isn't in use — which is itself a finding.

---

## Scope → check reference

This is a per-data-source map, not a promise that the script dynamically requests a smaller delegated token. Interactive runs request the complete read-only scope set in section A.2; app-only runs use the documented application-permission profile and need `Directory.Read.All` for the startup permission self-check. The map is useful when reviewing why a scope exists or designing a separately maintained subset profile:

| Scope / permission | Checks |
|---|---|
| `Directory.Read.All` | underpins most; tenant info, accounts, guests, posture, apps, consentgrants, workload/enterprise-app relationships and delegated grants, devices, recent changes, health, group-governance lifecycle policy, monitoring provisioning evidence, and the app-only startup permission self-check |
| `Organization.Read.All` | tenant-info, tenanthealth, authrecovery, federationhealth |
| `RoleManagement.Read.Directory` | privroles, directoryroles, accesspaths, breakglass, guests (priv), mfa (admin x-ref), apps (group roles), riskyusers (priv x-ref), staleusers (priv x-ref), externaldelegation |
| `RoleEligibilitySchedule.Read.Directory` + `RoleAssignmentSchedule.Read.Directory` | privroles, directoryroles (PIM instances) |
| `User.Read.All` | accounts, staleusers, guests, recentchanges, externaldelegation |
| `AuditLog.Read.All` | staleusers, mfa, legacyauth, recentchanges, guests, staleapps, authrecovery, externaldelegation, enterpriseapps, monitoring, changemonitoring |
| `Policy.Read.All` | tenantposture, capolicies, trusts, guests, authrecovery, workloadcredentials, identitygovernance |
| `Application.Read.All` | apps, appcredentials, staleapps, workloadcredentials, enterpriseapps |
| `Group.Read.All` | accesspaths, guests, apps, recentchanges, accessreviews, groupgovernance, identitygovernance |
| `Device.Read.All` | devices |
| `IdentityRiskyUser.Read.All` | riskyusers |
| `IdentityRiskEvent.Read.All` | riskyusers, monitoring (optional risk-detection evidence) |
| `IdentityRiskyServicePrincipal.Read.All` | riskyserviceprincipals (gated on Workload Identities Premium, not P2) |
| `CrossTenantInformation.ReadBasic.All` | trusts (partner resolution) |
| `OnPremDirectorySynchronization.Read.All` | tenanthealth, authrecovery, federationhealth |
| `Reports.Read.All` | mfa (registration report alt), groupgovernance activity |
| `RoleManagementPolicy.Read.Directory` | pimpolicies (PIM activation policy rules) |
| `Member.Read.Hidden` | accesspaths (expand hidden-membership groups; optional) |
| `DirectoryRecommendations.Read.All` | recommendations |
| `SecurityEvents.Read.All` | securescore |
| `SecurityAlert.Read.All` | monitoring (Microsoft 365 Defender alert evidence; optional when the service/license is unavailable) |
| `AccessReview.Read.All` | accessreviews |
| `EntitlementManagement.Read.All` | identitygovernance (catalogs, access packages and assignments) |
| `LifecycleWorkflows.Read.All` | identitygovernance (lifecycle workflows) |
| `Agreement.Read.All` | identitygovernance (Terms of Use; delegated operation only, so app-only reports this sub-control incomplete) |
| `PrivilegedAssignmentSchedule.Read.AzureADGroup` / `PrivilegedEligibilitySchedule.Read.AzureADGroup` | identitygovernance (PIM for Groups assignment/eligibility schedules) |
| `RoleManagementPolicy.Read.AzureADGroup` | identitygovernance (PIM for Groups policy rules) |
| `DelegatedAdminRelationship.Read.All` | externaldelegation (GDAP relationships) |
| `Domain.Read.All` / `Domain-InternalFederation.Read.All` | federationhealth |

> **Least-privilege note:** the `-authmethodpolicy` and `-authrecovery` checks are satisfied by the broad `Policy.Read.All` (which the tool already requests for the CA / posture checks). In a separately maintained subset profile, `Policy.Read.AuthenticationMethod` is the least-privileged Graph permission for reading the authentication-methods policy.

---

## Verifying it's read-only

At startup the script calls `Get-MgContext` and **aborts** if any granted scope matches a write-capable token: `ReadWrite`, `.Write`, `.Send`, `.Create`, `.Delete`, `.Update`, `.Invite`, `.Manage` (e.g. `Sites.Manage.All`, `User.ManageIdentities.All`), `PrivilegedOperations`, `ManageAsApp`, `AccessAsUser`, `FullControl`, `full_access` or `Impersonation`. You can confirm at any time:

```powershell
(Get-MgContext).Scopes      # should be all *.Read.* entries
```

Every tenant/API call in the audit is a read (`Get-Mg*` / `Get-Az*` cmdlets, `Invoke-MgGraphRequest -Method GET`, and Azure Resource Manager `GET`). No `New-`, `Set-`, `Update-`, `Remove-`, `Add-`, `Revoke-` or `Disable-` Graph/Azure management cmdlet is used by an audit check.
