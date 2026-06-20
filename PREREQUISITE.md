# PREREQUISITE — Permissions & Setup for EntraAudit-PS7

This document lists exactly what EntraAudit-PS7 needs to run. Everything here is **read-only**. The tool requests only `*.Read.*` Graph scopes, issues only `GET` requests, and **refuses to run if it is ever granted a write-capable scope**.

There are two ways to authenticate — pick one:

- **A. Interactive (delegated)** — an admin signs in. Best for ad-hoc audits. → [Section A](#a-interactive-delegated-sign-in)
- **B. App-only (certificate)** — a dedicated app registration, no human. Best for scheduled/unattended runs. → [Section B](#b-app-only-unattended-sign-in)

---

## 0. Software prerequisites

- **PowerShell 7.x** (`pwsh.exe`) on Windows.
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
or manually:
```powershell
$modules = @(
  'Microsoft.Graph.Authentication','Microsoft.Graph.Identity.DirectoryManagement',
  'Microsoft.Graph.Identity.SignIns','Microsoft.Graph.Identity.Governance',
  'Microsoft.Graph.Users','Microsoft.Graph.Groups','Microsoft.Graph.Applications',
  'Microsoft.Graph.Reports','Microsoft.Graph.DirectoryObjects')
Install-Module $modules -Scope CurrentUser -Repository PSGallery -Force
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

> Keep all Microsoft.Graph sub-modules at the **same version** to avoid assembly-load conflicts.

---

## A. Interactive (delegated) sign-in

### A.1 Directory roles for the auditor account

Assign the account these two **read-only** roles (together they cover every check with zero write ability):

| Role | Why |
|---|---|
| **Global Reader** | Read-only mirror of Global Administrator: configuration, policies, applications, directory objects, sync status. |
| **Security Reader** | Identity Protection (risky users/detections), security policies, Secure Score. |

No other role is required. Do **not** use Global Administrator — Global Reader is sufficient and keeps the audit demonstrably read-only.

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
DelegatedPermissionGrant.Read.All
Device.Read.All
IdentityRiskyUser.Read.All
IdentityRiskEvent.Read.All
IdentityRiskyServicePrincipal.Read.All
CrossTenantInformation.ReadBasic.All
OnPremDirectorySynchronization.Read.All
Reports.Read.All
RoleManagementPolicy.Read.Directory
Member.Read.Hidden
```

### A.3 Run it

```powershell
.\EntraAudit-PS7.ps1 -all
```
A browser / WAM sign-in window appears. In a terminal with no browser (SSH, some VS Code setups), use:
```powershell
.\EntraAudit-PS7.ps1 -all -UseDeviceCode
```

> If the auditor account is missing a scope, only the checks that need it are skipped (shown as **Skipped-NoScope** in the Posture-Summary) — the rest of the audit still runs.

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
   DelegatedPermissionGrant.Read.All
   Device.Read.All
   IdentityRiskyUser.Read.All
   IdentityRiskEvent.Read.All
   IdentityRiskyServicePrincipal.Read.All
   CrossTenantInformation.ReadBasic.All
   OnPremDirectorySynchronization.Read.All
   Reports.Read.All
   RoleManagementPolicy.Read.Directory
   Member.Read.Hidden
   ```

   > **App-only read-only enforcement (allowlist, fail-closed):** on every app-only run the script reads this app's *actual* granted app-role assignments (across all resource APIs) and **refuses to run** unless **every** one is clearly read-only. It is an allowlist, not a denylist: anything that writes/sends/creates/deletes/updates/invites/manages/impersonates or grants full control — **and any unknown or custom app role it cannot resolve** — is treated as unsafe. So an accidentally over-permissioned app registration fails closed at startup rather than running with write access.
3. Click **Grant admin consent**.
4. *(Optional, belt-and-suspenders)* also assign the **Global Reader** directory role to this app's service principal.

> **Notes:**
> - There is no read-only `AppRoleAssignment.Read.All`; the app-role-assignment reads are covered by `Directory.Read.All` (read via `$expand`), **not** the write-capable `AppRoleAssignment.ReadWrite.All`.
> - The fine-grained PIM scopes (`RoleEligibilitySchedule.Read.Directory` / `RoleAssignmentSchedule.Read.Directory`) aren't consistently offered as **application** permissions — `RoleManagement.Read.Directory` covers PIM reads in app-only mode.
> - In app-only mode `Get-MgContext().Scopes` is sparse, so the script treats a runtime `403` as the authoritative "permission/license missing" signal and skips that check.

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

---

## Licensing — what each tier unlocks

The script detects your SKUs (`Get-MgSubscribedSku`) and records the tier in the report. License-gated checks are reported as **Skipped-NoLicense**, never as "clean".

| Tier | Unlocks |
|---|---|
| **Entra ID Free** | Most posture checks: roles (classic), accounts, guests, apps, consent grants, Conditional Access inventory, Security Defaults, devices, tenant health. |
| **Entra ID P1** | `signInActivity` → **stale users**; sign-in logs → **legacy auth**. |
| **Entra ID P2** | **PIM** eligibility/assignment schedules → the permanent-vs-eligible classification; **Identity Protection** → risky users/detections. |
| **Workload Identities Premium** | Risky **service principals**. |

> Without P2, the privileged-roles check falls back to classic role assignments (everything appears as **permanent**) and notes that PIM/just-in-time isn't in use — which is itself a finding.

---

## Scope → check reference

If you want to grant the absolute minimum for a subset of checks, this maps each scope to the checks that need it:

| Scope / permission | Checks |
|---|---|
| `Directory.Read.All` | underpins most; tenant info, accounts, guests, posture, apps, devices, recent changes, health |
| `Organization.Read.All` | tenant-info, tenanthealth |
| `RoleManagement.Read.Directory` | privroles, directoryroles, breakglass, guests (priv), mfa (admin x-ref), apps (group roles), riskyusers (priv x-ref) |
| `RoleEligibilitySchedule.Read.Directory` + `RoleAssignmentSchedule.Read.Directory` | privroles, directoryroles (PIM instances) |
| `User.Read.All` | accounts, staleusers, guests, recentchanges |
| `AuditLog.Read.All` | staleusers, mfa (registration report), legacyauth, recentchanges, guests, staleapps (service-principal sign-in activity, beta report) |
| `Policy.Read.All` | tenantposture, capolicies, trusts, guests (guest policy) |
| `Application.Read.All` | apps |
| `DelegatedPermissionGrant.Read.All` | consentgrants |
| `Group.Read.All` | guests, apps (role-assignable groups), recentchanges |
| `Device.Read.All` | devices |
| `IdentityRiskyUser.Read.All` / `IdentityRiskEvent.Read.All` | riskyusers |
| `IdentityRiskyServicePrincipal.Read.All` | riskyserviceprincipals (gated on Workload Identities Premium, not P2) |
| `CrossTenantInformation.ReadBasic.All` | trusts (partner resolution) |
| `OnPremDirectorySynchronization.Read.All` | tenanthealth |
| `Reports.Read.All` | mfa (registration report alt), usage |
| `RoleManagementPolicy.Read.Directory` | pimpolicies (PIM activation policy rules) |
| `Member.Read.Hidden` | accesspaths (expand hidden-membership groups; optional) |

> **Least-privilege note:** the `-authmethodpolicy` check is satisfied by the broad `Policy.Read.All` (which the tool already requests for the CA / posture checks). If you want to grant the narrowest possible permission for it instead, `Policy.Read.AuthenticationMethod` is the least-privileged Graph permission for reading the authentication-methods policy.

---

## Verifying it's read-only

At startup the script calls `Get-MgContext` and **aborts** if any granted scope matches `ReadWrite`, `.Write`, `AccessAsUser`, or `FullControl`. You can confirm at any time:

```powershell
(Get-MgContext).Scopes      # should be all *.Read.* entries
```

Every Graph call in the script is a read (`Get-Mg*` cmdlets and `Invoke-MgGraphRequest -Method GET`). No `New-`, `Set-`, `Update-`, `Remove-`, `Add-`, `Revoke-` or `Disable-` Graph cmdlet is used anywhere.
