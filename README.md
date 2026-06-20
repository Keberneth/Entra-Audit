# EntraAudit-PS7 — Microsoft Entra ID (Azure AD) Read-Only Security Audit

A PowerShell 7 + Microsoft Graph audit tool that mirrors the on-prem ADAudit-PS7 audit and produces the **same style of HTML reports**. It is the cloud counterpart to the Active Directory audit: same severity model (Critical / High / Medium / Low / Information), same filterable finding cards with *Why it matters* / *Recommended action* / source-evidence links, the same executive **Risk-Report**, and a **Posture-Summary** that plays the role of the AD Health report.

Its flagship capability is auditing **privileged role assignments by activation model** — every privileged role is classified as **Permanent (standing)** vs **Eligible (PIM)** vs **Time-bound active**. A *permanent* Global Administrator is flagged as a risk; the same role held as *eligible* (activated just-in-time through PIM) is the desired posture and is **not** flagged.

> ## 🔒 Read-only by design
> This tool **only reads** from Microsoft Graph. It requests only `*.Read.*` scopes, issues only `GET` requests, and **aborts at startup if any write-capable scope is granted**. It never creates, modifies, activates, revokes, assigns or deletes anything. Every "Recommended action" in the reports is advisory guidance for a human operator — the tool performs no management.

---

## Quick start

**GUI** — pick sign-in mode, choose checks, install modules, preview and run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\EntraAudit-GUI.ps1
```

**Command line — run every check (recommended):**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\EntraAudit-PS7.ps1 -all
```

You'll be prompted to sign in. Use an account with **Global Reader + Security Reader** (read-only) — see [PREREQUISITE.md](PREREQUISITE.md). Install the Microsoft Graph modules first if you don't have them:

```powershell
.\EntraAudit-PS7.ps1 -installdeps -all
```

---

## Requirements

- **PowerShell 7.x** on Windows (`pwsh.exe`)
- **Microsoft Graph PowerShell SDK v2.x** (installed via `-installdeps`, or see [PREREQUISITE.md](PREREQUISITE.md) for offline install)
- A read-only auditor identity:
  - **Interactive:** an account with the **Global Reader** and **Security Reader** directory roles (recommended), or any account that can consent to the read-only scopes.
  - **App-only / unattended:** a dedicated app registration with the read-only **application** permissions and a certificate.
- Some checks need premium licensing (the tool detects this and marks gated checks as *Skipped-NoLicense* rather than reporting them clean):
  - **Entra ID P1** — sign-in activity (stale users, legacy auth).
  - **Entra ID P2** — PIM eligibility data and Identity Protection (risky users).

Full permission and licensing detail is in **[PREREQUISITE.md](PREREQUISITE.md)**.

---

## Output

Results are written to a tenant-named, timestamped folder (mirrors the AD audit layout):

```
<TenantName>-EntraAudit-<yyyyMMdd-HHmm>\
   HTML Reports\
      EntraAudit-Results.html     # all findings, grouped by severity, filterable
      Risk-Report.html            # executive 0-100 score, band matrix, top risks
      Posture-Summary.html        # per-check status grid + licensing/coverage
   Raw Data\Source\
      privileged_roles.csv/.txt   # one evidence file per check (full data)
      accounts.csv/.txt
      conditional_access.csv/.txt
      ... (etc.)
```

The three reports share a top navigation bar (Audit Results · Risk Report · Posture Summary) and a light/dark theme toggle, exactly like the AD reports. Each finding links to its raw evidence file under `Raw Data\Source\` for technician hand-off. Raw evidence is written for **every** check, even ones that pass, so you always have the underlying data.

---

## Audit checks

| Switch | Description | Notes |
|---|---|---|
| `-tenantinfo` | Tenant / organization overview, verified domains, licensing | |
| `-privroles` | **Privileged roles — permanent (risk) vs eligible (PIM) vs time-bound** | flagship; PIM data needs **P2** |
| `-directoryroles` | Global Admin count & privileged assignment volume | |
| `-accounts` | Account hygiene: disabled-but-licensed, non-expiring passwords, sync split | |
| `-staleusers` | Stale / inactive / never-signed-in users | needs **P1** |
| `-guests` | Guest / external user governance, privileged guests | |
| `-mfa` | MFA capability & authentication-method strength | |
| `-legacyauth` | Legacy authentication usage (sign-in logs) | needs **P1** |
| `-tenantposture` | Security Defaults, authorization policy & consent settings | |
| `-capolicies` | Conditional Access policy posture | |
| `-riskyusers` | Identity Protection: risky users / detections / risky SPs | needs **P2** |
| `-apps` | App / service principal hygiene, over-privilege, credentials, shadow creds | |
| `-consentgrants` | OAuth2 delegated consent grants (illicit consent risk) | |
| `-devices` | Stale / unmanaged / non-compliant devices | |
| `-trusts` | Cross-tenant access & B2B trust | |
| `-recentchanges` | Recently created users/groups & directory audit | |
| `-tenanthealth` | Directory-sync / Password Hash Sync platform health | hybrid only |

### How the AD audit maps to the Entra audit

| On-prem AD audit | Entra equivalent |
|---|---|
| Domain Admins / privileged group review | `-privroles`, `-directoryroles` (permanent vs eligible) |
| Account issues (disabled, never-expire) | `-accounts` |
| Inactive accounts / computers | `-staleusers`, `-devices` |
| Password policy / quality | `-accounts`, `-mfa`, `-tenantposture` |
| Recent changes (new users/groups) | `-recentchanges` |
| Dangerous ACLs / Kerberoast / delegation | `-apps` (over-privileged app permissions), `-consentgrants` |
| GPO / domain hardening posture | `-capolicies`, `-tenantposture` (Security Defaults, CA) |
| Domain trusts | `-trusts` (cross-tenant access) |
| AD health (replication, sync) | `-tenanthealth` (directory sync / PHS) |
| — (cloud-only) | `-legacyauth`, `-riskyusers`, `-guests` |

---

## Run modes & switches

| Switch | Description |
|---|---|
| `-all` | Run all checks (recommended) |
| `-exclude <ids>` | Comma-separated checks to skip with `-all` (e.g. `-exclude legacyauth,devices`) |
| `-select <ids>` | Comma-separated check ids to run (e.g. `-select privileged-roles,mfa`) |
| `-installdeps` | Install the Microsoft Graph SDK modules (CurrentUser scope) |

> `-select` uses the **check ids** shown in the Posture-Summary (`privileged-roles`, `directory-roles`, `tenant-info`, …). The individual `-switch` form (`-privroles`, `-mfa`, …) is the convenient alias.

### Sign-in

| Switch | Description |
|---|---|
| *(none)* | Interactive delegated sign-in (browser / WAM) |
| `-UseDeviceCode` | Interactive device-code sign-in (for terminals without a browser) |
| `-TenantId <id>` | Target a specific tenant |
| `-ClientId <appId>` + `-CertificateThumbprint <thumb>` | App-only (unattended) sign-in |

### Tuning

| Switch | Description |
|---|---|
| `-InactiveDays <n>` | Inactivity threshold for stale users/devices (default 90) |
| `-ExpiringCredentialDays <n>` | Warn on app credentials expiring within N days (default 30) |
| `-RecentChangeDays <n>` | Window for recently-created principals (default 30) |
| `-BreakGlassUpns <upns>` | Cloud-only emergency-access Global Admins to treat as expected-permanent |
| `-OutputRoot <path>` | Where to write the report folder (default: script folder) |
| `-ModulesPath <path>` | Offline: folder containing `Save-Module` output |
| `-NoLaunch` | Do not auto-open the report when finished |

---

## Examples

Run everything:
```powershell
.\EntraAudit-PS7.ps1 -all
```

Run everything except the log-heavy checks, naming the break-glass accounts:
```powershell
.\EntraAudit-PS7.ps1 -all -exclude legacyauth -BreakGlassUpns "bg1@contoso.com;bg2@contoso.com"
```

Just the privileged-access picture:
```powershell
.\EntraAudit-PS7.ps1 -privroles -directoryroles -mfa
```

Unattended (app-only, certificate), don't open a browser window:
```powershell
.\EntraAudit-PS7.ps1 -all -NoLaunch `
  -TenantId contoso.onmicrosoft.com `
  -ClientId 11111111-2222-3333-4444-555555555555 `
  -CertificateThumbprint A1B2C3D4E5F6...
```

---

## How the risk score works

The Risk-Report starts at **100** and deducts per finding by severity (with caps so a few criticals dominate but volume still matters). **Any Critical finding caps the score at 49** — you cannot be "green" with an active tenant-takeover-class risk.

| Score | Band |
|---|---|
| 90–100 | Excellent |
| 75–89 | Good |
| 50–74 | Fair |
| 25–49 | Poor |
| 0–24 | Critical |

---

## Notes & limitations

- **Read-only guarantee:** the script self-aborts if Graph ever returns a write scope. Remediation is always left to the operator.
- **License gating:** P1/P2-gated checks are reported as *Skipped-NoLicense*, never as "clean". Check the Posture-Summary for coverage.
- **Sign-in logs** are retained ~30 days; the legacy-auth check only sees that window.
- A few signals (on-prem banned-password configuration, some Identity Protection detail) are not fully exposed by Graph read APIs and are reported with that caveat.

See **[PREREQUISITE.md](PREREQUISITE.md)** for the exact Graph permissions, the recommended read-only roles, and app-registration setup.
