# EntraAudit-PS7 — Microsoft Entra ID (Azure AD) Read-Only Security Audit

## In short

1. Run the GUI: `.\EntraAudit-GUI.ps1`
2. Click **Install Graph Modules** (one-time).
3. Click **Run Audit** and **sign in** on the page that opens with an account that has enough permissions.

That's it — the HTML reports open when it finishes. Because the audit is **read-only**, a **Global Reader + Security Reader** account is all you need (no admin write rights, no app registration). Everything below is detail.

---

A PowerShell 7 + Microsoft Graph audit tool that mirrors the on-prem ADAudit-PS7 audit and produces the **same style of HTML reports**. It is the cloud counterpart to the Active Directory audit: same severity model (Critical / High / Medium / Low / Information), same filterable finding cards with *Why it matters* / *Recommended action* / source-evidence links, the same executive **Risk-Report**, and a **Posture-Summary** that plays the role of the AD Health report.

Its flagship capability is auditing **privileged role assignments by activation model** — every privileged role is classified as **Permanent (standing)** vs **Eligible (PIM)** vs **Time-bound active**. A *permanent* Global Administrator is flagged as a risk; the same role held as *eligible* (activated just-in-time through PIM) is the desired posture and is **not** flagged.

> ## 🔒 Read-only against Entra / Microsoft Graph
> This tool is **read-only against Microsoft Entra / Graph**. It requests only `*.Read.*` scopes, issues only `GET` requests, and **aborts at startup if any write-capable scope is granted**. It never creates, modifies, activates, revokes, assigns or deletes anything in the tenant. Every "Recommended action" in the reports is advisory guidance for a human operator — the tool performs no management.
>
> It is **not** local-filesystem read-only: like any reporting tool it **writes** the HTML/CSV/TXT/JSON reports and evidence to the output folder, and with `-installdeps` it installs the Microsoft Graph modules. Those reports contain sensitive identity/security data — point `-OutputRoot` at a restricted directory and avoid sharing the raw CSV/JSON broadly.

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
      EntraAudit-Results.html           # all findings, grouped by severity, filterable (severity / category / free text)
      Risk-Report.html                  # executive risk score (unbounded, higher = worse, diminishing returns per issue), band matrix, top risks, score drivers
      Posture-Summary.html              # per-check status grid + licensing/coverage
      Raw-Data.html                     # index of every raw dataset (HTML/CSV/TXT links)
   Raw Data\Source\
      privileged_roles.html/.csv/.txt   # each check: styled HTML table + CSV + TXT
      accounts.html/.csv/.txt
      conditional_access.html/.csv/.txt
      ... (etc.)
   Findings.json                        # all findings, machine-readable (automation / trend)
   Findings.csv                         # all findings, flat (operations hand-off)
```

The four reports share a top navigation bar (Audit Results · Risk Report · Posture Summary · Raw Data) and a light/dark theme toggle, exactly like the AD reports.

**Every check writes its full evidence three ways** — a styled, searchable **HTML** table (same design as the reports), a **CSV** (data), and a **TXT** (plain) — even when the check passes, so you always have the underlying data in a readable form. Each finding links to its dataset's HTML page, and the **Raw Data** tab indexes them all. `Findings.json` / `Findings.csv` give every finding a stable id of the form `TenantId|CheckId|Rule|ObjectType|ObjectId|PathHash` for automation and trend comparison. `Rule` is an explicit `RuleId` where one is set on the finding, otherwise a digit-stripped title slug (so a changing count — "5 stale users" → "7" — does not change the id); explicit `RuleId`s are being applied to checks incrementally.

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
| `-mfa` | MFA posture split — registered / capable / **strong** / **phishing-resistant**; flags admins lacking phishing-resistant methods (disabled accounts excluded) | |
| `-legacyauth` | Legacy authentication usage (sign-in logs) | needs **P1** |
| `-tenantposture` | Security Defaults, authorization policy & consent settings | |
| `-capolicies` | Conditional Access policy posture | |
| `-riskyusers` | Identity Protection: risky users / detections | needs **P2** |
| `-riskyserviceprincipals` | Identity Protection: risky service principals (workload identities) | needs **Workload ID Premium** |
| `-apps` | App / service principal hygiene, over-privilege, shadow creds | |
| `-appcredentials` | **App registration secret/certificate expiry** — expired credentials → **Medium**, expiring within `-ExpiringCredentialDays` (default 30) → Low | |
| `-consentgrants` | OAuth2 delegated consent grants (illicit consent risk) | |
| `-devices` | Stale / unmanaged / non-compliant devices | |
| `-trusts` | Cross-tenant access & B2B trust | |
| `-recentchanges` | Recently created users/groups & directory audit | |
| `-tenanthealth` | Directory-sync / Password Hash Sync platform health | hybrid only |
| `-pimpolicies` | **PIM policy quality** — activation requires MFA / approval / justification, max duration, permanent-allowed | needs **P2** |
| `-breakglass` | **Emergency-access (break-glass) health** — count, cloud-only, GA, .onmicrosoft.com, recent test, licensing | pass `-BreakGlassUpns` |
| `-authmethodpolicy` | Authentication-methods policy — weak (SMS/voice) vs phishing-resistant (FIDO2/WHfB), TAP reuse | |
| `-accesspaths` | **Effective-access / attack-path graph** — duplicate privilege paths (classified **active** vs **eligible-only**), ownership-based escalation (group-, app- and SP-owners), and **CA-exclusion-group owners who can self-add to bypass MFA** | needs `Group.Read.All` (+ `Member.Read.Hidden` for hidden groups) |
| `-staleapps` | **Stale / unused applications** — flags app service principals with no sign-in in `-StaleAppDays` (default 90); stale-with-live-credentials → Medium, stale-no-credentials → Low. Excludes Microsoft first-party SPs | needs **P1** (uses service-principal sign-in activity) |

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

> `-select` and `-exclude` accept **both** the check ids shown in the Posture-Summary (`privileged-roles`, `directory-roles`, `tenant-info`, …) **and** the switch-style aliases (`privroles`, `directoryroles`, `tenantinfo`, …), comma- **or** semicolon-separated. So a GUI-built `-exclude privroles,directoryroles` resolves correctly.

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
| `-StaleAppDays <n>` | Days with no service-principal sign-in before an application is flagged stale (default 90) |
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

The Risk-Report **accumulates** points per finding by severity, with **diminishing returns for repeats of the same issue**: findings are grouped into *(check, rule, severity)* buckets — the *rule* is an explicit `RuleId` where set, else the digit-stripped title with any per-object suffix removed (so every *"Permanent (standing) Global Administrator: `<user>`"* finding lands in **one** bucket) — and each bucket contributes **points × √count**. So **a higher score is worse** and volume still raises it — 28 permanent Global Admins (28 Critical findings in one bucket) score well above 8 (`25×√28 ≈ 132` vs `25×√8 ≈ 71`) — but one systemic issue repeated across many objects can no longer drown out every other signal the way a straight per-finding sum did, while **distinct issues inside the same check each add their own weight** instead of sharing one bucket. The score is **unbounded**, so the magnitude stays visible.

The Risk-Report shows a **"What drives the score"** table — every issue bucket with its finding count, its points contribution and its share of the total — so the score is explainable rather than a black box.

| Severity | Points (per bucket, × √count) |
|---|---|
| Critical | 25 |
| High | 10 |
| Medium | 4 |
| Low | 1 |
| Information | 0 |

| Score | Band |
|---|---|
| 0 | Clean |
| 1–19 | Low |
| 20–59 | Moderate |
| 60–149 | High |
| 150+ | Critical |

Severity for standing role assignments is also **tiered by role**: tier-0 roles (Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator) and guest-held roles are **Critical**; every other privileged role caps at **High**, with the risk factors (service-principal/group principal, not MFA-capable, on-prem synced) recorded on the finding instead of inflating its severity.

---

## Notes & limitations

- **Read-only guarantee:** the script self-aborts if Graph returns any write scope. In **app-only** mode it goes further — it reads the app's *actual* granted app-role assignments (across all resource APIs) and **fails closed** unless **every** one is on the **exact documented audit allowlist**. *Read-only does not mean low-impact: broad read permissions (e.g. `Mail.Read`) can expose sensitive data, so the app-only startup check permits only the documented audit permissions, not arbitrary `*.Read.*` permissions* — anything else (write, send, create, delete, update, invite, manage, impersonate, full-control, **or any unknown/custom app role**) is refused. Remediation is always left to the operator.
- **License gating:** P1-gated checks (`staleusers`, `legacyauth`) and P2-gated checks (`pimpolicies`, `riskyusers`) are reported as *Skipped-NoLicense* (not "clean") when the tier isn't detected; license detection reads enabled **service plans**, so P1/P2 bundled inside EMS/M365 SKUs is recognised. If the license read itself **fails**, gated checks are reported as *Skipped-LicenseUnknown* instead — a failed detection is never presented as "no license". `riskyserviceprincipals` is a **separate** check gated on **Workload Identities Premium** (not P2), so a Workload-ID-Premium tenant without P2 still evaluates risky workload identities. `privileged-roles` always runs (it falls back to classic role assignments without PIM).
- **Posture Summary status:** the per-check grid distinguishes `RiskFindings(n)` (an actual risk-level finding), `InfoOnly(n)` (only Information-level baselines were added — treated as clean), `Pass`, `Skipped-*` and `Error`, so informational baselines don't make a clean check look noisy.
- **Stable finding ids:** `Findings.json`/`.csv` ids are count-independent (a finding's id doesn't change when "5 stale users" becomes "7"), so they're usable for run-over-run trend/diff. Every check also always writes its CSV (a `NoData` row when empty) so automation can rely on the file existing.
- **Failed reads are never "clean":** when a Graph read that feeds a check fails (role assignments, CA policies, group members/owners, Identity Protection), the check reports *could not be evaluated / coverage gap* — or errors outright — instead of silently passing. An audit that couldn't see the data says so.
- **Exit code:** the script exits `1` when the audit run fails (connection, output folder, report generation), so scheduled/unattended runs can detect failure.
- **Sign-in logs** are retained ~30 days; the legacy-auth check only sees that window (the legacy-client filter is applied server-side, so large tenants no longer download the full sign-in log).
- A few signals (on-prem banned-password configuration, some Identity Protection detail) are not fully exposed by Graph read APIs and are reported with that caveat.

See **[PREREQUISITE.md](PREREQUISITE.md)** for the exact Graph permissions, the recommended read-only roles, and app-registration setup.
