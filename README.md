# EntraAudit-PS7 — Microsoft Entra ID (Azure AD) Read-Only Security Audit

## In short

1. Run the GUI: `.\EntraAudit-GUI.ps1`
2. Click **Install Graph Modules** (one-time).
3. Click **Run Audit** and **sign in** on the page that opens with an account that has enough permissions.

That's it — the HTML reports open when it finishes. Because the audit is **read-only**, a **Global Reader + Security Reader** account covers nearly all Microsoft Graph evidence without admin write rights. A few sub-controls may need more than those two roles (for example tenant-wide federated-identity-credential listing); they are reported as **Not assessed** rather than clean — see [PREREQUISITE.md](PREREQUISITE.md). Use the read-only app-only mode for complete tenant-wide federated-credential coverage. Azure diagnostic-setting and alert-rule coverage additionally needs a pre-existing read-only Azure session. Anything the audit could not read is reported as incomplete, never as clean.

---

## What's new in v2.2.0 (October 2026)

- **Consistent population counts.** Findings carry explicit affected identities/counts and, when collected, assessed and unknown counts. Scoring deduplicates affected identities within each issue. Evidence-table rows are never assumed to be distinct objects. Unrecorded populations and overlap that cannot be resolved are labelled explicitly.
- **Clearer priorities.** Confirmed risk, action priority, highest confirmed severity and assessment coverage are shown separately. Accepted risks retain their severity and points, but carry their owner/review date instead of silently occupying the immediate remediation list.
- **Complete operational handoff.** The Action Register includes selected checks skipped before producing findings, actual affected identities, rule-specific verification, and tenant/run/version details. Historical-event review and manual tests have different completion criteria from configuration fixes or collection failures.
- **Usable summaries and exports.** Priority actions appear sooner, compatible-run changes are summarized, long action details can be expanded, and the register supports filtering. Shared print styles and keyboard controls improve offline use.
- **New comparison baseline.** The scoring ruleset is now **2.2.0**. Start a new baseline; earlier rulesets are not compared automatically. Existing finding IDs remain stable. `Follow-Up.json` is now schema 2 and includes run metadata and population changes.

### Earlier v2.1.0 improvements

- **One file per check.** The 36 checks live in `Checks/Invoke-*Check.ps1`; shared collection, reporting and follow-up helpers live in `Library`. The runner and GUI use `EntraAudit.Checks.psd1`. Copy the whole folder when deploying; existing command-line switches still work.
- **More reliable conclusions.** Custom authentication strengths must prove MFA. Effective app credential policies include creation-date cutoffs and custom overrides. Ordinary group-based app assignments are informational, with direct-membership semantics.
- **Additional checks.** Failed/stalled lifecycle runs, access-review reviewer configuration and overdue denied-access removal, PIM membership approval and PIM-managed ordinary groups, plus application redirects and implicit access-token issuance.
- **Clear urgency.** Highest confirmed severity is shown separately from the numeric risk index. A Critical issue remains urgent even when the index is Moderate.
- **Follow-up.** A new Action Register provides suggested teams, next actions and verification steps. Optional previous-run comparison and expiring documented exceptions are available in both the GUI and CLI.
- **Automation.** Exit code 2 identifies failed collection. `-FailOnIncomplete` also fails runs with partial coverage or expected licensing exclusions. Findings alone do not fail the process.
- **Versioned comparisons.** Run metadata includes `RulesetVersion` and a fingerprint of the emergency-account list. Comparisons require the same ruleset and assessment settings. Existing finding IDs are retained; new rules add new IDs.

### Earlier v2.0 improvements

The September 2026 release introduced:

- **Plain-language findings.** Every finding title, *Why it matters* and *What to do* text was rewritten for non-specialists. Findings link to the matching Microsoft Learn page (**Microsoft guidance**).
- **Explicit rule ids everywhere — finding ids change once.** Every finding now carries an explicit `RuleId`. Automation that compares runs by finding id will see a one-time reset: start a new baseline with this version. Details in [Upgrade note: finding ids](#upgrade-note-finding-ids-change-once).
- **Clearer reports.** The Results page shows **one card per problem** (with a table of the affected objects) instead of one card per object, plus *Priority actions*, a *Check coverage* table and a separate **Not assessed** section. The Risk Report adds *Do first*, *Top risks* and *What drives the score*. The Posture Summary shows the reason for every check that did not fully run. Raw Data shows which check produced each dataset and which findings use it.
- **Never "clean" by accident.** Every check result now has a plain label and a one-sentence reason (for example *Skipped: access denied*, *Stopped part-way*, *Not run*). A check that Microsoft Graph refuses or that stops with an error adds a *Not assessed* finding, and a license refusal from Graph is reported as *Skipped: no license*. The risk level shows **Not fully assessed** / **Not assessed** instead of *Clean* when something could not be checked.
- **New hygiene rules.** Disabled accounts left in the directory (`-DisabledAccountDays`, default 180); app registrations that have no enterprise app (service principal) in this tenant.
- **Safer sign-in.** Interactive runs now refuse to start unless **every** permission on the sign-in is read-only (fail-closed allow-list). New **`-DelegatedClientId`** lets you sign in through your own read-only app registration instead of Microsoft's shared app.
- **Automation.** `Findings.json` is now an object (`SchemaVersion` 2) with run details, score, per-check status, datasets and findings — read `.Findings` for the list. `Findings.csv` gains `Rule`, `IssueKey` and `DocumentationUrl`. Every run writes **`EntraAudit-Run.log`**. An unknown `-select` id, an empty selection or an output file that could not be written now ends the run with exit code 1.
- **Less double counting.** Checks that look at the same object from different angles report it once (see [Overlap between checks](#overlap-between-checks)).
- **Faster on large tenants.** Users, app consent grants, app sign-in activity and group members/owners are read once per run and shared between checks.
- **Fewer requirements.** `Microsoft.Graph.DirectoryObjects` is no longer needed (8 Graph modules), and the scopes `RoleEligibilitySchedule.Read.Directory` / `RoleAssignmentSchedule.Read.Directory` are no longer requested (`RoleManagement.Read.Directory` covers those reads).

---

A PowerShell 7 + Microsoft Graph audit tool that mirrors the on-prem ADAudit-PS7 audit and produces the **same style of HTML reports**. It is the cloud counterpart to the Active Directory audit: same severity model (Critical / High / Medium / Low / Information), same filterable finding cards with *Why it matters* / *What to do* / source-evidence links, the same executive **Risk-Report**, and a **Posture-Summary** that plays the role of the AD Health report.

Its flagship capability is auditing **privileged role assignments by activation model** — every privileged role is classified as **Permanent (standing)** vs **Eligible (PIM)** vs **Time-bound active**. A *permanent* Global Administrator is flagged as a risk; the same role held as *eligible* (activated just-in-time through PIM) is the desired posture and is **not** flagged.

> ## 🔒 Read-only against Entra / Microsoft Graph and Azure Resource Manager
> All **audit/data-collection API calls are read-only** against Microsoft Entra / Graph and Azure Resource Manager. The checks request only documented read permissions and issue only `GET` requests. The run **stops before any check** unless every permission on the sign-in is read-only (interactive: every consented scope must be a *Read* scope; app-only: every application permission must be on the exact audit allow-list). They never create, modify, activate, revoke, assign or delete tenant/subscription resources. First-time interactive OAuth consent is a separate operator-authorized setup grant for those read permissions; pre-consent them before the audit window when literal zero setup changes during execution is required. Every "What to do" text is advisory.
>
> It is **not** local-filesystem read-only: like any reporting tool it **writes** the HTML/CSV/TXT/JSON reports, the evidence and a run log to the output folder, and with `-installdeps` it installs the Microsoft Graph modules. Those reports contain sensitive identity/security data — point `-OutputRoot` at a restricted directory and avoid sharing the raw CSV/JSON broadly.

---

## Quick start

**GUI** — install modules (Step 1), pick the sign-in mode (Step 2), choose checks (Step 3), set options such as the break-glass accounts (Step 4), then check the command preview and click **Run Audit**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\EntraAudit-GUI.ps1
```

The GUI's *Own sign-in app ID (optional)* field sets `-DelegatedClientId`; it also needs the tenant ID or domain, and the GUI refuses to start without it.

**Command line — run every check (recommended):**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\EntraAudit-PS7.ps1 -all
```

You'll be prompted to sign in. Use an account with **Global Reader + Security Reader** (read-only); the few gaps this leaves are reported explicitly — see [PREREQUISITE.md](PREREQUISITE.md). Install the Microsoft Graph modules first if you don't have them:

```powershell
.\EntraAudit-PS7.ps1 -installdeps -all
```

Name your emergency-access accounts for the best result — four checks use them (`privroles`, `capolicies`, `pimpolicies`, `breakglass`) and `monitoring` looks for alerts on their sign-ins:

```powershell
.\EntraAudit-PS7.ps1 -all -BreakGlassUpns "bg1@contoso.onmicrosoft.com;bg2@contoso.onmicrosoft.com"
```

---

## Requirements

- **PowerShell 7.x** on Windows (`pwsh.exe`). The GUI uses Windows Forms.
- **Microsoft Graph PowerShell SDK v2.x** — 8 sub-modules (installed via `-installdeps`, or see [PREREQUISITE.md](PREREQUISITE.md) for offline install)
- Keep `EntraAudit-PS7.ps1`, `EntraAudit.Checks.psd1`, and the complete `Checks` and `Library` folders together. Startup validates every required file before connecting. Keep `EntraAudit-GUI.ps1` there when using the GUI.
- A read-only auditor identity:
  - **Interactive:** an account with the **Global Reader** and **Security Reader** directory roles (recommended). Optionally sign in through your own read-only app registration with `-DelegatedClientId`.
  - **App-only / unattended:** a dedicated app registration with the read-only **application** permissions and a certificate.
- Some checks need premium licensing. The tool detects your licenses and marks gated checks as *Skipped: no license* rather than reporting them clean:
  - **Entra ID P1** — sign-in activity: `staleusers`, `legacyauth`, `staleapps` (skipped without it); sign-in dates also feed `accounts` (disabled-account age), `breakglass` (last test sign-in) and the activity parts of `enterpriseapps`, `externaldelegation` and `monitoring` (reported as *Not assessed* without it).
  - **Entra ID P2** — `pimpolicies` and `riskyusers` (skipped without it); PIM eligibility data for `privroles`; the risk-based Conditional Access baselines (evaluated only when licensed).
  - **Workload Identities Premium** — `riskyserviceprincipals` (reported as *Not assessed* without it) and the workload-identity Conditional Access baselines (evaluated only when licensed).

Full permission and licensing detail is in **[PREREQUISITE.md](PREREQUISITE.md)**.

---

## Output

Results are written to a new tenant-named, timestamped folder (mirrors the AD audit layout). An existing folder is never reused: if the name is taken, `-2`, `-3` … is added.

```
<TenantName>-EntraAudit-<yyyyMMdd-HHmmss>\
   HTML Reports\
      EntraAudit-Results.html           # all findings, one card per problem, filterable (severity / check / category / free text)
      Risk-Report.html                  # executive summary: risk level and score, do-first list, top risks, what drives the score
      Posture-Summary.html              # did every check run? per-check result and reason, licenses, run details
      Raw-Data.html                     # index of every evidence dataset (HTML/CSV/TXT links, producing check, findings that use it)
      Action-Register.html              # ownership, next actions, verification, changes and documented exceptions
   Raw Data\Source\
      privileged_roles.html/.csv/.txt   # every dataset: styled HTML table + CSV + TXT
      accounts.html/.csv/.txt
      disabled_accounts.html/.csv/.txt
      conditional_access.html/.csv/.txt
      ... (one or more datasets per check)
   Findings.json                        # everything, machine-readable (automation / trend) - see below
   Findings.csv                         # all findings, flat (operations hand-off)
   Action-Register.csv                  # editable owner, team, due date and status for operational handoff
   Follow-Up.json                       # action register, comparison, exceptions and input warnings
   EntraAudit-Run.log                   # everything the run printed: warnings, skips, errors
```

The five reports share navigation (Audit Results · Risk Report · Posture Summary · Raw Data · Action Register) and a light/dark theme button. `HTML Reports/Action-Register.html` links to `Action-Register.csv` for operational handoff and `Follow-Up.json` for comparison and exception details. The theme follows your operating system until you choose one.

**Every check writes its full evidence three ways** — a styled, searchable, sortable **HTML** table, a **CSV** (data) and a **TXT** (plain text) — even when the check passes, so you always have the underlying data in a readable form. The TXT file is never cut off: very wide datasets are written as one block per row instead of a table. An empty dataset still gets a CSV (one `NoData` row) so automation can rely on the file existing. Each finding links to its dataset's HTML page, and the **Raw Data** tab indexes them all.

**Run log.** `EntraAudit-Run.log` in the run folder has everything the run printed, including the messages from before the folder existed (sign-in, license detection), so the warnings and skip reasons travel with the report when the folder is handed on. If the run stops before the run folder is created (for example the sign-in is refused, or a `-select` id is unknown), there is no folder and no log; the reason is printed in the console.

**Console summary.** At the end the console shows the overall risk, the finding counts (plus *Not assessed*), how many checks gave a full result / could not read all of their data / were skipped / stopped with an error, and where the reports, `Findings.json`, evidence and run log are. The results page opens automatically unless `-NoLaunch` is used or the session is non-interactive (scheduled task, service).

### Findings.json and Findings.csv

`Findings.csv` has one row per finding, with these columns:

`FindingId, Severity, Category, CheckId, RuleId, Rule, IssueKey, ObjectType, ObjectId, Title, AffectedPrincipal, Evidence, WhyItMatters, RecommendedAction, DocumentationUrl, SourceFile, CoverageGap, ChangeStatus, AcceptedRisk, ExceptionReason, ExceptionOwner, ExceptionExpiresUtc`

- `FindingId` — stable id `TenantId|CheckId|Rule|ObjectType|ObjectId|PathHash` (ObjectId falls back to the affected principal, else `tenant`). Use it for run-over-run comparison.
- `Rule` — the explicit `RuleId` (every current finding has one). `IssueKey` — `CheckId|Rule|Severity`, the "problem" the reports group by and the risk score counts once.
- `CoverageGap` — `True` for *Not assessed* findings (something could not be read), `False` for confirmed facts.
- `DocumentationUrl` — the Microsoft guidance link; `SourceFile` — the evidence page the finding came from.
- `AcceptedRisk` and the exception fields document a current acceptance without changing severity or score. `ChangeStatus` records the comparison result, or `Not compared` when no compatible baseline was supplied.
- Population fields include `AffectedObjectIds`, `AffectedObjectType`, `AffectedCount`, `AssessedCount`, `UnknownCount` and `PopulationLabel`. An absent count means unknown, not zero. JSON preserves the identity array; CSV flattens it for handoff. `VerificationType` and `VerificationSteps` describe how to complete the action.
- The CSV is UTF-8 with BOM (opens correctly in Excel). Cells that start with `=`, `+`, `-`, `@`, a tab or a line break get a leading `'` so a spreadsheet cannot run them as a formula; `Findings.json` keeps the original values.

`Findings.json` is **an object**, not a plain list (it was a list before v2.0 — read `.Findings` now). Its shape, with field names only:

```jsonc
{
  "SchemaVersion": 2,
  "GeneratedUtc": "2026-09-23T17:56:39Z",
  "RunInfo": {                 // who/what/when
    "ToolVersion", "RulesetVersion", "RunId", "StartedUtc", "FinishedUtc", "DurationSeconds", "CollectionExitCode",
    "AuthMode",                // Delegated | AppOnly
    "Account",                 // signed-in account, or the app's client id
    "TenantId", "TenantName", "GrantedScopes": [], "SelectedChecks": [], "ExcludedChecks": [],
    "Settings": { "InactiveDays", "ExpiringCredentialDays", "RecentChangeDays", "StaleAppDays",
                  "DisabledAccountDays", "BreakGlassUpnsCount", "BreakGlassUpnsHash", "DelegatedClientId",
                  "UseDeviceCode", "OfflineModulesPath" },   // count and fingerprint here; names can appear in evidence
    "PowerShellVersion", "GraphModuleVersion",
    "Licenses": { "P1", "P2", "WorkloadIdPremium", "Known", "Skus": [], "Notes": [] },
    "LogFile": "EntraAudit-Run.log"
  },
  "Score": {
    "Score", "Band", "ScoreBand", "ConfirmedScore", "NotAssessedPoints", "CoverageComplete",
    "HighestConfirmedSeverity", "RemediationUrgency", "OpenRemediationUrgency", "ScoringVersion",
    "Counts": { "Critical", "High", "Medium", "Low", "Information" },   // every finding
    "ConfirmedCounts": {}, "NotAssessedCounts": {},                    // split by CoverageGap
    "Coverage": { "Known", "Complete", "Total", "Selected", "Evaluated", "FullyEvaluated",
                  "Clean", "WithFindings", "Incomplete", "Skipped", "Errored", "NotRun" },
    "Drivers": [ { "IssueKey", "Severity", "CheckId", "Rule", "Title", "DisplayTitle",
                   "Count", "Points", "Share", "CoverageGap", "DocumentationUrl" } ]
  },
  "CheckStatus": [            // one entry per check the tool has, selected or not
    { "CheckId", "Title", "Selected",
      "Status",               // raw code, see "Check results" below; "NotRun" when not selected
      "Result",               // the plain label shown in the reports
      "Reason", "ErrorMessage", "MissingScopes": [], "Count", "InfoCount", "CoverageCount",
      "Partial", "DurationSeconds", "Datasets": [] }
  ],
  "Datasets": [
    { "BaseName", "Title", "CheckId", "Rows", "Notes": [], "Errors": [],
      "Files": { "Html", "Csv", "Txt" }, "UsedByFindingIds": [] }
  ],
  "Findings": [               // same fields as Findings.csv, plus:
    { "FindingId", "...": "...", "ReportLink": "HTML Reports/EntraAudit-Results.html#<anchor>" }
  ]
}
```

```powershell
$run = Get-Content .\Findings.json -Raw | ConvertFrom-Json
# confirmed Critical/High findings
$run.Findings | Where-Object { -not $_.CoverageGap -and $_.Severity -in 'Critical','High' }
# selected checks that did not give a full result
$run.CheckStatus | Where-Object { $_.Selected -and $_.Status -notmatch '^(Pass|InfoOnly\(\d+\)|RiskFindings\(\d+\))$' }
```

### Upgrade note: finding ids change once

Version 2.0 gave every finding an explicit `RuleId`, and the finding titles were rewritten. Before, many findings had no `RuleId` and their id was built from the title text, so that rewrite changed those ids **once**. Since v2.0, ids no longer depend on the wording or on counts ("5 stale users" → "7" keeps the same id). Version 2.2.0 preserves those IDs, but comparisons require a new **2.2.0 baseline** because the population-based scoring rules changed.

What changed when comparing v2.0 with older runs:

- **Runs from commit `0552807` (July 2026) or older:** almost every finding of the 24 core checks (`-tenantinfo` … `-staleapps`, in `EntraAudit-PS7.ps1`) gets a new id. Only the Conditional Access admin-MFA rules (`ENTRA-CA-ADMIN-*`), `app-credential-expired`, `app-credential-expiring` and `capolicies-named-location-coverage-unknown` keep theirs. The library checks (`-recommendations` … `-changemonitoring`) keep their ids, except the four notes and the GDAP finding listed in the next bullet.
- **Runs from commit `a992521` (23 September 2026, which already had most RuleIds):** only these ids change:
  - `workloadcredentials-reviewed`, `enterpriseapps-reviewed`, `monitoring-azure-configured`, `changemonitoring-no-critical-changes` — the four "no problems found" notes, which were title-based;
  - `capolicies-trusted-location-too-broad` — `ObjectType` is now `namedLocation` (was `policy`);
  - the `externaldelegation` *Not assessed* finding for one GDAP relationship's role risk — now keyed by the relationship id instead of its name.

Also expect findings that are new in this version (for example `accounts-disabled-not-removed`, `staleapps-appreg-no-service-principal`, `capolicies-admin-mfa-unconfirmed-exclusions`, `consentgrants-grants-unreadable`, `changemonitoring-pim-activations`, `<check>-check-did-not-finish`). Automation should therefore treat the first run of this version as a **new baseline**, and match findings on `FindingId` or `Rule`, never on `Title`.

---

## Reading the reports

Start with the **Risk Report** for the overall picture, use **Audit Results** to work through the problems, and check the **Posture Summary** to see whether every check ran.

**Severity** — Critical: fix now, it can lead to a takeover of the tenant or its admin accounts. High: fix soon. Medium: plan a fix. Low: minor clean-up. Information: background only, no action needed.

**Not assessed** — the audit could not read or check something (missing permission or license, a failed read, a setting that must be tested by hand). It is **not a pass**. These findings are kept apart from the confirmed problems (dashed cards, their own section and counts) but still count toward the risk score, because not being able to see something is a risk in itself.

### EntraAudit-Results.html — the detailed findings

- **Header:** tenant, sign-in, run time, the overall risk level and score, tiles per severity (with the number of distinct problems) and *Not assessed*, and check tiles: *Checks selected*, *Passed*, *Problems found*, *Incomplete*, *Skipped*, *Errors*, *Not run*. A banner warns when some selected checks did not fully run. **Run details** lists the account, permissions, settings and versions used.
- **How to read this report** — a short guide on the page itself.
- **Priority actions** — the Critical and High problems, most severe first and then the most widespread, each with its first step and Microsoft guidance link.
- **Check coverage** — every check that did not give a full result, with the reason and a link to its findings (*Show all checks* lists all of them).
- **Filters:** severity (including *Problems only*, *Not assessed only* and *All except not assessed*), check, category and free-text search. The search also looks inside closed cards and their affected-object tables. *Expand all* / *Collapse all* / *Clear filters*.
- **Cards — one per problem.** If the same problem affects several users, apps or policies they share one card with a count and an *Affected objects* table. Open a card for *What was found*, *Why it matters*, *What to do*, the evidence file and the result rows. The small grey line names the check, the rule and the finding id (the same id as in `Findings.json`/`.csv`) and shows how to re-run only that check (`-select <checkId>`).
- **Links into the page:** `EntraAudit-Results.html?check=<checkId>`, `?sev=Critical|High|Medium|Low|Information|Risk|Gap|NoGap`, `?q=<text>`, `#<finding anchor>` (the `ReportLink` in `Findings.json`) and `#check-<checkId>` (that check's coverage row).

### Risk-Report.html — the executive summary

- The **overall risk level** and **risk score** (higher = worse), severity tiles (with "+N not assessed"; clicking one opens the Results page filtered to it), *Checks with a full result*, and the number of users, guests and app registrations.
- **Summary** in plain sentences, including how much of the score comes from things that could not be checked, and **Do first** — the three problems to fix first.
- **Top risks** — the problems that add most to the score. **Not assessed** — what the audit could not check.
- **What drives the score** — every problem with its finding count, points and share of the total, so the score can be explained line by line. **How the score works** and **Findings by category**.

### Posture-Summary.html — did every check run?

- Tiles: *Passed*, *Problems found*, *Incomplete* (can overlap *Problems found*), *Skipped*, *Errors*, *Not run*, plus users, guests and applications.
- **Licenses and what they allow the audit to check** — every subscription with its status, licenses bought and assigned, what it gives the audit and whether the audit counted it.
- **Check results** — one row per check, problems first, with its result, findings by severity, the reason in plain language, what could not be checked, and links to its evidence datasets. The *Show* filter narrows it to *Needs attention*, *Problems found*, *Gaps*, *Passed* or *Not run*. Hover over a result to see the raw status code used in `Findings.json`. `Posture-Summary.html#check-<checkId>` jumps to a check.
- **Run details** — the same run information as on the Results page.

### Raw-Data.html — the evidence

One row per dataset with its title, notes, the **check that produced it**, the number of rows, the **findings that use it**, and the HTML / CSV / TXT files. Filter by text, sort by any column, or open `Raw-Data.html?check=<checkId>` for one check's datasets.

### Check results (status values)

The same labels appear on every page; `Findings.json` → `CheckStatus[].Status` holds the raw code.

| Label in the reports | Raw status | What it means | Counts as |
|---|---|---|---|
| Passed | `Pass` | Checked fully, nothing found | clean |
| Passed (with notes) | `InfoOnly(n)` | Checked fully, only Information notes | clean |
| N findings | `RiskFindings(n)` | Problems found | problems found |
| N findings, incomplete | `RiskFindings(n)+Incomplete(m)` | Problems found, and some data could not be read, so there may be more | problems found **and** incomplete |
| Incomplete | `Incomplete(n)` | No problems in the data that could be read, but some data could not be read | incomplete — **not** clean |
| Skipped: missing permission | `Skipped-NoScope` | The sign-in lacks a permission the check needs (`MissingScopes` names it) | skipped |
| Skipped: access denied | `Skipped-NoPermission` | Microsoft Graph refused the read (a permission or admin role is missing) | skipped |
| Skipped: no license | `Skipped-NoLicense` | The tenant lacks the license: found by the license check, or Microsoft Graph refused the data because the tenant is not licensed | skipped |
| Skipped: license unknown | `Skipped-LicenseUnknown` | The license check itself failed, so it is unknown whether the tenant has the license | skipped |
| Error | `Error` | The check stopped with an error before finding anything | error |
| Stopped part-way | `Error` with `Partial = true` | The check stopped after recording some findings; those are real, but there may be more | error (and problems found, when it recorded confirmed problems) |
| No result | `NoResult` | Selected but recorded no result (the run may have stopped early) | error |
| Not run | `NotRun` | Not selected for this run — says nothing about the tenant | not run |

Only *Passed* and *Passed (with notes)* are clean. A check that Microsoft Graph refused at run time or that stopped with an error also adds a *Not assessed* finding (`<checkId>-check-did-not-finish`) with the error text; a check skipped before it started is listed with its reason in *Check coverage* and the Posture Summary. Errors, missing scope/permission and unknown licensing produce exit code 2. Known licensing exclusions and partial sub-control coverage remain visible without failing the process unless `-FailOnIncomplete` is selected.

---

## Audit checks

| Switch | What it checks | Notes |
|---|---|---|
| `-tenantinfo` | Tenant overview: organization details, verified domains, licenses. Flags missing e-mail addresses for Microsoft security notices | |
| `-privroles` | **Who holds admin roles permanently vs only when activated (PIM-eligible) vs time-bound.** A permanent admin role is **Critical** for Global Administrator, Privileged Role Administrator and Privileged Authentication Administrator and for any guest, **High** for other admin roles. Also flags a permanent role that makes the PIM-eligible one pointless, no permanent break-glass Global Administrator, PIM not used at all, and extra permanent roles on a break-glass account | flagship. Works without P2 (everything then shows as permanent); PIM eligibility needs **P2**. Accounts in `-BreakGlassUpns` may keep permanent Global Administrator |
| `-directoryroles` | How many admins: 5 or more always-on Global Administrators → High (4 → Medium; Microsoft recommends fewer than 5); 10 or more always-on privileged role assignments → High | |
| `-accounts` | Account clean-up: disabled accounts that still have licenses (Medium) or have **not been used for more than `-DisabledAccountDays`** (Low, new); enabled cloud accounts whose password never expires (Medium, High if some cannot use MFA); accounts allowed weak passwords (Medium); enabled members with no manager (Low) | disabled-account age needs sign-in dates (**P1** + `AuditLog.Read.All`), otherwise *Not assessed* |
| `-staleusers` | Enabled accounts with no successful sign-in for `-InactiveDays` (Medium; High for admins), accounts that never signed in (Medium), unused accounts that show only failed sign-in attempts (Low) | needs **P1** |
| `-guests` | Guests holding an active admin role (Critical) or able to activate one (High), guests seeing the directory like employees (High), who may invite guests (Medium), invitations not accepted after 30–90 days (Low) or over 90 days (Medium) | |
| `-mfa` | MFA registration and method strength from the registration report — registered / capable / strong / **phishing-resistant**. Admins who cannot use MFA (Critical), admins with only weak methods — text message, phone call or e-mail (High), admins without a phishing-resistant method (Medium), members without MFA (Low; Medium above 25%). Disabled accounts are left out of the findings; guests are listed but not counted | |
| `-legacyauth` | Sign-ins with old protocols that cannot do MFA (POP, IMAP, SMTP, ActiveSync …) in the last 30 days: successful ones (High), only failed attempts (Low) | needs **P1** |
| `-tenantposture` | Tenant-wide settings: Security Defaults off with no Conditional Access policy on (High — an Information pointer when `-capolicies` is in the same run, which rates it), Security Defaults on alongside CA policies, any user can register apps, self-service sign-up by e-mail, users can consent to any app | |
| `-capolicies` | Conditional Access baselines: MFA for all users, MFA and phishing-resistant MFA for admins, legacy-auth and device-code blocks, compliant device, sign-in-risk and user-risk policies (P2), workload-identity policies (Workload ID Premium), MFA policies that are off or report-only, trusted named locations with huge IP ranges. A policy counts as requiring MFA only when MFA (or an authentication strength) is mandatory — an *either/or* choice with a non-MFA control such as a compliant device, Terms of Use or a custom control does not count | **use `-BreakGlassUpns`**: users excluded by name are accepted only if they are named there. Without it, a baseline policy that fails only because up to 5 users are excluded by name is *Not assessed* (Medium), and up to 5 admins excluded by name from an MFA policy are *Not assessed* (High, rule `capolicies-admin-mfa-unconfirmed-exclusions`) instead of Critical |
| `-riskyusers` | Users Microsoft flags as risky or compromised — admins (Critical), other users (High) — and recent risk detections | needs **P2** |
| `-riskyserviceprincipals` | Apps / service principals Microsoft flags as risky (High) | needs **Workload ID Premium**. Not skipped without it: the check runs and reports *Incomplete* with a *Not assessed* note ("licences could not be read" if the license check failed) |
| `-apps` | Apps with powerful **application** permissions: top-risk permissions such as `RoleManagement.ReadWrite.Directory`, `Mail.Read`, `Files.ReadWrite.All` (Critical), other tenant-wide write permissions (High); high-permission apps with no owner or a guest owner (Critical), owned by a regular or disabled user (High), third-party/multi-tenant without a verified publisher (High); app registrations with a secret or certificate but no owner (Medium); owners of role-assignable groups | reads admin roles, PIM eligibility and group membership to classify owners (optional; a failed read becomes *Not assessed*). See [overlap](#overlap-between-checks) |
| `-appcredentials` | **App registration secret/certificate expiry** — expired → **Medium**, expiring within `-ExpiringCredentialDays` (default 30) → Low | |
| `-consentgrants` | Access users or admins granted to apps (OAuth2 delegated consent): high-impact access (mail, files, directory write, full access) for all users (High) or by single users (Medium); admin consent workflow off (Low) | a failed grant read → *Incomplete* (Medium *Not assessed*), the workflow setting is still checked |
| `-devices` | Devices with no sign-in for `-InactiveDays` (Medium), unmanaged or non-compliant devices (Medium); devices with no date at all are *Not assessed* | |
| `-trusts` | Trust in other organizations' tenants (cross-tenant access defaults): accepting their MFA (Medium) or device checks (Medium), automatic invitation redemption (Medium), inbound B2B direct connect for everyone (Low) | |
| `-recentchanges` | Users and groups created in the last `-RecentChangeDays`, admin role grants/removals/setting changes (Medium), PIM activations (Information) | audit log kept 7 days on Free, 30 days with P1/P2 — a longer window is *Not assessed* |
| `-tenanthealth` | Sync from on-premises AD: last sync older than 3 hours, Password Hash Sync off, soft-match not blocked, cloud password policy off for synced users (each Medium) | hybrid only; sync settings that cannot be read are *Not assessed* |
| `-pimpolicies` | **PIM activation rules for admin roles**: activation without MFA (Critical for top-tier roles, High otherwise), an authentication context that does not enforce MFA (High), no approval (High) or no reason (Medium) required for top-tier roles, activation longer than 8 hours (Medium), permanent assignments allowed (High), eligibility that never expires (Low) | needs **P2** |
| `-breakglass` | **Emergency-access (break-glass) accounts**: at least two named, found, enabled, permanent Global Administrator, cloud-only, on `.onmicrosoft.com`, not blocked or forced through MFA by Conditional Access, a successful test sign-in within 90 days, no licenses | pass `-BreakGlassUpns`; without it the check is *Incomplete* (High *Not assessed*). Last sign-in needs **P1** |
| `-authmethodpolicy` | Allowed sign-in methods: phone-based methods (SMS/voice) on for everyone or admins (High) or a limited group (Low); no phishing-resistant method (Medium) or not every admin can use one (High); reusable Temporary Access Pass; registration campaign and system-preferred MFA off or not reaching every admin; migration from the legacy MFA/SSPR settings not finished | "Microsoft managed" counts as on |
| `-accesspaths` | **Hidden routes to admin rights**: the same admin role through several paths (active High / eligible-only Medium), **owners of groups that hold admin roles** who can add themselves (Critical when the group grants Global Administrator or another top-tier role, or the owner is a guest or disabled; else High), and **owners of Conditional Access exclusion groups** who can add themselves to skip MFA (Critical) or other policies (High) | needs `Group.Read.All` (+ `Member.Read.Hidden` for hidden groups). App and service-principal owners are rated by `-apps` |
| `-staleapps` | **Unused applications**: app service principals with no sign-in in `-StaleAppDays` (default 90) — with live secrets/certificates → Medium, without → Low. Microsoft first-party apps are excluded; an app only called as an API counts as used; only unexpired secrets, certificates and keys count as live (SAML token-signing certificates do not). **New:** app registrations with **no enterprise app (service principal) in this tenant** — single-tenant → Low (delete candidates), multi-tenant/personal-account → Information (confirm with the owner). Registrations created within `-StaleAppDays` or holding directory extension attributes (e.g. Entra Connect's *Tenant Schema Extension App*) are not flagged | needs **P1** (uses service-principal sign-in activity); the app-registration rule needs no sign-in data |
| `-recommendations` | Microsoft Entra recommendations that are still open, high-impact ones first, with affected-resource counts | `DirectoryRecommendations.Read.All`; beta API |
| `-securescore` | Latest Microsoft Identity Secure Score (below 50% Medium, below 70% Low, a drop Medium) and the improvement actions not yet done | `SecurityEvents.Read.All` |
| `-accessreviews` | Access reviews: none set up, auto-approve when reviewers do not answer, sensitive access not reviewed on a schedule, denied access not removed automatically, overdue rounds, admin-role groups without a review | `AccessReview.Read.All`; governance licensing may apply |
| `-identitygovernance` | Access packages (broad audience without approval, no expiry, external users without review), lifecycle (leaver) workflows, Terms of Use, and PIM for Groups (permanent members/owners, activation without MFA/approval/reason, long activation) | governance read scopes; licensing may apply; Terms of Use listing is delegated-only |
| `-authrecovery` | Self-service password reset and recovery readiness, admins and users without a passwordless method, registration campaign, system-preferred MFA, banned-password list and lockout settings, on-premises password protection and password writeback | |
| `-groupgovernance` | Groups: admin-role groups with no owner or dynamic membership (High), ownerless cloud groups, guests allowed to own groups, public Microsoft 365 groups, groups that never expire, paused dynamic groups, inactive groups | |
| `-externaldelegation` | Outside access: guests without a sponsor or inactive for `-InactiveDays`, partner admin relationships (GDAP) holding admin roles, active past their end date, long-lived or auto-extending | `DelegatedAdminRelationship.Read.All` for GDAP; guest sponsors need a supported directory role (see PREREQUISITE) |
| `-federationhealth` | Federated domains: signing certificates expired (Critical) or expiring, federation settings, unsigned SAML requests; directory sync stopped for over 24 hours (High) and no accidental-deletion protection (High) | domain/federation read scopes |
| `-workloadcredentials` | Secrets, certificates and federated credentials on **apps and service principals**: no end date, expired, expiring within `-ExpiringCredentialDays`, too long-lived, too many overlapping; federated credential trusts that are too broad; the tenant-wide app credential policy off or incomplete | app-only `Application.Read.All` gives complete tenant-wide federated-credential coverage; delegated Global/Security Reader can be incomplete |
| `-enterpriseapps` | Enterprise apps: no owner, third-party apps anyone can use, group-based assignments, top-risk application permissions (Critical, same list as `-apps`), write and high-impact read permissions (High), sensitive access granted by a single user (Medium), third-party apps unused for `-StaleAppDays` (Medium) | managed identities' assignments are not read (their permissions are) |
| `-monitoring` | Are sign-in and audit logs available and recent; optional provisioning logs, risk detections and Defender alerts; with an Azure session: Entra log export (diagnostic settings), alert rules for important identity changes in Azure Monitor or Microsoft Sentinel, action groups that notify someone, and an alert for break-glass sign-ins | `SecurityAlert.Read.All`; optional pre-connected Azure read context for ARM evidence; destination retention is not assessed |
| `-changemonitoring` | Security-sensitive changes in the last `-RecentChangeDays`: successful (Medium) or attempted (Low) admin, role, policy, app, consent, credential and federation changes; group access changes. PIM activations and users' own MFA registrations are listed but not counted | audit log retention as for `-recentchanges` |

### Overlap between checks

Several checks look at the same objects from a different angle. Where two checks would rate the same fact, it is scored once:

| Topic | Checks | How it is reported |
|---|---|---|
| Application permissions, high-permission apps without an owner | `apps`, `enterpriseapps` | `enterpriseapps` lists a grant or missing owner that `apps` already reported at the same or a higher severity under "already reported by another check" (Information) and does not score it again |
| Delegated consent grants | `consentgrants`, `enterpriseapps` | the same rule, with `consentgrants` as the first reporter |
| Expired / expiring app registration secrets and certificates | `appcredentials`, `workloadcredentials` | `workloadcredentials` lists the ones `appcredentials` already reported as "reported elsewhere" and adds service-principal credentials, no-expiry, long-lived and federated credentials |
| Owners of role-assignable groups | `apps`, `accesspaths` | `accesspaths` rates owners of groups that hold admin roles; `apps` rates them only when `-accesspaths` is not in the run or its role data could not be read, otherwise it adds an Information pointer |
| No MFA baseline while Security Defaults are off | `tenantposture`, `capolicies` | when both run, `capolicies` rates it and `tenantposture` adds an Information pointer |
| Directory sync stopped | `tenanthealth`, `federationhealth` | `tenanthealth` flags a sync older than 3 hours (Medium), `federationhealth` an outage over 24 hours (High); the evidence names the other rule — one fix resolves both |
| Authentication-methods migration, registration campaign, admins without passwordless methods | `authmethodpolicy`, `authrecovery`, `mfa` | each check scores its own angle; the `authrecovery` evidence names the matching `authmethodpolicy` / `mfa` rule |
| Admin role changes | `recentchanges`, `changemonitoring` | `recentchanges` lists role grants and new users/groups; `changemonitoring` covers the wider set of security-sensitive changes |
| Unused applications | `staleapps`, `enterpriseapps` | `staleapps` covers every app by sign-in activity; `enterpriseapps` looks at third-party apps only |
| Break-glass accounts | `privroles`, `capolicies`, `pimpolicies`, `breakglass`, `monitoring` | all read `-BreakGlassUpns`; each checks a different property of the accounts |

### How the AD audit maps to the Entra audit

| On-prem AD audit | Entra equivalent |
|---|---|
| Domain Admins / privileged group review | `-privroles`, `-directoryroles` (permanent vs eligible), `-accesspaths` |
| Account issues (disabled, never-expire) | `-accounts` |
| Inactive accounts / computers | `-staleusers`, `-devices`, `-staleapps` |
| Password policy / quality | `-accounts`, `-mfa`, `-authmethodpolicy`, `-authrecovery`, `-tenantposture` |
| Recent changes (new users/groups) | `-recentchanges`, `-changemonitoring` |
| Dangerous ACLs / Kerberoast / delegation | `-apps` (over-privileged app permissions), `-consentgrants`, `-enterpriseapps` |
| GPO / domain hardening posture | `-capolicies`, `-tenantposture` (Security Defaults, CA) |
| Domain trusts | `-trusts` (cross-tenant access), `-externaldelegation` |
| AD health (replication, sync) | `-tenanthealth` (directory sync / PHS), `-federationhealth` |
| — (cloud-only) | `-legacyauth`, `-riskyusers`, `-guests` |

---

## Run modes & switches

| Switch | Description |
|---|---|
| `-all` | Run all checks (recommended). Running with no check switch at all does the same |
| `-exclude <ids>` | Comma-separated checks to skip with `-all` (e.g. `-exclude legacyauth,devices`). An unknown id only gives a warning. Ignored (with a warning) when `-select` or individual check switches are used |
| `-select <ids>` | Comma-separated check ids to run (e.g. `-select privileged-roles,mfa`). An **unknown id stops the run** with exit code 1, so a typo in a scheduled task cannot pass silently |
| `-<check>` | Individual check switches (`-privroles -mfa …`, see the table above) run only those checks |
| `-installdeps` | Install the Microsoft Graph SDK modules for the current user, then continue with the audit if checks were selected (see below) |

> `-select` and `-exclude` accept **both** the check ids shown in the Posture-Summary (`privileged-roles`, `directory-roles`, `tenant-info`, …) **and** the switch-style aliases (`privroles`, `directoryroles`, `tenantinfo`, …), comma- **or** semicolon-separated. So a GUI-built `-exclude privroles,directoryroles` resolves correctly. A selection that ends up empty (for example `-all -exclude` of every check) stops the run with exit code 1.

**What `-installdeps` does:** installs the 8 Microsoft Graph sub-modules from the PowerShell Gallery for the current user only (no admin rights), pinned to major version 2. A module that is already installed at v2 is kept. If needed it installs the NuGet package provider, and it temporarily marks PSGallery as trusted and puts the original setting back afterwards. With `-ModulesPath`, the offline folder is used first, so modules found there are not downloaded. With no check switch (`.\EntraAudit-PS7.ps1 -installdeps`) it only installs and stops; with `-all` or other check switches it installs and then runs the audit. A failed install stops the run with exit code 1.

### Sign-in

| Switch | Description |
|---|---|
| *(none)* | Interactive delegated sign-in (browser / WAM) through Microsoft's shared *Microsoft Graph Command Line Tools* app. If the sign-in window fails, the script retries with a device code |
| `-UseDeviceCode` | Interactive device-code sign-in (for terminals without a browser) |
| `-TenantId <id or domain>` | Target a specific tenant. **Required with `-DelegatedClientId`** |
| `-DelegatedClientId <appId>` | Interactive sign-in through **your own read-only app registration** instead of the shared app, whose consented permissions build up over time (see [PREREQUISITE.md, A.4](PREREQUISITE.md#a4-optional-sign-in-through-your-own-read-only-app--delegatedclientid)). Needs `-TenantId`, because new app registrations are single-tenant. Cannot be combined with `-ClientId` / `-CertificateThumbprint` |
| `-ClientId <appId>` + `-CertificateThumbprint <thumb>` | App-only (unattended) sign-in. Both must be given; one without the other stops the run instead of falling back to an interactive prompt |

### Tuning

| Switch | Description |
|---|---|
| `-InactiveDays <n>` | Days without sign-in before a user, device or guest counts as inactive (1–3650, default 90). Used by `staleusers`, `devices`, `externaldelegation` |
| `-DisabledAccountDays <n>` | Days (1–3650, default 180) after which a disabled user account that has not been used is listed for clean-up by the `accounts` check. Needs P1 + `AuditLog.Read.All` for sign-in dates; otherwise the age is reported as unknown (*Not assessed*). Shared, room and equipment mailboxes are disabled by design and will be listed — keep those. GUI: Step 4, *Disabled account age (days)* |
| `-ExpiringCredentialDays <n>` | Warn on app secrets/certificates expiring within N days (1–3650, default 30). Used by `appcredentials`, `workloadcredentials` |
| `-RecentChangeDays <n>` | Look-back window for recent changes (1–3650, default 30). Used by `recentchanges`, `changemonitoring`. Entra keeps audit logs 7 days on Free and 30 days with P1/P2; a longer window is reported as *Not assessed* |
| `-StaleAppDays <n>` | Days with no sign-in before an application counts as unused (1–3650, default 90). Used by `staleapps`, `enterpriseapps` |
| `-BreakGlassUpns <upns>` | Your cloud-only emergency-access Global Administrator accounts (`;` or `,` separated). Used by role, CA, PIM, break-glass and monitoring checks. Run settings store the count and a SHA-256 fingerprint for reliable comparison; account names remain in relevant findings/evidence |
| `-OutputRoot <path>` | Where to create the run folder (default: the script folder) |
| `-ModulesPath <path>` | Offline: folder containing `Save-Module` output; used for both import and `-installdeps` |
| `-NoLaunch` | Do not open the results page when finished. It is also not opened in non-interactive sessions (scheduled tasks, services) |
| `-PreviousRunPath <file>` | Previous `Findings.json` from the same tenant, ruleset and assessment settings. Adds New / Still present / Resolved / No longer assessed / Previously not assessed comparisons |
| `-ExceptionsPath <file>` | JSON risk-acceptance records with exact rule/object, owner, reason and expiration. Findings remain visible and scored |
| `-FailOnIncomplete` | Return exit code 2 for every incomplete or skipped selected check, including known licensing exclusions |

---

## Follow-up and documented exceptions

```powershell
.\EntraAudit-PS7.ps1 -all -NoLaunch `
  -PreviousRunPath 'D:\Audits\previous-run\Findings.json' `
  -ExceptionsPath 'D:\Audits\exceptions.json'
```

Comparison requires the same tenant, ruleset and assessment settings. A finding disappears as **Resolved** only if its check was fully assessed in the new run. If the check was skipped or incomplete, it is **No longer assessed**. Newly visible findings following an incomplete baseline are **Previously not assessed**. Incompatible or malformed inputs produce visible warnings; they do not prevent the regular audit reports from being generated.

Historical-event findings are different: an event can leave the rolling window without any remediation. Their disappearance is labelled **Outside current window**, not Resolved. Completion requires review or verification evidence, as described in the action.

An aggregate finding can remain present while its affected accounts change. When both runs have complete identity lists, comparison also shows added and removed identities. Removed identities are not considered resolved when current assessment is incomplete. A count alone cannot identify which accounts changed.

Exceptions are local reporting records, not tenant changes. Use exact values from `Findings.json`; wildcards are not allowed. For an aggregate finding without an object ID, use `tenant`. An exception is active only before its timezone-qualified expiration. Invalid, expired and unmatched records are shown but do not accept any risk.

For a grouped population, also supply `AffectedObjectIds` with the exact full identity list from the finding. If that population changes, the exception needs review and is not automatically applied to newly affected accounts. Incomplete/count-only aggregate populations cannot receive a blanket acceptance. A tenant-wide setting with no affected-object population still uses the ordinary `tenant` scope.

```json
{
  "SchemaVersion": 1,
  "TenantId": "11111111-2222-3333-4444-555555555555",
  "Exceptions": [
    {
      "RuleId": "copy-the-exact-rule-id-from-Findings.json",
      "ObjectId": "copy-the-exact-object-id-or-tenant",
      "Reason": "Approved temporary dependency; migration is scheduled.",
      "Owner": "Identity operations",
      "ExpiresUtc": "2027-01-31T23:59:59Z"
    }
  ]
}
```

The Action Register groups work by issue and separates administrator/team actions from end-user or application-owner actions. Suggested teams are routing guidance; no assignments are sent. Edit owner, due date and status in your copy of the CSV; the HTML remains a snapshot. Accepted findings retain their severity and score, and partial acceptance of a group of findings is labelled explicitly. Every register identifies its tenant, run, timestamps and ruleset. Configuration fixes, collection failures, historical-event reviews and manual tests have distinct verification instructions; record manual-test evidence and dates in the work item rather than treating an accepted risk as proof of a successful test.

## Check coverage added in v2.1.0

- **Access reviews:** reviewer and multistage settings, sensitive self-review, absent fallback reviewers, denied decisions still unapplied after seven days. A completed review is not proof that access was removed. Decision reads are bounded to 500 review instances.
- **Lifecycle workflows:** recent run failures, failed users/tasks reported by run counters, and processing stalled for over 24 hours within a 30-day lookback. No recent run is informational; incomplete or truncated execution evidence is a coverage gap. Reads are bounded to 500 workflows.
- **PIM for Groups:** cloud security/Microsoft 365 groups are considered in addition to role-assignable groups. Discovery is bounded to 2,000 candidate groups; reaching a limit is reported as incomplete. Member approval is checked for role-assignable groups as well as owner approval.
- **Application credentials:** effective default/custom restrictions and object creation-date applicability. Audit review thresholds are 180 days for secrets/symmetric keys and 730 days for certificates; these are audit thresholds, not Microsoft service limits. Actor exemptions and unresolved applicability are explicit unknowns. Policies govern credential creation/update and do not revoke old credentials.
- **Application authentication:** HTTP/wildcard redirects and implicit access-token issuance, with native-client loopback and public-client context. Redirect-domain ownership still requires manual validation.

The new reads use existing documented read permissions: `Policy.Read.All`, `Application.Read.All`, `AccessReview.Read.All`, `LifecycleWorkflows.Read.All`, group reads and PIM-for-Groups reads. No apply-decisions, workflow-execution, credential-update or other write operation is performed.

## Source layout and offline tests

```text
EntraAudit-PS7.ps1          runner and command-line parameters
EntraAudit-GUI.ps1          graphical launcher
EntraAudit.Checks.psd1      shared check IDs, switches, files, scopes and descriptions
Checks/Invoke-*Check.ps1   one definition-only file for each check
Library/                   shared state, Graph, governance, application and report helpers
Tests/                     local offline tests (Git-ignored; not included on GitHub)
```

Check files retain their existing `Invoke-Check-*` function names and finding IDs. They are dot-sourced into the runner's script scope so shared caches work consistently; do not execute them directly with `&`. The loader validates the complete package before connecting. Add a check file, its manifest entry and corresponding CLI switch when introducing a new check.

Local development copies may include the Git-ignored `Tests` folder. It is not included in GitHub clones or required to run the audit. When present, run these tests in PowerShell 7 without tenant credentials or Graph modules:

```powershell
pwsh -NoProfile -File .\Tests\Run-Tests.ps1
```

Each suite runs in a separate process with mocked collectors. Integration tests generate synthetic reports under the system temporary folder. Offline tests validate logic and report generation; deployment-specific permissions, licensing and live API behavior still need a read-only tenant run.

## Examples

Run everything:
```powershell
.\EntraAudit-PS7.ps1 -all
```

Run everything except the log-heavy checks, naming the break-glass accounts:
```powershell
.\EntraAudit-PS7.ps1 -all -exclude legacyauth -BreakGlassUpns "bg1@contoso.onmicrosoft.com;bg2@contoso.onmicrosoft.com"
```

Just the privileged-access picture:
```powershell
.\EntraAudit-PS7.ps1 -privroles -directoryroles -mfa
```

Clean up disabled accounts unused for a year, and write the report to a restricted folder:
```powershell
.\EntraAudit-PS7.ps1 -accounts -DisabledAccountDays 365 -OutputRoot D:\Audits
```

Interactive, through your own read-only app registration:
```powershell
.\EntraAudit-PS7.ps1 -all -TenantId contoso.onmicrosoft.com -DelegatedClientId 22222222-3333-4444-5555-666666666666
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

The headline **confirmed risk index** accumulates points for confirmed findings, grouped by *(check, rule, severity)* — the issue key `CheckId|Rule|Severity`. Each issue contributes **severity points × √scoring units**. Where collectors identify the affected population, units are distinct typed object IDs within that issue, independent of whether the collector emitted one grouped finding or many individual findings. Nine affected MFA administrators therefore contribute `25×√9 = 75` Critical points whether represented together or separately.

Populations are explicit; evidence-table rows are not scoring units. One application can have several expired credentials, and one principal can have several access paths. If only counts are available, overlapping populations are not blindly added: the largest supported population is used as a labelled lower bound. If no population is recorded, the report explicitly uses finding records. Assessed/unknown denominators are shown only when the collector supplied them. A missing count is unknown, not zero.

The index is unbounded and a higher value means more accumulated audit findings. It is not a percentage secure or a probability of compromise. Compare the same tenant, ruleset, selected scope and assessment settings, and check coverage before interpreting a decrease. Version 2.2.0 introduces these population scoring rules; older rulesets require a new baseline.

The Risk Report shows the population/scoring basis, finding-record count and contribution for each issue. **Highest confirmed severity** always remains visible, including accepted risks. **Action priority** and immediate actions consider work that has not been accepted; accepted risks remain in the report with their owner and expiry, and retain every point. Within open remediation, severity takes priority over accumulated points.

| Severity | Points (per issue, × √scoring units) |
|---|---|
| Critical | 25 |
| High | 10 |
| Medium | 4 |
| Low | 1 |
| Information | 0 |

| Score | Band |
|---|---|
| 0 | Clean — only when every selected check ran and read all of its data |
| 1–19 | Low |
| 20–59 | Moderate |
| 60–149 | High |
| 150+ | Critical |

**Coverage is part of the result.** A score of 0 is shown as **Not fully assessed** (not *Clean*) when any selected check was skipped, stopped with an error or could not read all of its data, when there is a *Not assessed* finding, or when it is unknown which checks ran — and as **Not assessed** when none of the selected checks gave a result. `Findings.json` keeps the plain threshold band in `Score.ScoreBand` and the coverage-aware one in `Score.Band`.

**Assessment gaps are a separate measure.** `ConfirmedScore` includes confirmed findings only. `NotAssessedPoints` describes risk-bearing assessment gaps. The secondary combined operational index remains available as `Score`; it includes the confirmed contribution and the marginal contribution of gaps sharing an issue key. The exported rounded components sum to the combined total. Selected checks skipped before collection may have no finding points, but still appear in coverage and the Action Register. A lower index with less coverage does not establish improvement.

Severity for standing role assignments is also **tiered by role**: tier-0 roles (Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator) and guest-held roles are **Critical**; every other privileged role caps at **High**, with the risk factors (service-principal/group principal, not MFA-capable, on-prem synced) recorded on the finding instead of inflating its severity.

---

## Notes & limitations

- **Read-only guarantee:** the script stops before any check unless the sign-in is provably read-only. **Interactive:** every consented scope must be recognisably read-only (a *Read*, *ReadBasic* or *ReadFor…* scope with no write or action word, or a sign-in scope such as `openid`); anything else — including an unknown shape — is refused. Microsoft Graph returns **every permission ever consented** to the app used for sign-in, so a write scope someone once consented to the shared *Microsoft Graph Command Line Tools* app makes the audit refuse to run; the error message explains the two fixes (revoke it, or use `-DelegatedClientId`) — see [PREREQUISITE.md](PREREQUISITE.md#a5-if-the-audit-refuses-to-run-permission-that-is-not-read-only). **App-only:** it reads the app's *actual* granted app-role assignments (across all resource APIs) and **fails closed** unless **every** one is on the **exact documented audit allowlist**. *Read-only does not mean low-impact: broad read permissions (e.g. `Mail.Read`) can expose sensitive data, so the app-only startup check permits only the documented audit permissions, not arbitrary `*.Read.*` permissions* — anything else (write, send, create, delete, update, invite, manage, impersonate, full-control, **any permission on another API, or any unknown/custom app role**) is refused, and so is an app with no permissions at all. Remediation is always left to the operator.
- **License gating:** P1-gated checks (`staleusers`, `legacyauth`, `staleapps`) and P2-gated checks (`pimpolicies`, `riskyusers`) are reported as *Skipped: no license* (not "clean") when the tier isn't detected. License detection reads enabled **service plans**, so P1/P2 bundled inside EMS/M365 SKUs is recognised. Subscriptions that are suspended, deleted or locked out, or that have no active licenses, are **not** counted; a subscription in its grace period (*Warning*) still counts, with a note. If the license read itself **fails**, gated checks are reported as *Skipped: license unknown* — a failed detection is never presented as "no license". If Microsoft Graph refuses data at run time because the tenant is not licensed, the check is also reported as *Skipped: no license*, with Graph's message as the reason. `riskyserviceprincipals` is **not** gated: without **Workload Identities Premium** it reports *Incomplete*. `privileged-roles` always runs (it falls back to classic role assignments without PIM). `accounts`, `breakglass`, `enterpriseapps`, `externaldelegation` and `monitoring` still run without P1, but mark their sign-in/activity portions *Not assessed*. Governance checks likewise mark feature-specific evidence incomplete when the required governance feature or license is unavailable.
- **Coverage severity:** a *Not assessed* finding can carry a risk-bearing severity (including High) and affect the overall score because a monitoring/audit blind spot is itself operational risk. It is counted under *Incomplete*, not under *Problems found*, unless the same check also found a separate confirmed problem.
- **Failed reads are never "clean":** when a Graph or optional Azure Resource Manager read that feeds a check fails, the check reports *Incomplete*, *Skipped* or *Error* instead of silently passing. A check can keep its confirmed findings and still be marked incomplete when another evidence source was unavailable. Large reads that are cut short (throttling, access denied part-way, page limits) are reported as partial reads, never as the full picture.
- **Stable finding ids:** `Findings.json`/`.csv` ids are count- and wording-independent (a finding's id doesn't change when "5 stale users" becomes "7"), so they're usable for run-over-run trend/diff — from this version on (see the [upgrade note](#upgrade-note-finding-ids-change-once)). Every check also always writes its CSV (a `NoData` row when empty) so automation can rely on the file existing.
- **Exit codes:** `0` means no process/collection failure under the selected policy; it does not mean the tenant has no findings. `1` means startup, package, authentication, output or unexpected runner failure. `2` means a check errored or was skipped for missing scopes/permissions or unknown licensing; `-FailOnIncomplete` additionally includes partial coverage and known licensing exclusions. Reports are still written for collection failures. See `RunInfo.CollectionExitCode`, the Posture Summary and the log.
- **Sign-in logs** are retained ~30 days; the legacy-auth check only sees that window (the legacy-client filter is applied server-side, so large tenants do not download the full sign-in log).
- **Hybrid sync settings:** the directory-sync settings (Password Hash Sync, soft-match blocking, accidental-deletion protection, password writeback) are read from Microsoft Graph's on-premises synchronization API. If Graph refuses that read for the audit account or app, those sub-controls are *Not assessed* and the finding says how to check them in Entra Connect — do not run the audit as Global Administrator just for them (see [PREREQUISITE.md](PREREQUISITE.md#a1-directory-roles-for-the-auditor-account)).
- A few signals (password writeback to on-premises AD, parts of the on-premises banned-password configuration, some Identity Protection detail, whether an alert really reaches someone) are not fully exposed by Graph read APIs and are reported as *must be checked by hand*.

See **[PREREQUISITE.md](PREREQUISITE.md)** for the exact Graph permissions, the recommended read-only roles, and app-registration setup.
