# Invoke-EntraAdminAudit

**Entra ID Global Administrator & Intune Management Plane Security Audit**

PowerShell audit scripts for Microsoft Entra ID, built in response to the identity control gaps exploited in the March 2026 Stryker / Handala wiper attack.

Reference: [CISA Advisory, March 18 2026 — "CISA Urges Endpoint Management System Hardening After Cyberattack Against US Organization"](https://www.cisa.gov/news-events/alerts/2026/03/18/cisa-urges-endpoint-management-system-hardening)

Companion article: *No Malware Required: How Iran Erased a Fortune 500 With Its Own Admin Console* — available on [Medium](https://medium.com/@albertjee)

---

## Scripts

| Script | Edition | Availability |
|---|---|---|
| `Invoke-EntraAdminAudit-Lite.ps1` | **Community Preview** | Public — this repo |
| `Invoke-EntraAdminAudit.ps1` | **Full** | Private — DM to request |

The **Community Preview** edition is designed for the article walkthrough and covers Global Administrator account hygiene. The **Full** edition audits MFA registration status on every GA account, checks PIM enablement, and detects Intune Multi Admin Approval configuration.

To request access to the Full edition, connect via LinkedIn DM: [linkedin.com/in/albertjee](https://linkedin.com/in/albertjee)

---

## ⚠️ Critical Pre-Requisite — MFA on Global Administrator Accounts

The Community Preview surfaces GA account hygiene gaps — stale accounts, disabled accounts still holding GA, accounts that have never signed in, and missing manager attributes. If you are running the Community Preview, that is your full finding set.

The Full edition additionally surfaces whether phishing-resistant MFA credentials are registered on your Global Administrator accounts. If you are running the Full edition and see MFA-related findings, address them using the steps below.

From fifteen years of field experience: most GA accounts do not have MFA enforced — or have it "enabled" via Conditional Access but never validated that a phishing-resistant method is actually registered. These are not the same thing.

In the March 2026 Stryker/Handala attack, the threat actor used Adversary-in-the-Middle (AiTM) proxies to bypass standard MFA (SMS, authenticator app push) by capturing session tokens in transit. Only phishing-resistant methods — FIDO2 and Windows Hello for Business — break this attack vector because they bind the authentication cryptographically to the legitimate origin. A session token stolen from a FIDO2-authenticated session is useless to an AiTM attacker.

When the script completes, address findings in this order:

**Step 1 — Fix the registration gap first.**
If the script flags GA accounts as missing phishing-resistant MFA, go to each flagged account and register the credential directly:

Entra ID Portal > Users > [flagged GA account] > Authentication Methods
— register a FIDO2 security key or Windows Hello for Business on that account.

A Conditional Access policy cannot enforce what has not been registered. Fix the registration gap first — CA enforces it after.

**Step 2 — Then enforce it at sign-in via Conditional Access.**
Once phishing-resistant methods are registered on your GA accounts, create or update a CA policy to require them at every sign-in:

Entra ID Portal > Security > Conditional Access > New Policy
— target Global Administrators, require phishing-resistant MFA strength.

Note: this script does not audit CA policy configuration. Step 2 is a manual follow-on action after you close the registration gaps surfaced in Step 1.

### Why This Gap Exists — The Identity Maturity Curve

Why do so many organizations have this gap? It is not negligence. It is maturity.

Most mid-market organizations sit below Level 2.0 on the Identity Maturity Curve. Reaching Level 2.0 requires more than having phishing-resistant MFA available — it requires 85% or more of Global Administrator accounts to have FIDO2 or Windows Hello for Business actually registered, with a CA policy enforcing it at every sign-in. In practice, most tenants audited with this script will not meet that bar on first run.

This is not a criticism — it is a map. The script tells you exactly where you are. What you do next determines where you land on the curve.

For a deeper read on the Identity Maturity Curve and where your organization likely sits, visit: [medium.com/@albertjee](https://medium.com/@albertjee)

---

## Repo Structure

```
Invoke-EntraAdminAudit-Lite.ps1   # Community Preview edition
Show-PoCDisclaimer.ps1            # Shared disclaimer module (dot-sourced)
README.md                         # This file

/hashes                           # SHA256 integrity hashes for all script files
                                  # Verify before running — see Integrity Verification below

/samples                          # Sample HTML report output
                                  # (placeholder — sample report added post-publication)

/docs                             # Supporting documentation
                                  # (placeholder — companion article PDF added post-publication)
```

---

## Integrity Verification

Before running any script from this repo, verify the SHA256 hash matches the published value in `/hashes`.

```powershell
# Verify Community Preview script integrity
Get-FileHash .\Invoke-EntraAdminAudit-Lite.ps1 -Algorithm SHA256

# Compare against published hash in /hashes/Invoke-EntraAdminAudit-Lite.sha256
Get-Content .\hashes\Invoke-EntraAdminAudit-Lite.sha256
```

If the hashes do not match — do not run the script. Download a fresh copy directly from this repo.

This matters. If someone copies and modifies this script before distributing it, the hash will not match. In the context of a tool that requires Global Administrator rights, running a tampered script is a significant risk.

---

## Community Preview — Invoke-EntraAdminAudit-Lite.ps1

### What It Checks

**Global Administrator account hygiene — three orphan detection criteria:**

1. **Stale accounts** — no successful sign-in beyond the configurable threshold (default: 90 days, overridable at launch)
2. **Disabled accounts still holding the GA role** — the account is disabled but the role assignment was never removed
3. **Accounts that have never signed in** — provisioned and forgotten, a common service account pattern. Accounts under 7 days old are rated HIGH rather than CRITICAL to avoid onboarding noise.

It also flags accounts with **no manager attribute set** — a governance gap that breaks the ownership chain for privileged identities.

For a detailed side-by-side comparison of Community Preview vs Full edition output with real-world examples, see `/docs/SampleOutput_Comparison.md` (placeholder — content added post-publication).

### What It Does Not Check (Full Edition Only)

- Phishing-resistant MFA registration status
- PIM enablement status for the Global Administrator role
- Standing (permanent) GA assignments outside the PIM eligible model
- Intune Multi Admin Approval (MAA) configuration

### Requirements

**Authentication:** Interactive (`Connect-MgGraph`). No app registration required.

**RBAC:** Requires Global Administrator. To audit your privileged access posture, you need privileged access.

**Licensing:** `SignInActivity` requires **Entra ID P1 or P2**. On tenants running Entra ID Free or standalone Office 365 plans without a Microsoft 365 E3/E5/Business Premium bundle, `SignInActivity` returns null. Affected accounts are rated HIGH with a note rather than generating false CRITICAL ratings. If your tenant includes Microsoft 365 E3 or higher, Entra ID P1 is already bundled — `SignInActivity` will be available without additional licensing.

**Microsoft Graph permissions (delegated):**
- `Directory.Read.All`
- `AuditLog.Read.All`

**PowerShell modules — install before first run:**
```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser
```

**Microsoft Graph SDK version:** v2 (`Microsoft.Graph`) — not v1 or beta.

### Built-In Help

The script includes full comment-based help. Run this before executing:

```powershell
Get-Help .\Invoke-EntraAdminAudit-Lite.ps1 -Full
```

Returns: synopsis, full description, all parameters with defaults, usage examples, required permissions, and licensing notes. If you are new to this script, read the help output first.

### Stale Threshold — Default and Override

The default stale threshold is **90 days**. Override at launch with `-StaleThresholdDays`:

```powershell
# Use default 90-day threshold
.\Invoke-EntraAdminAudit-Lite.ps1

# Override to 30 days
.\Invoke-EntraAdminAudit-Lite.ps1 -StaleThresholdDays 30

# Override to 180 days
.\Invoke-EntraAdminAudit-Lite.ps1 -StaleThresholdDays 180

# Maximum supported value
.\Invoke-EntraAdminAudit-Lite.ps1 -StaleThresholdDays 999
```

### Usage Examples

```powershell
# Example 1 — Basic run, defaults, CSV to current directory
.\Invoke-EntraAdminAudit-Lite.ps1

# Example 2 — Override stale threshold to 30 days
.\Invoke-EntraAdminAudit-Lite.ps1 -StaleThresholdDays 30

# Example 3 — Override threshold and specify CSV export path
.\Invoke-EntraAdminAudit-Lite.ps1 -StaleThresholdDays 60 -ExportPath "C:\Audits\ga_audit.csv"
```

### Output

- **Color-coded console** — CRITICAL (red), HIGH (yellow), OK (green), INFO (gray)
- **Structured JSON log** — timestamped `.log` file, directly ingestible by Microsoft Sentinel or any SIEM
- **CSV export** — timestamped file in current directory (or `-ExportPath`)
- **HTML report** — timestamped file in current directory with scorecard, findings table, and remediation reference. See `/samples` for an example (placeholder — sample report added post-publication).

### Disclaimer

This script dot-sources `Show-PoCDisclaimer.ps1` on first run. You must type `I AGREE` to proceed. The acknowledgment is saved locally so you are not prompted again on the same machine unless you run with `-ForceShow` or delete the flag file at:

```
%LOCALAPPDATA%\AlbertJee\EntraAgentPoC\disclaimer.acknowledged
```

Both files (`Invoke-EntraAdminAudit-Lite.ps1` and `Show-PoCDisclaimer.ps1`) must be in the same directory.

---

## Full Edition — Invoke-EntraAdminAudit.ps1

The Full edition is available via private request. It audits the following on top of the Community Preview:

It audits the MFA registration status of every Global Administrator account in the tenant. The script reads what authentication methods are actually registered against each account — whether that is SMS, Microsoft Authenticator push, FIDO2 security key, or Windows Hello for Business — and surfaces the result as a risk finding.

This matters because not all MFA methods offer the same protection. Standard methods like SMS and authenticator push can be intercepted by Adversary-in-the-Middle proxies — the exact technique used in the Stryker attack. Only FIDO2 and Windows Hello for Business are cryptographically bound to the legitimate sign-in origin and cannot be intercepted this way.

The script does not change, enable, or register anything. It reads and reports. What you do with that report is the remediation decision.

- **MFA registration audit** — reads what authentication methods are registered against each GA account and flags accounts missing phishing-resistant methods (FIDO2 or Windows Hello for Business). The script does not change MFA configuration.
- **PIM enablement** for the Global Administrator role — detects whether the role is governed by PIM or whether all GAs have standing permanent access
- **Standing GA assignments** outside the PIM eligible model — accounts with always-on GA rights
- **Role-assignable group detection** — flags GA role assignments via groups, which bypass per-user sign-in and MFA audit logic
- **Intune Multi Admin Approval** — detects whether a single compromised GA can execute a mass device wipe unilaterally

**Additional requirements (Full edition):**
- `PrivilegedAccess.Read.AzureAD` (delegated)
- `DeviceManagementConfiguration.Read.All` (delegated)
- `Microsoft.Graph.DeviceManagement` module
- `Microsoft.Graph.Reports` module

**Full edition also supports unattended execution:**
- Service Principal with certificate (`-ClientId`, `-TenantId`, `-CertificateThumbprint`)
- Managed Identity (auto-detected in Azure Automation)

To request the Full edition: [linkedin.com/in/albertjee](https://linkedin.com/in/albertjee) — connect and send a DM.

---

## Security Notes

### XSS Protection in HTML Report Generation

The HTML report generation uses `[System.Web.HttpUtility]::HtmlEncode()` to sanitize all Entra ID-sourced strings before they are written into the report.

This is not boilerplate — it is a direct defense against a realistic attack scenario. If an attacker gains write access to your Entra ID tenant (the exact vector in the Stryker/Handala attack), they could modify a user's DisplayName or UPN to inject malicious script tags. Without encoding, those tags execute in your browser when you open the audit report — turning your own security tool against you.

For the full explanation, read the inline comment block in the script's `Export-HtmlReport` function, XSS Protection section.

---

## Performance & Scale — A Note for Senior Engineers

The current version uses an N+1 API call pattern — one call to retrieve GA role members, then one `Get-MgUser` call per member. For a tenant with 20 GA accounts that is 21 API calls.

A production-grade approach collapses this into a single expanded Graph call using `-ExpandProperty`, reducing API round-trips to 1 regardless of GA account count. This pattern is intentionally not implemented here to keep the code readable for the article walkthrough. If you are adapting this for a large tenant, this is the first performance change to make.

The `-ExpandProperty` syntax for this call is documented in the inline comments inside CHECK 1 of the script.

---

## Troubleshooting

**`SignInActivity` returns null for all accounts**
Your tenant does not have Entra ID P1 or P2 licensing. Affected accounts are rated HIGH with a licensing note — not false CRITICAL. Upgrade to P1/P2 to enable sign-in activity reporting.

**MFA registration check returns "data unavailable" (Full edition only)**
Verify `AuditLog.Read.All` is consented for your session. Run `Get-MgContext` and check the `Scopes` property. If the scope is missing, disconnect and reconnect with the full scope list.

**PIM query throws an error**
Verify `PrivilegedAccess.Read.AzureAD` is consented (Full edition only). If PIM has never been activated in your tenant, the query returns empty — the script handles this gracefully and rates it CRITICAL.

**HTML report shows zeros in the scorecard**
This can occur if the script encountered a non-terminating error before the summary section. Check the JSON log file for error entries. The HTML report calculates counts internally from `$Results` — if `$Results` is empty, verify the Graph connection succeeded and the GA role has members.

---

## Risk Ratings

| Rating | Meaning |
|---|---|
| **CRITICAL** | Matches the Stryker attack profile. Remediate today. |
| **HIGH** | Material risk. Schedule remediation this sprint. |
| **OK** | Control present. Continue monitoring. |
| **INFO** | Informational — no action required. |

---

## Remediation Reference

| Control | Portal Path | Priority |
|---|---|---|
| Remove orphaned / disabled GA accounts | Entra ID Portal > Roles > Global Administrator > Assignments | TODAY |
| Register phishing-resistant MFA on all GA accounts | Entra ID Portal > Users > [Account] > Authentication Methods | TODAY |
| Enable PIM for Global Administrator | Entra ID Portal > Identity Governance > PIM > Azure AD Roles | TODAY |
| Set manager attribute on all admin accounts | Entra ID Portal > Users > [Account] > Properties > Manager | THIS WEEK |
| Enable Multi Admin Approval in Intune | Intune Portal > Tenant Administration > Multi Admin Approval | THIS WEEK |
| Enforce phishing-resistant MFA via Conditional Access | Entra ID Portal > Security > Conditional Access > New Policy | THIS WEEK |

---

## Author

**Albert Jee**
IAM Consultant | Former Microsoft FastTrack Architect (15 years)

[linkedin.com/in/albertjee](https://linkedin.com/in/albertjee) | [medium.com/@albertjee](https://medium.com/@albertjee)
![CSA-600x600 (Small)](https://github.com/user-attachments/assets/82cdd672-cd66-461b-bb15-c6eb764db44c)

---<img width="72" height="72" alt="CSA-0 75in-96dpi-transparent" src="https://github.com/user-attachments/assets/45cd1ccc-a5fa-4e98-814c-cb0f33094ff9" />


## License

For educational and proof-of-concept use only. Not licensed for production deployment without independent review, modification, and validation by a qualified engineer.

© 2026 Albert Jee. All rights reserved.
