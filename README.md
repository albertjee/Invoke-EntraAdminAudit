# Invoke-IdentityAudit.ps1
**Entra ID Identity Audit — Zero Trust Assessment POC**
By Albert Jee | IAM Consultant | Former Microsoft FastTrack Architect

---

## Overview

This script maps every identity type in your Microsoft Entra ID tenant as described in the Zero Trust assessment framework from the article series:

**"The Identity Assumption That Will Compromise Your Enterprise in 2026"**
🔗 [Link to Medium — Part 1]
🔗 [Link to Medium — Part 2]

Before you draw a single architecture diagram, you need an honest inventory of your current trust relationships — not the ones documented in your runbooks, but the ones that actually exist in your environment. This script produces that inventory in under 10 minutes.

---

## What It Audits

| Identity Type | What It Captures |
|---|---|
| **Human Users** | All accounts, last sign-in, assigned roles, stale flag, guest vs member |
| **Service Accounts** | Pattern-matched non-interactive accounts, privilege detection |
| **Machine Identities** | All Service Principals + Managed Identities, directory roles, third-party vs Microsoft |
| **AI Agents / OAuth Apps** | All app registrations, delegated scopes, high-risk scope detection, orphan detection |

---

## Output

- **Console** — color-coded summary per identity category
- **CSV** — timestamped export: `IdentityAudit_<TenantID>_<Timestamp>.csv`

Sort the CSV by the **Notes** column to triage by risk level immediately.

---

## Requirements

**PowerShell modules:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

**Required Graph scopes (read-only — no write permissions):**
- User.Read.All
- Application.Read.All
- Directory.Read.All
- AuditLog.Read.All
- RoleManagement.Read.Directory

---

## Usage

```powershell
# Default — 90 day stale threshold
.\Invoke-IdentityAudit.ps1

# Custom stale threshold
.\Invoke-IdentityAudit.ps1 -StaleThresholdDays 180
```

---

## Sample Output

| IdentityType | DisplayName | AssignedRoles | StaleFlag | Notes |
|---|---|---|---|---|
| HumanUser | Sarah Chen | None | STALE | No sign-in 187 days |
| HumanUser | Marcus Webb | Global Administrator | ACTIVE | Privileged — verify MFA |
| ServiceAccount | svc-legacy-sync | Global Administrator | STALE | ⚠ SVC ACCT WITH GLOBAL ADMIN — REVIEW |
| MachineIdentity | reporting-func-identity | Directory.ReadWrite.All | REVIEW | ⚠ MACHINE IDENTITY WITH ROLES — CRITICAL |
| OAuthApp | Copilot Studio Connector | NO OWNER — ORPHANED | REVIEW | ⚠ ORPHANED APP — CRITICAL |
| OAuthApp (AI) | AutoSummarize-MktgBot | Owner: m.webb@corp.com | REVIEW | ⚠ AI AGENT — offline_access + Files.ReadWrite.All + Mail.Send |

---

## Prioritize Findings In This Order

1. **Orphaned app registrations** — no owner = no accountability. Revoke or assign immediately.
2. **AI agents with high-risk scopes** — `offline_access + Files.ReadWrite.All + Mail.Send` = data exfiltration waiting to happen.
3. **Machine identities with directory roles** — a Managed Identity with Global Admin is your highest blast-radius non-human identity.
4. **Stale human accounts with roles** — dormant privileged accounts = standing invitation for credential abuse.
5. **Service accounts with standing privileges** — replace with Managed Identities where possible. Scope to minimum and implement JIT via PIM where not.

---

## Important Notes

- This script is **read-only** — it makes no changes to your tenant
- Designed as a **POC and assessment starting point** — not a replacement for a full IGA platform
- Test against a **dev or staging tenant** before running on production
- Service Principal sign-in history requires additional query — flagged as REVIEW by default
- Adjust `$ServiceAccountPatterns` array to match your organization's naming conventions

---

## About the Author

Albert Jee is an independent IAM consultant and former Microsoft FastTrack Architect with fifteen years of experience designing enterprise identity and access management solutions across healthcare, financial services, and Fortune 500 organizations.

He specializes in Zero Trust architecture, Microsoft Entra ID, Conditional Access policy design, and cloud identity security.

🔗 Medium: medium.com/@albertjee
🔗 LinkedIn: linkedin.com/in/albertjee

*Available for consulting engagements and advisory roles. If this script surfaces findings you're not sure how to act on — or you're staring down a broader Zero Trust or identity modernization initiative — I'd genuinely like to hear from you. Connect or DM me on LinkedIn.*

---

## License

MIT License — free to use, modify, and distribute with attribution.
