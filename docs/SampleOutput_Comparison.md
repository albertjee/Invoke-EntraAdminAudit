# Invoke-EntraAdminAudit — Sample Output Comparison
## Community Preview (Lite) vs Full Edition

> View in landscape mode for best experience.
> These are illustrative examples — data is fictional for demonstration purposes only.

---

## Example 1 — Orphaned Service Account (Never Signed In)

| Field | Community Preview Output | Full Edition Output |
|---|---|---|
| **Check** | Global Administrator Account | Global Administrator Account |
| **Display Name** | svc-migration-2023 | svc-migration-2023 |
| **UPN** | svc-migration-2023@contoso.com | svc-migration-2023@contoso.com |
| **Created** | 2023-01-15 | 2023-01-15 |
| **Last Successful Sign-In** | Never | Never |
| **Account Status** | Enabled | Enabled |
| **Manager Set** | NOT SET | NOT SET |
| **MFA Methods Registered** | *(not checked)* | **None registered** |
| **PIM Governed** | *(not checked)* | **NO — standing permanent access** |
| **Risk Rating** | 🔴 CRITICAL | 🔴 CRITICAL |
| **Risk Note** | NEVER signed in — account is 430 days old. Likely orphaned or service account with GA. No manager set — no ownership chain. | NEVER signed in — 430 days old. No MFA registered — password-only authentication. Not PIM governed — standing GA rights. |

**What the Lite version catches:** Orphaned account, age, no manager.
**What the Full version adds:** No MFA registered at all — a stolen password is an immediate full GA compromise. Not governed by PIM — no activation friction, no approval workflow, no time limit.

---

## Example 2 — Former Contractor, Stale Account

| Field | Community Preview Output | Full Edition Output |
|---|---|---|
| **Check** | Global Administrator Account | Global Administrator Account |
| **Display Name** | J. Morrison | J. Morrison |
| **UPN** | j.morrison@contoso.com | j.morrison@contoso.com |
| **Created** | 2022-06-01 | 2022-06-01 |
| **Last Successful Sign-In** | 2025-09-18 | 2025-09-18 |
| **Account Status** | Enabled | Enabled |
| **Manager Set** | NOT SET | NOT SET |
| **MFA Methods Registered** | *(not checked)* | microsoftAuthenticatorPush, sms |
| **PIM Governed** | *(not checked)* | NO — standing permanent access |
| **Risk Rating** | 🟡 HIGH | 🔴 CRITICAL |
| **Risk Note** | No successful sign-in in 183 days — potential orphan. No manager set. | No sign-in in 183 days. MFA registered but SMS and push are AiTM-interceptable — not phishing-resistant. Not PIM governed. |

**What the Lite version catches:** Stale account, no manager — flags it HIGH.
**What the Full version adds:** MFA exists but is the wrong class — SMS and Authenticator push are vulnerable to the exact AiTM technique used in the Stryker attack. Elevates to CRITICAL. This is the "false sense of security" finding — the org thinks MFA protects this account. It does not.

---

## Example 3 — Disabled Account Still Holding GA Role

| Field | Community Preview Output | Full Edition Output |
|---|---|---|
| **Check** | Global Administrator Account | Global Administrator Account |
| **Display Name** | admin-backup | admin-backup |
| **UPN** | admin-backup@contoso.com | admin-backup@contoso.com |
| **Created** | 2021-03-10 | 2021-03-10 |
| **Last Successful Sign-In** | 2024-12-01 | 2024-12-01 |
| **Account Status** | **DISABLED** | **DISABLED** |
| **Manager Set** | Set | Set |
| **MFA Methods Registered** | *(not checked)* | fido2, microsoftAuthenticatorPush |
| **PIM Governed** | *(not checked)* | NO — standing permanent access |
| **Risk Rating** | 🟡 HIGH | 🟡 HIGH |
| **Risk Note** | DISABLED account still holding GA role — remove immediately. | DISABLED account still holding GA role. FIDO2 registered — good credential posture. Not PIM governed — convert to eligible assignment. |

**What the Lite version catches:** Disabled account with GA role still assigned — flags it HIGH immediately.
**What the Full version adds:** FIDO2 is registered (good news). But the account is not PIM governed — if re-enabled, it has instant standing GA rights with no activation friction. The Full edition gives a more complete picture — not just the risk, but the credential posture underneath it.

---

## Example 4 — Active, Well-Managed GA Account

| Field | Community Preview Output | Full Edition Output |
|---|---|---|
| **Check** | Global Administrator Account | Global Administrator Account |
| **Display Name** | A. Jee | A. Jee |
| **UPN** | a.jee@contoso.com | a.jee@contoso.com |
| **Created** | 2023-06-01 | 2023-06-01 |
| **Last Successful Sign-In** | 2026-03-18 | 2026-03-18 |
| **Account Status** | Enabled | Enabled |
| **Manager Set** | Set | Set |
| **MFA Methods Registered** | *(not checked)* | fido2, windowsHelloForBusiness, microsoftAuthenticatorPush |
| **PIM Governed** | *(not checked)* | YES — eligible assignment, activation requires approval |
| **Risk Rating** | ✅ OK | ✅ OK |
| **Risk Note** | Active, recent sign-in. Manager set. | Active, recent sign-in. FIDO2 + WHfB registered — phishing-resistant. PIM governed — JIT activation, approval required. |

**What the Lite version catches:** Active, recent sign-in, manager set — rates it OK.
**What the Full version adds:** Confirms FIDO2 and WHfB are registered — this account would survive an AiTM attack. PIM is governing it — no standing access, activation requires approval. This is what a well-managed GA account looks like.

---

## Key Takeaway — Why Both Editions Matter

The Community Preview tells you **who** has a problem.
The Full edition tells you **what kind** of problem — and how severe.

Example 2 above is the most important illustration: the Lite version flags it HIGH (stale, no manager). The Full version elevates it to CRITICAL — because the MFA registered on that account is the wrong class entirely and would not have survived the Stryker attack vector. Without the Full edition, you know the account is stale. With it, you know it is actively exploitable with off-the-shelf AiTM tooling.

---

*Sample data is illustrative only. Generated by Invoke-EntraAdminAudit.ps1*
*Author: Albert Jee | IAM Consultant | Former Microsoft FastTrack Architect*
*github.com/albertjee/Invoke-EntraAdminAudit | linkedin.com/in/albertjee*
