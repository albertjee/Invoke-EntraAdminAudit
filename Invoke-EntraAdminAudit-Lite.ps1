#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
    Invoke-EntraAdminAudit-Lite.ps1
    Entra ID Global Administrator Security Audit — Lite Edition

.DESCRIPTION
    Audits your Microsoft Entra ID tenant for Global Administrator identity
    control gaps linked to the March 2026 Stryker / Handala wiper attack.

    This is the Lite edition. It covers GA account hygiene only:
      1. All active Global Administrator accounts (count, creation date, last sign-in)
      2. Orphaned GA accounts — stale (no sign-in beyond threshold), disabled
         accounts still holding GA, and accounts that have never signed in

    Checks NOT included in this edition (available in the full version):
      - PIM enablement and standing assignment detection
      - Intune Multi Admin Approval (MAA) configuration

    Output:
      - Color-coded console summary with risk ratings
      - CSV export to the current directory

    Reference:
      CISA Advisory, March 18 2026 — "CISA Urges Endpoint Management System
      Hardening After Cyberattack Against US Organization"
      https://www.cisa.gov/news-events/alerts/2026/03/18/cisa-urges-endpoint-management-system-hardening

    Full version and companion article:
      https://github.com/albertjee/Invoke-EntraAdminAudit

    Author : Albert Jee
             IAM Consultant | Former Microsoft FastTrack Architect
             https://www.linkedin.com/in/albertjee
    GitHub : https://github.com/albertjee/Invoke-EntraAdminAudit
    Version: 1.0
    Date   : March 2026

.PARAMETER StaleThresholdDays
    Number of days since last sign-in before a GA account is flagged as orphaned.
    Default: 90

.PARAMETER ExportPath
    Path for the CSV export. Defaults to current directory with timestamp filename.

.EXAMPLE
    .\Invoke-EntraAdminAudit-Lite.ps1

.EXAMPLE
    .\Invoke-EntraAdminAudit-Lite.ps1 -StaleThresholdDays 60

.EXAMPLE
    .\Invoke-EntraAdminAudit-Lite.ps1 -StaleThresholdDays 30 -ExportPath "C:\Audits\ga_audit_lite.csv"

.NOTES
    Required Microsoft Graph permissions (delegated):
      - Directory.Read.All
      - AuditLog.Read.All

    Requires Global Administrator. To audit your privileged access posture,
    you need privileged access.

    To run as a Service Principal / App Registration instead of interactive login,
    replace the Connect-MgGraph block below with certificate or client secret auth.
    See: https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands
#>

[CmdletBinding()]
param(
    [int]$StaleThresholdDays = 90,
    [string]$ExportPath = ""
)

# ─────────────────────────────────────────────────────────────────────────────
# DISCLAIMER — dot-sourced from Show-PoCDisclaimer.ps1
# ─────────────────────────────────────────────────────────────────────────────

. "$PSScriptRoot\Show-PoCDisclaimer.ps1"
Show-PoCDisclaimer -ScriptName "Invoke-EntraAdminAudit-Lite — GA Account Audit"

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

$RequiredScopes = @(
    "Directory.Read.All",
    "AuditLog.Read.All"
)

$GATemplateId   = "62e90394-69f5-4237-9190-012177145e10"  # Well-known immutable ID
$StaleThreshold = (Get-Date).AddDays(-$StaleThresholdDays)

if ($ExportPath -eq "") {
    $Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $ExportPath = ".\EntraAdminAudit_Lite_$Timestamp.csv"
}

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
}

function Write-Risk {
    param([string]$Level, [string]$Message)
    switch ($Level) {
        "CRITICAL" { Write-Host "  [CRITICAL] $Message" -ForegroundColor Red }
        "HIGH"     { Write-Host "  [HIGH]     $Message" -ForegroundColor Yellow }
        "OK"       { Write-Host "  [OK]       $Message" -ForegroundColor Green }
        "INFO"     { Write-Host "  [INFO]     $Message" -ForegroundColor Gray }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# CONNECT
# ─────────────────────────────────────────────────────────────────────────────

Write-Header "Connecting to Microsoft Graph"

try {
    Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
    $Context = Get-MgContext
    Write-Risk "OK" "Connected as: $($Context.Account)"
    Write-Risk "OK" "Tenant ID   : $($Context.TenantId)"
}
catch {
    Write-Risk "CRITICAL" "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# CHECK 1 — GLOBAL ADMINISTRATOR ACCOUNTS
# ─────────────────────────────────────────────────────────────────────────────

Write-Header "CHECK 1 — Global Administrator Accounts"

try {
    # Get the GA directory role by template ID (reliable across tenants)
    $GARole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$GATemplateId'" -ErrorAction Stop

    if (-not $GARole) {
        Write-Risk "INFO" "Global Administrator role not yet activated in this tenant (no members found via role)."
        $GAMembers = @()
    }
    else {
        $GAMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $GARole.Id -All -ErrorAction Stop
    }

    Write-Risk "INFO" "Total active Global Administrator accounts: $($GAMembers.Count)"

    if ($GAMembers.Count -gt 5) {
        Write-Risk "CRITICAL" "$($GAMembers.Count) GA accounts detected. Best practice: 2-4 maximum, all PIM-governed."
    }
    elseif ($GAMembers.Count -gt 2) {
        Write-Risk "HIGH" "$($GAMembers.Count) GA accounts detected. Review each for necessity."
    }
    else {
        Write-Risk "OK" "GA account count is within best-practice range."
    }

    foreach ($Member in $GAMembers) {
        try {
            $User = Get-MgUser -UserId $Member.Id `
                -Property "displayName,userPrincipalName,createdDateTime,signInActivity,accountEnabled,manager" `
                -ErrorAction Stop

            $LastSignIn     = $User.SignInActivity.LastSignInDateTime
            $CreatedDate    = $User.CreatedDateTime
            $AccountEnabled = $User.AccountEnabled

            # ── ORPHAN DETECTION: all three criteria ──────────────────────────
            $IsNeverSignedIn = ($null -eq $LastSignIn)
            $IsStale         = (-not $IsNeverSignedIn) -and ($LastSignIn -lt $StaleThreshold)
            $IsDisabled      = ($AccountEnabled -eq $false)

            # ── MANAGER ATTRIBUTE ─────────────────────────────────────────────
            $ManagerResult = $null
            try {
                $ManagerResult = Get-MgUserManager -UserId $Member.Id -ErrorAction Stop
            }
            catch {
                # No manager set — non-fatal
            }
            $HasNoManager = ($null -eq $ManagerResult)

            # ── RISK RATING ───────────────────────────────────────────────────
            $RiskLevel = "OK"
            $RiskNotes = [System.Collections.Generic.List[string]]::new()

            if ($IsDisabled) {
                $RiskLevel = "HIGH"
                $RiskNotes.Add("DISABLED account still holding GA role — remove immediately")
            }

            if ($IsNeverSignedIn) {
                $RiskLevel = "CRITICAL"
                $RiskNotes.Add("NEVER signed in — likely orphaned or service account with GA")
            }
            elseif ($IsStale) {
                if ($RiskLevel -ne "CRITICAL") { $RiskLevel = "HIGH" }
                $RiskNotes.Add("No sign-in in $StaleThresholdDays+ days — potential orphan")
            }

            if ($HasNoManager) {
                if ($RiskLevel -eq "OK") { $RiskLevel = "HIGH" }
                $RiskNotes.Add("No manager attribute set — no ownership chain for this account")
            }

            if ($RiskNotes.Count -eq 0) {
                $RiskNotes.Add("Active, recent sign-in, manager set")
            }

            $RiskNote = $RiskNotes -join " | "

            # ── CONSOLE OUTPUT ────────────────────────────────────────────────
            Write-Risk $RiskLevel "$($User.DisplayName) | $($User.UserPrincipalName)"
            Write-Host "             Created    : $CreatedDate" -ForegroundColor Gray
            Write-Host "             Last Login : $(if ($LastSignIn) { $LastSignIn } else { 'Never' })" -ForegroundColor Gray
            Write-Host "             Status     : $(if ($AccountEnabled) { 'Enabled' } else { 'DISABLED' })" -ForegroundColor Gray
            Write-Host "             Manager    : $(if ($HasNoManager) { 'NOT SET' } else { 'Set' })" -ForegroundColor Gray
            Write-Host "             Risk Note  : $RiskNote" -ForegroundColor Gray

            # ── RESULT OBJECT ─────────────────────────────────────────────────
            $ResultJson = [PSCustomObject]@{
                Check          = "Global Administrator Account"
                DisplayName    = $User.DisplayName
                UPN            = $User.UserPrincipalName
                CreatedDate    = $CreatedDate
                LastSignIn     = if ($LastSignIn) { $LastSignIn } else { "Never" }
                AccountEnabled = $AccountEnabled
                ManagerSet     = (-not $HasNoManager)
                IsNeverSignedIn = $IsNeverSignedIn
                IsStale        = $IsStale
                IsDisabled     = $IsDisabled
                RiskLevel      = $RiskLevel
                RiskNote       = $RiskNote
            }

            # ConvertTo-Json / ConvertFrom-Json round-trip for structured logging
            $JsonString  = $ResultJson | ConvertTo-Json -Compress
            $Hydrated    = $JsonString | ConvertFrom-Json

            $Results.Add([PSCustomObject]@{
                Check          = $Hydrated.Check
                DisplayName    = $Hydrated.DisplayName
                UPN            = $Hydrated.UPN
                CreatedDate    = $Hydrated.CreatedDate
                LastSignIn     = $Hydrated.LastSignIn
                AccountEnabled = $Hydrated.AccountEnabled
                ManagerSet     = $Hydrated.ManagerSet
                IsNeverSignedIn = $Hydrated.IsNeverSignedIn
                IsStale        = $Hydrated.IsStale
                IsDisabled     = $Hydrated.IsDisabled
                RiskLevel      = $Hydrated.RiskLevel
                RiskNote       = $Hydrated.RiskNote
            })
        }
        catch {
            # Member may be a service principal, not a user
            Write-Risk "HIGH" "Member ID $($Member.Id) — could not retrieve user details (may be Service Principal with GA role)"

            $SpResult = [PSCustomObject]@{
                Check          = "Global Administrator Account"
                DisplayName    = "Unknown (Service Principal?)"
                UPN            = $Member.Id
                CreatedDate    = "N/A"
                LastSignIn     = "N/A"
                AccountEnabled = "N/A"
                ManagerSet     = "N/A"
                IsNeverSignedIn = "N/A"
                IsStale        = "N/A"
                IsDisabled     = "N/A"
                RiskLevel      = "HIGH"
                RiskNote       = "Non-user object holding GA role — investigate immediately"
            }

            $JsonString = $SpResult | ConvertTo-Json -Compress
            $Hydrated   = $JsonString | ConvertFrom-Json

            $Results.Add([PSCustomObject]@{
                Check          = $Hydrated.Check
                DisplayName    = $Hydrated.DisplayName
                UPN            = $Hydrated.UPN
                CreatedDate    = $Hydrated.CreatedDate
                LastSignIn     = $Hydrated.LastSignIn
                AccountEnabled = $Hydrated.AccountEnabled
                ManagerSet     = $Hydrated.ManagerSet
                IsNeverSignedIn = $Hydrated.IsNeverSignedIn
                IsStale        = $Hydrated.IsStale
                IsDisabled     = $Hydrated.IsDisabled
                RiskLevel      = $Hydrated.RiskLevel
                RiskNote       = $Hydrated.RiskNote
            })
        }
    }
}
catch {
    Write-Risk "CRITICAL" "Failed to retrieve GA role members: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

Write-Header "AUDIT SUMMARY"

$CriticalCount = ($Results | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$HighCount     = ($Results | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$OkCount       = ($Results | Where-Object { $_.RiskLevel -eq "OK" }).Count

Write-Host ""
Write-Host "  CRITICAL findings : $CriticalCount" -ForegroundColor Red
Write-Host "  HIGH findings     : $HighCount"     -ForegroundColor Yellow
Write-Host "  OK findings       : $OkCount"       -ForegroundColor Green
Write-Host ""

if ($CriticalCount -gt 0) {
    Write-Risk "CRITICAL" "Your environment has CRITICAL gaps matching the Stryker attack profile."
    Write-Risk "CRITICAL" "Remediate before close of business today."
}
elseif ($HighCount -gt 0) {
    Write-Risk "HIGH" "HIGH-risk findings detected. Schedule remediation this sprint."
}
else {
    Write-Risk "OK" "No critical GA account gaps detected. Continue monitoring and review quarterly."
}

Write-Host ""
Write-Risk "INFO" "NOTE: This is the Lite edition. PIM and Intune MAA checks require the full version."
Write-Risk "INFO" "Full version: https://github.com/albertjee/Invoke-EntraAdminAudit"
Write-Host ""
Write-Host "  Reference: CISA Advisory March 18 2026" -ForegroundColor DarkGray
Write-Host "  https://www.cisa.gov/news-events/alerts/2026/03/18/" -ForegroundColor DarkGray
Write-Host "  Script by Albert Jee | linkedin.com/in/albertjee" -ForegroundColor DarkGray
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# CSV EXPORT
# ─────────────────────────────────────────────────────────────────────────────

try {
    $Results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Risk "OK" "Audit results exported to: $ExportPath"
}
catch {
    Write-Risk "HIGH" "CSV export failed: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# DISCONNECT
# ─────────────────────────────────────────────────────────────────────────────

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Write-Host ""
Write-Host "  Disconnected from Microsoft Graph." -ForegroundColor DarkGray
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT EXPORT
# ─────────────────────────────────────────────────────────────────────────────

function Export-HtmlReport {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$Data,
        [string]$TenantId,
        [string]$Account,
        [int]$CriticalCount,
        [int]$HighCount,
        [int]$OkCount
    )

    $Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
    $HtmlPath    = ".\EntraAdminAudit_Lite_$Timestamp.html"
    $RunDateTime = Get-Date -Format "MMMM dd, yyyy HH:mm UTC"

    $RowsHtml = ""
    foreach ($Row in $Data) {
        $BadgeClass = switch ($Row.RiskLevel) {
            "CRITICAL" { "badge-critical" }
            "HIGH"     { "badge-high" }
            "OK"       { "badge-ok" }
            default    { "badge-info" }
        }
        $RowClass = switch ($Row.RiskLevel) {
            "CRITICAL" { "row-critical" }
            "HIGH"     { "row-high" }
            "OK"       { "row-ok" }
            default    { "" }
        }
        $RowsHtml += @"
        <tr class="$RowClass">
            <td><strong>$($Row.Check)</strong></td>
            <td>$($Row.DisplayName)<br/><span class="upn">$($Row.UPN)</span></td>
            <td>$($Row.RiskNote)</td>
            <td>$($Row.LastSignIn)</td>
            <td>$(if ($Row.ManagerSet -eq $true) { '&#10003;' } elseif ($Row.ManagerSet -eq $false) { '<span style="color:#DC2626">&#10007; NOT SET</span>' } else { 'N/A' })</td>
            <td><span class="badge $BadgeClass">$($Row.RiskLevel)</span></td>
        </tr>
"@
    }

    $OverallBanner = if ($CriticalCount -gt 0) {
        '<div class="banner banner-critical">&#9888; CRITICAL GAPS DETECTED — Remediate before close of business today. Your environment matches the Stryker attack profile.</div>'
    } elseif ($HighCount -gt 0) {
        '<div class="banner banner-high">&#9888; HIGH-RISK findings detected. Schedule remediation this sprint.</div>'
    } else {
        '<div class="banner banner-ok">&#10003; No critical GA account gaps detected. Continue monitoring and review quarterly.</div>'
    }

    $Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Entra Admin Audit Report — Lite</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #F3F4F6; color: #1F2937; font-size: 14px; }
  .header { background: #111827; padding: 28px 36px 20px; border-bottom: 3px solid #B45309; }
  .header h1 { color: #fff; font-size: 22px; font-weight: 700; margin-bottom: 4px; }
  .header .edition { display: inline-block; background: #B45309; color: #fff; font-size: 11px; font-weight: 700;
    padding: 2px 8px; border-radius: 999px; margin-left: 10px; vertical-align: middle; letter-spacing: .05em; text-transform: uppercase; }
  .header p  { color: #D1D5DB; font-size: 12px; margin-top: 4px; }
  .header .meta { color: #9CA3AF; font-size: 11px; margin-top: 8px; }
  .container { max-width: 1100px; margin: 24px auto; padding: 0 20px; }
  .scorecard { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
  .score-box { background: #fff; border-radius: 8px; padding: 18px; text-align: center; border: 1px solid #E5E7EB; }
  .score-box .num { font-size: 36px; font-weight: 800; line-height: 1; }
  .score-box .label { font-size: 11px; font-weight: 600; margin-top: 4px; text-transform: uppercase; letter-spacing: .05em; }
  .score-critical .num, .score-critical .label { color: #DC2626; }
  .score-critical { background: #FEF2F2; border-color: #FECACA; }
  .score-high .num, .score-high .label { color: #D97706; }
  .score-high { background: #FFFBEB; border-color: #FDE68A; }
  .score-ok .num, .score-ok .label { color: #16A34A; }
  .score-ok { background: #F0FDF4; border-color: #BBF7D0; }
  .score-total .num, .score-total .label { color: #2563EB; }
  .score-total { background: #EFF6FF; border-color: #BFDBFE; }
  .banner { padding: 12px 16px; border-radius: 6px; font-weight: 600; font-size: 13px; margin-bottom: 20px; }
  .banner-critical { background: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; }
  .banner-high     { background: #FFFBEB; color: #D97706; border: 1px solid #FDE68A; }
  .banner-ok       { background: #F0FDF4; color: #16A34A; border: 1px solid #BBF7D0; }
  .lite-notice { background: #EFF6FF; border: 1px solid #BFDBFE; color: #1E40AF; border-radius: 6px;
    padding: 10px 16px; font-size: 12px; margin-bottom: 20px; }
  .lite-notice a { color: #1E40AF; }
  .section-title { font-size: 15px; font-weight: 700; color: #1F2937; margin: 20px 0 10px; padding-bottom: 6px; border-bottom: 2px solid #E5E7EB; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  thead tr { background: #1F2937; }
  thead th { color: #fff; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; padding: 10px 12px; text-align: left; }
  tbody tr { border-bottom: 1px solid #F3F4F6; }
  tbody tr:hover { filter: brightness(0.97); }
  tbody td { padding: 10px 12px; font-size: 13px; vertical-align: top; }
  .row-critical { background: #FEF2F2; }
  .row-high     { background: #FFFBEB; }
  .row-ok       { background: #F0FDF4; }
  .upn { font-size: 11px; color: #6B7280; }
  .badge { display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
  .badge-critical { background: #DC2626; color: #fff; }
  .badge-high     { background: #D97706; color: #fff; }
  .badge-ok       { background: #16A34A; color: #fff; }
  .badge-info     { background: #2563EB; color: #fff; }
  .remed-table td { font-size: 12px; }
  .priority-critical { color: #DC2626; font-weight: 700; }
  .priority-high     { color: #D97706; font-weight: 700; }
  .footer { text-align: center; font-size: 11px; color: #9CA3AF; padding: 24px 0 32px; border-top: 2px solid #B45309; margin-top: 32px; }
  .footer a { color: #B45309; text-decoration: none; }
  .sample-watermark { position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%) rotate(-35deg);
    font-size: 80px; font-weight: 900; color: rgba(180,83,9,0.07); pointer-events: none; z-index: 9999;
    white-space: nowrap; letter-spacing: 10px; }
</style>
</head>
<body>
<div class="sample-watermark">SAMPLE REPORT</div>
<div class="header">
  <h1>Invoke-EntraAdminAudit-Lite.ps1 <span class="edition">Lite Edition</span></h1>
  <p>Entra ID Global Administrator Security Audit — GA Account Hygiene</p>
  <p class="meta">Tenant: $TenantId &nbsp;|&nbsp; Account: $Account &nbsp;|&nbsp; Generated: $RunDateTime</p>
</div>
<div class="container">
  <div class="scorecard">
    <div class="score-box score-critical"><div class="num">$CriticalCount</div><div class="label">Critical</div></div>
    <div class="score-box score-high"><div class="num">$HighCount</div><div class="label">High</div></div>
    <div class="score-box score-ok"><div class="num">$OkCount</div><div class="label">OK</div></div>
    <div class="score-box score-total"><div class="num">$($Data.Count)</div><div class="label">Total Findings</div></div>
  </div>
  $OverallBanner
  <div class="lite-notice">
    &#9432; <strong>Lite Edition</strong> — This report covers GA account hygiene only (stale accounts, disabled accounts still holding GA, never-signed-in accounts, missing manager).
    PIM enablement and Intune Multi Admin Approval checks are available in the
    <a href="https://github.com/albertjee/Invoke-EntraAdminAudit">full version</a>.
  </div>
  <div class="section-title">Detailed Findings</div>
  <table>
    <thead><tr>
      <th>Check</th><th>Identity / Object</th><th>Risk Note</th><th>Last Sign-In</th><th>Manager Set</th><th>Risk</th>
    </tr></thead>
    <tbody>$RowsHtml</tbody>
  </table>
  <div class="section-title" style="margin-top:28px">Remediation Reference</div>
  <table class="remed-table">
    <thead><tr><th>Control</th><th>Portal Path</th><th>Priority</th></tr></thead>
    <tbody>
      <tr><td>Remove orphaned / disabled GA accounts</td><td>Entra ID Portal &gt; Roles &gt; Global Administrator &gt; Assignments</td><td class="priority-critical">TODAY</td></tr>
      <tr><td>Set manager attribute on all admin accounts</td><td>Entra ID Portal &gt; Users &gt; [Account] &gt; Properties &gt; Manager</td><td class="priority-critical">TODAY</td></tr>
      <tr><td>Enable PIM for Global Administrator</td><td>Entra ID Portal &gt; Identity Governance &gt; PIM &gt; Azure AD Roles</td><td class="priority-high">THIS WEEK</td></tr>
      <tr><td>Enable Multi Admin Approval in Intune</td><td>Intune Portal &gt; Tenant Administration &gt; Multi Admin Approval</td><td class="priority-high">THIS WEEK</td></tr>
      <tr><td>Enforce phishing-resistant MFA on admin accounts</td><td>Entra ID Portal &gt; Security &gt; Conditional Access &gt; New Policy</td><td class="priority-high">THIS WEEK</td></tr>
    </tbody>
  </table>
  <div class="footer">
    Script by <strong>Albert Jee</strong> &nbsp;|&nbsp; IAM Consultant &amp; Former Microsoft FastTrack Architect<br/>
    <a href="https://linkedin.com/in/albertjee">linkedin.com/in/albertjee</a> &nbsp;|&nbsp;
    <a href="https://github.com/albertjee/Invoke-EntraAdminAudit">github.com/albertjee/Invoke-EntraAdminAudit</a><br/><br/>
    Reference: <a href="https://www.cisa.gov/news-events/alerts/2026/03/18/">CISA Advisory March 18, 2026</a> &nbsp;|&nbsp;
    This is a SAMPLE REPORT &mdash; data is illustrative only
  </div>
</div>
</body>
</html>
"@

    $Html | Out-File -FilePath $HtmlPath -Encoding UTF8
    Write-Risk "OK" "HTML report exported to: $HtmlPath"
}

# Call HTML export
Export-HtmlReport -Data $Results -TenantId $Context.TenantId -Account $Context.Account `
    -CriticalCount $CriticalCount -HighCount $HighCount -OkCount $OkCount
