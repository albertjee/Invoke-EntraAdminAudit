# =============================================================================
# Show-PoCDisclaimer.ps1
# Shared Disclaimer Module — Entra Agent Identity PoC Series
#
# Author:    Albert Jee
#            IAM Consultant | Former Microsoft FastTrack Architect (15 years)
#            medium.com/@albertjee | linkedin.com/in/albertjee
#
# Copyright: © 2026 Albert Jee. All rights reserved.
#
# License:   For educational and proof-of-concept use only.
#            Not licensed for production deployment without independent
#            review, modification, and validation by a qualified engineer.
#
# Version:   Beta 1.0 | Pre-Production
# Series:    Zero Trust for AI — Entra Agent Identity PoC
# Companion: "Your AI Agent Won't Stop. Zero Trust Will."
#            medium.com/@albertjee
# GitHub:    github.com/albertjee/entra-agent-identity-poc
# =============================================================================
#
# USAGE:
#   Dot-source this file at the top of each PoC script:
#
#       . "$PSScriptRoot\Show-PoCDisclaimer.ps1"
#       Show-PoCDisclaimer -ScriptName "Script 1 — Healthy Agent Baseline"
#
#   The function checks for a local acknowledgment flag file.
#   If the user has previously agreed on this machine, the disclaimer
#   is skipped and execution continues immediately.
#   If not, the full disclaimer is shown and the user must type "I AGREE"
#   to proceed. Typing anything else exits the script cleanly.
#
# FLAG FILE LOCATION:
#   %LOCALAPPDATA%\AlbertJee\EntraAgentPoC\disclaimer.acknowledged
#
#   This file is written once per machine on first acknowledgment.
#   It will NOT be present on a new or freshly imaged machine,
#   ensuring the disclaimer is always shown in new environments.
#   To force the disclaimer to re-appear (e.g. for a new user
#   on a shared machine), delete the flag file manually.
# =============================================================================

function Show-PoCDisclaimer {
    <#
    .SYNOPSIS
        Displays the PoC disclaimer and enforces user acknowledgment.
        Writes a local flag file on first acknowledgment to suppress
        repeat prompts on the same machine.

    .PARAMETER ScriptName
        The name of the calling script, displayed in the disclaimer header.

    .PARAMETER ForceShow
        If specified, always shows the disclaimer regardless of flag file.
        Useful for testing or shared-machine scenarios.

    .EXAMPLE
        Show-PoCDisclaimer -ScriptName "Script 1 — Healthy Agent Baseline"

    .EXAMPLE
        Show-PoCDisclaimer -ScriptName "Script 3 — Kill Switch" -ForceShow
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,

        [Parameter(Mandatory = $false)]
        [switch]$ForceShow
    )

    # ── FLAG FILE CONFIGURATION ───────────────────────────────────────────────
    $FlagDir  = Join-Path $env:LOCALAPPDATA "AlbertJee\EntraAgentPoC"
    $FlagFile = Join-Path $FlagDir "disclaimer.acknowledged"

    # ── CHECK FOR EXISTING ACKNOWLEDGMENT ─────────────────────────────────────
    if (-not $ForceShow -and (Test-Path $FlagFile)) {

        # Flag file exists — user has previously agreed on this machine.
        # Read the acknowledgment metadata and show a brief reminder only.
        $AckData = Get-Content $FlagFile -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue

        Write-Host ""
        Write-Host "  PoC Disclaimer previously acknowledged." -ForegroundColor DarkGray
        if ($AckData.AcknowledgedOn) {
            Write-Host "  Acknowledged on: $($AckData.AcknowledgedOn)" -ForegroundColor DarkGray
        }
        Write-Host "  Running: $ScriptName" -ForegroundColor DarkGray
        Write-Host "  To force disclaimer re-display: run with -ForceShow" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    # ── FULL DISCLAIMER DISPLAY ───────────────────────────────────────────────
    Clear-Host

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host "   ENTRA AGENT IDENTITY POC — DISCLAIMER & TERMS OF USE" -ForegroundColor Yellow
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Script:    $ScriptName" -ForegroundColor Cyan
    Write-Host "  Author:    Albert Jee" -ForegroundColor Cyan
    Write-Host "             IAM Consultant | Former Microsoft FastTrack Architect" -ForegroundColor Cyan
    Write-Host "  Copyright: © 2026 Albert Jee. All rights reserved." -ForegroundColor Cyan
    Write-Host "  Version:   Beta 1.0 | Pre-Production" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor DarkYellow
    Write-Host "   IMPORTANT — READ BEFORE PROCEEDING" -ForegroundColor DarkYellow
    Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  1. BETA / PRE-PRODUCTION STATUS" -ForegroundColor White
    Write-Host "     These scripts are proof-of-concept only. They are provided" -ForegroundColor Gray
    Write-Host "     for educational purposes as a companion to the article series:" -ForegroundColor Gray
    Write-Host "     'Zero Trust for AI' by Albert Jee on Medium." -ForegroundColor Gray
    Write-Host "     They are NOT production-hardened, NOT enterprise-scale," -ForegroundColor Gray
    Write-Host "     and NOT a substitute for a formal security architecture review." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. TEST TENANT REQUIREMENT" -ForegroundColor White
    Write-Host "     These scripts MUST be run in a dedicated Microsoft Entra" -ForegroundColor Gray
    Write-Host "     TEST tenant — not your production environment." -ForegroundColor Gray
    Write-Host "     Running against a production tenant is done entirely at" -ForegroundColor Gray
    Write-Host "     your own risk. Albert Jee accepts no liability for any" -ForegroundColor Gray
    Write-Host "     impact to production systems, data, or configurations." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. ENVIRONMENT VARIANCE" -ForegroundColor White
    Write-Host "     Your mileage may vary. Every Entra tenant is different." -ForegroundColor Gray
    Write-Host "     License configurations, Preview feature availability," -ForegroundColor Gray
    Write-Host "     tenant settings, and propagation timing all affect results." -ForegroundColor Gray
    Write-Host "     Scripts that worked in the author's test tenant may behave" -ForegroundColor Gray
    Write-Host "     differently in yours. Consult the troubleshooting section" -ForegroundColor Gray
    Write-Host "     in the companion article before raising issues." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  4. READ-ONLY SCOPE (Scripts 1, 2, 4)" -ForegroundColor White
    Write-Host "     Scripts 1, 2, and 4 use read-only Microsoft Graph scopes." -ForegroundColor Gray
    Write-Host "     They make no changes to your tenant configuration," -ForegroundColor Gray
    Write-Host "     identities, or policies." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  5. WRITE SCOPE — SCRIPT 3 ONLY" -ForegroundColor White
    Write-Host "     Script 3 (Kill Switch) uses a write scope to flag a Service" -ForegroundColor Gray
    Write-Host "     Principal as compromised. This action affects the targeted" -ForegroundColor Gray
    Write-Host "     identity's risk state in Entra ID Protection. Use ONLY" -ForegroundColor Gray
    Write-Host "     against your designated test Service Principal." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  6. NO SUPPORT COMMITMENT" -ForegroundColor White
    Write-Host "     These scripts are provided as-is with no warranty, express" -ForegroundColor Gray
    Write-Host "     or implied. The author provides no support commitment." -ForegroundColor Gray
    Write-Host "     For questions, connect via LinkedIn: linkedin.com/in/albertjee" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  7. COMPANION RESOURCES" -ForegroundColor White
    Write-Host "     Article: medium.com/@albertjee" -ForegroundColor Gray
    Write-Host "     GitHub:  github.com/albertjee/entra-agent-identity-poc" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  This acknowledgment will be saved to this machine." -ForegroundColor DarkGray
    Write-Host "  You will not be prompted again on this machine unless" -ForegroundColor DarkGray
    Write-Host "  you run with -ForceShow or delete the flag file at:" -ForegroundColor DarkGray
    Write-Host "  $FlagFile" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host ""

    # ── ACKNOWLEDGMENT PROMPT ─────────────────────────────────────────────────
    Write-Host "  To proceed, type exactly:  I AGREE" -ForegroundColor White
    Write-Host "  To exit, type anything else or press Ctrl+C." -ForegroundColor DarkGray
    Write-Host ""
    $UserInput = Read-Host "  Your response"

    if ($UserInput.Trim() -ne "I AGREE") {
        Write-Host ""
        Write-Host "  Acknowledgment not confirmed. Exiting script." -ForegroundColor Red
        Write-Host "  No changes were made to your tenant." -ForegroundColor DarkGray
        Write-Host ""
        exit 0
    }

    # ── WRITE FLAG FILE ───────────────────────────────────────────────────────
    try {
        if (-not (Test-Path $FlagDir)) {
            New-Item -ItemType Directory -Path $FlagDir -Force | Out-Null
        }

        $AckRecord = [PSCustomObject]@{
            AcknowledgedOn = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            MachineName    = $env:COMPUTERNAME
            UserName       = $env:USERNAME
            ScriptName     = $ScriptName
        } | ConvertTo-Json

        Set-Content -Path $FlagFile -Value $AckRecord -Force

        Write-Host ""
        Write-Host "  Acknowledged. Proceeding with $ScriptName" -ForegroundColor Green
        Write-Host ""

    } catch {
        # Flag file write failed — non-fatal, continue anyway
        Write-Host ""
        Write-Host "  Note: Could not write acknowledgment flag file." -ForegroundColor DarkYellow
        Write-Host "  Disclaimer will be shown again on next run." -ForegroundColor DarkYellow
        Write-Host "  Proceeding with $ScriptName" -ForegroundColor Green
        Write-Host ""
    }
}
