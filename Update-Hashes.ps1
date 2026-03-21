# =============================================================================
# Update-Hashes.ps1
# SHA256 Hash Generator — Invoke-EntraAdminAudit Repo
#
# Copyright © 2026 Albert Jee. All rights reserved.
#
# Author:  Albert Jee
#          IAM Consultant | Former Microsoft FastTrack Architect (15 years)
#          linkedin.com/in/albertjee | medium.com/@albertjee
# GitHub:  github.com/albertjee/Invoke-EntraAdminAudit
# Version: 1.0
# Date   : March 2026
#
# PURPOSE:
#   Generates SHA256 integrity hashes for all PowerShell script files in the
#   repo root and writes them to the /hashes folder.
#
#   Run this script any time a script file is added, updated, or replaced.
#   Commit the updated /hashes files alongside the script changes so that
#   consumers can verify integrity before running.
#
# USAGE:
#   .\Update-Hashes.ps1
#
#   Run from the repo root directory. The /hashes folder is created
#   automatically if it does not exist.
#
# VERIFYING A HASH (consumer instruction):
#   Get-FileHash .\Invoke-EntraAdminAudit-Lite.ps1 -Algorithm SHA256
#   Get-Content .\hashes\Invoke-EntraAdminAudit-Lite.ps1.sha256
#
#   If the Hash values match — the file is untampered.
#   If they do not match — do not run the script.
#
# WHY THIS MATTERS:
#   Both scripts in this repo require Global Administrator rights.
#   Running a tampered script with GA rights is a critical security risk.
#   Hash verification takes 10 seconds and eliminates that risk entirely.
# =============================================================================

[CmdletBinding()]
param()

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

$RepoRoot   = $PSScriptRoot
$HashesDir  = Join-Path $RepoRoot "hashes"
$Algorithm  = "SHA256"

# Scripts to hash — add new script filenames here as the repo grows
$ScriptsToHash = @(
    "Invoke-EntraAdminAudit-Lite.ps1"
    "Show-PoCDisclaimer.ps1"
    "Update-Hashes.ps1"
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

function Write-Status {
    param([string]$Level, [string]$Message)
    switch ($Level) {
        "OK"    { Write-Host "  [OK]    $Message" -ForegroundColor Green }
        "ERROR" { Write-Host "  [ERROR] $Message" -ForegroundColor Red }
        "INFO"  { Write-Host "  [INFO]  $Message" -ForegroundColor Gray }
        "SKIP"  { Write-Host "  [SKIP]  $Message" -ForegroundColor Yellow }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host "  Update-Hashes.ps1 — SHA256 Integrity Hash Generator" -ForegroundColor Cyan
Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host ""

# Create /hashes folder if it does not exist
if (-not (Test-Path $HashesDir)) {
    New-Item -ItemType Directory -Path $HashesDir -Force | Out-Null
    Write-Status "OK" "Created /hashes directory."
}
else {
    Write-Status "INFO" "/hashes directory exists — updating."
}

Write-Host ""

$HashCount  = 0
$SkipCount  = 0
$ErrorCount = 0

foreach ($ScriptName in $ScriptsToHash) {
    $ScriptPath = Join-Path $RepoRoot $ScriptName
    $HashFile   = Join-Path $HashesDir "$ScriptName.sha256"

    if (-not (Test-Path $ScriptPath)) {
        Write-Status "SKIP" "$ScriptName — file not found in repo root. Skipping."
        $SkipCount++
        continue
    }

    try {
        $Hash = Get-FileHash -Path $ScriptPath -Algorithm $Algorithm -ErrorAction Stop
        $HashValue = $Hash.Hash

        # Write hash file — format: HASH  FILENAME (space-separated, standard shasum format)
        "$HashValue  $ScriptName" | Out-File -FilePath $HashFile -Encoding UTF8 -Force

        Write-Status "OK" "$ScriptName"
        Write-Host "             Hash : $HashValue" -ForegroundColor Gray
        Write-Host "             File : hashes\$ScriptName.sha256" -ForegroundColor Gray
        Write-Host ""
        $HashCount++
    }
    catch {
        Write-Status "ERROR" "Failed to hash $ScriptName : $_"
        $ErrorCount++
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "  ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Hashes generated : $HashCount" -ForegroundColor Green
if ($SkipCount -gt 0) {
    Write-Host "  Files skipped    : $SkipCount" -ForegroundColor Yellow
}
if ($ErrorCount -gt 0) {
    Write-Host "  Errors           : $ErrorCount" -ForegroundColor Red
}
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "  1. Review the /hashes folder — verify each .sha256 file looks correct." -ForegroundColor Gray
Write-Host "  2. Commit both the updated scripts AND the updated /hashes files together." -ForegroundColor Gray
Write-Host "  3. Never commit a script change without running Update-Hashes.ps1 first." -ForegroundColor Gray
Write-Host ""
Write-Host "  Script by Albert Jee | linkedin.com/in/albertjee" -ForegroundColor DarkGray
Write-Host "  github.com/albertjee/Invoke-EntraAdminAudit" -ForegroundColor DarkGray
Write-Host ""
