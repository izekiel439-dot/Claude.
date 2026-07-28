<#
.SYNOPSIS
    Smoke test for ArgusDriveScanner.ps1's headless path.

.DESCRIPTION
    Runs the scanner exactly the way a user would (-Path -NoGui), through the
    real Start-ScanJob / runspace handoff, with a timeout. This is the path a
    prior change (see git history: "Drive scanner: scan several drives in one
    run") broke without anyone noticing, because that session's test harness
    dot-sourced the engine directly and never exercised Start-ScanJob's
    threading. Run this after touching Start-ScanJob, the engine scriptblock,
    or anything they share, to catch that class of bug again.

.EXAMPLE
    .\tests\Test-DriveScanSmoke.ps1
#>

[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
$repoRoot   = Split-Path -Parent $PSScriptRoot
$scanner    = Join-Path $repoRoot 'ArgusDriveScanner.ps1'
$testDir    = Join-Path ([System.IO.Path]::GetTempPath()) ("argus-smoke-" + [guid]::NewGuid())

New-Item -ItemType Directory -Force -Path $testDir | Out-Null
"hello" | Out-File (Join-Path $testDir 'a.txt')
"world" | Out-File (Join-Path $testDir 'b.txt')

try {
    Write-Host "Running headless scan against $testDir (timeout ${TimeoutSeconds}s)..."

    $job = Start-Job -ScriptBlock {
        param($scannerPath, $path)
        & $scannerPath -Path $path -NoGui 2>&1
    } -ArgumentList $scanner, $testDir

    $completed = Wait-Job $job -Timeout $TimeoutSeconds

    if (-not $completed) {
        Stop-Job $job
        Remove-Job $job -Force
        throw "FAIL: scan did not complete within ${TimeoutSeconds}s. If Start-ScanJob was " +
              "touched recently, check for the AddScript-pipeline bug (two AddScript calls " +
              "instead of one shared-scope call) described in the git history."
    }

    $output = Receive-Job $job
    $state  = $job.State
    Remove-Job $job -Force

    $output | ForEach-Object { Write-Host "  $_" }

    if ($state -ne 'Completed') {
        throw "FAIL: scan job ended in state '$state', expected 'Completed'."
    }

    if ($output -notmatch 'Report:') {
        throw "FAIL: scan finished but produced no report line in its output."
    }

    Write-Host "PASS: headless scan completed and produced a report." -ForegroundColor Green
    exit 0
}
finally {
    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
}
