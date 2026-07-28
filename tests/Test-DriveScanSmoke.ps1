<#
.SYNOPSIS
    Smoke test for ArgusDriveScanner.ps1's headless path, single- and multi-root.

.DESCRIPTION
    Runs the scanner exactly the way a user would (-Path -NoGui), through the
    real Start-ScanJob / runspace handoff, with a timeout. This is the path a
    prior change (see git history: "Drive scanner: scan several drives in one
    run") broke without anyone noticing, because that session's test harness
    dot-sourced the engine directly and never exercised Start-ScanJob's
    threading. Run this after touching Start-ScanJob, the engine scriptblock,
    or anything they share, to catch that class of bug again.

    Also exercises multiple -Path values in one run, since the headless entry
    point originally only accepted a single path even though the engine
    (Start-DriveScan) always supported scanning several roots in one pass -
    the CLI surface just never exposed it.

.EXAMPLE
    .\tests\Test-DriveScanSmoke.ps1
#>

[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scanner  = Join-Path $repoRoot 'ArgusDriveScanner.ps1'

function Invoke-ScanCase {
    param(
        [string]$Name,
        [string[]]$Paths
    )

    Write-Host "--- $Name ---"

    $job = Start-Job -ScriptBlock {
        param($scannerPath, $paths)
        & $scannerPath -Path $paths -NoGui 2>&1
    } -ArgumentList $scanner, $Paths

    $completed = Wait-Job $job -Timeout $TimeoutSeconds

    if (-not $completed) {
        Stop-Job $job
        Remove-Job $job -Force
        throw "FAIL [$Name]: scan did not complete within ${TimeoutSeconds}s. If Start-ScanJob " +
              "was touched recently, check for the AddScript-pipeline bug (two AddScript calls " +
              "instead of one shared-scope call) described in the git history."
    }

    # *>&1 merges all streams (including Information, which is where Write-Host
    # output lives) into the one Receive-Job actually returns. Without it,
    # Write-Host lines from the job are printed live but never captured here.
    $output     = Receive-Job $job *>&1
    $state      = $job.State
    Remove-Job $job -Force
    $outputText = ($output | Out-String)

    $outputText -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Write-Host "  $_" }

    if ($state -ne 'Completed') {
        throw "FAIL [$Name]: scan job ended in state '$state', expected 'Completed'."
    }

    $reportMatch = [regex]::Match($outputText, 'Report:\s*(.+\.html)')
    if (-not $reportMatch.Success) {
        throw "FAIL [$Name]: scan finished but produced no report line in its output."
    }

    $reportPath = $reportMatch.Groups[1].Value.Trim()
    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "FAIL [$Name]: reported path '$reportPath' does not exist."
    }

    foreach ($p in $Paths) {
        if (-not (Select-String -LiteralPath $reportPath -Pattern ([regex]::Escape($p)) -Quiet)) {
            Remove-Item $reportPath -Force -ErrorAction SilentlyContinue
            throw "FAIL [$Name]: report does not mention scanned path '$p'."
        }
    }

    Remove-Item $reportPath -Force -ErrorAction SilentlyContinue
    Write-Host "  PASS: $Name" -ForegroundColor Green
}

$dirA = Join-Path ([System.IO.Path]::GetTempPath()) ("argus-smoke-a-" + [guid]::NewGuid())
$dirB = Join-Path ([System.IO.Path]::GetTempPath()) ("argus-smoke-b-" + [guid]::NewGuid())

New-Item -ItemType Directory -Force -Path $dirA, $dirB | Out-Null
"hello" | Out-File (Join-Path $dirA 'a.txt')
"world" | Out-File (Join-Path $dirB 'b.txt')

try {
    Invoke-ScanCase -Name 'single root' -Paths @($dirA)
    Invoke-ScanCase -Name 'multiple roots in one run' -Paths @($dirA, $dirB)

    Write-Host "PASS: all headless scan cases completed and produced reports." -ForegroundColor Green
    exit 0
}
finally {
    Remove-Item $dirA, $dirB -Recurse -Force -ErrorAction SilentlyContinue
}
