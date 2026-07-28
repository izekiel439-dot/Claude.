<#
.SYNOPSIS
    Tests the scan engine. Runs on any platform.

.DESCRIPTION
    Covers the things the move onto the UI thread made load-bearing: the pump
    that keeps the window alive, the fact that pump output must never reach the
    pipeline of the check that called it, and cancellation unwinding a scan.

    None of this needs a window, so it runs on Linux and macOS too - which is
    the point. The GUI-dependent half lives in Gui.Tests.ps1 and needs Windows.
#>

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Assert.ps1')
. (Join-Path $PSScriptRoot 'Split-Scanner.ps1')

# Everything above the GUI section: the engine, the report writer, the runner.
$slice = New-ScannerSlice -StopBefore '^#\s+GUI\s*$'
try { . $slice } finally { Remove-Item -LiteralPath $slice -Force -ErrorAction SilentlyContinue }

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "argus-engine-fixture"
$fixture = & (Join-Path $PSScriptRoot 'New-TestFixture.ps1') -Path $fixtureRoot -Kind Full

try {

Start-TestGroup '[1] a scan runs to completion and drives the pump'
$script:Sync = New-SyncState
$script:PumpCalls = 0
$script:PumpUi = { $script:PumpCalls++ }
Start-DriveScan -Roots @($fixture) -DeepInspection $true -UseDefender $false

Assert 'pump was invoked' ($script:PumpCalls -gt 0) "calls=$script:PumpCalls"
Assert 'scan reached Done' ([bool]$script:Sync.Done)
Assert 'progress ended at 100' ($script:Sync.Percent -eq 100) "percent=$($script:Sync.Percent)"
Assert 'no scan-level error' ($null -eq $script:Sync.Error) "error=$($script:Sync.Error)"

$baseline = $script:Sync.Findings.Count
Assert 'findings were produced' ($baseline -gt 0) "count=$baseline"

Start-TestGroup '[2] the planted threats are actually detected'
$titles = @($script:Sync.Findings | ForEach-Object { $_.Title })
$critical = @($script:Sync.Findings | Where-Object { $_.Severity -eq 'Critical' })

Assert 'autorun.inf flagged'      ([bool]($titles -match 'autorun\.inf found'))
Assert 'double extension flagged' ([bool]($titles -match 'Double extension'))
Assert 'content mismatch flagged' ([bool]($titles -match 'do not match its extension'))
Assert 'direction trick flagged'  ([bool]($titles -match 'text-direction trick'))
Assert 'downloader script flagged'([bool]($titles -match 'Script on drive: install\.ps1'))
Assert 'archived program flagged' ([bool]($titles -match 'Archive contains'))
Assert 'several criticals found'  ($critical.Count -ge 5) "critical=$($critical.Count)"

$innocent = @($script:Sync.Findings | Where-Object { $_.File -match 'notes\.txt|logo\.png' })
Assert 'ordinary files not flagged' ($innocent.Count -eq 0) "flagged=$($innocent.Count)"

Start-TestGroup '[3] pump output cannot leak into Test-Cancelled'
# Test-Cancelled pumps, then returns a bool. If the pump''s output escaped into
# its pipeline the return value would become an array - which is truthy - so
# every check would read as cancelled and a scan would stop after the first one.
# This is the regression the $null= in Update-Progress exists to prevent.
$script:Sync = New-SyncState
$script:PumpUi = { 'chatty pump output'; 42; Write-Output 'more noise' }
Start-DriveScan -Roots @($fixture) -DeepInspection $true -UseDefender $false
Assert 'a noisy pump changes nothing' ($script:Sync.Findings.Count -eq $baseline) `
       "got=$($script:Sync.Findings.Count) expected=$baseline"

$script:Sync = New-SyncState
$script:PumpUi = { 'noise' }
$verdict = Test-Cancelled
Assert 'Test-Cancelled returns a scalar' ($verdict -is [bool]) "type=$($verdict.GetType().Name)"
Assert 'and it is false when not cancelled' ($verdict -eq $false)

Start-TestGroup '[4] cancelling from inside the pump stops the scan'
# This is exactly how Stop works now: DoEvents dispatches the click from inside
# the pump, the handler sets Cancel, and the next Test-Cancelled unwinds.
$script:Sync = New-SyncState
$script:Ticks = 0
$script:PumpUi = { $script:Ticks++; if ($script:Ticks -ge 2) { $script:Sync.Cancel = $true } }
Start-DriveScan -Roots @($fixture) -DeepInspection $true -UseDefender $false
Assert 'cancel was observed' ([bool]$script:Sync.Cancel)
Assert 'scan stopped early' ($script:Sync.Findings.Count -lt $baseline) `
       "got=$($script:Sync.Findings.Count) full=$baseline"
Assert 'still marked Done so the UI recovers' ([bool]$script:Sync.Done)

Start-TestGroup '[5] several roots in one run'
$script:Sync = New-SyncState
$script:PumpUi = $null
Start-DriveScan -Roots @($fixture, (Join-Path $fixture 'docs')) -DeepInspection $true -UseDefender $false
$drives = @($script:Sync.Findings | ForEach-Object { $_.Drive } | Sort-Object -Unique)
Assert 'findings tagged with both roots' ($drives.Count -eq 2) "drives=$($drives -join ' , ')"
Assert 'progress still ends at 100' ($script:Sync.Percent -eq 100) "percent=$($script:Sync.Percent)"

Start-TestGroup '[6] an unreadable path degrades to a finding'
$script:Sync = New-SyncState
Start-DriveScan -Roots @((Join-Path ([System.IO.Path]::GetTempPath()) 'no-such-path-at-all')) `
                -DeepInspection $false -UseDefender $false
$couldNot = @($script:Sync.Findings | Where-Object { $_.Title -like 'Could not scan*' })
Assert 'reported as a finding' ($couldNot.Count -eq 1) "count=$($couldNot.Count)"
Assert 'not raised as an error' ($null -eq $script:Sync.Error) "error=$($script:Sync.Error)"

Start-TestGroup '[7] the report writer produces a readable file'
$script:Sync = New-SyncState
Start-DriveScan -Roots @($fixture) -DeepInspection $true -UseDefender $false
$reportPath = Join-Path ([System.IO.Path]::GetTempPath()) 'argus-test-report.html'
$null = Save-DriveReport -Findings @($script:Sync.Findings) -ScanPath $fixture -OutputPath $reportPath
Assert 'report was written' (Test-Path -LiteralPath $reportPath)
$html = Get-Content -LiteralPath $reportPath -Raw
Assert 'report names a finding' ([bool]($html -match 'autorun\.inf'))
Assert 'report escapes markup' (-not ($html -match '<script>'))
Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue

}
finally {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Exit-WithTestResult
