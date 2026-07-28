<#
.SYNOPSIS
    Tests the windowed half of the scanner. Windows only.

.DESCRIPTION
    This is the half that cannot be tested anywhere else. Windows Forms does not
    exist on Linux or macOS, and .NET refuses to initialise System.Drawing there
    at all, so until this ran on a Windows machine the GUI code had only ever
    been parsed - never executed.

    It loads the real form: every control is constructed, every handler is
    registered, and Start-Scan runs a real scan on this thread with the real
    pump calling the real DoEvents. The window is simply never shown, because
    ShowDialog would block forever.

    Requires a single-threaded apartment - run with `powershell.exe -STA` or
    `pwsh -STA`. Windows Forms silently misbehaves otherwise.
#>

$ErrorActionPreference = 'Stop'

if (-not ($IsWindows -or $env:OS -eq 'Windows_NT')) {
    Write-Host 'Gui.Tests.ps1 skipped: needs Windows.' -ForegroundColor Yellow
    exit 0
}

. (Join-Path $PSScriptRoot 'Assert.ps1')
. (Join-Path $PSScriptRoot 'Split-Scanner.ps1')

$apartment = [System.Threading.Thread]::CurrentThread.GetApartmentState()
if ($apartment -ne 'STA') {
    Write-Host "Refusing to run in a $apartment apartment - re-run with -STA." -ForegroundColor Red
    exit 1
}

# Everything except the final ShowDialog: builds the window, wires the handlers,
# and stops short of entering the modal loop.
$slice = New-ScannerSlice -StopBefore '^\s*\[void\]\$form\.ShowDialog\(\)'
try { . $slice } finally { Remove-Item -LiteralPath $slice -Force -ErrorAction SilentlyContinue }

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'argus-gui-fixture'
$criticalRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'argus-gui-critical'

# Complete-Scan raises a modal MessageBox on any Critical finding, and a modal
# dialog with nobody to dismiss it would hang the run until CI kills the job.
# So the end-to-end scan uses a tree whose worst finding is High.
$fixture = & (Join-Path $PSScriptRoot 'New-TestFixture.ps1') -Path $fixtureRoot -Kind NoCritical

try {

Start-TestGroup '[1] the window and its controls were built'
Assert 'form exists'            ($null -ne $form)
Assert 'form is not disposed'   (-not $form.IsDisposed)
Assert 'drive list populated'   ($driveList.Items.Count -gt 0) "items=$($driveList.Items.Count)"
Assert 'results list is empty'  ($resultList.Items.Count -eq 0)
Assert 'scan button enabled'    ($scanButton.Enabled)
Assert 'stop button disabled'   (-not $cancelButton.Enabled)
Assert 'not scanning yet'       (-not $script:Scanning)

Start-TestGroup '[2] Set-Scanning drives the controls both ways'
Set-Scanning -Running $true
Assert 'scan disabled while running'  (-not $scanButton.Enabled)
Assert 'stop enabled while running'   ($cancelButton.Enabled)
Assert 'drive list locked'            (-not $driveList.Enabled)
Set-Scanning -Running $false
Assert 'scan re-enabled'              ($scanButton.Enabled)
Assert 'stop disabled again'          (-not $cancelButton.Enabled)

Start-TestGroup '[3] a full scan through the real UI path'
# Wrap the pump rather than replace it, so the real one - control updates and
# DoEvents both - still runs. This is the assertion that the window would have
# kept repainting.
$realPump = $script:PumpUi
$script:PumpCalls = 0
$script:PumpUi = { $script:PumpCalls++; & $realPump }

Start-Scan -Roots @($fixture)

Assert 'pump ran during the scan'  ($script:PumpCalls -gt 0) "calls=$script:PumpCalls"
Assert 'scan finished'             (-not $script:Scanning)
Assert 'form survived the scan'    (-not $form.IsDisposed)
Assert 'results were listed'       ($resultList.Items.Count -gt 0) "rows=$($resultList.Items.Count)"
Assert 'findings were kept'        ($script:Findings.Count -gt 0) "count=$($script:Findings.Count)"
Assert 'row count matches findings'($resultList.Items.Count -eq $script:Findings.Count)
Assert 'progress bar at 100'       ($progressBar.Value -eq 100) "value=$($progressBar.Value)"
Assert 'controls re-enabled'       ($scanButton.Enabled)
Assert 'stop disabled again'       (-not $cancelButton.Enabled)
Assert 'summary was written'       ($summaryLabel.Text -match 'Critical')
Assert 'status reports completion' ($statusLabel.Text -match 'Done')
Assert 'save button enabled'       ($saveButton.Enabled)
Assert 'the archive was found'     ([bool](@($script:Findings | ForEach-Object { $_.Title }) -match 'Archive contains'))
Assert 'nothing critical in this tree' (@($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count -eq 0)

$script:PumpUi = $realPump

Start-TestGroup '[4] selecting a row fills the detail box'
$resultList.Items[0].Selected = $true
Assert 'detail box populated' ($detailBox.Text.Length -gt 0) "len=$($detailBox.Text.Length)"

Start-TestGroup '[5] a second scan is refused while one is running'
# DoEvents dispatches queued clicks, so a Scan click can land mid-scan even
# with the button disabled. The guard has to refuse it outright.
$before = $script:Findings.Count
$script:Scanning = $true
Start-Scan -Roots @($fixture)
Assert 'still flagged as scanning' ($script:Scanning)
Assert 'no second scan ran'        ($script:Findings.Count -eq $before)
$script:Scanning = $false

Start-TestGroup '[6] closing mid-scan is deferred, not obeyed'
$script:Sync = New-SyncState
$script:ClosePending = $false
$script:Scanning = $true
$held = Resolve-CloseRequest
Assert 'close was held back'    ($held -eq $true)
Assert 'scan was asked to stop' ([bool]$script:Sync.Cancel)
Assert 'close was remembered'   ([bool]$script:ClosePending)
Assert 'form still alive'       (-not $form.IsDisposed)

$script:Scanning = $false
$script:ClosePending = $false
$script:Sync = New-SyncState
$held = Resolve-CloseRequest
Assert 'close allowed when idle'  ($held -eq $false)
Assert 'nothing left pending'     (-not $script:ClosePending)

Start-TestGroup '[7] a Critical result does not raise a modal while closing'
# Complete-Scan suppresses its MessageBox when a close is pending. If that
# suppression broke, this call would block on a modal dialog nobody can dismiss
# and CI would hang until the job times out - so reaching the assertions at all
# is most of the result.
$criticalFixture = & (Join-Path $PSScriptRoot 'New-TestFixture.ps1') -Path $criticalRoot -Kind Full
$script:Sync = New-SyncState
$script:PumpUi = $null
Start-DriveScan -Roots @($criticalFixture) -DeepInspection $true -UseDefender $false
$criticals = @($script:Sync.Findings | Where-Object { $_.Severity -eq 'Critical' })
Assert 'fixture really is critical' ($criticals.Count -gt 0) "count=$($criticals.Count)"

$script:ScanRoots = @($criticalFixture)
$script:StartedAt = Get-Date
$script:ClosePending = $true
Complete-Scan
Assert 'returned without a modal'  ($true)
Assert 'critical rows were listed' ($resultList.Items.Count -eq $script:Findings.Count)
Assert 'summary shows criticals'   ($summaryLabel.Text -match 'Critical [1-9]')
$script:ClosePending = $false

}
finally {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $criticalRoot -Recurse -Force -ErrorAction SilentlyContinue
    if ($form -and -not $form.IsDisposed) { $form.Dispose() }
}

Exit-WithTestResult
