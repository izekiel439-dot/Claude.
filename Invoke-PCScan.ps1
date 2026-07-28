<#
.SYNOPSIS
    Argus - a host posture and anomaly scanner for Windows.

.DESCRIPTION
    Microsoft Defender is very good at answering "is this file malware?".
    It is not designed to answer "has something changed the way this machine
    behaves?" - and that second question covers most of what actually goes
    wrong on a personal PC.

    Argus audits the things Defender has no opinion about:

      * Persistence and autoruns - every location code can register itself to
        run again, graded on signature, location and command shape. Includes
        WMI event subscriptions, which live in the CIM repository rather than
        on disk and are therefore invisible to file scanning entirely.

      * Defender tampering and OS hardening - exclusion paths, disabled ASR
        rules, policy overrides, WDigest cleartext credential caching, UAC
        downgrades, SMBv1, RDP exposure. Changing any of these is a supported
        operation that produces no detection.

      * Network and trust - what is listening and what is talking out,
        attributed to the responsible binary, plus hosts file, DNS, proxy/PAC
        and the trusted root certificate store. A rogue root CA silently
        defeats HTTPS for every application on the machine.

      * Accounts and privilege paths - hidden accounts, weak service ACLs,
        unquoted service paths, writable PATH directories. These answer the
        question: what lets a standard user become SYSTEM without an exploit?

    Everything is read-only. Argus never modifies configuration; each finding
    carries the command you would run to fix it, for you to review first.

.PARAMETER OutputPath
    Where to write the HTML report. Defaults to a timestamped file on the
    Desktop. The report is self-contained and opens offline.

.PARAMETER Categories
    Which check families to run. Defaults to all four.

.PARAMETER Json
    Also write a JSON file alongside the HTML, for diffing two scans.

.PARAMETER MinimumSeverity
    Lowest severity to print to the console. The report always contains
    everything regardless of this setting.

.PARAMETER NoReport
    Skip writing files; console output only.

.PARAMETER Quiet
    Suppress per-finding console output. The summary is still shown.

.EXAMPLE
    .\Invoke-PCScan.ps1
    Full scan, HTML report on the Desktop.

.EXAMPLE
    .\Invoke-PCScan.ps1 -Categories Persistence,Defender -MinimumSeverity High
    Only autoruns and Defender posture, printing High and Critical to console.

.EXAMPLE
    .\Invoke-PCScan.ps1 -Json -OutputPath C:\scans\today.html
    Full scan writing both today.html and today.json.

.NOTES
    Run from an elevated PowerShell prompt. Without elevation the WMI
    subscription, service descriptor and user-rights checks are skipped or
    incomplete, and the report says so.

    Requires Windows PowerShell 5.1 or PowerShell 7+ on Windows.
#>

[CmdletBinding()]
param(
    [string]$OutputPath,

    [ValidateSet('Persistence', 'Defender', 'Network', 'Accounts', 'All')]
    [string[]]$Categories = @('All'),

    [switch]$Json,

    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
    [string]$MinimumSeverity = 'Low',

    [switch]$NoReport,

    [switch]$Quiet
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$script:ArgusVersion      = '1.0.0'
$script:Quiet             = [bool]$Quiet
$script:ConsoleThreshold  = $MinimumSeverity

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error 'Argus requires Windows PowerShell 5.1 or later.'
    exit 1
}

$isWindows_ = $true
if ($PSVersionTable.PSObject.Properties['Platform'] -and $PSVersionTable.Platform -eq 'Unix') { $isWindows_ = $false }
if (-not $isWindows_) {
    Write-Error 'Argus audits Windows-specific configuration and only runs on Windows.'
    exit 1
}

#region module-loader (matched by build/Build-Standalone.ps1 by these markers - keep them intact)
$libraryPath = Join-Path $PSScriptRoot 'lib'
foreach ($file in @('Core.ps1', 'Checks.Persistence.ps1', 'Checks.Defender.ps1', 'Checks.Network.ps1', 'Checks.Accounts.ps1', 'Report.ps1')) {
    $full = Join-Path $libraryPath $file
    if (-not (Test-Path -LiteralPath $full)) {
        Write-Error "Missing component: $full. Keep Invoke-PCScan.ps1 and the lib folder together."
        exit 1
    }
    . $full
}
#endregion module-loader

# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------

$startedAt = Get-Date
$hostInfo  = Get-HostSummary

if (-not $Quiet) {
    Write-Host ''
    Write-Host '  ARGUS' -ForegroundColor White -NoNewline
    Write-Host "  host posture scanner v$script:ArgusVersion" -ForegroundColor DarkGray
    Write-Host "  $($hostInfo.ComputerName)  |  $($hostInfo.OS)" -ForegroundColor DarkGray
    Write-Host "  running as $($hostInfo.UserName)$(if ($hostInfo.Elevated) { ' (elevated)' } else { ' (NOT elevated)' })" -ForegroundColor $(if ($hostInfo.Elevated) { 'DarkGray' } else { 'Yellow' })
    if (-not $hostInfo.Elevated) {
        Write-Host '  Several checks need administrator rights and will be skipped.' -ForegroundColor Yellow
    }
    Write-Host ''
}

$runAll = ($Categories -contains 'All')

if ($runAll -or $Categories -contains 'Persistence') { Invoke-PersistenceChecks }
if ($runAll -or $Categories -contains 'Defender')    { Invoke-DefenderChecks }
if ($runAll -or $Categories -contains 'Network')     { Invoke-NetworkChecks }
if ($runAll -or $Categories -contains 'Accounts')    { Invoke-AccountChecks }

$finishedAt = Get-Date
$findings   = @($script:Findings)

Write-ConsoleSummary -Findings $findings -HostInfo $hostInfo -Errors @($script:CheckErrors)

# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

if (-not $NoReport) {
    if (-not $OutputPath) {
        $desktop = [Environment]::GetFolderPath('Desktop')
        if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = $env:USERPROFILE }
        $OutputPath = Join-Path $desktop ("ArgusScan-{0}.html" -f $startedAt.ToString('yyyyMMdd-HHmmss'))
    }
    if ([System.IO.Path]::GetExtension($OutputPath) -ne '.html') { $OutputPath = "$OutputPath.html" }

    $htmlPath = New-HtmlReport -Findings $findings -HostInfo $hostInfo -OutputPath $OutputPath `
                               -StartedAt $startedAt -FinishedAt $finishedAt `
                               -Errors @($script:CheckErrors) -ChecksRun @($script:ChecksRun)

    Write-Host ''
    Write-Host "  Report: $htmlPath" -ForegroundColor Green

    if ($Json) {
        $jsonPath = [System.IO.Path]::ChangeExtension($OutputPath, '.json')
        $null = New-JsonReport -Findings $findings -HostInfo $hostInfo -OutputPath $jsonPath `
                               -StartedAt $startedAt -FinishedAt $finishedAt `
                               -Errors @($script:CheckErrors) -ChecksRun @($script:ChecksRun)
        Write-Host "  JSON:   $jsonPath" -ForegroundColor Green
    }
    Write-Host ''
}

# Exit code reflects the worst finding, so the script is usable from a
# scheduled task or a CI-style wrapper: 0 clean, 1 low/medium, 2 high, 3 critical.
$exitCode = 0
if     (@($findings | Where-Object { $_.Severity -eq 'Critical' }).Count -gt 0) { $exitCode = 3 }
elseif (@($findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0)     { $exitCode = 2 }
elseif (@($findings | Where-Object { $_.Severity -in @('Medium','Low') }).Count -gt 0) { $exitCode = 1 }

exit $exitCode
