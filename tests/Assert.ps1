<#
    A dozen lines of assertion helper, so the tests need nothing installed.
    The scanner itself promises "no install, no build tools, no dependencies";
    its tests should not quietly need Pester to make that true.

    Dot-source this, call Assert, then end with Exit-WithTestResult.
#>

$script:TestFailures = 0
$script:TestCount    = 0

function Assert {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Condition,
        [string]$Detail = ''
    )
    $script:TestCount++
    if ($Condition) {
        Write-Host "  PASS  $Name" -ForegroundColor Green
    }
    else {
        $script:TestFailures++
        Write-Host "  FAIL  $Name$(if ($Detail) { "  ($Detail)" })" -ForegroundColor Red
    }
}

function Start-TestGroup {
    param([Parameter(Mandatory)][string]$Name)
    Write-Host ''
    Write-Host $Name -ForegroundColor Cyan
}

function Exit-WithTestResult {
    Write-Host ''
    if ($script:TestFailures -gt 0) {
        Write-Host "$script:TestFailures of $script:TestCount assertions FAILED" -ForegroundColor Red
        exit 1
    }
    Write-Host "all $script:TestCount assertions passed" -ForegroundColor Green
    exit 0
}
