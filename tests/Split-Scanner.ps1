<#
.SYNOPSIS
    Loads part of ArgusDriveScanner.ps1 without running the whole thing.

.DESCRIPTION
    The scanner is a single script that ends by opening a window, so a test
    cannot just dot-source it: on Linux the Windows Forms and System.Drawing
    type references fail to resolve at all, and on Windows the final
    ShowDialog would block forever.

    So the tests take a prefix of the file. The cut is found by matching a line
    rather than by counting them, and the slice is taken from the file on disk,
    so the tests exercise the code that actually ships and cannot drift from it.

.PARAMETER StopBefore
    Regex matching the first line to leave out. Everything above it is kept.
#>

function New-ScannerSlice {
    param(
        [Parameter(Mandatory)][string]$StopBefore,
        # Two-argument Join-Path only: the three-argument form is PowerShell 6+,
        # and these tests have to run under Windows PowerShell 5.1 as well.
        [string]$ScannerPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'ArgusDriveScanner.ps1')
    )

    $lines = Get-Content -LiteralPath $ScannerPath
    $cut = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $StopBefore) { $cut = $i; break }
    }
    if ($cut -lt 0) {
        throw "Could not find a line matching '$StopBefore' in $ScannerPath. The file has been restructured and the tests need updating to match."
    }

    $slice = Join-Path ([System.IO.Path]::GetTempPath()) ("scanner-slice-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
    Set-Content -LiteralPath $slice -Value $lines[0..($cut - 1)] -Encoding UTF8
    return $slice
}
