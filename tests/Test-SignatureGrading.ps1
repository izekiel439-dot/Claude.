<#
    Test-SignatureGrading.ps1 - regression guard for signature-aware path grading.

    A live scan on a normal machine used to raise a wall of High findings for
    OneDrive, Spotify and other validly-signed apps, purely because they install
    under the user profile. Get-PathFlagSeverity fixed that: a location flag is
    graded against the file's signature (Microsoft -> Info, other trusted
    publisher -> Low, unsigned/invalid -> High), while filename-deception flags
    (double extension, system-binary masquerade, ...) stay High regardless.

    This test shadows the signature/resolver helpers so it can assert the grade
    for invented scenarios without touching the real machine. Run it after any
    change to the grading logic in Core.ps1 or Checks.Persistence.ps1.
#>

$repo = Split-Path $PSScriptRoot -Parent
. "$repo\lib\Core.ps1"
. "$repo\lib\Checks.Persistence.ps1"

$script:Findings         = New-Object System.Collections.ArrayList
$script:Quiet            = $true
$script:ConsoleThreshold = 'Info'
$script:SigTable         = @{}

function Get-SignatureInfo {
    param([string]$Path)
    if ($Path -and $script:SigTable.ContainsKey($Path)) { return $script:SigTable[$Path] }
    [pscustomobject]@{ Path=$Path; Exists=$false; Status='NoFile'; Signer=''
        IsSigned=$false; IsMicrosoft=$false; IsTrusted=$false; Company=''; Product=''; VersionInfoOk=$false }
}
function Resolve-ExecutablePath {
    param([string]$CommandLine)
    if ($CommandLine -match '^"([^"]+)"') { return $matches[1] }
    return ($CommandLine -split '\s+')[0]
}
function Get-ReferencedScriptContent { param([string]$CommandLine) return $null }

function New-Sig {
    param($Path, [bool]$IsSigned, [bool]$IsMicrosoft, [bool]$IsTrusted, [string]$Company, [string]$Status='Valid')
    [pscustomobject]@{ Path=$Path; Exists=$true; Status=$Status; Signer=$Company
        IsSigned=$IsSigned; IsMicrosoft=$IsMicrosoft; IsTrusted=$IsTrusted; Company=$Company; Product=''; VersionInfoOk=$true }
}

$script:pass = 0; $script:fail = 0
function Check {
    param([string]$Name, [string]$Path, $Sig, [string]$Expect)
    $before = $script:Findings.Count
    if ($Sig) { $script:SigTable[$Path] = $Sig }
    Add-AutorunFinding -Source 'TestSource' -Name $Name -CommandLine ('"{0}"' -f $Path) -Check 'Test'
    $after = $script:Findings.Count
    $got = if ($after -gt $before) { $script:Findings[$after-1].Severity } else { '(no finding)' }
    if ($got -eq $Expect) { $script:pass++; "PASS  {0,-34} -> {1}" -f $Name, $got }
    else { $script:fail++; "FAIL  {0,-34} -> got '{1}', expected '{2}'" -f $Name, $got, $Expect }
}

# Signed, legit apps under the user profile must not scream High.
Check 'OneDrive (MS, AppData)'     'C:\Users\Zeke\AppData\Local\Microsoft\OneDrive\OneDrive.exe' (New-Sig 'p' $true $true  $true  'Microsoft Corporation') 'Info'
Check 'Spotify (trusted, Roaming)' 'C:\Users\Zeke\AppData\Roaming\Spotify\Spotify.exe'          (New-Sig 'p' $true $false $true  'Spotify AB')             'Low'

# Real threats must stay High.
Check 'Unsigned in Temp'           'C:\Users\Zeke\AppData\Local\Temp\abc\thing.exe'              (New-Sig 'p' $false $false $false '' 'NotSigned')          'High'
Check 'Unsigned in Public'         'C:\Users\Public\update.exe'                                  (New-Sig 'p' $false $false $false '' 'NotSigned')          'High'
Check 'Invalid signature'          'C:\Users\Zeke\AppData\Roaming\thing.exe'                     (New-Sig 'p' $true  $false $false 'Evil' 'HashMismatch')   'High'

# A valid signature must NOT launder a filename deception.
Check 'MS-signed svchost in AppData' 'C:\Users\Zeke\AppData\Local\svchost.exe'                   (New-Sig 'p' $true $true  $true  'Microsoft Corporation') 'High'
Check 'Signed double-extension'      'C:\Users\Zeke\Downloads\invoice.pdf.exe'                   (New-Sig 'p' $true $false $true  'SomeVendor')            'High'

# Controls: a signed app in a normal location is not a finding at all.
Check 'Signed app in Program Files'  'C:\Program Files\App\app.exe'                              (New-Sig 'p' $true $false $true  'Vendor')                '(no finding)'
Check 'MS binary in System32'        'C:\Windows\System32\legit.exe'                             (New-Sig 'p' $true $true  $true  'Microsoft Corporation') '(no finding)'

"===== $script:pass passed, $script:fail failed ====="
if ($script:fail -gt 0) { exit 1 }
