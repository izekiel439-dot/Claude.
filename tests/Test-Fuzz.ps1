<#
    Test-Fuzz.ps1 - property/fuzz testing for the pure classifiers in Core.ps1.

    Unlike the fixed-case suite, this generates thousands of random and
    adversarial strings each run (fresh seed every time) and asserts invariants
    that must hold for ANY input - the kind of thing a hand-written case list
    never stumbles onto:

      1. ROBUSTNESS   - no classifier throws on any input. A scanner parses
                        attacker-controlled registry/WMI/service strings; a parse
                        that throws is a check that silently dies mid-scan.
      2. TYPE/RANGE   - Test-SuspiciousPath / Test-SuspiciousCommand always return
                        an array; Get-PathFlagSeverity / Get-WorstSeverity always
                        return a valid severity name.
      3. METAMORPHIC  - a string built to be malicious is still detected after
                        random noise is wrapped around it (detection can't be
                        evaded by padding). Strong filename flags always grade High.
      4. MONOTONIC    - Get-WorstSeverity never returns something less severe than
                        its most-severe input.

    A failure prints the seed and the exact input so it is reproducible. Pass
    -Seed N to replay one.
#>
param(
    [int]$Seed = [int]([long](Get-Date).Ticks -band 0x7FFFFFFF),
    [int]$Iterations = 1500,
    # Escalation knobs. A driver bumps these each generation to make the inputs
    # progressively nastier: longer strings, and a higher chance that any given
    # character is replaced by a whole adversarial token (path fragment, LOLBin,
    # RTL override, ...) rather than a random letter.
    [int]$MaxLen = 60,
    [double]$TokenBias = 0.20
)

$repo = Split-Path $PSScriptRoot -Parent
. "$repo\lib\Core.ps1"

$rng = [System.Random]::new($Seed)
$script:pass = 0; $script:fail = 0; $script:fails = New-Object System.Collections.ArrayList
$validSeverities = @('Critical','High','Medium','Low','Info')

function Fail { param([string]$Msg) $script:fail++; if ($script:fails.Count -lt 20) { $null = $script:fails.Add($Msg) } }

# Alphabet skewed toward the characters that actually break parsers: quotes,
# backslashes, spaces, drive-letter colons, env-var percents, comma (rundll32),
# plus a couple of RTL/format unicode code points.
$alpha = ([char[]]('abcdefABCDEF0123 \\/:."'+"'"+'%$-_,;()[]<>|*?&=@'+"`t")) + [char]0x202E + [char]0x2066
$tokens = @(
    '\AppData\Local\Temp\','\AppData\Roaming\','\Users\Public\','\Downloads\','\Windows\Temp\',
    '.exe','.dll','.pdf.exe','.doc.scr','svchost.exe','a.exe',
    'powershell','-enc ','FromBase64String','IEX','rundll32.exe ','regsvr32 ','certutil -urlcache ',
    'http://185.10.20.30/','\\host\share\','C:\','"',',EntryPoint',' ',("x"+[char]0x202E+"cod.exe")
)

function New-RandomString {
    param([int]$Max = $MaxLen, [double]$Bias = $TokenBias)
    $len = $rng.Next(0, [Math]::Max(1, $Max))
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $len; $i++) {
        if ($rng.NextDouble() -lt $Bias) { $null = $sb.Append($tokens[$rng.Next(0, $tokens.Count)]) }
        else                             { $null = $sb.Append($alpha[$rng.Next(0, $alpha.Count)]) }
    }
    return $sb.ToString()
}

# ---- 1 & 2: robustness + type/range over pure classifiers ----
for ($i = 0; $i -lt $Iterations; $i++) {
    $s = New-RandomString

    try {
        $r = @(Test-SuspiciousPath $s)
        $script:pass++
    } catch { Fail "Test-SuspiciousPath threw on [seed $Seed] input <<$s>> : $($_.Exception.Message)" }

    try {
        $c = @(Test-SuspiciousCommand $s)
        # every hit must carry a valid severity
        foreach ($h in $c) { if ($validSeverities -notcontains $h.Severity) { Fail "Test-SuspiciousCommand bad severity '$($h.Severity)' on <<$s>>" } }
        $script:pass++
    } catch { Fail "Test-SuspiciousCommand threw on [seed $Seed] input <<$s>> : $($_.Exception.Message)" }

    try {
        $sev = Get-PathFlagSeverity -Reason $s -Signature $null
        if ($validSeverities -notcontains $sev) { Fail "Get-PathFlagSeverity returned invalid '$sev' on reason <<$s>>" } else { $script:pass++ }
    } catch { Fail "Get-PathFlagSeverity threw on reason <<$s>> : $($_.Exception.Message)" }

    try {
        $null = Resolve-ExecutablePath $s   # may hit disk for unquoted probes; just must not throw
        $script:pass++
    } catch { Fail "Resolve-ExecutablePath threw on [seed $Seed] input <<$s>> : $($_.Exception.Message)" }

    try {
        $null = Expand-PathVariables $s
        $null = Get-CommonName $s
        $script:pass++
    } catch { Fail "Expand/CommonName threw on <<$s>> : $($_.Exception.Message)" }
}

# ---- 3: metamorphic - noise around a malicious core must not hide it ----
$noisyDirs = { 'C:\' + (New-RandomString 20) -replace '[\\"]', 'z' }  # random-but-safe dir fragment
for ($i = 0; $i -lt 300; $i++) {
    # location flag survives arbitrary prefix
    $p = (& $noisyDirs) + '\AppData\Roaming\' + ('n'*$rng.Next(1,8)) + '.exe'
    if (-not ((Test-SuspiciousPath $p) -contains 'Runs from the roaming profile')) { Fail "roaming flag lost on <<$p>>" } else { $script:pass++ }

    # double-extension survives any leading directory
    $p2 = (& $noisyDirs) + '\' + ('a'*$rng.Next(1,6)) + '.pdf.exe'
    if (-not ((Test-SuspiciousPath $p2) -contains 'Filename uses a double extension')) { Fail "double-ext lost on <<$p2>>" } else { $script:pass++ }

    # strong flags always grade High regardless of signature trust
    $strong = $script:StrongPathReasons[$rng.Next(0, $script:StrongPathReasons.Count)]
    $sig = [pscustomobject]@{ Exists=$true; IsMicrosoft=($rng.Next(0,2)-eq1); IsTrusted=$true }
    if ((Get-PathFlagSeverity -Reason $strong -Signature $sig) -ne 'High') { Fail "strong flag not High: <<$strong>>" } else { $script:pass++ }

    # encoded-command core is detected inside random padding
    $cmd = (New-RandomString 15) + ' -enc ' + (-join (1..40 | ForEach-Object { $alpha[$rng.Next(0,52)] }))
    # (padding may contain quotes/percent; the -enc rule only needs 20+ base64-ish chars, so build a clean tail)
    $cmd = (New-RandomString 15) + ' -encodedcommand SQBFAFgAIABhAGIAYwBkAGUAZgBnAGgAaQBqAGsAbABtAG4A'
    if (@(Test-SuspiciousCommand $cmd).Count -lt 1) { Fail "encoded cmd not detected: <<$cmd>>" } else { $script:pass++ }
}

# ---- 4: Get-WorstSeverity monotonicity over random severity sets ----
for ($i = 0; $i -lt 300; $i++) {
    $n = $rng.Next(0, 6)
    $set = @(1..$n | ForEach-Object { $validSeverities[$rng.Next(0, $validSeverities.Count)] })
    $worst = Get-WorstSeverity $set
    if ($validSeverities -notcontains $worst) { Fail "worst returned invalid '$worst'"; continue }
    $ok = $true
    foreach ($s in $set) { if ($script:SeverityRank[$worst] -gt $script:SeverityRank[$s]) { $ok = $false } }
    if ($ok) { $script:pass++ } else { Fail "worst '$worst' less severe than an input in [$($set -join ',')]" }
}

"" ; foreach ($f in $script:fails) { $f }
"seed $Seed  |  $Iterations iters  |  maxlen $MaxLen  |  tokenbias $TokenBias"
"===== Fuzz: $script:pass passed, $script:fail failed ====="
if ($script:fail -gt 0) { exit 1 }
