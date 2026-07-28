<#
    Core.ps1 - Shared plumbing for the Argus host auditor.

    Dot-sourced by Invoke-PCScan.ps1, so everything here lands in the caller's
    script scope. Nothing in this file performs a check; it only provides the
    finding model, caching helpers and the file/path forensics used by the
    check modules.
#>

# Deliberately no Set-StrictMode: this script walks a large amount of untrusted
# registry, WMI and ACL data where absent properties are the norm, and a hard
# stop mid-scan is worse than a skipped check.

# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

$script:Findings        = New-Object System.Collections.ArrayList
$script:SignatureCache  = @{}
$script:AclCache        = @{}
$script:CheckErrors     = New-Object System.Collections.ArrayList
$script:ChecksRun       = New-Object System.Collections.ArrayList

$script:SeverityRank = @{
    'Critical' = 0
    'High'     = 1
    'Medium'   = 2
    'Low'      = 3
    'Info'     = 4
}

# Directories an attacker drops payloads into far more often than a vendor does.
$script:SuspiciousPathPatterns = @(
    @{ Pattern = '\\Windows\\Temp\\';                Reason = 'Runs from the machine-wide temp directory' }
    @{ Pattern = '\\AppData\\Local\\Temp\\';         Reason = 'Runs from the user temp directory' }
    @{ Pattern = '\\AppData\\Roaming\\';             Reason = 'Runs from the roaming profile' }
    @{ Pattern = '\\AppData\\Local\\(?!Programs\\)'; Reason = 'Runs from local AppData' }
    @{ Pattern = '\\Users\\Public\\';                Reason = 'Runs from the Public profile (world-writable)' }
    @{ Pattern = '\\ProgramData\\[^\\]+\.(exe|dll|scr|js|vbs|ps1)$'; Reason = 'Loose binary at the root of ProgramData' }
    @{ Pattern = '\\\$Recycle\.Bin\\';               Reason = 'Runs from the recycle bin' }
    @{ Pattern = '\\Windows\\Tasks\\';               Reason = 'Runs from the legacy Tasks directory' }
    @{ Pattern = '\\Windows\\Debug\\';               Reason = 'Runs from the Debug directory' }
    @{ Pattern = '\\Windows\\Fonts\\';               Reason = 'Runs from the Fonts directory' }
    @{ Pattern = '\\Downloads\\';                    Reason = 'Runs directly from the Downloads folder' }
    @{ Pattern = '\\Music\\|\\Pictures\\|\\Videos\\';Reason = 'Runs from a media library folder' }
    @{ Pattern = '\\Windows\\System32\\Tasks\\';     Reason = 'Executable staged in the task definition folder' }
    @{ Pattern = '\\Windows\\SysWOW64\\Tasks\\';     Reason = 'Executable staged in the task definition folder' }
    @{ Pattern = '\\PerfLogs\\';                     Reason = 'Runs from PerfLogs' }
    @{ Pattern = '\\Windows\\addins\\';              Reason = 'Runs from the addins directory' }
)

# Signed Microsoft tools attackers use as proxies to run their own code.
$script:LolBinNames = @(
    'mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe',
    'wmic.exe','cscript.exe','wscript.exe','msbuild.exe','installutil.exe',
    'regasm.exe','regsvcs.exe','cmstp.exe','msiexec.exe','forfiles.exe',
    'pcalua.exe','scriptrunner.exe','odbcconf.exe','ieexec.exe','presentationhost.exe',
    'msdt.exe','hh.exe','ftp.exe','curl.exe','sc.exe','schtasks.exe','at.exe'
)

# Command-line shapes that are strong signals regardless of which binary runs them.
$script:SuspiciousCommandPatterns = @(
    @{ Pattern = '-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}'; Reason = 'Base64-encoded PowerShell command'; Severity = 'Critical' }
    @{ Pattern = 'FromBase64String';                          Reason = 'Decodes base64 at runtime';        Severity = 'High' }
    @{ Pattern = '(IEX|Invoke-Expression)';                   Reason = 'Evaluates a string as code';       Severity = 'High' }
    @{ Pattern = '(DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|Start-BitsTransfer)'; Reason = 'Downloads content at runtime'; Severity = 'High' }
    @{ Pattern = '-w(indowstyle)?\s+hidden|-nop\b|-noprofile\b';  Reason = 'PowerShell launched hidden / without profile'; Severity = 'Medium' }
    @{ Pattern = '-ExecutionPolicy\s+(Bypass|Unrestricted)';   Reason = 'Bypasses PowerShell execution policy'; Severity = 'Medium' }
    @{ Pattern = 'certutil.*-(urlcache|decode|encode)';        Reason = 'certutil used as a downloader/decoder'; Severity = 'Critical' }
    @{ Pattern = 'regsvr32.*scrobj\.dll|regsvr32.*/i:http';    Reason = 'Squiblydoo-style regsvr32 execution'; Severity = 'Critical' }
    @{ Pattern = 'mshta.*(http|javascript:|vbscript:)';        Reason = 'mshta executing remote or inline script'; Severity = 'Critical' }
    @{ Pattern = 'rundll32.*javascript:';                      Reason = 'rundll32 executing inline JavaScript'; Severity = 'Critical' }
    @{ Pattern = '\bbitsadmin\b.*(/transfer|/addfile)';        Reason = 'BITS used to transfer a file';     Severity = 'High' }
    @{ Pattern = 'wmic.*process.*call.*create';                Reason = 'WMI used to spawn a process';      Severity = 'High' }
    @{ Pattern = '\\\\[a-z0-9._-]+\\[a-z0-9$._-]+\\';          Reason = 'Executes from a UNC network path'; Severity = 'High' }
    @{ Pattern = 'https?://\d{1,3}(\.\d{1,3}){3}';             Reason = 'References a bare IP over HTTP';   Severity = 'High' }
)

# --------------------------------------------------------------------------
# Finding model
# --------------------------------------------------------------------------

function Add-Finding {
    <#
        .SYNOPSIS
        Records a single observation. Everything the report shows comes from here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity = 'Info',
        [string]$Detail = '',
        [string]$Recommendation = '',
        [object]$Evidence,
        [string]$Check = ''
    )

    $evidencePairs = New-Object System.Collections.ArrayList
    if ($null -ne $Evidence) {
        if ($Evidence -is [System.Collections.IDictionary]) {
            foreach ($key in $Evidence.Keys) {
                $value = $Evidence[$key]
                if ($null -eq $value) { continue }
                if ($value -is [array]) { $value = ($value | ForEach-Object { "$_" }) -join ', ' }
                $text = "$value".Trim()
                if ($text.Length -eq 0) { continue }
                $null = $evidencePairs.Add([pscustomobject]@{ Name = "$key"; Value = $text })
            }
        }
        else {
            $null = $evidencePairs.Add([pscustomobject]@{ Name = 'Detail'; Value = "$Evidence" })
        }
    }

    $finding = [pscustomobject]@{
        Id             = [guid]::NewGuid().ToString('N').Substring(0, 8)
        Category       = $Category
        Check          = $Check
        Title          = $Title
        Severity       = $Severity
        Rank           = $script:SeverityRank[$Severity]
        Detail         = $Detail
        Recommendation = $Recommendation
        Evidence       = @($evidencePairs)
    }

    $null = $script:Findings.Add($finding)
    Write-FindingToConsole -Finding $finding
    return $finding
}

function Write-FindingToConsole {
    param([Parameter(Mandatory)][object]$Finding)

    if ($script:Quiet) { return }
    if ($script:SeverityRank[$Finding.Severity] -gt $script:SeverityRank[$script:ConsoleThreshold]) { return }

    $color = switch ($Finding.Severity) {
        'Critical' { 'Magenta' }
        'High'     { 'Red' }
        'Medium'   { 'Yellow' }
        'Low'      { 'Cyan' }
        default    { 'DarkGray' }
    }
    Write-Host ("  [{0,-8}] {1}" -f $Finding.Severity.ToUpper(), $Finding.Title) -ForegroundColor $color
    if ($Finding.Detail) {
        Write-Host ("             {0}" -f $Finding.Detail) -ForegroundColor DarkGray
    }
}

function Write-ScanLog {
    param([string]$Message, [string]$Level = 'Info')

    if ($script:Quiet) { return }
    $color = switch ($Level) {
        'Step'  { 'White' }
        'Warn'  { 'Yellow' }
        'Error' { 'Red' }
        'Good'  { 'Green' }
        default { 'DarkGray' }
    }
    $prefix = if ($Level -eq 'Step') { "`n==> " } else { '    ' }
    Write-Host ("{0}{1}" -f $prefix, $Message) -ForegroundColor $color
}

function Invoke-Check {
    <#
        .SYNOPSIS
        Runs one check in a guard so a single failure never aborts the scan.
        Missing cmdlets and access-denied are normal on some SKUs.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body
    )

    $null = $script:ChecksRun.Add($Name)
    try {
        & $Body
    }
    catch {
        $null = $script:CheckErrors.Add([pscustomobject]@{
            Check   = $Name
            Message = $_.Exception.Message
        })
        Write-ScanLog -Message "check '$Name' could not complete: $($_.Exception.Message)" -Level 'Warn'
    }
}

# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------

function Test-IsElevated {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Get-HostSummary {
    $os  = $null
    $cs  = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }

    [pscustomobject]@{
        ComputerName  = $env:COMPUTERNAME
        UserName      = "$env:USERDOMAIN\$env:USERNAME"
        Elevated      = Test-IsElevated
        OS            = if ($os) { $os.Caption } else { 'unknown' }
        OSVersion     = if ($os) { $os.Version } else { [string][Environment]::OSVersion.Version }
        InstallDate   = if ($os) { $os.InstallDate } else { $null }
        LastBoot      = if ($os) { $os.LastBootUpTime } else { $null }
        Domain        = if ($cs) { $cs.Domain } else { 'unknown' }
        PartOfDomain  = if ($cs) { $cs.PartOfDomain } else { $false }
        Manufacturer  = if ($cs) { $cs.Manufacturer } else { 'unknown' }
        Model         = if ($cs) { $cs.Model } else { 'unknown' }
        PSVersion     = $PSVersionTable.PSVersion.ToString()
    }
}

# --------------------------------------------------------------------------
# Registry helpers
# --------------------------------------------------------------------------

function Get-RegistryValues {
    <#
        .SYNOPSIS
        Returns the values under a key as Name/Value pairs, minus PowerShell's
        own PS* noise properties. Returns nothing when the key is absent.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }

    foreach ($property in $item.PSObject.Properties) {
        if ($property.Name -like 'PS*') { continue }
        [pscustomobject]@{
            Key   = $Path
            Name  = $property.Name
            Value = $property.Value
        }
    }
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    if (-not $item.PSObject.Properties[$Name]) { return $null }
    return $item.$Name
}

function Get-UserHivePaths {
    <#
        .SYNOPSIS
        Every loaded user hive, so per-user persistence is not missed just
        because the scan runs as a different account.
    #>
    $result = New-Object System.Collections.ArrayList

    $null = $result.Add([pscustomobject]@{ Sid = 'Current'; User = "$env:USERNAME"; Root = 'HKCU:' })

    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path 'HKU:\')) { return $result }

    foreach ($hive in (Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue)) {
        $sid = Split-Path $hive.Name -Leaf
        # Skip machine/service SIDs and the _Classes shadow hives.
        if ($sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        $name = $sid
        try {
            $account = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value
            if ($account) { $name = $account }
        }
        catch { }
        $null = $result.Add([pscustomobject]@{ Sid = $sid; User = $name; Root = "HKU:\$sid" })
    }

    return $result
}

# --------------------------------------------------------------------------
# Path and signature forensics
# --------------------------------------------------------------------------

function Expand-PathVariables {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    # Native NT / systemroot prefixes seen in service ImagePath values.
    $expanded = $expanded -replace '^\\\?\?\\', ''
    $expanded = $expanded -replace '^\\SystemRoot\\', "$env:SystemRoot\"
    $expanded = $expanded -replace '^system32\\', "$env:SystemRoot\system32\"
    return $expanded.Trim()
}

function Get-ReferencedScriptContent {
    <#
        .SYNOPSIS
        Reads the content of a script file a command line points at.

        A Run key or Scheduled Task entry that reads
        "powershell.exe -File C:\ProgramData\Vendor\task.ps1" looks completely
        clean by command-line pattern matching alone - the badness, if any, is
        inside task.ps1, which nothing was reading before. This is capped at
        400 lines so one huge referenced file can't stall a scan.
    #>
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }

    foreach ($match in [regex]::Matches($CommandLine, '(?i)(?<path>"[^"]+\.(ps1|vbs|js|jse|bat|cmd|wsf|hta)"|\S+\.(ps1|vbs|js|jse|bat|cmd|wsf|hta)\b)')) {
        $candidate = $match.Groups['path'].Value.Trim('"')
        $expanded  = Expand-PathVariables -Path $candidate
        if (-not (Test-Path -LiteralPath $expanded -PathType Leaf -ErrorAction SilentlyContinue)) { continue }

        try {
            $content = (Get-Content -LiteralPath $expanded -TotalCount 400 -ErrorAction Stop) -join "`n"
            if ($content) { return [pscustomobject]@{ Path = $expanded; Content = $content } }
        }
        catch { }
    }
    return $null
}

function Resolve-ExecutablePath {
    <#
        .SYNOPSIS
        Extracts the on-disk image from a command line.

        Handles quoted paths, unquoted paths containing spaces, bare command
        names on PATH, and rundll32/regsvr32 style invocations where the
        interesting file is an argument rather than the image.
    #>
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $line = Expand-PathVariables -Path $CommandLine.Trim()

    $candidate = $null

    if ($line.StartsWith('"')) {
        $end = $line.IndexOf('"', 1)
        if ($end -gt 1) { $candidate = $line.Substring(1, $end - 1) }
    }

    if (-not $candidate) {
        # Walk the unquoted string looking for the longest prefix that exists on
        # disk. "C:\Program Files\App\a.exe -x" must not resolve to "C:\Program".
        if ($line -match '^([a-zA-Z]:\\|\\\\)') {
            $parts = $line.Split(' ')
            for ($i = $parts.Count; $i -ge 1; $i--) {
                $probe = ($parts[0..($i - 1)] -join ' ').Trim()
                if ($probe -match '\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js|jar|msi)$' -or (Test-Path -LiteralPath $probe -PathType Leaf -ErrorAction SilentlyContinue)) {
                    $candidate = $probe
                    break
                }
            }
            if (-not $candidate) { $candidate = $parts[0] }
        }
        else {
            $candidate = $line.Split(' ')[0]
        }
    }

    if (-not $candidate) { return $null }
    $candidate = $candidate.Trim('"', ' ', "`t")

    # rundll32 / regsvr32 point at a DLL that matters more than the host binary.
    $leaf = try { Split-Path $candidate -Leaf } catch { $candidate }
    if ($leaf -match '^(rundll32|regsvr32)(\.exe)?$') {
        $remainder = $line.Substring([Math]::Min($line.Length, $line.IndexOf($leaf) + $leaf.Length)).Trim()
        $remainder = ($remainder -replace '^(/[a-zA-Z]\s+)+', '').Trim().Trim('"')
        if ($remainder) {
            $dll = $remainder.Split(',')[0].Split(' ')[0].Trim('"')
            $dll = Expand-PathVariables -Path $dll
            if ($dll -match '\.(dll|ocx|cpl)$') { $candidate = $dll }
        }
    }

    if ($candidate -notmatch '[\\/]') {
        $resolved = Get-Command $candidate -ErrorAction SilentlyContinue |
                    Where-Object { $_.Path } |
                    Select-Object -First 1
        if ($resolved) { $candidate = $resolved.Path }
    }

    return $candidate
}

function Get-SignatureInfo {
    <#
        .SYNOPSIS
        Authenticode verdict for a file, cached because the call is expensive
        and the same binaries recur across autorun locations.
    #>
    param([string]$Path)

    $empty = [pscustomobject]@{
        Path = $Path; Exists = $false; Status = 'NoFile'; Signer = ''
        IsSigned = $false; IsMicrosoft = $false; IsTrusted = $false
        Company = ''; Product = ''; VersionInfoOk = $false
    }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $empty }
    $key = $Path.ToLowerInvariant()
    if ($script:SignatureCache.ContainsKey($key)) { return $script:SignatureCache[$key] }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) {
        $script:SignatureCache[$key] = $empty
        return $empty
    }

    $status = 'Unknown'; $signer = ''; $company = ''; $product = ''; $versionOk = $false
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $status = "$($signature.Status)"
        if ($signature.SignerCertificate) { $signer = $signature.SignerCertificate.Subject }
    }
    catch { $status = 'Unreadable' }

    try {
        $info = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo
        if ($info) {
            $company   = "$($info.CompanyName)".Trim()
            $product   = "$($info.ProductName)".Trim()
            $versionOk = -not [string]::IsNullOrWhiteSpace($company)
        }
    }
    catch { }

    $isSigned  = ($status -ne 'NotSigned' -and $status -ne 'Unreadable' -and $status -ne 'Unknown')
    $isTrusted = ($status -eq 'Valid')

    # Signer subject is authoritative; company name is only a hint because it is
    # trivially forged in an unsigned file's resources.
    $isMicrosoft = $false
    if ($isTrusted -and $signer -match 'O=Microsoft Corporation|CN=Microsoft (Windows|Corporation)') { $isMicrosoft = $true }

    $result = [pscustomobject]@{
        Path = $Path; Exists = $true; Status = $status; Signer = (Get-CommonName $signer)
        IsSigned = $isSigned; IsMicrosoft = $isMicrosoft; IsTrusted = $isTrusted
        Company = $company; Product = $product; VersionInfoOk = $versionOk
    }
    $script:SignatureCache[$key] = $result
    return $result
}

function Get-CommonName {
    <#
        .SYNOPSIS
        Pulls CN= out of an X.500 subject so reports stay readable.
    #>
    param([string]$Subject)

    if ([string]::IsNullOrWhiteSpace($Subject)) { return '' }
    if ($Subject -match 'CN=(?<cn>[^,]+)') { return $Matches['cn'].Trim('"', ' ') }
    return $Subject
}

function Test-SuspiciousPath {
    <#
        .SYNOPSIS
        Returns the reasons a path looks like a payload drop site, or nothing.
    #>
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return @() }
    $reasons = New-Object System.Collections.ArrayList

    foreach ($rule in $script:SuspiciousPathPatterns) {
        if ($Path -match $rule.Pattern) { $null = $reasons.Add($rule.Reason) }
    }

    $leaf = try { Split-Path $Path -Leaf } catch { $Path }

    # Right-to-left override and friends: used to disguise "xxxexe.doc" as a document.
    if ($leaf -match "[\u202A-\u202E\u2066-\u2069]") {
        $null = $reasons.Add('Filename contains a bidirectional text override character')
    }
    if ($leaf -match '\.(doc|docx|pdf|jpg|png|txt|xls|xlsx|mp4|zip)\s*\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|msi|scf|url|lnk)$') {
        $null = $reasons.Add('Filename uses a double extension')
    }
    if ($leaf -match '\s+\.(exe|scr|com|dll)$') {
        $null = $reasons.Add('Filename pads the extension with whitespace')
    }
    # System binary names living outside the system directory.
    if ($leaf -match '^(svchost|lsass|csrss|services|winlogon|explorer|smss|spoolsv|taskhost|taskhostw|dwm|conhost|wininit|lsm|sihost|ctfmon|dllhost|runtimebroker|searchindexer|fontdrvhost)\.exe$' -and
        $Path -notmatch '\\Windows\\(System32|SysWOW64|WinSxS)\\') {
        $null = $reasons.Add('Masquerades as a Windows system binary but sits outside System32')
    }

    return @($reasons)
}

function Test-SuspiciousCommand {
    <#
        .SYNOPSIS
        Matches a command line against known tradecraft patterns.
    #>
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
    $hits = New-Object System.Collections.ArrayList

    foreach ($rule in $script:SuspiciousCommandPatterns) {
        if ($CommandLine -match $rule.Pattern) {
            $null = $hits.Add([pscustomobject]@{ Reason = $rule.Reason; Severity = $rule.Severity })
        }
    }
    return @($hits)
}

function Get-WorstSeverity {
    <#
        .SYNOPSIS
        Highest severity in a set, defaulting when the set is empty.
    #>
    param([string[]]$Severities, [string]$Default = 'Info')

    $best = $Default
    foreach ($severity in $Severities) {
        if ([string]::IsNullOrWhiteSpace($severity)) { continue }
        if ($script:SeverityRank[$severity] -lt $script:SeverityRank[$best]) { $best = $severity }
    }
    return $best
}

function Test-UserWritable {
    <#
        .SYNOPSIS
        True when a non-administrator can modify the path.

        This is what turns "a service runs as SYSTEM" into "any user on this box
        can become SYSTEM", so it drives most of the privilege-path findings.
    #>
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $key = $Path.ToLowerInvariant()
    if ($script:AclCache.ContainsKey($key)) { return $script:AclCache[$key] }

    $result = $null
    try {
        if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
            $script:AclCache[$key] = $null
            return $null
        }

        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $riskyIdentities = @(
            'Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users',
            'NT AUTHORITY\INTERACTIVE','BUILTIN\Guests','NT AUTHORITY\ANONYMOUS LOGON'
        )
        $riskyRights = 'FullControl|Modify|Write|CreateFiles|WriteData|AppendData|ChangePermissions|TakeOwnership'

        $granting = New-Object System.Collections.ArrayList
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $identity = "$($ace.IdentityReference)"
            if ($riskyIdentities -notcontains $identity) { continue }
            if ("$($ace.FileSystemRights)" -notmatch $riskyRights) { continue }
            $null = $granting.Add("$identity : $($ace.FileSystemRights)")
        }

        if ($granting.Count -gt 0) {
            $result = [pscustomobject]@{ Writable = $true;  Grants = @($granting); Owner = "$($acl.Owner)" }
        }
        else {
            $result = [pscustomobject]@{ Writable = $false; Grants = @();          Owner = "$($acl.Owner)" }
        }
    }
    catch { $result = $null }

    $script:AclCache[$key] = $result
    return $result
}

function Get-ProcessForPid {
    param([int]$ProcessId)

    if ($ProcessId -le 0) { return $null }
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $path = $null
        try { $path = $process.Path } catch { }
        if (-not $path) {
            $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
            if ($wmi) { $path = $wmi.ExecutablePath }
        }
        return [pscustomobject]@{ Id = $ProcessId; Name = $process.ProcessName; Path = $path }
    }
    catch { return $null }
}

function ConvertTo-DisplayString {
    param([object]$Value, [int]$MaxLength = 400)

    if ($null -eq $Value) { return '' }
    if ($Value -is [array]) { $Value = ($Value | ForEach-Object { "$_" }) -join '; ' }
    $text = "$Value".Trim()
    if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength) + ' ...(truncated)' }
    return $text
}
