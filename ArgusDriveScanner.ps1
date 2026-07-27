<#
.SYNOPSIS
    Argus Drive Scanner - a windowed app for inspecting removable drives.

.DESCRIPTION
    Pick a drive, press Scan, read the results. Self-contained: no install,
    no build tools, no dependencies beyond what ships with Windows.

    This looks for the tricks that target removable media specifically -
    autorun entries, shortcut worms that hide your real folders, files whose
    extension lies about their contents, right-to-left filename spoofing,
    executables buried inside archives, and NTFS alternate data streams.
    Defender does not flag most of these, because individually none of them
    are malware; they are packaging.

    It can also drive Defender itself over the same path, so one press gets
    you both the signature scan and the structural one.

    NOTHING ON THE DRIVE IS EXECUTED. Files are opened read-only, shortcuts
    are parsed rather than followed, and archives are listed from their
    directory records without being extracted.

.PARAMETER Path
    Skip the picker and scan this path immediately.

.PARAMETER NoGui
    Run headless and write a report. Useful from a scheduled task.

.EXAMPLE
    .\ArgusDriveScanner.ps1
    Opens the window.

.EXAMPLE
    .\ArgusDriveScanner.ps1 -Path E:\ -NoGui
    Scans E:\ with no window and writes a report to the Desktop.

.NOTES
    Requires Windows PowerShell 5.1 (already on Windows 10/11) or PowerShell 7+.
    Windows Forms needs a single-threaded apartment; use Scan-Drive.cmd, or
    run pwsh with -STA if you launch it by hand from PowerShell 7.

    The scan runs on the UI thread. The window keeps drawing because the checks
    pump the message queue between steps, so Stop stays clickable throughout -
    but any single long call that reports no progress will freeze it until that
    call returns. Ticking "Also run Microsoft Defender" is the one that shows:
    Start-MpScan can sit there for minutes with the window unresponsive.
#>

[CmdletBinding()]
param(
    [string]$Path,
    [switch]$NoGui,
    [switch]$Deep,
    [switch]$DefenderScan
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$script:AppVersion     = '1.0.0'

# ===========================================================================
#  SCAN ENGINE
#
#  Runs on the calling thread - the UI thread, in windowed mode. There is no
#  runspace, no marshalling, and no second copy of these functions: the window
#  calls Start-DriveScan the same way the headless path does.
#
#  What that costs is the thing a background thread gave for free. A scan
#  holding the UI thread means nothing repaints unless we let it, so progress
#  reporting and cancellation checks pump the message queue as they go (see
#  Update-Progress below). Long single calls that report no progress - notably
#  Start-MpScan in Invoke-DefenderScan - still block the window for their
#  duration, because there is no point during them at which we get control back.
# ===========================================================================

# --- state shared with whatever is driving the scan ------------------------
# $script:Sync carries progress, findings and the cancel flag. It is no longer
# read from another thread, so it needs no synchronisation - but it stays the
# single channel between the checks and the front end, which is what lets the
# window and the headless path share one engine.

# Whichever front end is driving installs a pump here: the window repaints and
# processes clicks, headless mode writes a line. Called often enough to feel
# live, throttled so DoEvents does not become the bottleneck.
$script:PumpUi      = $null
$script:PumpWatch   = [System.Diagnostics.Stopwatch]::StartNew()
$script:PumpEveryMs = 100

function Update-Progress {
    param([switch]$Force)

    if (-not $script:PumpUi) { return }
    if (-not $Force -and $script:PumpWatch.ElapsedMilliseconds -lt $script:PumpEveryMs) { return }
    $script:PumpWatch.Restart()
    # Assigned away so a front end that accidentally emits something cannot
    # leak it into the pipeline of whatever check happened to call us.
    $null = & $script:PumpUi
}

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity = 'Info',
        [string]$Detail = '',
        [string]$Recommendation = '',
        [string]$File = '',
        [System.Collections.IDictionary]$Evidence
    )

    $rank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }[$Severity]

    $pairs = New-Object System.Collections.ArrayList
    if ($Evidence) {
        foreach ($key in $Evidence.Keys) {
            $value = $Evidence[$key]
            if ($null -eq $value) { continue }
            if ($value -is [array]) { $value = ($value | ForEach-Object { "$_" }) -join ', ' }
            $text = "$value".Trim()
            if ($text.Length -eq 0) { continue }
            if ($text.Length -gt 500) { $text = $text.Substring(0, 500) + ' ...(truncated)' }
            $null = $pairs.Add([pscustomobject]@{ Name = "$key"; Value = $text })
        }
    }

    $null = $script:Sync.Findings.Add([pscustomobject]@{
        Severity       = $Severity
        Rank           = $rank
        Title          = $Title
        Detail         = $Detail
        Recommendation = $Recommendation
        File           = $File
        Drive          = $script:CurrentDrive
        Evidence       = @($pairs)
    })
}

# When several drives are scanned in one run, each check still reports 0-100
# for its own drive; these map that onto the drive's slice of the overall bar.
$script:PercentBase = 0
$script:PercentSpan = 100
$script:CurrentDrive = ''

function Set-Status {
    param([string]$Text, [int]$Percent = -1)

    $prefix = if ($script:CurrentDrive) { "$($script:CurrentDrive)  " } else { '' }
    $script:Sync.Status = "$prefix$Text"

    if ($Percent -ge 0) {
        $mapped = $script:PercentBase + ($Percent * $script:PercentSpan / 100.0)
        $script:Sync.Percent = [Math]::Max(0, [Math]::Min(100, [int]$mapped))
    }

    # A status change is exactly the moment the user should see something move.
    Update-Progress -Force
}

function Test-Cancelled {
    # Every check calls this from inside its own loop, which makes it the one
    # place guaranteed to be reached often during long work - so it doubles as
    # the pump. Without this the window would freeze between status updates and
    # the Stop button would never see its click.
    Update-Progress
    return [bool]$script:Sync.Cancel
}

# --- helpers ---------------------------------------------------------------

function Get-FileHeader {
    <#
        Reads the first bytes of a file to learn what it actually is. File
        extensions are a naming convention; the header is the truth.
    #>
    param([string]$FilePath)

    $bytes = New-Object byte[] 8
    $read = 0
    try {
        $stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try { $read = $stream.Read($bytes, 0, 8) } finally { $stream.Dispose() }
    }
    catch { return $null }
    if ($read -lt 2) { return $null }

    $hex = ($bytes[0..([Math]::Min($read, 8) - 1)] | ForEach-Object { $_.ToString('X2') }) -join ''

    if ($hex.StartsWith('4D5A'))         { return 'PE executable' }      # MZ
    if ($hex.StartsWith('7F454C46'))     { return 'ELF executable' }
    if ($hex.StartsWith('504B0304') -or $hex.StartsWith('504B0506')) { return 'ZIP archive / Office document' }
    if ($hex.StartsWith('D0CF11E0'))     { return 'Legacy Office document' }
    if ($hex.StartsWith('25504446'))     { return 'PDF' }
    if ($hex.StartsWith('FFD8FF'))       { return 'JPEG image' }
    if ($hex.StartsWith('89504E47'))     { return 'PNG image' }
    if ($hex.StartsWith('47494638'))     { return 'GIF image' }
    if ($hex.StartsWith('377ABCAF'))     { return '7-Zip archive' }
    if ($hex.StartsWith('52617221'))     { return 'RAR archive' }
    if ($hex.StartsWith('1F8B'))         { return 'GZIP archive' }
    if ($hex.StartsWith('4C000000'))     { return 'Windows shortcut' }
    if ($hex.StartsWith('CAFEBABE'))     { return 'Java class' }
    return $null
}

function Get-SignatureVerdict {
    param([string]$FilePath)

    $status = 'Unknown'; $signer = ''
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop
        $status = "$($signature.Status)"
        if ($signature.SignerCertificate) {
            $subject = $signature.SignerCertificate.Subject
            if ($subject -match 'CN=(?<cn>[^,]+)') { $signer = $Matches['cn'].Trim('"', ' ') } else { $signer = $subject }
        }
    }
    catch { $status = 'Unreadable' }

    [pscustomobject]@{
        Status   = $status
        Signer   = $signer
        IsValid  = ($status -eq 'Valid')
        IsSigned = ($status -notin @('NotSigned', 'Unreadable', 'Unknown'))
    }
}

function Get-QuickHash {
    param([string]$FilePath)
    try { return (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { return '' }
}

$script:ExecutableExtensions = @(
    '.exe','.dll','.scr','.com','.pif','.cpl','.ocx','.sys','.drv','.msi','.msp','.jar'
)
$script:ScriptExtensions = @(
    '.bat','.cmd','.ps1','.psm1','.vbs','.vbe','.js','.jse','.wsf','.wsh','.hta','.reg','.lnk','.url','.scf','.inf'
)
$script:DocumentExtensions = @(
    '.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.txt','.rtf','.jpg','.jpeg','.png','.gif','.bmp','.mp3','.mp4','.avi','.zip'
)
$script:MacroExtensions = @('.docm','.xlsm','.pptm','.dotm','.xltm','.potm','.xlam','.ppam')

# --- checks ----------------------------------------------------------------

function Test-AutorunFile {
    param([string]$Root)

    Set-Status 'Checking for autorun entries...' 5

    $autorunPath = Join-Path $Root 'autorun.inf'
    if (-not (Test-Path -LiteralPath $autorunPath)) { return }

    $content = ''
    try { $content = Get-Content -LiteralPath $autorunPath -Raw -ErrorAction Stop } catch { }

    $commands = New-Object System.Collections.ArrayList
    foreach ($match in [regex]::Matches($content, '(?im)^\s*(open|shellexecute|shell\\[^\\=]*\\command)\s*=\s*(?<cmd>.+)$')) {
        $null = $commands.Add($match.Groups['cmd'].Value.Trim())
    }

    $severity = if ($commands.Count -gt 0) { 'Critical' } else { 'High' }
    $detail = 'This drive carries an autorun.inf file. '
    if ($commands.Count -gt 0) {
        $detail += "It names a program to launch: $($commands -join ' | '). "
    }
    $detail += 'Modern Windows ignores autorun on USB drives, so this cannot fire on its own here - but it is the signature of a drive prepared to infect older machines, and it means this drive has been touched by something that wanted to spread.'

    Add-Result -Severity $severity -Title 'autorun.inf found on the drive' -File $autorunPath `
               -Detail $detail `
               -Recommendation 'Do not open the file it names. Treat the whole drive as suspect: back up only your own documents, then reformat.' `
               -Evidence ([ordered]@{
                   'File'     = $autorunPath
                   'Launches' = if ($commands.Count) { ($commands -join ' | ') } else { 'no launch directive' }
                   'Contents' = $content
               })
}

function Test-ShortcutWorm {
    <#
        The most common USB infection you will actually meet. The worm sets
        your real folders to hidden+system, then drops a .lnk with the same
        name and a folder icon. You click what looks like your folder, the
        worm runs, and it opens the real folder so nothing seems wrong.
    #>
    param([string]$Root, $Directories, $Files)

    Set-Status 'Looking for shortcut-worm patterns...' 12

    $hiddenDirectories = @($Directories | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::Hidden) -and ($_.Attributes -band [IO.FileAttributes]::System)
    })
    if ($hiddenDirectories.Count -eq 0) { return }

    $shortcuts = @($Files | Where-Object { $_.Extension -eq '.lnk' })
    if ($shortcuts.Count -eq 0) {
        Add-Result -Severity 'High' -Title "$($hiddenDirectories.Count) folder(s) are hidden as system files" -File $Root `
                   -Detail 'Folders marked hidden+system do not appear in Explorer at all under default settings. Windows itself only does this for a couple of known folders, so ordinary folders in this state usually means something hid them.' `
                   -Recommendation "Reveal them from an admin prompt: attrib -h -s -r `"$Root*`" /s /d" `
                   -Evidence ([ordered]@{ 'Hidden folders' = (($hiddenDirectories | Select-Object -First 20 | ForEach-Object { $_.Name }) -join ', ') })
        return
    }

    # The tell: a visible shortcut whose name matches a folder you cannot see.
    $hiddenNames = @{}
    foreach ($directory in $hiddenDirectories) { $hiddenNames[$directory.Name.ToLowerInvariant()] = $directory.FullName }

    $decoys = New-Object System.Collections.ArrayList
    foreach ($shortcut in $shortcuts) {
        $baseName = [IO.Path]::GetFileNameWithoutExtension($shortcut.Name).ToLowerInvariant()
        if ($hiddenNames.ContainsKey($baseName)) {
            $null = $decoys.Add("$($shortcut.Name)  ->  hides  $($hiddenNames[$baseName])")
        }
    }

    if ($decoys.Count -gt 0) {
        Add-Result -Severity 'Critical' -Title "Shortcut worm detected: $($decoys.Count) fake folder shortcut(s)" -File $Root `
                   -Detail 'Your real folders have been hidden and replaced with shortcuts that look identical to them. Clicking one runs the worm, which then opens the real folder so you notice nothing. This is an active infection on this drive, not a leftover.' `
                   -Recommendation "Do not double-click anything on this drive. Recover your files by unhiding them from an admin prompt (attrib -h -s -r `"$Root*`" /s /d), copy out only your own documents, then reformat the drive." `
                   -Evidence ([ordered]@{
                       'Decoy shortcuts' = (($decoys | Select-Object -First 20) -join ' | ')
                       'Hidden folders'  = $hiddenDirectories.Count
                   })
    }
    else {
        Add-Result -Severity 'High' -Title "$($hiddenDirectories.Count) hidden system folder(s) alongside $($shortcuts.Count) shortcut(s)" -File $Root `
                   -Detail 'Hidden+system folders and loose shortcuts together are the shape of a shortcut worm, though the names do not line up exactly. Worth a close look.' `
                   -Recommendation "Inspect with: attrib `"$Root*`" /s /d" `
                   -Evidence ([ordered]@{
                       'Hidden folders' = (($hiddenDirectories | Select-Object -First 15 | ForEach-Object { $_.Name }) -join ', ')
                       'Shortcuts'      = (($shortcuts | Select-Object -First 15 | ForEach-Object { $_.Name }) -join ', ')
                   })
    }
}

function Test-Shortcuts {
    param($Files)

    $shortcuts = @($Files | Where-Object { $_.Extension -eq '.lnk' })
    if ($shortcuts.Count -eq 0) { return }

    Set-Status "Parsing $($shortcuts.Count) shortcut(s)..." 20

    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { return }

    try {
        foreach ($shortcut in $shortcuts) {
            if (Test-Cancelled) { return }

            $target = ''; $arguments = ''; $workingDirectory = ''; $icon = ''
            try {
                $link = $shell.CreateShortcut($shortcut.FullName)
                $target           = "$($link.TargetPath)"
                $arguments        = "$($link.Arguments)"
                $workingDirectory = "$($link.WorkingDirectory)"
                $icon             = "$($link.IconLocation)"
            }
            catch { continue }

            $combined = "$target $arguments"
            $reasons  = New-Object System.Collections.ArrayList
            $severity = 'Low'

            $targetLeaf = ''
            try { if ($target) { $targetLeaf = [IO.Path]::GetFileName($target).ToLowerInvariant() } } catch { }

            if ($targetLeaf -match '^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|forfiles|conhost)\.exe$') {
                $null = $reasons.Add("It runs $targetLeaf rather than opening a file or folder")
                $severity = 'High'
            }
            if ($arguments -match '-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}') {
                $null = $reasons.Add('Its arguments contain a base64-encoded PowerShell command')
                $severity = 'Critical'
            }
            if ($arguments -match '(IEX|Invoke-Expression|DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient|FromBase64String)') {
                $null = $reasons.Add('Its arguments download or evaluate code at runtime')
                $severity = 'Critical'
            }
            if ($arguments -match '-w(indowstyle)?\s+hidden|-nop\b|-noprofile\b|-ExecutionPolicy\s+(Bypass|Unrestricted)') {
                $null = $reasons.Add('Its arguments hide the window or bypass PowerShell restrictions')
                if ($severity -eq 'Low') { $severity = 'High' }
            }
            if ($arguments.Length -gt 260) {
                $null = $reasons.Add("Its argument string is unusually long ($($arguments.Length) characters), a common way to pack in a payload")
                if ($severity -eq 'Low') { $severity = 'High' }
            }
            if ($combined -match 'https?://') {
                $null = $reasons.Add('It references a web address')
                if ($severity -eq 'Low') { $severity = 'Medium' }
            }
            # Folder icon on something that is not a folder is deliberate disguise.
            if ($icon -match 'imageres\.dll,\s*-?3\b|shell32\.dll,\s*-?(3|4)\b' -and $targetLeaf -match '\.(exe|cmd|bat|vbs|js|scr)$') {
                $null = $reasons.Add('It wears a folder icon but points at a program')
                $severity = 'Critical'
            }

            if ($reasons.Count -eq 0) { continue }

            Add-Result -Severity $severity -Title "Suspicious shortcut: $($shortcut.Name)" -File $shortcut.FullName `
                       -Detail (($reasons -join '; ') + '. A shortcut is a small file that tells Windows what to run when you double-click it - the name and icon you see say nothing about what it actually does.') `
                       -Recommendation 'Do not open it. Delete the shortcut, and check whether the program it points at is also on the drive.' `
                       -Evidence ([ordered]@{
                           'Shortcut'  = $shortcut.FullName
                           'Runs'      = $target
                           'Arguments' = $arguments
                           'Starts in' = $workingDirectory
                           'Icon'      = $icon
                       })
        }
    }
    finally {
        if ($shell) { try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) } catch { } }
    }
}

function Test-DeceptiveNames {
    param($Files)

    Set-Status 'Checking filenames for disguises...' 30

    foreach ($file in $Files) {
        if (Test-Cancelled) { return }
        $name = $file.Name

        # Right-to-left override: "photo_gnp.exe" renders as "photo_exe.png".
        if ($name -match "[\u202A-\u202E\u2066-\u2069]") {
            Add-Result -Severity 'Critical' -Title "Filename uses a text-direction trick: $name" -File $file.FullName `
                       -Detail 'This filename contains an invisible character that reverses how the rest of the name is displayed. It exists for exactly one purpose: to make a program look like a document or image in Explorer. There is no legitimate use for this on a normal file.' `
                       -Recommendation 'Delete it. Do not open it to "check what it is".' `
                       -Evidence ([ordered]@{
                           'Displayed name' = $name
                           'Real extension' = $file.Extension
                           'Full path'      = $file.FullName
                           'Size'           = "$([math]::Round($file.Length / 1KB, 1)) KB"
                       })
            continue
        }

        if ($name -match '\.(doc|docx|pdf|jpg|jpeg|png|txt|xls|xlsx|ppt|mp3|mp4|zip|rar)\s*\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|msi)$') {
            Add-Result -Severity 'Critical' -Title "Double extension: $name" -File $file.FullName `
                       -Detail 'The name is built to read as a document while the real extension makes it a program. Windows hides known extensions by default, so in Explorer this very likely appears as an ordinary file.' `
                       -Recommendation 'Delete it. If you believe it is genuine, confirm with whoever gave you the drive through a different channel first.' `
                       -Evidence ([ordered]@{ 'Filename' = $name; 'Real type' = $file.Extension; 'Full path' = $file.FullName })
            continue
        }

        if ($name -match '\s{2,}\.[a-z0-9]{2,4}$' -or $name -match '\s+\.(exe|scr|com|bat|cmd|vbs|js)$') {
            Add-Result -Severity 'High' -Title "Filename pads the extension with spaces: $name" -File $file.FullName `
                       -Detail 'Whitespace before the extension pushes the real type out of view in narrow Explorer columns. It is a disguise technique.' `
                       -Recommendation 'Treat as hostile unless you can account for it.' `
                       -Evidence ([ordered]@{ 'Filename' = $name; 'Full path' = $file.FullName })
            continue
        }

        if ($name.Length -gt 150) {
            Add-Result -Severity 'Medium' -Title "Extremely long filename ($($name.Length) characters)" -File $file.FullName `
                       -Detail 'Very long names are used to push the real extension off the end of the display, and occasionally to trip up tools that parse paths.' `
                       -Recommendation 'Inspect before opening.' `
                       -Evidence ([ordered]@{ 'Filename' = $name.Substring(0, 100) + '...'; 'Length' = $name.Length })
        }
    }
}

function Test-ContentMismatch {
    <#
        The extension claims one thing; the file header says another. A .jpg
        that begins with MZ is a Windows program wearing a photo's name.
    #>
    param($Files)

    Set-Status 'Comparing file contents against their extensions...' 40

    $candidates = @($Files | Where-Object { $script:DocumentExtensions -contains $_.Extension.ToLowerInvariant() })
    $index = 0

    foreach ($file in $candidates) {
        if (Test-Cancelled) { return }
        $index++
        if ($index % 50 -eq 0) { Set-Status "Comparing file contents... ($index of $($candidates.Count))" (40 + [int](10 * $index / [Math]::Max(1, $candidates.Count))) }

        $actual = Get-FileHeader -FilePath $file.FullName
        if (-not $actual) { continue }

        $extension = $file.Extension.ToLowerInvariant()
        $mismatch = $false

        if ($actual -eq 'PE executable' -or $actual -eq 'ELF executable') { $mismatch = $true }
        elseif ($actual -eq 'ZIP archive / Office document' -and $extension -in @('.pdf','.jpg','.jpeg','.png','.gif','.mp3','.mp4','.txt')) { $mismatch = $true }

        if (-not $mismatch) { continue }

        $severity = if ($actual -match 'executable') { 'Critical' } else { 'Medium' }

        Add-Result -Severity $severity -Title "File contents do not match its extension: $($file.Name)" -File $file.FullName `
                   -Detail "The name ends in $extension, but the file actually begins like a $actual. $(if ($actual -match 'executable') { 'This is a program pretending to be a harmless file - the single strongest signal on a drive short of a live detection.' } else { 'The mismatch may be innocent, but it is worth knowing about.' })" `
                   -Recommendation $(if ($actual -match 'executable') { 'Delete it, or if you need to be certain, check its hash on virustotal.com. Do not open it.' } else { 'Verify where the file came from.' }) `
                   -Evidence ([ordered]@{
                       'Filename'      = $file.Name
                       'Claims to be'  = $extension
                       'Actually is'   = $actual
                       'Full path'     = $file.FullName
                       'Size'          = "$([math]::Round($file.Length / 1KB, 1)) KB"
                       'Modified'      = $file.LastWriteTime
                   })
    }
}

function Test-Executables {
    param($Files, [bool]$ComputeHashes)

    Set-Status 'Inspecting programs and scripts...' 52

    $programs = @($Files | Where-Object {
        $extension = $_.Extension.ToLowerInvariant()
        # .lnk and autorun.inf have dedicated checks; skip them here so a single
        # file does not produce two findings saying much the same thing.
        ($_.Name.ToLowerInvariant() -ne 'autorun.inf') -and
        (($script:ExecutableExtensions -contains $extension) -or ($script:ScriptExtensions -contains $extension -and $extension -ne '.lnk'))
    })

    if ($programs.Count -eq 0) {
        Add-Result -Severity 'Info' -Title 'No programs or scripts found on the drive' `
                   -Detail 'The drive contains only data files. That removes the most common way a drive infects a machine.' `
                   -Recommendation 'Nothing to do.'
        return
    }

    $index = 0
    foreach ($file in $programs) {
        if (Test-Cancelled) { return }
        $index++
        if ($index % 10 -eq 0) { Set-Status "Inspecting programs... ($index of $($programs.Count))" (52 + [int](18 * $index / [Math]::Max(1, $programs.Count))) }

        $extension = $file.Extension.ToLowerInvariant()
        $isScript  = $script:ScriptExtensions -contains $extension

        $reasons  = New-Object System.Collections.ArrayList
        $severity = 'Low'

        if ($isScript) {
            $severity = 'Medium'
            $null = $reasons.Add("Script files like $extension run instantly when double-clicked, with no warning and no installer")

            # -Raw and -TotalCount are mutually exclusive; join the capped read
            # instead, so a huge file still only costs the first 400 lines.
            $content = ''
            try { $content = (Get-Content -LiteralPath $file.FullName -TotalCount 400 -ErrorAction Stop) -join "`n" } catch { }
            if ($content) {
                if ($content -match '-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}|FromBase64String') {
                    $null = $reasons.Add('It contains base64-encoded content, typically used to hide what the script does')
                    $severity = 'Critical'
                }
                if ($content -match '(DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|XMLHTTP|WinHttpRequest|Start-BitsTransfer|urlmon)') {
                    $null = $reasons.Add('It downloads something from the internet when run')
                    $severity = 'Critical'
                }
                if ($content -match '(IEX|Invoke-Expression|eval\(|WScript\.Shell|Shell\.Application|cmd\.exe /c|powershell)') {
                    $null = $reasons.Add('It launches other programs or evaluates code at runtime')
                    if ($severity -ne 'Critical') { $severity = 'High' }
                }
                if ($content -match '(HKEY_|HKLM|HKCU|CurrentVersion\\Run|schtasks|reg add)') {
                    $null = $reasons.Add('It writes to the registry or creates a scheduled task, which is how software makes itself persistent')
                    if ($severity -ne 'Critical') { $severity = 'High' }
                }
            }
        }
        else {
            $signature = Get-SignatureVerdict -FilePath $file.FullName
            if ($signature.IsValid) {
                $null = $reasons.Add("Signed by $($signature.Signer)")
                $severity = 'Info'
            }
            elseif ($signature.IsSigned) {
                $null = $reasons.Add("Its digital signature does not validate (status: $($signature.Status)) - the file may have been altered after signing")
                $severity = 'High'
            }
            else {
                $null = $reasons.Add('It carries no digital signature, so there is nothing tying it to a publisher')
                $severity = 'Medium'
            }
        }

        $evidence = [ordered]@{
            'File'     = $file.FullName
            'Type'     = $extension
            'Size'     = "$([math]::Round($file.Length / 1KB, 1)) KB"
            'Modified' = $file.LastWriteTime
        }
        if ($ComputeHashes -and $file.Length -lt 200MB) {
            $hash = Get-QuickHash -FilePath $file.FullName
            if ($hash) { $evidence['SHA-256'] = $hash }
        }

        $recommendation = if ($severity -in @('Critical','High')) {
            'Do not run it. If you want a second opinion, paste the SHA-256 above into virustotal.com - that checks the hash against 70+ engines without uploading your file.'
        } elseif ($severity -eq 'Info') {
            'Signed by a verifiable publisher. Normally fine.'
        } else {
            'Only run it if you know where it came from.'
        }

        Add-Result -Severity $severity -Title "$(if ($isScript) { 'Script' } else { 'Program' }) on drive: $($file.Name)" -File $file.FullName `
                   -Detail ($reasons -join '; ') `
                   -Recommendation $recommendation `
                   -Evidence $evidence
    }
}

function Test-MacroDocuments {
    param($Files)

    Set-Status 'Checking documents for macros...' 72

    foreach ($file in $Files) {
        if (Test-Cancelled) { return }
        $extension = $file.Extension.ToLowerInvariant()

        $hasMacro = $false
        $reason = ''

        if ($script:MacroExtensions -contains $extension) {
            $hasMacro = $true
            $reason = "The $extension format exists specifically to carry macros"
        }
        elseif ($extension -in @('.docx','.xlsx','.pptx')) {
            # Modern Office files are zips; a vbaProject.bin inside one whose
            # extension says "no macros" is a mismatch worth flagging.
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                $archive = [System.IO.Compression.ZipFile]::OpenRead($file.FullName)
                try {
                    if ($archive.Entries | Where-Object { $_.FullName -match 'vbaProject\.bin$' }) {
                        $hasMacro = $true
                        $reason = "The file claims to be a macro-free $extension but contains a VBA project"
                    }
                }
                finally { $archive.Dispose() }
            }
            catch { }
        }
        elseif ($extension -in @('.doc','.xls','.ppt')) {
            $header = Get-FileHeader -FilePath $file.FullName
            if ($header -eq 'Legacy Office document') {
                $hasMacro = $true
                $reason = 'Legacy Office formats can carry macros and give no visual indication either way'
            }
        }

        if (-not $hasMacro) { continue }

        $severity = if ($reason -match 'claims to be') { 'High' } else { 'Medium' }

        Add-Result -Severity $severity -Title "Document may contain macros: $($file.Name)" -File $file.FullName `
                   -Detail "$reason. Macros are small programs embedded in a document; malicious ones are the most common way office documents deliver malware. They only run if you click 'Enable Content'." `
                   -Recommendation 'Open it in Protected View and do not click "Enable Content" or "Enable Macros" unless you specifically expected this file to contain a macro.' `
                   -Evidence ([ordered]@{
                       'File'     = $file.FullName
                       'Type'     = $extension
                       'Size'     = "$([math]::Round($file.Length / 1KB, 1)) KB"
                       'Modified' = $file.LastWriteTime
                   })
    }
}

function Test-Archives {
    <#
        Archives are listed from their directory records, never extracted.
        Malware is routinely shipped zipped precisely because it stops a
        scanner from seeing the payload.
    #>
    param($Files)

    Set-Status 'Looking inside archives...' 80

    $archives = @($Files | Where-Object { $_.Extension.ToLowerInvariant() -in @('.zip','.jar','.docm','.xlsm') })
    if ($archives.Count -eq 0) { return }

    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { return }

    foreach ($file in $archives) {
        if (Test-Cancelled) { return }
        if ($file.Length -gt 500MB) { continue }

        $dangerous = New-Object System.Collections.ArrayList
        $encrypted = $false
        $entryCount = 0

        try {
            $archive = [System.IO.Compression.ZipFile]::OpenRead($file.FullName)
            try {
                foreach ($entry in $archive.Entries) {
                    $entryCount++
                    if ($entryCount -gt 3000) { break }

                    $entryName = $entry.FullName
                    $entryExtension = ''
                    try { $entryExtension = [IO.Path]::GetExtension($entryName).ToLowerInvariant() } catch { }

                    if (($script:ExecutableExtensions -contains $entryExtension) -or ($script:ScriptExtensions -contains $entryExtension)) {
                        $null = $dangerous.Add($entryName)
                    }
                    if ($entryName -match '\.(doc|pdf|jpg|png|txt|xls)\s*\.(exe|scr|com|bat|cmd|js|vbs)$') {
                        $null = $dangerous.Add("$entryName (double extension)")
                    }
                    # Bit 0 of the general-purpose flags marks an encrypted entry.
                    try { if (($entry.GetType().GetProperty('.') -eq $null) -and $entry.CompressedLength -gt 0 -and $entry.Crc32 -eq 0 -and $entry.Length -gt 0) { } } catch { }
                }
            }
            finally { $archive.Dispose() }
        }
        catch {
            $encrypted = $true
        }

        if ($encrypted) {
            Add-Result -Severity 'High' -Title "Archive could not be read: $($file.Name)" -File $file.FullName `
                       -Detail 'The archive is password-protected or damaged, so neither this scanner nor Defender can see what is inside. Password-protected archives are a standard way to smuggle malware past scanners - the password sits in the email or message that came with it.' `
                       -Recommendation 'Do not extract it unless you know exactly who sent it and why it needed a password.' `
                       -Evidence ([ordered]@{ 'File' = $file.FullName; 'Size' = "$([math]::Round($file.Length / 1KB, 1)) KB" })
            continue
        }

        if ($dangerous.Count -eq 0) { continue }

        Add-Result -Severity 'High' -Title "Archive contains $($dangerous.Count) program(s) or script(s): $($file.Name)" -File $file.FullName `
                   -Detail 'Executable content inside an archive is not scanned until it is extracted. Nothing here is running yet - but extracting and opening it is the step that would start it.' `
                   -Recommendation 'Extract only if you trust the source, and scan the extracted folder before opening anything in it.' `
                   -Evidence ([ordered]@{
                       'Archive'  = $file.FullName
                       'Contains' = (($dangerous | Select-Object -First 20) -join ' | ')
                       'Entries'  = $entryCount
                   })
    }
}

function Test-AlternateDataStreams {
    param($Files)

    Set-Status 'Checking for hidden data streams...' 86

    foreach ($file in $Files) {
        if (Test-Cancelled) { return }

        $streams = $null
        try { $streams = @(Get-Item -LiteralPath $file.FullName -Stream * -ErrorAction Stop | Where-Object { $_.Stream -ne ':$DATA' }) }
        catch { continue }
        if (-not $streams -or $streams.Count -eq 0) { continue }

        $interesting = @($streams | Where-Object { $_.Stream -ne 'Zone.Identifier' })
        if ($interesting.Count -eq 0) { continue }

        Add-Result -Severity 'High' -Title "Hidden data stream attached to $($file.Name)" -File $file.FullName `
                   -Detail 'This file carries extra data in an alternate data stream - content attached to a file that does not show up in Explorer, does not count toward the file size, and survives copying on NTFS drives. It is a classic hiding place for a payload.' `
                   -Recommendation "Inspect it with: Get-Item `"$($file.FullName)`" -Stream * . Remove a stream with: Remove-Item `"$($file.FullName)`" -Stream <name>" `
                   -Evidence ([ordered]@{
                       'File'    = $file.FullName
                       'Streams' = (($interesting | ForEach-Object { "$($_.Stream) ($($_.Length) bytes)" }) -join ', ')
                   })
    }
}

function Test-HiddenFiles {
    param([string]$Root, $Files, $Directories)

    Set-Status 'Checking hidden and system files...' 90

    $hidden = @($Files | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::Hidden) -and $_.Name -ne 'desktop.ini' -and $_.Name -ne 'Thumbs.db'
    })
    if ($hidden.Count -eq 0) { return }

    $hiddenPrograms = @($hidden | Where-Object {
        $extension = $_.Extension.ToLowerInvariant()
        ($script:ExecutableExtensions -contains $extension) -or ($script:ScriptExtensions -contains $extension)
    })

    if ($hiddenPrograms.Count -gt 0) {
        Add-Result -Severity 'Critical' -Title "$($hiddenPrograms.Count) hidden program(s) or script(s) on the drive" -File $Root `
                   -Detail 'These are executable files marked hidden, so they do not appear in Explorer under default settings. Legitimate software on a USB drive has no reason to hide itself.' `
                   -Recommendation 'Treat the drive as compromised. Copy out only your own documents, then reformat.' `
                   -Evidence ([ordered]@{ 'Hidden programs' = (($hiddenPrograms | Select-Object -First 20 | ForEach-Object { $_.FullName }) -join ' | ') })
    }
    elseif ($hidden.Count -gt 0) {
        Add-Result -Severity 'Low' -Title "$($hidden.Count) hidden file(s) on the drive" -File $Root `
                   -Detail 'Hidden files are often harmless leftovers from other operating systems - macOS in particular writes a lot of them. None of them are executable.' `
                   -Recommendation 'No action needed unless you recognise none of them.' `
                   -Evidence ([ordered]@{ 'Sample' = (($hidden | Select-Object -First 15 | ForEach-Object { $_.Name }) -join ', ') })
    }
}

function Invoke-DefenderScan {
    param([string]$Root)

    Set-Status 'Running Microsoft Defender over the drive...' 93

    if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
        Add-Result -Severity 'Info' -Title 'Defender scan unavailable' `
                   -Detail 'The Defender PowerShell commands are not present, so the signature scan was skipped. The structural checks above still ran.' `
                   -Recommendation 'Scan the drive manually: right-click it in Explorer and choose Scan with Microsoft Defender.'
        return
    }

    $before = @()
    try { $before = @(Get-MpThreatDetection -ErrorAction SilentlyContinue) } catch { }

    try { Start-MpScan -ScanPath $Root -ScanType CustomScan -ErrorAction Stop }
    catch {
        Add-Result -Severity 'Info' -Title 'Defender scan could not be started' `
                   -Detail "Start-MpScan reported: $($_.Exception.Message)" `
                   -Recommendation 'Right-click the drive in Explorer and choose Scan with Microsoft Defender instead.'
        return
    }

    $after = @()
    try { $after = @(Get-MpThreatDetection -ErrorAction SilentlyContinue) } catch { }

    $new = @($after | Where-Object { $_.DetectionID -notin @($before | ForEach-Object { $_.DetectionID }) })

    if ($new.Count -eq 0) {
        Add-Result -Severity 'Info' -Title 'Microsoft Defender found no known malware on this drive' `
                   -Detail 'The signature scan came back clean. That rules out known malware, but not a brand-new sample or the structural tricks listed elsewhere in this report.' `
                   -Recommendation 'Combine this with the findings above rather than treating it as an all-clear on its own.'
        return
    }

    foreach ($threat in $new) {
        $resources = ''
        try { $resources = ($threat.Resources -join ' | ') } catch { }
        Add-Result -Severity 'Critical' -Title "Defender detected: $($threat.ThreatName)" -File $resources `
                   -Detail 'Microsoft Defender identified known malware on this drive. This is a confirmed detection, not a heuristic.' `
                   -Recommendation 'Let Defender quarantine it, then reformat the drive. Also run a full scan of this PC in case something already ran from the drive.' `
                   -Evidence ([ordered]@{
                       'Threat'    = "$($threat.ThreatName)"
                       'Severity'  = "$($threat.ThreatStatusID)"
                       'Resources' = $resources
                       'Detected'  = "$($threat.InitialDetectionTime)"
                   })
    }
}

# --- driver ----------------------------------------------------------------

function Invoke-DriveChecks {
    <#
        Runs every check against one path. Progress is reported 0-100 for this
        drive alone; Set-Status maps it onto the drive's slice of the bar.
    #>
    param(
        [Parameter(Mandatory)][string]$Root,
        [bool]$DeepInspection = $true,
        [bool]$UseDefender = $false,
        [int]$MaxFiles = 200000
    )

    try {
        if (-not (Test-Path -LiteralPath $Root)) { throw "The path '$Root' is not available. Is the drive still plugged in?" }

        Set-Status 'Building a file list...' 2

        # Walking a whole drive is the longest single step in a scan, and it is
        # the one that used to happen safely out of sight on another thread. Run
        # as one Get-ChildItem it would hold the UI thread for its whole
        # duration; streaming it lets us report progress and honour Stop while
        # the walk is still going.
        $collected = New-Object System.Collections.ArrayList
        try {
            Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $null = $collected.Add($_)
                if (($collected.Count % 200) -eq 0) {
                    Set-Status "Building a file list... ($($collected.Count) items)" 2
                    # Throwing is the reliable way to stop a pipeline early from
                    # inside ForEach-Object; break would unwind further than we
                    # want and leave the caught state ambiguous.
                    if ($script:Sync.Cancel) { throw (New-Object System.OperationCanceledException 'Scan cancelled') }
                }
            }
        }
        catch [System.OperationCanceledException] { }
        catch { }

        $allItems = @($collected)

        $files       = @($allItems | Where-Object { -not $_.PSIsContainer } | Select-Object -First $MaxFiles)
        $directories = @($allItems | Where-Object { $_.PSIsContainer })

        $script:Sync.FileCount = $files.Count
        $totalBytes = 0
        foreach ($file in $files) { $totalBytes += $file.Length }
        $script:Sync.TotalSize = $totalBytes

        if (Test-Cancelled) { return }

        Add-Result -Severity 'Info' -Title "Scanned $($files.Count) file(s) in $($directories.Count) folder(s)" -File $Root `
                   -Detail "Total size $([math]::Round($totalBytes / 1MB, 1)) MB. Everything below was read without being opened or run." `
                   -Recommendation '' `
                   -Evidence ([ordered]@{
                       'Path'    = $Root
                       'Files'   = $files.Count
                       'Folders' = $directories.Count
                       'Size'    = "$([math]::Round($totalBytes / 1MB, 1)) MB"
                   })

        if ($files.Count -eq 0 -and $directories.Count -eq 0) {
            Add-Result -Severity 'Info' -Title 'The drive appears to be empty' -File $Root `
                       -Detail "Nothing was found. If you expected files to be here, they may have been hidden - a worm that hides your folders leaves the drive looking exactly like this." `
                       -Recommendation "Reveal anything hidden from an admin prompt: attrib -h -s -r `"$Root*`" /s /d . If files should be present but are not, that is itself worth investigating."
        }

        Test-AutorunFile        -Root $Root;                                     if (Test-Cancelled) { return }
        Test-ShortcutWorm       -Root $Root -Directories $directories -Files $files; if (Test-Cancelled) { return }
        Test-Shortcuts          -Files $files;                                   if (Test-Cancelled) { return }
        Test-DeceptiveNames     -Files $files;                                   if (Test-Cancelled) { return }
        Test-ContentMismatch    -Files $files;                                   if (Test-Cancelled) { return }
        Test-Executables        -Files $files -ComputeHashes $DeepInspection;    if (Test-Cancelled) { return }
        Test-MacroDocuments     -Files $files;                                   if (Test-Cancelled) { return }
        if ($DeepInspection) {
            Test-Archives            -Files $files;                              if (Test-Cancelled) { return }
            Test-AlternateDataStreams -Files $files;                             if (Test-Cancelled) { return }
        }
        Test-HiddenFiles        -Root $Root -Files $files -Directories $directories

        if ($UseDefender) { Invoke-DefenderScan -Root $Root }

        Set-Status 'Finished this drive.' 100
    }
    catch {
        # One unreadable drive must not abandon the others, so this is recorded
        # as a finding rather than thrown.
        Add-Result -Severity 'High' -Title "Could not scan $Root" -File $Root `
                   -Detail "$($_.Exception.Message)" `
                   -Recommendation 'Check the drive is still connected and that you have permission to read it, then scan again.' `
                   -Evidence ([ordered]@{ 'Path' = $Root; 'Error' = "$($_.Exception.Message)" })
    }
}

function Start-DriveScan {
    <#
        The one entry point for a scan, called directly by both front ends.
        Accepts one or many paths and walks them in turn, so "scan everything
        plugged in" is a single run producing a single set of results.

        This returns only when the scan is finished or cancelled. Callers on the
        UI thread stay blocked for that whole time; the window keeps drawing
        because the checks pump it as they go, not because this returns early.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Roots,
        [bool]$DeepInspection = $true,
        [bool]$UseDefender = $false,
        [int]$MaxFiles = 200000
    )

    $script:Sync.Findings = New-Object System.Collections.ArrayList
    $script:Sync.Percent  = 0
    $script:Sync.Done     = $false
    $script:Sync.Error    = $null
    $script:Sync.Drives   = @($Roots)

    try {
        $paths = @($Roots | Where-Object { $_ })
        if ($paths.Count -eq 0) { throw 'No drives were selected.' }

        $span = [Math]::Floor(100 / $paths.Count)
        $index = 0

        foreach ($root in $paths) {
            if ($script:Sync.Cancel) { break }

            $script:PercentBase  = $index * $span
            $script:PercentSpan  = $span
            $script:CurrentDrive = if ($paths.Count -gt 1) { $root } else { '' }

            Invoke-DriveChecks -Root $root -DeepInspection $DeepInspection -UseDefender $UseDefender -MaxFiles $MaxFiles
            $index++
        }

        $script:CurrentDrive = ''
        $script:PercentBase  = 0
        $script:PercentSpan  = 100

        Set-Status $(if ($paths.Count -gt 1) { "Scan complete - $($paths.Count) drives checked." } else { 'Scan complete.' }) 100
    }
    catch {
        $script:Sync.Error = $_.Exception.Message
        Set-Status "Scan failed: $($_.Exception.Message)" 100
    }
    finally {
        $script:Sync.Done = $true
    }
}

# ===========================================================================
#  REPORT
# ===========================================================================

function ConvertTo-SafeHtml {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

function Save-DriveReport {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][string]$ScanPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [datetime]$StartedAt = (Get-Date),
        [datetime]$FinishedAt = (Get-Date),
        [hashtable]$DriveInfo
    )

    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($finding in $Findings) { $counts[$finding.Severity]++ }

    $verdict = if ($counts.Critical -gt 0) {
        'Do not use this drive until you have dealt with the critical findings'
    } elseif ($counts.High -gt 0) {
        'Something on this drive needs a closer look before you open anything'
    } elseif ($counts.Medium -gt 0) {
        'Nothing alarming, but a few things are worth understanding'
    } else {
        'Nothing suspicious found on this drive'
    }
    $verdictClass = if ($counts.Critical) { 'bad' } elseif ($counts.High) { 'warn' } elseif ($counts.Medium) { 'ok' } else { 'good' }

    $style = @'
<style>
  :root{--bg:#f6f7f9;--panel:#fff;--ink:#16191d;--muted:#5c6570;--line:#e2e5ea;--accent:#2f6fed;
    --crit:#b4232c;--crit-bg:#fdf0f0;--high:#c2410c;--high-bg:#fdf3ec;--med:#a16207;--med-bg:#fdf8e9;
    --low:#1d6fa5;--low-bg:#eef6fc;--info:#5c6570;--info-bg:#f2f4f6;--good:#17734a;
    --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08);}
  @media (prefers-color-scheme:dark){:root{--bg:#0f1216;--panel:#171b21;--ink:#e7eaee;--muted:#98a2b0;
    --line:#262c35;--accent:#6f9dff;--crit:#ff8489;--crit-bg:#2a161a;--high:#ffab70;--high-bg:#2a1e15;
    --med:#e8c468;--med-bg:#272115;--low:#7cc2f0;--low-bg:#131f2a;--info:#98a2b0;--info-bg:#1c2128;
    --good:#5fd7a0;--shadow:none;}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  .wrap{max-width:1000px;margin:0 auto;padding:32px 20px 70px}
  h1{font-size:25px;margin:0 0 4px;letter-spacing:-.02em}
  .sub{color:var(--muted);font-size:14px;margin:0 0 22px}
  .verdict{padding:14px 18px;border-radius:10px;font-weight:600;margin-bottom:22px;border:1px solid var(--line);background:var(--panel);box-shadow:var(--shadow)}
  .verdict.bad{border-left:4px solid var(--crit)}.verdict.warn{border-left:4px solid var(--high)}
  .verdict.ok{border-left:4px solid var(--med)}.verdict.good{border-left:4px solid var(--good)}
  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:22px}
  .tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;box-shadow:var(--shadow)}
  .tile .n{font-size:25px;font-weight:650;display:block;line-height:1.1}
  .tile .l{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
  .tile.c .n{color:var(--crit)}.tile.h .n{color:var(--high)}.tile.m .n{color:var(--med)}
  .tile.l2 .n{color:var(--low)}.tile.i .n{color:var(--info)}
  .meta{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:4px 16px;margin-bottom:24px;box-shadow:var(--shadow)}
  .meta dl{display:grid;grid-template-columns:minmax(110px,max-content) 1fr;gap:0 18px;margin:12px 0;font-size:13.5px}
  .meta dt{color:var(--muted)}.meta dd{margin:0;word-break:break-word}
  details.f{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:8px;box-shadow:var(--shadow);overflow:hidden}
  details.f>summary{padding:13px 16px;cursor:pointer;display:flex;gap:11px;align-items:flex-start;list-style:none}
  details.f>summary::-webkit-details-marker{display:none}
  .badge{flex:none;font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:3px 7px;border-radius:5px;margin-top:2px}
  .s-Critical{border-left:3px solid var(--crit)}.s-Critical .badge{color:var(--crit);background:var(--crit-bg)}
  .s-High{border-left:3px solid var(--high)}.s-High .badge{color:var(--high);background:var(--high-bg)}
  .s-Medium{border-left:3px solid var(--med)}.s-Medium .badge{color:var(--med);background:var(--med-bg)}
  .s-Low{border-left:3px solid var(--low)}.s-Low .badge{color:var(--low);background:var(--low-bg)}
  .s-Info{border-left:3px solid var(--info)}.s-Info .badge{color:var(--info);background:var(--info-bg)}
  .t{font-weight:550;word-break:break-word}
  .body{padding:0 16px 16px;border-top:1px solid var(--line)}
  .body p{margin:12px 0}
  .rec{background:var(--info-bg);border-radius:8px;padding:11px 13px;font-size:14px}
  .rec strong{display:block;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:4px}
  table.ev{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
  table.ev th,table.ev td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
  table.ev th{width:150px;color:var(--muted);font-weight:500;white-space:nowrap}
  table.ev td{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
  .scroll{overflow-x:auto}
  h2.cat{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:26px 0 10px}
  footer{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px}
</style>
'@

    $body = New-Object System.Text.StringBuilder
    foreach ($finding in ($Findings | Sort-Object Rank, Title)) {
        $evidenceRows = New-Object System.Text.StringBuilder
        foreach ($pair in $finding.Evidence) {
            $null = $evidenceRows.AppendLine("<tr><th>$(ConvertTo-SafeHtml $pair.Name)</th><td>$(ConvertTo-SafeHtml $pair.Value)</td></tr>")
        }
        $evidenceTable = if ($finding.Evidence.Count) { "<div class=""scroll""><table class=""ev"">$($evidenceRows.ToString())</table></div>" } else { '' }
        $recommendation = if ($finding.Recommendation) { "<p class=""rec""><strong>What to do</strong>$(ConvertTo-SafeHtml $finding.Recommendation)</p>" } else { '' }

        $null = $body.AppendLine(@"
<details class="f s-$($finding.Severity)"$(if ($finding.Severity -in @('Critical','High')) { ' open' })>
  <summary><span class="badge">$($finding.Severity)</span><span class="t">$(ConvertTo-SafeHtml $finding.Title)</span></summary>
  <div class="body">
    <p>$(ConvertTo-SafeHtml $finding.Detail)</p>
    $recommendation
    $evidenceTable
  </div>
</details>
"@)
    }

    $driveRows = ''
    if ($DriveInfo) {
        foreach ($key in $DriveInfo.Keys) {
            $driveRows += "<dt>$(ConvertTo-SafeHtml $key)</dt><dd>$(ConvertTo-SafeHtml "$($DriveInfo[$key])")</dd>"
        }
    }

    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Drive scan &mdash; $(ConvertTo-SafeHtml $ScanPath)</title>
$style
</head><body><div class="wrap">
<h1>Argus drive scan</h1>
<p class="sub">Removable media inspection &mdash; structure, disguises and hidden content, not signatures.</p>

<div class="verdict $verdictClass">$verdict</div>

<div class="tiles">
  <div class="tile c"><span class="n">$($counts.Critical)</span><span class="l">Critical</span></div>
  <div class="tile h"><span class="n">$($counts.High)</span><span class="l">High</span></div>
  <div class="tile m"><span class="n">$($counts.Medium)</span><span class="l">Medium</span></div>
  <div class="tile l2"><span class="n">$($counts.Low)</span><span class="l">Low</span></div>
  <div class="tile i"><span class="n">$($counts.Info)</span><span class="l">Info</span></div>
</div>

<div class="meta"><dl>
  <dt>Scanned path</dt><dd>$(ConvertTo-SafeHtml $ScanPath)</dd>
  $driveRows
  <dt>Started</dt><dd>$($StartedAt.ToString('yyyy-MM-dd HH:mm:ss'))</dd>
  <dt>Duration</dt><dd>$([int]($FinishedAt - $StartedAt).TotalSeconds) seconds</dd>
  <dt>Scanned on</dt><dd>$(ConvertTo-SafeHtml $env:COMPUTERNAME)</dd>
</dl></div>

<h2 class="cat">Findings &middot; $($Findings.Count)</h2>
$($body.ToString())

<footer>
<p>Nothing on the drive was opened or executed. Files were read, shortcuts parsed, archives listed from their directory records.</p>
<p>This checks structure and disguise, not malware signatures. Use it alongside Microsoft Defender, not instead of it.</p>
<p>Generated $($FinishedAt.ToString('yyyy-MM-dd HH:mm:ss')) &middot; Argus Drive Scanner v$script:AppVersion</p>
</footer>
</div></body></html>
"@

    $directory = Split-Path $OutputPath -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Path $directory -Force }
    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
    return $OutputPath
}

# ===========================================================================
#  SCAN RUNNER (shared by GUI and headless)
# ===========================================================================

function New-SyncState {
    # Plain hashtable and plain list: one thread touches these now. The type
    # still exists because it is the contract between the checks and whichever
    # front end is showing their progress.
    $sync = @{}
    $sync.Findings  = New-Object System.Collections.ArrayList
    $sync.Status    = 'Ready'
    $sync.Percent   = 0
    $sync.Done      = $false
    $sync.Cancel    = $false
    $sync.Error     = $null
    $sync.FileCount = 0
    $sync.TotalSize = 0
    return $sync
}

function Get-DriveList {
    $drives = New-Object System.Collections.ArrayList
    $typeNames = @{ 2 = 'Removable'; 3 = 'Fixed disk'; 4 = 'Network'; 5 = 'CD/DVD'; 6 = 'RAM disk' }

    try {
        foreach ($disk in (Get-CimInstance Win32_LogicalDisk -ErrorAction Stop)) {
            $null = $drives.Add([pscustomobject]@{
                Letter     = "$($disk.DeviceID)"
                Root       = "$($disk.DeviceID)\"
                Label      = if ($disk.VolumeName) { "$($disk.VolumeName)" } else { '(no label)' }
                Type       = if ($typeNames.ContainsKey([int]$disk.DriveType)) { $typeNames[[int]$disk.DriveType] } else { 'Unknown' }
                TypeCode   = [int]$disk.DriveType
                FileSystem = if ($disk.FileSystem) { "$($disk.FileSystem)" } else { '-' }
                SizeGB     = if ($disk.Size) { [math]::Round($disk.Size / 1GB, 1) } else { 0 }
                FreeGB     = if ($disk.FreeSpace) { [math]::Round($disk.FreeSpace / 1GB, 1) } else { 0 }
                Ready      = [bool]$disk.Size
            })
        }
    }
    catch { }

    return $drives
}

# ===========================================================================
#  HEADLESS MODE
# ===========================================================================

if ($NoGui) {
    if (-not $Path) { Write-Error 'Specify -Path when using -NoGui.'; exit 1 }

    $script:Sync = New-SyncState
    $startedAt = Get-Date
    Write-Host "Scanning $Path ..." -ForegroundColor Cyan

    # Nothing to poll any more - the scan runs right here. The pump just echoes
    # each new status line as the checks reach it.
    $script:LastConsoleStatus = ''
    $script:PumpUi = {
        if ($script:Sync.Status -ne $script:LastConsoleStatus) {
            $script:LastConsoleStatus = $script:Sync.Status
            Write-Host "  $($script:LastConsoleStatus)" -ForegroundColor DarkGray
        }
    }

    Start-DriveScan -Roots @($Path) -DeepInspection $true -UseDefender ([bool]$DefenderScan)

    $findings = @($script:Sync.Findings)
    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($finding in $findings) { $counts[$finding.Severity]++ }

    Write-Host ''
    Write-Host ("  Critical {0}  High {1}  Medium {2}  Low {3}  Info {4}" -f $counts.Critical, $counts.High, $counts.Medium, $counts.Low, $counts.Info)

    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not $desktop) { $desktop = $env:USERPROFILE }
    $reportPath = Join-Path $desktop ("DriveScan-{0}.html" -f $startedAt.ToString('yyyyMMdd-HHmmss'))
    $null = Save-DriveReport -Findings $findings -ScanPath $Path -OutputPath $reportPath -StartedAt $startedAt -FinishedAt (Get-Date)
    Write-Host "  Report: $reportPath" -ForegroundColor Green

    if ($counts.Critical) { exit 3 } elseif ($counts.High) { exit 2 } elseif ($counts.Medium -or $counts.Low) { exit 1 }
    exit 0
}

# ===========================================================================
#  GUI
# ===========================================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$colours = @{
    Critical = [System.Drawing.Color]::FromArgb(180, 35, 44)
    High     = [System.Drawing.Color]::FromArgb(194, 65, 12)
    Medium   = [System.Drawing.Color]::FromArgb(161, 98, 7)
    Low      = [System.Drawing.Color]::FromArgb(29, 111, 165)
    Info     = [System.Drawing.Color]::FromArgb(92, 101, 112)
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Argus Drive Scanner"
$form.Size = New-Object System.Drawing.Size(960, 740)
$form.MinimumSize = New-Object System.Drawing.Size(800, 620)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.BackColor = [System.Drawing.Color]::FromArgb(246, 247, 249)

# --- header ---------------------------------------------------------------
$header = New-Object System.Windows.Forms.Label
$header.Text = 'Tick the drives you want scanned'
$header.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Regular)
$header.Location = New-Object System.Drawing.Point(18, 14)
$header.Size = New-Object System.Drawing.Size(600, 28)
$form.Controls.Add($header)

$subheader = New-Object System.Windows.Forms.Label
$subheader.Text = 'Looks for autorun files, shortcut worms, disguised programs and hidden content. Nothing on the drive is opened or run.'
$subheader.ForeColor = [System.Drawing.Color]::FromArgb(92, 101, 112)
$subheader.Location = New-Object System.Drawing.Point(20, 42)
$subheader.Size = New-Object System.Drawing.Size(900, 20)
$subheader.Anchor = 'Top, Left, Right'
$form.Controls.Add($subheader)

# --- drive list -----------------------------------------------------------
$driveList = New-Object System.Windows.Forms.ListView
$driveList.Location = New-Object System.Drawing.Point(18, 70)
$driveList.Size = New-Object System.Drawing.Size(910, 140)
$driveList.View = 'Details'
$driveList.FullRowSelect = $true
$driveList.MultiSelect = $true
$driveList.CheckBoxes = $true
$driveList.HideSelection = $false
$driveList.GridLines = $false
$driveList.Anchor = 'Top, Left, Right'
$driveList.BackColor = [System.Drawing.Color]::White
$null = $driveList.Columns.Add('Drive', 60)
$null = $driveList.Columns.Add('Label', 200)
$null = $driveList.Columns.Add('Type', 110)
$null = $driveList.Columns.Add('Format', 80)
$null = $driveList.Columns.Add('Size', 90)
$null = $driveList.Columns.Add('Free', 90)
$null = $driveList.Columns.Add('Path', 250)
$form.Controls.Add($driveList)

function Update-DriveList {
    $driveList.Items.Clear()
    foreach ($drive in (Get-DriveList)) {
        if (-not $drive.Ready) { continue }
        $item = New-Object System.Windows.Forms.ListViewItem($drive.Letter)
        $null = $item.SubItems.Add($drive.Label)
        $null = $item.SubItems.Add($drive.Type)
        $null = $item.SubItems.Add($drive.FileSystem)
        $null = $item.SubItems.Add("$($drive.SizeGB) GB")
        $null = $item.SubItems.Add("$($drive.FreeGB) GB")
        $null = $item.SubItems.Add($drive.Root)
        $item.Tag = $drive.Root
        if ($drive.TypeCode -eq 2) {
            $item.ForeColor = [System.Drawing.Color]::FromArgb(23, 115, 74)
            $item.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
            # Removable drives are why you opened this, so tick them by default.
            $item.Checked = $true
        }
        $null = $driveList.Items.Add($item)
    }
    Update-ScanButtonText
}

function Get-CheckedRoots {
    <#
        Ticked rows win. If nothing is ticked, fall back to whatever row is
        highlighted, so a single click-and-scan still works.
    #>
    $roots = New-Object System.Collections.ArrayList
    foreach ($item in $driveList.CheckedItems) { $null = $roots.Add("$($item.Tag)") }
    if ($roots.Count -eq 0) {
        foreach ($item in $driveList.SelectedItems) { $null = $roots.Add("$($item.Tag)") }
    }
    return @($roots)
}

function Update-ScanButtonText {
    $count = $driveList.CheckedItems.Count
    if ($count -gt 1) {
        $scanButton.Text = "SCAN $count DRIVES"
    }
    elseif ($count -eq 1) {
        $scanButton.Text = "SCAN $($driveList.CheckedItems[0].Text)"
    }
    else {
        $scanButton.Text = 'SCAN DRIVE'
    }
}

# --- options row ----------------------------------------------------------
$tips = New-Object System.Windows.Forms.ToolTip
$tips.AutoPopDelay = 12000

$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = 'Refresh'
$refreshButton.Location = New-Object System.Drawing.Point(18, 220)
$refreshButton.Size = New-Object System.Drawing.Size(84, 28)
$refreshButton.FlatStyle = 'System'
$tips.SetToolTip($refreshButton, 'Re-read the drive list. Use this after plugging in a drive.')
$form.Controls.Add($refreshButton)

$tickAllButton = New-Object System.Windows.Forms.Button
$tickAllButton.Text = 'Tick all'
$tickAllButton.Location = New-Object System.Drawing.Point(110, 220)
$tickAllButton.Size = New-Object System.Drawing.Size(76, 28)
$tickAllButton.FlatStyle = 'System'
$tips.SetToolTip($tickAllButton, 'Select every drive, including your internal hard disk. Scanning C: takes much longer.')
$form.Controls.Add($tickAllButton)

$tickNoneButton = New-Object System.Windows.Forms.Button
$tickNoneButton.Text = 'Untick all'
$tickNoneButton.Location = New-Object System.Drawing.Point(194, 220)
$tickNoneButton.Size = New-Object System.Drawing.Size(84, 28)
$tickNoneButton.FlatStyle = 'System'
$form.Controls.Add($tickNoneButton)

$browseButton = New-Object System.Windows.Forms.Button
$browseButton.Text = 'Scan a folder...'
$browseButton.Location = New-Object System.Drawing.Point(286, 220)
$browseButton.Size = New-Object System.Drawing.Size(110, 28)
$browseButton.FlatStyle = 'System'
$tips.SetToolTip($browseButton, 'Scan any folder instead of a whole drive.')
$form.Controls.Add($browseButton)

$deepCheck = New-Object System.Windows.Forms.CheckBox
$deepCheck.Text = 'Deep inspection'
$deepCheck.Location = New-Object System.Drawing.Point(420, 224)
$deepCheck.Size = New-Object System.Drawing.Size(130, 22)
$deepCheck.Checked = $true
$tips.SetToolTip($deepCheck, 'Also compute SHA-256 hashes, look inside archives, and check for hidden data streams. Slower, but catches more.')
$form.Controls.Add($deepCheck)

$defenderCheck = New-Object System.Windows.Forms.CheckBox
$defenderCheck.Text = 'Also run Microsoft Defender'
$defenderCheck.Location = New-Object System.Drawing.Point(560, 224)
$defenderCheck.Size = New-Object System.Drawing.Size(200, 22)
$defenderCheck.Checked = $true
$tips.SetToolTip($defenderCheck, 'Run a Defender signature scan over the same drives. Catches known malware; the other checks catch disguises Defender ignores.')
$form.Controls.Add($defenderCheck)

# --- scan button + progress ----------------------------------------------
$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Text = 'SCAN DRIVE'
$scanButton.Location = New-Object System.Drawing.Point(18, 258)
$scanButton.Size = New-Object System.Drawing.Size(160, 40)
$scanButton.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$scanButton.BackColor = [System.Drawing.Color]::FromArgb(47, 111, 237)
$scanButton.ForeColor = [System.Drawing.Color]::White
$scanButton.FlatStyle = 'Flat'
$scanButton.FlatAppearance.BorderSize = 0
$form.Controls.Add($scanButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = 'Stop'
$cancelButton.Location = New-Object System.Drawing.Point(186, 258)
$cancelButton.Size = New-Object System.Drawing.Size(80, 40)
$cancelButton.Enabled = $false
$cancelButton.FlatStyle = 'System'
$form.Controls.Add($cancelButton)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(276, 258)
$progressBar.Size = New-Object System.Drawing.Size(652, 18)
$progressBar.Anchor = 'Top, Left, Right'
$form.Controls.Add($progressBar)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = 'Ready.'
$statusLabel.Location = New-Object System.Drawing.Point(276, 280)
$statusLabel.Size = New-Object System.Drawing.Size(652, 20)
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(92, 101, 112)
$statusLabel.Anchor = 'Top, Left, Right'
$form.Controls.Add($statusLabel)

# --- summary strip --------------------------------------------------------
$summaryLabel = New-Object System.Windows.Forms.Label
$summaryLabel.Location = New-Object System.Drawing.Point(18, 310)
$summaryLabel.Size = New-Object System.Drawing.Size(910, 24)
$summaryLabel.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$summaryLabel.Anchor = 'Top, Left, Right'
$form.Controls.Add($summaryLabel)

# --- results --------------------------------------------------------------
$resultList = New-Object System.Windows.Forms.ListView
$resultList.Location = New-Object System.Drawing.Point(18, 338)
$resultList.Size = New-Object System.Drawing.Size(910, 230)
$resultList.View = 'Details'
$resultList.FullRowSelect = $true
$resultList.MultiSelect = $false
$resultList.HideSelection = $false
$resultList.Anchor = 'Top, Bottom, Left, Right'
$resultList.BackColor = [System.Drawing.Color]::White
$null = $resultList.Columns.Add('Severity', 75)
$null = $resultList.Columns.Add('Drive', 55)
$null = $resultList.Columns.Add('Finding', 480)
$null = $resultList.Columns.Add('File', 285)
$form.Controls.Add($resultList)

$detailBox = New-Object System.Windows.Forms.TextBox
$detailBox.Location = New-Object System.Drawing.Point(18, 578)
$detailBox.Size = New-Object System.Drawing.Size(910, 82)
$detailBox.Multiline = $true
$detailBox.ReadOnly = $true
$detailBox.ScrollBars = 'Vertical'
$detailBox.BackColor = [System.Drawing.Color]::White
$detailBox.Anchor = 'Bottom, Left, Right'
$detailBox.Text = 'Click a finding above to read what it means and what to do about it.'
$form.Controls.Add($detailBox)

$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = 'Save report...'
$saveButton.Location = New-Object System.Drawing.Point(18, 668)
$saveButton.Size = New-Object System.Drawing.Size(120, 30)
$saveButton.Enabled = $false
$saveButton.Anchor = 'Bottom, Left'
$saveButton.FlatStyle = 'System'
$form.Controls.Add($saveButton)

$openButton = New-Object System.Windows.Forms.Button
$openButton.Text = 'Open report'
$openButton.Location = New-Object System.Drawing.Point(146, 668)
$openButton.Size = New-Object System.Drawing.Size(110, 30)
$openButton.Enabled = $false
$openButton.Anchor = 'Bottom, Left'
$openButton.FlatStyle = 'System'
$form.Controls.Add($openButton)

$hintLabel = New-Object System.Windows.Forms.Label
$hintLabel.Text = 'Tip: most Low and Info results are normal. Focus on Critical and High.'
$hintLabel.Location = New-Object System.Drawing.Point(268, 675)
$hintLabel.Size = New-Object System.Drawing.Size(660, 20)
$hintLabel.ForeColor = [System.Drawing.Color]::FromArgb(92, 101, 112)
$hintLabel.Anchor = 'Bottom, Left, Right'
$form.Controls.Add($hintLabel)

# --- state ----------------------------------------------------------------
$script:Sync         = $null
$script:LastReport   = $null
$script:ScanPath     = $null
$script:ScanRoots    = @()
$script:StartedAt    = $null
$script:Findings     = @()
$script:Scanning     = $false
$script:ClosePending = $false

# The scan holds this thread, so the window only stays alive because this runs
# between checks. Deliberately cheap: progress widgets and a running count, no
# rebuilding of the results list - findings are added once, at the end.
$script:PumpUi = {
    if ($form.IsDisposed) { return }
    $statusLabel.Text = "$($script:Sync.Status)"
    $percent = [int]$script:Sync.Percent
    if ($percent -ge 0 -and $percent -le 100) { $progressBar.Value = $percent }
    $found = $script:Sync.Findings.Count
    if ($found -gt 0) { $summaryLabel.Text = "$found finding(s) so far..." }
    [System.Windows.Forms.Application]::DoEvents()
}

# --- behaviour ------------------------------------------------------------

function Set-Scanning {
    param([bool]$Running)
    $scanButton.Enabled    = -not $Running
    $cancelButton.Enabled  = $Running
    $driveList.Enabled     = -not $Running
    $refreshButton.Enabled = -not $Running
    $browseButton.Enabled  = -not $Running
    $deepCheck.Enabled     = -not $Running
    $defenderCheck.Enabled = -not $Running
}

function Start-Scan {
    param([string[]]$Roots)

    # DoEvents dispatches whatever is already queued, so a second Scan click can
    # arrive mid-scan even though the button is disabled. Refuse it outright
    # rather than re-entering the engine on top of itself.
    if ($script:Scanning) { return }

    $Roots = @($Roots | Where-Object { $_ })

    if ($Roots.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show(
            'Tick at least one drive in the list, or use "Scan a folder...".',
            'Nothing selected', 'OK', 'Information')
        return
    }

    $missing = @($Roots | Where-Object { -not (Test-Path -LiteralPath $_) })
    if ($missing.Count -gt 0) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "Cannot reach: $($missing -join ', ')`n`nIs the drive still plugged in?",
            'Drive not available', 'OK', 'Warning')
        return
    }

    # Scanning an internal disk is legitimate but slow; make sure it was meant.
    $fixed = @()
    foreach ($item in $driveList.CheckedItems) {
        if ($item.SubItems[2].Text -eq 'Fixed disk' -and $Roots -contains "$($item.Tag)") { $fixed += "$($item.Tag)" }
    }
    if ($fixed.Count -gt 0) {
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "You have included an internal hard disk ($($fixed -join ', ')).`n`nThat works, but it can take a long time and will produce a lot of Low and Info results. Carry on?",
            'Internal disk selected', 'YesNo', 'Question')
        if ($answer -ne 'Yes') { return }
    }

    $resultList.Items.Clear()
    $detailBox.Text = ''
    $summaryLabel.Text = ''
    $progressBar.Value = 0
    $saveButton.Enabled = $false
    $openButton.Enabled = $false

    $script:ScanRoots = @($Roots)
    $script:ScanPath  = ($Roots -join ', ')
    $script:StartedAt = Get-Date
    $script:Sync      = New-SyncState

    Set-Scanning -Running $true
    $script:Scanning = $true

    # The scan runs here, on this thread, and this call does not come back until
    # it is done or stopped. Everything the user sees during it happens inside
    # $script:PumpUi.
    try {
        Start-DriveScan -Roots $Roots -DeepInspection $deepCheck.Checked -UseDefender $defenderCheck.Checked
    }
    finally {
        $script:Scanning = $false
        Complete-Scan
        # A close request that arrived mid-scan was deferred until the thread
        # came back; honour it now.
        if ($script:ClosePending) { $form.Close() }
    }
}

function Complete-Scan {
    Set-Scanning -Running $false

    $script:Findings = @(@($script:Sync.Findings) | Sort-Object Rank, Title)

    $resultList.BeginUpdate()
    $resultList.Items.Clear()
    foreach ($finding in $script:Findings) {
        $item = New-Object System.Windows.Forms.ListViewItem($finding.Severity)
        $driveLabel = "$($finding.Drive)"
        if (-not $driveLabel -and $script:ScanRoots.Count -eq 1) { $driveLabel = $script:ScanRoots[0] }
        $null = $item.SubItems.Add($driveLabel)
        $null = $item.SubItems.Add($finding.Title)
        $null = $item.SubItems.Add($finding.File)
        $item.ForeColor = $colours[$finding.Severity]
        if ($finding.Severity -in @('Critical','High')) {
            $item.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        }
        $item.Tag = $finding
        $null = $resultList.Items.Add($item)
    }
    $resultList.EndUpdate()

    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($finding in $script:Findings) { $counts[$finding.Severity]++ }

    $summaryLabel.Text = "Critical $($counts.Critical)   -   High $($counts.High)   -   Medium $($counts.Medium)   -   Low $($counts.Low)   -   Info $($counts.Info)"
    $summaryLabel.ForeColor = if ($counts.Critical) { $colours.Critical }
                              elseif ($counts.High) { $colours.High }
                              elseif ($counts.Medium) { $colours.Medium }
                              else { [System.Drawing.Color]::FromArgb(23, 115, 74) }

    if ($script:Sync.Error) {
        $statusLabel.Text = "Scan failed: $($script:Sync.Error)"
    }
    elseif ($script:Sync.Cancel) {
        $statusLabel.Text = 'Scan stopped. Partial results shown.'
    }
    else {
        $where = if ($script:ScanRoots.Count -gt 1) { "$($script:ScanRoots.Count) drives" } else { "$($script:ScanRoots -join '')" }
        $statusLabel.Text = "Done. $where checked in $([int]((Get-Date) - $script:StartedAt).TotalSeconds) seconds."
    }

    $saveButton.Enabled = ($script:Findings.Count -gt 0)
    $progressBar.Value = 100

    # Not while the window is on its way out - a modal dialog would strand the
    # close the user already asked for.
    if ($counts.Critical -gt 0 -and -not $script:ClosePending) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "$($counts.Critical) critical finding(s) on this drive.`n`nDo not open anything on it until you have read them. Click each red row for details.",
            'Critical findings', 'OK', 'Warning')
    }
}

$scanButton.Add_Click({ Start-Scan -Roots (Get-CheckedRoots) })

$tickAllButton.Add_Click({
    foreach ($item in $driveList.Items) { $item.Checked = $true }
    Update-ScanButtonText
})

$tickNoneButton.Add_Click({
    foreach ($item in $driveList.Items) { $item.Checked = $false }
    Update-ScanButtonText
})

$driveList.Add_ItemChecked({ Update-ScanButtonText })

$cancelButton.Add_Click({
    if ($script:Sync) { $script:Sync.Cancel = $true }
    $statusLabel.Text = 'Stopping...'
})

$refreshButton.Add_Click({ Update-DriveList })

$browseButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Pick a folder to scan'
    if ($dialog.ShowDialog() -eq 'OK') { Start-Scan -Roots @($dialog.SelectedPath) }
})

# Double-clicking a row scans just that drive, whatever is ticked.
$driveList.Add_DoubleClick({
    if ($driveList.SelectedItems.Count -gt 0) { Start-Scan -Roots @("$($driveList.SelectedItems[0].Tag)") }
})

$resultList.Add_SelectedIndexChanged({
    if ($resultList.SelectedItems.Count -eq 0) { return }
    $finding = $resultList.SelectedItems[0].Tag
    if (-not $finding) { return }

    $text = New-Object System.Text.StringBuilder
    $null = $text.AppendLine("[$($finding.Severity)]  $($finding.Title)")
    $null = $text.AppendLine()
    $null = $text.AppendLine($finding.Detail)
    if ($finding.Recommendation) {
        $null = $text.AppendLine()
        $null = $text.AppendLine("WHAT TO DO:  $($finding.Recommendation)")
    }
    foreach ($pair in $finding.Evidence) {
        $null = $text.AppendLine()
        $null = $text.AppendLine("$($pair.Name): $($pair.Value)")
    }
    $detailBox.Text = $text.ToString()
})

$saveButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'HTML report (*.html)|*.html'
    $dialog.FileName = "DriveScan-{0}.html" -f (Get-Date).ToString('yyyyMMdd-HHmmss')
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ($desktop) { $dialog.InitialDirectory = $desktop }

    if ($dialog.ShowDialog() -ne 'OK') { return }

    $driveInfo = @{}
    $described = New-Object System.Collections.ArrayList
    foreach ($item in $driveList.Items) {
        if ($script:ScanRoots -notcontains "$($item.Tag)") { continue }
        $null = $described.Add("$($item.SubItems[0].Text) $($item.SubItems[1].Text) - $($item.SubItems[2].Text), $($item.SubItems[3].Text)")
    }
    if ($described.Count -gt 0) { $driveInfo['Drives scanned'] = ($described -join ' | ') }

    $saved = Save-DriveReport -Findings $script:Findings -ScanPath $script:ScanPath -OutputPath $dialog.FileName `
                              -StartedAt $script:StartedAt -FinishedAt (Get-Date) -DriveInfo $driveInfo
    $script:LastReport = $saved
    $openButton.Enabled = $true
    $statusLabel.Text = "Report saved to $saved"
})

$openButton.Add_Click({
    if ($script:LastReport -and (Test-Path -LiteralPath $script:LastReport)) {
        Start-Process $script:LastReport
    }
})

$form.Add_FormClosing({
    param($eventSender, $e)

    if ($script:Scanning) {
        # The scan owns this thread and is several frames below us on the stack.
        # Disposing the form now would leave the checks writing to dead controls,
        # so refuse the close, ask the scan to stop, and let Start-Scan close the
        # window when it unwinds.
        $script:Sync.Cancel  = $true
        $script:ClosePending = $true
        $statusLabel.Text    = 'Stopping...'
        $e.Cancel = $true
        return
    }

    if ($script:Sync) { $script:Sync.Cancel = $true }
})

Update-DriveList

if ($Path) {
    $form.Add_Shown({ Start-Scan -Roots @($Path) })
}

[void]$form.ShowDialog()
