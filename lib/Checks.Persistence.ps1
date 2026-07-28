<#
    Checks.Persistence.ps1 - Autoruns and persistence mechanisms.

    Defender scans files. It rarely objects to *where* a legitimate-looking
    binary has installed itself. This module walks the places code arranges to
    be re-executed and grades each entry on signature, location and command
    shape rather than on content.
#>

$script:PersistenceCategory = 'Persistence & Autoruns'

function Add-AutorunFinding {
    <#
        .SYNOPSIS
        Shared grading for "something will run this command later".

        Scores the resolved image (signature + location) and the command line
        (tradecraft patterns) and only emits a finding when something is off,
        so a clean machine produces a short report.
    #>
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Name,
        [string]$CommandLine,
        [string]$Check,
        [string]$BaselineSeverity = 'Low',
        [hashtable]$ExtraEvidence,
        [switch]$AlwaysReport
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return }

    $imagePath = Resolve-ExecutablePath -CommandLine $CommandLine
    $signature = Get-SignatureInfo -Path $imagePath
    $pathFlags = @(Test-SuspiciousPath -Path $imagePath)
    $cmdFlags  = @(Test-SuspiciousCommand -CommandLine $CommandLine)

    # The command line itself can look completely clean while pointing at a
    # script file whose actual content is the malicious part - inspect that
    # referenced file too, not just the invocation that names it.
    $scriptContentFlags = @()
    $referencedScript = Get-ReferencedScriptContent -CommandLine $CommandLine
    if ($referencedScript) {
        $scriptContentFlags = @(Test-SuspiciousCommand -CommandLine $referencedScript.Content)
    }

    $reasons    = New-Object System.Collections.ArrayList
    $severities = New-Object System.Collections.ArrayList

    foreach ($reason in $pathFlags) {
        $null = $reasons.Add($reason)
        $null = $severities.Add('High')
    }
    foreach ($hit in $cmdFlags) {
        $null = $reasons.Add($hit.Reason)
        $null = $severities.Add($hit.Severity)
    }
    foreach ($hit in $scriptContentFlags) {
        $null = $reasons.Add("Referenced script $(Split-Path $referencedScript.Path -Leaf): $($hit.Reason)")
        $null = $severities.Add($hit.Severity)
    }

    if ($imagePath -and -not $signature.Exists) {
        $null = $reasons.Add('Target file does not exist on disk (stale or removed payload)')
        $null = $severities.Add('Medium')
    }
    elseif ($signature.Exists -and -not $signature.IsMicrosoft) {
        if (-not $signature.IsSigned) {
            $null = $reasons.Add('Binary is not digitally signed')
            $null = $severities.Add('Medium')
        }
        elseif (-not $signature.IsTrusted) {
            $null = $reasons.Add("Signature does not validate (status: $($signature.Status))")
            $null = $severities.Add('High')
        }
    }

    $leaf = if ($imagePath) { try { Split-Path $imagePath -Leaf } catch { '' } } else { '' }
    $isLolBin = [bool]($leaf -and $script:LolBinNames -contains $leaf.ToLowerInvariant())
    if ($isLolBin) {
        $null = $reasons.Add("Persistence runs through $leaf, a signed Windows binary commonly abused to proxy execution")
        $null = $severities.Add('Medium')
    }

    if ($reasons.Count -eq 0 -and -not $AlwaysReport) { return }

    $severity = Get-WorstSeverity -Severities @($severities) -Default $BaselineSeverity

    # A trusted Microsoft binary in a normal location is background noise even
    # when it trips a soft heuristic - but not when the binary itself is a
    # known execution-proxy tool, or the script it was told to run is bad;
    # neither of those signals may be silently dropped.
    if ($signature.IsMicrosoft -and $pathFlags.Count -eq 0 -and $cmdFlags.Count -eq 0 -and $scriptContentFlags.Count -eq 0 -and -not $isLolBin) { $severity = 'Info' }

    $evidence = [ordered]@{
        'Location'    = $Source
        'Entry name'  = $Name
        'Command'     = ConvertTo-DisplayString $CommandLine 600
        'Resolved image' = $imagePath
        'Signature'   = if ($signature.Exists) { "$($signature.Status)$(if ($signature.Signer) { " - $($signature.Signer)" })" } else { 'file not found' }
        'Publisher'   = $signature.Company
    }
    if ($referencedScript) { $evidence['Referenced script'] = $referencedScript.Path }
    if ($ExtraEvidence) {
        foreach ($key in $ExtraEvidence.Keys) { $evidence[$key] = ConvertTo-DisplayString $ExtraEvidence[$key] }
    }

    Add-Finding -Category $script:PersistenceCategory `
                -Check $Check `
                -Severity $severity `
                -Title "Autorun entry '$Name' in $Source" `
                -Detail ($reasons -join '; ') `
                -Recommendation "Confirm you installed this. If unrecognised, remove the entry and quarantine the target file before rebooting." `
                -Evidence $evidence
}

# --------------------------------------------------------------------------

function Test-RunKeys {
    Write-ScanLog -Message 'Run / RunOnce registry keys' -Level 'Step'

    $machineKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    $userKeySuffixes = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )

    foreach ($key in $machineKeys) {
        foreach ($value in (Get-RegistryValues -Path $key)) {
            Add-AutorunFinding -Source ($key -replace '^HKLM:', 'HKLM') -Name $value.Name `
                               -CommandLine ([string]$value.Value) -Check 'RunKeys'
        }
    }

    foreach ($hive in (Get-UserHivePaths)) {
        foreach ($suffix in $userKeySuffixes) {
            $key = Join-Path $hive.Root $suffix
            foreach ($value in (Get-RegistryValues -Path $key)) {
                Add-AutorunFinding -Source "$($hive.User) : $suffix" -Name $value.Name `
                                   -CommandLine ([string]$value.Value) -Check 'RunKeys'
            }
        }
    }
}

function Test-StartupFolders {
    Write-ScanLog -Message 'Startup folders' -Level 'Step'

    $folders = New-Object System.Collections.ArrayList
    $null = $folders.Add("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    foreach ($profileDir in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
        $null = $folders.Add((Join-Path $profileDir.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
    }

    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($file in (Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.Name -eq 'desktop.ini') { continue }

            $target = $file.FullName
            $note   = $null

            # Resolve .lnk so the shortcut's target gets graded, not the shortcut.
            if ($file.Extension -eq '.lnk') {
                try {
                    $shell    = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($file.FullName)
                    if ($shortcut.TargetPath) {
                        $note   = "Shortcut -> $($shortcut.TargetPath) $($shortcut.Arguments)"
                        $target = "$($shortcut.TargetPath) $($shortcut.Arguments)"
                    }
                    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
                }
                catch { }
            }

            Add-AutorunFinding -Source ($folder -replace [regex]::Escape($env:SystemDrive), '') `
                               -Name $file.Name -CommandLine $target -Check 'StartupFolder' `
                               -ExtraEvidence @{ 'Shortcut target' = $note; 'Created' = $file.CreationTime }
        }
    }
}

function Test-ScheduledTasks {
    Write-ScanLog -Message 'Scheduled tasks' -Level 'Step'

    $tasks = $null
    try { $tasks = Get-ScheduledTask -ErrorAction Stop } catch { }

    if (-not $tasks) {
        Write-ScanLog -Message 'Get-ScheduledTask unavailable; scheduled task persistence could not be checked' -Level 'Warn'
        return
    }

    foreach ($task in $tasks) {
        # Microsoft's own tasks under \Microsoft\Windows\ are enormous in number
        # and uniformly benign; only inspect them if the action looks wrong.
        $isMicrosoftPath = $task.TaskPath -like '\Microsoft\Windows\*'

        foreach ($action in @($task.Actions)) {
            if (-not $action.PSObject.Properties['Execute']) { continue }
            $execute = "$($action.Execute)"
            if ([string]::IsNullOrWhiteSpace($execute)) { continue }

            $arguments = ''
            if ($action.PSObject.Properties['Arguments']) { $arguments = "$($action.Arguments)" }
            $commandLine = "$execute $arguments".Trim()

            $principal = ''
            $runLevel  = ''
            try {
                $principal = "$($task.Principal.UserId)"
                $runLevel  = "$($task.Principal.RunLevel)"
            }
            catch { }

            $extra = @{
                'Task path'  = $task.TaskPath
                'Runs as'    = "$principal $(if ($runLevel -eq 'Highest') { '(elevated)' })".Trim()
                'State'      = "$($task.State)"
                'Author'     = "$($task.Author)"
            }

            if ($isMicrosoftPath) {
                # Still grade it, but require a hard signal before reporting.
                $flags = @(Test-SuspiciousCommand -CommandLine $commandLine) + @(Test-SuspiciousPath -Path (Resolve-ExecutablePath $commandLine))
                if ($flags.Count -eq 0) { continue }
                $extra['Note'] = 'Task lives in the Microsoft task tree but its action is unusual - possible hijack of a built-in task'
            }

            Add-AutorunFinding -Source "Scheduled Task $($task.TaskPath)$($task.TaskName)" `
                               -Name $task.TaskName -CommandLine $commandLine `
                               -Check 'ScheduledTasks' -ExtraEvidence $extra
        }
    }

    # Tasks that hide themselves from the Task Scheduler UI.
    foreach ($task in $tasks) {
        $hidden = $false
        try { $hidden = [bool]$task.Settings.Hidden } catch { }
        if (-not $hidden) { continue }
        if ($task.TaskPath -like '\Microsoft\*') { continue }

        Add-Finding -Category $script:PersistenceCategory -Check 'ScheduledTasks' -Severity 'Medium' `
                    -Title "Hidden scheduled task '$($task.TaskName)'" `
                    -Detail 'The task sets the Hidden flag, so it does not appear in Task Scheduler by default. Legitimate third-party software rarely needs this.' `
                    -Recommendation 'Inspect the task action. Remove it if you do not recognise the software that created it.' `
                    -Evidence ([ordered]@{
                        'Task path' = "$($task.TaskPath)$($task.TaskName)"
                        'Author'    = "$($task.Author)"
                        'State'     = "$($task.State)"
                    })
    }
}

function Test-Services {
    Write-ScanLog -Message 'Services' -Level 'Step'

    $services = $null
    try { $services = Get-CimInstance Win32_Service -ErrorAction Stop } catch { return }

    foreach ($service in $services) {
        $imagePath = "$($service.PathName)"
        if ([string]::IsNullOrWhiteSpace($imagePath)) { continue }

        $resolved  = Resolve-ExecutablePath -CommandLine $imagePath
        $signature = Get-SignatureInfo -Path $resolved
        if ($signature.IsMicrosoft -and (Test-SuspiciousPath -Path $resolved).Count -eq 0) { continue }

        $extra = @{
            'Service name'  = $service.Name
            'Display name'  = $service.DisplayName
            'Start mode'    = $service.StartMode
            'State'         = $service.State
            'Runs as'       = $service.StartName
        }

        Add-AutorunFinding -Source "Service: $($service.Name)" -Name $service.DisplayName `
                           -CommandLine $imagePath -Check 'Services' -ExtraEvidence $extra
    }

    # svchost-hosted services load a DLL named in the registry rather than an
    # image path, so they are invisible to the loop above.
    foreach ($service in $services) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)\Parameters"
        $dll = Get-RegistryValue -Path $key -Name 'ServiceDll'
        if (-not $dll) { continue }

        $dllPath   = Expand-PathVariables -Path ([string]$dll)
        $signature = Get-SignatureInfo -Path $dllPath
        if ($signature.IsMicrosoft) { continue }

        $reasons = @(Test-SuspiciousPath -Path $dllPath)
        if (-not $signature.Exists)      { $reasons += 'ServiceDll target is missing from disk' }
        elseif (-not $signature.IsSigned) { $reasons += 'ServiceDll is unsigned' }
        elseif (-not $signature.IsTrusted) { $reasons += "ServiceDll signature is invalid ($($signature.Status))" }
        if ($reasons.Count -eq 0) { continue }

        Add-Finding -Category $script:PersistenceCategory -Check 'Services' -Severity 'High' `
                    -Title "Service '$($service.Name)' loads a non-Microsoft DLL into svchost" `
                    -Detail ($reasons -join '; ') `
                    -Recommendation 'Service DLL hijacking is a common persistence route. Verify the DLL publisher; if unknown, stop the service and quarantine the file.' `
                    -Evidence ([ordered]@{
                        'Service'    = "$($service.Name) ($($service.DisplayName))"
                        'ServiceDll' = $dllPath
                        'Signature'  = "$($signature.Status) $($signature.Signer)"
                        'Start mode' = $service.StartMode
                    })
    }
}

function Test-WmiSubscriptions {
    <#
        .SYNOPSIS
        WMI event subscriptions - filesystem-free persistence that Defender's
        file scanning cannot see at all, since the payload lives in the CIM
        repository rather than on disk.
    #>
    Write-ScanLog -Message 'WMI event subscriptions' -Level 'Step'

    $consumers = @()
    $filters   = @()
    $bindings  = @()
    try {
        $consumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop)
        $filters   = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue)
        $bindings  = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue)
    }
    catch {
        Write-ScanLog -Message 'root\subscription is not readable (needs an elevated session)' -Level 'Warn'
        return
    }

    foreach ($consumer in $consumers) {
        $class = $consumer.CimClass.CimClassName
        $name  = "$($consumer.Name)"

        # Shipped with Windows / SCCM and present on clean machines.
        if ($name -match '^(SCM Event Log Consumer|BVTConsumer|TSLogonEvents)$') { continue }

        $payload = ''
        $type    = $class
        if ($class -eq 'CommandLineEventConsumer') {
            $payload = "$($consumer.CommandLineTemplate)"
            if ($consumer.ExecutablePath) { $payload = "$($consumer.ExecutablePath) $payload" }
        }
        elseif ($class -eq 'ActiveScriptEventConsumer') {
            $payload = "$($consumer.ScriptText)"
            if ($consumer.ScriptFileName) { $payload = "$($consumer.ScriptFileName) $payload" }
            $type = "ActiveScriptEventConsumer ($($consumer.ScriptingEngine))"
        }
        else {
            $payload = "$($consumer.Name)"
        }

        $linkedFilter = ''
        foreach ($binding in $bindings) {
            $consumerName = $null
            if ("$($binding.Consumer)" -match '="(?<n>[^"]*)"\s*$') { $consumerName = $Matches['n'] }
            if ($consumerName -ne $name) { continue }

            foreach ($filter in $filters) {
                $filterName = $null
                if ("$($binding.Filter)" -match '="(?<n>[^"]*)"\s*$') { $filterName = $Matches['n'] }
                if ($filterName -eq $filter.Name) { $linkedFilter = "$($filter.Query)" }
            }
        }

        $severity = if ($class -in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) { 'Critical' } else { 'High' }
        $flags    = @(Test-SuspiciousCommand -CommandLine $payload)
        $detail   = 'A WMI event consumer runs code when a system event fires. This persists across reboots, leaves no autorun registry entry, and is a well-known technique for staying resident.'
        if ($flags.Count -gt 0) { $detail += ' Command shape flags: ' + (($flags | ForEach-Object { $_.Reason }) -join '; ') + '.' }

        Add-Finding -Category $script:PersistenceCategory -Check 'WmiSubscriptions' -Severity $severity `
                    -Title "WMI event consumer '$name'" `
                    -Detail $detail `
                    -Recommendation "Unless you or your IT department deployed this, treat it as malicious. Remove with: Get-CimInstance -Namespace root\subscription -ClassName $class | Where-Object Name -eq '$name' | Remove-CimInstance (also remove the paired __EventFilter and __FilterToConsumerBinding)." `
                    -Evidence ([ordered]@{
                        'Consumer type' = $type
                        'Name'          = $name
                        'Payload'       = ConvertTo-DisplayString $payload 800
                        'Trigger query' = ConvertTo-DisplayString $linkedFilter 500
                    })
    }
}

function Test-ImageFileExecutionOptions {
    Write-ScanLog -Message 'Image File Execution Options and SilentProcessExit' -Level 'Step'

    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    )

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($entry in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $debugger = Get-RegistryValue -Path $entry.PSPath -Name 'Debugger'
            if ($debugger) {
                Add-Finding -Category $script:PersistenceCategory -Check 'IFEO' -Severity 'Critical' `
                            -Title "IFEO debugger hijack on $($entry.PSChildName)" `
                            -Detail "Launching $($entry.PSChildName) will instead start '$debugger'. This both persists code and can be used to neutralise a security tool by pointing its executable at something harmless." `
                            -Recommendation "Delete the Debugger value under $($entry.Name) unless a developer intentionally configured this for debugging." `
                            -Evidence ([ordered]@{
                                'Hijacked image' = $entry.PSChildName
                                'Debugger'       = ConvertTo-DisplayString $debugger
                                'Key'            = $entry.Name
                            })
            }

            $globalFlag = Get-RegistryValue -Path $entry.PSPath -Name 'GlobalFlag'
            if ($globalFlag -and ([int]$globalFlag -band 0x200)) {
                $silentKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$($entry.PSChildName)"
                $monitor   = Get-RegistryValue -Path $silentKey -Name 'MonitorProcess'
                if ($monitor) {
                    Add-Finding -Category $script:PersistenceCategory -Check 'IFEO' -Severity 'Critical' `
                                -Title "SilentProcessExit persistence on $($entry.PSChildName)" `
                                -Detail "When $($entry.PSChildName) exits, Windows will launch '$monitor'. This is a stealthy trigger that survives reboot and is not shown by most autorun viewers." `
                                -Recommendation "Remove the MonitorProcess value under $silentKey and clear the GlobalFlag under the IFEO key." `
                                -Evidence ([ordered]@{
                                    'Monitored image' = $entry.PSChildName
                                    'MonitorProcess'  = ConvertTo-DisplayString $monitor
                                    'GlobalFlag'      = $globalFlag
                                })
                }
            }
        }
    }
}

function Test-WinlogonAndAppInit {
    Write-ScanLog -Message 'Winlogon, AppInit and LSA extension points' -Level 'Step'

    $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $expected = @{
        'Shell'    = 'explorer.exe'
        'Userinit' = "$env:SystemRoot\system32\userinit.exe,"
        'Taskman'  = $null
    }

    foreach ($name in $expected.Keys) {
        $value = Get-RegistryValue -Path $winlogonKey -Name $name
        if (-not $value) { continue }

        $normalized = "$value".Trim().TrimEnd(',').ToLowerInvariant()
        $baseline   = if ($expected[$name]) { "$($expected[$name])".Trim().TrimEnd(',').ToLowerInvariant() } else { $null }

        if ($name -eq 'Taskman' -or ($baseline -and $normalized -ne $baseline)) {
            Add-Finding -Category $script:PersistenceCategory -Check 'Winlogon' -Severity 'Critical' `
                        -Title "Winlogon $name has been modified" `
                        -Detail "Winlogon's $name value runs at every interactive logon before the desktop appears. Expected '$($expected[$name])', found '$value'." `
                        -Recommendation "Restore the default value. If $name is 'Shell', the default is explorer.exe; for 'Userinit' it is $env:SystemRoot\system32\userinit.exe, (trailing comma included). 'Taskman' should not normally exist." `
                        -Evidence ([ordered]@{
                            'Value name' = $name
                            'Current'    = ConvertTo-DisplayString $value
                            'Expected'   = if ($expected[$name]) { $expected[$name] } else { '(value should be absent)' }
                        })
        }
    }

    foreach ($subKey in @('Notify')) {
        $path = Join-Path $winlogonKey $subKey
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($entry in (Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue)) {
            $dll = Get-RegistryValue -Path $entry.PSPath -Name 'DLLName'
            if (-not $dll) { continue }
            Add-AutorunFinding -Source "Winlogon\Notify\$($entry.PSChildName)" -Name $entry.PSChildName `
                               -CommandLine ([string]$dll) -Check 'Winlogon' -BaselineSeverity 'High' -AlwaysReport
        }
    }

    # AppInit_DLLs is loaded into every process that links user32.dll.
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    )) {
        $appInit = Get-RegistryValue -Path $key -Name 'AppInit_DLLs'
        if ([string]::IsNullOrWhiteSpace("$appInit")) { continue }
        $enabled = Get-RegistryValue -Path $key -Name 'LoadAppInit_DLLs'

        Add-Finding -Category $script:PersistenceCategory -Check 'AppInit' -Severity 'Critical' `
                    -Title 'AppInit_DLLs is populated' `
                    -Detail "AppInit_DLLs injects the listed DLLs into essentially every GUI process on the system. It is deprecated and almost never used legitimately on a modern machine. Enabled flag: $enabled." `
                    -Recommendation 'Clear the AppInit_DLLs value and set LoadAppInit_DLLs to 0.' `
                    -Evidence ([ordered]@{ 'Key' = $key; 'AppInit_DLLs' = ConvertTo-DisplayString $appInit; 'LoadAppInit_DLLs' = $enabled })
    }

    $appCert = Get-RegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    foreach ($value in $appCert) {
        Add-Finding -Category $script:PersistenceCategory -Check 'AppCertDlls' -Severity 'Critical' `
                    -Title "AppCertDlls entry '$($value.Name)'" `
                    -Detail 'AppCertDlls load into any process that calls CreateProcess. The key is empty on a clean Windows install.' `
                    -Recommendation 'Delete this value unless you can attribute it to installed software.' `
                    -Evidence ([ordered]@{ 'Name' = $value.Name; 'DLL' = ConvertTo-DisplayString $value.Value })
    }

    # LSA packages run inside lsass.exe - the process holding credentials.
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lsaChecks = @{
        'Security Packages'       = @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','negoexts','cloudap','""')
        'Authentication Packages' = @('msv1_0','relogonms')
        'Notification Packages'   = @('scecli','rassfm','kdcsvc')
    }
    foreach ($name in $lsaChecks.Keys) {
        $value = Get-RegistryValue -Path $lsaKey -Name $name
        if (-not $value) { continue }
        foreach ($package in @($value)) {
            $clean = "$package".Trim().Trim('"').ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($clean)) { continue }
            if ($lsaChecks[$name] -contains $clean) { continue }

            Add-Finding -Category $script:PersistenceCategory -Check 'LsaPackages' -Severity 'Critical' `
                        -Title "Unrecognised LSA package '$package' in $name" `
                        -Detail 'LSA packages are DLLs loaded into lsass.exe, the process that holds credential material. An unexpected entry here is a classic credential-theft implant and is not something Defender flags by default.' `
                        -Recommendation "Identify $package in $env:SystemRoot\system32. If you cannot attribute it to installed security software, treat the machine as compromised and rotate credentials from a clean device." `
                        -Evidence ([ordered]@{ 'Registry value' = $name; 'Package' = "$package"; 'Key' = $lsaKey })
        }
    }
}

function Test-ComHijacks {
    <#
        .SYNOPSIS
        Per-user COM registrations that shadow machine-wide ones.

        HKCU\Software\Classes wins over HKLM for the calling user, so writing a
        CLSID there redirects a system component into an attacker DLL without
        needing administrator rights.
    #>
    Write-ScanLog -Message 'COM object hijacks (HKCU shadowing HKLM)' -Level 'Step'

    foreach ($hive in (Get-UserHivePaths)) {
        $clsidRoot = Join-Path $hive.Root 'SOFTWARE\Classes\CLSID'
        if (-not (Test-Path -LiteralPath $clsidRoot)) { continue }

        foreach ($clsid in (Get-ChildItem -LiteralPath $clsidRoot -ErrorAction SilentlyContinue)) {
            foreach ($serverType in @('InprocServer32', 'LocalServer32', 'InprocServer')) {
                $serverKey = Join-Path $clsid.PSPath $serverType
                if (-not (Test-Path -LiteralPath $serverKey)) { continue }

                $default = Get-RegistryValue -Path $serverKey -Name '(default)'
                if ([string]::IsNullOrWhiteSpace("$default")) { continue }

                $shadowsMachine = Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\CLSID\$($clsid.PSChildName)\$serverType"
                $severity = if ($shadowsMachine) { 'Critical' } else { 'High' }
                $detail = if ($shadowsMachine) {
                    "This per-user CLSID registration overrides a machine-wide one. Any process running as this user that instantiates $($clsid.PSChildName) will load the user-controlled file instead of the system component."
                } else {
                    "A per-user COM server is registered for $($clsid.PSChildName). Per-user COM registration is uncommon outside of a handful of applications."
                }

                Add-AutorunFinding -Source "$($hive.User) COM $serverType $($clsid.PSChildName)" `
                                   -Name $clsid.PSChildName -CommandLine ([string]$default) `
                                   -Check 'ComHijack' -BaselineSeverity $severity -AlwaysReport `
                                   -ExtraEvidence @{
                                       'CLSID'                = $clsid.PSChildName
                                       'Shadows HKLM'         = $shadowsMachine
                                       'Why this matters'     = $detail
                                   }
            }
        }
    }
}

function Test-PowerShellProfiles {
    Write-ScanLog -Message 'PowerShell profile scripts' -Level 'Step'

    $profilePaths = New-Object System.Collections.ArrayList
    foreach ($name in @('AllUsersAllHosts','AllUsersCurrentHost','CurrentUserAllHosts','CurrentUserCurrentHost')) {
        try {
            $path = $PROFILE.$name
            if ($path) { $null = $profilePaths.Add([pscustomobject]@{ Scope = $name; Path = $path }) }
        }
        catch { }
    }
    foreach ($profileDir in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
        foreach ($relative in @('Documents\WindowsPowerShell\profile.ps1','Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1','Documents\PowerShell\profile.ps1')) {
            $null = $profilePaths.Add([pscustomobject]@{ Scope = "User: $($profileDir.Name)"; Path = (Join-Path $profileDir.FullName $relative) })
        }
    }

    $seen = @{}
    foreach ($entry in $profilePaths) {
        if (-not $entry.Path) { continue }
        $key = $entry.Path.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        if (-not (Test-Path -LiteralPath $entry.Path -PathType Leaf)) { continue }

        $content = ''
        try { $content = (Get-Content -LiteralPath $entry.Path -Raw -ErrorAction Stop) } catch { }
        $flags = @(Test-SuspiciousCommand -CommandLine $content)

        $severity = if ($flags.Count -gt 0) { Get-WorstSeverity -Severities @($flags | ForEach-Object { $_.Severity }) -Default 'High' } else { 'Low' }
        $detail = 'A PowerShell profile executes automatically in every PowerShell session. It is a quiet persistence and credential-capture location.'
        if ($flags.Count -gt 0) { $detail += ' Flags: ' + (($flags | ForEach-Object { $_.Reason }) -join '; ') + '.' }

        Add-Finding -Category $script:PersistenceCategory -Check 'PowerShellProfile' -Severity $severity `
                    -Title "PowerShell profile present ($($entry.Scope))" `
                    -Detail $detail `
                    -Recommendation 'Open the file and confirm every line is yours. Profiles you did not create should be removed.' `
                    -Evidence ([ordered]@{
                        'Path'     = $entry.Path
                        'Modified' = (Get-Item -LiteralPath $entry.Path -ErrorAction SilentlyContinue).LastWriteTime
                        'Preview'  = ConvertTo-DisplayString $content 600
                    })
    }
}

function Test-ExplorerExtensionPoints {
    Write-ScanLog -Message 'Explorer and shell extension points' -Level 'Step'

    # Browser Helper Objects still load into anything hosting the IE control.
    foreach ($bhoRoot in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
    )) {
        if (-not (Test-Path -LiteralPath $bhoRoot)) { continue }
        foreach ($bho in (Get-ChildItem -LiteralPath $bhoRoot -ErrorAction SilentlyContinue)) {
            $clsid  = $bho.PSChildName
            $server = Get-RegistryValue -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -Name '(default)'
            Add-AutorunFinding -Source 'Browser Helper Object' -Name $clsid `
                               -CommandLine ([string]$server) -Check 'ShellExtensions' `
                               -BaselineSeverity 'Medium' -AlwaysReport -ExtraEvidence @{ 'CLSID' = $clsid }
        }
    }

    # ShellServiceObjectDelayLoad entries load into explorer.exe at logon.
    $ssodl = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'
    foreach ($value in (Get-RegistryValues -Path $ssodl)) {
        $server = Get-RegistryValue -Path "HKLM:\SOFTWARE\Classes\CLSID\$($value.Value)\InprocServer32" -Name '(default)'
        if (-not $server) { continue }
        Add-AutorunFinding -Source 'ShellServiceObjectDelayLoad' -Name $value.Name `
                           -CommandLine ([string]$server) -Check 'ShellExtensions' -ExtraEvidence @{ 'CLSID' = $value.Value }
    }

    # Active Setup runs StubPath once per user at first logon.
    foreach ($activeSetupRoot in @(
        'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components'
    )) {
        if (-not (Test-Path -LiteralPath $activeSetupRoot)) { continue }
        foreach ($component in (Get-ChildItem -LiteralPath $activeSetupRoot -ErrorAction SilentlyContinue)) {
            $stub = Get-RegistryValue -Path $component.PSPath -Name 'StubPath'
            if ([string]::IsNullOrWhiteSpace("$stub")) { continue }
            Add-AutorunFinding -Source 'Active Setup StubPath' -Name $component.PSChildName `
                               -CommandLine ([string]$stub) -Check 'ActiveSetup' `
                               -ExtraEvidence @{ 'Component' = (Get-RegistryValue -Path $component.PSPath -Name '(default)') }
        }
    }

    # File association hijack: what actually runs when you double-click an .exe.
    $exeCommand = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Classes\exefile\shell\open\command' -Name '(default)'
    if ($exeCommand -and "$exeCommand".Trim() -ne '"%1" %*') {
        Add-Finding -Category $script:PersistenceCategory -Check 'FileAssociation' -Severity 'Critical' `
                    -Title 'Executable file association has been hijacked' `
                    -Detail "Running any .exe passes through '$exeCommand' instead of the default '`"%1`" %*'. Every program you launch would be proxied through the attacker's command." `
                    -Recommendation 'Restore HKLM\SOFTWARE\Classes\exefile\shell\open\command to "%1" %*' `
                    -Evidence ([ordered]@{ 'Current' = ConvertTo-DisplayString $exeCommand; 'Expected' = '"%1" %*' })
    }

    # Screensaver executable is a long-standing autorun.
    foreach ($hive in (Get-UserHivePaths)) {
        $screensaver = Get-RegistryValue -Path (Join-Path $hive.Root 'Control Panel\Desktop') -Name 'SCRNSAVE.EXE'
        if ([string]::IsNullOrWhiteSpace("$screensaver")) { continue }
        if ("$screensaver" -match '\.scr$' -and "$screensaver" -match '\\Windows\\(System32|SysWOW64)\\') { continue }
        Add-AutorunFinding -Source "$($hive.User) screensaver" -Name 'SCRNSAVE.EXE' `
                           -CommandLine ([string]$screensaver) -Check 'Screensaver' -BaselineSeverity 'Medium' -AlwaysReport
    }
}

function Test-BootAndDriverPersistence {
    Write-ScanLog -Message 'Boot execution and kernel drivers' -Level 'Step'

    $bootExecute = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'BootExecute'
    foreach ($entry in @($bootExecute)) {
        $text = "$entry".Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        if ($text -match '^autocheck autochk') { continue }

        Add-Finding -Category $script:PersistenceCategory -Check 'BootExecute' -Severity 'Critical' `
                    -Title "Non-default BootExecute entry" `
                    -Detail "BootExecute runs native applications before Win32 and before any security product loads. The only expected entries are autocheck autochk variants; found '$text'." `
                    -Recommendation 'Remove the entry unless a disk utility you installed documented it.' `
                    -Evidence ([ordered]@{ 'Entry' = $text })
    }

    # Unsigned or invalidly signed kernel drivers - full ring 0, and a running
    # driver can hide itself from user-mode scanners entirely.
    $drivers = $null
    try { $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction Stop } catch { return }

    foreach ($driver in $drivers) {
        $path = Expand-PathVariables -Path "$($driver.PathName)"
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        $signature = Get-SignatureInfo -Path $path
        if ($signature.IsMicrosoft) { continue }
        if ($signature.IsTrusted -and $driver.State -ne 'Running') { continue }

        $reasons = @(Test-SuspiciousPath -Path $path)
        if (-not $signature.Exists)        { $reasons += 'Driver file is missing from disk' }
        elseif (-not $signature.IsSigned)  { $reasons += 'Driver is unsigned' }
        elseif (-not $signature.IsTrusted) { $reasons += "Driver signature does not validate ($($signature.Status))" }
        if ($reasons.Count -eq 0) { continue }

        Add-Finding -Category $script:PersistenceCategory -Check 'Drivers' -Severity 'Critical' `
                    -Title "Kernel driver '$($driver.Name)' is not properly signed" `
                    -Detail (($reasons -join '; ') + ". A driver runs in kernel mode and can conceal files, processes and network connections from every user-mode scanner, including Defender.") `
                    -Recommendation 'Identify the driver publisher. Unattributable kernel drivers warrant offline analysis and, if confirmed malicious, a rebuild of the machine.' `
                    -Evidence ([ordered]@{
                        'Driver'     = "$($driver.Name) ($($driver.DisplayName))"
                        'Path'       = $path
                        'State'      = $driver.State
                        'Start mode' = $driver.StartMode
                        'Signature'  = "$($signature.Status) $($signature.Signer)"
                    })
    }
}

function Test-NetshAndPrintPersistence {
    Write-ScanLog -Message 'netsh helpers, print monitors and Winsock providers' -Level 'Step'

    foreach ($value in (Get-RegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\NetSh')) {
        $dll = Expand-PathVariables -Path ([string]$value.Value)
        if ($dll -notmatch '[\\/]') { $dll = Join-Path "$env:SystemRoot\System32" $dll }
        $signature = Get-SignatureInfo -Path $dll
        if ($signature.IsMicrosoft) { continue }

        Add-AutorunFinding -Source 'netsh helper DLL' -Name $value.Name -CommandLine $dll `
                           -Check 'NetshHelper' -BaselineSeverity 'High' -AlwaysReport `
                           -ExtraEvidence @{ 'Note' = 'netsh helper DLLs load whenever netsh.exe runs' }
    }

    foreach ($monitorRoot in @('HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors')) {
        if (-not (Test-Path -LiteralPath $monitorRoot)) { continue }
        foreach ($monitor in (Get-ChildItem -LiteralPath $monitorRoot -ErrorAction SilentlyContinue)) {
            $dll = Get-RegistryValue -Path $monitor.PSPath -Name 'Driver'
            if ([string]::IsNullOrWhiteSpace("$dll")) { continue }

            $dllPath = Expand-PathVariables -Path "$dll"
            if ($dllPath -notmatch '[\\/]') { $dllPath = Join-Path "$env:SystemRoot\System32" $dllPath }
            $signature = Get-SignatureInfo -Path $dllPath
            if ($signature.IsMicrosoft) { continue }

            Add-AutorunFinding -Source 'Print monitor' -Name $monitor.PSChildName -CommandLine $dllPath `
                               -Check 'PrintMonitor' -BaselineSeverity 'High' -AlwaysReport `
                               -ExtraEvidence @{ 'Note' = 'Print monitor DLLs are loaded by the spooler service as SYSTEM' }
        }
    }
}

function Invoke-PersistenceChecks {
    Invoke-Check -Name 'RunKeys'              -Body { Test-RunKeys }
    Invoke-Check -Name 'StartupFolders'       -Body { Test-StartupFolders }
    Invoke-Check -Name 'ScheduledTasks'       -Body { Test-ScheduledTasks }
    Invoke-Check -Name 'Services'             -Body { Test-Services }
    Invoke-Check -Name 'WmiSubscriptions'     -Body { Test-WmiSubscriptions }
    Invoke-Check -Name 'IFEO'                 -Body { Test-ImageFileExecutionOptions }
    Invoke-Check -Name 'WinlogonAppInitLsa'   -Body { Test-WinlogonAndAppInit }
    Invoke-Check -Name 'ComHijacks'           -Body { Test-ComHijacks }
    Invoke-Check -Name 'PowerShellProfiles'   -Body { Test-PowerShellProfiles }
    Invoke-Check -Name 'ExplorerExtensions'   -Body { Test-ExplorerExtensionPoints }
    Invoke-Check -Name 'BootAndDrivers'       -Body { Test-BootAndDriverPersistence }
    Invoke-Check -Name 'NetshAndPrint'        -Body { Test-NetshAndPrintPersistence }
}
