<#
    Checks.Accounts.ps1 - Local accounts and privilege escalation paths.

    Everything here is a misconfiguration rather than a file, so none of it
    produces an antivirus detection. The privilege-path checks answer a
    specific question: if a standard user (or a piece of malware running as
    one) is on this machine, what lets it become SYSTEM without an exploit?
#>

$script:AccountCategory = 'Accounts & Privilege Paths'

function Test-LocalAccounts {
    Write-ScanLog -Message 'Local accounts' -Level 'Step'

    $users = $null
    try { $users = @(Get-LocalUser -ErrorAction Stop) } catch { }
    if (-not $users) {
        try { $users = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop) } catch { return }
    }

    # Accounts hidden from the sign-in screen. A real backdoor account is
    # usually paired with an entry here so nobody notices it exists.
    $hiddenList = @{}
    foreach ($value in (Get-RegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList')) {
        if ([int]$value.Value -eq 0) { $hiddenList["$($value.Name)".ToLowerInvariant()] = $true }
    }

    foreach ($user in $users) {
        $name    = "$($user.Name)"
        $enabled = if ($user.PSObject.Properties['Enabled']) { [bool]$user.Enabled } else { -not [bool]$user.Disabled }
        if (-not $enabled) { continue }

        if ($hiddenList.ContainsKey($name.ToLowerInvariant())) {
            Add-Finding -Category $script:AccountCategory -Check 'LocalAccounts' -Severity 'Critical' `
                        -Title "Account '$name' is enabled but hidden from the sign-in screen" `
                        -Detail 'A registry entry under Winlogon\SpecialAccounts\UserList hides this account from the logon UI and from the Users control panel while leaving it fully usable. There is essentially no legitimate reason for this on a personal machine - it is how a backdoor account is concealed.' `
                        -Recommendation "Delete the '$name' value under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList, then disable or remove the account with Disable-LocalUser -Name '$name'." `
                        -Evidence ([ordered]@{
                            'Account'    = $name
                            'Enabled'    = $enabled
                            'Last logon' = if ($user.PSObject.Properties['LastLogon']) { $user.LastLogon } else { '' }
                            'Description'= "$($user.Description)"
                        })
        }

        if ($name -match '^Guest$') {
            Add-Finding -Category $script:AccountCategory -Check 'LocalAccounts' -Severity 'High' `
                        -Title 'The Guest account is enabled' `
                        -Detail 'Guest allows password-less local and, depending on policy, network access. It is disabled by default on every supported Windows version.' `
                        -Recommendation 'Disable-LocalUser -Name Guest' `
                        -Evidence ([ordered]@{ 'Account' = $name; 'Enabled' = 'True' })
        }

        if ($user.PSObject.Properties['PasswordRequired'] -and $user.PasswordRequired -eq $false) {
            Add-Finding -Category $script:AccountCategory -Check 'LocalAccounts' -Severity 'High' `
                        -Title "Account '$name' does not require a password" `
                        -Detail 'Anyone with physical access can log in as this account, and depending on policy it may be usable over the network too.' `
                        -Recommendation "Set a password with Set-LocalUser -Name '$name' -Password (Read-Host -AsSecureString), or disable the account." `
                        -Evidence ([ordered]@{ 'Account' = $name; 'PasswordRequired' = 'False' })
        }

        # Recently created accounts are worth a look after a suspected incident.
        if ($user.PSObject.Properties['PasswordLastSet'] -and $user.PasswordLastSet) {
            $age = ((Get-Date) - $user.PasswordLastSet).TotalDays
            if ($age -lt 14 -and $name -notmatch '^(DefaultAccount|WDAGUtilityAccount|Guest|Administrator)$') {
                Add-Finding -Category $script:AccountCategory -Check 'LocalAccounts' -Severity 'Low' `
                            -Title "Account '$name' had its password set within the last $([int]$age) days" `
                            -Detail 'Noted so you can rule out an account that was created or taken over recently. Expected if you set this up yourself.' `
                            -Recommendation 'Confirm you recognise this account and this change.' `
                            -Evidence ([ordered]@{ 'Account' = $name; 'PasswordLastSet' = $user.PasswordLastSet })
            }
        }
    }

    # Administrators group membership.
    try {
        $administrators = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        $memberList = ($administrators | ForEach-Object { "$($_.Name) [$($_.ObjectClass)]" }) -join ', '

        $unexpected = @($administrators | Where-Object {
            "$($_.Name)" -notmatch '\\(Administrator|Domain Admins|Enterprise Admins)$' -and
            "$($_.PrincipalSource)" -ne 'MicrosoftAccount'
        })

        Add-Finding -Category $script:AccountCategory -Check 'LocalAccounts' `
                    -Severity ($(if ($administrators.Count -gt 3) { 'Medium' } else { 'Info' })) `
                    -Title "Local Administrators group has $($administrators.Count) member(s)" `
                    -Detail 'Every member here can disable Defender, add exclusions and install drivers. Confirm each one is expected; day-to-day use should be from a standard account.' `
                    -Recommendation 'Remove any member you do not recognise with Remove-LocalGroupMember -Group Administrators -Member <name>.' `
                    -Evidence ([ordered]@{
                        'Members'  = $memberList
                        'Reviewed' = if ($unexpected.Count -gt 0) { "Pay particular attention to: $(($unexpected | ForEach-Object { $_.Name }) -join ', ')" } else { 'Only default members detected' }
                    })
    }
    catch { }

    # Built-in Administrator (RID 500) enabled is unusual on modern Windows.
    try {
        $builtinAdmin = Get-LocalUser -ErrorAction Stop | Where-Object { "$($_.SID)" -match '-500$' }
        if ($builtinAdmin -and $builtinAdmin.Enabled) {
            Add-Finding -Category $script:AccountCategory -Check 'LocalAccounts' -Severity 'Medium' `
                        -Title "The built-in Administrator account ('$($builtinAdmin.Name)') is enabled" `
                        -Detail 'RID 500 is disabled by default. When enabled it is exempt from UAC prompts in the default configuration, and it is the first account name a remote attacker will try.' `
                        -Recommendation "Disable-LocalUser -Name '$($builtinAdmin.Name)' and use your own administrator account instead." `
                        -Evidence ([ordered]@{ 'Account' = $builtinAdmin.Name; 'SID' = "$($builtinAdmin.SID)"; 'Last logon' = $builtinAdmin.LastLogon })
        }
    }
    catch { }
}

function Test-PasswordPolicy {
    Write-ScanLog -Message 'Password and lockout policy' -Level 'Step'

    $output = ''
    try { $output = (& net accounts 2>$null | Out-String) } catch { return }
    if ([string]::IsNullOrWhiteSpace($output)) { return }

    if ($output -match 'Lockout threshold:\s*(?<threshold>\S+)') {
        $threshold = $Matches['threshold']
        if ($threshold -match '^(Never|0)$') {
            Add-Finding -Category $script:AccountCategory -Check 'PasswordPolicy' -Severity 'Medium' `
                        -Title 'No account lockout threshold is set' `
                        -Detail 'Passwords can be guessed indefinitely with no lockout. This matters most alongside RDP or SMB being reachable from the network.' `
                        -Recommendation 'Set a threshold: net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15' `
                        -Evidence ([ordered]@{ 'Lockout threshold' = $threshold })
        }
    }

    if ($output -match 'Minimum password length:\s*(?<length>\d+)') {
        $length = [int]$Matches['length']
        if ($length -lt 8) {
            Add-Finding -Category $script:AccountCategory -Check 'PasswordPolicy' -Severity 'Low' `
                        -Title "Minimum password length is $length" `
                        -Detail 'Short passwords fall quickly to offline cracking if a credential hash is ever captured.' `
                        -Recommendation 'net accounts /minpwlen:14' `
                        -Evidence ([ordered]@{ 'Minimum password length' = $length })
        }
    }
}

function Test-UnquotedServicePaths {
    <#
        .SYNOPSIS
        Classic unquoted service path escalation.

        "C:\Program Files\My App\svc.exe" without quotes makes Windows try
        C:\Program.exe first. If any prefix directory is user-writable, a
        standard user plants a binary there and it runs as the service account.
    #>
    Write-ScanLog -Message 'Unquoted service paths' -Level 'Step'

    $services = $null
    try { $services = @(Get-CimInstance Win32_Service -ErrorAction Stop) } catch { return }

    foreach ($service in $services) {
        $imagePath = "$($service.PathName)"
        if ([string]::IsNullOrWhiteSpace($imagePath)) { continue }
        if ($imagePath.TrimStart().StartsWith('"')) { continue }

        # Only the executable portion matters; arguments after it are irrelevant.
        $executable = $imagePath
        if ($imagePath -match '^(?<exe>.*?\.exe)\s') { $executable = $Matches['exe'] }
        if ($executable -notmatch '\s') { continue }
        if ($executable -match '^[^\\/]*$') { continue }

        # Drivers under system32 with no spaces are not affected.
        $writablePrefixes = New-Object System.Collections.ArrayList
        $parent = Split-Path $executable -Parent
        while ($parent -and $parent -match '\\') {
            if ($parent -match '\s') {
                $acl = Test-UserWritable -Path (Split-Path $parent -Parent)
                if ($acl -and $acl.Writable) {
                    $null = $writablePrefixes.Add("$(Split-Path $parent -Parent) ($($acl.Grants -join '; '))")
                }
            }
            $next = Split-Path $parent -Parent
            if ($next -eq $parent) { break }
            $parent = $next
        }

        $severity = if ($writablePrefixes.Count -gt 0) { 'Critical' } else { 'Medium' }
        $detail = "The service '$($service.Name)' has an unquoted image path containing spaces: $imagePath. Windows will try each space-separated prefix as an executable in turn."
        if ($writablePrefixes.Count -gt 0) {
            $detail += " One of those prefix directories is writable by non-administrators, so any user on this machine can place a file there and have it run as $($service.StartName)."
        }
        else {
            $detail += ' No writable prefix directory was found, so this is currently not exploitable - but it becomes exploitable the moment permissions change.'
        }

        Add-Finding -Category $script:AccountCategory -Check 'UnquotedServicePath' -Severity $severity `
                    -Title "Unquoted service path: $($service.Name)" `
                    -Detail $detail `
                    -Recommendation "Quote the path: sc.exe config `"$($service.Name)`" binPath= `"`"$executable`"`" (keep any original arguments after the closing quote)." `
                    -Evidence ([ordered]@{
                        'Service'    = "$($service.Name) ($($service.DisplayName))"
                        'ImagePath'  = $imagePath
                        'Runs as'    = $service.StartName
                        'Start mode' = $service.StartMode
                        'Writable prefixes' = if ($writablePrefixes.Count -gt 0) { ($writablePrefixes -join ' | ') } else { 'none found' }
                    })
    }
}

function Test-WritableServiceBinaries {
    Write-ScanLog -Message 'Service binary and directory permissions' -Level 'Step'

    $services = $null
    try { $services = @(Get-CimInstance Win32_Service -ErrorAction Stop) } catch { return }

    foreach ($service in $services) {
        $imagePath = "$($service.PathName)"
        if ([string]::IsNullOrWhiteSpace($imagePath)) { continue }

        $resolved = Resolve-ExecutablePath -CommandLine $imagePath
        if (-not $resolved -or -not (Test-Path -LiteralPath $resolved -PathType Leaf -ErrorAction SilentlyContinue)) { continue }

        # Only privileged service accounts turn a write into an escalation.
        $runsAs = "$($service.StartName)"
        if ($runsAs -notmatch 'LocalSystem|NT AUTHORITY\\SYSTEM|LocalService|NetworkService') { continue }

        $fileAcl = Test-UserWritable -Path $resolved
        if ($fileAcl -and $fileAcl.Writable) {
            Add-Finding -Category $script:AccountCategory -Check 'WritableServiceBinary' -Severity 'Critical' `
                        -Title "Service binary for '$($service.Name)' is writable by non-administrators" `
                        -Detail "Any standard user can overwrite $resolved. The service runs as $runsAs, so replacing that file gives full SYSTEM code execution at the next service start or reboot. No exploit and no malware file is needed for this - which is why antivirus does not flag it." `
                        -Recommendation "Correct the ACL so only Administrators and SYSTEM can write: icacls `"$resolved`" /inheritance:r /grant `"Administrators:(F)`" `"SYSTEM:(F)`" `"Users:(RX)`"" `
                        -Evidence ([ordered]@{
                            'Service' = "$($service.Name) ($($service.DisplayName))"
                            'Binary'  = $resolved
                            'Runs as' = $runsAs
                            'Owner'   = $fileAcl.Owner
                            'Dangerous grants' = ($fileAcl.Grants -join ' | ')
                        })
            continue
        }

        # A writable containing directory permits a rename-and-replace attack.
        $directory = Split-Path $resolved -Parent
        if ($directory -match '\\Windows\\(System32|SysWOW64)$') { continue }

        $directoryAcl = Test-UserWritable -Path $directory
        if ($directoryAcl -and $directoryAcl.Writable) {
            Add-Finding -Category $script:AccountCategory -Check 'WritableServiceBinary' -Severity 'High' `
                        -Title "Directory holding service '$($service.Name)' is writable by non-administrators" `
                        -Detail "Standard users can write into $directory. Even without permission on the binary itself, a user can often replace or shadow it (or drop a DLL the service loads) and gain $runsAs privileges." `
                        -Recommendation "Restrict the directory: icacls `"$directory`" /inheritance:r /grant `"Administrators:(OI)(CI)F`" `"SYSTEM:(OI)(CI)F`" `"Users:(OI)(CI)RX`"" `
                        -Evidence ([ordered]@{
                            'Service'   = $service.Name
                            'Directory' = $directory
                            'Runs as'   = $runsAs
                            'Dangerous grants' = ($directoryAcl.Grants -join ' | ')
                        })
        }
    }
}

function Test-ServicePermissions {
    <#
        .SYNOPSIS
        Service security descriptors that let non-administrators reconfigure a
        service. SERVICE_CHANGE_CONFIG is equivalent to SYSTEM: the binary path
        can simply be repointed.
    #>
    Write-ScanLog -Message 'Service security descriptors' -Level 'Step'

    $services = $null
    try { $services = @(Get-Service -ErrorAction Stop) } catch { return }

    # SDDL identities for non-administrative principals.
    $weakPrincipals = @{
        'AU' = 'Authenticated Users'
        'BU' = 'Built-in Users'
        'WD' = 'Everyone'
        'IU' = 'Interactive Users'
        'BG' = 'Built-in Guests'
        'AN' = 'Anonymous'
    }
    # Rights that amount to control of the service.
    $dangerousRights = @{
        'RP' = 'start the service'
        'WP' = 'stop the service'
        'DT' = 'pause the service'
        'CC' = 'query configuration'
        'DC' = 'change configuration (equivalent to SYSTEM code execution)'
        'WD' = 'change permissions'
        'WO' = 'take ownership'
        'GA' = 'full control'
        'SD' = 'delete the service'
    }

    foreach ($service in $services) {
        $sddl = ''
        try { $sddl = (& sc.exe sdshow "$($service.Name)" 2>$null | Out-String).Trim() } catch { continue }
        if ([string]::IsNullOrWhiteSpace($sddl) -or $sddl -notmatch '^D:') { continue }

        foreach ($ace in [regex]::Matches($sddl, '\(A;[^;]*;(?<rights>[^;]*);[^;]*;[^;]*;(?<sid>[^\)]*)\)')) {
            $sid    = $ace.Groups['sid'].Value
            $rights = $ace.Groups['rights'].Value
            if (-not $weakPrincipals.ContainsKey($sid)) { continue }

            $granted = New-Object System.Collections.ArrayList
            foreach ($right in @('DC','WD','WO','GA','SD')) {
                if ($rights -match $right) { $null = $granted.Add($dangerousRights[$right]) }
            }
            if ($granted.Count -eq 0) { continue }

            Add-Finding -Category $script:AccountCategory -Check 'ServicePermissions' -Severity 'Critical' `
                        -Title "Service '$($service.Name)' can be reconfigured by $($weakPrincipals[$sid])" `
                        -Detail "The service security descriptor grants $($weakPrincipals[$sid]) the ability to $(($granted -join ', ')). Anyone in that group can point the service at their own executable and have it launched by the service control manager." `
                        -Recommendation "Reset the descriptor to the Windows default for this service type, or apply a restrictive one with sc.exe sdset. Verify with: sc.exe sdshow $($service.Name)" `
                        -Evidence ([ordered]@{
                            'Service'   = "$($service.Name) ($($service.DisplayName))"
                            'Principal' = "$($weakPrincipals[$sid]) ($sid)"
                            'Rights'    = $rights
                            'SDDL'      = ConvertTo-DisplayString $sddl 400
                        })
        }
    }
}

function Test-PathHijacking {
    Write-ScanLog -Message 'PATH directory permissions' -Level 'Step'

    $systemPath = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name 'Path'
    if (-not $systemPath) { return }

    $index = 0
    foreach ($directory in ("$systemPath" -split ';')) {
        $index++
        $expanded = Expand-PathVariables -Path $directory
        if ([string]::IsNullOrWhiteSpace($expanded)) { continue }
        if (-not (Test-Path -LiteralPath $expanded -PathType Container -ErrorAction SilentlyContinue)) {
            # A missing PATH entry that a user can create is also a hijack.
            $parent = Split-Path $expanded -Parent
            $parentAcl = Test-UserWritable -Path $parent
            if ($parentAcl -and $parentAcl.Writable) {
                Add-Finding -Category $script:AccountCategory -Check 'PathHijack' -Severity 'High' `
                            -Title "System PATH entry '$expanded' does not exist but can be created by any user" `
                            -Detail "The directory is listed in the machine PATH but is absent. Because its parent is writable by non-administrators, a standard user can create it and place executables that will be found by name before the real ones." `
                            -Recommendation "Remove the stale entry from the system PATH, or create the directory with administrator-only write permissions." `
                            -Evidence ([ordered]@{ 'PATH entry' = $expanded; 'Position' = $index; 'Writable parent' = $parent })
            }
            continue
        }

        $acl = Test-UserWritable -Path $expanded
        if (-not $acl -or -not $acl.Writable) { continue }

        Add-Finding -Category $script:AccountCategory -Check 'PathHijack' -Severity 'Critical' `
                    -Title "System PATH directory '$expanded' is writable by non-administrators" `
                    -Detail "This directory is searched when any process runs a command by name. A standard user can drop a file such as cmd.exe or a commonly-used tool name here; when an administrator or a service later runs that command, the planted binary executes with their privileges. It is position $index in the PATH." `
                    -Recommendation "Either remove the directory from the system PATH or restrict it: icacls `"$expanded`" /inheritance:r /grant `"Administrators:(OI)(CI)F`" `"SYSTEM:(OI)(CI)F`" `"Users:(OI)(CI)RX`"" `
                    -Evidence ([ordered]@{
                        'Directory' = $expanded
                        'PATH position' = $index
                        'Owner' = $acl.Owner
                        'Dangerous grants' = ($acl.Grants -join ' | ')
                    })
    }
}

function Test-ScheduledTaskPrivilegePaths {
    Write-ScanLog -Message 'Scheduled tasks running with elevated rights' -Level 'Step'

    $tasks = $null
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) } catch { return }

    foreach ($task in $tasks) {
        $principal = ''
        try { $principal = "$($task.Principal.UserId)" } catch { continue }
        if ($principal -notmatch 'SYSTEM|LocalService|NetworkService') { continue }
        if ($task.TaskPath -like '\Microsoft\Windows\*') { continue }

        foreach ($action in @($task.Actions)) {
            if (-not $action.PSObject.Properties['Execute']) { continue }
            $resolved = Resolve-ExecutablePath -CommandLine "$($action.Execute)"
            if (-not $resolved) { continue }

            $acl = Test-UserWritable -Path $resolved
            $target = $resolved
            if (-not ($acl -and $acl.Writable)) {
                $directory = Split-Path $resolved -Parent
                if ($directory -match '\\Windows\\(System32|SysWOW64)$') { continue }
                $acl = Test-UserWritable -Path $directory
                $target = $directory
                if (-not ($acl -and $acl.Writable)) { continue }
            }

            Add-Finding -Category $script:AccountCategory -Check 'TaskPrivilegePath' -Severity 'Critical' `
                        -Title "SYSTEM scheduled task '$($task.TaskName)' targets a user-writable location" `
                        -Detail "The task runs as $principal and executes $resolved. Because $target can be modified by non-administrators, any user on this machine can replace the target and gain $principal privileges the next time the task fires." `
                        -Recommendation "Restrict write access to $target, or change the task to run as a less privileged account." `
                        -Evidence ([ordered]@{
                            'Task'    = "$($task.TaskPath)$($task.TaskName)"
                            'Runs as' = $principal
                            'Target'  = $resolved
                            'Writable location' = $target
                            'Dangerous grants'  = ($acl.Grants -join ' | ')
                        })
        }
    }
}

function Test-StoredCredentials {
    Write-ScanLog -Message 'Stored credentials and secrets' -Level 'Step'

    try {
        $output = (& cmdkey /list 2>$null | Out-String)
        $targets = @([regex]::Matches($output, 'Target:\s*(?<target>.+)') | ForEach-Object { $_.Groups['target'].Value.Trim() })
        $interesting = @($targets | Where-Object { $_ -notmatch 'virtualapp/didlogical|SSO_POP_Device|WindowsLive:target=virtualapp' })

        if ($interesting.Count -gt 0) {
            Add-Finding -Category $script:AccountCategory -Check 'StoredCredentials' -Severity 'Medium' `
                        -Title "$($interesting.Count) saved credential(s) in Windows Credential Manager" `
                        -Detail 'Saved credentials can be replayed by any process running as you - no password prompt, and nothing for an antivirus to detect. Malware routinely harvests this store, and stored RDP or network-share credentials give it somewhere to move to.' `
                        -Recommendation 'Review with cmdkey /list and delete anything you do not need: cmdkey /delete:<target>. Prefer a password manager over the Windows credential store for anything sensitive.' `
                        -Evidence ([ordered]@{ 'Targets' = (($interesting | Select-Object -First 20) -join ' | ') })
        }
    }
    catch { }

    # Files whose names advertise that they hold secrets, in obvious locations.
    $searchRoots = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
    $patterns = @('*password*','*passwd*','*credential*','*secret*','id_rsa','*.pem','*.ppk','unattend.xml','sysprep.inf')
    $hits = New-Object System.Collections.ArrayList

    foreach ($root in $searchRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($pattern in $patterns) {
            foreach ($file in (Get-ChildItem -LiteralPath $root -Filter $pattern -File -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 5)) {
                $null = $hits.Add($file.FullName)
            }
        }
    }

    if ($hits.Count -gt 0) {
        Add-Finding -Category $script:AccountCategory -Check 'StoredCredentials' -Severity 'Low' `
                    -Title "$($hits.Count) file(s) in your profile appear to contain credentials" `
                    -Detail 'Files named for passwords or private keys sitting in Desktop/Documents/Downloads are the first thing an infostealer collects. This check only looks at filenames; it does not open the files.' `
                    -Recommendation 'Move secrets into a password manager or an encrypted volume, and delete plaintext copies.' `
                    -Evidence ([ordered]@{ 'Files' = (($hits | Select-Object -Unique -First 15) -join ' | ') })
    }
}

function Test-PrivilegeAssignments {
    <#
        .SYNOPSIS
        Dangerous user rights held by non-administrative principals.
        SeDebugPrivilege alone lets a holder open lsass.exe and dump credentials.
    #>
    Write-ScanLog -Message 'User rights assignments' -Level 'Step'

    if (-not (Test-IsElevated)) { return }

    $exportPath = Join-Path $env:TEMP "argus-secpol-$([guid]::NewGuid().ToString('N')).inf"
    try {
        $null = & secedit /export /cfg $exportPath /areas USER_RIGHTS 2>$null
        if (-not (Test-Path -LiteralPath $exportPath)) { return }

        $content = Get-Content -LiteralPath $exportPath -ErrorAction Stop

        $dangerous = @{
            'SeDebugPrivilege'              = 'debug any process, which allows reading credentials out of lsass.exe'
            'SeTakeOwnershipPrivilege'      = 'take ownership of any file or object'
            'SeBackupPrivilege'             = 'read any file on disk regardless of its permissions'
            'SeRestorePrivilege'            = 'write any file on disk regardless of its permissions'
            'SeLoadDriverPrivilege'         = 'load kernel drivers'
            'SeImpersonatePrivilege'        = 'impersonate other users, the basis of most local escalation exploits'
            'SeTcbPrivilege'                = 'act as part of the operating system'
            'SeCreateTokenPrivilege'        = 'create arbitrary access tokens'
        }
        # SIDs that are administrative or service accounts by design.
        $expectedSids = '\*S-1-5-32-544|\*S-1-5-32-551|\*S-1-5-18|\*S-1-5-19|\*S-1-5-20|\*S-1-5-6|\*S-1-5-32-568|\*S-1-5-83'

        foreach ($line in $content) {
            if ($line -notmatch '^(?<privilege>Se\w+)\s*=\s*(?<holders>.+)$') { continue }
            $privilege = $Matches['privilege']
            if (-not $dangerous.ContainsKey($privilege)) { continue }

            $holders = @($Matches['holders'] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $unexpected = @($holders | Where-Object { $_ -notmatch $expectedSids })
            if ($unexpected.Count -eq 0) { continue }

            $resolved = foreach ($holder in $unexpected) {
                $sid = $holder.TrimStart('*')
                try { (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value }
                catch { $holder }
            }

            Add-Finding -Category $script:AccountCategory -Check 'PrivilegeAssignments' -Severity 'High' `
                        -Title "$privilege is granted to a non-default principal" `
                        -Detail "Holders of this right can $($dangerous[$privilege]). Granted to: $($resolved -join ', ')." `
                        -Recommendation "Review in secpol.msc under Local Policies > User Rights Assignment, and remove any principal that does not need it." `
                        -Evidence ([ordered]@{
                            'Privilege'   = $privilege
                            'Unexpected holders' = ($resolved -join ', ')
                            'Raw entry'   = ConvertTo-DisplayString $Matches['holders'] 300
                        })
        }
    }
    catch { }
    finally {
        Remove-Item -LiteralPath $exportPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-AccountChecks {
    Invoke-Check -Name 'LocalAccounts'         -Body { Test-LocalAccounts }
    Invoke-Check -Name 'PasswordPolicy'        -Body { Test-PasswordPolicy }
    Invoke-Check -Name 'UnquotedServicePaths'  -Body { Test-UnquotedServicePaths }
    Invoke-Check -Name 'WritableServiceBinary' -Body { Test-WritableServiceBinaries }
    Invoke-Check -Name 'ServicePermissions'    -Body { Test-ServicePermissions }
    Invoke-Check -Name 'PathHijacking'         -Body { Test-PathHijacking }
    Invoke-Check -Name 'TaskPrivilegePaths'    -Body { Test-ScheduledTaskPrivilegePaths }
    Invoke-Check -Name 'StoredCredentials'     -Body { Test-StoredCredentials }
    Invoke-Check -Name 'PrivilegeAssignments'  -Body { Test-PrivilegeAssignments }
}
